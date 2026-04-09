//! Ceremony drivers — these run a full FROST flow against a deterministic
//! [`RecordingRng`] and produce a [`Fixture`].

use std::collections::BTreeMap;

use frost_core::{
    compute_binding_factor_list, compute_group_commitment, derive_interpolating_value,
    Ciphersuite,
};
use frost_secp256k1_tr::{
    self as frost_tr,
    keys::{dkg, IdentifierList, KeyPackage, PublicKeyPackage},
    round1, round2, Field, Group, Identifier, Secp256K1Group, Secp256K1Sha256TR, SigningPackage,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::fixture::*;
use crate::recording_rng::RecordingRng;

/// Compute the intermediate values that `round2::sign` walks internally so
/// they can be cross-checked from the TS port. Uses the `internals`-feature
/// helpers on `frost-core` plus the ciphersuite trait method `challenge`
/// (which is the `-tr` x-only override). Mirrors the order of operations in
/// `frost-core/src/round2.rs::sign`.
#[allow(non_snake_case)]
fn capture_signing_intermediates(
    signing_package: &SigningPackage,
    pub_key_package: &PublicKeyPackage,
) -> SigningIntermediates {
    // 1. Binding factor input prefix: vk.serialize() || H4(msg) || H5(encoded_commits).
    //    `binding_factor_preimages` returns the FULL per-signer preimages, each of
    //    which is `prefix || identifier_serialized`. To recover the prefix we slice
    //    one preimage and drop its trailing 32-byte identifier.
    let preimages = signing_package
        .binding_factor_preimages(pub_key_package.verifying_key(), &[])
        .expect("binding_factor_preimages");
    let first_preimage = &preimages.first().expect("at least one signer").1;
    let prefix_len = first_preimage.len() - 32;
    let prefix = &first_preimage[..prefix_len];
    let binding_factor_input_prefix = hex::encode(prefix);

    // 2. Per-signer binding factors via the internals helper.
    let binding_factor_list =
        compute_binding_factor_list::<Secp256K1Sha256TR>(signing_package, pub_key_package.verifying_key(), &[])
            .expect("compute_binding_factor_list");
    let mut binding_factors: Vec<BindingFactorEntry> = signing_package
        .signing_commitments()
        .keys()
        .map(|id| {
            let bf = binding_factor_list
                .get(id)
                .expect("binding factor for signer");
            BindingFactorEntry {
                identifier: identifier_as_u16(*id),
                rho: hex::encode(bf.serialize()),
            }
        })
        .collect();
    binding_factors.sort_by_key(|e| e.identifier);

    // 3. Per-signer Lagrange coefficients via derive_interpolating_value.
    let mut lagrange_coefficients: Vec<LagrangeCoefficientEntry> = signing_package
        .signing_commitments()
        .keys()
        .map(|id| {
            let lambda = derive_interpolating_value::<Secp256K1Sha256TR>(id, signing_package)
                .expect("derive_interpolating_value");
            LagrangeCoefficientEntry {
                identifier: identifier_as_u16(*id),
                lambda: hex::encode(<<Secp256K1Group as Group>::Field>::serialize(&lambda)),
            }
        })
        .collect();
    lagrange_coefficients.sort_by_key(|e| e.identifier);

    // 4. Group commitment R = Σ (D_i + rho_i · E_i).
    let group_commitment_value =
        compute_group_commitment::<Secp256K1Sha256TR>(signing_package, &binding_factor_list)
            .expect("compute_group_commitment");
    let group_commitment_hex = hex::encode(
        Secp256K1Group::serialize(&group_commitment_value.clone().to_element())
            .expect("group commitment ser"),
    );

    // 5. H2 challenge — uses the `-tr` x-only override on Ciphersuite::challenge.
    let challenge_value = <Secp256K1Sha256TR as Ciphersuite>::challenge(
        &group_commitment_value.to_element(),
        pub_key_package.verifying_key(),
        signing_package.message(),
    )
    .expect("Ciphersuite::challenge");
    let challenge_hex = hex::encode(<<Secp256K1Group as Group>::Field>::serialize(
        &challenge_value.to_scalar(),
    ));

    SigningIntermediates {
        binding_factor_input_prefix,
        binding_factors,
        lagrange_coefficients,
        group_commitment: group_commitment_hex,
        challenge: challenge_hex,
    }
}

/// Convert a default-style `Identifier` (which is just a small integer
/// reduced into the secp256k1 scalar field) back into the original `u16`.
/// This works because default identifiers are constructed from `u16` values
/// 1, 2, 3, ... — the serialized big-endian scalar therefore has the
/// integer in its last two bytes.
fn identifier_as_u16(id: Identifier) -> u16 {
    let bytes = id.serialize();
    let len = bytes.len();
    u16::from_be_bytes([bytes[len - 2], bytes[len - 1]])
}

/// `(t, n)` trusted-dealer ceremony with `frost-secp256k1-tr`.
///
/// Drives the full flow: dealer key generation → round 1 commit → round 2
/// sign → aggregate → verify. Captures every intermediate value plus the
/// full RNG byte log.
///
/// Note: dealer mode does NOT apply the BIP341 unspendable taproot tweak,
/// because `frost-secp256k1-tr` only overrides `Ciphersuite::post_dkg`, not
/// `Ciphersuite::post_generate`. The verifying key in the resulting fixture
/// is therefore the *raw* aggregate `secret_key * G` (with even-y forced by
/// the BIP340 normalization in `pre_sign`/`pre_aggregate`), NOT the
/// post-tweak key.
#[allow(non_snake_case)]
pub fn run_dealer_tr(min_signers: u16, max_signers: u16, seed: [u8; 32], message: &[u8]) -> Fixture {
    let MIN_SIGNERS = min_signers;
    let MAX_SIGNERS = max_signers;
    let SEED = seed;
    let MESSAGE = message;

    let inner = ChaCha20Rng::from_seed(SEED);
    let mut rng = RecordingRng::new(inner);

    // -----------------------------------------------------------------------
    // Phase 1: dealer key generation
    //
    // Empirically (verified by inspecting the rng_log of an early run): for
    // a (t, n) = (2, 3) ceremony this consumes exactly 2 fill_bytes calls of
    // 32 bytes each — one for `SigningKey::new(rng)` and one for the single
    // polynomial coefficient. k256's `Scalar::random` uses 32-byte rejection
    // sampling, not 64-byte uniform sampling.
    // -----------------------------------------------------------------------
    rng.label_next("dealer.signing_key");
    let cursor_keygen_start = rng.cursor();
    let (shares, pub_key_package) = frost_tr::keys::generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        IdentifierList::Default,
        &mut rng,
    )
    .expect("dealer keygen");
    let keygen_calls = &rng.log()[cursor_keygen_start..rng.cursor()];
    debug_assert_eq!(
        keygen_calls.len(),
        MIN_SIGNERS as usize,
        "dealer keygen: expected {} RNG calls (1 signing key + {} coefficients), got {}",
        MIN_SIGNERS,
        MIN_SIGNERS - 1,
        keygen_calls.len()
    );
    debug_assert!(keygen_calls.iter().all(|c| c.len == 32));

    // Convert SecretShares -> KeyPackages (does VSS verification per share)
    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (id, share) in shares.iter() {
        let kp = KeyPackage::try_from(share.clone()).expect("share -> keypackage");
        key_packages.insert(*id, kp);
    }

    // Pick the first MIN_SIGNERS signers (sorted by Identifier scalar)
    let signers: Vec<Identifier> = key_packages.keys().take(MIN_SIGNERS as usize).copied().collect();

    // -----------------------------------------------------------------------
    // Phase 2: round 1 commit per signer
    // -----------------------------------------------------------------------
    let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    let mut round_one_records: Vec<RoundOneOutput> = Vec::new();

    for &id in &signers {
        let kp = key_packages.get(&id).unwrap();
        let cursor_before = rng.cursor();
        rng.label_next(format!("round1.commit.p{}.hiding_nonce_randomness", identifier_as_u16(id)));
        let (nonces, commitments) = round1::commit(kp.signing_share(), &mut rng);
        let cursor_after = rng.cursor();

        // round1::commit MUST consume exactly two 32-byte fill_bytes calls
        // (hiding nonce randomness, then binding nonce randomness). Verify.
        let calls = &rng.log()[cursor_before..cursor_after];
        assert_eq!(
            calls.len(),
            2,
            "round1::commit consumed {} RNG calls, expected exactly 2",
            calls.len()
        );
        assert!(calls.iter().all(|c| c.len == 32));

        round_one_records.push(RoundOneOutput {
            identifier: identifier_as_u16(id),
            hiding_nonce_randomness: calls[0].bytes_hex.clone(),
            binding_nonce_randomness: calls[1].bytes_hex.clone(),
            hiding_nonce: hex::encode(nonces.hiding().serialize()),
            binding_nonce: hex::encode(nonces.binding().serialize()),
            hiding_nonce_commitment: hex::encode(
                commitments.hiding().serialize().expect("commitment ser"),
            ),
            binding_nonce_commitment: hex::encode(
                commitments.binding().serialize().expect("commitment ser"),
            ),
        });

        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    // -----------------------------------------------------------------------
    // Phase 3: build SigningPackage and run round 2
    // -----------------------------------------------------------------------
    let signing_package = SigningPackage::new(commitments_map, MESSAGE);

    let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    let mut round_two_records: Vec<RoundTwoOutput> = Vec::new();

    for &id in &signers {
        let kp = key_packages.get(&id).unwrap();
        let nonces = nonces_map.get(&id).unwrap();
        let share = round2::sign(&signing_package, nonces, kp).expect("round 2 sign");
        round_two_records.push(RoundTwoOutput {
            identifier: identifier_as_u16(id),
            sig_share: hex::encode(share.serialize()),
        });
        signature_shares.insert(id, share);
    }

    // Capture the signing-flow intermediates that round2::sign computed internally,
    // for cross-checking from the TS port.
    let signing_intermediates = capture_signing_intermediates(&signing_package, &pub_key_package);

    // -----------------------------------------------------------------------
    // Phase 4: aggregate
    // -----------------------------------------------------------------------
    let signature = frost_tr::aggregate(&signing_package, &signature_shares, &pub_key_package)
        .expect("aggregate");

    // Verify against the operative verifying key (this exercises the BIP340
    // even-y normalization in `pre_verify`)
    pub_key_package
        .verifying_key()
        .verify(MESSAGE, &signature)
        .expect("aggregate signature must verify against the public key package");

    // -----------------------------------------------------------------------
    // Build the Fixture
    // -----------------------------------------------------------------------
    let mut participant_shares: Vec<ParticipantShare> = shares
        .iter()
        .map(|(id, share)| ParticipantShare {
            identifier: identifier_as_u16(*id),
            participant_share: hex::encode(share.signing_share().serialize()),
            verifying_share: pub_key_package
                .verifying_shares()
                .get(id)
                .map(|vs| hex::encode(vs.serialize().expect("verifying share ser")))
                .unwrap_or_default(),
        })
        .collect();
    participant_shares.sort_by_key(|s| s.identifier);

    let mut signer_ids: Vec<u16> = signers.iter().map(|id| identifier_as_u16(*id)).collect();
    signer_ids.sort();

    Fixture {
        config: Config {
            MAX_PARTICIPANTS: MAX_SIGNERS.to_string(),
            MIN_PARTICIPANTS: MIN_SIGNERS.to_string(),
            NUM_PARTICIPANTS: signers.len().to_string(),
            name: "FROST(secp256k1, SHA-256-TR)".to_string(),
            group: "secp256k1".to_string(),
            hash: "SHA-256".to_string(),
            flow: "dealer".to_string(),
            tweak_applied: false, // dealer flow does not apply post_dkg tweak in -tr
            rng_seed_hex: hex::encode(SEED),
        },
        inputs: Inputs {
            participant_list: signer_ids,
            verifying_key_key: hex::encode(
                pub_key_package
                    .verifying_key()
                    .serialize()
                    .expect("verifying key ser"),
            ),
            verifying_key_pre_tweak: None,
            message: hex::encode(MESSAGE),
            share_polynomial_coefficients: None, // not directly accessible from the public API
            group_secret_key: None, // ditto — would require internals access
            participant_shares,
        },
        round_one_outputs: RoundOneOutputs {
            outputs: round_one_records,
        },
        round_two_outputs: RoundTwoOutputs {
            outputs: round_two_records,
        },
        signing_intermediates,
        final_output: FinalOutput {
            sig: hex::encode(signature.serialize().expect("signature ser")),
        },
        rng_log: rng.into_log(),
    }
}

/// 2-of-3 distributed key generation (no dealer) ceremony with `frost-secp256k1-tr`.
///
/// All three parties run `dkg::part1` / `part2` / `part3` against a single
/// shared `RecordingRng` (in a real ceremony each party would have its own
/// RNG, but for replay-buffer purposes a single ordered byte stream is
/// equivalent and easier to consume from the TS port).
///
/// Captures every per-party intermediate value (polynomial coefficients,
/// commitments, proof-of-knowledge, secret shares, signing shares, verifying
/// shares, and the post-DKG-tweaked aggregate verifying key) plus the
/// signing flow's round 1 / 2 / aggregate outputs.
#[allow(non_snake_case)]
pub fn run_dkg_tr(min_signers: u16, max_signers: u16, seed: [u8; 32], message: &[u8]) -> DkgFixture {
    let MIN_SIGNERS = min_signers;
    let MAX_SIGNERS = max_signers;
    let SEED = seed;
    let MESSAGE = message;

    let inner = ChaCha20Rng::from_seed(SEED);
    let mut rng = RecordingRng::new(inner);

    // -----------------------------------------------------------------------
    // Phase 1: each party runs dkg::part1 (one polynomial + PoK each)
    // RNG consumption per party = MIN_SIGNERS (1 secret + (t-1) coeffs) + 1 PoK
    //                           = (2-1+1) + 1 = MIN_SIGNERS + 1 calls
    // For (2,3): 3 calls × 32 bytes per party × 3 parties = 288 bytes
    // -----------------------------------------------------------------------
    let identifiers: Vec<Identifier> = (1u16..=MAX_SIGNERS)
        .map(|i| Identifier::try_from(i).expect("non-zero identifier"))
        .collect();

    let mut round1_secrets: BTreeMap<Identifier, dkg::round1::SecretPackage> = BTreeMap::new();
    let mut round1_packages: BTreeMap<Identifier, dkg::round1::Package> = BTreeMap::new();
    let mut part1_records: Vec<DkgPart1Party> = Vec::new();

    for &id in &identifiers {
        let id_u16 = identifier_as_u16(id);
        rng.label_next(format!("dkg.part1.p{}.signing_key", id_u16));
        let cursor_before = rng.cursor();
        let (secret_pkg, round1_pkg) =
            dkg::part1(id, MAX_SIGNERS, MIN_SIGNERS, &mut rng).expect("dkg part1");
        let cursor_after = rng.cursor();

        // Sanity-check the consumption pattern: 1 secret + (t-1) coefficients + 1 PoK = t+1
        let calls = &rng.log()[cursor_before..cursor_after];
        debug_assert_eq!(
            calls.len(),
            MIN_SIGNERS as usize + 1,
            "dkg::part1 consumed {} RNG calls, expected {}",
            calls.len(),
            MIN_SIGNERS + 1
        );
        debug_assert!(calls.iter().all(|c| c.len == 32));

        // Pull the per-party secret polynomial coefficients (requires `internals`).
        let coeffs = secret_pkg.coefficients();
        let coeffs_hex: Vec<String> = coeffs
            .iter()
            .map(|s| hex::encode(<<frost_tr::Secp256K1Group as Group>::Field as frost_tr::Field>::serialize(s)))
            .collect();

        // Pull the public commitments to those coefficients
        let commitments = round1_pkg.commitment();
        let commitment_hex: Vec<String> = commitments
            .coefficients()
            .iter()
            .map(|cc| hex::encode(Secp256K1Group::serialize(&cc.value()).expect("commit ser")))
            .collect();

        // Pull the proof-of-knowledge (R, z)
        let pok = round1_pkg.proof_of_knowledge();
        let pok_R = Secp256K1Group::serialize(pok.R()).expect("pok R ser");
        let pok_z = <<frost_tr::Secp256K1Group as Group>::Field as frost_tr::Field>::serialize(pok.z());

        part1_records.push(DkgPart1Party {
            identifier: id_u16,
            secret_polynomial_coefficients: coeffs_hex,
            commitments: commitment_hex,
            proof_of_knowledge_R: hex::encode(pok_R),
            proof_of_knowledge_z: hex::encode(pok_z),
            round1_package_bytes: hex::encode(round1_pkg.serialize().expect("round1 ser")),
        });

        round1_secrets.insert(id, secret_pkg);
        round1_packages.insert(id, round1_pkg);
    }

    // -----------------------------------------------------------------------
    // Phase 2: each party runs dkg::part2 with everyone ELSE'S round1 packages
    // -----------------------------------------------------------------------
    let mut round2_secrets: BTreeMap<Identifier, dkg::round2::SecretPackage> = BTreeMap::new();
    // round2_outbound[sender][recipient] = round2::Package
    let mut round2_outbound: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>> =
        BTreeMap::new();
    let mut part2_records: Vec<DkgPart2Party> = Vec::new();

    for &sender in &identifiers {
        // Collect every round1 package EXCEPT the sender's own
        let received_round1: BTreeMap<Identifier, dkg::round1::Package> = round1_packages
            .iter()
            .filter(|(other, _)| **other != sender)
            .map(|(other, pkg)| (*other, pkg.clone()))
            .collect();

        let secret_pkg = round1_secrets
            .remove(&sender)
            .expect("round1 secret present");
        let (round2_secret, round2_outbox) =
            dkg::part2(secret_pkg, &received_round1).expect("dkg part2");

        // Record the per-recipient secret shares
        let mut share_records: Vec<DkgPart2Share> = round2_outbox
            .iter()
            .map(|(recipient, pkg)| DkgPart2Share {
                recipient: identifier_as_u16(*recipient),
                signing_share: hex::encode(pkg.signing_share().serialize()),
                round2_package_bytes: hex::encode(pkg.serialize().expect("round2 ser")),
            })
            .collect();
        share_records.sort_by_key(|s| s.recipient);

        part2_records.push(DkgPart2Party {
            identifier: identifier_as_u16(sender),
            round2_secret_shares: share_records,
        });

        round2_secrets.insert(sender, round2_secret);
        round2_outbound.insert(sender, round2_outbox);
    }

    // -----------------------------------------------------------------------
    // Phase 3: each party runs dkg::part3 with their round2 secret +
    // received round2 packages
    // -----------------------------------------------------------------------
    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    let mut public_key_packages: BTreeMap<Identifier, PublicKeyPackage> = BTreeMap::new();
    let mut part3_records: Vec<DkgPart3Party> = Vec::new();

    for &id in &identifiers {
        // Build the round1 / round2 maps as seen by THIS party (filtering out
        // their own outbox entries)
        let received_round1: BTreeMap<Identifier, dkg::round1::Package> = round1_packages
            .iter()
            .filter(|(other, _)| **other != id)
            .map(|(other, pkg)| (*other, pkg.clone()))
            .collect();

        let received_round2: BTreeMap<Identifier, dkg::round2::Package> = round2_outbound
            .iter()
            .filter(|(sender, _)| **sender != id)
            .filter_map(|(sender, outbox)| outbox.get(&id).map(|pkg| (*sender, pkg.clone())))
            .collect();

        let r2_secret = round2_secrets.get(&id).expect("round2 secret present");
        let (kp, pkp) = dkg::part3(r2_secret, &received_round1, &received_round2)
            .expect("dkg part3");

        part3_records.push(DkgPart3Party {
            identifier: identifier_as_u16(id),
            signing_share: hex::encode(kp.signing_share().serialize()),
            verifying_share: hex::encode(kp.verifying_share().serialize().expect("vs ser")),
            verifying_key: hex::encode(kp.verifying_key().serialize().expect("vk ser")),
        });

        key_packages.insert(id, kp);
        public_key_packages.insert(id, pkp);
    }

    // Sanity: every party must have computed the SAME aggregate verifying key
    let canonical_vk = public_key_packages
        .values()
        .next()
        .unwrap()
        .verifying_key()
        .clone();
    for (id, pkp) in &public_key_packages {
        assert_eq!(
            pkp.verifying_key(),
            &canonical_vk,
            "party {} computed a different aggregate verifying key — DKG diverged",
            identifier_as_u16(*id)
        );
    }

    // Compute the pre-tweak verifying key for cross-checking. The aggregate
    // pre-tweak public key is `Σ_j commitment_j[0]` where commitment_j[0] is
    // the constant-term commitment of party j (i.e. `secret_j * G`).
    let pre_tweak_pubkey = {
        let mut acc = Secp256K1Group::identity();
        for pkg in round1_packages.values() {
            let cc0 = pkg
                .commitment()
                .coefficients()
                .first()
                .expect("commitment has at least one coefficient");
            acc = acc + cc0.value();
        }
        Secp256K1Group::serialize(&acc).expect("pre-tweak pubkey ser")
    };

    // Pick the canonical PublicKeyPackage (any party's, they're all equal)
    let pub_key_package = public_key_packages
        .values()
        .next()
        .expect("at least one party")
        .clone();

    // -----------------------------------------------------------------------
    // Phase 4: signing rounds 1 / 2 / aggregate (same as dealer flow)
    // -----------------------------------------------------------------------
    let signers: Vec<Identifier> = key_packages.keys().take(MIN_SIGNERS as usize).copied().collect();

    let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    let mut round_one_records: Vec<RoundOneOutput> = Vec::new();

    for &id in &signers {
        let kp = key_packages.get(&id).unwrap();
        let cursor_before = rng.cursor();
        rng.label_next(format!("round1.commit.p{}.hiding_nonce_randomness", identifier_as_u16(id)));
        let (nonces, commitments) = round1::commit(kp.signing_share(), &mut rng);
        let cursor_after = rng.cursor();

        let calls = &rng.log()[cursor_before..cursor_after];
        assert_eq!(calls.len(), 2, "round1::commit should consume exactly 2 RNG calls");
        assert!(calls.iter().all(|c| c.len == 32));

        round_one_records.push(RoundOneOutput {
            identifier: identifier_as_u16(id),
            hiding_nonce_randomness: calls[0].bytes_hex.clone(),
            binding_nonce_randomness: calls[1].bytes_hex.clone(),
            hiding_nonce: hex::encode(nonces.hiding().serialize()),
            binding_nonce: hex::encode(nonces.binding().serialize()),
            hiding_nonce_commitment: hex::encode(
                commitments.hiding().serialize().expect("commitment ser"),
            ),
            binding_nonce_commitment: hex::encode(
                commitments.binding().serialize().expect("commitment ser"),
            ),
        });

        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    let signing_package = SigningPackage::new(commitments_map, MESSAGE);
    let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    let mut round_two_records: Vec<RoundTwoOutput> = Vec::new();

    for &id in &signers {
        let kp = key_packages.get(&id).unwrap();
        let nonces = nonces_map.get(&id).unwrap();
        let share = round2::sign(&signing_package, nonces, kp).expect("round 2 sign");
        round_two_records.push(RoundTwoOutput {
            identifier: identifier_as_u16(id),
            sig_share: hex::encode(share.serialize()),
        });
        signature_shares.insert(id, share);
    }

    // Capture the signing-flow intermediates for cross-checking from the TS port.
    let signing_intermediates = capture_signing_intermediates(&signing_package, &pub_key_package);

    let signature = frost_tr::aggregate(&signing_package, &signature_shares, &pub_key_package)
        .expect("aggregate");

    pub_key_package
        .verifying_key()
        .verify(MESSAGE, &signature)
        .expect("aggregate signature must verify against the post-DKG-tweaked verifying key");

    let mut signer_ids: Vec<u16> = signers.iter().map(|id| identifier_as_u16(*id)).collect();
    signer_ids.sort();

    DkgFixture {
        config: Config {
            MAX_PARTICIPANTS: MAX_SIGNERS.to_string(),
            MIN_PARTICIPANTS: MIN_SIGNERS.to_string(),
            NUM_PARTICIPANTS: signers.len().to_string(),
            name: "FROST(secp256k1, SHA-256-TR)".to_string(),
            group: "secp256k1".to_string(),
            hash: "SHA-256".to_string(),
            flow: "dkg".to_string(),
            tweak_applied: true,
            rng_seed_hex: hex::encode(SEED),
        },
        inputs: DkgInputs {
            participant_list: signer_ids,
            verifying_key_key: hex::encode(
                pub_key_package
                    .verifying_key()
                    .serialize()
                    .expect("verifying key ser"),
            ),
            verifying_key_pre_tweak: hex::encode(pre_tweak_pubkey),
            message: hex::encode(MESSAGE),
        },
        dkg: DkgData {
            part1: part1_records,
            part2: part2_records,
            part3: part3_records,
        },
        round_one_outputs: RoundOneOutputs { outputs: round_one_records },
        round_two_outputs: RoundTwoOutputs { outputs: round_two_records },
        signing_intermediates,
        final_output: FinalOutput {
            sig: hex::encode(signature.serialize().expect("signature ser")),
        },
        rng_log: rng.into_log(),
    }
}
