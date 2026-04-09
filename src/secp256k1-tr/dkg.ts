/**
 * Distributed Key Generation (DKG) primitives and types.
 *
 * Step 3 ported the DKG proof-of-knowledge challenge primitive. Step 4
 * sub-step 6 adds the public-API type wrappers and round functions
 * (`dkgRound1`, `dkgRound2`, `dkgFinalize`) that compose the validated
 * Step 3 primitives into a complete DKG flow.
 *
 * Type-wrapper conventions (per the Step 4 design checkpoint):
 * - **Minimal shape** (Q3): mirror only the Rust fields the public API
 *   actually consumes. No `Header<C>`, no serialization version bytes.
 * - **`Uint8Array` for points** at the interface boundary, matching the
 *   dealer-flow `KeyPackage` / `PublicKeyPackage` convention in `keys.ts`.
 * - **`bigint` for identifiers**, matching `KeyPackage.identifier`.
 * - **`bigint` for secret scalars** (polynomial coefficients, signing
 *   shares), matching `KeyPackage.signingShare`.
 *
 * Reference: `frost-core/src/keys/dkg.rs` (round types + part1/2/3),
 * `RUST_REFERENCE_NOTES.md` §2 (DKG API surface), §8 (PoK challenge),
 * §9 (RNG consumption order).
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { HDKG } from './hash.ts';
import type { KeyPackage, PublicKeyPackage } from './keys.ts';
import { hasEvenY, intoEvenY, scalarBaseMul } from './point.ts';
import { evalPoly, evalPolyOnPoints } from './poly.ts';
import { tapTweakScalar } from './tweak.ts';
import type { Rng } from './sign.ts';

const Fn = secp256k1.Point.Fn;

type Point = typeof secp256k1.Point.BASE;

// =============================================================================
// DKG round types (Step 4 sub-step 6.1)
// =============================================================================

/**
 * Per-party private state after `dkgRound1`. Consumed by `dkgRound2`.
 *
 * Mirrors `frost_core::keys::dkg::round1::SecretPackage<C>`. Holds the
 * secret polynomial coefficients and public commitments that `dkgRound2`
 * uses to compute per-recipient secret shares.
 */
export interface Round1SecretPackage {
  readonly identifier: bigint;
  /** Secret polynomial coefficients (constant term first), `t` scalars. */
  readonly polynomialCoefficients: readonly bigint[];
  /** Public commitments to the polynomial: `commitment[i] = coeff[i] · G`, `t` SEC1 33-byte points. */
  readonly commitment: readonly Uint8Array[];
  readonly minSigners: number;
  readonly maxSigners: number;
}

/**
 * Per-party public broadcast after `dkgRound1`. Every other participant
 * receives this and uses it in `dkgRound2` (PoK verification) and
 * `dkgFinalize` (aggregate-key + share verification).
 *
 * Mirrors `frost_core::keys::dkg::round1::Package<C>` minus `Header<C>`.
 * The `identifier` field is added for routing (Rust carries it as the
 * `BTreeMap` key in `part2`/`part3`'s received-packages map).
 */
export interface Round1Package {
  /** Sender's participant identifier. */
  readonly identifier: bigint;
  /** VSS commitment, `t` SEC1 33-byte points (constant term first). */
  readonly commitment: readonly Uint8Array[];
  /** Schnorr proof of knowledge of `polynomialCoefficients[0]`. */
  readonly proofOfKnowledge: {
    /** 33-byte SEC1 compressed nonce commitment. */
    readonly R: Uint8Array;
    /** Schnorr response scalar. */
    readonly z: bigint;
  };
}

/**
 * Per-party private state after `dkgRound2`. Consumed by `dkgFinalize`.
 *
 * Mirrors `frost_core::keys::dkg::round2::SecretPackage<C>`. Holds the
 * party's own commitment and its self-evaluated share `f_me(me)`, which
 * `dkgFinalize` folds into the final signing share alongside received
 * shares from other parties.
 */
export interface Round2SecretPackage {
  readonly identifier: bigint;
  /** Own VSS commitment from round 1, `t` SEC1 33-byte points. */
  readonly commitment: readonly Uint8Array[];
  /** Own secret share contribution: `evalPoly(ownCoefficients, ownIdentifier)`. */
  readonly secretShare: bigint;
  readonly minSigners: number;
  readonly maxSigners: number;
}

/**
 * Per-recipient secret share sent by one party to another in round 2.
 *
 * Mirrors `frost_core::keys::dkg::round2::Package<C>` minus `Header<C>`.
 * `sender` and `recipient` are added for routing (Rust carries sender as
 * the `BTreeMap` key and recipient is implicit from the transport).
 */
export interface Round2Package {
  /** Identifier of the party that computed the share. */
  readonly sender: bigint;
  /** Identifier of the intended recipient. */
  readonly recipient: bigint;
  /** Secret share `f_sender(recipient)`, a scalar mod n. */
  readonly signingShare: bigint;
}

/**
 * `dkgProofOfKnowledgeChallenge` — build the Schnorr challenge scalar `c` for
 * a DKG part-1 proof of knowledge.
 *
 * Mirrors `frost-core/src/keys/dkg.rs`'s `challenge<C>` helper:
 *
 *     fn challenge<C>(identifier, verifying_key, R) -> Challenge<C> {
 *         let mut preimage = vec![];
 *         preimage.extend_from_slice(identifier.serialize().as_ref());                    // 32
 *         preimage.extend_from_slice(<C::Group>::serialize(&verifying_key.to_element())?); // 33
 *         preimage.extend_from_slice(<C::Group>::serialize(R)?);                           // 33
 *         Challenge(C::HDKG(&preimage[..])...)
 *     }
 *
 * Crucially the preimage uses **full 33-byte SEC1 compressed** points (NOT
 * x-only) — DKG happens before BIP340 even-y normalization is meaningful, so
 * we're proving knowledge of a polynomial coefficient, not BIP340-signing yet.
 * This is what distinguishes DKG-PoK challenges from `Ciphersuite::challenge`
 * (which builds an x-only preimage for the on-chain Schnorr equation).
 *
 * Identifier encoding: the canonical 32-byte big-endian field encoding via
 * `Fn.toBytes`. For default identifiers `1, 2, ...` the last 2 bytes hold the
 * `u16` value, matching `frost-core`'s `Identifier::serialize()`.
 */
export function dkgProofOfKnowledgeChallenge(
  identifier: bigint,
  verifyingKey: Point,
  R: Point,
): bigint {
  const idBytes = Fn.toBytes(identifier);
  const vkBytes = verifyingKey.toBytes(true);
  const rBytes = R.toBytes(true);

  // 32 (identifier) + 33 (vk) + 33 (R) = 98 bytes
  const preimage = new Uint8Array(98);
  preimage.set(idBytes, 0);
  preimage.set(vkBytes, 32);
  preimage.set(rBytes, 65);

  return HDKG(preimage);
}

// =============================================================================
// DKG round functions (Step 4 sub-step 6.2+)
// =============================================================================

/**
 * `dkgRound1` — generate a party's secret polynomial, public commitments,
 * and proof of knowledge for DKG part 1.
 *
 * Mirrors `frost_core::keys::dkg::part1(identifier, max_signers, min_signers, rng)`.
 *
 * RNG consumption order (per RUST_REFERENCE_NOTES §9, empirically confirmed
 * against the DKG fixture rng_log):
 *   1. Signing key / first polynomial coefficient: 32 bytes
 *   2. Additional polynomial coefficients: (minSigners - 1) × 32 bytes
 *   3. Proof-of-knowledge nonce `k`: 32 bytes
 * Total: (minSigners + 1) × 32 bytes per party.
 *
 * The proof of knowledge is a Schnorr signature `(R, z)` where:
 *   - `R = k · G`
 *   - `c = HDKG(identifier || commitment[0] || R)` (full 33-byte SEC1 points)
 *   - `z = k + c · coefficient[0]`
 *
 * Returns both the secret package (for this party's use in round 2) and the
 * public package (broadcast to all other parties).
 */
export function dkgRound1(
  identifier: bigint,
  maxSigners: number,
  minSigners: number,
  rng: Rng,
): { secretPackage: Round1SecretPackage; package: Round1Package } {
  // 1. Generate the secret polynomial coefficients (constant term first).
  const coefficients: bigint[] = [];
  for (let i = 0; i < minSigners; i++) {
    const buf = new Uint8Array(32);
    rng.fillBytes(buf);
    coefficients.push(Fn.fromBytes(buf));
  }

  // 2. Compute public commitments: commitment[i] = coefficient[i] · G.
  const commitmentPoints: Point[] = coefficients.map((c) => scalarBaseMul(c));
  const commitment: Uint8Array[] = commitmentPoints.map((p) => p.toBytes(true));

  // 3. Read the proof-of-knowledge nonce k, then apply the
  //    `Ciphersuite::generate_nonce` even-y dance (lib.rs:365-378):
  //    negate (k, R) if R has odd y, so R is always even-y.
  //    This is NOT the same path as round-1 commit nonces (which use
  //    `nonce_generate_from_random_bytes` with no parity dance — see §6.1).
  const kBuf = new Uint8Array(32);
  rng.fillBytes(kBuf);
  let k = Fn.fromBytes(kBuf);
  let R = scalarBaseMul(k);
  if (!hasEvenY(R)) {
    k = Fn.neg(k);
    R = R.negate();
  }

  // 4. Schnorr proof of knowledge of coefficient[0].
  const c = dkgProofOfKnowledgeChallenge(identifier, commitmentPoints[0]!, R);
  const z = Fn.add(k, Fn.mul(c, coefficients[0]!));

  return {
    secretPackage: {
      identifier,
      polynomialCoefficients: coefficients,
      commitment,
      minSigners,
      maxSigners,
    },
    package: {
      identifier,
      commitment,
      proofOfKnowledge: { R: R.toBytes(true), z },
    },
  };
}

/**
 * `dkgVerifyProofOfKnowledge` — verify a party's Schnorr proof of knowledge
 * from their round 1 package.
 *
 * Mirrors `frost_core::keys::dkg::verify_proof_of_knowledge` (dkg.rs:~445-462):
 *
 *     R == z·G - c·vk   ⟺   z·G == R + c·vk
 *
 * where `vk = commitment[0]` (the party's public key contribution) and
 * `c = HDKG(identifier || vk_full_33 || R_full_33)`.
 *
 * Throws on failure (matching Rust's `Error::InvalidProofOfKnowledge`).
 */
export function dkgVerifyProofOfKnowledge(pkg: Round1Package): void {
  const vk = secp256k1.Point.fromBytes(pkg.commitment[0]!);
  const R = secp256k1.Point.fromBytes(pkg.proofOfKnowledge.R);
  const z = pkg.proofOfKnowledge.z;

  const c = dkgProofOfKnowledgeChallenge(pkg.identifier, vk, R);

  // z·G == R + c·vk
  const lhs = scalarBaseMul(z);
  const rhs = R.add(vk.multiply(c));

  if (!lhs.equals(rhs)) {
    throw new Error(
      `dkgVerifyProofOfKnowledge: invalid proof of knowledge from participant ${pkg.identifier}`,
    );
  }
}

/**
 * `dkgRound2` — verify received round 1 packages and compute per-recipient
 * secret shares for DKG part 2.
 *
 * Mirrors `frost_core::keys::dkg::part2(round1_secret, round1_packages)`.
 *
 * For each received round 1 package from another party `ell`:
 *   1. Verify the proof of knowledge on `ell`'s package.
 *   2. Compute `f_me(ell) = evalPoly(myCoefficients, ell)` — the share
 *      we send to party `ell`.
 *
 * Also computes `f_me(me) = evalPoly(myCoefficients, myIdentifier)` for the
 * self-share that goes into `Round2SecretPackage.secretShare`.
 *
 * Returns the Round2SecretPackage (private state for `dkgFinalize`) and a
 * map of Round2Packages keyed by recipient identifier.
 */
export function dkgRound2(
  secretPackage: Round1SecretPackage,
  receivedRound1: ReadonlyMap<bigint, Round1Package>,
): {
  secretPackage: Round2SecretPackage;
  packages: ReadonlyMap<bigint, Round2Package>;
} {
  const packages = new Map<bigint, Round2Package>();

  for (const [, round1Package] of receivedRound1) {
    // 1. Verify the PoK.
    dkgVerifyProofOfKnowledge(round1Package);

    // 2. Compute the share we send to this party.
    const recipientId = round1Package.identifier;
    const signingShare = evalPoly(
      secretPackage.polynomialCoefficients,
      recipientId,
    );

    packages.set(recipientId, {
      sender: secretPackage.identifier,
      recipient: recipientId,
      signingShare,
    });
  }

  // Self-share: f_me(me) — stored in the secret package for part3.
  const selfShare = evalPoly(
    secretPackage.polynomialCoefficients,
    secretPackage.identifier,
  );

  return {
    secretPackage: {
      identifier: secretPackage.identifier,
      commitment: secretPackage.commitment,
      secretShare: selfShare,
      minSigners: secretPackage.minSigners,
      maxSigners: secretPackage.maxSigners,
    },
    packages,
  };
}

/**
 * `dkgFinalize` — verify received shares, compute the aggregate key, and
 * apply the BIP341 post-DKG tap tweak. Returns the final `KeyPackage` and
 * `PublicKeyPackage`.
 *
 * Mirrors `frost_core::keys::dkg::part3(round2_secret, round1_packages, round2_packages)`
 * + `Ciphersuite::post_dkg`.
 *
 * Steps:
 *   1. **VSS verification:** for each received round 2 share, verify
 *      `share · G == evalPolyOnPoints(senderCommitment, myId)`.
 *   2. **Signing share accumulation:** sum all received shares + self-share.
 *   3. **Group commitment:** sum all parties' commitments (received + own)
 *      coefficient-by-coefficient. The constant term is the aggregate vk.
 *   4. **Per-party verifying shares:** evaluate the group commitment
 *      polynomial at each party's identifier.
 *   5. **Post-DKG tap tweak** (`post_dkg`): apply `tapTweakScalar` +
 *      `into_even_y` normalization to all outputs. This is the BIP341
 *      unspendable-script-path commitment that makes the resulting key
 *      BIP341-compliant. Dealer flow does NOT apply this — see
 *      `RUST_REFERENCE_NOTES.md` §5.1.5.
 *
 * The returned `KeyPackage.verifyingKey` is the POST-TWEAK aggregate.
 * It may still have odd y at test seeds (the tweak is unrelated to BIP340
 * parity normalization). Per the Q2 convention, `signRound2` will apply
 * `pre_sign` parity normalization on top of the post-tweak vk.
 */
export function dkgFinalize(
  secretPackage: Round2SecretPackage,
  receivedRound1: ReadonlyMap<bigint, Round1Package>,
  receivedRound2: ReadonlyMap<bigint, Round2Package>,
): { keyPackage: KeyPackage; publicKeyPackage: PublicKeyPackage } {
  const Point = secp256k1.Point;

  // --- Step 1+2: VSS verify and accumulate signing share ---
  let signingShare = 0n;

  for (const [senderId, round2Package] of receivedRound2) {
    const round1Package = receivedRound1.get(senderId);
    if (!round1Package) {
      throw new Error(
        `dkgFinalize: missing round 1 package from sender ${senderId}`,
      );
    }

    // VSS: share · G == evalPolyOnPoints(senderCommitment, myId)
    const senderCommitmentPoints = round1Package.commitment.map((b) =>
      Point.fromBytes(b),
    );
    const expectedShareCommitment = evalPolyOnPoints(
      senderCommitmentPoints,
      secretPackage.identifier,
    );
    const actualShareCommitment = scalarBaseMul(round2Package.signingShare);
    if (!expectedShareCommitment.equals(actualShareCommitment)) {
      throw new Error(
        `dkgFinalize: VSS verification failed for share from sender ${senderId}`,
      );
    }

    signingShare = Fn.add(signingShare, round2Package.signingShare);
  }

  // Add self-share.
  signingShare = Fn.add(signingShare, secretPackage.secretShare);

  // --- Step 3: Group commitment (sum of ALL parties' commitments) ---
  // Collect all commitments: received parties + own.
  const allCommitments: Point[][] = [];
  for (const [, round1Package] of receivedRound1) {
    allCommitments.push(round1Package.commitment.map((b) => Point.fromBytes(b)));
  }
  allCommitments.push(
    secretPackage.commitment.map((b) => Point.fromBytes(b)),
  );

  // Sum coefficient-by-coefficient.
  const t = secretPackage.minSigners;
  const groupCommitment: Point[] = [];
  for (let k = 0; k < t; k++) {
    let sum = Point.ZERO;
    for (const partyCommitment of allCommitments) {
      sum = sum.add(partyCommitment[k]!);
    }
    groupCommitment.push(sum);
  }

  // Aggregate verifying key = group_commitment[0].
  const aggregateVk = groupCommitment[0]!;

  // --- Step 4: Per-party verifying shares ---
  // Collect ALL party identifiers (received + self).
  const allIdentifiers: bigint[] = [];
  for (const [id] of receivedRound1) {
    allIdentifiers.push(id);
  }
  allIdentifiers.push(secretPackage.identifier);

  const preTweakVerifyingShares = new Map<bigint, Point>();
  for (const id of allIdentifiers) {
    preTweakVerifyingShares.set(id, evalPolyOnPoints(groupCommitment, id));
  }

  // --- Step 5: Post-DKG tap tweak ---
  // Mirrors `Ciphersuite::post_dkg` (lib.rs:478-491) which calls
  // `KeyPackage::tweak(None)` and `PublicKeyPackage::tweak(None)`.
  const tweakT = tapTweakScalar(aggregateVk);
  const tp = scalarBaseMul(tweakT);
  const isEven = hasEvenY(aggregateVk);
  const evenAggregate = intoEvenY(aggregateVk);

  // Post-tweak aggregate verifying key.
  const postTweakVk = evenAggregate.add(tp);
  const postTweakVkBytes = postTweakVk.toBytes(true);

  // Post-tweak current party's signing share + verifying share.
  const evenSs = isEven ? signingShare : Fn.neg(signingShare);
  const postTweakSs = Fn.add(evenSs, tweakT);

  const myPreTweakVs = preTweakVerifyingShares.get(secretPackage.identifier)!;
  const evenMyVs = isEven ? myPreTweakVs : myPreTweakVs.negate();
  const postTweakMyVs = evenMyVs.add(tp);

  // Post-tweak all parties' verifying shares (for PublicKeyPackage).
  const postTweakVerifyingShares = new Map<bigint, Uint8Array>();
  for (const [id, preTweakVs] of preTweakVerifyingShares) {
    const evenVs = isEven ? preTweakVs : preTweakVs.negate();
    postTweakVerifyingShares.set(id, evenVs.add(tp).toBytes(true));
  }

  return {
    keyPackage: {
      identifier: secretPackage.identifier,
      signingShare: postTweakSs,
      verifyingShare: postTweakMyVs.toBytes(true),
      verifyingKey: postTweakVkBytes,
      minSigners: secretPackage.minSigners,
    },
    publicKeyPackage: {
      verifyingShares: postTweakVerifyingShares,
      verifyingKey: postTweakVkBytes,
      minSigners: secretPackage.minSigners,
    },
  };
}
