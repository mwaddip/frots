//! Serializable fixture types.
//!
//! The JSON shape is a **superset** of the existing
//! `frost-secp256k1-tr/tests/helpers/vectors.json` format used by the upstream
//! Rust test runner. Same field names where they overlap, plus:
//!
//! - `config.flow` — `"dealer"` or `"dkg"`
//! - `config.rng_seed_hex` — the seed driving the deterministic ChaCha20 RNG
//! - `config.tweak_applied` — whether the verifying key has been post-DKG taproot-tweaked
//! - `inputs.verifying_key_pre_tweak` — present when the flow tweaks the key, for cross-checking
//! - `rng_log` — the full byte-by-byte capture from `RecordingRng`, with optional phase labels
//!
//! Keeping the overlap with the upstream format means our generated fixtures
//! can in principle be fed back into `frost_core::tests::vectors::check_sign_with_test_vectors`
//! as a sanity check that the captured intermediate values are self-consistent.

use serde::Serialize;

use crate::recording_rng::RngCall;

/// Top-level fixture document.
#[derive(Debug, Serialize)]
pub struct Fixture {
    pub config: Config,
    pub inputs: Inputs,
    pub round_one_outputs: RoundOneOutputs,
    pub round_two_outputs: RoundTwoOutputs,
    /// Captured intermediates from `round2::sign`'s internal pipeline:
    /// binding factors, Lagrange coefficients, the group commitment R, and
    /// the H2 challenge c. Lets the TS port test each sub-primitive against
    /// the Rust reference in isolation rather than only checking the final
    /// `sig_share` end-to-end.
    pub signing_intermediates: SigningIntermediates,
    pub final_output: FinalOutput,
    pub rng_log: Vec<RngCall>,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
pub struct Config {
    /// Total number of participants in the key (max_signers in the FROST API)
    pub MAX_PARTICIPANTS: String,
    /// Threshold required to sign (min_signers in the FROST API)
    pub MIN_PARTICIPANTS: String,
    /// Number of participants actually used in the signing ceremony
    pub NUM_PARTICIPANTS: String,
    /// Ciphersuite display name
    pub name: String,
    /// Group identifier
    pub group: String,
    /// Hash identifier
    pub hash: String,
    /// `"dealer"` or `"dkg"`
    pub flow: String,
    /// Whether the verifying key in `inputs.verifying_key_key` has had the
    /// post-DKG BIP341 unspendable taproot tweak applied. For -tr DKG flows
    /// this is true; for -tr dealer flows this is **false** because
    /// `Ciphersuite::post_generate` is the default no-op (verified empirically).
    pub tweak_applied: bool,
    /// 32-byte seed driving the deterministic ChaCha20Rng wrapped by `RecordingRng`
    pub rng_seed_hex: String,
}

#[derive(Debug, Serialize)]
pub struct Inputs {
    /// Identifiers of the signers participating in the signing ceremony
    pub participant_list: Vec<u16>,
    /// Operative aggregate verifying key (33-byte SEC1 compressed, hex)
    pub verifying_key_key: String,
    /// Pre-tweak aggregate verifying key, when distinct from the operative one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_key_pre_tweak: Option<String>,
    /// Hex-encoded message bytes
    pub message: String,
    /// Hex-encoded scalar coefficients of the dealer polynomial (excluding the constant term).
    /// Only present in dealer flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_polynomial_coefficients: Option<Vec<String>>,
    /// Hex-encoded group secret key (only present in dealer flow — DKG never reveals
    /// the group secret to any single party).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_secret_key: Option<String>,
    /// Per-participant secret shares
    pub participant_shares: Vec<ParticipantShare>,
}

#[derive(Debug, Serialize)]
pub struct ParticipantShare {
    pub identifier: u16,
    /// 32-byte big-endian scalar (hex)
    pub participant_share: String,
    /// 33-byte SEC1 compressed verifying share (hex)
    pub verifying_share: String,
}

#[derive(Debug, Serialize)]
pub struct RoundOneOutputs {
    pub outputs: Vec<RoundOneOutput>,
}

#[derive(Debug, Serialize)]
pub struct RoundOneOutput {
    pub identifier: u16,
    /// 32-byte random bytes consumed for the hiding nonce (hex). Combined with the
    /// signing share via H3 to derive `hiding_nonce`.
    pub hiding_nonce_randomness: String,
    /// 32-byte random bytes consumed for the binding nonce (hex)
    pub binding_nonce_randomness: String,
    /// 32-byte big-endian scalar (hex) — the H3 output
    pub hiding_nonce: String,
    /// 32-byte big-endian scalar (hex)
    pub binding_nonce: String,
    /// 33-byte SEC1 compressed point: hiding_nonce * G
    pub hiding_nonce_commitment: String,
    /// 33-byte SEC1 compressed point: binding_nonce * G
    pub binding_nonce_commitment: String,
}

#[derive(Debug, Serialize)]
pub struct RoundTwoOutputs {
    pub outputs: Vec<RoundTwoOutput>,
}

#[derive(Debug, Serialize)]
pub struct RoundTwoOutput {
    pub identifier: u16,
    /// 32-byte big-endian scalar signature share (hex)
    pub sig_share: String,
}

#[derive(Debug, Serialize)]
pub struct FinalOutput {
    /// 64-byte BIP340 compact signature (hex): `R_x (32) || z (32)`
    pub sig: String,
}

// =====================================================================
// Signing-flow intermediates
// =====================================================================

/// Captured intermediate values from the inside of `round2::sign` and
/// `frost::aggregate`. Each field shadows a value computed by the Rust
/// reference, exposed via the `internals` feature on `frost-core`.
///
/// The TS port walks the same pipeline (binding factor preimages → H1 →
/// rho_i, group commitment, Lagrange interpolation → lambda_i, H2 → c,
/// `compute_signature_share`) and asserts byte-for-byte equivalence
/// against these recorded values, isolating each sub-primitive.
#[derive(Debug, Serialize)]
pub struct SigningIntermediates {
    /// The shared per-session prefix for every binding-factor preimage:
    /// `verifying_key.serialize() || H4(message) || H5(encode_group_commitments(commitments))`.
    /// Per signer, the full preimage is `prefix || identifier.serialize()`.
    /// Hex-encoded. (Length depends on the encoded commitments size, which
    /// scales linearly with the number of signers.)
    pub binding_factor_input_prefix: String,
    /// Per-signer binding factor `rho_i = H1(prefix || identifier.serialize())`.
    pub binding_factors: Vec<BindingFactorEntry>,
    /// Per-signer Lagrange coefficient `lambda_i = derive_interpolating_value(signer_set, identifier)`.
    pub lagrange_coefficients: Vec<LagrangeCoefficientEntry>,
    /// The aggregate group commitment `R = Σ (D_i + rho_i · E_i)` over the
    /// signer set, 33-byte SEC1 compressed (hex). This is the operative R
    /// before any BIP340 even-y normalization — `compute_signature_share`
    /// negates the local nonces if `R.y` is odd.
    pub group_commitment: String,
    /// The Schnorr challenge `c = H2(R_x || vk_x || message)`, 32-byte
    /// big-endian scalar (hex). The `-tr` ciphersuite hashes only the
    /// x-coordinates of R and vk per BIP340.
    pub challenge: String,
}

#[derive(Debug, Serialize)]
pub struct BindingFactorEntry {
    pub identifier: u16,
    /// 32-byte big-endian scalar (hex)
    pub rho: String,
}

#[derive(Debug, Serialize)]
pub struct LagrangeCoefficientEntry {
    pub identifier: u16,
    /// 32-byte big-endian scalar (hex)
    pub lambda: String,
}

// =====================================================================
// DKG fixture types (no-dealer flow)
// =====================================================================

/// Top-level DKG fixture document. Same overall shape as [`Fixture`] but with
/// a `dkg` section instead of `inputs.share_polynomial_coefficients` and
/// `tweak_applied = true` (the DKG flow runs `Ciphersuite::post_dkg`, which
/// `frost-secp256k1-tr` overrides to apply the BIP341 unspendable tweak).
#[derive(Debug, Serialize)]
pub struct DkgFixture {
    pub config: Config,
    pub inputs: DkgInputs,
    pub dkg: DkgData,
    pub round_one_outputs: RoundOneOutputs,
    pub round_two_outputs: RoundTwoOutputs,
    /// Captured signing-flow intermediates — see [`Fixture::signing_intermediates`].
    pub signing_intermediates: SigningIntermediates,
    pub final_output: FinalOutput,
    pub rng_log: Vec<RngCall>,
}

#[derive(Debug, Serialize)]
pub struct DkgInputs {
    /// Identifiers of the signers participating in the signing ceremony
    pub participant_list: Vec<u16>,
    /// Operative aggregate verifying key — post-DKG-tweaked, even-y normalized.
    /// 33-byte SEC1 compressed (hex). This is what signatures verify against.
    pub verifying_key_key: String,
    /// The pre-tweak aggregate verifying key — `Σ commitment[0]` across parties,
    /// before `post_dkg`'s tap tweak. 33-byte SEC1 compressed (hex).
    pub verifying_key_pre_tweak: String,
    /// Hex-encoded message bytes
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DkgData {
    pub part1: Vec<DkgPart1Party>,
    pub part2: Vec<DkgPart2Party>,
    pub part3: Vec<DkgPart3Party>,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
pub struct DkgPart1Party {
    pub identifier: u16,
    /// The participant's secret polynomial coefficients (constant term first).
    /// `t` 32-byte big-endian scalars (hex). MUST NOT leave the participant in
    /// a real protocol — captured here only because we control all parties in
    /// the fixture.
    pub secret_polynomial_coefficients: Vec<String>,
    /// Public commitments to those coefficients: `t` 33-byte SEC1 compressed
    /// points (hex), where `commitments[i] = coefficients[i] * G`.
    pub commitments: Vec<String>,
    /// Proof-of-knowledge of the constant term, as a Schnorr signature
    /// `(R, z)` over the FROST DKG challenge. Capital R/z follow standard
    /// crypto notation.
    pub proof_of_knowledge_R: String,
    pub proof_of_knowledge_z: String,
    /// The complete `round1::Package` re-serialized via postcard (hex). This is
    /// the byte-level ground truth for inter-language testing.
    pub round1_package_bytes: String,
}

#[derive(Debug, Serialize)]
pub struct DkgPart2Party {
    pub identifier: u16,
    /// `round2_packages[recipient_id]` is the secret share polynomial-evaluated
    /// at the recipient's identifier: a 32-byte big-endian scalar (hex).
    pub round2_secret_shares: Vec<DkgPart2Share>,
}

#[derive(Debug, Serialize)]
pub struct DkgPart2Share {
    pub recipient: u16,
    pub signing_share: String,
    /// The complete `round2::Package` re-serialized via postcard (hex)
    pub round2_package_bytes: String,
}

#[derive(Debug, Serialize)]
pub struct DkgPart3Party {
    pub identifier: u16,
    /// The participant's final signing share: 32-byte big-endian scalar (hex).
    /// Equal to `Σ_j eval(f_j, identifier)` where the sum is over all parties.
    pub signing_share: String,
    /// The participant's verifying share (signing_share * G): 33-byte SEC1 (hex)
    pub verifying_share: String,
    /// The aggregate group verifying key — should be IDENTICAL across all parties
    /// after part3 (each party reaches the same group key independently).
    pub verifying_key: String,
}

