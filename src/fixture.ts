/**
 * Fixture types and loader.
 *
 * Mirrors the Rust serializable structs in `fixture-gen/src/fixture.rs`. Same
 * field names. The JSON shape is a superset of the upstream
 * `frost-secp256k1-tr/tests/helpers/vectors.json` format, with extra fields
 * for the recorded RNG byte log and the post-DKG tweak vs pre-tweak verifying
 * key distinction.
 *
 * Two top-level shapes: `DealerFixture` for the trusted-dealer flow and
 * `DkgFixture` for the no-dealer DKG flow. They share `Config`, the round 1/2
 * outputs, and the `RngCall` log entries.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// =============================================================================
// Shared types
// =============================================================================

/**
 * One captured `fill_bytes` call from the Rust `RecordingRng`. The TS replay
 * shim re-emits these in the same order.
 */
export interface RngCall {
  /** Position in the global call log (0-indexed). */
  readonly seq: number;
  /** Optional human-readable label set at call time on the Rust side. */
  readonly label?: string;
  /** Number of bytes consumed. */
  readonly len: number;
  /** The bytes that were produced, hex-encoded. */
  readonly bytes_hex: string;
}

export interface Config {
  readonly MAX_PARTICIPANTS: string;
  readonly MIN_PARTICIPANTS: string;
  readonly NUM_PARTICIPANTS: string;
  readonly name: string;
  readonly group: string;
  readonly hash: string;
  readonly flow: 'dealer' | 'dkg';
  /**
   * Whether the verifying key has had the post-DKG BIP341 unspendable taproot
   * tweak applied. True for `-tr` DKG flow; false for `-tr` dealer flow (see
   * `RUST_REFERENCE_NOTES.md` §5.1.5 for the asymmetry).
   */
  readonly tweak_applied: boolean;
  /** 32-byte seed driving the deterministic ChaCha20Rng. Hex-encoded. */
  readonly rng_seed_hex: string;
}

export interface RoundOneOutput {
  readonly identifier: number;
  /** 32-byte random bytes consumed for the hiding nonce. Hex-encoded. */
  readonly hiding_nonce_randomness: string;
  readonly binding_nonce_randomness: string;
  /** 32-byte big-endian scalar (H3 output). Hex-encoded. */
  readonly hiding_nonce: string;
  readonly binding_nonce: string;
  /** 33-byte SEC1 compressed point (`hiding_nonce * G`). Hex-encoded. */
  readonly hiding_nonce_commitment: string;
  readonly binding_nonce_commitment: string;
}

export interface RoundOneOutputs {
  readonly outputs: readonly RoundOneOutput[];
}

export interface RoundTwoOutput {
  readonly identifier: number;
  /** 32-byte big-endian scalar signature share. Hex-encoded. */
  readonly sig_share: string;
}

export interface RoundTwoOutputs {
  readonly outputs: readonly RoundTwoOutput[];
}

export interface FinalOutput {
  /** 64-byte BIP340 compact signature (`R_x || z`). Hex-encoded. */
  readonly sig: string;
}

// =============================================================================
// Signing-flow intermediates (captured from inside `round2::sign`)
// =============================================================================

/**
 * Captured intermediate values from the inside of `round2::sign` and
 * `frost::aggregate`. Each field shadows a value computed by the Rust
 * reference, exposed via the `internals` feature on `frost-core`. The TS port
 * walks the same pipeline (binding factor preimages → H1, group commitment,
 * Lagrange interpolation, H2 challenge, then `compute_signature_share`) and
 * asserts byte-for-byte equivalence against these recorded values.
 */
export interface SigningIntermediates {
  /**
   * The shared per-session prefix for every binding-factor preimage:
   * `verifying_key.serialize() || H4(message) || H5(encode_group_commitments(commitments))`.
   * Per signer, the full preimage is `prefix || identifier.serialize()`.
   * Hex-encoded; length depends on the encoded commitments size, which scales
   * linearly with the number of signers.
   */
  readonly binding_factor_input_prefix: string;
  /** Per-signer binding factor `rho_i = H1(prefix || identifier.serialize())`. */
  readonly binding_factors: readonly BindingFactorEntry[];
  /**
   * Per-signer Lagrange coefficient `lambda_i` (the no-x variant of
   * `compute_lagrange_coefficient` over the signing set, evaluated at 0).
   */
  readonly lagrange_coefficients: readonly LagrangeCoefficientEntry[];
  /**
   * Aggregate group commitment `R = Σ (D_i + rho_i · E_i)` over the signer
   * set, 33-byte SEC1 compressed. NOT yet BIP340-normalized — `compute_signature_share`
   * negates the local nonces if `R.y` is odd.
   */
  readonly group_commitment: string;
  /**
   * Schnorr challenge `c = H2(R_x || vk_x || message)`, 32-byte big-endian
   * scalar. The `-tr` ciphersuite hashes only the x-coordinates per BIP340.
   */
  readonly challenge: string;
}

export interface BindingFactorEntry {
  readonly identifier: number;
  /** 32-byte big-endian scalar. Hex-encoded. */
  readonly rho: string;
}

export interface LagrangeCoefficientEntry {
  readonly identifier: number;
  /** 32-byte big-endian scalar. Hex-encoded. */
  readonly lambda: string;
}

// =============================================================================
// Dealer fixture
// =============================================================================

export interface ParticipantShare {
  readonly identifier: number;
  /** 32-byte big-endian scalar. Hex-encoded. */
  readonly participant_share: string;
  /** 33-byte SEC1 compressed verifying share. Hex-encoded. */
  readonly verifying_share: string;
}

export interface DealerInputs {
  readonly participant_list: readonly number[];
  /** 33-byte SEC1 compressed verifying key. Hex-encoded. */
  readonly verifying_key_key: string;
  readonly verifying_key_pre_tweak?: string;
  /** Hex-encoded message bytes. */
  readonly message: string;
  readonly share_polynomial_coefficients?: readonly string[];
  readonly group_secret_key?: string;
  /**
   * The dealer's polynomial commitment, captured from any one issued
   * `SecretShare`'s `commitment()` getter (every share carries the same
   * commitment because there is one polynomial per dealer ceremony). A list
   * of `t` 33-byte SEC1 compressed points, hex-encoded, where
   * `dealer_commitment[i] = polynomial_coefficients[i] * G` and
   * `dealer_commitment[0]` is the aggregate verifying key. Used by
   * `finalizeKeygen` to construct a `SecretShare` from fixture data and run
   * VSS verification.
   */
  readonly dealer_commitment?: readonly string[];
  readonly participant_shares: readonly ParticipantShare[];
}

export interface DealerFixture {
  readonly config: Config;
  readonly inputs: DealerInputs;
  readonly round_one_outputs: RoundOneOutputs;
  readonly round_two_outputs: RoundTwoOutputs;
  readonly signing_intermediates: SigningIntermediates;
  readonly final_output: FinalOutput;
  readonly rng_log: readonly RngCall[];
}

// =============================================================================
// DKG fixture
// =============================================================================

export interface DkgInputs {
  readonly participant_list: readonly number[];
  /**
   * Operative aggregate verifying key — post-DKG-tweaked, even-y normalized.
   * 33-byte SEC1 compressed. Hex-encoded.
   */
  readonly verifying_key_key: string;
  /** Pre-tweak aggregate verifying key (`Σ commitment[0]` across parties). */
  readonly verifying_key_pre_tweak: string;
  readonly message: string;
}

export interface DkgPart1Party {
  readonly identifier: number;
  /** Per-party secret polynomial coefficients (constant term first), hex. */
  readonly secret_polynomial_coefficients: readonly string[];
  /** Per-party public commitments to those coefficients, 33-byte SEC1, hex. */
  readonly commitments: readonly string[];
  /** Proof-of-knowledge Schnorr signature `(R, z)` over the FROST DKG challenge. */
  readonly proof_of_knowledge_R: string;
  readonly proof_of_knowledge_z: string;
  /** Complete `round1::Package` re-serialized via postcard, hex. */
  readonly round1_package_bytes: string;
}

export interface DkgPart2Share {
  readonly recipient: number;
  readonly signing_share: string;
  readonly round2_package_bytes: string;
}

export interface DkgPart2Party {
  readonly identifier: number;
  readonly round2_secret_shares: readonly DkgPart2Share[];
}

export interface DkgPart3Party {
  readonly identifier: number;
  readonly signing_share: string;
  readonly verifying_share: string;
  /**
   * The aggregate group verifying key — must be IDENTICAL across all parties
   * after part3 (each party reaches the same group key independently).
   */
  readonly verifying_key: string;
}

export interface DkgData {
  readonly part1: readonly DkgPart1Party[];
  readonly part2: readonly DkgPart2Party[];
  readonly part3: readonly DkgPart3Party[];
}

export interface DkgFixture {
  readonly config: Config;
  readonly inputs: DkgInputs;
  readonly dkg: DkgData;
  readonly round_one_outputs: RoundOneOutputs;
  readonly round_two_outputs: RoundTwoOutputs;
  readonly signing_intermediates: SigningIntermediates;
  readonly final_output: FinalOutput;
  readonly rng_log: readonly RngCall[];
}

export type Fixture = DealerFixture | DkgFixture;

// =============================================================================
// Loader
// =============================================================================

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixture-gen', 'fixtures');

/**
 * Load any fixture by base name (without `.json` suffix).
 *
 * Caller must know whether the fixture is a dealer or DKG flow and use the
 * appropriate typed loader (`loadDealerFixture` / `loadDkgFixture`).
 */
function loadJsonByName<T>(name: string): T {
  const path = join(FIXTURES_DIR, `${name}.json`);
  const raw = readFileSync(path, 'utf8');
  return JSON.parse(raw) as T;
}

export function loadDealerFixture(name: string): DealerFixture {
  const fixture = loadJsonByName<DealerFixture>(name);
  if (fixture.config.flow !== 'dealer') {
    throw new Error(
      `loadDealerFixture(${name}): expected config.flow='dealer', got '${fixture.config.flow}'`,
    );
  }
  return fixture;
}

export function loadDkgFixture(name: string): DkgFixture {
  const fixture = loadJsonByName<DkgFixture>(name);
  if (fixture.config.flow !== 'dkg') {
    throw new Error(
      `loadDkgFixture(${name}): expected config.flow='dkg', got '${fixture.config.flow}'`,
    );
  }
  return fixture;
}

/** All fixture base names known to the harness. Update when fixture-gen grows. */
export const ALL_FIXTURE_NAMES = [
  'secp256k1_tr_2of3_dealer',
  'secp256k1_tr_2of3_dkg',
  'secp256k1_tr_3of5_dealer',
  'secp256k1_tr_3of5_dkg',
] as const;

export type FixtureName = (typeof ALL_FIXTURE_NAMES)[number];
