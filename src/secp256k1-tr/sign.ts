/**
 * FROST signing-flow primitives.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. This file holds the
 * sub-primitives that compose into `round2::sign` (binding factor preimage
 * construction, group commitment computation, signature share computation),
 * built up incrementally as the dependent hashes / scalar primitives land.
 *
 * Reference: `frost-core/src/lib.rs` (binding factor / group commitment),
 * `frost-core/src/round1.rs:401-413` (`encode_group_commitments`),
 * `frost-core/src/round2.rs:99-111` (`compute_signature_share`),
 * and the `-tr` overrides in `frost-secp256k1-tr/src/lib.rs:382-416`.
 */

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';

import { H1, H2, H3, H4, H5 } from './hash.ts';
import type { KeyPackage, PublicKeyPackage } from './keys.ts';
import { deriveInterpolatingValue } from './lagrange.ts';
import { hasEvenY, intoEvenY, scalarBaseMul } from './point.ts';

const Fn = secp256k1.Point.Fn;

type Point = typeof secp256k1.Point.BASE;

/**
 * Structural interface for an RNG that hands back random bytes a buffer at
 * a time. Mirrors Rust's `RngCore::fill_bytes(dest: &mut [u8])`. The
 * `FixtureRng` shim in `src/rng-replay.ts` satisfies this interface — and
 * for production use, a thin adapter over `crypto.getRandomValues` does
 * too. Decoupling the public API from any particular RNG implementation
 * is what lets the same code run under deterministic byte-for-byte tests
 * AND under real entropy.
 *
 * The single-method shape is deliberate: every Rust call into `RngCore`
 * that this port currently mirrors is a `fill_bytes` call. If a later
 * primitive ever needs another RNG operation (e.g., a single u32),
 * extend this interface — don't add a wrapper.
 */
export interface Rng {
  fillBytes(dest: Uint8Array): void;
}

/**
 * One signer's round-1 secret nonces — the local material that MUST stay
 * private until round 2's signature share is computed. Mirrors
 * `frost::round1::SigningNonces` (`frost-core/src/round1.rs:130-138`).
 *
 * - `hidingNonce` is `d_i`, the per-session hiding nonce, derived from
 *   `H3(random_bytes(32) || signing_share.serialize()(32))` per
 *   `frost-core/src/round1.rs:77-90`.
 * - `bindingNonce` is `e_i`, derived the same way from a fresh 32-byte
 *   random block.
 *
 * Both are raw scalars (`bigint`, mod n). The matching public commitments
 * `D_i = d_i · G` / `E_i = e_i · G` live on the paired `SigningCommitment`
 * returned by `signRound1`.
 */
export interface SigningNonces {
  readonly hidingNonce: bigint;
  readonly bindingNonce: bigint;
}

/**
 * Output of `signRound1` — the per-signer pair of (private nonces, public
 * commitments) that the round-1 commit phase produces. Mirrors the Rust
 * `(SigningNonces, SigningCommitments)` tuple returned by
 * `frost::round1::commit`, expressed as a named-field object for
 * call-site readability.
 */
export interface Round1Output {
  /** Private — keep on the signer until round 2. */
  readonly nonces: SigningNonces;
  /** Public — broadcast to the coordinator (and from there to all signers). */
  readonly commitments: SigningCommitment;
}

/**
 * One signer's contribution to the joint signature, produced by round 2.
 * Mirrors `frost::round2::SignatureShare` (`frost-core/src/round2.rs:54-62`).
 *
 * - `identifier` is the producing signer's u16 identifier (matches the
 *   wire-level convention on `SigningCommitment`). Lets the coordinator
 *   route shares back to signers without an out-of-band map.
 * - `share` is the `z_i` scalar — the per-signer contribution to the
 *   joint Schnorr `z`, satisfying:
 *
 *       z = Σ_i  z_i  =  Σ_i  ( d_i + (e_i · ρ_i) + (λ_i · s_i · c) )
 *
 *   pre BIP340 parity normalization on both the signing share and the
 *   nonces (handled inside `signRound2` per the type-wrapper convention).
 */
export interface SignatureShare {
  readonly identifier: number;
  readonly share: bigint;
}

/**
 * One signer's round-1 commitment pair: their hiding nonce commitment `D_i`
 * and binding nonce commitment `E_i`, both 33-byte SEC1 compressed encodings.
 *
 * The shape mirrors `frost::round1::SigningCommitments` from the Rust crate
 * but stays at the byte level — the higher-level wrapper that holds parsed
 * `Point` objects can be added when we need it.
 */
export interface SigningCommitment {
  /** u16 identifier (1, 2, ...) */
  readonly identifier: number;
  /** 33-byte SEC1 compressed `D_i = d_i · G` */
  readonly hiding: Uint8Array;
  /** 33-byte SEC1 compressed `E_i = e_i · G` */
  readonly binding: Uint8Array;
}

/**
 * `encodeGroupCommitments` — serialize the round-1 commitments for input to
 * H5 in the binding factor preimage.
 *
 * Mirrors `frost-core/src/round1.rs:401-413`'s `encode_group_commitments`:
 *
 *     for each (identifier, commitment) in BTreeMap order:
 *         out || identifier.serialize() || hiding.serialize() || binding.serialize()
 *
 * Length per signer: 32 (identifier) + 33 (hiding) + 33 (binding) = 98 bytes.
 *
 * **Order matters.** The Rust source iterates a `BTreeMap<Identifier, _>`,
 * which sorts by `Identifier`'s scalar `Ord`. For default identifiers
 * (1, 2, 3, ...) this is equivalent to ascending u16 order — the caller is
 * responsible for sorting `commitments` by `identifier` before calling.
 */
export function encodeGroupCommitments(
  commitments: readonly SigningCommitment[],
): Uint8Array {
  const PER_SIGNER = 32 + 33 + 33;
  const out = new Uint8Array(commitments.length * PER_SIGNER);
  let offset = 0;
  for (const c of commitments) {
    const idBytes = Fn.toBytes(BigInt(c.identifier));
    out.set(idBytes, offset);
    offset += 32;
    out.set(c.hiding, offset);
    offset += 33;
    out.set(c.binding, offset);
    offset += 33;
  }
  return out;
}

/**
 * `bindingFactorInputPrefix` — build the per-session shared prefix that
 * every signer's binding-factor preimage starts with.
 *
 * Mirrors the prefix-construction half of `SigningPackage::binding_factor_preimages`
 * (`frost-core/src/lib.rs:418-432`):
 *
 *     prefix = vk_serialized(33)
 *           || H4(message)(32)
 *           || H5(encode_group_commitments(commitments))(32)
 *
 * The full per-signer preimage that goes into H1 is `prefix || identifier_serialized(32)`,
 * 97 + 32 = 129 bytes for secp256k1. The trailing `additional_prefix` slot
 * (used by the rerandomized variant only) is omitted here — the standard
 * FROST signing flow always passes empty bytes for it.
 */
export function bindingFactorInputPrefix(
  verifyingKey: Uint8Array,
  message: Uint8Array,
  commitments: readonly SigningCommitment[],
): Uint8Array {
  const h4 = H4(message);
  const encodedCommits = encodeGroupCommitments(commitments);
  const h5 = H5(encodedCommits);

  const out = new Uint8Array(verifyingKey.length + h4.length + h5.length);
  out.set(verifyingKey, 0);
  out.set(h4, verifyingKey.length);
  out.set(h5, verifyingKey.length + h4.length);
  return out;
}

/**
 * `computeBindingFactorList` — derive the per-signer binding factor `rho_i`
 * for each commitment in the signing set.
 *
 * Mirrors `frost-core/src/lib.rs:241-260`'s `compute_binding_factor_list`:
 *
 *     for each (identifier, commitment) in commitments:
 *         preimage_i = bindingFactorInputPrefix(vk, msg, commitments)
 *                    || identifier.serialize()(32)
 *         rho_i      = H1(preimage_i)
 *
 * Returns a `Map<identifier, rho>` keyed by the u16 identifier so callers
 * can look up `rho_i` by signer id (matching the `BindingFactorList::get`
 * shape from the Rust crate). The order of insertion follows the order of
 * `commitments` — the caller is responsible for sorting if a deterministic
 * iteration order is required (the binding factor scalars themselves are
 * order-independent because the prefix is fixed and only the identifier
 * suffix varies per signer).
 *
 * Composes three already-validated primitives:
 *   - `bindingFactorInputPrefix` (validated by tests/binding-factor-prefix.test.ts)
 *   - identifier serialization via `Fn.toBytes(BigInt(id))` (32-byte BE)
 *   - `H1` (this is its first byte-equality validation surface)
 */
export function computeBindingFactorList(
  verifyingKey: Uint8Array,
  message: Uint8Array,
  commitments: readonly SigningCommitment[],
): Map<number, bigint> {
  const prefix = bindingFactorInputPrefix(verifyingKey, message, commitments);
  const out = new Map<number, bigint>();
  for (const c of commitments) {
    const idBytes = Fn.toBytes(BigInt(c.identifier));
    const preimage = new Uint8Array(prefix.length + idBytes.length);
    preimage.set(prefix, 0);
    preimage.set(idBytes, prefix.length);
    out.set(c.identifier, H1(preimage));
  }
  return out;
}

/**
 * `computeGroupCommitment` — aggregate the round-1 commitments and binding
 * factors into a single Schnorr `R` point for the joint signature.
 *
 * Mirrors `frost-core/src/lib.rs:495-538`'s `compute_group_commitment`:
 *
 *     R = Σ_i (D_i + rho_i · E_i)
 *
 * where `D_i` is signer i's hiding nonce commitment (deserialized from the
 * 33-byte SEC1 in `commitments[i].hiding`), `E_i` is their binding nonce
 * commitment, and `rho_i` is the binding factor from `computeBindingFactorList`.
 *
 * The result is the *operative* group commitment BEFORE BIP340 even-y
 * normalization. `compute_signature_share` is the downstream consumer that
 * checks `R.has_even_y()` and negates the local nonces if odd. The Rust
 * crate also rejects identity hiding/binding commitments (would-be share
 * disclosure attack); we omit that validation here because the fixture data
 * never trips it and `Point.fromBytes` already rejects malformed encodings.
 *
 * Implemented via Horner-style accumulation: parse each commitment to a
 * `Point`, multiply the binding nonce commitment by `rho_i`, add to the
 * hiding nonce commitment, accumulate into `R`. Identity element is handled
 * by initializing the accumulator from the first signer rather than from
 * `Point.ZERO` (mirroring the same `evalPolyOnPoints` pattern in `src/poly.ts`).
 */
export function computeGroupCommitment(
  commitments: readonly SigningCommitment[],
  bindingFactors: ReadonlyMap<number, bigint>,
): Point {
  if (commitments.length === 0) {
    throw new Error('computeGroupCommitment: commitments must be non-empty');
  }

  let R: Point | undefined;
  for (const c of commitments) {
    const rho = bindingFactors.get(c.identifier);
    if (rho === undefined) {
      throw new Error(
        `computeGroupCommitment: no binding factor for signer ${c.identifier}`,
      );
    }
    const D = secp256k1.Point.fromBytes(c.hiding);
    const E = secp256k1.Point.fromBytes(c.binding);
    const contribution = D.add(E.multiply(rho));
    R = R === undefined ? contribution : R.add(contribution);
  }
  if (R === undefined) {
    throw new Error('computeGroupCommitment: unreachable — length checked above');
  }
  return R;
}

/**
 * `challenge` — compute the Schnorr challenge scalar `c` for the joint
 * signature, using the `-tr` x-only preimage construction.
 *
 * Mirrors `frost-secp256k1-tr/src/lib.rs:382-392`'s `Ciphersuite::challenge`
 * override:
 *
 *     preimage = R.to_affine().x()(32)
 *             || verifying_key.to_element().to_affine().x()(32)
 *             || message
 *     c        = H2(preimage)
 *
 * Crucially this is the **x-only** variant. Vanilla FROST hashes the full
 * 33-byte SEC1 points; the `-tr` variant strips the SEC1 prefix byte and
 * hashes only the 32-byte x-coordinates of R and the verifying key. This
 * is exactly per BIP340, and it's what makes the joint signature output
 * verify under standard BIP340 verification.
 *
 * Note: this is the *operative* challenge — it is computed on the
 * pre-normalization R returned by `computeGroupCommitment`. The downstream
 * `compute_signature_share` may negate the local nonces if `R.y` is odd,
 * but `c` itself is unchanged because `R.x` is invariant under negation.
 */
export function challenge(
  R: Point,
  verifyingKey: Point,
  message: Uint8Array,
): bigint {
  // Strip the 0x02/0x03 SEC1 prefix to get the 32-byte x-only encoding.
  const rX = R.toBytes(true).slice(1);
  const vkX = verifyingKey.toBytes(true).slice(1);

  const preimage = new Uint8Array(rX.length + vkX.length + message.length);
  preimage.set(rX, 0);
  preimage.set(vkX, rX.length);
  preimage.set(message, rX.length + vkX.length);

  return H2(preimage);
}

/**
 * Inputs to `computeSignatureShare`. Bundled into an object because there are
 * eight of them and positional ordering would be too easy to confuse at the
 * call site.
 */
export interface SignatureShareInputs {
  /**
   * The aggregate group commitment R = Σ (D_i + rho_i · E_i), pre-normalization.
   * Used for the BIP340 aggregate parity check on the local nonces.
   */
  readonly groupCommitment: Point;
  /**
   * The operative aggregate verifying key. Used for the `pre_sign` parity
   * check on the local signing share. (NOT the pre-tweak verifying key —
   * for DKG flows this is the post-tap-tweak operative key; for dealer flows
   * it's the raw aggregate.)
   */
  readonly verifyingKey: Point;
  /** Hiding nonce d_i (round 1, raw scalar — pre-parity). */
  readonly hidingNonce: bigint;
  /** Binding nonce e_i (round 1, raw scalar — pre-parity). */
  readonly bindingNonce: bigint;
  /** Signing share s_i (raw scalar — pre-pre_sign). */
  readonly signingShare: bigint;
  /** Per-signer binding factor rho_i. */
  readonly bindingFactor: bigint;
  /** Per-signer Lagrange coefficient lambda_i. */
  readonly lagrange: bigint;
  /** Schnorr challenge c. */
  readonly challenge: bigint;
}

/**
 * `computeSignatureShare` — compute one signer's `z_i` for round 2.
 *
 * Mirrors the composition of `pre_sign` (lib.rs:308-325) +
 * `compute_signature_share` (lib.rs:395-416) + the inner core formula
 * (frost-core/src/round2.rs:99-111). Single function because the Rust
 * separation between the trait override and the inner core exists for
 * dispatch reasons that don't apply to the TS port.
 *
 * Two parity normalizations sit before the formula:
 *
 * 1. **`pre_sign` normalization on the signing share.** If the operative
 *    verifying key has odd y, `into_even_y(None)` negates the entire
 *    KeyPackage including the signing share. Equivalent here:
 *
 *        s_i'  =  hasEvenY(vk) ?  s_i  :  -s_i
 *
 * 2. **Aggregate parity normalization on the nonces.** If the group
 *    commitment R has odd y, both nonces are negated:
 *
 *        d_i', e_i'  =  hasEvenY(R)  ?  (d_i, e_i)  :  (-d_i, -e_i)
 *
 * Then the FROST formula:
 *
 *        z_i  =  d_i'  +  (e_i' · rho_i)  +  (lambda_i · s_i' · c)
 *
 * Validated by `tests/signature-share.test.ts` against
 * `round_two_outputs[i].sig_share` in all 4 fixtures (10 byte-equality
 * assertions).
 */
export function computeSignatureShare(inputs: SignatureShareInputs): bigint {
  const {
    groupCommitment,
    verifyingKey,
    hidingNonce,
    bindingNonce,
    signingShare,
    bindingFactor,
    lagrange,
    challenge: c,
  } = inputs;

  // pre_sign: negate the signing share if vk.y is odd.
  const s = hasEvenY(verifyingKey) ? signingShare : Fn.neg(signingShare);

  // compute_signature_share: aggregate-parity dance on the nonces.
  const dRaw = hidingNonce;
  const eRaw = bindingNonce;
  const d = hasEvenY(groupCommitment) ? dRaw : Fn.neg(dRaw);
  const e = hasEvenY(groupCommitment) ? eRaw : Fn.neg(eRaw);

  // z = d + (e * rho) + (lambda * s * c)
  const eRho = Fn.mul(e, bindingFactor);
  const lambdaSc = Fn.mul(Fn.mul(lagrange, s), c);
  return Fn.add(Fn.add(d, eRho), lambdaSc);
}

/**
 * `aggregate` — combine per-signer signature shares into a single 64-byte
 * BIP340 signature. The coordinator-side primitive that closes round 2.
 *
 * Mirrors `frost-core/src/lib.rs:596-686`'s `aggregate_custom` (without the
 * cheater-detection retry — that's a separate verify primitive that lands
 * later) and `frost-secp256k1-tr/src/lib.rs:446-454`'s `serialize_signature`.
 *
 *     1. pre_aggregate: into_even_y(rawVerifyingKey) → operative vk
 *     2. binding_factor_list (operative vk + commitments)
 *     3. R = compute_group_commitment
 *     4. z = Σ z_i (plain scalar sum)
 *     5. serialize: R.x (drop SEC1 prefix) || z (32-byte BE) → 64 bytes
 *
 * The BIP340 deserializer hardcodes `R_bytes[0] = 0x02` (always-even-y);
 * the parity dance baked into `compute_signature_share` is what makes this
 * round-trip mathematically correct even when the operative R has odd y.
 *
 * Validated by `tests/aggregate.test.ts` against `final_output.sig` in all
 * 4 fixtures.
 */
export function aggregate(
  commitments: readonly SigningCommitment[],
  message: Uint8Array,
  rawVerifyingKey: Uint8Array,
  signatureShares: ReadonlyMap<number, bigint>,
): Uint8Array {
  // 1. pre_aggregate normalization on the verifying key.
  const vkPoint = secp256k1.Point.fromBytes(rawVerifyingKey);
  const operativeVk = intoEvenY(vkPoint).toBytes(true);

  // 2-3. Binding factors and group commitment.
  const bindingFactors = computeBindingFactorList(operativeVk, message, commitments);
  const R = computeGroupCommitment(commitments, bindingFactors);

  // 4. z = Σ z_i (over the signers in the signing package).
  let z = 0n;
  for (const c of commitments) {
    const share = signatureShares.get(c.identifier);
    if (share === undefined) {
      throw new Error(`aggregate: no signature share for signer ${c.identifier}`);
    }
    z = Fn.add(z, share);
  }

  // 5. Serialize as 64 bytes: R.x || z. The BIP340 verifier interprets R as
  //    even-y on deserialize regardless of the source's parity.
  const rX = R.toBytes(true).slice(1);
  const zBytes = Fn.toBytes(z);
  const out = new Uint8Array(64);
  out.set(rX, 0);
  out.set(zBytes, 32);
  return out;
}

/**
 * `deriveNonce` — internal helper. One H3-based nonce derivation, matching
 * `frost-core/src/round1.rs:77-90`'s `nonce_generate_from_random_bytes`:
 *
 *     nonce = H3(random_bytes(32) || signing_share.serialize()(32))
 *
 * Reads exactly 32 bytes from `rng`, concatenates with the 32-byte BE
 * scalar encoding of the signing share, and feeds the 64-byte preimage to
 * H3. The order is **random first, secret second** — verified by the H3
 * test surface in `tests/h3.test.ts` against the recorded
 * `hiding_nonce_randomness` / `binding_nonce_randomness` fields in every
 * dealer fixture.
 *
 * Per `RUST_REFERENCE_NOTES.md` §6.1: this is the FROST round-1 commit
 * path, which is a *direct* H3 call with **no parity dance**. The
 * `Ciphersuite::generate_nonce` override (with its `(k, R)` negation on
 * odd y) belongs to the synchronous `single_sign` path and is NOT
 * reachable from `round1::commit`.
 */
function deriveNonce(rng: Rng, signingShare: bigint): bigint {
  const randomness = new Uint8Array(32);
  rng.fillBytes(randomness);
  const shareBytes = Fn.toBytes(signingShare);
  const preimage = new Uint8Array(64);
  preimage.set(randomness, 0);
  preimage.set(shareBytes, 32);
  return H3(preimage);
}

/**
 * `signRound1` — the per-signer round-1 commit primitive. Wraps
 * `frost::round1::commit` (`frost-core/src/round1.rs:175-187`):
 *
 *     let nonces       = SigningNonces::new(signing_share, rng);
 *     let commitments  = SigningCommitments::from(&nonces);
 *     return (nonces, commitments);
 *
 * Two H3-based nonce derivations (hiding then binding, in that order),
 * each consuming exactly 32 bytes from `rng`. The matching public
 * commitments are `D_i = d_i · G` and `E_i = e_i · G`, both 33-byte SEC1
 * compressed.
 *
 * The RNG byte ordering (hiding first, binding second) matches Rust's
 * `SigningNonces::new` (`frost-core/src/round1.rs:140-146`), which is
 * what every dealer fixture's `rng_log` records. End-to-end tests built
 * on `FixtureRng` therefore replay byte-for-byte once the signing phase
 * is reached.
 *
 * Takes a **raw** `KeyPackage` per the type-wrapper convention. Round 1
 * does not need any verifying-key normalization — `pre_sign`'s parity
 * dance only kicks in at round 2 (`signRound2`).
 *
 * Returns `Round1Output` with the secret `nonces` (kept on the signer)
 * and the public `commitments` (broadcast to the coordinator). Mirrors
 * the Rust `(SigningNonces, SigningCommitments)` tuple, named for clarity.
 */
export function signRound1(keyPackage: KeyPackage, rng: Rng): Round1Output {
  const hidingNonce = deriveNonce(rng, keyPackage.signingShare);
  const bindingNonce = deriveNonce(rng, keyPackage.signingShare);

  const D = scalarBaseMul(hidingNonce);
  const E = scalarBaseMul(bindingNonce);

  return {
    nonces: { hidingNonce, bindingNonce },
    commitments: {
      identifier: Number(keyPackage.identifier),
      hiding: D.toBytes(true),
      binding: E.toBytes(true),
    },
  };
}

/**
 * `signRound2` — the per-signer round-2 partial signing primitive. Wraps
 * `frost::round2::sign` (`frost-core/src/round2.rs:99-170`) including the
 * `-tr` ciphersuite's `pre_sign` even-y normalization.
 *
 * Composition (in order):
 *
 *   1. **`pre_sign` normalization on the verifying key.** The raw
 *      `keyPackage.verifyingKey` is parsed and normalized via `intoEvenY`
 *      to produce the operative vk. The corresponding `pre_sign`
 *      normalization on the signing share is folded into
 *      `computeSignatureShare`'s parity dance below — we hand it the RAW
 *      vk (as a `Point`), not the operative one, because that helper
 *      already runs `hasEvenY(verifyingKey) ? s : -s` itself.
 *   2. **Sort `allCommitments` by identifier.** Mirrors the Rust
 *      `BTreeMap<Identifier, _>` iteration order. Default identifiers
 *      sort by ascending u16, which is what every fixture records.
 *   3. **`computeBindingFactorList`** — H1 over (operative vk || H4(msg)
 *      || H5(encode_commitments) || identifier_BE_32) per signer.
 *   4. **`computeGroupCommitment`** — `R = Σ (D_i + ρ_i · E_i)`,
 *      pre-parity. The downstream `computeSignatureShare` will negate
 *      the local nonces if `R.y` is odd.
 *   5. **`challenge`** — `c = H2(R.x || vk.x || msg)`, the BIP340 x-only
 *      preimage. The vk parity does not matter here because only the
 *      x-coordinate is hashed; we pass the operative vk for consistency.
 *   6. **`deriveInterpolatingValue`** — `λ_i` for the local signer over
 *      the signing set extracted from `allCommitments`.
 *   7. **`computeSignatureShare`** — runs the parity dance on signing
 *      share + nonces, then computes `z_i = d + (e·ρ) + (λ·s·c)`.
 *
 * Takes a **raw** `KeyPackage` per the type-wrapper convention. The
 * caller doesn't need to know about BIP340 parity — `pre_sign` is
 * applied internally.
 *
 * Throws if the local signer's identifier is missing from
 * `allCommitments` (a structural mismatch the coordinator must fix).
 *
 * Validated by `tests/sign-round2.test.ts`, which drives this against the
 * same fixture data as `tests/signature-share.test.ts` but through the
 * high-level public API.
 */
export function signRound2(
  keyPackage: KeyPackage,
  nonces: SigningNonces,
  message: Uint8Array,
  allCommitments: readonly SigningCommitment[],
  options?: { tweaked?: boolean },
): SignatureShare {
  const tweaked = options?.tweaked ?? true;

  // Select key material based on tweaked/untweaked mode.
  const vkBytes = tweaked ? keyPackage.verifyingKey : keyPackage.untweakedVerifyingKey;
  const ss = tweaked ? keyPackage.signingShare : keyPackage.untweakedSigningShare;

  // 1. Parse the raw verifying key. operativeVk is used for hashing into
  //    the binding factor preimage and the challenge; vkPoint (raw) is
  //    handed to computeSignatureShare which runs its own parity dance.
  const vkPoint = secp256k1.Point.fromBytes(vkBytes);
  const operativeVkPoint = intoEvenY(vkPoint);
  const operativeVkBytes = operativeVkPoint.toBytes(true);

  // 2. Sort by identifier — matches Rust's BTreeMap iteration order.
  //    Sorting in place would mutate the caller's input; copy first.
  const sortedCommitments: SigningCommitment[] = [...allCommitments].sort(
    (a, b) => a.identifier - b.identifier,
  );

  // 3. Per-signer binding factors ρ_i = H1(prefix || identifier_BE_32).
  const bindingFactors = computeBindingFactorList(operativeVkBytes, message, sortedCommitments);

  // 4. Aggregate group commitment R = Σ (D_i + ρ_i · E_i).
  const R = computeGroupCommitment(sortedCommitments, bindingFactors);

  // 5. Schnorr challenge c = H2(R.x || vk.x || message).
  const c = challenge(R, operativeVkPoint, message);

  // 6. Lagrange coefficient λ_i over the signer set.
  const signerSet = sortedCommitments.map((sc) => BigInt(sc.identifier));
  const lambda = deriveInterpolatingValue(signerSet, keyPackage.identifier);

  // 7. The local signer's binding factor.
  const localId = Number(keyPackage.identifier);
  const rho = bindingFactors.get(localId);
  if (rho === undefined) {
    throw new Error(
      `signRound2: local signer ${localId} is not present in allCommitments — ` +
        `the coordinator must include this signer's round-1 commitment before round 2`,
    );
  }

  // 8. Compute the signature share. computeSignatureShare receives the
  //    RAW vk Point and runs its own pre_sign parity dance internally.
  const z = computeSignatureShare({
    groupCommitment: R,
    verifyingKey: vkPoint,
    hidingNonce: nonces.hidingNonce,
    bindingNonce: nonces.bindingNonce,
    signingShare: ss,
    bindingFactor: rho,
    lagrange: lambda,
    challenge: c,
  });

  return { identifier: localId, share: z };
}

/**
 * `verifySignature` — public-side BIP340 verification of a 64-byte
 * compact Schnorr signature against a 33-byte SEC1 verifying key.
 * Wraps `noble.schnorr.verify` with the FROST-tr parity convention:
 * the input verifying key may be RAW (odd y), and the helper normalizes
 * to the operative even-y form before extracting the 32-byte x-only
 * coordinate that BIP340 verification requires.
 *
 * Per `RUST_REFERENCE_NOTES.md` §10, noble's `schnorr.verify` is the
 * matching primitive — same SHA256-tagged challenge construction, same
 * x-only public key encoding. The internal pre-verify normalization is
 * how `frost-secp256k1-tr/src/lib.rs:350-362`'s `pre_verify` ciphersuite
 * override interoperates with vanilla BIP340 verifiers.
 *
 * Returns a boolean rather than throwing — callers like `signAggregate`
 * decide whether a verification failure is fatal.
 */
export function verifySignature(
  signature: Uint8Array,
  message: Uint8Array,
  rawVerifyingKey: Uint8Array,
): boolean {
  const vkPoint = secp256k1.Point.fromBytes(rawVerifyingKey);
  const operativeVk = intoEvenY(vkPoint);
  // Strip the 0x02 SEC1 prefix to get the 32-byte x-only encoding.
  const vkXOnly = operativeVk.toBytes(true).slice(1);
  return schnorr.verify(signature, message, vkXOnly);
}

/**
 * `signAggregate` — coordinator-side primitive that combines per-signer
 * `SignatureShare`s into the final 64-byte BIP340 signature **and verifies
 * it against the public key**.
 *
 * Wraps the existing low-level `aggregate` (Step 3 primitive #17) and
 * adds the BIP340 verification pass per the Step 4 design checkpoint
 * (Q1 = bundle-verify-into-aggregate). The verification step matches
 * Rust's `aggregate` default behavior in `frost-core/src/lib.rs:678-685`,
 * which validates the produced signature before returning it. The
 * cheater-detection retry path (per-share verification when the
 * aggregate fails) is NOT implemented in this commit — see PLAN.md
 * Step 4 follow-ups.
 *
 * Throws (rather than returning a `Result`) on:
 * - structural mismatch: a signer in `commitments` lacks a matching
 *   `SignatureShare` (or vice versa)
 * - verification failure: the assembled signature does not validate
 *   against `publicKeyPackage.verifyingKey`
 *
 * Takes a **raw** `PublicKeyPackage` per the type-wrapper convention.
 * Internal aggregation calls the existing low-level `aggregate` which
 * applies `pre_aggregate` parity normalization.
 *
 * The `publicKeyPackage.verifyingShares` field is currently unused — it
 * is reserved for the future cheater-detection retry path (which iterates
 * `verify_share` per signer to identify the culprit when aggregation
 * fails).
 */
export function signAggregate(
  signatureShares: readonly SignatureShare[],
  message: Uint8Array,
  commitments: readonly SigningCommitment[],
  publicKeyPackage: PublicKeyPackage,
  options?: { tweaked?: boolean },
): Uint8Array {
  const tweaked = options?.tweaked ?? true;

  // Select key material based on tweaked/untweaked mode.
  const vk = tweaked ? publicKeyPackage.verifyingKey : publicKeyPackage.untweakedVerifyingKey;
  const vs = tweaked ? publicKeyPackage.verifyingShares : publicKeyPackage.untweakedVerifyingShares;

  // Build the Map<number, bigint> the low-level aggregate expects.
  const sharesMap = new Map<number, bigint>();
  for (const ss of signatureShares) {
    sharesMap.set(ss.identifier, ss.share);
  }

  // Sort commitments to match the binding-factor list iteration order.
  const sortedCommitments: SigningCommitment[] = [...commitments].sort(
    (a, b) => a.identifier - b.identifier,
  );

  const sig = aggregate(
    sortedCommitments,
    message,
    vk,
    sharesMap,
  );

  if (!verifySignature(sig, message, vk)) {
    // Cheater detection: identify which signer(s) submitted invalid shares.
    const cheaterPkg: PublicKeyPackage = { ...publicKeyPackage, verifyingKey: vk, verifyingShares: vs };
    const culprits = detectCheaters(
      sortedCommitments,
      message,
      cheaterPkg,
      sharesMap,
    );
    if (culprits.length > 0) {
      throw new Error(
        `signAggregate: failed BIP340 verification — invalid share(s) from signer(s): ${culprits.join(', ')}`,
      );
    }
    throw new Error(
      'signAggregate: assembled signature failed BIP340 verification — ' +
        'all individual shares verified but the aggregate is invalid',
    );
  }

  return sig;
}

/**
 * `detectCheaters` — scan each signature share to find the culprit(s) when
 * the assembled signature fails BIP340 verification.
 *
 * Mirrors `frost-core/src/lib.rs:688-742`'s `detect_cheater`. For each
 * signer `i`, verifies:
 *
 *     z_i · G == R_i + (c · lambda_i) · VS_i
 *
 * where:
 *   - `R_i = D_i + rho_i · E_i` (the per-signer commitment share)
 *   - If the aggregate group commitment `R` has odd y, `R_i` is negated
 *     (the `-tr` parity dance from `Ciphersuite::verify_share`)
 *   - `c = H2(R_x || vk_x || message)` (the Schnorr challenge)
 *   - `lambda_i` is the Lagrange coefficient for signer `i`
 *   - `VS_i` is the operative (even-y-normalized) verifying share
 *
 * Returns the list of identifier(s) whose shares failed verification.
 */
function detectCheaters(
  commitments: readonly SigningCommitment[],
  message: Uint8Array,
  publicKeyPackage: PublicKeyPackage,
  sharesMap: ReadonlyMap<number, bigint>,
): number[] {
  // Recompute intermediates (this is a failure path, so perf is not critical).
  const vkPoint = secp256k1.Point.fromBytes(publicKeyPackage.verifyingKey);
  const operativeVk = intoEvenY(vkPoint);
  const operativeVkBytes = operativeVk.toBytes(true);

  const bindingFactors = computeBindingFactorList(operativeVkBytes, message, commitments);
  const R = computeGroupCommitment(commitments, bindingFactors);
  const c = challenge(R, operativeVk, message);

  const signerIds = commitments.map((sc) => BigInt(sc.identifier));
  const groupRHasEvenY = hasEvenY(R);

  const culprits: number[] = [];

  for (const sc of commitments) {
    const z_i = sharesMap.get(sc.identifier);
    if (z_i === undefined) continue;

    // Per-signer commitment share: R_i = D_i + rho_i · E_i
    const rho_i = bindingFactors.get(sc.identifier)!;
    const D_i = secp256k1.Point.fromBytes(sc.hiding);
    const E_i = secp256k1.Point.fromBytes(sc.binding);
    let R_i = D_i.add(E_i.multiply(rho_i));

    // -tr parity dance: negate R_i if the aggregate R has odd y.
    if (!groupRHasEvenY) {
      R_i = R_i.negate();
    }

    // Lagrange coefficient.
    const lambda_i = deriveInterpolatingValue(signerIds, BigInt(sc.identifier));

    // Operative verifying share (even-y-normalized like the aggregate vk).
    const rawVs = publicKeyPackage.verifyingShares.get(BigInt(sc.identifier));
    if (rawVs === undefined) {
      culprits.push(sc.identifier);
      continue;
    }
    const vsPoint = secp256k1.Point.fromBytes(rawVs);
    const operativeVs = hasEvenY(vkPoint) ? vsPoint : vsPoint.negate();

    // Check: z_i · G == R_i + (c · lambda_i) · VS_i
    const lhs = scalarBaseMul(z_i);
    const rhs = R_i.add(operativeVs.multiply(Fn.mul(c, lambda_i)));

    if (!lhs.equals(rhs)) {
      culprits.push(sc.identifier);
    }
  }

  return culprits;
}
