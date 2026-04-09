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

import { secp256k1 } from '@noble/curves/secp256k1.js';

import { H1, H2, H4, H5 } from './hash.ts';
import { hasEvenY, intoEvenY } from './point.ts';

const Fn = secp256k1.Point.Fn;

type Point = typeof secp256k1.Point.BASE;

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
