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

import { H1, H4, H5 } from './hash.ts';

const Fn = secp256k1.Point.Fn;

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
