/**
 * FROST(secp256k1, SHA-256-TR) hash primitives.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. This file currently exposes
 * only `H3` (the nonce-derivation hash). The other H_n hashes will be added as
 * the dependent primitives are ported.
 *
 * Reference: `RUST_REFERENCE_NOTES.md` §3 (hash domain tags) and §10
 * (noble/curves API mapping).
 */

import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const N = secp256k1.Point.Fn.ORDER;

/**
 * `H3` — FROST nonce-derivation hash-to-scalar (RFC 9591 §6.5.2.2.3).
 *
 * Mirrors `frost-secp256k1-tr/src/lib.rs:268-270` exactly:
 *
 *     fn H3(m: &[u8]) -> Scalar {
 *         hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"nonce"], m)
 *     }
 *
 * which itself is `hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>` with the
 * concatenated DST (no separator between CONTEXT_STRING and the suffix) and
 * a single output element reduced mod the secp256k1 curve order `n`.
 *
 * Returns a `bigint` in `[0, n)`. Serialize via `secp256k1.Point.Fn.toBytes`
 * for the canonical 32-byte big-endian encoding.
 */
export function H3(msg: Uint8Array): bigint {
  const u = hash_to_field(msg, 1, {
    DST: 'FROST-secp256k1-SHA256-TR-v1nonce',
    p: N,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: sha256,
  });
  // count=1, m=1 → noble returns exactly one field element holding one bigint;
  // narrow for strict TS (`noUncheckedIndexedAccess`).
  const element = u[0];
  if (element === undefined || element[0] === undefined) {
    throw new Error('H3: hash_to_field returned an empty result');
  }
  return element[0];
}
