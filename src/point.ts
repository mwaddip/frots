/**
 * secp256k1 point primitives.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. This file currently exposes
 * only `scalarBaseMul` (the constant-time `scalar · G` used to turn private
 * scalars — nonces, polynomial coefficients — into public commitment points).
 * Additional point ops (`scalarMul`, `add`, BIP340 even-y normalization) will
 * land as the dependent primitives are ported.
 *
 * Reference: `RUST_REFERENCE_NOTES.md` §4 (point/scalar serialization) and
 * §10 (noble/curves API mapping).
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';

const G = secp256k1.Point.BASE;

/**
 * `scalarBaseMul` — constant-time secp256k1 base-point multiplication.
 *
 * Equivalent to Rust's `ProjectivePoint::GENERATOR * scalar` (k256 0.13.x);
 * dispatches to noble's `Point.multiply`, which is constant-time and safe
 * for secret scalars (per noble/curves §10 API mapping).
 *
 * Returns the resulting `Point` object. Callers serialize via `.toBytes(true)`
 * for the canonical 33-byte SEC1 compressed encoding.
 */
export function scalarBaseMul(scalar: bigint): typeof G {
  return G.multiply(scalar);
}
