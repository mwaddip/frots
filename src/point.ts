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

/**
 * `hasEvenY` — BIP340 even-y predicate on a secp256k1 point.
 *
 * BIP340 mandates that all operative public keys and signature R points have
 * an even y-coordinate. This is the parity test the rest of the BIP340 /
 * BIP341 normalization machinery is built on.
 *
 * Implemented as a direct parity check on the affine y coordinate. noble v2
 * exposes affine `.x` / `.y` as `bigint` properties on the Point class
 * (`abstract/curve.d.ts:17-20`); we don't need to call `toAffine()` first.
 */
export function hasEvenY(p: typeof G): boolean {
  return (p.y & 1n) === 0n;
}

/**
 * `intoEvenY` — BIP340 even-y normalization on a secp256k1 point.
 *
 * Mirrors the `EvenY::into_even_y` impl in `frost-secp256k1-tr/src/lib.rs`
 * (lines 680-693 for `VerifyingKey`, lines 626-651 for the
 * `PublicKeyPackage` variant — same parity check, same negate-on-odd
 * behavior). Returns the input unchanged if `y` is even, otherwise returns
 * the additive inverse (which has the same x and the negated y).
 *
 * Negating a public key is meaningful only when paired with the matching
 * negation of any associated secret material; the seven negation points
 * documented in `RUST_REFERENCE_NOTES.md` §6 trace where this happens
 * across the FROST flows. The lone-point version exposed here is the
 * primitive used by all of them.
 */
export function intoEvenY(p: typeof G): typeof G {
  return hasEvenY(p) ? p : p.negate();
}
