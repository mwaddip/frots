/**
 * Polynomial primitives over the secp256k1 scalar field.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. This file currently exposes
 * only `evalPoly` (Shamir polynomial evaluation), which is the load-bearing
 * primitive for both trusted-dealer share derivation and `dkg::part2`'s
 * per-recipient secret share computation.
 *
 * Reference: `RUST_REFERENCE_NOTES.md` §4 (scalar field) and §10 (noble/curves
 * API mapping). The corresponding Rust live in `frost-core/src/keys.rs`'s
 * polynomial evaluation helper.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';

const Fn = secp256k1.Point.Fn;

/**
 * `evalPoly` — evaluate a polynomial over the secp256k1 scalar field.
 *
 * Coefficients are constant-term first, matching the Rust convention used by
 * `frost-core` and the `secret_polynomial_coefficients` field in our DKG
 * fixtures:
 *
 *     f(x) = c[0] + c[1]·x + c[2]·x² + ... + c[n-1]·x^(n-1)   (mod n)
 *
 * Implemented via Horner's method, which evaluates the polynomial in n
 * multiplications and n additions instead of computing each `x^i` separately.
 * Walking the coefficient slice in reverse, we accumulate
 *
 *     acc ← acc·x + c[i]   for i = n-1, n-2, ..., 0
 *
 * starting from `acc = 0`. After the first iteration `acc = c[n-1]`; after
 * the last `acc = f(x)`.
 *
 * `x` is taken as a raw `bigint` — the field operations reduce mod n
 * automatically, so no explicit reduction is required at the boundary.
 */
export function evalPoly(coefficients: readonly bigint[], x: bigint): bigint {
  if (coefficients.length === 0) {
    throw new Error('evalPoly: coefficients must be non-empty');
  }

  // Walk in reverse via a copied-and-reversed view to keep iteration clean
  // under `noUncheckedIndexedAccess` (no raw `coefficients[i]` accesses).
  const reversed = [...coefficients].reverse();
  let acc = 0n;
  for (const c of reversed) {
    acc = Fn.add(Fn.mul(acc, x), c);
  }
  return acc;
}
