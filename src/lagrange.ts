/**
 * Lagrange interpolation primitives over the secp256k1 scalar field.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. This file currently exposes
 * only `deriveInterpolatingValue` (the no-x variant of Lagrange interpolation
 * evaluated at zero), which is the load-bearing primitive for both partial
 * signing and signature verification:
 *
 * - In `compute_signature_share`, `lambda_i` weights the local secret share
 *   so the per-party `z_i` contributions reconstruct the joint Schnorr `z`
 *   when summed.
 * - In `verify_share` (during aggregation), the same `lambda_i` is re-applied
 *   to verify that each share is consistent with the published verifying share.
 *
 * Reference: `frost-core/src/lib.rs:282-353` (`compute_lagrange_coefficient` /
 * `derive_interpolating_value`).
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';

const Fn = secp256k1.Point.Fn;

/**
 * `deriveInterpolatingValue` — Lagrange interpolation coefficient `λ_i`
 * evaluated at `x = 0`.
 *
 * Mirrors `frost-core/src/lib.rs:340-353`'s `derive_interpolating_value`,
 * which delegates to `compute_lagrange_coefficient(set, None, x_i)`. The
 * `None` (zero-evaluated) form uses the sign-flipped Rust formulation:
 *
 *     num = ∏_{j ≠ i}  x_j
 *     den = ∏_{j ≠ i}  (x_j - x_i)
 *     λ_i = num · den⁻¹
 *
 * This is mathematically equivalent to `∏ (-x_j) / (x_i - x_j)` (the textbook
 * form `∏ (0 - x_j)/(x_i - x_j)`); both signs flipped, ratio unchanged. The
 * Rust crate writes it this way to avoid needing field negation.
 *
 * Throws if `signerSet` is empty or if `signerId` is not present in
 * `signerSet`. The Rust source uses distinct error variants
 * (`IncorrectNumberOfIdentifiers` and `UnknownIdentifier`); we collapse them
 * into a single `Error` because the TS port has no equivalent error taxonomy
 * yet.
 */
export function deriveInterpolatingValue(
  signerSet: readonly bigint[],
  signerId: bigint,
): bigint {
  if (signerSet.length === 0) {
    throw new Error('deriveInterpolatingValue: signerSet must be non-empty');
  }

  let num = 1n;
  let den = 1n;
  let xiFound = false;

  for (const xj of signerSet) {
    if (xj === signerId) {
      xiFound = true;
      continue;
    }
    num = Fn.mul(num, xj);
    den = Fn.mul(den, Fn.sub(xj, signerId));
  }

  if (!xiFound) {
    throw new Error(
      `deriveInterpolatingValue: signerId ${signerId} not found in signerSet`,
    );
  }

  return Fn.mul(num, Fn.inv(den));
}
