/**
 * Lagrange interpolation coefficient byte-equality test.
 *
 * `derive_interpolating_value(signer_set, signer_id)` is the load-bearing
 * primitive for both partial-signing (`compute_signature_share` multiplies
 * the secret share by `lambda_i` to weight it for the threshold-Lagrange
 * combination) and aggregation (`verify_share` re-applies the same `lambda_i`
 * during cheater detection).
 *
 * Per `frost-core/src/lib.rs:282-353` (`compute_lagrange_coefficient` /
 * `derive_interpolating_value`), the no-x variant — evaluated at `x = 0`,
 * because identifiers are non-zero so there's no clash — uses the
 * sign-flipped form:
 *
 *     λ_i = ∏_{j ≠ i}  x_j  /  (x_j - x_i)
 *
 * (Mathematically equivalent to `∏ (-x_j) / (x_i - x_j)`; both signs
 * inverted, ratio unchanged. Rust does this to avoid needing field
 * negation.)
 *
 * Reference fixture data, sanity-checked by hand:
 *   2-of-3 (signers {1,2}):  λ_1 = 2/(2-1) = 2,           λ_2 = 1/(1-2) = -1 mod n
 *   3-of-5 (signers {1,2,3}): λ_1 = (2·3)/(1·2) = 3,       λ_2 = (1·3)/(-1·1) = -3 mod n,
 *                            λ_3 = (1·2)/(-2·-1) = 1
 *
 * Both match the recorded `signing_intermediates.lagrange_coefficients` for
 * every fixture. The test loops over all 4 fixtures × every signer; total
 * assertion count is the sum of `MIN_PARTICIPANTS` across the four ceremonies
 * = 2 + 2 + 3 + 3 = 10 byte-equality assertions.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  loadDealerFixture,
  loadDkgFixture,
  type SigningIntermediates,
} from '../src/index.ts';
import { deriveInterpolatingValue } from '../src/secp256k1-tr/lagrange.ts';

const Fn = secp256k1.Point.Fn;

function loadIntermediates(name: string): {
  participantList: readonly number[];
  intermediates: SigningIntermediates;
} {
  if (name.endsWith('_dkg')) {
    const fx = loadDkgFixture(name);
    return {
      participantList: fx.inputs.participant_list,
      intermediates: fx.signing_intermediates,
    };
  } else {
    const fx = loadDealerFixture(name);
    return {
      participantList: fx.inputs.participant_list,
      intermediates: fx.signing_intermediates,
    };
  }
}

describe('deriveInterpolatingValue — Lagrange coefficient at x=0', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    describe(name, () => {
      const { participantList, intermediates } = loadIntermediates(name);
      const signerSet = participantList.map((id) => BigInt(id));

      for (const entry of intermediates.lagrange_coefficients) {
        it(`computes lambda for signer ${entry.identifier}`, () => {
          const lambda = deriveInterpolatingValue(signerSet, BigInt(entry.identifier));
          const actual = bytesToHex(Fn.toBytes(lambda));
          expect(actual).toBe(entry.lambda);
        });
      }
    });
  }
});
