/**
 * Shamir polynomial evaluation byte-equality test against the DKG fixtures.
 *
 * The third primitive in `PLAN.md` Step 3 is the scalar-field polynomial
 * evaluation that underlies both Shamir secret sharing and the per-recipient
 * share derivation in `dkg::part2`. For a polynomial
 *
 *     f_j(x) = a_{j,0} + a_{j,1}·x + a_{j,2}·x² + ... + a_{j,t-1}·x^(t-1)  (mod n)
 *
 * with coefficients drawn from `Secp256K1ScalarField`, the per-recipient share
 * sender `j` ships to recipient `i` in DKG round 2 is exactly `f_j(i)` where
 * `i` is the recipient's identifier reduced into the scalar field. For default
 * identifiers (`1, 2, 3, ...`) the reduction is the trivial `BigInt(i)`.
 *
 * Both DKG fixtures already capture every input AND output we need:
 *   - `dkg.part1[j].secret_polynomial_coefficients` — sender j's coefficients
 *     (constant term first), captured via the `internals` feature on
 *     `frost-core` per `fixture-gen/src/ceremony.rs:277-282`.
 *   - `dkg.part2[j].round2_secret_shares[k].signing_share` — the share that
 *     sender j sent to recipient k, taken straight off the round2 outbox.
 *
 * 2-of-3 DKG: 3 senders × 2 recipients each = 6 test points.
 * 3-of-5 DKG: 5 senders × 4 recipients each = 20 test points.
 * Total: 26 byte-equality assertions covering polynomial evaluation over the
 * secp256k1 scalar field.
 *
 * Driving from the recorded coefficients (rather than chaining a separate
 * coefficient generator) isolates the test to JUST the polynomial evaluation
 * primitive — a failure pinpoints the bug to `evalPoly`, not upstream.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDkgFixture,
} from '../src/index.ts';
import { evalPoly } from '../src/poly.ts';

const Fn = secp256k1.Point.Fn;

describe('evalPoly — Shamir polynomial evaluation over Fn', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);
      const part1ByIdent = new Map(
        fixture.dkg.part1.map((p) => [p.identifier, p] as const),
      );

      for (const part2Party of fixture.dkg.part2) {
        const sender = part2Party.identifier;

        for (const share of part2Party.round2_secret_shares) {
          it(`f_${sender}(${share.recipient}) reproduces signing_share sent from ${sender} → ${share.recipient}`, () => {
            const part1Party = part1ByIdent.get(sender);
            if (!part1Party) {
              throw new Error(`no part1 entry for sender ${sender}`);
            }

            const coeffs = part1Party.secret_polynomial_coefficients.map((hex) =>
              Fn.fromBytes(hexToBytes(hex)),
            );
            const x = BigInt(share.recipient);
            const y = evalPoly(coeffs, x);
            const actual = bytesToHex(Fn.toBytes(y));

            expect(actual).toBe(share.signing_share);
          });
        }
      }
    });
  }
});
