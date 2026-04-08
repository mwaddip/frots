/**
 * VSS (Feldman/Pedersen) share verification byte-equality test.
 *
 * The fundamental verifiable-secret-sharing invariant: when sender `j` ships
 * share `s_{j,i} = f_j(i)` to recipient `i`, the recipient can verify the
 * share against j's PUBLIC commitments
 * `[A_{j,0}, A_{j,1}, ..., A_{j,t-1}] = [a_{j,k} · G]_k`
 * (which everyone sees) WITHOUT knowing the secret coefficients, by checking:
 *
 *     s_{j,i} · G  ?=  Σ_k A_{j,k} · i^k
 *
 * The right-hand side is "polynomial evaluation in the exponent" — same Horner
 * structure as `evalPoly` but operating on points (with point addition and
 * constant-time scalar multiplication) instead of scalars. This is the new
 * primitive `evalPolyOnPoints` exposed by `src/poly.ts`.
 *
 * Both sides of the equality are derivable from already-recorded fixture
 * data:
 *   - LHS:  scalarBaseMul(part2[j].round2_secret_shares[i].signing_share)
 *   - RHS:  evalPolyOnPoints(part1[j].commitments, BigInt(i))
 *
 * 2-of-3 DKG: 6 (sender, recipient) pairs.
 * 3-of-5 DKG: 20 pairs.
 * Total: 26 byte-equality assertions, each composing scalarBaseMul +
 * evalPolyOnPoints + 33-byte SEC1 serialization.
 *
 * If a test fails, the strongly-suspect culprit is `evalPolyOnPoints` (the
 * NEW primitive) — `scalarBaseMul` is already validated against 10 byte
 * equality points, and the recorded commitments themselves are checked for
 * internal consistency (each commitment[k] should be coefficient[k] · G,
 * which downstream tests will pin separately if needed).
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDkgFixture,
} from '../src/index.ts';
import { scalarBaseMul } from '../src/point.ts';
import { evalPolyOnPoints } from '../src/poly.ts';

const Fn = secp256k1.Point.Fn;
const Point = secp256k1.Point;

describe('VSS share verification — s · G == Σ A_k · i^k', () => {
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
          it(`s_${sender}→${share.recipient} · G == Σ A_${sender},k · ${share.recipient}^k`, () => {
            const part1Party = part1ByIdent.get(sender);
            if (!part1Party) {
              throw new Error(`no part1 entry for sender ${sender}`);
            }

            const commitments = part1Party.commitments.map((hex) =>
              Point.fromBytes(hexToBytes(hex)),
            );
            const s = Fn.fromBytes(hexToBytes(share.signing_share));
            const i = BigInt(share.recipient);

            const lhs = scalarBaseMul(s);
            const rhs = evalPolyOnPoints(commitments, i);

            // Compare via canonical 33-byte SEC1 compressed encoding
            expect(bytesToHex(lhs.toBytes(true))).toBe(bytesToHex(rhs.toBytes(true)));
          });
        }
      }
    });
  }
});
