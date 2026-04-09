/**
 * DKG type-wrapper shape tests — fixture data → interface mapping.
 *
 * Step 4 sub-step 6.1: verify the DKG fixture data parses cleanly into
 * the Round1Package, Round1SecretPackage, Round2Package, and
 * Round2SecretPackage interfaces. These are smoke tests — they don't
 * exercise the round functions (which don't exist yet), they just confirm
 * the type shapes are consistent with the fixture format.
 *
 * One test per type, using the 2-of-3 DKG fixture. A second describe block
 * repeats for 3-of-5 to catch threshold-dependent size assumptions.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ALL_FIXTURE_NAMES, loadDkgFixture, hexToBytes } from '../src/index.ts';
import { evalPoly } from '../src/secp256k1-tr/poly.ts';
import type {
  Round1SecretPackage,
  Round1Package,
  Round2SecretPackage,
  Round2Package,
} from '../src/secp256k1-tr/dkg.ts';

const Fn = secp256k1.Point.Fn;

describe('DKG type shapes', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);
      const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
      const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);

      it('Round1SecretPackage — fixture part1 maps to interface', () => {
        for (const party of fixture.dkg.part1) {
          const pkg: Round1SecretPackage = {
            identifier: BigInt(party.identifier),
            polynomialCoefficients: party.secret_polynomial_coefficients.map(
              (hex) => Fn.fromBytes(hexToBytes(hex)),
            ),
            commitment: party.commitments.map((hex) => hexToBytes(hex)),
            minSigners,
            maxSigners,
          };

          // t coefficients → t commitments
          expect(pkg.polynomialCoefficients.length).toBe(minSigners);
          expect(pkg.commitment.length).toBe(minSigners);
          // Each commitment is 33-byte SEC1 compressed
          for (const c of pkg.commitment) {
            expect(c.length).toBe(33);
            // Must parse as a valid secp256k1 point
            secp256k1.Point.fromBytes(c);
          }
        }
      });

      it('Round1Package — fixture part1 maps to interface', () => {
        for (const party of fixture.dkg.part1) {
          const pkg: Round1Package = {
            identifier: BigInt(party.identifier),
            commitment: party.commitments.map((hex) => hexToBytes(hex)),
            proofOfKnowledge: {
              R: hexToBytes(party.proof_of_knowledge_R),
              z: Fn.fromBytes(hexToBytes(party.proof_of_knowledge_z)),
            },
          };

          expect(pkg.commitment.length).toBe(minSigners);
          // R is a 33-byte SEC1 point
          expect(pkg.proofOfKnowledge.R.length).toBe(33);
          secp256k1.Point.fromBytes(pkg.proofOfKnowledge.R);
          // z is a non-zero scalar (would be astronomically unlikely to be zero)
          expect(pkg.proofOfKnowledge.z).not.toBe(0n);
        }
      });

      it('Round2Package — fixture part2 maps to interface', () => {
        for (const party of fixture.dkg.part2) {
          for (const share of party.round2_secret_shares) {
            const pkg: Round2Package = {
              sender: BigInt(party.identifier),
              recipient: BigInt(share.recipient),
              signingShare: Fn.fromBytes(hexToBytes(share.signing_share)),
            };

            expect(pkg.sender).not.toBe(pkg.recipient);
            expect(pkg.signingShare).not.toBe(0n);
          }
        }
      });

      it('Round2SecretPackage — own secret share via evalPoly matches', () => {
        // The Rust round2::SecretPackage stores f_me(me). The fixture
        // doesn't record this directly, but we can compute it from the
        // part1 coefficients and verify it's a valid scalar.
        for (const party of fixture.dkg.part1) {
          const coefficients = party.secret_polynomial_coefficients.map(
            (hex) => Fn.fromBytes(hexToBytes(hex)),
          );
          const id = BigInt(party.identifier);
          const selfShare = evalPoly(coefficients, id);

          const pkg: Round2SecretPackage = {
            identifier: id,
            commitment: party.commitments.map((hex) => hexToBytes(hex)),
            secretShare: selfShare,
            minSigners,
            maxSigners,
          };

          expect(pkg.secretShare).not.toBe(0n);
          expect(pkg.commitment.length).toBe(minSigners);
        }
      });
    });
  }
});
