/**
 * DKG round 1 byte-equality test against the Rust DKG fixtures.
 *
 * Step 4 sub-step 6.2: verify `dkgRound1` produces byte-identical output
 * to `frost_core::keys::dkg::part1` for every party in every DKG fixture.
 *
 * Per the empirically confirmed rng_log layout, ALL parties run part1
 * sequentially before any signer runs round1 commit. For 2-of-3 DKG with
 * t=2, each party's part1 consumes 3 × 32-byte RNG calls:
 *   [signing_key, coeff_1, pok_nonce]
 * For 3-of-5 with t=3, each party consumes 4 × 32-byte calls:
 *   [signing_key, coeff_1, coeff_2, pok_nonce]
 *
 * The test replays the rng_log from the beginning (all part1 calls come
 * first), running `dkgRound1` for each party in order and comparing:
 *   - polynomial coefficients (secret)
 *   - commitment points (public)
 *   - proof-of-knowledge R and z
 */

import { describe, expect, it } from 'vitest';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  FixtureRng,
  loadDkgFixture,
} from '../src/index.ts';
import { dkgRound1 } from '../src/secp256k1-tr/dkg.ts';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const Fn = secp256k1.Point.Fn;

describe('dkgRound1 — byte equality against Rust fixtures', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);
      const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
      const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);

      it('reproduces all parties\' part1 output byte-for-byte', () => {
        const rng = new FixtureRng(fixture);

        for (const expected of fixture.dkg.part1) {
          const id = BigInt(expected.identifier);
          const result = dkgRound1(id, maxSigners, minSigners, rng);

          // --- Secret polynomial coefficients ---
          expect(result.secretPackage.polynomialCoefficients.length).toBe(
            expected.secret_polynomial_coefficients.length,
          );
          for (let i = 0; i < expected.secret_polynomial_coefficients.length; i++) {
            const expectedHex = expected.secret_polynomial_coefficients[i]!;
            const actualHex = bytesToHex(
              Fn.toBytes(result.secretPackage.polynomialCoefficients[i]!),
            );
            expect(actualHex).toBe(expectedHex);
          }

          // --- Public commitments ---
          expect(result.package.commitment.length).toBe(
            expected.commitments.length,
          );
          for (let i = 0; i < expected.commitments.length; i++) {
            expect(bytesToHex(result.package.commitment[i]!)).toBe(
              expected.commitments[i]!,
            );
          }

          // --- Proof-of-knowledge R ---
          expect(bytesToHex(result.package.proofOfKnowledge.R)).toBe(
            expected.proof_of_knowledge_R,
          );

          // --- Proof-of-knowledge z ---
          expect(
            bytesToHex(Fn.toBytes(result.package.proofOfKnowledge.z)),
          ).toBe(expected.proof_of_knowledge_z);

          // --- Identifier round-trip ---
          expect(result.secretPackage.identifier).toBe(id);
          expect(result.package.identifier).toBe(id);
          expect(result.secretPackage.minSigners).toBe(minSigners);
          expect(result.secretPackage.maxSigners).toBe(maxSigners);
        }
      });
    });
  }
});
