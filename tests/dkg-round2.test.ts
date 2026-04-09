/**
 * DKG round 2 byte-equality test against the Rust DKG fixtures.
 *
 * Step 4 sub-step 6.3+6.4: verify `dkgRound2` produces byte-identical
 * round 2 secret shares to `frost_core::keys::dkg::part2` for every party
 * in every DKG fixture.
 *
 * The test first runs `dkgRound1` for ALL parties (consuming part1 rng_log
 * entries) to produce the Round1SecretPackage + Round1Package per party,
 * then drives `dkgRound2` for each party and compares:
 *   - Per-recipient signing shares against `dkg.part2[i].round2_secret_shares`
 *
 * Also validates that `dkgVerifyProofOfKnowledge` accepts valid PoKs and
 * rejects tampered ones.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  FixtureRng,
  loadDkgFixture,
} from '../src/index.ts';
import {
  dkgRound1,
  dkgRound2,
  dkgVerifyProofOfKnowledge,
  type Round1Package,
  type Round1SecretPackage,
} from '../src/secp256k1-tr/dkg.ts';

const Fn = secp256k1.Point.Fn;

describe('dkgRound2 — byte equality against Rust fixtures', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);
      const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
      const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);

      // Run all parties through dkgRound1 first.
      const rng = new FixtureRng(fixture);
      const secretPackages = new Map<bigint, Round1SecretPackage>();
      const round1Packages = new Map<bigint, Round1Package>();

      for (const party of fixture.dkg.part1) {
        const id = BigInt(party.identifier);
        const result = dkgRound1(id, maxSigners, minSigners, rng);
        secretPackages.set(id, result.secretPackage);
        round1Packages.set(id, result.package);
      }

      it('dkgVerifyProofOfKnowledge accepts all valid PoKs', () => {
        for (const [, pkg] of round1Packages) {
          expect(() => dkgVerifyProofOfKnowledge(pkg)).not.toThrow();
        }
      });

      it('dkgVerifyProofOfKnowledge rejects a tampered PoK', () => {
        const [, firstPkg] = [...round1Packages.entries()][0]!;
        const tampered: Round1Package = {
          ...firstPkg,
          proofOfKnowledge: {
            ...firstPkg.proofOfKnowledge,
            z: Fn.add(firstPkg.proofOfKnowledge.z, 1n),
          },
        };
        expect(() => dkgVerifyProofOfKnowledge(tampered)).toThrow(
          /invalid proof of knowledge/,
        );
      });

      it('reproduces all parties\' round2 secret shares byte-for-byte', () => {
        for (const expectedParty of fixture.dkg.part2) {
          const myId = BigInt(expectedParty.identifier);
          const mySecret = secretPackages.get(myId)!;

          // Build the received round1 packages map (everyone except self).
          const received = new Map<bigint, Round1Package>();
          for (const [id, pkg] of round1Packages) {
            if (id !== myId) received.set(id, pkg);
          }

          const result = dkgRound2(mySecret, received);

          // Compare each recipient's signing share.
          for (const expectedShare of expectedParty.round2_secret_shares) {
            const recipientId = BigInt(expectedShare.recipient);
            const actualPkg = result.packages.get(recipientId);
            expect(actualPkg).toBeDefined();
            expect(bytesToHex(Fn.toBytes(actualPkg!.signingShare))).toBe(
              expectedShare.signing_share,
            );
            expect(actualPkg!.sender).toBe(myId);
            expect(actualPkg!.recipient).toBe(recipientId);
          }

          // Number of output packages should be maxSigners - 1 (all others).
          expect(result.packages.size).toBe(maxSigners - 1);

          // Secret package round-trip checks.
          expect(result.secretPackage.identifier).toBe(myId);
          expect(result.secretPackage.minSigners).toBe(minSigners);
          expect(result.secretPackage.maxSigners).toBe(maxSigners);
        }
      });
    });
  }
});
