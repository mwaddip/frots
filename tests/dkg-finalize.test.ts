/**
 * DKG finalize byte-equality test against the Rust DKG fixtures.
 *
 * Step 4 sub-step 6.5: verify `dkgFinalize` produces byte-identical output
 * to `frost_core::keys::dkg::part3` + `Ciphersuite::post_dkg` for every
 * party in every DKG fixture.
 *
 * The test drives ALL parties through `dkgRound1` → `dkgRound2` →
 * `dkgFinalize` and compares each party's:
 *   - signing_share (post-tweak)
 *   - verifying_share (post-tweak)
 *   - verifying_key (post-tweak, should equal `inputs.verifying_key_key`)
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
  dkgFinalize,
  dkgRound1,
  dkgRound2,
  type Round1Package,
  type Round1SecretPackage,
  type Round2Package,
  type Round2SecretPackage,
} from '../src/secp256k1-tr/dkg.ts';

const Fn = secp256k1.Point.Fn;

describe('dkgFinalize — byte equality against Rust fixtures', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);
      const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
      const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);
      const allPartyIds = fixture.dkg.part1.map((p) => BigInt(p.identifier));

      // --- Drive all parties through round 1 ---
      const rng = new FixtureRng(fixture);
      const round1Secrets = new Map<bigint, Round1SecretPackage>();
      const round1Packages = new Map<bigint, Round1Package>();

      for (const id of allPartyIds) {
        const result = dkgRound1(id, maxSigners, minSigners, rng);
        round1Secrets.set(id, result.secretPackage);
        round1Packages.set(id, result.package);
      }

      // --- Drive all parties through round 2 ---
      const round2Secrets = new Map<bigint, Round2SecretPackage>();
      // round2Outgoing[senderId][recipientId] = Round2Package
      const round2Outgoing = new Map<bigint, ReadonlyMap<bigint, Round2Package>>();

      for (const id of allPartyIds) {
        const received = new Map<bigint, Round1Package>();
        for (const [otherId, pkg] of round1Packages) {
          if (otherId !== id) received.set(otherId, pkg);
        }
        const result = dkgRound2(round1Secrets.get(id)!, received);
        round2Secrets.set(id, result.secretPackage);
        round2Outgoing.set(id, result.packages);
      }

      it('reproduces all parties\' part3 output byte-for-byte', () => {
        for (const expectedParty of fixture.dkg.part3) {
          const myId = BigInt(expectedParty.identifier);

          // Build received round1 (everyone except self).
          const receivedRound1 = new Map<bigint, Round1Package>();
          for (const [id, pkg] of round1Packages) {
            if (id !== myId) receivedRound1.set(id, pkg);
          }

          // Build received round2 (shares others sent to me).
          const receivedRound2 = new Map<bigint, Round2Package>();
          for (const [senderId, outgoing] of round2Outgoing) {
            if (senderId === myId) continue;
            const shareForMe = outgoing.get(myId);
            if (!shareForMe) {
              throw new Error(
                `expected sender ${senderId} to have a round2 share for ${myId}`,
              );
            }
            receivedRound2.set(senderId, shareForMe);
          }

          const { keyPackage, publicKeyPackage } = dkgFinalize(
            round2Secrets.get(myId)!,
            receivedRound1,
            receivedRound2,
          );

          // --- signing_share (post-tweak) ---
          expect(bytesToHex(Fn.toBytes(keyPackage.signingShare))).toBe(
            expectedParty.signing_share,
          );

          // --- verifying_share (post-tweak) ---
          expect(bytesToHex(keyPackage.verifyingShare)).toBe(
            expectedParty.verifying_share,
          );

          // --- verifying_key (post-tweak) ---
          expect(bytesToHex(keyPackage.verifyingKey)).toBe(
            expectedParty.verifying_key,
          );

          // --- All parties' verifying_key should be the same ---
          expect(bytesToHex(publicKeyPackage.verifyingKey)).toBe(
            expectedParty.verifying_key,
          );

          // --- Aggregate vk matches inputs.verifying_key_key ---
          expect(bytesToHex(keyPackage.verifyingKey)).toBe(
            fixture.inputs.verifying_key_key,
          );
        }
      });
    });
  }
});
