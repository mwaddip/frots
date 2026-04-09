/**
 * Untweaked signing tests.
 *
 * Verifies that `signRound2` and `signAggregate` with `{ tweaked: false }`
 * produce valid BIP340 signatures under the **untweaked** aggregate key.
 *
 * Also validates that `untweakedVerifyingKey` matches the DKG fixture's
 * `inputs.verifying_key_pre_tweak`, confirming the pre-tweak key is
 * correctly surfaced through the public API.
 */

import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  FixtureRng,
  hexToBytes,
  loadDkgFixture,
  signAggregate,
  signRound1,
  signRound2,
  verifySignature,
  type KeyPackage,
  type PublicKeyPackage,
  type SignatureShare,
  type SigningCommitment,
  type SigningNonces,
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

/** Run the full DKG ceremony and return key material + rng (positioned for signing). */
function runDkg(fixtureName: string) {
  const fixture = loadDkgFixture(fixtureName);
  const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
  const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);
  const allPartyIds = fixture.dkg.part1.map((p) => BigInt(p.identifier));
  const signerIds = fixture.inputs.participant_list.map(BigInt);
  const message = hexToBytes(fixture.inputs.message);
  const rng = new FixtureRng(fixture);

  // Round 1
  const round1Secrets = new Map<bigint, Round1SecretPackage>();
  const round1Packages = new Map<bigint, Round1Package>();
  for (const id of allPartyIds) {
    const r = dkgRound1(id, maxSigners, minSigners, rng);
    round1Secrets.set(id, r.secretPackage);
    round1Packages.set(id, r.package);
  }

  // Round 2
  const round2Secrets = new Map<bigint, Round2SecretPackage>();
  const round2Outgoing = new Map<bigint, ReadonlyMap<bigint, Round2Package>>();
  for (const id of allPartyIds) {
    const received = new Map<bigint, Round1Package>();
    for (const [otherId, pkg] of round1Packages) {
      if (otherId !== id) received.set(otherId, pkg);
    }
    const r = dkgRound2(round1Secrets.get(id)!, received);
    round2Secrets.set(id, r.secretPackage);
    round2Outgoing.set(id, r.packages);
  }

  // Finalize
  const keyPackages = new Map<bigint, KeyPackage>();
  let publicKeyPackage: PublicKeyPackage | undefined;
  for (const id of allPartyIds) {
    const recR1 = new Map<bigint, Round1Package>();
    for (const [otherId, pkg] of round1Packages) {
      if (otherId !== id) recR1.set(otherId, pkg);
    }
    const recR2 = new Map<bigint, Round2Package>();
    for (const [senderId, outgoing] of round2Outgoing) {
      if (senderId === id) continue;
      recR2.set(senderId, outgoing.get(id)!);
    }
    const result = dkgFinalize(round2Secrets.get(id)!, recR1, recR2);
    keyPackages.set(id, result.keyPackage);
    publicKeyPackage = result.publicKeyPackage;
  }

  return { fixture, keyPackages, publicKeyPackage: publicKeyPackage!, signerIds, message, rng };
}

describe('untweaked signing', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      it('untweakedVerifyingKey matches fixture verifying_key_pre_tweak', () => {
        const { fixture, publicKeyPackage } = runDkg(name);
        expect(bytesToHex(publicKeyPackage.untweakedVerifyingKey)).toBe(
          fixture.inputs.verifying_key_pre_tweak,
        );
      });

      it('untweaked signing produces a valid BIP340 signature under the untweaked key', () => {
        const { keyPackages, publicKeyPackage, signerIds, message, rng } = runDkg(name);

        // Round 1 commit (same as tweaked — nonces are independent of key material).
        const nonceMap = new Map<bigint, SigningNonces>();
        const commitments: SigningCommitment[] = [];
        for (const id of signerIds) {
          const r1 = signRound1(keyPackages.get(id)!, rng);
          nonceMap.set(id, r1.nonces);
          commitments.push(r1.commitments);
        }

        // Round 2 — untweaked mode.
        const signatureShares: SignatureShare[] = [];
        for (const id of signerIds) {
          signatureShares.push(
            signRound2(keyPackages.get(id)!, nonceMap.get(id)!, message, commitments, { tweaked: false }),
          );
        }

        // Aggregate — untweaked mode.
        const signature = signAggregate(
          signatureShares,
          message,
          commitments,
          publicKeyPackage,
          { tweaked: false },
        );

        expect(signature.length).toBe(64);

        // Verify against the untweaked key via our wrapper.
        expect(
          verifySignature(signature, message, publicKeyPackage.untweakedVerifyingKey),
        ).toBe(true);

        // Cross-check: verify via noble's schnorr.verify directly.
        const xOnlyUntweaked = publicKeyPackage.untweakedVerifyingKey.slice(1);
        expect(schnorr.verify(signature, message, xOnlyUntweaked)).toBe(true);

        // Must NOT verify under the tweaked key.
        expect(
          verifySignature(signature, message, publicKeyPackage.verifyingKey),
        ).toBe(false);
      });

      it('tweaked signing still works (regression)', () => {
        const { fixture, keyPackages, publicKeyPackage, signerIds, message, rng } = runDkg(name);

        const nonceMap = new Map<bigint, SigningNonces>();
        const commitments: SigningCommitment[] = [];
        for (const id of signerIds) {
          const r1 = signRound1(keyPackages.get(id)!, rng);
          nonceMap.set(id, r1.nonces);
          commitments.push(r1.commitments);
        }

        const signatureShares: SignatureShare[] = [];
        for (const id of signerIds) {
          signatureShares.push(
            signRound2(keyPackages.get(id)!, nonceMap.get(id)!, message, commitments),
          );
        }

        const signature = signAggregate(signatureShares, message, commitments, publicKeyPackage);
        expect(bytesToHex(signature)).toBe(fixture.final_output.sig);
      });
    });
  }
});
