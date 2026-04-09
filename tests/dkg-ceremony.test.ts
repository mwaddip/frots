/**
 * End-to-end DKG ceremony test — Step 4 sub-step 6.6 / Step 5 (DKG flow).
 *
 * Drives ALL parties through the complete FROST(secp256k1, SHA-256-TR)
 * pipeline via the public API:
 *
 *     dkgRound1 → dkgRound2 → dkgFinalize → signRound1 → signRound2 → signAggregate
 *
 * with a single `FixtureRng` replaying the entire rng_log. Asserts the
 * final 64-byte BIP340 signature matches `final_output.sig`.
 *
 * This closes Step 5 for the DKG flow: the entire FROST port is byte-perfect
 * end-to-end through the public API for both dealer and DKG flows.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
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

const Fn = secp256k1.Point.Fn;
import {
  dkgFinalize,
  dkgRound1,
  dkgRound2,
  type Round1Package,
  type Round1SecretPackage,
  type Round2Package,
  type Round2SecretPackage,
} from '../src/secp256k1-tr/dkg.ts';

describe('DKG end-to-end ceremony — full pipeline reproduces final_output.sig', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    it(`${name}: DKG + signing pipeline matches byte-for-byte`, () => {
      const fixture = loadDkgFixture(name);
      const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
      const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);
      const allPartyIds = fixture.dkg.part1.map((p) => BigInt(p.identifier));
      const signerIds = fixture.inputs.participant_list.map(BigInt);
      const message = hexToBytes(fixture.inputs.message);

      const rng = new FixtureRng(fixture);

      // =====================================================================
      // Phase 1: DKG — all parties
      // =====================================================================

      // Round 1.
      const round1Secrets = new Map<bigint, Round1SecretPackage>();
      const round1Packages = new Map<bigint, Round1Package>();
      for (const id of allPartyIds) {
        const r = dkgRound1(id, maxSigners, minSigners, rng);
        round1Secrets.set(id, r.secretPackage);
        round1Packages.set(id, r.package);
      }

      // Round 2.
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

      // Finalize.
      const keyPackages = new Map<bigint, KeyPackage>();
      let publicKeyPackage: PublicKeyPackage | undefined;
      for (const id of allPartyIds) {
        const receivedRound1 = new Map<bigint, Round1Package>();
        for (const [otherId, pkg] of round1Packages) {
          if (otherId !== id) receivedRound1.set(otherId, pkg);
        }
        const receivedRound2 = new Map<bigint, Round2Package>();
        for (const [senderId, outgoing] of round2Outgoing) {
          if (senderId === id) continue;
          receivedRound2.set(senderId, outgoing.get(id)!);
        }
        const result = dkgFinalize(
          round2Secrets.get(id)!,
          receivedRound1,
          receivedRound2,
        );
        keyPackages.set(id, result.keyPackage);
        publicKeyPackage = result.publicKeyPackage;
      }

      // =====================================================================
      // Phase 2: Signing — only the signing quorum (participant_list)
      // =====================================================================

      // Round 1 commit.
      const nonceMap = new Map<bigint, SigningNonces>();
      const commitments: SigningCommitment[] = [];
      for (const id of signerIds) {
        const kp = keyPackages.get(id)!;
        const r1 = signRound1(kp, rng);
        nonceMap.set(id, r1.nonces);
        commitments.push(r1.commitments);
      }

      // Round 2 sign.
      const signatureShares: SignatureShare[] = [];
      for (const id of signerIds) {
        const kp = keyPackages.get(id)!;
        const nonces = nonceMap.get(id)!;
        signatureShares.push(signRound2(kp, nonces, message, commitments));
      }

      // Aggregate.
      const signature = signAggregate(
        signatureShares,
        message,
        commitments,
        publicKeyPackage!,
      );

      // =====================================================================
      // Assertions
      // =====================================================================

      expect(signature.length).toBe(64);
      expect(bytesToHex(signature)).toBe(fixture.final_output.sig);

      // Standalone BIP340 verification against the post-tweak vk.
      expect(
        verifySignature(
          signature,
          message,
          hexToBytes(fixture.inputs.verifying_key_key),
        ),
      ).toBe(true);

      // RNG fully consumed.
      expect(rng.isExhausted()).toBe(true);
    });
  }

  it('signAggregate identifies the cheater in a DKG-flow ceremony', () => {
    const fixture = loadDkgFixture('secp256k1_tr_2of3_dkg');
    const minSigners = Number(fixture.config.MIN_PARTICIPANTS);
    const maxSigners = Number(fixture.config.MAX_PARTICIPANTS);
    const allPartyIds = fixture.dkg.part1.map((p) => BigInt(p.identifier));
    const signerIds = fixture.inputs.participant_list.map(BigInt);
    const message = hexToBytes(fixture.inputs.message);

    const rng = new FixtureRng(fixture);

    // DKG rounds.
    const round1Secrets = new Map<bigint, import('../src/secp256k1-tr/dkg.ts').Round1SecretPackage>();
    const round1Packages = new Map<bigint, import('../src/secp256k1-tr/dkg.ts').Round1Package>();
    for (const id of allPartyIds) {
      const r = dkgRound1(id, maxSigners, minSigners, rng);
      round1Secrets.set(id, r.secretPackage);
      round1Packages.set(id, r.package);
    }
    const round2Outgoing = new Map<bigint, ReadonlyMap<bigint, import('../src/secp256k1-tr/dkg.ts').Round2Package>>();
    const round2Secrets = new Map<bigint, import('../src/secp256k1-tr/dkg.ts').Round2SecretPackage>();
    for (const id of allPartyIds) {
      const received = new Map<bigint, import('../src/secp256k1-tr/dkg.ts').Round1Package>();
      for (const [otherId, pkg] of round1Packages) {
        if (otherId !== id) received.set(otherId, pkg);
      }
      const r = dkgRound2(round1Secrets.get(id)!, received);
      round2Secrets.set(id, r.secretPackage);
      round2Outgoing.set(id, r.packages);
    }
    const keyPackages = new Map<bigint, KeyPackage>();
    let publicKeyPackage: PublicKeyPackage | undefined;
    for (const id of allPartyIds) {
      const recR1 = new Map<bigint, import('../src/secp256k1-tr/dkg.ts').Round1Package>();
      for (const [otherId, pkg] of round1Packages) {
        if (otherId !== id) recR1.set(otherId, pkg);
      }
      const recR2 = new Map<bigint, import('../src/secp256k1-tr/dkg.ts').Round2Package>();
      for (const [senderId, outgoing] of round2Outgoing) {
        if (senderId === id) continue;
        recR2.set(senderId, outgoing.get(id)!);
      }
      const result = dkgFinalize(round2Secrets.get(id)!, recR1, recR2);
      keyPackages.set(id, result.keyPackage);
      publicKeyPackage = result.publicKeyPackage;
    }

    // Signing rounds.
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

    // Tamper with signer 2's share.
    const culpritId = signatureShares[1]!.identifier;
    const tampered: SignatureShare[] = signatureShares.map((ss, i) =>
      i === 1 ? { identifier: ss.identifier, share: Fn.add(ss.share, 1n) } : ss,
    );

    expect(() =>
      signAggregate(tampered, message, commitments, publicKeyPackage!),
    ).toThrow(new RegExp(`invalid share.*${culpritId}`));
  });
});
