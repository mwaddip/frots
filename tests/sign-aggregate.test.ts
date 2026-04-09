/**
 * `signAggregate` byte-equality test — sub-step 5 of Step 4.
 *
 * Closes the high-level public API for the dealer flow:
 *
 *     finalizeKeygen   →   signRound1   →   signRound2   →   signAggregate
 *
 * Asserts that driving the wrappers end-to-end against a `FixtureRng`
 * advanced past the dealer phase produces the **same** 64-byte BIP340
 * signature as the recorded `final_output.sig`. If this passes for every
 * dealer fixture, the high-level wrappers compose into a byte-perfect
 * port of the FROST(secp256k1, SHA-256-TR) signing pipeline through the
 * public surface — which is the precondition for Step 5 (end-to-end
 * equivalence test driving the API with the same RNG seed as Rust).
 *
 * Per the Q1=b decision (signAggregate bundles BIP340 verification by
 * default), this test also implicitly exercises the verification path on
 * every happy-path call. The negative-case test below tampers with one
 * signature share and asserts that signAggregate throws.
 *
 * Also tests the standalone `verifySignature` helper against each
 * fixture's `final_output.sig`, confirming that the public-side
 * BIP340 verification interoperates with noble's `schnorr.verify`
 * regardless of the raw vk's parity.
 *
 * 2 fixtures × (1 sig + 1 verify) + 1 negative = 5 inner assertions.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import {
  bytesToHex,
  FixtureRng,
  hexToBytes,
  loadDealerFixture,
  type DealerFixture,
  type ParticipantShare,
} from '../src/index.ts';
import {
  finalizeKeygen,
  type KeyPackage,
  type PublicKeyPackage,
  type SecretShare,
} from '../src/secp256k1-tr/keys.ts';
import {
  signAggregate,
  signRound1,
  signRound2,
  verifySignature,
  type SignatureShare,
  type SigningCommitment,
  type SigningNonces,
} from '../src/secp256k1-tr/sign.ts';

const Fn = secp256k1.Point.Fn;

function loadKeyPackage(fx: DealerFixture, ps: ParticipantShare): KeyPackage {
  const dealerCommitment = fx.inputs.dealer_commitment;
  if (dealerCommitment === undefined) {
    throw new Error(`${fx.config.name}: missing dealer_commitment`);
  }
  const secretShare: SecretShare = {
    identifier: BigInt(ps.identifier),
    signingShare: Fn.fromBytes(hexToBytes(ps.participant_share)),
    commitment: dealerCommitment.map(hexToBytes),
  };
  return finalizeKeygen(secretShare);
}

function loadPublicKeyPackage(fx: DealerFixture): PublicKeyPackage {
  const verifyingShares = new Map<bigint, Uint8Array>();
  for (const ps of fx.inputs.participant_shares) {
    verifyingShares.set(BigInt(ps.identifier), hexToBytes(ps.verifying_share));
  }
  return {
    verifyingShares,
    verifyingKey: hexToBytes(fx.inputs.verifying_key_key),
    minSigners: Number(fx.config.MIN_PARTICIPANTS),
  };
}

function skipDealerPhase(rng: FixtureRng, minSigners: number): void {
  const scratch = new Uint8Array(32);
  for (let i = 0; i < minSigners; i++) {
    rng.fillBytes(scratch);
  }
}

/**
 * Run the full high-level pipeline for one dealer fixture and return the
 * intermediate state plus the final signature. Used by both happy-path
 * and negative tests.
 */
function runFullCeremony(fx: DealerFixture): {
  signature: Uint8Array;
  signatureShares: SignatureShare[];
  commitments: SigningCommitment[];
  publicKeyPackage: PublicKeyPackage;
  message: Uint8Array;
} {
  const minSigners = Number(fx.config.MIN_PARTICIPANTS);
  const message = hexToBytes(fx.inputs.message);
  const rng = new FixtureRng(fx);
  skipDealerPhase(rng, minSigners);

  // Phase 1: per-signer finalizeKeygen + signRound1.
  const keyPackages = new Map<number, KeyPackage>();
  const nonceMap = new Map<number, SigningNonces>();
  const commitments: SigningCommitment[] = [];

  for (const ps of fx.inputs.participant_shares) {
    if (!fx.inputs.participant_list.includes(ps.identifier)) continue;
    const kp = loadKeyPackage(fx, ps);
    const r1 = signRound1(kp, rng);
    keyPackages.set(ps.identifier, kp);
    nonceMap.set(ps.identifier, r1.nonces);
    commitments.push(r1.commitments);
  }

  // Phase 2: per-signer signRound2.
  const signatureShares: SignatureShare[] = [];
  for (const ps of fx.inputs.participant_shares) {
    if (!fx.inputs.participant_list.includes(ps.identifier)) continue;
    const kp = keyPackages.get(ps.identifier)!;
    const nonces = nonceMap.get(ps.identifier)!;
    signatureShares.push(signRound2(kp, nonces, message, commitments));
  }

  // Phase 3: aggregate.
  const publicKeyPackage = loadPublicKeyPackage(fx);
  const signature = signAggregate(signatureShares, message, commitments, publicKeyPackage);

  return { signature, signatureShares, commitments, publicKeyPackage, message };
}

describe('signAggregate — full high-level pipeline reproduces final_output.sig', () => {
  for (const name of ['secp256k1_tr_2of3_dealer', 'secp256k1_tr_3of5_dealer'] as const) {
    it(`${name}: end-to-end signature matches`, () => {
      const fx = loadDealerFixture(name);
      const { signature } = runFullCeremony(fx);
      expect(signature.length).toBe(64);
      expect(bytesToHex(signature)).toBe(fx.final_output.sig);
    });

    it(`${name}: standalone verifySignature accepts the recorded signature`, () => {
      const fx = loadDealerFixture(name);
      const recorded = hexToBytes(fx.final_output.sig);
      const message = hexToBytes(fx.inputs.message);
      const rawVk = hexToBytes(fx.inputs.verifying_key_key);
      expect(verifySignature(recorded, message, rawVk)).toBe(true);
    });
  }

  it('signAggregate identifies the cheater when one share is tampered', () => {
    const fx = loadDealerFixture('secp256k1_tr_2of3_dealer');
    const { signatureShares, commitments, publicKeyPackage, message } = runFullCeremony(fx);

    // Tamper with the first share — flip the scalar by adding 1.
    const culpritId = signatureShares[0]!.identifier;
    const tampered: SignatureShare[] = signatureShares.map((ss, i) =>
      i === 0 ? { identifier: ss.identifier, share: Fn.add(ss.share, 1n) } : ss,
    );

    expect(() =>
      signAggregate(tampered, message, commitments, publicKeyPackage),
    ).toThrow(new RegExp(`invalid share.*${culpritId}`));
  });
});
