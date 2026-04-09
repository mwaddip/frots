/**
 * Public API surface smoke test — closes the Step 4 dealer-flow re-export
 * pass.
 *
 * This test imports SOLELY through `src/index.ts` (not from individual
 * source files) and exercises the full dealer-flow signing pipeline. If
 * any of the high-level types or functions go missing from the public
 * re-exports, this test fails to type-check or fails at runtime.
 *
 * Acts as a regression check on the public API contract: any future
 * commit that accidentally removes an export will be caught here, even
 * if every other test (which imports directly from `src/sign.ts` /
 * `src/keys.ts`) keeps passing.
 *
 * No new crypto — pure composition over the wrappers already validated
 * by `tests/finalize-keygen.test.ts`, `tests/sign-round1.test.ts`,
 * `tests/sign-round2.test.ts`, and `tests/sign-aggregate.test.ts`.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import {
  bytesToHex,
  finalizeKeygen,
  FixtureRng,
  hexToBytes,
  loadDealerFixture,
  signAggregate,
  signRound1,
  signRound2,
  verifySignature,
  type KeyPackage,
  type PublicKeyPackage,
  type Round1Output,
  type SecretShare,
  type SignatureShare,
  type SigningCommitment,
  type SigningNonces,
} from '../src/index.ts';

const Fn = secp256k1.Point.Fn;

describe('public API surface — full dealer ceremony driven via src/index.ts only', () => {
  it('2of3 dealer fixture: every export is present and the pipeline reproduces final_output.sig', () => {
    const fx = loadDealerFixture('secp256k1_tr_2of3_dealer');
    const minSigners = Number(fx.config.MIN_PARTICIPANTS);
    const message = hexToBytes(fx.inputs.message);
    if (fx.inputs.dealer_commitment === undefined) {
      throw new Error('fixture missing dealer_commitment');
    }
    const dealerCommitmentBytes = fx.inputs.dealer_commitment.map(hexToBytes);

    // Step through each public API entry, holding intermediate values in
    // explicitly-typed locals so a missing or renamed type-export breaks
    // the type-check.
    const rng = new FixtureRng(fx);

    // Skip the dealer phase (signing key + polynomial coefficients).
    const scratch = new Uint8Array(32);
    for (let i = 0; i < minSigners; i++) rng.fillBytes(scratch);

    const keyPackages = new Map<number, KeyPackage>();
    const noncesByIdent = new Map<number, SigningNonces>();
    const commitments: SigningCommitment[] = [];

    for (const ps of fx.inputs.participant_shares) {
      if (!fx.inputs.participant_list.includes(ps.identifier)) continue;

      const secretShare: SecretShare = {
        identifier: BigInt(ps.identifier),
        signingShare: Fn.fromBytes(hexToBytes(ps.participant_share)),
        commitment: dealerCommitmentBytes,
      };

      const kp: KeyPackage = finalizeKeygen(secretShare);
      const r1: Round1Output = signRound1(kp, rng);

      keyPackages.set(ps.identifier, kp);
      noncesByIdent.set(ps.identifier, r1.nonces);
      commitments.push(r1.commitments);
    }

    const sigShares: SignatureShare[] = [];
    for (const ps of fx.inputs.participant_shares) {
      if (!fx.inputs.participant_list.includes(ps.identifier)) continue;
      const kp = keyPackages.get(ps.identifier)!;
      const nonces = noncesByIdent.get(ps.identifier)!;
      sigShares.push(signRound2(kp, nonces, message, commitments));
    }

    const verifyingShares = new Map<bigint, Uint8Array>();
    for (const ps of fx.inputs.participant_shares) {
      verifyingShares.set(BigInt(ps.identifier), hexToBytes(ps.verifying_share));
    }
    const publicKeyPackage: PublicKeyPackage = {
      verifyingShares,
      verifyingKey: hexToBytes(fx.inputs.verifying_key_key),
      minSigners,
    };

    const signature = signAggregate(sigShares, message, commitments, publicKeyPackage);

    expect(signature.length).toBe(64);
    expect(bytesToHex(signature)).toBe(fx.final_output.sig);

    // verifySignature is also part of the public surface — exercise it.
    expect(verifySignature(signature, message, publicKeyPackage.verifyingKey)).toBe(true);
  });
});
