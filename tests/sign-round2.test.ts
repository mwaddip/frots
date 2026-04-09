/**
 * `signRound2` byte-equality test — sub-step 4 of Step 4.
 *
 * Composes the high-level public API end-to-end for the dealer flow:
 *
 *     finalizeKeygen          (sub-step 2)
 *         ↓
 *     signRound1              (sub-step 3, FixtureRng-driven)
 *         ↓
 *     signRound2              (sub-step 4, this test)
 *
 * Asserts that every signer's `SignatureShare.share` matches the recorded
 * `round_two_outputs[i].sig_share` byte-for-byte. This is the same byte
 * surface as the existing `tests/signature-share.test.ts` (which targets
 * the low-level `computeSignatureShare`), but driven by the high-level
 * wrapper. If the two tests both pass, the wrapper composes correctly
 * AND the parity normalization is being applied at the right layer.
 *
 * Per the type-wrapper convention (see src/keys.ts header):
 * `signRound2` takes a RAW KeyPackage and applies `pre_sign` internally.
 * For dealer fixtures the raw vk has odd y at our test seeds — so this
 * test exercises the `pre_sign` parity-on-share negation path on every
 * call.
 *
 * 2 fixtures × N signers byte-equality assertions (2 + 3 = 5 inner
 * `expect(share).toBe(recorded)` checks).
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
import { finalizeKeygen, type KeyPackage, type SecretShare } from '../src/secp256k1-tr/keys.ts';
import {
  signRound1,
  signRound2,
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

function skipDealerPhase(rng: FixtureRng, minSigners: number): void {
  const scratch = new Uint8Array(32);
  for (let i = 0; i < minSigners; i++) {
    rng.fillBytes(scratch);
  }
}

describe('signRound2 — end-to-end finalizeKeygen → signRound1 → signRound2', () => {
  for (const name of ['secp256k1_tr_2of3_dealer', 'secp256k1_tr_3of5_dealer'] as const) {
    it(`${name}: every signer's share matches round_two_outputs.sig_share`, () => {
      const fx = loadDealerFixture(name);
      const minSigners = Number(fx.config.MIN_PARTICIPANTS);
      const message = hexToBytes(fx.inputs.message);
      const rng = new FixtureRng(fx);
      skipDealerPhase(rng, minSigners);

      // Phase 1: every participant runs finalizeKeygen + signRound1.
      // Collect both private nonces (for round 2) and public commitments
      // (broadcast to all signers).
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

      // Phase 2: every participant runs signRound2 against the full
      // commitment set, producing a SignatureShare.
      const sharesByIdent = new Map<number, bigint>();
      for (const ps of fx.inputs.participant_shares) {
        if (!fx.inputs.participant_list.includes(ps.identifier)) continue;
        const kp = keyPackages.get(ps.identifier)!;
        const nonces = nonceMap.get(ps.identifier)!;
        const sigShare = signRound2(kp, nonces, message, commitments);

        expect(sigShare.identifier).toBe(ps.identifier);
        sharesByIdent.set(sigShare.identifier, sigShare.share);
      }

      // Phase 3: assert each share against the recorded fixture.
      for (const r2 of fx.round_two_outputs.outputs) {
        const actual = sharesByIdent.get(r2.identifier);
        if (actual === undefined) {
          throw new Error(`signRound2 produced no share for identifier ${r2.identifier}`);
        }
        expect(bytesToHex(Fn.toBytes(actual))).toBe(r2.sig_share);
      }
    });
  }

  it('throws when local signer is missing from allCommitments', () => {
    const fx = loadDealerFixture('secp256k1_tr_2of3_dealer');
    const message = hexToBytes(fx.inputs.message);
    const rng = new FixtureRng(fx);
    skipDealerPhase(rng, Number(fx.config.MIN_PARTICIPANTS));

    const ps0 = fx.inputs.participant_shares[0]!;
    const kp0 = loadKeyPackage(fx, ps0);
    const r1_0 = signRound1(kp0, rng);

    const ps1 = fx.inputs.participant_shares[1]!;
    const kp1 = loadKeyPackage(fx, ps1);
    const r1_1 = signRound1(kp1, rng);

    // Pass only signer 1's commitment, then ask signer 0 to sign — the
    // local signer is missing from allCommitments → throw. The exact
    // error is whichever sub-primitive notices first; in practice it's
    // `deriveInterpolatingValue`'s "signerId not found in signerSet"
    // because Lagrange runs before the binding-factor lookup.
    expect(() => signRound2(kp0, r1_0.nonces, message, [r1_1.commitments])).toThrow(
      /not (found|present)/,
    );
  });
});
