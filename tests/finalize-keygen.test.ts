/**
 * `finalizeKeygen` byte-equality test — sub-step 2 of Step 4.
 *
 * Wraps the dealer-flow `KeyPackage::try_from(SecretShare)` semantics:
 *   1. VSS-verify the dealer-issued share against the polynomial commitment
 *      (composed from the already-validated `evalPolyOnPoints` primitive).
 *   2. Construct the per-party `KeyPackage` with `verifyingShare = s_i · G`
 *      and `verifyingKey = commitment[0]` (the polynomial constant term =
 *      aggregate group key, raw / un-normalized).
 *
 * Test surface: for every dealer fixture, for every participant, build a
 * `SecretShare` from `inputs.dealer_commitment` + `inputs.participant_shares[i]`,
 * call `finalizeKeygen`, and assert each resulting field matches the
 * fixture's recorded `verifying_share` and `verifying_key_key` byte-for-byte.
 *
 * Per the design lesson in `SESSION_CONTEXT.md` ("operative vs raw verifying
 * key"), the verifying key returned here is the RAW aggregate — for dealer
 * mode that means it may have odd y at our test seeds. `signRound2` (later
 * sub-step) is the place where `pre_sign` normalization happens; this test
 * deliberately checks the un-normalized output.
 *
 * 2 fixtures × (1 vk assertion + 1 minSigners assertion + N participant
 * assertions) = 12 byte-equality assertions total (2of3 contributes 6,
 * 3of5 contributes 6 — but each vk + per-share shape adds up across the
 * loops).
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import {
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
  type DealerFixture,
} from '../src/index.ts';
import { finalizeKeygen, type SecretShare } from '../src/keys.ts';

const Fn = secp256k1.Point.Fn;

function buildSecretShare(fx: DealerFixture, participantIndex: number): SecretShare {
  const dealerCommitment = fx.inputs.dealer_commitment;
  if (dealerCommitment === undefined) {
    throw new Error(
      `${fx.config.name}: fixture missing dealer_commitment — fixture-gen needs to be regenerated`,
    );
  }
  const ps = fx.inputs.participant_shares[participantIndex];
  if (ps === undefined) {
    throw new Error(`participant index ${participantIndex} out of range`);
  }
  return {
    identifier: BigInt(ps.identifier),
    signingShare: Fn.fromBytes(hexToBytes(ps.participant_share)),
    commitment: dealerCommitment.map(hexToBytes),
  };
}

describe('finalizeKeygen — dealer flow constructs raw KeyPackage with VSS check', () => {
  for (const name of ['secp256k1_tr_2of3_dealer', 'secp256k1_tr_3of5_dealer'] as const) {
    it(`${name}: every participant's KeyPackage matches the fixture`, () => {
      const fx = loadDealerFixture(name);
      const expectedVk = fx.inputs.verifying_key_key;
      const minSigners = Number(fx.config.MIN_PARTICIPANTS);

      for (let i = 0; i < fx.inputs.participant_shares.length; i++) {
        const ps = fx.inputs.participant_shares[i]!;
        const secretShare = buildSecretShare(fx, i);

        const keyPackage = finalizeKeygen(secretShare);

        // identifier round-trips through bigint cast
        expect(keyPackage.identifier).toBe(BigInt(ps.identifier));

        // signingShare unchanged from input
        expect(keyPackage.signingShare).toBe(secretShare.signingShare);

        // verifyingShare equals fixture's recorded `s_i · G`
        expect(bytesToHex(keyPackage.verifyingShare)).toBe(ps.verifying_share);

        // verifyingKey equals the raw aggregate vk (commitment[0]).
        // Dealer mode does NOT apply post_dkg, so this is the un-normalized
        // group key — it may start with 0x03 (odd y) and that is correct.
        expect(bytesToHex(keyPackage.verifyingKey)).toBe(expectedVk);

        // minSigners derived from commitment length
        expect(keyPackage.minSigners).toBe(minSigners);
      }
    });
  }

  it('rejects a tampered share with InvalidSecretShare-equivalent error', () => {
    // Negative case: flip one bit in the signing share, expect throw.
    const fx = loadDealerFixture('secp256k1_tr_2of3_dealer');
    const valid = buildSecretShare(fx, 0);
    const tampered: SecretShare = {
      identifier: valid.identifier,
      signingShare: Fn.add(valid.signingShare, 1n), // off by one — guaranteed not on the polynomial
      commitment: valid.commitment,
    };
    expect(() => finalizeKeygen(tampered)).toThrow(/VSS verification failed/);
  });
});
