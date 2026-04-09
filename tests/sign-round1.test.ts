/**
 * `signRound1` byte-equality test — sub-step 3 of Step 4.
 *
 * Wraps the H3-based nonce derivation (Step 3 primitive #1) and the
 * `s · G` commitment computation (Step 3 primitive #2) into the public
 * round-1 commit entry point. This is the first wrapper that consumes a
 * `KeyPackage` (from sub-steps 1+2) and the first that consumes a `Rng`.
 *
 * Test surface: for every dealer fixture, drive `signRound1` with a
 * `FixtureRng` advanced past the dealer phase, then assert each signer's
 * resulting `(hidingNonce, bindingNonce, hidingCommitment, bindingCommitment)`
 * matches the recorded fields in `round_one_outputs` byte-for-byte.
 *
 * Why dealer-only: the DKG fixtures' `rng_log` interleaves DKG part1/part2
 * RNG calls with the round-1 commit calls in a more involved order. The
 * end-to-end DKG exercise lands in sub-step 6 (`dkgRound1` / `dkgRound2`
 * wrappers); for now sub-step 3's contract is the dealer flow only.
 *
 * Per `RUST_REFERENCE_NOTES.md` §6.1: round-1 commit is a *direct* H3
 * call with no parity dance — even when the resulting commitment point
 * has odd y, the recorded scalar is still `H3(random || share)` exactly.
 * This test reproduces that empirically across both dealer fixtures.
 *
 * 2 fixtures × per-signer (4 byte-equality assertions) ≈ 20 inner
 * assertions total (2 signers × 4 in 2of3, 3 signers × 4 in 3of5).
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
import { signRound1 } from '../src/secp256k1-tr/sign.ts';

const Fn = secp256k1.Point.Fn;

/**
 * Build a `KeyPackage` for one fixture participant by running the same
 * `finalizeKeygen` path the public API would. Slightly indirect, but it
 * also acts as a regression check that finalizeKeygen + signRound1 chain
 * cleanly.
 */
function loadKeyPackage(fx: DealerFixture, ps: ParticipantShare): KeyPackage {
  const dealerCommitment = fx.inputs.dealer_commitment;
  if (dealerCommitment === undefined) {
    throw new Error(
      `${fx.config.name}: fixture missing dealer_commitment — fixture-gen needs to be regenerated`,
    );
  }
  const secretShare: SecretShare = {
    identifier: BigInt(ps.identifier),
    signingShare: Fn.fromBytes(hexToBytes(ps.participant_share)),
    commitment: dealerCommitment.map(hexToBytes),
  };
  return finalizeKeygen(secretShare);
}

/**
 * Advance a `FixtureRng` past the dealer-phase calls (signing key
 * generation + polynomial coefficients) so the next `fillBytes` call lands
 * on the first round-1 commit byte block. The dealer phase consumes
 * exactly `min_signers` 32-byte calls: 1 for the SigningKey constant
 * term, then `min_signers - 1` for the additional polynomial coefficients
 * needed to define a degree-(t-1) polynomial. Verified empirically against
 * the `rng_log` `label` fields in both dealer fixtures.
 */
function skipDealerPhase(rng: FixtureRng, minSigners: number): void {
  const scratch = new Uint8Array(32);
  for (let i = 0; i < minSigners; i++) {
    rng.fillBytes(scratch);
  }
}

describe('signRound1 — H3-based nonce derivation + commitment computation', () => {
  for (const name of ['secp256k1_tr_2of3_dealer', 'secp256k1_tr_3of5_dealer'] as const) {
    it(`${name}: reproduces every signer's round-1 nonces and commitments`, () => {
      const fx = loadDealerFixture(name);
      const minSigners = Number(fx.config.MIN_PARTICIPANTS);
      const rng = new FixtureRng(fx);
      skipDealerPhase(rng, minSigners);

      // The signing ceremony walks signers in identifier order — same as
      // the order Rust's `participant_shares` BTreeMap iterates. The
      // `round_one_outputs` array is also pre-sorted by identifier.
      const r1ByIdent = new Map(
        fx.round_one_outputs.outputs.map((r1) => [r1.identifier, r1] as const),
      );

      for (const ps of fx.inputs.participant_shares) {
        if (!fx.inputs.participant_list.includes(ps.identifier)) continue;

        const kp = loadKeyPackage(fx, ps);
        const out = signRound1(kp, rng);

        const r1 = r1ByIdent.get(ps.identifier);
        if (!r1) {
          throw new Error(`no round_one_outputs entry for identifier ${ps.identifier}`);
        }

        // Identifier round-trips through the bigint→number boundary.
        expect(out.commitments.identifier).toBe(ps.identifier);

        // Hiding nonce scalar matches H3(hiding_randomness || share).
        expect(bytesToHex(Fn.toBytes(out.nonces.hidingNonce))).toBe(r1.hiding_nonce);

        // Binding nonce scalar matches H3(binding_randomness || share).
        expect(bytesToHex(Fn.toBytes(out.nonces.bindingNonce))).toBe(r1.binding_nonce);

        // Hiding commitment = hidingNonce · G, 33-byte SEC1.
        expect(out.commitments.hiding.length).toBe(33);
        expect(bytesToHex(out.commitments.hiding)).toBe(r1.hiding_nonce_commitment);

        // Binding commitment = bindingNonce · G, 33-byte SEC1.
        expect(out.commitments.binding.length).toBe(33);
        expect(bytesToHex(out.commitments.binding)).toBe(r1.binding_nonce_commitment);
      }
    });
  }
});
