/**
 * BIP341 unspendable-tweak composite test against the DKG fixtures.
 *
 * Validates the post-DKG pipeline that turns a freshly-aggregated FROST
 * verifying key into the operative one — the most -tr-specific piece of the
 * ciphersuite. Per `frost-secp256k1-tr/src/lib.rs:751-792` and
 * `RUST_REFERENCE_NOTES.md` §5.1 + §5.2 + §6, the pipeline applied to the
 * aggregate verifying key by `Tweak::PublicKeyPackage::tweak(None)` is:
 *
 *   1. t = tap_tweak_scalar(x_only(P))         // BIP341 unspendable tweak
 *   2. P_even = into_even_y(P)                 // negate iff y is odd
 *   3. Q = P_even + t·G                        // operative aggregate key
 *
 * Note that step 1 uses the ORIGINAL P (not P_even); since the tap tweak only
 * consumes the x-coordinate and negation preserves x, this is equivalent to
 * using P_even — but mirroring the Rust order keeps the port byte-precise.
 *
 * Both DKG fixtures already capture P (`verifying_key_pre_tweak` = the raw
 * Σ_j commitment_j[0] aggregate, with no normalization or tweak applied) and
 * Q (`verifying_key_key` = the post-`Tweak` operative key). 2 fixtures = 2
 * byte-equality assertions, each composing FOUR primitives:
 *
 *   intoEvenY  +  tapTweakScalar  +  scalarBaseMul  +  Point.add
 *
 * If a test fails, the strongly-suspect culprits are intoEvenY (parity
 * check) or tapTweakScalar (the BIP340 tagged hash). scalarBaseMul and
 * Point.add are already validated against earlier byte-equality tests.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDkgFixture,
} from '../src/index.ts';
import { evalPoly, evalPolyOnPoints } from '../src/poly.ts';
import { applyDkgTweakToPubkey, applyDkgTweakToShare } from '../src/tweak.ts';

const Point = secp256k1.Point;
const Fn = Point.Fn;

describe('post_dkg verifying-key tweak — applyDkgTweakToPubkey', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    it(`${name}: applyDkgTweakToPubkey(verifying_key_pre_tweak) == verifying_key_key`, () => {
      const fixture = loadDkgFixture(name);

      const preTweak = Point.fromBytes(hexToBytes(fixture.inputs.verifying_key_pre_tweak));
      const tweaked = applyDkgTweakToPubkey(preTweak);

      const actual = bytesToHex(tweaked.toBytes(true));
      expect(actual).toBe(fixture.inputs.verifying_key_key);
    });
  }
});

/**
 * Per-share half of `Tweak::KeyPackage::tweak` (lib.rs:776-793).
 *
 * For every participant `i` in a DKG fixture we reconstruct the raw aggregate
 * share material from the part1 polynomial data:
 *
 *     raw_signing_share_i   = Σ_j f_j(i)                  (mod n)
 *                           = Σ_j evalPoly(coeffs_j, i)
 *     raw_verifying_share_i = Σ_j evalPolyOnPoints(commits_j, i)
 *
 * Both sums use already-validated primitives (`evalPoly`, `evalPolyOnPoints`).
 * We then run the reconstructed pair through `applyDkgTweakToShare` along
 * with the aggregate `verifying_key_pre_tweak` and assert byte equality
 * against the post-`post_dkg` values recorded in `dkg.part3[i]`. This
 * exercises the full per-share pipeline:
 *
 *   1. parity check on the aggregate (`hasEvenY`)
 *   2. simultaneous negation of (raw_ss, raw_vs, aggregate) when aggregate is odd
 *      (mirroring `KeyPackage::into_even_y` lib.rs:660-678)
 *   3. add `t` to the scalar share, `t·G` to the verifying share
 *
 * 2of3 DKG: 3 participants × 2 channels = 6 assertions
 * 3of5 DKG: 5 participants × 2 channels = 10 assertions
 * Total: 16 byte-equality assertions
 *
 * The 2of3 DKG fixture has `verifying_key_pre_tweak = 03d60d4c…` (odd y), so
 * its 6 assertions exercise the negation path; the 3of5 fixture covers the
 * other branch (or the same one, depending on its parity).
 */
describe('post_dkg per-share tweak — applyDkgTweakToShare', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);
      const preTweak = Point.fromBytes(hexToBytes(fixture.inputs.verifying_key_pre_tweak));

      // Pre-parse each sender's polynomial data exactly once.
      const senders = fixture.dkg.part1.map((p) => ({
        identifier: p.identifier,
        coeffs: p.secret_polynomial_coefficients.map((hex) => Fn.fromBytes(hexToBytes(hex))),
        commitments: p.commitments.map((hex) => Point.fromBytes(hexToBytes(hex))),
      }));

      for (const part3Party of fixture.dkg.part3) {
        const x = BigInt(part3Party.identifier);

        // Reconstruct the raw aggregate share material for this participant.
        let rawSs = 0n;
        let rawVs = Point.ZERO;
        for (const sender of senders) {
          rawSs = Fn.add(rawSs, evalPoly(sender.coeffs, x));
          rawVs = rawVs.add(evalPolyOnPoints(sender.commitments, x));
        }

        const tweaked = applyDkgTweakToShare(rawSs, rawVs, preTweak);

        it(`reproduces post_dkg signing_share for participant ${part3Party.identifier}`, () => {
          const actual = bytesToHex(Fn.toBytes(tweaked.signingShare));
          expect(actual).toBe(part3Party.signing_share);
        });

        it(`reproduces post_dkg verifying_share for participant ${part3Party.identifier}`, () => {
          const actual = bytesToHex(tweaked.verifyingShare.toBytes(true));
          expect(actual).toBe(part3Party.verifying_share);
        });
      }
    });
  }
});
