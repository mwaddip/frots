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
import { applyDkgTweakToPubkey } from '../src/tweak.ts';

const Point = secp256k1.Point;

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
