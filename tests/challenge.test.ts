/**
 * Schnorr challenge byte-equality test.
 *
 * `challenge` (the `-tr` x-only override at frost-secp256k1-tr/src/lib.rs:382-392)
 * is the load-bearing primitive that turns the joint commitment R, the
 * verifying key, and the message into the per-signature scalar `c` that
 * weights each signer's contribution. Per BIP340 the preimage is x-only:
 *
 *     preimage = R.x(32) || vk.x(32) || message
 *     c        = H2(preimage)
 *
 * H2 itself is the BIP340 tagged hash applied to the preimage:
 *
 *     H2(m) = SHA256(SHA256("BIP0340/challenge")^2 || m)  reduced mod n
 *
 * Crucially the `-tr` ciphersuite hashes only the **x-coordinates** of R and
 * vk (32 bytes each), unlike vanilla FROST which would hash the full 33-byte
 * SEC1 points. This is what makes the FROST output verify under standard
 * BIP340 verification.
 *
 * Test surface: `signing_intermediates.challenge` in each fixture is the
 * captured 32-byte big-endian challenge scalar. The TS port walks the same
 * pipeline (parse R from group_commitment → extract x-only → concat with
 * vk_x and message → H2) and asserts byte-for-byte equivalence.
 *
 * 4 byte-equality assertions (1 per fixture).
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
  loadDkgFixture,
} from '../src/index.ts';
import { challenge } from '../src/secp256k1-tr/sign.ts';

const Fn = secp256k1.Point.Fn;
const Point = secp256k1.Point;

interface Loaded {
  verifyingKey: typeof Point.BASE;
  R: typeof Point.BASE;
  message: Uint8Array;
  expectedChallenge: string;
}

function loadChallengeInputs(name: string): Loaded {
  const isDkg = name.endsWith('_dkg');
  const fx = isDkg ? loadDkgFixture(name) : loadDealerFixture(name);
  return {
    verifyingKey: Point.fromBytes(hexToBytes(fx.inputs.verifying_key_key)),
    R: Point.fromBytes(hexToBytes(fx.signing_intermediates.group_commitment)),
    message: hexToBytes(fx.inputs.message),
    expectedChallenge: fx.signing_intermediates.challenge,
  };
}

describe('challenge — c = H2(R_x || vk_x || message) (-tr x-only)', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    it(`${name}: reproduces signing_intermediates.challenge`, () => {
      const { verifyingKey, R, message, expectedChallenge } = loadChallengeInputs(name);
      const c = challenge(R, verifyingKey, message);
      const actual = bytesToHex(Fn.toBytes(c));
      expect(actual).toBe(expectedChallenge);
    });
  }
});
