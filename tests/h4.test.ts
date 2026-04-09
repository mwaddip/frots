/**
 * H4 byte-equality test against the captured binding factor input prefix.
 *
 * H4 is the FROST(secp256k1, SHA-256-TR) message hash (RFC 9591 §6.5.2.2.4),
 * a raw 32-byte SHA-256 over `CONTEXT_STRING || "msg" || message` with NO
 * scalar reduction. Mirrors `lib.rs:275-277`:
 *
 *     fn H4(m: &[u8]) -> [u8; 32] {
 *         hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
 *     }
 *
 * Test surface: the captured `signing_intermediates.binding_factor_input_prefix`
 * field in each fixture has the layout `vk(33) || H4(message)(32) || H5(...)(32)`,
 * so bytes `[33:65]` of the prefix are precisely `H4(inputs.message)` byte-for-byte.
 * No hand-computed expected values are needed — the recorded prefix IS the
 * source of truth.
 *
 * One assertion per fixture × 4 fixtures = 4 byte-equality assertions.
 */

import { describe, expect, it } from 'vitest';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
  loadDkgFixture,
} from '../src/index.ts';
import { H4 } from '../src/hash.ts';

function loadIntermediatesAndMessage(name: string): {
  message: Uint8Array;
  prefix: Uint8Array;
} {
  if (name.endsWith('_dkg')) {
    const fx = loadDkgFixture(name);
    return {
      message: hexToBytes(fx.inputs.message),
      prefix: hexToBytes(fx.signing_intermediates.binding_factor_input_prefix),
    };
  } else {
    const fx = loadDealerFixture(name);
    return {
      message: hexToBytes(fx.inputs.message),
      prefix: hexToBytes(fx.signing_intermediates.binding_factor_input_prefix),
    };
  }
}

describe('H4 — FROST(secp256k1, SHA-256-TR) message hash', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    it(`${name}: H4(message) matches prefix[33:65]`, () => {
      const { message, prefix } = loadIntermediatesAndMessage(name);
      // prefix layout: vk(33) || H4(message)(32) || H5(encoded_commits)(32)
      const expected = prefix.slice(33, 65);
      const actual = H4(message);
      expect(bytesToHex(actual)).toBe(bytesToHex(expected));
    });
  }
});
