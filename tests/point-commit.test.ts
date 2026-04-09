/**
 * Scalar·G byte-equality test against the Rust dealer fixtures.
 *
 * Tests the second primitive in `PLAN.md` Step 3: secp256k1 base-point
 * multiplication followed by 33-byte SEC1 compressed serialization. This is
 * the operation that turns a scalar nonce into the public commitment point
 * the other signers will see.
 *
 * Per `RUST_REFERENCE_NOTES.md` §4 + §10:
 *   commitment = scalar · G            (constant-time scalar mul)
 *              = serialize_sec1(point) (33 bytes, even-y is `0x02`, odd-y `0x03`)
 *
 * The dealer fixtures already record the round-1 scalar (`hiding_nonce` /
 * `binding_nonce`) AND the matching commitment point (`hiding_nonce_commitment`
 * / `binding_nonce_commitment`), so we can drive both halves of this primitive
 * directly from committed Rust output without depending on H3.
 *
 * (Using the recorded scalars rather than chaining H3→scalar·G isolates the
 * test to JUST scalar·G — if it fails, the bug is in the point primitive, not
 * upstream.)
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
} from '../src/index.ts';
import { scalarBaseMul } from '../src/secp256k1-tr/point.ts';

const Fn = secp256k1.Point.Fn;

describe('scalar·G — secp256k1 base-point multiplication, 33-byte SEC1 commitment', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dealer')) continue;

    describe(name, () => {
      const fixture = loadDealerFixture(name);

      for (const r1 of fixture.round_one_outputs.outputs) {
        it(`hiding_nonce·G == hiding_nonce_commitment for participant ${r1.identifier}`, () => {
          const scalar = Fn.fromBytes(hexToBytes(r1.hiding_nonce));
          const point = scalarBaseMul(scalar);
          expect(bytesToHex(point.toBytes(true))).toBe(r1.hiding_nonce_commitment);
        });

        it(`binding_nonce·G == binding_nonce_commitment for participant ${r1.identifier}`, () => {
          const scalar = Fn.fromBytes(hexToBytes(r1.binding_nonce));
          const point = scalarBaseMul(scalar);
          expect(bytesToHex(point.toBytes(true))).toBe(r1.binding_nonce_commitment);
        });
      }
    });
  }
});
