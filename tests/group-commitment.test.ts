/**
 * Group commitment byte-equality test.
 *
 * `computeGroupCommitment` is the load-bearing primitive that aggregates the
 * round-1 commitments into a single Schnorr `R` point for the joint signature.
 * Mirrors `frost-core/src/lib.rs:495-538`'s `compute_group_commitment`:
 *
 *     R = Σ_i (D_i + rho_i · E_i)
 *
 * where `D_i` is signer i's hiding nonce commitment, `E_i` is their binding
 * nonce commitment, and `rho_i` is the per-signer binding factor (computed
 * by `computeBindingFactorList`).
 *
 * The result is the *operative* group commitment BEFORE any BIP340 even-y
 * normalization — `compute_signature_share` checks `R.has_even_y()` and
 * negates the local nonces if odd, but that's a downstream concern.
 *
 * Test surface: `signing_intermediates.group_commitment` in each fixture is
 * the captured 33-byte SEC1 compressed encoding of R. The TS port walks the
 * same pipeline (parse commitments → compute binding factors → sum
 * `D_i + rho_i · E_i`) and asserts byte-for-byte equivalence.
 *
 * 4 byte-equality assertions (1 per fixture).
 *
 * If a regression hits, the strongly-suspect culprits in order are:
 *   (a) wrong binding factor → would have failed binding-factor.test.ts first
 *   (b) accidentally adding `D_i · rho_i` instead of `rho_i · E_i`
 *   (c) accidentally subtracting instead of adding (additive vs. subtractive notation)
 *   (d) commitment ordering — but the sum is order-independent (commutative)
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
  loadDkgFixture,
  type RoundOneOutput,
} from '../src/index.ts';
import { intoEvenY } from '../src/point.ts';
import {
  computeBindingFactorList,
  computeGroupCommitment,
  type SigningCommitment,
} from '../src/sign.ts';

const Point = secp256k1.Point;

interface Loaded {
  verifyingKey: Uint8Array;
  message: Uint8Array;
  commitments: readonly SigningCommitment[];
  expectedGroupCommitment: string;
}

function loadCommitments(name: string): Loaded {
  const isDkg = name.endsWith('_dkg');
  const fx = isDkg ? loadDkgFixture(name) : loadDealerFixture(name);
  const commitments: SigningCommitment[] = fx.round_one_outputs.outputs.map(
    (r1: RoundOneOutput): SigningCommitment => ({
      identifier: r1.identifier,
      hiding: hexToBytes(r1.hiding_nonce_commitment),
      binding: hexToBytes(r1.binding_nonce_commitment),
    }),
  );
  commitments.sort((a, b) => a.identifier - b.identifier);
  // Apply pre_sign even-y normalization to vk before passing to
  // computeBindingFactorList — the binding factors that flow into the group
  // commitment depend on the operative (post-pre_sign) vk per
  // frost-core/round2.rs:145-160.
  const vkPoint = Point.fromBytes(hexToBytes(fx.inputs.verifying_key_key));
  return {
    verifyingKey: intoEvenY(vkPoint).toBytes(true),
    message: hexToBytes(fx.inputs.message),
    commitments,
    expectedGroupCommitment: fx.signing_intermediates.group_commitment,
  };
}

describe('computeGroupCommitment — R = Σ (D_i + rho_i · E_i)', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    it(`${name}: reproduces signing_intermediates.group_commitment`, () => {
      const { verifyingKey, message, commitments, expectedGroupCommitment } =
        loadCommitments(name);
      const bindingFactors = computeBindingFactorList(verifyingKey, message, commitments);
      const R = computeGroupCommitment(commitments, bindingFactors);
      expect(bytesToHex(R.toBytes(true))).toBe(expectedGroupCommitment);
      // Sanity: also confirm the parsed R round-trips
      const parsed = Point.fromBytes(hexToBytes(expectedGroupCommitment));
      expect(R.equals(parsed)).toBe(true);
    });
  }
});
