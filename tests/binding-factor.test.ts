/**
 * Binding factor list byte-equality test.
 *
 * `compute_binding_factor_list` (frost-core/src/lib.rs:241-260) is the
 * load-bearing primitive that turns the per-session binding factor preimage
 * into per-signer rho_i scalars via H1. For each signer:
 *
 *     preimage_i = bindingFactorInputPrefix(vk, msg, commitments) || identifier_serialized(32)
 *     rho_i      = H1(preimage_i)
 *
 * H1 itself is the FROST binding-factor hash from `lib.rs:252-254`,
 * `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"rho"], m)`. Already exposed
 * in `src/hash.ts` after the earlier hashToScalar refactor; this test is its
 * first byte-equality validation.
 *
 * Test surface: `signing_intermediates.binding_factors` in each fixture is
 * a `[(identifier, rho)]` list — one entry per signer. The TS port walks
 * the same pipeline (build prefix → append identifier → H1) and asserts
 * byte-for-byte equivalence of the resulting Map<identifier, rho> against
 * the captured list.
 *
 * Total assertion count: 2 + 2 + 3 + 3 = 10 byte-equality assertions across
 * the four fixtures (one per signer per fixture).
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
  type SigningIntermediates,
} from '../src/index.ts';
import {
  computeBindingFactorList,
  type SigningCommitment,
} from '../src/sign.ts';

const Fn = secp256k1.Point.Fn;

interface Loaded {
  verifyingKey: Uint8Array;
  message: Uint8Array;
  commitments: readonly SigningCommitment[];
  intermediates: SigningIntermediates;
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
  return {
    verifyingKey: hexToBytes(fx.inputs.verifying_key_key),
    message: hexToBytes(fx.inputs.message),
    commitments,
    intermediates: fx.signing_intermediates,
  };
}

describe('computeBindingFactorList — H1(prefix || identifier) per signer', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    describe(name, () => {
      const { verifyingKey, message, commitments, intermediates } =
        loadCommitments(name);
      const factors = computeBindingFactorList(verifyingKey, message, commitments);

      for (const expected of intermediates.binding_factors) {
        it(`reproduces rho for signer ${expected.identifier}`, () => {
          const actual = factors.get(expected.identifier);
          if (actual === undefined) {
            throw new Error(
              `computeBindingFactorList returned no entry for signer ${expected.identifier}`,
            );
          }
          expect(bytesToHex(Fn.toBytes(actual))).toBe(expected.rho);
        });
      }
    });
  }
});
