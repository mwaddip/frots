/**
 * Aggregate signature byte-equality test — closes Step 3 of PLAN.md.
 *
 * `aggregate` is the coordinator-side primitive that combines per-signer
 * signature shares into a single 64-byte BIP340 signature. Per
 * `frost-core/src/lib.rs:596-686`'s `aggregate_custom` and
 * `frost-secp256k1-tr/src/lib.rs:446-454`'s `serialize_signature`:
 *
 *     1. pre_aggregate: into_even_y(PublicKeyPackage)
 *     2. binding_factor_list: H1 over the operative vk + signer commitments
 *     3. group_commitment R = Σ (D_i + rho_i · E_i)
 *     4. z = Σ z_i (plain scalar sum of all signature shares)
 *     5. serialize as 64 bytes: R.x (32, drop SEC1 prefix) || z (32, BE)
 *
 * The deserialize side (`lib.rs:457-468`) hardcodes `R_bytes[0] = 0x02`
 * because BIP340 signatures always have even-y R; the parity dance in
 * `compute_signature_share` is what makes this round-trip mathematically
 * correct even when the operative R has odd y.
 *
 * Test surface: `final_output.sig` in each fixture is the captured 64-byte
 * BIP340 signature. The TS port walks the same pipeline (compute binding
 * factors → group commitment → sum sig shares → package) and asserts
 * byte-for-byte equivalence.
 *
 * 4 byte-equality assertions (1 per fixture). When all four pass, the
 * **entire FROST(secp256k1, SHA-256-TR) signing pipeline is byte-perfect
 * end-to-end** against the audited Rust reference, from RNG seed all the
 * way through to the on-chain Schnorr signature. That closes Step 3 of
 * PLAN.md and unblocks Step 4 (the public API surface).
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
  type RoundTwoOutput,
} from '../src/index.ts';
import {
  aggregate,
  type SigningCommitment,
} from '../src/secp256k1-tr/sign.ts';

const Fn = secp256k1.Point.Fn;

interface Loaded {
  verifyingKey: Uint8Array;
  message: Uint8Array;
  commitments: readonly SigningCommitment[];
  signatureShares: ReadonlyMap<number, bigint>;
  expectedSig: string;
}

function loadAggregateInputs(name: string): Loaded {
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

  const signatureShares = new Map<number, bigint>();
  for (const r2 of fx.round_two_outputs.outputs as readonly RoundTwoOutput[]) {
    signatureShares.set(r2.identifier, Fn.fromBytes(hexToBytes(r2.sig_share)));
  }

  return {
    verifyingKey: hexToBytes(fx.inputs.verifying_key_key),
    message: hexToBytes(fx.inputs.message),
    commitments,
    signatureShares,
    expectedSig: fx.final_output.sig,
  };
}

describe('aggregate — sum sig_shares, package as BIP340 R_x || z', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    it(`${name}: reproduces final_output.sig`, () => {
      const { verifyingKey, message, commitments, signatureShares, expectedSig } =
        loadAggregateInputs(name);
      const sig = aggregate(commitments, message, verifyingKey, signatureShares);
      expect(sig.length).toBe(64);
      expect(bytesToHex(sig)).toBe(expectedSig);
    });
  }
});
