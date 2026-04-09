/**
 * Binding factor input prefix byte-equality test.
 *
 * The per-session shared prefix is the load-bearing input to the binding
 * factor hash (H1). Per `frost-core/src/lib.rs:418-432`'s
 * `binding_factor_preimages`, the prefix is built once per signing session
 * and identifier-suffixed per signer:
 *
 *     prefix = vk_serialized(33)
 *           || H4(message)(32)
 *           || H5(encode_group_commitments(commitments))(32)
 *
 * For each signer the full preimage is `prefix || identifier_serialized(32)`,
 * fed to H1 to produce the per-signer rho_i.
 *
 * Test surface: `signing_intermediates.binding_factor_input_prefix` in each
 * fixture is the captured prefix bytes. The TS port reconstructs the same
 * prefix from the round-1 commitments and verifying key, then asserts
 * byte-for-byte equivalence.
 *
 * 4 byte-equality assertions (1 per fixture). This single composite test
 * validates **four** sub-primitives at once:
 *   - H5 (commitment-list hash) — composes into the prefix
 *   - encodeGroupCommitments (the byte assembly that feeds H5)
 *   - bindingFactorInputPrefix (the per-session prefix construction)
 *   - the SigningCommitment ordering convention (sorted by identifier scalar)
 *
 * If a regression hits, the strongly-suspect culprits in order are:
 *   (a) commitment ordering — Rust uses BTreeMap which sorts by Identifier's
 *       scalar Ord, equivalent to ascending u16 for default identifiers
 *   (b) the H5 DST suffix `"com"` — case matters
 *   (c) encodeGroupCommitments byte order: id, hiding, binding (NOT id, binding, hiding)
 *   (d) identifier serialization (32-byte big-endian, last 2 bytes = u16)
 */

import { describe, expect, it } from 'vitest';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
  loadDkgFixture,
  type RoundOneOutput,
} from '../src/index.ts';
import { bindingFactorInputPrefix, type SigningCommitment } from '../src/sign.ts';

interface Loaded {
  verifyingKey: Uint8Array;
  message: Uint8Array;
  commitments: readonly SigningCommitment[];
  expectedPrefix: Uint8Array;
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
  // Match Rust's BTreeMap iteration order: ascending by identifier
  commitments.sort((a, b) => a.identifier - b.identifier);
  return {
    verifyingKey: hexToBytes(fx.inputs.verifying_key_key),
    message: hexToBytes(fx.inputs.message),
    commitments,
    expectedPrefix: hexToBytes(fx.signing_intermediates.binding_factor_input_prefix),
  };
}

describe('bindingFactorInputPrefix — vk || H4(msg) || H5(encoded_commits)', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    it(`${name}: reproduces signing_intermediates.binding_factor_input_prefix`, () => {
      const { verifyingKey, message, commitments, expectedPrefix } = loadCommitments(name);
      const actual = bindingFactorInputPrefix(verifyingKey, message, commitments);
      expect(bytesToHex(actual)).toBe(bytesToHex(expectedPrefix));
    });
  }
});
