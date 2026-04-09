/**
 * H3 byte-equality test against the Rust dealer fixtures.
 *
 * H3 is the FROST(secp256k1, SHA-256-TR) hash-to-scalar primitive used for
 * nonce derivation (RFC 9591 §6.5.2.2.3). Per `RUST_REFERENCE_NOTES.md` §3.1
 * + §3.4 + §9 the recipe is:
 *
 *     H3(m) = hash_to_field<ExpandMsgXmd<Sha256>, Scalar>(
 *         msg = m,
 *         DST = "FROST-secp256k1-SHA256-TR-v1nonce",  // CONTEXT_STRING + "nonce"
 *         p   = secp256k1_n,
 *         m   = 1,
 *         k   = 128,
 *         expand = "xmd",
 *         hash = sha256,
 *     )[0][0]
 *
 * And per `frost-core/src/round1.rs:77-90`, the round-1 hiding nonce of a
 * participant is computed as:
 *
 *     hiding_nonce = H3(random_bytes(32) || signing_share.serialize()(32))
 *
 * with random first, secret second. Both halves are recorded in the dealer
 * fixtures (`hiding_nonce_randomness` in each `round_one_outputs` entry; the
 * matching `participant_share` in `inputs.participant_shares` for the same
 * identifier), so we can replay this computation in pure TS and assert the
 * resulting scalar serializes back to the recorded `hiding_nonce` byte-for-byte.
 *
 * If this passes for every dealer fixture row, the entire pure-TS-vs-Rust
 * strategy is empirically validated (PLAN.md last paragraph) and §12 open
 * item #2 (k=128 assumption) is resolved.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDealerFixture,
} from '../src/index.ts';
import { H3 } from '../src/secp256k1-tr/hash.ts';

const Fn = secp256k1.Point.Fn;

describe('H3 — FROST(secp256k1, SHA-256-TR) hash-to-scalar (nonce derivation)', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dealer')) continue;

    describe(name, () => {
      const fixture = loadDealerFixture(name);
      const sharesByIdent = new Map(
        fixture.inputs.participant_shares.map((s) => [s.identifier, s] as const),
      );

      for (const r1 of fixture.round_one_outputs.outputs) {
        it(`reproduces hiding_nonce for participant ${r1.identifier}`, () => {
          const share = sharesByIdent.get(r1.identifier);
          if (!share) {
            throw new Error(`no participant_share for identifier ${r1.identifier}`);
          }

          const random = hexToBytes(r1.hiding_nonce_randomness);
          const secret = hexToBytes(share.participant_share);
          expect(random.length).toBe(32);
          expect(secret.length).toBe(32);

          // Preimage = random_bytes (32) || signing_share.serialize() (32)
          const preimage = new Uint8Array(64);
          preimage.set(random, 0);
          preimage.set(secret, 32);

          const scalar = H3(preimage);
          const actual = bytesToHex(Fn.toBytes(scalar));

          expect(actual).toBe(r1.hiding_nonce);
        });

        it(`reproduces binding_nonce for participant ${r1.identifier}`, () => {
          const share = sharesByIdent.get(r1.identifier);
          if (!share) {
            throw new Error(`no participant_share for identifier ${r1.identifier}`);
          }

          // Binding nonce uses the same H3(random || signing_share) recipe;
          // only the random half differs from the hiding nonce (it's the second
          // 32-byte block consumed from the RNG by Round 1 commit).
          const random = hexToBytes(r1.binding_nonce_randomness);
          const secret = hexToBytes(share.participant_share);
          expect(random.length).toBe(32);
          expect(secret.length).toBe(32);

          const preimage = new Uint8Array(64);
          preimage.set(random, 0);
          preimage.set(secret, 32);

          const scalar = H3(preimage);
          const actual = bytesToHex(Fn.toBytes(scalar));

          expect(actual).toBe(r1.binding_nonce);
        });
      }
    });
  }
});
