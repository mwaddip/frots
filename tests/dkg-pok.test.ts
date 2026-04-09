/**
 * DKG proof-of-knowledge byte-equality test against the Rust DKG fixtures.
 *
 * Each party in DKG part 1 publishes a Schnorr proof of knowledge of the
 * constant term of its secret polynomial — i.e., a Schnorr signature `(R, z)`
 * over the FROST DKG challenge with the polynomial commitment `commitments[0]`
 * playing the role of public key. Without this proof, a malicious party could
 * publish arbitrary commitments without actually knowing the matching scalar
 * and break the threshold-secret guarantee.
 *
 * Per `RUST_REFERENCE_NOTES.md` §8 + `frost-core/src/keys/dkg.rs:~416`, the
 * Schnorr verification equation is:
 *
 *     vk        = commitments[0]                          // 33-byte SEC1
 *     preimage  = identifier.serialize() (32 BE)
 *               || G.serialize(vk) (33 SEC1)
 *               || G.serialize(R)  (33 SEC1)              // 98 bytes total
 *     c         = HDKG(preimage)                          // = hashToScalar(
 *                                                         //     "FROST-secp256k1-SHA256-TR-v1dkg",
 *                                                         //     preimage)
 *     lhs       = z · G
 *     rhs       = R + c · vk
 *     assert lhs == rhs   (compared as 33-byte SEC1 compressed)
 *
 * Crucially the preimage uses the **full 33-byte SEC1** points (NOT x-only) —
 * DKG happens before BIP340 even-y normalization is meaningful, so we're
 * proving knowledge of a polynomial coefficient, not BIP340-signing yet.
 *
 * 2-of-3 DKG: 3 parties → 3 assertions.
 * 3-of-5 DKG: 5 parties → 5 assertions.
 * Total: 8 byte-equality assertions across both `-tr` DKG fixtures.
 *
 * If this passes for every (fixture, party) pair, the HDKG hash is empirically
 * validated AND the DKG-PoK construction is locked byte-for-byte against the
 * Rust reference. The strongly-suspect culprit on failure is the preimage
 * byte order (identifier-then-vk-then-R, all big-endian / SEC1 compressed) or
 * the HDKG DST suffix (`"dkg"` not `"DKG"` — case matters).
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ALL_FIXTURE_NAMES,
  bytesToHex,
  hexToBytes,
  loadDkgFixture,
} from '../src/index.ts';
import { scalarBaseMul } from '../src/secp256k1-tr/point.ts';
import { dkgProofOfKnowledgeChallenge } from '../src/secp256k1-tr/dkg.ts';

const Fn = secp256k1.Point.Fn;
const Point = secp256k1.Point;

describe('DKG proof-of-knowledge — z·G == R + c·vk', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    if (!name.endsWith('_dkg')) continue;

    describe(name, () => {
      const fixture = loadDkgFixture(name);

      for (const party of fixture.dkg.part1) {
        it(`verifies proof of knowledge for party ${party.identifier}`, () => {
          // commitments[0] is the polynomial constant-term commitment, which
          // serves as the verifying key for this party's proof of knowledge.
          const vkHex = party.commitments[0];
          if (vkHex === undefined) {
            throw new Error(
              `party ${party.identifier} has no commitments — fixture is malformed`,
            );
          }
          const vk = Point.fromBytes(hexToBytes(vkHex));
          const R = Point.fromBytes(hexToBytes(party.proof_of_knowledge_R));
          const z = Fn.fromBytes(hexToBytes(party.proof_of_knowledge_z));

          const c = dkgProofOfKnowledgeChallenge(BigInt(party.identifier), vk, R);

          const lhs = scalarBaseMul(z);
          const rhs = R.add(vk.multiply(c));

          // Compare via canonical 33-byte SEC1 compressed encoding
          expect(bytesToHex(lhs.toBytes(true))).toBe(bytesToHex(rhs.toBytes(true)));
        });
      }
    });
  }
});
