/**
 * Distributed Key Generation (DKG) primitives.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. This file currently exposes
 * only the DKG proof-of-knowledge challenge construction; round-1/round-2/
 * round-3 wrappers will land as the dependent primitives are ported.
 *
 * Reference: `RUST_REFERENCE_NOTES.md` §8 (DKG proof-of-knowledge challenge),
 * §3.4 (HDKG hash recipe). The corresponding Rust source lives in
 * `frost-core/src/keys/dkg.rs` around the `challenge` helper function (~line
 * 416 per the notes).
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { HDKG } from './hash.ts';

const Fn = secp256k1.Point.Fn;

type Point = typeof secp256k1.Point.BASE;

/**
 * `dkgProofOfKnowledgeChallenge` — build the Schnorr challenge scalar `c` for
 * a DKG part-1 proof of knowledge.
 *
 * Mirrors `frost-core/src/keys/dkg.rs`'s `challenge<C>` helper:
 *
 *     fn challenge<C>(identifier, verifying_key, R) -> Challenge<C> {
 *         let mut preimage = vec![];
 *         preimage.extend_from_slice(identifier.serialize().as_ref());                    // 32
 *         preimage.extend_from_slice(<C::Group>::serialize(&verifying_key.to_element())?); // 33
 *         preimage.extend_from_slice(<C::Group>::serialize(R)?);                           // 33
 *         Challenge(C::HDKG(&preimage[..])...)
 *     }
 *
 * Crucially the preimage uses **full 33-byte SEC1 compressed** points (NOT
 * x-only) — DKG happens before BIP340 even-y normalization is meaningful, so
 * we're proving knowledge of a polynomial coefficient, not BIP340-signing yet.
 * This is what distinguishes DKG-PoK challenges from `Ciphersuite::challenge`
 * (which builds an x-only preimage for the on-chain Schnorr equation).
 *
 * Identifier encoding: the canonical 32-byte big-endian field encoding via
 * `Fn.toBytes`. For default identifiers `1, 2, ...` the last 2 bytes hold the
 * `u16` value, matching `frost-core`'s `Identifier::serialize()`.
 */
export function dkgProofOfKnowledgeChallenge(
  identifier: number,
  verifyingKey: Point,
  R: Point,
): bigint {
  const idBytes = Fn.toBytes(BigInt(identifier));
  const vkBytes = verifyingKey.toBytes(true);
  const rBytes = R.toBytes(true);

  // 32 (identifier) + 33 (vk) + 33 (R) = 98 bytes
  const preimage = new Uint8Array(98);
  preimage.set(idBytes, 0);
  preimage.set(vkBytes, 32);
  preimage.set(rBytes, 65);

  return HDKG(preimage);
}
