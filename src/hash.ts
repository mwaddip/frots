/**
 * FROST(secp256k1, SHA-256-TR) hash primitives.
 *
 * Step 3 of `PLAN.md` ports primitives bottom-up. The five FROST hashes built
 * on `hash_to_scalar` (H1, H3, HDKG, HID, hash_randomizer per the
 * `RUST_REFERENCE_NOTES.md` §3.4 table) all share the same RFC 9380 ExpandMsgXmd
 * recipe — only the DST suffix differs. This file factors that recipe into a
 * single `hashToScalar(dst, msg)` and exposes the labeled wrappers as
 * one-liners. H2 (BIP340 tagged hash, mod-n direct reduction) and H4/H5 (raw
 * SHA256, no reduction) live elsewhere — they have different constructions and
 * are not on the critical path for the current sub-step.
 *
 * Reference: `RUST_REFERENCE_NOTES.md` §3 (hash domain tags) and §10
 * (noble/curves API mapping).
 */

import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const N = secp256k1.Point.Fn.ORDER;

/** FROST(secp256k1, SHA-256-TR) ciphersuite context string (lib.rs:179). */
const CONTEXT_STRING = 'FROST-secp256k1-SHA256-TR-v1';

/**
 * `hashToScalar` — RFC 9380 ExpandMsgXmd-SHA256 hash-to-field, reduced mod the
 * secp256k1 curve order `n`.
 *
 * Mirrors `frost-secp256k1-tr/src/lib.rs:169-174` exactly:
 *
 *     fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> Scalar {
 *         let mut u = [Secp256K1ScalarField::zero()];
 *         hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[msg], domain, &mut u)
 *             .expect("...");
 *         u[0]
 *     }
 *
 * The Rust side concatenates the items in `domain` with NO separator before
 * passing to `expand_message_xmd`; we pass the full pre-concatenated `dst` here.
 * Per RFC 9380 with k=128 the expansion produces L=ceil((256+128)/8)=48 bytes,
 * which `os2ip`-decode to a bigint and reduce mod n.
 *
 * Returns a `bigint` in `[0, n)`. Serialize via `secp256k1.Point.Fn.toBytes`
 * for the canonical 32-byte big-endian encoding.
 */
export function hashToScalar(dst: string, msg: Uint8Array): bigint {
  const u = hash_to_field(msg, 1, {
    DST: dst,
    p: N,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: sha256,
  });
  // count=1, m=1 → noble returns exactly one field element holding one bigint;
  // narrow for strict TS (`noUncheckedIndexedAccess`).
  const element = u[0];
  if (element === undefined || element[0] === undefined) {
    throw new Error('hashToScalar: hash_to_field returned an empty result');
  }
  return element[0];
}

/**
 * `H1` — FROST binding-factor hash-to-scalar (RFC 9591 §6.5.2.2.1).
 *
 * `lib.rs:252-254`: `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"rho"], m)`.
 * DST = `"FROST-secp256k1-SHA256-TR-v1rho"` (31 bytes).
 *
 * Used to derive the per-signer binding factor during the signing flow. Not
 * yet fixture-tested in the TS port — will be exercised when `pre_sign` lands.
 */
export function H1(msg: Uint8Array): bigint {
  return hashToScalar(`${CONTEXT_STRING}rho`, msg);
}

/**
 * `H3` — FROST nonce-derivation hash-to-scalar (RFC 9591 §6.5.2.2.3).
 *
 * `lib.rs:268-270`: `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"nonce"], m)`.
 * DST = `"FROST-secp256k1-SHA256-TR-v1nonce"` (33 bytes).
 *
 * Validated by `tests/h3.test.ts` (10 byte-equality assertions across both
 * `-tr` dealer fixtures, hiding + binding nonces).
 */
export function H3(msg: Uint8Array): bigint {
  return hashToScalar(`${CONTEXT_STRING}nonce`, msg);
}

/**
 * `HDKG` — DKG proof-of-knowledge challenge hash-to-scalar.
 *
 * `lib.rs:287-289`: `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m)`.
 * DST = `"FROST-secp256k1-SHA256-TR-v1dkg"` (31 bytes).
 *
 * Drives the per-party Schnorr proof-of-knowledge that participants publish
 * during DKG round 1. The preimage (per `RUST_REFERENCE_NOTES.md` §8) is
 * `identifier(32 BE) || verifying_key(33 SEC1) || R(33 SEC1)` — 98 bytes total.
 * Validated by `tests/dkg-pok.test.ts` against both `-tr` DKG fixtures.
 */
export function HDKG(msg: Uint8Array): bigint {
  return hashToScalar(`${CONTEXT_STRING}dkg`, msg);
}

/**
 * `HID` — FROST identifier-derivation hash-to-scalar.
 *
 * `lib.rs:292-294`: `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"id"], m)`.
 * DST = `"FROST-secp256k1-SHA256-TR-v1id"` (30 bytes).
 *
 * Used by callers that derive participant identifiers from arbitrary strings
 * rather than supplying raw `u16` ids. Not yet fixture-tested.
 */
export function HID(msg: Uint8Array): bigint {
  return hashToScalar(`${CONTEXT_STRING}id`, msg);
}

/**
 * `hash_randomizer` — rerandomized-FROST extension hash-to-scalar.
 *
 * `lib.rs:495-500`: `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"randomizer"], m)`.
 * DST = `"FROST-secp256k1-SHA256-TR-v1randomizer"` (38 bytes).
 *
 * Only used by the rerandomized-signing variant of FROST; the standard signing
 * flow does not invoke this. Exposed here for completeness alongside its
 * sibling H_n's; not yet fixture-tested.
 */
export function hashRandomizer(msg: Uint8Array): bigint {
  return hashToScalar(`${CONTEXT_STRING}randomizer`, msg);
}

const CONTEXT_BYTES = new TextEncoder().encode(CONTEXT_STRING);

/**
 * `hashToArray` — raw 32-byte SHA-256 over `CONTEXT_STRING || suffix || msg`.
 *
 * Mirrors `frost-secp256k1-tr/src/lib.rs:159-167`'s `hash_to_array`:
 *
 *     fn hash_to_array(inputs: &[&[u8]]) -> [u8; 32] {
 *         let mut h = Sha256::new();
 *         for i in inputs { h.update(i); }
 *         let mut output = [0u8; 32];
 *         output.copy_from_slice(h.finalize().as_ref());
 *         output
 *     }
 *
 * H4 and H5 are the only callers, both passing `[CONTEXT_STRING.as_bytes(),
 * suffix.as_bytes(), msg]`. There is **no scalar reduction** — the raw 32-byte
 * digest is the output. (Contrast with `hashToScalar`, which feeds the digest
 * through ExpandMsgXmd and reduces mod n.)
 */
function hashToArray(suffix: string, msg: Uint8Array): Uint8Array {
  const suffixBytes = new TextEncoder().encode(suffix);
  const buf = new Uint8Array(CONTEXT_BYTES.length + suffixBytes.length + msg.length);
  buf.set(CONTEXT_BYTES, 0);
  buf.set(suffixBytes, CONTEXT_BYTES.length);
  buf.set(msg, CONTEXT_BYTES.length + suffixBytes.length);
  return sha256(buf);
}

/**
 * `H4` — FROST message hash (RFC 9591 §6.5.2.2.4).
 *
 * `lib.rs:275-277`: `hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])`.
 * 32-byte SHA-256 over `"FROST-secp256k1-SHA256-TR-v1msg" || message`, with
 * NO scalar reduction. Used by `compute_binding_factor_list` to fold the
 * message into a fixed-length 32-byte slot in the binding-factor preimage.
 *
 * Validated by `tests/h4.test.ts` against bytes `[33:65]` of the captured
 * `binding_factor_input_prefix` field in all 4 fixtures.
 */
export function H4(msg: Uint8Array): Uint8Array {
  return hashToArray('msg', msg);
}

/**
 * `H5` — FROST commitment-list hash (RFC 9591 §6.5.2.2.5).
 *
 * `lib.rs:282-284`: `hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])`.
 * 32-byte SHA-256 over `"FROST-secp256k1-SHA256-TR-v1com" || encoded_commits`,
 * with NO scalar reduction. Used by `compute_binding_factor_list` to fold
 * the variable-length encoded group commitments into a fixed-length 32-byte
 * slot in the binding-factor preimage.
 *
 * The input is the byte string produced by `encode_group_commitments`
 * (`round1.rs:401-413`): `for each signer (sorted by id): id_serialized(32) ||
 * hiding_serialized(33) || binding_serialized(33)`. Validated indirectly via
 * `tests/binding-factor-prefix.test.ts`.
 */
export function H5(msg: Uint8Array): Uint8Array {
  return hashToArray('com', msg);
}
