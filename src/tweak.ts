/**
 * BIP341 taproot tweak primitives for `frost-secp256k1-tr`.
 *
 * The `-tr` ciphersuite applies the BIP341 unspendable script-path tweak as
 * part of `Ciphersuite::post_dkg`, turning the freshly-aggregated FROST
 * verifying key into the operative one. Without this step the resulting
 * group key is BIP341-non-compliant AND vulnerable to a post-hoc rogue
 * tapscript-tweak attack — see `RUST_REFERENCE_NOTES.md` §5.2 for the
 * threat model.
 *
 * This file currently exposes only the verifying-key half of `Tweak`. The
 * matching key-package half (which also folds `+ t` into the signing share
 * and `+ t·G` into the verifying share) lands when DKG part 3 is ported.
 *
 * Reference: `RUST_REFERENCE_NOTES.md` §5 (`tweak`, `post_dkg`, `Tweak::tweak`)
 * and lib.rs:200-216 (`tweak`) + lib.rs:478-491 (`post_dkg`) +
 * lib.rs:751-792 (`Tweak::PublicKeyPackage::tweak`).
 */

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';

import { intoEvenY, scalarBaseMul } from './point.ts';

const Fn = secp256k1.Point.Fn;
type Point = typeof secp256k1.Point.BASE;

/**
 * `tapTweakScalar` — BIP341 unspendable tap-tweak scalar.
 *
 * Mirrors `frost-secp256k1-tr/src/lib.rs:200-216`:
 *
 *     fn tweak<T: AsRef<[u8]>>(public_key: &Element, merkle_root: Option<T>)
 *         -> Scalar
 *     {
 *         let mut hasher = tagged_hash("TapTweak");
 *         hasher.update(public_key.to_affine().x());      // 32 bytes
 *         // optional: hasher.update(merkle_root);
 *         hasher_to_scalar(hasher)                        // direct mod-n reduce
 *     }
 *
 * which is the standard BIP341 `taproot_tweak_pubkey` formula
 * `t = SHA256(SHA256("TapTweak") || SHA256("TapTweak") || pk_x [|| merkle_root])`
 * reduced mod n.
 *
 * The `-tr` ciphersuite always passes `None` for `merkle_root` (the
 * unspendable-script-path case), so this primitive does the same. A future
 * `tapTweakScalarWithRoot` variant can be added when key-spend-only signers
 * need to commit to a real script tree.
 *
 * `pubkey` may have either parity — the tweak only consumes the x-coordinate
 * (which is invariant under negation), so the result is the same whether
 * `pubkey` was even-y normalized first or not.
 */
export function tapTweakScalar(pubkey: Point): bigint {
  // 32-byte big-endian x coordinate (matching `point.to_affine().x()` in Rust).
  const xBytes = pubkey.toBytes(true).slice(1);
  const tagged = schnorr.utils.taggedHash('TapTweak', xBytes);
  return Fn.create(bytesToNumberBE(tagged));
}

/**
 * `applyDkgTweakToPubkey` — composite that mirrors the verifying-key portion
 * of `Tweak::PublicKeyPackage::tweak(None)`.
 *
 * Per `frost-secp256k1-tr/src/lib.rs:751-773`, the operative aggregate
 * verifying key after `post_dkg` is computed as:
 *
 *     let t = tweak(&self.verifying_key().to_element(), merkle_root);
 *     let tp = ProjectivePoint::GENERATOR * t;
 *     let public_key_package = self.into_even_y(None);
 *     let verifying_key = pkp.verifying_key().to_element() + tp;
 *
 * i.e. `Q = into_even_y(P) + t·G`. Note the order: `t` is computed from the
 * ORIGINAL pubkey, not the even-y normalized one. Since `tweak()` only
 * consumes the x-coordinate and negation preserves x, both orders give the
 * same `t`, but mirroring Rust keeps the port byte-precise.
 *
 * The result `Q` is NOT itself even-y normalized — its parity depends on the
 * data. Downstream signing / verification code paths normalize Q again on
 * the way in via `pre_sign` / `pre_aggregate` / `pre_verify`.
 */
export function applyDkgTweakToPubkey(pubkey: Point): Point {
  const t = tapTweakScalar(pubkey);
  const tG = scalarBaseMul(t);
  const evenP = intoEvenY(pubkey);
  return evenP.add(tG);
}
