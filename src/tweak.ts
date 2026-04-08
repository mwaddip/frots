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

import { hasEvenY, intoEvenY, scalarBaseMul } from './point.ts';

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

/**
 * `applyDkgTweakToShare` — composite that mirrors `Tweak::KeyPackage::tweak(None)`.
 *
 * Per `frost-secp256k1-tr/src/lib.rs:776-793`, the operative key material a
 * participant holds after `post_dkg` is computed by applying both the BIP340
 * even-y normalization (which negates ALL three KeyPackage components when
 * the AGGREGATE verifying key has odd y) and the BIP341 unspendable tweak:
 *
 *     let t = tweak(&self.verifying_key().to_element(), merkle_root);
 *     let tp = ProjectivePoint::GENERATOR * t;
 *     let key_package = self.into_even_y(None);
 *     let verifying_key   = kp.verifying_key.to_element() + tp;
 *     let signing_share   = kp.signing_share.to_scalar()  + t;
 *     let verifying_share = kp.verifying_share.to_element() + tp;
 *
 * `KeyPackage::into_even_y` (lib.rs:660-678) checks the AGGREGATE verifying
 * key's parity and, if odd, negates the verifying key, the signing share,
 * AND the verifying share — all atomically. This preserves both the
 * `s·G == vs` invariant (signing share to its public counterpart) AND the
 * `Σ vs == vk` invariant (sum of verifying shares to the aggregate).
 *
 * The TS port takes the three RAW share components as separate arguments
 * (since we don't yet have a `KeyPackage` struct in Step 3) and returns the
 * tweaked trio. `aggregateVerifyingKey` is the pre-tweak aggregate (the
 * `Σ_j commitment_j[0]` sum); its parity drives the negation choice.
 */
export function applyDkgTweakToShare(
  rawSigningShare: bigint,
  rawVerifyingShare: Point,
  aggregateVerifyingKey: Point,
): { signingShare: bigint; verifyingShare: Point; verifyingKey: Point } {
  const t = tapTweakScalar(aggregateVerifyingKey);
  const tp = scalarBaseMul(t);

  // Aggregate parity drives all three negations atomically (mirrors
  // KeyPackage::into_even_y at lib.rs:660-678).
  const isEven = hasEvenY(aggregateVerifyingKey);
  const evenSs = isEven ? rawSigningShare : Fn.neg(rawSigningShare);
  const evenVs = isEven ? rawVerifyingShare : rawVerifyingShare.negate();
  const evenAggregate = intoEvenY(aggregateVerifyingKey);

  return {
    signingShare: Fn.add(evenSs, t),
    verifyingShare: evenVs.add(tp),
    verifyingKey: evenAggregate.add(tp),
  };
}
