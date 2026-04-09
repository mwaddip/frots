/**
 * FROST key-material types and key-package finalization (Step 4).
 *
 * Step 4 of `PLAN.md` composes the validated Step 3 primitives into a clean
 * public API surface. This file is the home of the *type wrappers* — the
 * structs that the public DKG / sign / aggregate functions take and return —
 * and the dealer-flow `finalizeKeygen` that turns a dealer-issued
 * `SecretShare` into a per-party `KeyPackage`.
 *
 * Type-wrapper conventions (per the Step 4 design checkpoint, see
 * `SESSION_CONTEXT.md`'s "operative vs raw verifying key" section):
 *
 * - **Minimal shape.** Mirror only the Rust fields that the public API
 *   actually consumes. No `Header<C>` analogues, no serialization version
 *   bytes — `frots` is a library, not a wire format.
 * - **Functional / readonly.** Plain `interface ... { readonly ... }` over
 *   classes. The Step 3 primitive layer is functional and the public API
 *   stays consistent with it.
 * - **Raw verifying key at the boundary.** A `KeyPackage` carries the *raw*
 *   (un-normalized, possibly odd-y) verifying key. High-level wrappers like
 *   `signRound2` are responsible for applying the BIP340 `pre_sign` parity
 *   normalization internally; low-level helpers in `src/sign.ts` continue to
 *   expect the operative (already-normalized) vk per the existing test
 *   surface.
 *
 * Reference: `frost-core/src/keys.rs` (`SecretShare`, `KeyPackage`,
 * `PublicKeyPackage`) and `frost-secp256k1-tr/src/lib.rs`'s `post_dkg`
 * asymmetry per `RUST_REFERENCE_NOTES.md` §5.1.5.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';

import { evalPolyOnPoints } from './poly.ts';
import { scalarBaseMul } from './point.ts';

type Point = typeof secp256k1.Point.BASE;

/**
 * Per-party signing material — what one signer needs to participate in a
 * round-2 sign call. Mirrors `frost_core::keys::KeyPackage<C>` minus the
 * `Header<C>` metadata field.
 *
 * - `identifier` is the non-zero u16 party identifier, lifted to `bigint`
 *   to match the scalar-field convention used everywhere else in the port.
 * - `signingShare` is the per-party secret share `s_i` as a raw scalar
 *   (`bigint`, mod n). **Pre-`pre_sign` parity** — the public `signRound2`
 *   wrapper applies `into_even_y` against `verifyingKey` internally before
 *   calling `computeSignatureShare`.
 * - `verifyingShare` is `s_i · G`, 33-byte SEC1 compressed.
 * - `verifyingKey` is the aggregate group verifying key. **Raw**: for the
 *   dealer flow, this is `Σ_i s_i · G` directly (the polynomial constant
 *   term commitment, possibly odd-y); for the DKG flow, this is the
 *   tap-tweaked aggregate from `post_dkg` (also possibly odd-y at the
 *   `pre_sign` boundary). 33-byte SEC1 compressed.
 * - `minSigners` is the threshold `t` — the minimum number of signers
 *   needed to produce a valid signature. Used by aggregation to size the
 *   binding-factor list and validate signing-set membership.
 */
export interface KeyPackage {
  readonly identifier: bigint;
  readonly signingShare: bigint;
  readonly verifyingShare: Uint8Array;
  readonly verifyingKey: Uint8Array;
  readonly minSigners: number;
}

/**
 * Group public material — what every signer (and any external verifier)
 * needs to validate signature shares and aggregate signatures. Mirrors
 * `frost_core::keys::PublicKeyPackage<C>` minus the `Header<C>` field.
 *
 * - `verifyingShares` is the per-party `s_i · G` map, keyed by `bigint`
 *   identifier. The map shape (rather than a list) is intentional: every
 *   downstream consumer that needs a particular party's verifying share
 *   already knows the party identifier and would otherwise have to scan a
 *   list. Insertion order matches the dealer's identifier ordering, but
 *   consumers should not rely on it.
 * - `verifyingKey` is the **raw** aggregate group verifying key (matching
 *   the convention on `KeyPackage` — see the type-wrapper conventions
 *   block at the top of this file). 33-byte SEC1 compressed.
 * - `minSigners` is the threshold `t`. Carried here as well as on
 *   `KeyPackage` because aggregation needs it without having to look at
 *   any individual party's package.
 */
export interface PublicKeyPackage {
  readonly verifyingShares: ReadonlyMap<bigint, Uint8Array>;
  readonly verifyingKey: Uint8Array;
  readonly minSigners: number;
}

/**
 * The dealer-issued (or DKG-derived) per-party share, ready to be turned
 * into a `KeyPackage` by `finalizeKeygen`. Mirrors `frost_core::keys::SecretShare<C>`
 * minus the `Header<C>` field.
 *
 * The `commitment` field is the dealer's polynomial commitment as a list of
 * 33-byte SEC1 compressed points: `commitment[i] = polynomial_coefficients[i] · G`.
 * **Every share from a single dealer ceremony carries the same commitment**
 * (there is one polynomial per dealer call). The commitment's length equals
 * the threshold `t = minSigners`, and `commitment[0]` is the aggregate
 * verifying key.
 *
 * `finalizeKeygen` uses the commitment in two ways:
 *   1. **VSS verification:** check that `signingShare · G == evalPolyOnPoints(commitment, identifier)`.
 *      A failed check means the dealer (or transport) corrupted the share —
 *      the participant must reject it.
 *   2. **Aggregate verifying key derivation:** `verifyingKey = commitment[0]`.
 */
export interface SecretShare {
  readonly identifier: bigint;
  readonly signingShare: bigint;
  readonly commitment: readonly Uint8Array[];
}

/**
 * `finalizeKeygen` — turn a dealer-issued `SecretShare` into the per-party
 * `KeyPackage` used by `signRound1` / `signRound2`.
 *
 * Mirrors `KeyPackage::try_from(SecretShare)` semantics from
 * `frost-core/src/keys.rs:578-606` (which delegates to `SecretShare::verify`
 * at lines 449-475 for the VSS check, then constructs the package).
 *
 * Steps:
 *   1. **VSS verification.** Compute `signingShare · G` and
 *      `evalPolyOnPoints(commitment, identifier)`. If they differ, the share
 *      is invalid — throw, matching Rust's `Error::InvalidSecretShare`.
 *      Built on the already-validated `evalPolyOnPoints` primitive (Step 3
 *      ledger #4) so the test surface here is purely composition.
 *   2. **Construct the `KeyPackage`.** `verifyingShare = signingShare · G`
 *      (the same point we just computed for VSS), `verifyingKey = commitment[0]`
 *      (the polynomial constant term, which is the aggregate group key),
 *      `minSigners = commitment.length`.
 *
 * **Returns the raw KeyPackage.** Per the type-wrapper convention at the
 * top of this file, BIP340 `pre_sign` parity normalization is the
 * responsibility of `signRound2`, NOT `finalizeKeygen`. For dealer-flow
 * fixtures the raw aggregate verifying key has odd y at our test seeds, so
 * the returned `verifyingKey` may start with `0x03`. That is intentional
 * and correct — `signRound2` will normalize it (and the matching
 * `signingShare`) before calling `computeSignatureShare`.
 *
 * **Note on the dealer-vs-DKG asymmetry** (per `RUST_REFERENCE_NOTES.md` §5.1.5):
 * for dealer mode, `verifyingKey` is `Σ s_i · G` directly (the
 * polynomial constant term, untweaked). For DKG mode, the equivalent
 * finalize step ALSO has to apply `applyDkgTweakToShare` /
 * `applyDkgTweakToPubkey` (Step 3 primitives #7/#8) to match Rust's
 * `post_dkg` hook. The DKG variant is not yet implemented — see PLAN.md
 * Step 4 sub-step 6.
 */
export function finalizeKeygen(secretShare: SecretShare): KeyPackage {
  const { identifier, signingShare, commitment } = secretShare;

  if (commitment.length === 0) {
    throw new Error('finalizeKeygen: commitment must be non-empty');
  }

  // Parse the commitment points once (also validates SEC1 encoding).
  const commitmentPoints: Point[] = commitment.map((bytes) =>
    secp256k1.Point.fromBytes(bytes),
  );

  // VSS check: signingShare · G == f(identifier) over the commitment polynomial.
  const expectedShareCommitment = evalPolyOnPoints(commitmentPoints, identifier);
  const actualShareCommitment = scalarBaseMul(signingShare);
  if (!expectedShareCommitment.equals(actualShareCommitment)) {
    throw new Error(
      `finalizeKeygen: VSS verification failed for identifier ${identifier} — ` +
        `signingShare does not lie on the dealer's polynomial`,
    );
  }

  // Construct KeyPackage. `verifyingShare = signingShare · G` (the point we
  // just verified), `verifyingKey = commitment[0]` (constant term = group key).
  const verifyingShare = actualShareCommitment.toBytes(true);
  const verifyingKey = commitment[0]!;

  return {
    identifier,
    signingShare,
    verifyingShare,
    verifyingKey,
    minSigners: commitment.length,
  };
}
