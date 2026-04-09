/**
 * Signature share byte-equality test — the load-bearing test for round 2.
 *
 * `compute_signature_share` is the function each signer runs once during
 * round 2 to produce their `z_i` contribution to the joint Schnorr signature.
 * Per `frost-secp256k1-tr/src/lib.rs:395-416` (the `-tr` override) and
 * `frost-core/src/round2.rs:99-111` (the inner core), the formula is:
 *
 *     z_i = d_i + (e_i · rho_i) + (lambda_i · s_i · c)
 *
 * where:
 *   d_i      = hiding nonce scalar (round 1)
 *   e_i      = binding nonce scalar (round 1)
 *   rho_i    = binding factor (computeBindingFactorList output)
 *   lambda_i = Lagrange coefficient (deriveInterpolatingValue output)
 *   s_i      = signing share (post-pre_sign)
 *   c        = Schnorr challenge (the -tr x-only construction)
 *
 * **Two parity normalizations** sit before the formula and are the
 * load-bearing BIP340 enforcement:
 *
 * 1. `pre_sign` (lib.rs:308-325) — calls `key_package.into_even_y(None)`
 *    on the way in. If the operative aggregate verifying key has odd y,
 *    the entire KeyPackage is negated, including the signing share. So
 *    `s_i` is the *negated* signing share if `vk.y` is odd.
 *
 * 2. `compute_signature_share` (lib.rs:395-416) — checks
 *    `group_commitment.has_even_y()`. If false, both nonces are negated:
 *    `d_i, e_i  ←  -d_i, -e_i`.
 *
 * Both normalizations happen before the formula. The aggregate-parity dance
 * is the standard "make-FROST-output-a-BIP340-signature" trick.
 *
 * Test surface: `round_two_outputs[i].sig_share` in each fixture is the
 * captured per-signer `z_i` scalar. The TS port walks the same pipeline
 * and asserts byte-for-byte equivalence. Total assertion count:
 * 2 + 2 + 3 + 3 = 10 byte-equality assertions across the four fixtures.
 *
 * If a regression hits, the strongly-suspect culprits in order are:
 *   (a) wrong sign on the pre_sign normalization (negate when vk.y EVEN
 *       instead of when vk.y ODD)
 *   (b) wrong sign on the aggregate parity (negate when R.y EVEN instead
 *       of when R.y ODD)
 *   (c) forgetting one of the two parity normalizations
 *   (d) field-arithmetic precedence error in `d + e*rho + lambda*s*c`
 *       (left-to-right vs operator precedence)
 *
 * If all 10 assertions pass, the FROST round-2 signing flow is byte-perfect
 * end-to-end against the audited Rust reference. This is the most
 * load-bearing single primitive in the entire signing pipeline.
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
} from '../src/index.ts';
import { intoEvenY } from '../src/secp256k1-tr/point.ts';
import {
  computeBindingFactorList,
  computeGroupCommitment,
  computeSignatureShare,
  challenge as computeChallenge,
  type SigningCommitment,
} from '../src/secp256k1-tr/sign.ts';
import { deriveInterpolatingValue } from '../src/secp256k1-tr/lagrange.ts';

const Fn = secp256k1.Point.Fn;
const Point = secp256k1.Point;

interface PerSignerInputs {
  identifier: number;
  hidingNonce: bigint;
  bindingNonce: bigint;
  signingShare: bigint;
  expectedSigShare: string;
}

interface SignerSession {
  /** Raw aggregate verifying key (pre-pre_sign), used by computeSignatureShare's
   *  parity check on the signing share. */
  rawVerifyingKey: typeof Point.BASE;
  /** Operative verifying key (post-pre_sign even-y normalization). Used to feed
   *  the binding factor / group commitment / challenge helpers, mirroring what
   *  Rust's round2::sign does after pre_sign (frost-core/round2.rs:145-170). */
  operativeVerifyingKey: typeof Point.BASE;
  message: Uint8Array;
  commitments: readonly SigningCommitment[];
  signers: readonly PerSignerInputs[];
}

function loadSession(name: string): SignerSession {
  const isDkg = name.endsWith('_dkg');

  // Build the SigningCommitment list (sorted by identifier)
  const fxAny = isDkg ? loadDkgFixture(name) : loadDealerFixture(name);
  const commitments: SigningCommitment[] = fxAny.round_one_outputs.outputs.map(
    (r1: RoundOneOutput): SigningCommitment => ({
      identifier: r1.identifier,
      hiding: hexToBytes(r1.hiding_nonce_commitment),
      binding: hexToBytes(r1.binding_nonce_commitment),
    }),
  );
  commitments.sort((a, b) => a.identifier - b.identifier);

  // Look up signing shares per fixture flavor
  const sharesById = new Map<number, bigint>();
  if (isDkg) {
    const fx = loadDkgFixture(name);
    for (const p of fx.dkg.part3) {
      sharesById.set(p.identifier, Fn.fromBytes(hexToBytes(p.signing_share)));
    }
  } else {
    const fx = loadDealerFixture(name);
    for (const p of fx.inputs.participant_shares) {
      sharesById.set(p.identifier, Fn.fromBytes(hexToBytes(p.participant_share)));
    }
  }

  // Build per-signer inputs from round 1 + round 2 records
  const sigShareById = new Map<number, string>();
  for (const r2 of fxAny.round_two_outputs.outputs) {
    sigShareById.set(r2.identifier, r2.sig_share);
  }

  const signers: PerSignerInputs[] = [];
  for (const r1 of fxAny.round_one_outputs.outputs) {
    const s = sharesById.get(r1.identifier);
    const expected = sigShareById.get(r1.identifier);
    if (s === undefined || expected === undefined) {
      throw new Error(`fixture ${name} is incomplete for signer ${r1.identifier}`);
    }
    signers.push({
      identifier: r1.identifier,
      hidingNonce: Fn.fromBytes(hexToBytes(r1.hiding_nonce)),
      bindingNonce: Fn.fromBytes(hexToBytes(r1.binding_nonce)),
      signingShare: s,
      expectedSigShare: expected,
    });
  }
  signers.sort((a, b) => a.identifier - b.identifier);

  const rawVerifyingKey = Point.fromBytes(hexToBytes(fxAny.inputs.verifying_key_key));
  return {
    rawVerifyingKey,
    operativeVerifyingKey: intoEvenY(rawVerifyingKey),
    message: hexToBytes(fxAny.inputs.message),
    commitments,
    signers,
  };
}

describe('computeSignatureShare — z_i = d + e·rho + lambda·s·c with parity dance', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    describe(name, () => {
      const session = loadSession(name);

      // Pre-compute the per-session values that all signers share. Helpers
      // take the OPERATIVE (post-pre_sign) verifying key per Rust's round2::sign
      // ordering. computeSignatureShare itself takes the RAW key and applies
      // the parity-on-share normalization internally.
      const bindingFactors = computeBindingFactorList(
        session.operativeVerifyingKey.toBytes(true),
        session.message,
        session.commitments,
      );
      const R = computeGroupCommitment(session.commitments, bindingFactors);
      const c = computeChallenge(R, session.operativeVerifyingKey, session.message);
      const signerIds = session.signers.map((s) => BigInt(s.identifier));

      for (const signer of session.signers) {
        it(`reproduces sig_share for signer ${signer.identifier}`, () => {
          const rho = bindingFactors.get(signer.identifier);
          if (rho === undefined) {
            throw new Error(`no binding factor for signer ${signer.identifier}`);
          }
          const lambda = deriveInterpolatingValue(signerIds, BigInt(signer.identifier));

          const z = computeSignatureShare({
            groupCommitment: R,
            verifyingKey: session.rawVerifyingKey,
            hidingNonce: signer.hidingNonce,
            bindingNonce: signer.bindingNonce,
            signingShare: signer.signingShare,
            bindingFactor: rho,
            lagrange: lambda,
            challenge: c,
          });

          const actual = bytesToHex(Fn.toBytes(z));
          expect(actual).toBe(signer.expectedSigShare);
        });
      }
    });
  }
});
