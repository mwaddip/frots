/**
 * KeyPackage type wrapper — sub-step 1a of Step 4.
 *
 * No new primitive logic — this is a shape / loader smoke test for the
 * `KeyPackage` interface introduced in `src/keys.ts`. It loads a dealer
 * fixture, manually constructs a `KeyPackage` from the `participant_shares`
 * and `verifying_key_key` fields, and asserts the field types and lengths
 * match expectations. This locks the public-API convention before later
 * sub-steps build wrappers on top of it.
 *
 * The deeper byte-equality test for `finalizeKeygen` (which actually runs
 * VSS verification + constructs the package from a `SecretShare`) lives in
 * `tests/finalize-keygen.test.ts`.
 */

import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import {
  hexToBytes,
  loadDealerFixture,
  type ParticipantShare,
} from '../src/index.ts';
import type { KeyPackage, PublicKeyPackage } from '../src/secp256k1-tr/keys.ts';

const Fn = secp256k1.Point.Fn;

describe('KeyPackage interface — shape smoke test against dealer fixtures', () => {
  for (const name of ['secp256k1_tr_2of3_dealer', 'secp256k1_tr_3of5_dealer'] as const) {
    it(`${name}: constructs one KeyPackage per participant share`, () => {
      const fx = loadDealerFixture(name);
      const minSigners = Number(fx.config.MIN_PARTICIPANTS);
      const verifyingKey = hexToBytes(fx.inputs.verifying_key_key);

      // Construct a KeyPackage per participant from the fixture's
      // dealer-issued share material. This mirrors the shape that the
      // forthcoming `finalizeKeygen` will return — but built by hand here
      // to lock the type, not the construction logic.
      const packages: KeyPackage[] = fx.inputs.participant_shares.map(
        (share: ParticipantShare): KeyPackage => {
          const ss = Fn.fromBytes(hexToBytes(share.participant_share));
          const vs = hexToBytes(share.verifying_share);
          return {
            identifier: BigInt(share.identifier),
            signingShare: ss,
            verifyingShare: vs,
            verifyingKey,
            minSigners,
            // Dealer flow: untweaked = tweaked (no tap tweak applied).
            untweakedVerifyingKey: verifyingKey,
            untweakedSigningShare: ss,
            untweakedVerifyingShare: vs,
          };
        },
      );

      expect(packages.length).toBe(fx.inputs.participant_shares.length);
      for (const kp of packages) {
        // identifier is a positive bigint (Rust identifiers are non-zero u16)
        expect(typeof kp.identifier).toBe('bigint');
        expect(kp.identifier > 0n).toBe(true);

        // signingShare is a scalar in [0, n)
        expect(typeof kp.signingShare).toBe('bigint');
        expect(kp.signingShare >= 0n && kp.signingShare < Fn.ORDER).toBe(true);

        // verifyingShare is a 33-byte SEC1 compressed point (0x02/0x03 prefix)
        expect(kp.verifyingShare).toBeInstanceOf(Uint8Array);
        expect(kp.verifyingShare.length).toBe(33);
        expect(kp.verifyingShare[0] === 0x02 || kp.verifyingShare[0] === 0x03).toBe(true);

        // verifyingKey is a 33-byte SEC1 compressed point
        expect(kp.verifyingKey).toBeInstanceOf(Uint8Array);
        expect(kp.verifyingKey.length).toBe(33);
        expect(kp.verifyingKey[0] === 0x02 || kp.verifyingKey[0] === 0x03).toBe(true);

        // minSigners is the threshold (t in t-of-n)
        expect(typeof kp.minSigners).toBe('number');
        expect(kp.minSigners).toBeGreaterThan(0);
        expect(kp.minSigners).toBe(minSigners);
      }
    });
  }
});

describe('PublicKeyPackage interface — shape smoke test against dealer fixtures', () => {
  for (const name of ['secp256k1_tr_2of3_dealer', 'secp256k1_tr_3of5_dealer'] as const) {
    it(`${name}: constructs a PublicKeyPackage from the dealer fixture`, () => {
      const fx = loadDealerFixture(name);
      const minSigners = Number(fx.config.MIN_PARTICIPANTS);
      const verifyingKey = hexToBytes(fx.inputs.verifying_key_key);

      const verifyingShares = new Map<bigint, Uint8Array>();
      for (const share of fx.inputs.participant_shares) {
        verifyingShares.set(BigInt(share.identifier), hexToBytes(share.verifying_share));
      }

      const pkp: PublicKeyPackage = {
        verifyingShares,
        verifyingKey,
        minSigners,
        untweakedVerifyingKey: verifyingKey,
        untweakedVerifyingShares: verifyingShares,
      };

      expect(pkp.verifyingShares.size).toBe(fx.inputs.participant_shares.length);
      for (const [id, vs] of pkp.verifyingShares) {
        expect(typeof id).toBe('bigint');
        expect(id > 0n).toBe(true);
        expect(vs).toBeInstanceOf(Uint8Array);
        expect(vs.length).toBe(33);
        expect(vs[0] === 0x02 || vs[0] === 0x03).toBe(true);
      }

      expect(pkp.verifyingKey).toBeInstanceOf(Uint8Array);
      expect(pkp.verifyingKey.length).toBe(33);
      expect(pkp.verifyingKey[0] === 0x02 || pkp.verifyingKey[0] === 0x03).toBe(true);
      expect(pkp.minSigners).toBe(minSigners);
    });
  }
});
