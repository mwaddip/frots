# API Reference — frots

## Import

```ts
// Default (secp256k1 + BIP340/BIP341 Taproot):
import { dkgRound1, signRound1, ... } from 'frots';

// Explicit ciphersuite:
import { dkgRound1, signRound1, ... } from 'frots/secp256k1-tr';
```

Both entry points export the same API.

---

## Key Generation — Dealer Flow

Use when a trusted dealer distributes shares to participants.

### `finalizeKeygen(secretShare: SecretShare): KeyPackage`

Turn a dealer-issued `SecretShare` into a per-party `KeyPackage`. Runs VSS verification internally and throws if the share doesn't lie on the dealer's polynomial.

```ts
const keyPackage = finalizeKeygen({
  identifier: 1n,
  signingShare: 0xabc...n,              // bigint
  commitment: [commitmentPoint0, ...],   // Uint8Array[] (33-byte SEC1)
});
```

---

## Key Generation — DKG Flow

Use when parties jointly generate keys without a trusted dealer. Three round trips.

### `dkgRound1(identifier: bigint, maxSigners: number, minSigners: number, rng: Rng): { secretPackage: Round1SecretPackage; package: Round1Package }`

Generate a party's secret polynomial, public commitments, and proof of knowledge.

- **RNG consumption:** `(minSigners + 1) * 32` bytes per party.
- Returns `secretPackage` (private, consumed by `dkgRound2`) and `package` (broadcast to all other parties).

### `dkgRound2(secretPackage: Round1SecretPackage, receivedRound1: ReadonlyMap<bigint, Round1Package>): { secretPackage: Round2SecretPackage; packages: ReadonlyMap<bigint, Round2Package> }`

Verify all received round 1 proofs of knowledge, then compute per-recipient secret shares.

- Throws if any proof of knowledge is invalid.
- Returns `secretPackage` (private, consumed by `dkgFinalize`) and `packages` (one per other party, sent privately to each).

### `dkgFinalize(secretPackage: Round2SecretPackage, receivedRound1: ReadonlyMap<bigint, Round1Package>, receivedRound2: ReadonlyMap<bigint, Round2Package>): { keyPackage: KeyPackage; publicKeyPackage: PublicKeyPackage }`

Verify received shares via VSS, compute the aggregate group key, and apply the BIP341 post-DKG tap tweak.

- Throws if any received share fails VSS verification.
- Returns the per-party `KeyPackage` and group `PublicKeyPackage`, both with the post-tweak verifying key.

### `dkgVerifyProofOfKnowledge(pkg: Round1Package): void`

Standalone verification of a round 1 proof of knowledge. Called internally by `dkgRound2` but also available for manual pre-checks. Throws on failure.

---

## Signing

Used identically for both dealer and DKG flows. Requires a `KeyPackage` per signer and a `PublicKeyPackage` for the coordinator.

### `signRound1(keyPackage: KeyPackage, rng: Rng): Round1Output`

Derive per-signer secret nonces and public commitments.

- **RNG consumption:** 64 bytes (32 hiding + 32 binding).
- Returns `{ nonces: SigningNonces, commitments: SigningCommitment }`.
- `nonces` are private and consumed by `signRound2`. `commitments` are broadcast.

### `signRound2(keyPackage: KeyPackage, nonces: SigningNonces, message: Uint8Array, commitments: readonly SigningCommitment[], options?: { tweaked?: boolean }): SignatureShare`

Produce a per-signer signature share.

- `message` is the 32-byte message hash being signed.
- `commitments` is the full list of all signers' round 1 commitments.
- `options.tweaked` (default `true`): when `false`, signs under the **untweaked** aggregate key using `keyPackage.untweakedSigningShare` and `keyPackage.untweakedVerifyingKey`. Used for OPNet script-path inputs and other scenarios requiring signatures under the raw aggregate key.
- No RNG consumption. Deterministic given inputs.

### `signAggregate(signatureShares: readonly SignatureShare[], message: Uint8Array, commitments: readonly SigningCommitment[], publicKeyPackage: PublicKeyPackage, options?: { tweaked?: boolean }): Uint8Array`

Combine signature shares into a 64-byte BIP340 Schnorr signature.

- `options.tweaked` (default `true`): when `false`, aggregates under the untweaked key. All shares must have been produced with `signRound2(..., { tweaked: false })`.
- Runs BIP340 verification internally. Throws on failure.
- **Cheater detection:** if verification fails, scans each share individually and reports the culprit identifier(s) in the error message.

### `verifySignature(signature: Uint8Array, message: Uint8Array, verifyingKey: Uint8Array): boolean`

Standalone BIP340 signature verification. Returns `true` if valid.

- `signature`: 64-byte BIP340 compact (`R_x || z`).
- `verifyingKey`: 33-byte SEC1 compressed aggregate public key.

---

## Types

### `KeyPackage`

Per-party signing material. Produced by `finalizeKeygen` (dealer) or `dkgFinalize` (DKG).

```ts
interface KeyPackage {
  readonly identifier: bigint;
  readonly signingShare: bigint;
  readonly verifyingShare: Uint8Array;          // 33-byte SEC1
  readonly verifyingKey: Uint8Array;            // 33-byte SEC1 (aggregate, post-tweak)
  readonly minSigners: number;
  readonly untweakedVerifyingKey: Uint8Array;   // 33-byte SEC1 (aggregate, pre-tweak)
  readonly untweakedSigningShare: bigint;
  readonly untweakedVerifyingShare: Uint8Array; // 33-byte SEC1
}
```

For dealer flow, the untweaked fields equal the tweaked fields (dealer does not apply the tap tweak).

### `PublicKeyPackage`

Group public material. Shared by all parties and used by the coordinator.

```ts
interface PublicKeyPackage {
  readonly verifyingShares: ReadonlyMap<bigint, Uint8Array>;          // per-party, 33-byte SEC1 (post-tweak)
  readonly verifyingKey: Uint8Array;                                   // 33-byte SEC1 (aggregate, post-tweak)
  readonly minSigners: number;
  readonly untweakedVerifyingKey: Uint8Array;                          // 33-byte SEC1 (aggregate, pre-tweak)
  readonly untweakedVerifyingShares: ReadonlyMap<bigint, Uint8Array>;  // per-party, 33-byte SEC1 (pre-tweak)
}
```

### `SecretShare`

Dealer-issued share, input to `finalizeKeygen`.

```ts
interface SecretShare {
  readonly identifier: bigint;
  readonly signingShare: bigint;
  readonly commitment: readonly Uint8Array[];  // t SEC1 points
}
```

### `Round1SecretPackage`

Private state after `dkgRound1`. Do not share.

```ts
interface Round1SecretPackage {
  readonly identifier: bigint;
  readonly polynomialCoefficients: readonly bigint[];
  readonly commitment: readonly Uint8Array[];
  readonly minSigners: number;
  readonly maxSigners: number;
}
```

### `Round1Package`

Public broadcast after `dkgRound1`. Sent to all other parties.

```ts
interface Round1Package {
  readonly identifier: bigint;
  readonly commitment: readonly Uint8Array[];
  readonly proofOfKnowledge: {
    readonly R: Uint8Array;  // 33-byte SEC1
    readonly z: bigint;
  };
}
```

### `Round2SecretPackage`

Private state after `dkgRound2`. Do not share.

```ts
interface Round2SecretPackage {
  readonly identifier: bigint;
  readonly commitment: readonly Uint8Array[];
  readonly secretShare: bigint;
  readonly minSigners: number;
  readonly maxSigners: number;
}
```

### `Round2Package`

Per-recipient secret share from `dkgRound2`. Send privately to the named recipient.

```ts
interface Round2Package {
  readonly sender: bigint;
  readonly recipient: bigint;
  readonly signingShare: bigint;
}
```

### `Rng`

Random number generator interface. Any object with a `fillBytes` method.

```ts
interface Rng {
  fillBytes(dest: Uint8Array): void;
}
```

For production, wrap `crypto.getRandomValues`:

```ts
const rng: Rng = {
  fillBytes(dest: Uint8Array) {
    crypto.getRandomValues(dest);
  },
};
```

### `SigningNonces`

Private nonces from `signRound1`. Used once in `signRound2`, then discarded.

```ts
interface SigningNonces {
  readonly hiding: bigint;
  readonly binding: bigint;
}
```

### `SigningCommitment`

Public commitment from `signRound1`. Broadcast to all signers.

```ts
interface SigningCommitment {
  readonly identifier: number;
  readonly hiding: Uint8Array;   // 33-byte SEC1
  readonly binding: Uint8Array;  // 33-byte SEC1
}
```

### `SignatureShare`

Per-signer signature share from `signRound2`.

```ts
interface SignatureShare {
  readonly identifier: number;
  readonly share: bigint;
}
```

### `Round1Output`

Return type of `signRound1`.

```ts
interface Round1Output {
  readonly nonces: SigningNonces;
  readonly commitments: SigningCommitment;
}
```
