# frots

Pure-TypeScript implementation of [FROST](https://www.rfc-editor.org/rfc/rfc9591.html) (Flexible Round-Optimized Schnorr Threshold Signatures) for **secp256k1 with BIP340/BIP341 Taproot** support.

This is a direct port of the Zcash Foundation's audited [`frost-secp256k1-tr`](https://crates.io/crates/frost-secp256k1-tr) Rust crate, validated **byte-for-byte** against the reference implementation. Every intermediate value — hash outputs, polynomial evaluations, nonces, signature shares, and final signatures — is tested for exact equality with the Rust crate's output given identical inputs.

## Reference Implementation

**Source:** [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) (look in `frost-secp256k1-tr/`)

The `frost-secp256k1-tr` crate is part of the Zcash Foundation's FROST library, which has been [audited](https://zfnd.org/frost-2-1-0-release/) and is used in production. This TypeScript port targets the same ciphersuite: `FROST-secp256k1-SHA256-TR-v1`.

## Install

```bash
npm install frots
```

## Quick Start

### DKG Flow (Distributed Key Generation)

```ts
import {
  dkgRound1,
  dkgRound2,
  dkgFinalize,
  signRound1,
  signRound2,
  signAggregate,
  type Rng,
} from 'frots';

const rng: Rng = {
  fillBytes: (dest) => crypto.getRandomValues(dest),
};

// === DKG: each party runs independently ===

// Round 1: generate polynomial + commitments + proof of knowledge
const { secretPackage: secret1, package: package1 } = dkgRound1(1n, 3, 2, rng);
const { secretPackage: secret2, package: package2 } = dkgRound1(2n, 3, 2, rng);
const { secretPackage: secret3, package: package3 } = dkgRound1(3n, 3, 2, rng);

// Round 2: verify PoKs + compute per-recipient shares
const round2_1 = dkgRound2(secret1, new Map([[2n, package2], [3n, package3]]));
const round2_2 = dkgRound2(secret2, new Map([[1n, package1], [3n, package3]]));
const round2_3 = dkgRound2(secret3, new Map([[1n, package1], [2n, package2]]));

// Finalize: VSS verify + aggregate key + apply BIP341 tap tweak
const { keyPackage: kp1, publicKeyPackage } = dkgFinalize(
  round2_1.secretPackage,
  new Map([[2n, package2], [3n, package3]]),
  new Map([[2n, round2_2.packages.get(1n)!], [3n, round2_3.packages.get(1n)!]]),
);
// (repeat for each party to get their keyPackage)

// === Signing: any t-of-n subset ===

const message = new Uint8Array(32); // your message hash

// Round 1: each signer generates nonces + commitments
const r1_1 = signRound1(kp1, rng);
const r1_2 = signRound1(kp2, rng);
const allCommitments = [r1_1.commitments, r1_2.commitments];

// Round 2: each signer produces a signature share
const share1 = signRound2(kp1, r1_1.nonces, message, allCommitments);
const share2 = signRound2(kp2, r1_2.nonces, message, allCommitments);

// Aggregate: coordinator combines shares into a BIP340 signature
const signature = signAggregate(
  [share1, share2],
  message,
  allCommitments,
  publicKeyPackage,
);
// signature is a 64-byte Uint8Array — a standard BIP340 Schnorr signature
```

### Tweaked vs Untweaked Signing

After DKG, `keyPackage` and `publicKeyPackage` carry both the BIP341 Taproot-tweaked key and the raw untweaked key. By default, signing uses the tweaked key (for Taproot key-path spends). Pass `{ tweaked: false }` for script-path inputs or any scenario requiring the raw aggregate key:

```ts
// Key-path spend (tweaked, default):
const share = signRound2(kp, nonces, message, commitments);
const sig = signAggregate([...shares], message, commitments, publicKeyPackage);
verifySignature(sig, message, publicKeyPackage.verifyingKey); // true

// Script-path spend (untweaked):
const share = signRound2(kp, nonces, message, commitments, { tweaked: false });
const sig = signAggregate([...shares], message, commitments, publicKeyPackage, { tweaked: false });
verifySignature(sig, message, publicKeyPackage.untweakedVerifyingKey); // true
```

### Dealer Flow (Trusted Dealer)

```ts
import { finalizeKeygen, signRound1, signRound2, signAggregate } from 'frots';

// The dealer distributes SecretShares to each party.
// Each party finalizes their KeyPackage:
const keyPackage = finalizeKeygen({
  identifier: 1n,
  signingShare: dealerIssuedShare,
  commitment: dealerCommitmentPoints,
});

// Then signing proceeds identically to the DKG flow above.
```

## API

See [API.md](./API.md) for the full API reference.

## Ciphersuite

This package currently implements a single ciphersuite:

| Ciphersuite | ID | Curve | Hash | Tweak |
|---|---|---|---|---|
| `secp256k1-tr` | `FROST-secp256k1-SHA256-TR-v1` | secp256k1 | SHA-256 | BIP341 Taproot |

The repo is structured to support additional ciphersuites in the future (e.g., Ed25519). Curve-specific code lives under `src/<ciphersuite>/`.

## Validation Strategy

Instead of reimplementing ChaCha20Rng in TypeScript, the test suite uses a **deterministic RNG replay** strategy:

1. A Rust fixture harness (`fixture-gen/`) runs the reference `frost-secp256k1-tr` crate with a fixed RNG seed and records every consumed random byte alongside every intermediate value.
2. The TypeScript tests replay those exact bytes through the same protocol steps and assert byte-for-byte equality at every level.

This means every hash output, polynomial evaluation, nonce derivation, signature share, and final signature in the TypeScript port is proven identical to the audited Rust implementation for the same inputs. 242 assertions across 28 test suites cover both 2-of-3 and 3-of-5 configurations for dealer and DKG flows.

## Dependencies

- [`@noble/curves`](https://github.com/paulmillr/noble-curves) `2.0.1` — secp256k1 point/scalar operations, BIP340 tagged hashes
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) `2.0.1` — SHA-256

No other runtime dependencies.

## Specs

- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) — FROST: Flexible Round-Optimized Schnorr Threshold Signatures
- [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) — Schnorr Signatures for secp256k1
- [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) — Taproot: SegWit version 1 spending rules

## License

MIT
