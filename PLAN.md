# frots — FROST in TypeScript

**Created:** 2026-04-08
**Status:** Pre-implementation. No code written. This file is the entry point for a focused session on porting FROST to pure TypeScript.
**Origin context:** Otzi (PERMAFROST Vault) — see `~/projects/otzi/docs/superpowers/research/2026-04-08-frost-integration-research.md` for the broader integration story. This file is narrower: it's just about producing the standalone FROST library that Otzi will eventually consume.

---

## Goal

Build a pure-TypeScript FROST (RFC 9591) implementation for **secp256k1 with BIP340/BIP341 Taproot tweak support**, suitable for use in Otzi's threshold BTC wallet. Validate the implementation **byte-for-byte against the Zcash Foundation's audited `frost-secp256k1-tr` Rust crate**.

The output is a standalone library — no UI, no relay, no network. Pure functions taking and returning bytes/structs. Otzi will consume it later by wrapping it in a ceremony state machine and a `multiSignPsbt`-implementing signer.

## Why Pure TS Instead of Compiling Rust to WASM

Both options are on the table. Reasons to try the pure-TS port first:

- **No exotic toolchain in the JS-first project.** WASM adds `wasm-pack`, async init, ~200-500 KB bundle, and a Rust dependency that future maintainers must understand.
- **Byte-for-byte tests against the Rust crate provide confidence equivalent to a meaningful portion of the audit.** If every primitive's output equals the Rust crate's output for the same inputs, the TS port inherits much of the audit's value (it's not the same as being audited, but it rules out almost every implementation bug).
- **WASM is the fallback.** If the TS port stalls — specifically, if hash-to-scalar matches but downstream primitives diverge in subtle ways we can't reconcile — bail and compile `frost-secp256k1-tr` to WASM instead. The fixture harness (step 1 below) is reusable in either path.

## What Exists in the JS Ecosystem (Verified 2026-04-08)

| Package | Curve | Status | Verdict |
|---|---|---|---|
| `@noble/curves` 2.0.1 | — | **No FROST.** Zero "frost" string anywhere in source/README/exports. Earlier search-engine claims that it implements FROST were hallucinated. | Use as primitive base only |
| `@substrate-system/frost` 0.0.9 | Ed25519 only | Alpha, no audit | Wrong curve |
| `@toruslabs/tss-frost-client` 0.4.1 | Tied to Torus's hosted TSS service via socket.io | Not standalone | Not viable |

**Conclusion:** No mature, self-hostable, secp256k1+Taproot FROST library on npm. Pure-TS port is genuinely novel work.

## What Exists Outside JS

- **`frost-secp256k1-tr`** (Rust, Zcash Foundation) — BIP340/BIP341-compatible. Audited. Used in production by Noosphere (Dart ROAST server) and Blockchain Commons frost-tools. **This is the reference implementation we test against.** crates.io: https://crates.io/crates/frost-secp256k1-tr
- **`bancaditalia/secp256k1-frost`** (C, Bank of Italy) — secondary cross-check option if needed.
- **Noosphere** (Dart) — application-layer reference, useful for understanding ROAST coordination but not the protocol primitives.
- **`frostrb`** (Ruby) — too far from our target.

## The Kushti Red Herring (Don't Chase This)

Kushti (Ergo founder) has talked about "vaults with hundreds of off-chain Schnorr signers" and authored **Ergo EIP-11 "Distributed Signatures"** (`ergoplatform/eips#8`). This is real, scales to hundreds of parties, and uses secp256k1 underneath.

**It is NOT FROST and NOT directly reusable for Bitcoin Taproot:**

- EIP-11 is built on **Sigma protocols**, not RFC 9591 FROST.
- The cited paper is Lindell's "Simple Three-Round Multiparty Schnorr Signing with Full Simulatability" (2022, https://eprint.iacr.org/2022/374.pdf) — different round structure than FROST.
- The output is a **Sigma proof**, not a BIP340 Schnorr signature. It will not verify on Bitcoin.
- Reference implementation is in **Scala** (Ergo node), with a partial Rust port effort in `sigma-rust` (issue #367 was a 500-SigmaUSD bounty).

EIP-11 is interesting as proof that "threshold Schnorr-like signing at scale works in production," but it cannot be borrowed as code or as a protocol design. Don't waste a session on it.

---

## Implementation Plan (Dependency Order)

### Step 0 — Read the Reference

One session inside `ZcashFoundation/frost/frost-secp256k1-tr`. Goal: spec-by-example understanding.

Output of this step is a written summary (in this directory) of:
- Module layout and public API surface
- Exact H1–H5 hash domain tags (the per-step domain-separation strings — these MUST match byte-for-byte)
- How randomness is injected (the crate uses `RngCore` from `rand`, seedable in tests via `ChaCha20Rng::from_seed`)
- Point and scalar serialization formats (expected: 33-byte compressed SEC1, 32-byte big-endian scalars — verify)
- How the Taproot tweak is applied. The `-tr` crate's special sauce: `t = tapTweakHash(toXOnly(P_aggregate))` is applied to the aggregate pubkey *before* signing, so partial signers know they're signing under the tweaked key. Read `Identifier` and `SigningPackage` to find where this diverges from plain `frost-secp256k1`.

Also confirm `@noble/curves` exposes everything we need:
- secp256k1 point ops: add, scalar-mul, generator, identity (expected via `secp256k1.ProjectivePoint`)
- Scalar arithmetic mod n (expected via `abstract/modular`)
- Point serialization in 33-byte compressed SEC1
- BIP340 x-only conversion (`lift_x`)

If any of these are missing, plan changes.

### Step 1 — Rust Fixture Harness

Tiny CLI binary in this directory: `fixture-gen/` (separate Cargo project, depends on `frost-secp256k1-tr`). The binary:

- Takes a fixed RNG seed (e.g. `[0u8; 32]`)
- Runs a 2-of-3 DKG end to end
- Runs a signing ceremony on a known 32-byte message hash
- Dumps **every intermediate value at every protocol step** to a single JSON file:
  - DKG: polynomial coefficients per party, commitments per party, proof-of-knowledge per party, secret shares per (party, recipient) pair, aggregate verification key
  - Signing: per-party signing nonces, per-party signing commitments, per-party partial sigs, final 64-byte BIP340 aggregate sig
  - Both plain and Taproot-tweaked variants
- **Also dumps the consumed random bytes alongside each output**, so the TS side can replay them from a buffer instead of reimplementing ChaCha20. (See "RNG strategy" below.)

This is a one-time effort. The output JSON file is the golden vector for the TS port.

Generate at least: 2-of-3, 3-of-5. Both plain and `-tr` (Taproot). Same fixed seed across all.

### Step 2 — TypeScript Skeleton

`src/` directory in this project. Contains:

- `package.json` with `@noble/curves`, `@noble/hashes`, `vitest` as deps
- A fixture loader that parses the JSON from step 1
- A **deterministic RNG shim**: takes the consumed-random-bytes buffer from the fixture and replays it byte-for-byte. This is the load-bearing piece for byte-equality testing.
- An empty test runner ready to grow

### Step 3 — Port Primitives Bottom-Up

One at a time. **Each primitive gets a fixture-driven byte-equality test before moving to the next.** If a test fails, do not move on — the bug compounds downstream.

1. **Hash-to-scalar** with the H1–H5 domain tags. Built on `@noble/hashes`. Test against the Rust harness's recorded hash outputs for known inputs.
2. **Polynomial generation + commitment.** Uses `@noble/curves` secp256k1 generator. Consumes the RNG shim for coefficients.
3. **DKG round 1** — party-local commitments + proof of knowledge.
4. **DKG round 2** — per-recipient secret shares.
5. **VSS share verification.**
6. **Signing nonce generation** — consumes the RNG shim.
7. **Signing commitment generation.**
8. **Partial signature generation.**
9. **Signature aggregation** → 64-byte BIP340 sig.
10. **Taproot tweak adjustment** — the `-tr` crate's special sauce. Verify the resulting sig validates under `P_aggregate + tapTweakHash·G` using `@noble/curves` BIP340 verification.

### Step 4 — Public API Surface

Compose primitives into clean public functions. No state machine yet — pure functions taking and returning bytes/structs:

```ts
dkgRound1(params, partyIndex, rng): Round1Output
dkgRound2(params, partyIndex, round1Inputs): Round2Output
finalizeKeygen(params, round2Inputs): KeyShare
signRound1(keyShare, rng): SigningCommitment
signRound2(keyShare, message, allCommitments): PartialSignature
aggregate(commitments, partialSigs, message): BIP340Signature
```

The state machine is a UI / ceremony concern that comes later, in Otzi.

### Step 5 — End-to-End Equivalence Test

Drive the public API with the same seed as the Rust harness and verify the final aggregate signature matches byte-for-byte. If yes, the port is done.

---

## Critical Watch-Outs

### RNG Strategy

The most fragile part of byte-equality testing. Two options:

- **Reimplement ChaCha20Rng in TS** (`@noble/ciphers` has ChaCha20). Hard to get exactly right because Rust's `ChaCha20Rng` from `rand_chacha` has specific block-counter and seeding semantics.
- **RECOMMENDED: Have the Rust harness pre-compute and emit consumed random bytes alongside each output.** The TS side replays from a buffer. Much simpler. The only cost is fixture file size (small).

Default to the second approach. The first approach is a fallback if for some reason we need to generate fixtures on the JS side too.

### Hash Domain Tags

FROST domain-separates all its hashes via tagged H1–H5. The exact tag bytes are spec-defined in RFC 9591 but with ciphersuite-specific overrides — `frost-secp256k1-tr` will have tags that differ from plain `frost-secp256k1`. Step 0 must extract the exact bytes from the Rust source. A single byte off here breaks every downstream primitive.

### Taproot Tweak Application

The `-tr` variant applies the BIP341 tap tweak to the aggregate pubkey before signing. This means:

- During DKG: compute the untweaked aggregate, then derive the tweaked one and treat that as the operative public key
- During signing: partial signers must know they're signing under the tweaked key, not the raw aggregate
- The math works because the tap tweak is publicly computable (`t = tapTweakHash(toXOnly(P_aggregate))`) — every party can adjust independently

Read the Rust crate's `SigningPackage` and `Identifier` carefully. This is where `-tr` diverges from plain `frost-secp256k1` and where bugs are most likely.

### Point Serialization

`@noble/curves` defaults to 33-byte compressed SEC1, which should match `frost-secp256k1-tr`. **Verify in step 0.** A mismatch here breaks every primitive that returns a point.

### Scalar Encoding

32-byte big-endian, mod the secp256k1 curve order n. Standard, but verify the Rust crate doesn't do something exotic (mod p instead of mod n, little-endian, etc.).

### `@noble/curves` API Gaps

Step 0 must `grep` `secp256k1.d.ts` to confirm everything we need is exposed. If `@noble/curves` doesn't expose, e.g., raw point addition outside of an ECDSA wrapper, we may need to drop to `abstract/weierstrass` directly.

---

## Decision Log

| Date | Decision | Reasoning |
|---|---|---|
| 2026-04-08 | Pure TS over WASM as first attempt | Avoids exotic toolchain, byte-for-byte tests give confidence equivalent to a meaningful portion of the audit, WASM is fallback |
| 2026-04-08 | Test against `frost-secp256k1-tr` (ZF), not RFC 9591 vectors directly | RFC vectors test final outputs only; byte-for-byte against Rust catches every spec-underspecified detail |
| 2026-04-08 | Ergo EIP-11 is a red herring | Different protocol (Sigma proofs), different output (not BIP340), different language (Scala) |
| 2026-04-08 | RNG: replay from buffer, not reimplement ChaCha20 | Much simpler, cost is small fixture file size |

## Pointers

### Reference implementation
- `frost-secp256k1-tr` crate: https://crates.io/crates/frost-secp256k1-tr
- Source: https://github.com/ZcashFoundation/frost (look in `frost-secp256k1-tr/`)
- Adding-the-crate PR (good context on what's `-tr`-specific): https://github.com/ZcashFoundation/frost/pull/730
- ZF FROST 2.1.0 release notes: https://zfnd.org/frost-2-1-0-release/

### Application-layer references
- Noosphere (Dart ROAST server, uses `frost-secp256k1-tr` underneath): https://forum.zcashcommunity.com/t/noosphere-a-roast-server-and-client-for-frost-threshold-signatures/51372

### Specs
- RFC 9591 (FROST): https://www.rfc-editor.org/rfc/rfc9591.html
- BIP340 (Schnorr): https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- BIP341 (Taproot, including tap tweak): https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

### Otzi context (the consumer of this library)
- Broader integration research: `~/projects/otzi/docs/superpowers/research/2026-04-08-frost-integration-research.md`
- Otzi backend signer pattern (the `multiSignPsbt` discovery): see Path 2 section of the integration research
- Otzi's existing `@noble/curves` usage: `~/projects/otzi/node_modules/@noble/curves/` (version 2.0.1 confirmed installed)

---

## Suggested Order for the First Focused Session

1. Read the Rust crate (Step 0). Write the spec-by-example summary as `~/projects/frots/RUST_REFERENCE_NOTES.md`.
2. Confirm `@noble/curves` API gaps. If any blockers found, update this plan.
3. Build the Rust fixture harness (Step 1). Generate fixtures for 2-of-3, both plain and `-tr`.
4. Set up the TS skeleton (Step 2).
5. Port the first primitive — hash-to-scalar — and get its fixture test green.

That's a realistic single-session scope. Steps 3–5 (the rest of the primitive port) are the bulk of the work and span multiple sessions.

The moment that hash-to-scalar matches byte-for-byte is the moment this whole strategy is validated. Until then, treat the project as exploratory.
