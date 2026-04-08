# RUST_REFERENCE_NOTES — frost-secp256k1-tr

**Purpose:** Single source of truth for the TypeScript port of `frost-secp256k1-tr`. Every claim cites a Rust source file (relative to `.reference/frost/`) by `path:line`. Where the byte-level construction matters, the exact bytes are written out and the noble/curves equivalent is named explicitly.

**Reference crate version:** Whatever ZcashFoundation/frost is at HEAD on 2026-04-08 (shallow clone). The lib.rs read passes are off the local copy; lines are stable for this commit but should be re-cited if the crate is re-cloned.

**Reference crate location:** `/home/mwaddip/projects/frots/.reference/frost/frost-secp256k1-tr/` (gitignored).

**Confidence:** ≥95% on every section below unless flagged ⚠️. The whole point of Step 0 is to lock in the byte-level details before any code is written.

---

## 1 · Crate map

```
frost-secp256k1-tr/src/
├── lib.rs              ─ ciphersuite trait impl, hash funcs, signing/verifying overrides, tweak helper
├── rerandomized.rs     ─ RandomizedCiphersuite::hash_randomizer (used only for the rerandomized variant)
├── tests.rs            ─ test re-export
└── keys/
    ├── dkg.rs          ─ DKG dealer-based and round1/round2 functions
    ├── refresh.rs      ─ key-refresh helpers
    └── repairable.rs   ─ RTS (recoverable threshold signing) repair flow
```

The crate is **thin** — almost everything lives in `frost-core/`, and `frost-secp256k1-tr` only overrides the parts that are ciphersuite-specific (hash funcs, ser/de, BIP340 even-y enforcement, post-DKG taproot tweak).

---

## 2 · Public API surface (what the TS port must expose)

From `frost-secp256k1-tr/src/lib.rs` re-exports and `keys` / `round1` / `round2` submodules:

### Key generation (dealer-based)
```rust
keys::generate_with_dealer<RNG>(
    max_signers: u16, min_signers: u16,
    identifiers: IdentifierList, rng: RNG,
) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error>
```
Wraps `frost::keys::generate_with_dealer`, then runs `Ciphersuite::post_dkg` which **automatically applies the BIP341 unspendable taproot tweak** (`merkle_root = None`) to every output (lib.rs:478-491).

### DKG (distributed, no dealer)
```rust
keys::dkg::part1(identifier, max_signers, min_signers, rng) -> (round1::SecretPackage, round1::Package)
keys::dkg::part2(round1_secret, received_round1) -> (round2::SecretPackage, BTreeMap<Identifier, round2::Package>)
keys::dkg::part3(round2_secret, received_round1, received_round2) -> (KeyPackage, PublicKeyPackage)
```
`part3` is also passed through `post_dkg` so the resulting KeyPackage / PublicKeyPackage are tweaked.

### Signing
```rust
round1::commit(secret: &SigningShare, rng) -> (SigningNonces, SigningCommitments)   // re-export from frost-core
round2::sign(signing_package, signer_nonces, key_package) -> Result<SignatureShare, Error>
round2::sign_with_tweak(signing_package, nonces, key_package, merkle_root: Option<&[u8]>) -> Result<SignatureShare, Error>
```
`sign_with_tweak` clones the key package, applies `tweak(merkle_root)`, then calls plain `sign`. For Otzi's vault use case (no script paths), only the post-DKG tweak (`merkle_root = None`) is in scope; the explicit `_with_tweak` variants exist for tapscript script-paths and are not strictly required for the first port milestone.

### Aggregation
```rust
aggregate(signing_package, signature_shares, public_key_package) -> Result<Signature, Error>
aggregate_with_tweak(signing_package, signature_shares, public_key_package, merkle_root) -> Result<Signature, Error>
```

### Types (re-exported from frost-core, parameterized by Secp256K1Sha256TR)
- `Identifier` — non-zero scalar mod n; serialized 32-byte big-endian
- `SigningShare` (private), `VerifyingShare` (public per-party)
- `KeyPackage` (per-party signing material), `PublicKeyPackage` (group public material)
- `SigningNonces` { hiding, binding }, `SigningCommitments` { hiding_R, binding_R }
- `SigningPackage` { commitments per signer, message }
- `SignatureShare` (32-byte scalar), `Signature` (64-byte BIP340 compact)
- `SigningKey`, `VerifyingKey`

### Ciphersuite trait
The `impl Ciphersuite for Secp256K1Sha256TR` block lives at lib.rs:240-492. The trait is defined in `frost-core/src/lib.rs` and the `-tr` impl overrides:
- `H1`–`H5`, `HDKG`, `HID` (lib.rs:252-294)
- `single_sign`, `pre_sign`, `pre_aggregate`, `pre_verify` (lib.rs:297-362) — all force even-y on key material before delegating to the generic frost-core flow
- `generate_nonce` (lib.rs:365-378) — random k, then negate (k, R) if R has odd y
- `challenge` (lib.rs:382-392) — uses **x-only** R and verifying_key in the H2 input (BIP340-style, NOT vanilla FROST)
- `compute_signature_share` (lib.rs:395-416) — negates nonces if the **aggregate** group commitment has odd y
- `verify_share` (lib.rs:420-443) — symmetric negation on verification
- `serialize_signature` / `deserialize_signature` (lib.rs:446-473) — 64-byte compact: x-only R || z, with hardcoded `0x02` prefix on deserialize because BIP340 sigs always have even-y R
- `post_dkg` (lib.rs:478-491) — the unspendable taproot tweak

The non-`-tr` crate (`frost-secp256k1`) overrides ONLY `H1-H5` / `HDKG` / `HID` (different tag suffixes) and uses the generic frost-core signing/aggregation paths with full-point challenge inputs. Every other `-tr` override is the BIP340/BIP341 special-sauce.

---

## 3 · Hash domain tags (CRITICAL — exact bytes)

**`CONTEXT_STRING`** (lib.rs:179):
```rust
const CONTEXT_STRING: &str = "FROST-secp256k1-SHA256-TR-v1";
```
- UTF-8 length: **28 bytes**
- Hex: `46524f53542d736563703235366b312d5348413235362d54522d7631`

The two underlying primitives both live in lib.rs and ARE different from each other:

### 3.1 · `hash_to_scalar` — used by H1, H3, HDKG, HID, hash_randomizer
```rust
// lib.rs:169-174
fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> Scalar {
    let mut u = [Secp256K1ScalarField::zero()];
    hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[msg], domain, &mut u)
        .expect("...");
    u[0]
}
```
- **Underlying construction:** RFC 9380 §5.2 hash-to-field with `expand_message_xmd` over SHA-256
- **DST:** the items in the `domain` slice are concatenated with NO separator. For H1: DST = `b"FROST-secp256k1-SHA256-TR-v1" || b"rho"` = `"FROST-secp256k1-SHA256-TR-v1rho"` (31 bytes).
- **Field modulus for reduction:** secp256k1 curve order `n` (because the type parameter is `Scalar`, the scalar field, not the base field)
- **Per RFC 9380 with k=128 and L=ceil((256+128)/8)=48 bytes:** each scalar consumes 48 bytes from `expand_message_xmd`, then `os2ip` to bigint and `mod n`
- **Output:** one scalar mod n

### 3.2 · `tagged_hash` + `hasher_to_scalar` — used by H2 and `tweak`
```rust
// lib.rs:194-201
fn tagged_hash(tag: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher
}

// lib.rs:186-191
fn hasher_to_scalar(hasher: Sha256) -> Scalar {
    Scalar::reduce(U256::from_be_slice(&hasher.finalize()))
}
```
- This is the **standard BIP340 tagged hash**: `SHA256(SHA256(tag) || SHA256(tag) || message)`
- For the scalar variant: take the 32-byte digest as a big-endian U256 and reduce mod n. **NB:** this is a 32-byte-input direct reduction, NOT the 48-byte expand-message construction. The bias is negligible because n is within ~2^-128 of 2^256.
- **noble/curves equivalent: `schnorr.utils.taggedHash(tag, ...messages)` (secp256k1.ts:107-115).** It uses the same SHA256(SHA256(tag)||SHA256(tag)||...) construction with cached prefixes.

### 3.3 · `hash_to_array` — used by H4 and H5
```rust
// lib.rs:159-167
fn hash_to_array(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for i in inputs {
        h.update(i);
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(h.finalize().as_ref());
    output
}
```
- Plain SHA256 over the concatenation of the input slices. **No domain separation tag prefixing in this helper itself** — H4/H5 build their own preimages (CONTEXT_STRING || suffix || message) by passing them in `inputs`.
- **No scalar reduction** — H4/H5 return raw 32-byte digests.

### 3.4 · The hash function table

| Fn | Cite | Body | Effective input | Output | Reduction | Semantic role |
|----|---|---|---|---|---|---|
| `H1` | lib.rs:252-254 | `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"rho"], m)` | DST=`"FROST-secp256k1-SHA256-TR-v1rho"`, msg=`m` | Scalar | ExpandMsgXmd → 48 bytes → mod n | Binding factor (RFC 9591 §6.5.2.2.1) |
| `H2` | lib.rs:259-263 | `tagged_hash("BIP0340/challenge")` then update(m) then `hasher_to_scalar` | `SHA256("BIP0340/challenge")^2 \|\| m` | Scalar | direct reduce 32→mod n | Schnorr challenge (RFC 9591 §6.5.2.2.2 / BIP340) |
| `H3` | lib.rs:268-270 | `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"nonce"], m)` | DST=`"FROST-secp256k1-SHA256-TR-v1nonce"`, msg=`m` | Scalar | ExpandMsgXmd → 48 → mod n | Nonce derivation (RFC 9591 §6.5.2.2.3) |
| `H4` | lib.rs:275-277 | `hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])` | `"FROST-secp256k1-SHA256-TR-v1" \|\| "msg" \|\| m` | `[u8; 32]` | none | Message hash (RFC 9591 §6.5.2.2.4) |
| `H5` | lib.rs:282-284 | `hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])` | `"FROST-secp256k1-SHA256-TR-v1" \|\| "com" \|\| m` | `[u8; 32]` | none | Commitment hash (RFC 9591 §6.5.2.2.5) |
| `HDKG` | lib.rs:287-289 | `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m)` | DST=`"FROST-secp256k1-SHA256-TR-v1dkg"`, msg=`m` | `Option<Scalar>` | ExpandMsgXmd → 48 → mod n | DKG proof-of-knowledge challenge |
| `HID` | lib.rs:292-294 | `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"id"], m)` | DST=`"FROST-secp256k1-SHA256-TR-v1id"`, msg=`m` | `Option<Scalar>` | ExpandMsgXmd → 48 → mod n | Identifier derivation |
| `hash_randomizer` | lib.rs:495-500 | `hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"randomizer"], m)` | DST=`"FROST-secp256k1-SHA256-TR-v1randomizer"`, msg=`m` | `Option<Scalar>` | ExpandMsgXmd → 48 → mod n | Rerandomized variant only |

**Key observation:** H2 is the cryptographic-difference oddball. Every other H_n inherits from a generic `hash_to_scalar` driven by the FROST DST array. H2 alone uses the BIP340 tagged-hash construction, and its preimage is built externally by `Ciphersuite::challenge` (lib.rs:382-392) as **x-only** R || x-only verifying_key || message.

### 3.5 · Where to look up the FROST RFC role of each hash
The RFC 9591 §6.5.2 table of H1–H5 is mirrored in the doc-comments in `frost-core/src/lib.rs` on the `Ciphersuite` trait. The semantic roles in the table above follow that.

---

## 4 · Point and scalar serialization

### Scalar (lib.rs:78-94)
- `serialize`: `scalar.to_bytes().into()` → 32-byte array, **big-endian**
- `little_endian_serialize`: byte-reverses the above. **Used only for identifier ordering** (frost-core's `Identifier::cmp` impl) — never for hashing or signing.
- The k256 `Scalar::to_bytes` is constant-time and the result is the canonical big-endian encoding mod n.

### Point / group element (lib.rs:128-156)
- `serialize`: `element.to_affine().to_encoded_point(true)` → 33-byte SEC1 compressed (`0x02` if y is even, `0x03` if odd, then 32-byte x)
- The identity element returns `GroupError::InvalidIdentityElement` — FROST never serializes the identity, deliberately.
- `deserialize`: `k256::EncodedPoint::from_bytes` → `AffinePoint::from_encoded_point` → `ProjectivePoint`. Rejects identity, rejects malformed.

### Signature (lib.rs:446-473)
- Output: 64 bytes = `x-only R (32) || z (32)`. The 33-byte SEC1 R is serialized first, then byte 0 (the `0x02` prefix) is sliced off.
- Deserialize: hardcoded `R_bytes[0] = 0x02` because BIP340 sigs always have even-y R, then deserialize the reconstructed 33-byte point.

### x-only point extraction (used by `challenge` and `tweak`)
- `point.to_affine().x()` returns 32 bytes via `k256::AffineCoordinates`. This is the same 32 bytes you'd get from `serialize(&P)[1..]`.

### Identifier (frost-core/src/identifier.rs:65-67)
- Big-endian 32-byte scalar, must be non-zero (a zero identifier would let an attacker recover the secret as f(0)).

---

## 5 · Taproot tweak — the -tr special sauce

### 5.1 · The tweak function (lib.rs:204-222)
```rust
fn tweak<T: AsRef<[u8]>>(public_key: &Element, merkle_root: Option<T>) -> Scalar {
    match merkle_root {
        None => {
            let mut hasher = tagged_hash("TapTweak");
            hasher.update(public_key.to_affine().x());
            hasher_to_scalar(hasher)
        }
        Some(root) => {
            let mut hasher = tagged_hash("TapTweak");
            hasher.update(public_key.to_affine().x());
            hasher.update(root.as_ref());
            hasher_to_scalar(hasher)
        }
    }
}
```
- Formula: `t = SHA256(SHA256("TapTweak") || SHA256("TapTweak") || pk_x [|| merkle_root])` reduced mod n
- This is exactly the BIP341 `taproot_tweak_pubkey` formula
- **noble/curves equivalent:** `Pointk1.Fn.create(bytesToNumberBE(schnorr.utils.taggedHash('TapTweak', pk_x_bytes, ...maybe_merkle_root)))`

### 5.1.5 · ⚠️ Dealer mode does NOT apply the tweak (post_generate is no-op)

`frost-core` defines two distinct post-keygen hooks on the `Ciphersuite` trait (`frost-core/src/traits.rs:450-470`):
- `post_dkg(KeyPackage, PublicKeyPackage)` — called from `frost-core/src/keys/dkg.rs:657` at the end of `keys::dkg::part3`
- `post_generate(BTreeMap<Identifier, SecretShare>, PublicKeyPackage)` — called from `frost-core/src/keys.rs:576` at the end of `keys::generate_with_dealer` / `keys::split`

**`frost-secp256k1-tr` overrides `post_dkg` (lib.rs:478) but does NOT override `post_generate`.** Dealer-mode key generation therefore returns the *raw, untweaked* aggregate verifying key. Empirically confirmed by `fixture-gen`: a 2-of-3 dealer ceremony with seed `[0u8; 32]` produces a verifying key starting with `0x03` (odd y), which is what the raw `secret_key·G` happens to be — the tweak has not been applied.

**Implications for the TS port:**
- A TS implementation of dealer mode that mirrors `generate_with_dealer` should NOT apply the tap tweak post-keygen. The verifying key returned is the raw aggregate.
- BIP340 even-y normalization still happens at sign / verify time via `pre_sign` / `pre_aggregate` / `pre_verify` (lib.rs:308-362), which call `into_even_y(None)` on the operative key. This is parity normalization only — NOT the tap tweak.
- A TS implementation of DKG mode (mirroring `keys::dkg::part1/2/3`) MUST apply the tap tweak post-keygen to match `post_dkg`.
- These two flows are therefore not interchangeable from a "what's the operative pubkey?" point of view: the dealer flow's pubkey is `Q = sk·G` (then parity-normalized at sign time); the DKG flow's pubkey is `Q = (sk·G) + t·G` where `t = tap_tweak(x_only(sk·G))`.
- For Otzi's vault, which uses DKG, this means the operative pubkey is the tweaked one. Stick with DKG semantics for the actual deployment.

### 5.2 · post_dkg — the BIP341 unspendable-tweak rogue-key defense
```rust
// lib.rs:478-491
fn post_dkg(
    key_package: keys::KeyPackage,
    public_key_package: keys::PublicKeyPackage,
) -> Result<(keys::KeyPackage, keys::PublicKeyPackage), Error> {
    // From BIP-341:
    // > If the spending conditions do not require a script path, the output
    // > key should commit to an unspendable script path instead of having
    // > no script path. This can be achieved by computing the output key
    // > point as Q = P + int(hashTapTweak(bytes(P)))G.
    Ok((
        key_package.tweak::<&[u8]>(None),
        public_key_package.tweak::<&[u8]>(None),
    ))
}
```
- **This runs unconditionally at the end of every DKG / dealer flow.** The KeyPackage / PublicKeyPackage you receive from `generate_with_dealer` or `keys::dkg::part3` has ALREADY been tweaked.
- **Effect on the operative key:** `Y' = Y + t·G`, `sk_i' = sk_i + t` (each individual signing share is shifted by the same `t`, since the tweak is a public scalar — this preserves the secret-sharing of the new aggregate `sk' = sk + t`).
- **Why it exists:** without an explicit unspendable script-path commitment, an attacker who later observes the aggregate key could announce "actually there's a script path with merkle root R, here's how to spend." The BIP341 unspendable tweak forecloses that — the key is bound to a known specific tweak, so no other tweak can be claimed.
- **TS port consequence:** if you do a DKG and skip this step, your output is BIP341-non-compliant AND vulnerable to the post-hoc rogue-script attack. It MUST be implemented.

### 5.3 · Tweak trait location
The `Tweak` trait is implemented for both `KeyPackage` and `PublicKeyPackage`. Per the subagent's report, `frost-secp256k1-tr/src/lib.rs:751-792` (this part wasn't read directly but matches the structure of the tweak function — the impl walks every signing share / verifying share and applies `+t` / `+t·G`).

---

## 6 · BIP340 even-y enforcement — the seven negation points

BIP340 mandates that R and the verifying key always have **even** y-coordinates. The `-tr` ciphersuite enforces this at every entry point so that the inner FROST math (which is curve-only and doesn't care about parity) emits something compatible with vanilla BIP340 verification.

| Site | Cite | What it does |
|---|---|---|
| `single_sign` | lib.rs:297-304 | `signing_key.into_even_y(None)` before delegating to `default_sign`. If the public key has odd y, the secret is negated. |
| `pre_sign` | lib.rs:308-325 | KeyPackage is `into_even_y(None)`'d before round 2 signing. |
| `pre_aggregate` | lib.rs:329-346 | PublicKeyPackage is `into_even_y(None)`'d before aggregation. |
| `pre_verify` | lib.rs:350-362 | Both VerifyingKey and Signature are `into_even_y(None)`'d before verification. |
| `generate_nonce` | lib.rs:365-378 | Random `k`, then if `(k·G).y` is odd, return `(-k, -R)`. ⚠️ **NOT on the FROST round-1 commit path** — see clarification below. |
| `compute_signature_share` | lib.rs:395-416 | If the **group** commitment (sum of all signers' R) has odd y, negate the local nonces before signing. The aggregate parity is what matters, not the individual one. |
| `verify_share` | lib.rs:420-443 | Symmetric: negate the group commitment share if the aggregate has odd y. |

**Two layers:**
1. **Per-key normalization** (sites 1-4): the *operative* signing/verifying material is forced to even-y on the way in.
2. **Aggregate-conditional negation** (sites 6-7): once R values are summed across signers, the sum may end up with odd y; in that case every signer's local nonce gets negated to compensate. This is the standard "make-all-of-FROST-output-a-BIP340-sig" trick.

The TS port must replicate all seven negation points exactly. **Missing any of them means signatures will fail verification half the time** (whichever half corresponds to the odd-y case).

### 6.1 · ⚠️ Clarification on `generate_nonce` (site #5) — added in Step 3

The `Ciphersuite::generate_nonce` override at lib.rs:365-378 IS implemented in `frost-secp256k1-tr` and DOES negate `(k, R)` when `R.y` is odd, **but it is NOT on the FROST round-1 commit path that produces our fixture data.** Round 1 commit (`round1::commit` → `Nonce::new` → `nonce_generate_from_random_bytes` at frost-core/round1.rs:77-90) is a *direct H3 call*: `nonce_scalar = H3(random_bytes(32) || signing_share.serialize())`, with **no parity dance**. The recorded scalar in the fixture is exactly H3 of that preimage, even when the resulting commitment point has odd y. `generate_nonce` is used by the synchronous standalone signing path (`single_sign`), not by the FROST distributed flow.

**Empirical confirmation:** in `secp256k1_tr_2of3_dealer.json`, participant 2's `hiding_nonce_commitment` starts with `0378120b…` (odd y), and the recorded `hiding_nonce` scalar matches `H3(random || share)` byte-for-byte (10/10 H3 byte-equality assertions in `tests/h3.test.ts` passed in Step 3). If round 1 had been negating on parity, the recorded scalar would have been the negation of `H3(random || share)` instead.

The aggregate-level parity dance still applies via sites #6 / #7 (`compute_signature_share` / `verify_share`) — it just happens at *signing time*, not nonce-generation time. The TS port must:
- NOT apply parity normalization in `Nonce::new`-equivalent code
- DO apply aggregate-level parity normalization in `compute_signature_share`-equivalent code

---

## 7 · `challenge` — x-only preimage

```rust
// lib.rs:382-392
fn challenge(R: &Element<S>, verifying_key: &VerifyingKey, message: &[u8]) -> Result<Challenge<S>, Error> {
    let mut preimage = vec![];
    preimage.extend_from_slice(&R.to_affine().x());                              // 32 bytes
    preimage.extend_from_slice(&verifying_key.to_element().to_affine().x());     // 32 bytes
    preimage.extend_from_slice(message);                                         // var
    Ok(Challenge::from_scalar(S::H2(&preimage[..])))
}
```
- Vanilla FROST hashes the **full 33-byte SEC1 points**. The `-tr` variant hashes only the **x-coordinates** (32 bytes each), exactly per BIP340.
- The full preimage to H2 is: `R_x (32) || verifying_key_x (32) || message (n)`.
- Then H2 = `tagged_hash("BIP0340/challenge", preimage)` reduced mod n.
- **Equivalent in noble/curves:** the internal `challenge()` helper at `secp256k1.ts:150-152` does *exactly* this: `Pointk1.Fn.create(num(taggedHash('BIP0340/challenge', ...args)))`. So we essentially get H2 + the challenge wiring together, for free, by passing the three preimage chunks as separate `messages...` to `taggedHash`.

---

## 8 · DKG proof-of-knowledge challenge — uses HDKG, full points

```rust
// frost-core/src/keys/dkg.rs (per subagent report, line ~416)
fn challenge<C>(identifier, verifying_key, R) -> Challenge<C> {
    let mut preimage = vec![];
    preimage.extend_from_slice(identifier.serialize().as_ref());                    // 32
    preimage.extend_from_slice(<C::Group>::serialize(&verifying_key.to_element())?); // 33
    preimage.extend_from_slice(<C::Group>::serialize(R)?);                           // 33
    Challenge(C::HDKG(&preimage[..]).ok_or(...)?)
}
```
- **Crucially different from `Ciphersuite::challenge`:** this one uses *full* 33-byte SEC1 points, not x-only. DKG happens before the BIP340 even-y normalization is meaningful (we're proving knowledge of a polynomial coefficient, not BIP340-signing yet).
- Preimage: 32 + 33 + 33 = 98 bytes.
- Hash: HDKG = `hash_to_scalar(&[CONTEXT_STRING, b"dkg"], preimage)`.

---

## 9 · RNG consumption order (this is what the fixture harness must emit)

The Step 1 Rust fixture harness is going to record the consumed random bytes alongside each protocol output. The order matters — the TS replay shim feeds them out in the same order.

### Dealer `keys::generate_with_dealer` (called once by the trusted dealer)
1. **Secret key**: `SigningKey::new(rng)` → `Scalar::random(rng)` — 32 bytes (one `fill_bytes` call). **Empirically confirmed by `fixture-gen` against k256 0.13.x: rejection sampling, 32 bytes per call, not 64.**
2. **Polynomial coefficients**: `generate_coefficients(min_signers - 1, rng)` → `(min_signers - 1)` calls to `Scalar::random(rng)`, 32 bytes each
3. No PoK in dealer mode (the dealer is trusted)
4. Total for (t, n) = (2, 3) dealer: **64 bytes** = 32 secret + 32 × 1 coefficient. For (3, 5): 96 bytes = 32 secret + 32 × 2 coefficients.

### DKG `keys::dkg::part1` (per participant)
1. **Secret key**: `Scalar::random(rng)` — 32 bytes
2. **Polynomial coefficients**: `(min_signers - 1)` calls — 32 bytes each
3. **Proof-of-knowledge nonce**: `random_nonzero::<Self, R>(rng)` — loops `Scalar::random` until non-zero (always one iteration in practice; rejection probability is ~2^-256), 32 bytes

### Round 1 commit (per participant)
- **Hiding nonce**: `Nonce::new` → `rng.fill_bytes(&mut [0u8; 32])` — exactly 32 bytes
- **Binding nonce**: same, another 32 bytes
- **Total: 64 bytes**, in this order
- Each random 32-byte block is then combined with the signing share via H3:
  ```rust
  // frost-core/src/round1.rs:77-90 (per subagent report)
  fn nonce_generate_from_random_bytes(secret: &SigningShare<C>, random_bytes: [u8; 32]) -> Self {
      let secret_enc = secret.0.serialize();
      let input: Vec<u8> = random_bytes.iter().chain(secret_enc.iter()).cloned().collect();
      Self::from_scalar(C::H3(input.as_slice()))
  }
  ```
  i.e. `nonce = H3(random_bytes(32) || signing_share_serialized(32))` — order matters: random first, secret second.

### Round 2 sign
- **No RNG.** All randomness is pre-baked into the Round 1 nonces.

### Aggregate
- **No RNG.**

### post_dkg / tweak
- **No RNG.** Deterministic.

**RESOLVED in Step 1 (2026-04-08, fixture-gen empirical run):** k256 `Scalar::random` consumes **32 bytes per call** via a single `fill_bytes(&mut [0u8; 32])`, using rejection sampling (not 64-byte uniform). The rng_log for `secp256k1_tr_2of3_dealer.json` shows exactly this: 2 calls × 32 bytes for dealer keygen, then 4 calls × 32 bytes for the 2-signer round1 (2 signers × 2 nonces). No additional fill_bytes calls anywhere in the dealer or signing flow.

---

## 10 · noble/curves API mapping

`@noble/curves@2.0.1` is what Otzi has installed (`~/projects/otzi/node_modules/@noble/curves/`). Inspected the `.d.ts` and `src/secp256k1.ts` directly. Everything FROST needs is exposed:

### Curve / point ops
| What we need (Rust) | TS equivalent |
|---|---|
| `ProjectivePoint::GENERATOR` | `secp256k1.Point.BASE` |
| `ProjectivePoint::IDENTITY` | `secp256k1.Point.ZERO` |
| `P + Q` | `P.add(Q)` |
| `P - Q` | `P.subtract(Q)` |
| `-P` | `P.negate()` |
| `k · P` (scalar mul, constant-time) | `P.multiply(k)` |
| `k · P` (variable-time, OK for verifying) | `P.multiplyUnsafe(k)` |
| Compressed SEC1 ser → 33 bytes | `P.toBytes(true)` (default is `true`) |
| SEC1 deser → point | `secp256k1.Point.fromBytes(bytes)` |
| x-only (32 bytes) | `P.toBytes(true).slice(1)` (matches `pointToBytes(P)` helper at secp256k1.ts:118) |
| `lift_x` (BIP340) | `schnorr.utils.lift_x(x_bigint)` |

### Scalar field arithmetic mod n
| Rust (`k256::Scalar`) | TS |
|---|---|
| field handle | `secp256k1.Point.Fn` (typed `IField<bigint>`) |
| `Scalar::ZERO` | `Fn.ZERO` |
| `Scalar::ONE` | `Fn.ONE` |
| `a + b` | `Fn.add(a, b)` |
| `a - b` | `Fn.sub(a, b)` |
| `a * b` | `Fn.mul(a, b)` |
| `a^-1` | `Fn.inv(a)` |
| `-a` | `Fn.neg(a)` |
| `a == 0` | `Fn.is0(a)` |
| big-endian to bigint | `Fn.fromBytes(bytes)` (32-byte big-endian) |
| bigint to big-endian | `Fn.toBytes(scalar)` |
| order n | `Fn.ORDER` (= `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n`) |

### Hash primitives
| Rust | TS |
|---|---|
| `tagged_hash("TAG").update(m).finalize()` (BIP340 style: `SHA256(SHA256(tag)\|\|SHA256(tag)\|\|m)`) | `schnorr.utils.taggedHash('TAG', m)` (secp256k1.ts:107-115). Same construction with cached prefixes. |
| `Scalar::reduce(U256::from_be_slice(hash_output))` (mod-n reduction of a 32-byte digest) | `Fn.create(bytesToNumberBE(bytes))` — exposed via `import { bytesToNumberBE } from '@noble/curves/utils.js'` |
| `hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[msg], domain, &mut u)` | `hash_to_field(msg, 1, { DST, p: secp256k1_n, m: 1, k: 128, expand: 'xmd', hash: sha256 })[0][0]` — exposed from `@noble/curves/abstract/hash-to-curve.js` (hash-to-curve.d.ts:77) |
| `expand_message_xmd` (RFC 9380 §5.3.1) | `expand_message_xmd(msg, DST, lenInBytes, sha256)` — also exposed (hash-to-curve.d.ts:60) |

### Composition recipes the TS port will need
**H1, H3, HDKG, HID, hash_randomizer (general FROST hash-to-scalar):**
```ts
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const N = secp256k1.Point.Fn.ORDER;

function hashToScalar(dst: string, msg: Uint8Array): bigint {
  const u = hash_to_field(msg, 1, {
    DST: dst,
    p: N, m: 1, k: 128,
    expand: 'xmd', hash: sha256,
  });
  return u[0][0];   // first element of first field element
}

const H1 = (m: Uint8Array) => hashToScalar('FROST-secp256k1-SHA256-TR-v1rho', m);
const H3 = (m: Uint8Array) => hashToScalar('FROST-secp256k1-SHA256-TR-v1nonce', m);
const HDKG = (m: Uint8Array) => hashToScalar('FROST-secp256k1-SHA256-TR-v1dkg', m);
const HID = (m: Uint8Array) => hashToScalar('FROST-secp256k1-SHA256-TR-v1id', m);
```

**H2 (BIP340-style):**
```ts
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';

function H2(preimage: Uint8Array): bigint {
  return secp256k1.Point.Fn.create(
    bytesToNumberBE(schnorr.utils.taggedHash('BIP0340/challenge', preimage))
  );
}
```

**H4 / H5 (raw SHA256, no scalar reduction):**
```ts
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/curves/utils.js';

const CONTEXT = new TextEncoder().encode('FROST-secp256k1-SHA256-TR-v1');
const MSG_TAG = new TextEncoder().encode('msg');
const COM_TAG = new TextEncoder().encode('com');

const H4 = (m: Uint8Array) => sha256(concatBytes(CONTEXT, MSG_TAG, m));
const H5 = (m: Uint8Array) => sha256(concatBytes(CONTEXT, COM_TAG, m));
```

**Tap tweak:**
```ts
function tapTweakScalar(pkXOnly: Uint8Array, merkleRoot?: Uint8Array): bigint {
  const tagged = merkleRoot
    ? schnorr.utils.taggedHash('TapTweak', pkXOnly, merkleRoot)
    : schnorr.utils.taggedHash('TapTweak', pkXOnly);
  return secp256k1.Point.Fn.create(bytesToNumberBE(tagged));
}
```

### API gap analysis: no blockers
Everything FROST needs is exposed by `@noble/curves@2.0.1` at the top-level or via `abstract/hash-to-curve.js`. **No need to drop into `abstract/weierstrass` directly.** The plan's hedge ("If `@noble/curves` doesn't expose, e.g., raw point addition outside of an ECDSA wrapper, we may need to drop to `abstract/weierstrass` directly") does not apply — `secp256k1.Point` IS the WeierstrassPointCons and exposes the full API.

---

## 11 · Pre-existing test vectors in the Rust crate

Subagent identified these in `frost-secp256k1-tr/tests/helpers/`:

| File | Purpose |
|---|---|
| `vectors.json` (3.6K) | 2-of-3 signing flow: inputs (secret, verifying key, message, shares, polynomial coeffs), round_one_outputs (nonces, commitments, binding factors), round_two_outputs (signature shares), final aggregate signature |
| `vectors_dkg.json` (3.0K) | DKG round 1 outputs per participant (secret polynomial, commitments, proof-of-knowledge) |
| `vectors-big-identifier.json` (3.6K) | Same shape as `vectors.json` but with non-sequential large identifiers |
| `samples.json`, `elements.json`, `repair-share.json` | Smaller / orthogonal test cases |

**Reuse strategy for Step 1:** the Rust fixture harness this project will build SHOULD output a JSON in the same shape as `vectors.json`, plus the consumed-random-bytes traces. It can use the existing harness in `frost-core/src/tests/vectors.rs` (`check_sign_with_test_vectors`) as a template.

---

## 12 · Open items

1. ✅ **`Scalar::random` byte count** — RESOLVED in Step 1: 32 bytes per call, rejection sampling.
2. ✅ **`hash_to_field` k parameter exact value used by k256** — RESOLVED empirically in Step 3: noble's `hash_to_field` with `k=128` matches Rust's `hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>` byte-for-byte across 10 independent H3 input pairs (5 hiding nonces + 5 binding nonces from both `-tr` dealer fixtures). See `tests/h3.test.ts`.
3. ✅ **`Tweak` trait impls for KeyPackage and PublicKeyPackage** — RESOLVED in Step 3: read directly from lib.rs:751-792. Pipeline for `PublicKeyPackage::tweak(None)` is `Q = into_even_y(P) + t·G` where `t = tap_tweak_scalar(x_only(P))` (computed from the *original* P, not the normalized one — but mathematically equivalent because x is invariant under negation). For `KeyPackage::tweak(None)`, the same `t` and `tp = t·G` are applied to all three components after the aggregate's `into_even_y` may have negated everything: `vk' = even(vk) + tp`, `ss' = even(ss) + t`, `vs' = even(vs) + tp`. Result Q is NOT itself even-y normalized after the tweak; downstream `pre_*` sites do that on the way in. Validated by `tests/dkg-tweak.test.ts` (2 byte-equality assertions on the verifying-key half).
4. ✅ **Exact body of `into_even_y`** — RESOLVED in Step 3: read directly from lib.rs:615-743. The `EvenY` trait has six impls (`PublicKeyPackage`, `KeyPackage`, `VerifyingKey`, `GroupCommitment`, `Signature`, `SigningKey`); each is the same pattern: check `verifying_key.to_affine().y_is_odd()`, and if odd, negate the point AND any associated secret scalars (since `-(s·G) = (-s)·G` preserves the `s·G == vs` and `Σ vs == vk` invariants). The TS port `intoEvenY` in `src/point.ts` mirrors the `VerifyingKey` variant; the more elaborate `KeyPackage` / `PublicKeyPackage` variants will land as separate composites when DKG part 3 is ported.
5. ⚠️ **NEW (from §5.1.5 added in Step 1):** `frost-secp256k1-tr` overrides `post_dkg` but NOT `post_generate`. Dealer flow returns an UNTWEAKED key. This is a behavior asymmetry between the two flows that the TS port must replicate exactly. Documented above; no further action needed beyond keeping the two flows separate in the TS API.
6. ⚠️ **NEW (from §6.1 added in Step 3):** `Ciphersuite::generate_nonce` (site #5 in §6's table) is NOT on the FROST round-1 commit path. Round 1 uses `nonce_generate_from_random_bytes` which is a direct `H3(random || share)` with no parity dance — confirmed empirically by 10/10 H3 byte-equality assertions passing on nonces whose commitments include odd-y points. The TS port must NOT apply parity normalization in the round-1 nonce primitive; aggregate-level parity is handled at sign time via sites #6 / #7. See §6.1 for the empirical confirmation.

All §12 items are now either resolved or documented as known asymmetries.

---

## 13 · Per-section confidence

| § | Confidence | Notes |
|---|---|---|
| 1 Crate map | ≥99% | Verified by `ls` |
| 2 Public API | 95% | Verified the main exports + ciphersuite trait by reading lib.rs:1-500. Submodule signatures (dkg::part1/2/3) come from the subagent report and frost-core conventions; will be cross-checked when building the Rust harness. |
| 3 Hash domain tags | 99% | Read every H_n impl directly. Read `hash_to_scalar`, `tagged_hash`, `hasher_to_scalar`, `hash_to_array` directly. Only residual uncertainty is the k=128 parameter assumption (see §12). |
| 4 Serialization | 98% | Read all serialize/deserialize impls directly. |
| 5 Tap tweak | 99% | Read the `tweak` function + `post_dkg` directly, including the BIP-341 quote in the comment. The Tweak trait impl bodies were not read directly (see §12 item 3). |
| 6 BIP340 even-y | 95% | Read all seven sites' bodies. Body of `into_even_y` itself not read; treating as a black-box "negate if pubkey has odd y" — that's the only thing it can be, but worth verifying when porting. |
| 7 Challenge x-only | 99% | Read directly. |
| 8 DKG challenge | 90% | Quoted from the subagent report; not personally verified against `frost-core/src/keys/dkg.rs:416`. Will verify when implementing DKG. |
| 9 RNG consumption | 90% | Order verified from the read passes; exact byte counts have one open item (§12 item 1). |
| 10 noble/curves mapping | 98% | Verified via direct reads of secp256k1.d.ts, secp256k1.ts, weierstrass.d.ts, modular.d.ts, hash-to-curve.d.ts. |
| 11 Test vectors | 90% | File list comes from the subagent report; have not opened the JSONs personally yet. Will when building the Rust harness. |

---

## 14 · The five-line summary for the next session

1. CONTEXT_STRING is `"FROST-secp256k1-SHA256-TR-v1"` (28 bytes UTF-8). DSTs are CONTEXT || suffix with NO separator.
2. H1, H3, HDKG, HID, hash_randomizer use RFC 9380 ExpandMsgXmd-SHA256 hash-to-field with k=128, mod n. **noble/curves' `hash_to_field` is the drop-in.** H2 is the BIP340 tagged-hash oddball — `schnorr.utils.taggedHash('BIP0340/challenge', preimage)` then mod-n. H4/H5 are raw SHA256 over `CONTEXT || suffix || msg`.
3. Scalars: 32-byte big-endian mod n. Points: 33-byte SEC1 compressed (or x-only 32 bytes for BIP340 contexts). Signatures: 64 bytes = R_x || z, R always even-y.
4. The post-DKG taproot tweak is **mandatory** and **automatic** in the **DKG** flow (`post_dkg` lib.rs:478-491). It's `Q = P + hashTapTweak(bytes(P))·G` with no merkle root — the BIP-341 unspendable-script-path commitment that defends against rogue-script post-hoc attacks. The TS port's DKG path MUST replicate this. **However, the dealer flow (`generate_with_dealer`) does NOT apply the tweak** because `frost-secp256k1-tr` doesn't override `post_generate` — see §5.1.5. Dealer-mode TS code must match this asymmetry.
5. BIP340 even-y is enforced at seven negation sites (lib.rs:297-443). Per-key normalization (4 sites) + aggregate-conditional negation (2 sites) + nonce pre-normalization (1 site). Missing any one breaks half the signatures.
