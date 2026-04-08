# CLAUDE.md — frots

Per-project instructions for Claude. Read these alongside the user's global `~/projects/OVERRIDES.md` (mechanical override rules) and `~/.claude/CLAUDE.md`.

## Read-first files (in this order, every session)

1. **`SESSION_CONTEXT.md`** — current state, last session's progress, immediate next action
2. **`PLAN.md`** — implementation plan, source of truth for what comes next
3. **`RUST_REFERENCE_NOTES.md`** — byte-level spec for `frost-secp256k1-tr`. Re-read fully before any crypto primitive port. The §12 open items list is what matters most.

If `SESSION_CONTEXT.md` and `PLAN.md` disagree, `SESSION_CONTEXT.md` is more current (it tracks what's actually been done; PLAN.md is the original blueprint).

## Project facts

- Repo name `frots` is intentional (not a typo of `frost`).
- Goal: pure-TypeScript port of FROST(secp256k1, SHA-256-TR), validated byte-for-byte against the audited Zcash Foundation `frost-secp256k1-tr` Rust crate.
- Consumer: `~/projects/otzi/` (PERMAFROST Vault, threshold BTC wallet). Otzi will wrap `frots` in a ceremony state machine and a `multiSignPsbt`-implementing signer. Those wrappers are NOT in scope for `frots`.
- Pinned dependency: `@noble/curves@2.0.1` (to match Otzi's installed version).
- Reference Rust source: `.reference/frost/` (gitignored, shallow clone of `https://github.com/ZcashFoundation/frost`).

## Verification commands (per OVERRIDES rule #6, always run before claiming done)

```bash
# TypeScript side
npm test                # vitest run — must show all tests passing
npx tsc --noEmit        # must be clean

# Rust side
cd fixture-gen
cargo build             # must be clean (no warnings beyond style)
cargo test              # must show all tests passing
cargo run               # regenerates fixtures; should match committed (determinism check)
```

If `cargo run` produces a diff against committed `fixtures/*.json`, **stop and investigate** — that's a determinism regression and the entire byte-equality testing strategy depends on stability.

## What to absolutely never do here

- **Never reimplement `ChaCha20Rng` in TypeScript.** The whole point of the RNG-replay strategy is to avoid this. Use `FixtureRng` from `src/rng-replay.ts`.
- **Never modify `.reference/frost/`** — it's a gitignored read-only clone. If you need a different version, re-clone.
- **Never claim a primitive port is done without a byte-equality test** against a committed fixture value.
- **Never conflate dealer flow and DKG flow** for the verifying-key tweak — see `RUST_REFERENCE_NOTES.md` §5.1.5. Dealer is untweaked; DKG is tap-tweaked.
- **Never generate plain (non-TR) ciphersuite fixtures** unless the user explicitly asks. Task #16 deferred them; the TS port targets `-tr` exclusively.
- **Never extend the public API surface (`src/index.ts`)** beyond what the current Step 3 primitive needs. The full public API is Step 4, not Step 3.
- **Never use `--no-verify`, `--no-gpg-sign`, or any hook-bypassing flag** on git operations.
- **Never refactor for "future flexibility" without an explicit current need.**

## Confidence escalation (extra-strict in this project)

Per OVERRIDES rule #2, halt and explicitly declare when crypto confidence drops below 95%. In this project that bar is unusually high because **every primitive is in scope** — every H_n hash, every serialization detail, every BIP340 normalization point, every tap tweak application can break the entire test chain if wrong by one byte.

Use the format from OVERRIDES.md:
> ⚠️ **ESCALATION REQUIRED**
> My confidence on [specific aspect] is ~[X]%. I recommend verifying [what specifically] before proceeding. Suggested approach: [Deep Think / manual review / reference implementation check].

When in doubt about a Rust source detail, **read the Rust source directly** (in `.reference/frost/`) rather than recalling notes. The notes are current as of last session but the source is always authoritative.

## Workflow expectations

- **Drive forward through a phase** once started. Don't ask permission for small reversible decisions mid-phase.
- **Stop at natural milestones** (a PLAN.md step done, a non-trivial decision needed). Present status + options + recommendation; let the user pick.
- **Use TaskCreate / TaskUpdate** for multi-step work. Create one task per PLAN.md sub-step.
- **Commit at major checkpoints** when the user says so, not autonomously. Use HEREDOC commit messages following the existing repo style.
- **Update `SESSION_CONTEXT.md`** when handing off to a future session (or when the user explicitly asks).

## Common gotchas

- **`.ts` extensions in imports**: enabled via `allowImportingTsExtensions` + `noEmit` in `tsconfig.json`. Don't try to switch to `.js` extensions — that breaks vitest's transformer.
- **`derive-getters` on FROST types**: `nonces.hiding()` / `commitments.binding()` etc. are auto-generated. They return `&T` references — call `.serialize()` on the result, not on the reference directly.
- **`internals` feature on `frost-core`**: enabled in `fixture-gen/Cargo.toml` so we can access things like `dkg::round1::SecretPackage::coefficients()` for capturing the secret polynomial. Don't depend on internals from the TS port — it's only for fixture-gen.
- **Identifier serialization**: `Identifier::serialize()` returns 32-byte big-endian (NOT little-endian, despite the existence of `little_endian_serialize` for ordering). For default identifiers (1, 2, 3...) the last 2 bytes hold the u16 value.
- **Signature format**: 64-byte BIP340 compact (`R_x || z`), NOT 65-byte standard FROST. The `0x02` prefix on R is hardcoded on deserialize because BIP340 sigs always have even-y R.
