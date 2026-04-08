/**
 * End-to-end sanity check of the Rust → JSON → TS pipeline.
 *
 * The Rust fixture-gen seeds `ChaCha20Rng::from_seed([0u8; 32])` and feeds
 * it to FROST. The very first 32 bytes the RNG produces must equal the
 * canonical ChaCha20 keystream output for an all-zero key/nonce/counter
 * (RFC 8439 section 2.3.2 test vector — the same value that appears in
 * countless ChaCha20 conformance suites).
 *
 * This is the smallest possible "is the whole pipeline working" check.
 * If this fails, every subsequent byte-equality test would also fail,
 * and the failure mode would be much harder to diagnose.
 */

import { describe, expect, it } from 'vitest';
import { ALL_FIXTURE_NAMES, loadDealerFixture, loadDkgFixture, type Fixture } from '../src/index.ts';

/**
 * Canonical first 32 bytes of `ChaCha20Rng::from_seed([0u8; 32])`. This is
 * the well-known RFC 8439 §2.3.2 test vector for ChaCha20 with an all-zero
 * 256-bit key, all-zero nonce, and counter starting at 0.
 */
const CANONICAL_CHACHA20_FIRST_32_BYTES =
  '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7';

describe('end-to-end pipeline sanity', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    it(`${name}: first rng_log entry is the canonical ChaCha20 keystream`, () => {
      const fixture: Fixture = name.endsWith('_dkg')
        ? loadDkgFixture(name)
        : loadDealerFixture(name);

      // Every fixture is generated with seed = [0u8; 32], so the first 32-byte
      // call MUST be the canonical keystream regardless of which protocol the
      // first call belongs to (dealer secret, DKG party 1's signing key, etc.)
      const first = fixture.rng_log[0];
      expect(first).toBeDefined();
      expect(first?.len).toBe(32);
      expect(first?.bytes_hex).toBe(CANONICAL_CHACHA20_FIRST_32_BYTES);
    });
  }

  it('every fixture starts from the same seed', () => {
    for (const name of ALL_FIXTURE_NAMES) {
      const fixture: Fixture = name.endsWith('_dkg')
        ? loadDkgFixture(name)
        : loadDealerFixture(name);
      expect(fixture.config.rng_seed_hex).toBe('0'.repeat(64));
    }
  });
});
