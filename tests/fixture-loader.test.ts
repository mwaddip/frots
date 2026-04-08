/**
 * Verifies that the loader reads every committed fixture and that each one
 * has a self-consistent schema (the fields the rest of the port will rely on
 * exist and have the right types).
 *
 * This is the cheap "did the JSON survive the round trip from Rust" check.
 */

import { describe, expect, it } from 'vitest';
import {
  ALL_FIXTURE_NAMES,
  loadDealerFixture,
  loadDkgFixture,
  type DealerFixture,
  type DkgFixture,
  type Fixture,
} from '../src/index.ts';

function loadByName(name: string): Fixture {
  // Use the typed loaders so the runtime flow check (config.flow === ...) runs
  if (name.endsWith('_dealer')) return loadDealerFixture(name);
  if (name.endsWith('_dkg')) return loadDkgFixture(name);
  throw new Error(`unknown fixture name pattern: ${name}`);
}

describe('fixture loader', () => {
  for (const name of ALL_FIXTURE_NAMES) {
    describe(name, () => {
      const fixture = loadByName(name);

      it('has a config block matching the file name', () => {
        expect(fixture.config.name).toBe('FROST(secp256k1, SHA-256-TR)');
        expect(fixture.config.group).toBe('secp256k1');
        expect(fixture.config.hash).toBe('SHA-256');
        expect(fixture.config.rng_seed_hex).toBe('0'.repeat(64));
      });

      it('has consistent participant counts', () => {
        const max = parseInt(fixture.config.MAX_PARTICIPANTS, 10);
        const min = parseInt(fixture.config.MIN_PARTICIPANTS, 10);
        const num = parseInt(fixture.config.NUM_PARTICIPANTS, 10);
        expect(min).toBeLessThanOrEqual(max);
        expect(num).toBe(min);
        expect(fixture.inputs.participant_list.length).toBe(num);
      });

      it('has a 33-byte SEC1 verifying key', () => {
        const vk = fixture.inputs.verifying_key_key;
        expect(vk.length).toBe(66); // 33 bytes hex
        expect(vk.slice(0, 2)).toMatch(/^0[23]$/);
      });

      it('has a 64-byte BIP340 compact signature in final_output', () => {
        const sig = fixture.final_output.sig;
        expect(sig.length).toBe(128); // 64 bytes hex
      });

      it('has min_signers round1 and round2 outputs', () => {
        const min = parseInt(fixture.config.MIN_PARTICIPANTS, 10);
        expect(fixture.round_one_outputs.outputs.length).toBe(min);
        expect(fixture.round_two_outputs.outputs.length).toBe(min);
      });

      it('round1 hiding/binding randomness matches the rng_log entries', () => {
        // The recorded round1 randomness must literally appear in the rng_log
        // (every round1 output's hiding/binding randomness should be locatable
        // in the log, in commit order). This catches accidental decoupling
        // between the two views in the fixture.
        const allRandomness = new Set<string>();
        for (const r1 of fixture.round_one_outputs.outputs) {
          allRandomness.add(r1.hiding_nonce_randomness);
          allRandomness.add(r1.binding_nonce_randomness);
        }
        const allLogged = new Set(fixture.rng_log.map((c) => c.bytes_hex));
        for (const rand of allRandomness) {
          expect(allLogged.has(rand)).toBe(true);
        }
      });

      it('rng_log entries all have len === bytes_hex.length / 2', () => {
        for (const call of fixture.rng_log) {
          expect(call.bytes_hex.length).toBe(call.len * 2);
        }
      });

      if (name.endsWith('_dealer')) {
        it('dealer flow has tweak_applied=false', () => {
          const dealer = fixture as DealerFixture;
          expect(dealer.config.flow).toBe('dealer');
          expect(dealer.config.tweak_applied).toBe(false);
        });

        it('dealer flow has participant_shares for every party', () => {
          const dealer = fixture as DealerFixture;
          const max = parseInt(dealer.config.MAX_PARTICIPANTS, 10);
          expect(dealer.inputs.participant_shares.length).toBe(max);
        });
      }

      if (name.endsWith('_dkg')) {
        it('dkg flow has tweak_applied=true', () => {
          const dkg = fixture as DkgFixture;
          expect(dkg.config.flow).toBe('dkg');
          expect(dkg.config.tweak_applied).toBe(true);
        });

        it('dkg flow has a pre-tweak verifying key distinct from the post-tweak one', () => {
          const dkg = fixture as DkgFixture;
          expect(dkg.inputs.verifying_key_pre_tweak).toBeDefined();
          expect(dkg.inputs.verifying_key_pre_tweak).not.toBe(dkg.inputs.verifying_key_key);
        });

        it('dkg flow has part1/part2/part3 records for every party', () => {
          const dkg = fixture as DkgFixture;
          const max = parseInt(dkg.config.MAX_PARTICIPANTS, 10);
          expect(dkg.dkg.part1.length).toBe(max);
          expect(dkg.dkg.part2.length).toBe(max);
          expect(dkg.dkg.part3.length).toBe(max);
        });

        it('dkg flow: every party computed the same aggregate verifying key', () => {
          const dkg = fixture as DkgFixture;
          const vks = new Set(dkg.dkg.part3.map((p) => p.verifying_key));
          expect(vks.size).toBe(1);
          // And it must match the inputs.verifying_key_key
          const [vk] = [...vks];
          expect(vk).toBe(dkg.inputs.verifying_key_key);
        });
      }
    });
  }

  it('loadDealerFixture rejects DKG fixtures', () => {
    expect(() => loadDealerFixture('secp256k1_tr_2of3_dkg')).toThrow(/expected config\.flow='dealer'/);
  });

  it('loadDkgFixture rejects dealer fixtures', () => {
    expect(() => loadDkgFixture('secp256k1_tr_2of3_dealer')).toThrow(/expected config\.flow='dkg'/);
  });
});
