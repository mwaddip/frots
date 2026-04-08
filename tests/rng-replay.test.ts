/**
 * Exercises the FixtureRng replay shim — the load-bearing piece of the
 * byte-equality testing strategy.
 */

import { describe, expect, it } from 'vitest';
import { FixtureRng, hexToBytes, bytesToHex, loadDealerFixture } from '../src/index.ts';

describe('hexToBytes / bytesToHex', () => {
  it('round-trips arbitrary bytes', () => {
    const cases = [
      '',
      '00',
      'ff',
      '0102030405',
      '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7',
    ];
    for (const hex of cases) {
      expect(bytesToHex(hexToBytes(hex))).toBe(hex);
    }
  });

  it('rejects odd-length input', () => {
    expect(() => hexToBytes('abc')).toThrow(/odd-length/);
  });

  it('rejects non-hex characters', () => {
    expect(() => hexToBytes('zz')).toThrow(/invalid hex/);
  });
});

describe('FixtureRng', () => {
  const fixture = loadDealerFixture('secp256k1_tr_2of3_dealer');

  it('replays every recorded call in order', () => {
    const rng = new FixtureRng(fixture);
    expect(rng.callsConsumed()).toBe(0);
    expect(rng.callsRemaining()).toBe(fixture.rng_log.length);

    for (const call of fixture.rng_log) {
      const buf = new Uint8Array(call.len);
      rng.fillBytes(buf);
      expect(bytesToHex(buf)).toBe(call.bytes_hex);
    }

    expect(rng.callsRemaining()).toBe(0);
    expect(rng.isExhausted()).toBe(true);
    expect(rng.bytesConsumed()).toBe(
      fixture.rng_log.reduce((acc, c) => acc + c.len, 0),
    );
  });

  it('throws on length mismatch (caller asks for wrong size at this position)', () => {
    const rng = new FixtureRng(fixture);
    // First recorded call is 32 bytes
    const wrongSize = new Uint8Array(16);
    expect(() => rng.fillBytes(wrongSize)).toThrow(/recorded length is 32, TS asked for 16/);
  });

  it('throws after the log is exhausted', () => {
    const rng = new FixtureRng(fixture);
    for (const call of fixture.rng_log) {
      rng.fillBytes(new Uint8Array(call.len));
    }
    expect(() => rng.fillBytes(new Uint8Array(32))).toThrow(/exhausted recorded log/);
  });

  it('peekNextCall does not advance the cursor', () => {
    const rng = new FixtureRng(fixture);
    const first = rng.peekNextCall();
    expect(first).not.toBeNull();
    expect(rng.callsConsumed()).toBe(0);
    expect(first?.seq).toBe(0);
  });

  it('peekNextCall returns null when exhausted', () => {
    const rng = new FixtureRng(fixture);
    for (const call of fixture.rng_log) {
      rng.fillBytes(new Uint8Array(call.len));
    }
    expect(rng.peekNextCall()).toBeNull();
  });
});
