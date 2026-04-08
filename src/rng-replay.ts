/**
 * Deterministic RNG replay shim.
 *
 * Reads the `rng_log` from a fixture and re-emits the recorded bytes in the
 * same order they were consumed on the Rust side. The TS port of any
 * primitive that calls into this shim will see byte-for-byte identical input
 * to what `frost-secp256k1-tr` saw in the recorded run, which is what makes
 * byte-equality testing of derived values (nonces, signatures, etc.) possible.
 *
 * Strict-by-call replay: every TS `fillBytes(dest)` call must match the next
 * recorded `RngCall` by length. If a TS port calls fillBytes with a different
 * length than Rust did at the same point, the shim throws — that's a
 * structural divergence we want to catch immediately, not let it silently
 * desync the byte stream.
 *
 * This is the load-bearing piece of the byte-equality testing strategy.
 */

import type { Fixture, RngCall } from './fixture.ts';

export class FixtureRng {
  private callIndex = 0;
  private byteCursor = 0;
  private readonly calls: readonly RngCall[];

  constructor(fixture: Fixture) {
    this.calls = fixture.rng_log;
  }

  /**
   * Fill the destination buffer with the next recorded bytes. Mirrors Rust's
   * `RngCore::fill_bytes(dest: &mut [u8])` signature.
   *
   * Throws if:
   * - the recorded log has been exhausted
   * - the next recorded call's length doesn't match `dest.length`
   */
  fillBytes(dest: Uint8Array): void {
    if (this.callIndex >= this.calls.length) {
      throw new Error(
        `FixtureRng: exhausted recorded log after ${this.callIndex} calls; ` +
          `TS asked for ${dest.length} more bytes`,
      );
    }
    const expected = this.calls[this.callIndex]!;
    if (expected.len !== dest.length) {
      throw new Error(
        `FixtureRng call ${this.callIndex} (${expected.label ?? 'unlabeled'}): ` +
          `recorded length is ${expected.len}, TS asked for ${dest.length} — ` +
          `the TS port and Rust reference are calling fill_bytes with different sizes ` +
          `at this point in the protocol, which is a structural divergence. Fix the TS ` +
          `port to match the Rust call sequence.`,
      );
    }
    const bytes = hexToBytes(expected.bytes_hex);
    if (bytes.length !== expected.len) {
      throw new Error(
        `FixtureRng call ${this.callIndex} (${expected.label ?? 'unlabeled'}): ` +
          `bytes_hex decodes to ${bytes.length} bytes but len field says ${expected.len} — ` +
          `fixture is malformed`,
      );
    }
    dest.set(bytes);
    this.callIndex++;
    this.byteCursor += dest.length;
  }

  /** Number of fill_bytes calls satisfied so far. */
  callsConsumed(): number {
    return this.callIndex;
  }

  /** Total bytes consumed across all calls so far. */
  bytesConsumed(): number {
    return this.byteCursor;
  }

  /** Number of calls remaining in the log. */
  callsRemaining(): number {
    return this.calls.length - this.callIndex;
  }

  /** True if there are no more recorded calls. */
  isExhausted(): boolean {
    return this.callIndex >= this.calls.length;
  }

  /**
   * Peek at the next call's metadata without consuming it. Useful for
   * validating that the TS port is about to make the right call before it
   * commits to it.
   */
  peekNextCall(): RngCall | null {
    if (this.callIndex >= this.calls.length) return null;
    return this.calls[this.callIndex]!;
  }
}

/**
 * Decode a hex string into a Uint8Array. Accepts both lowercase and uppercase.
 * Throws on odd length or non-hex characters.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string (${hex.length} chars)`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hexToBytes: invalid hex char at offset ${i * 2}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/** Encode a Uint8Array as a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}
