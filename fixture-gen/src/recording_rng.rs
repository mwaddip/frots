//! `RecordingRng` — wraps a deterministic [`RngCore`] and records every byte
//! it produces. The recorded log is what the TypeScript port will replay
//! against to get byte-for-byte equivalent intermediate values.
//!
//! Design constraints:
//!
//! 1. **All paths funnel through `fill_bytes`.** `next_u32` / `next_u64` are
//!    implemented in terms of `fill_bytes` so the log always represents a
//!    uniform byte stream. This is correct for `ChaCha20Rng` (the only RNG we
//!    use here) because its four `RngCore` methods all read from the same
//!    internal keystream and `fill_bytes(&mut [0u8; 4])` is byte-equivalent to
//!    `next_u32().to_le_bytes()`.
//! 2. **Labels are sticky-until-consumed.** Setting a label affects the *next*
//!    `fill_bytes` call, then is cleared. This lets the harness annotate each
//!    call with a phase name (e.g. `"dkg.part1.p1.coefficient[0]"`) without
//!    threading the label through the inner FROST APIs.
//! 3. **Cursor-based phase markers.** Tests can call [`RecordingRng::cursor`]
//!    before and after a protocol step to slice the log into named buckets in
//!    the output JSON, even when fine-grained per-call labels would be too
//!    fragile.

use rand_core::{CryptoRng, Error, RngCore};
use serde::Serialize;

/// One captured `fill_bytes` call.
#[derive(Debug, Clone, Serialize)]
pub struct RngCall {
    /// Position in the global call log (0-indexed).
    pub seq: usize,
    /// Optional human-readable label set via [`RecordingRng::label_next`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Number of bytes consumed.
    pub len: usize,
    /// The bytes that were produced, hex-encoded.
    pub bytes_hex: String,
}

/// `RngCore` wrapper that records every byte its inner RNG produces.
///
/// Construct with [`RecordingRng::new`], pass `&mut RecordingRng` anywhere a
/// `&mut R: RngCore + CryptoRng` is required, and recover the log via
/// [`RecordingRng::log`] / [`RecordingRng::into_log`].
#[derive(Debug)]
pub struct RecordingRng<R: RngCore> {
    inner: R,
    log: Vec<RngCall>,
    next_label: Option<String>,
}

impl<R: RngCore> RecordingRng<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            log: Vec::new(),
            next_label: None,
        }
    }

    /// Attach a label to the next `fill_bytes` call. The label is cleared
    /// once consumed.
    pub fn label_next(&mut self, label: impl Into<String>) {
        self.next_label = Some(label.into());
    }

    /// Drop a pending label without consuming a call.
    #[allow(dead_code)]
    pub fn clear_label(&mut self) {
        self.next_label = None;
    }

    /// Position in the global call log — useful as a phase marker so the
    /// harness can later slice the log by `[start, end)`.
    pub fn cursor(&self) -> usize {
        self.log.len()
    }

    /// Borrow the captured log.
    pub fn log(&self) -> &[RngCall] {
        &self.log
    }

    /// Take ownership of the captured log, consuming the wrapper.
    pub fn into_log(self) -> Vec<RngCall> {
        self.log
    }
}

impl<R: RngCore> RngCore for RecordingRng<R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        let label = self.next_label.take();
        self.log.push(RngCall {
            seq: self.log.len(),
            label,
            len: dest.len(),
            bytes_hex: hex::encode(&*dest),
        });
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for RecordingRng<R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn captures_fill_bytes_calls_in_order() {
        let inner = ChaCha20Rng::from_seed([0u8; 32]);
        let mut rng = RecordingRng::new(inner);

        let mut a = [0u8; 32];
        let mut b = [0u8; 8];
        rng.label_next("first");
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);

        let log = rng.log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 0);
        assert_eq!(log[0].len, 32);
        assert_eq!(log[0].label.as_deref(), Some("first"));
        assert_eq!(log[1].seq, 1);
        assert_eq!(log[1].len, 8);
        assert!(log[1].label.is_none(), "label should be one-shot");
    }

    #[test]
    fn next_u32_and_u64_route_through_fill_bytes() {
        let inner = ChaCha20Rng::from_seed([0u8; 32]);
        let mut rng = RecordingRng::new(inner);

        let _ = rng.next_u32();
        let _ = rng.next_u64();

        let log = rng.log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].len, 4);
        assert_eq!(log[1].len, 8);
    }

    #[test]
    fn determinism_against_fixed_seed() {
        // Two independent recorders with the same seed must produce identical logs.
        let mut a = RecordingRng::new(ChaCha20Rng::from_seed([42u8; 32]));
        let mut b = RecordingRng::new(ChaCha20Rng::from_seed([42u8; 32]));

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);

        assert_eq!(a.log()[0].bytes_hex, b.log()[0].bytes_hex);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn cursor_tracks_call_count() {
        let mut rng = RecordingRng::new(ChaCha20Rng::from_seed([0u8; 32]));
        assert_eq!(rng.cursor(), 0);
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        assert_eq!(rng.cursor(), 1);
        rng.fill_bytes(&mut buf);
        assert_eq!(rng.cursor(), 2);
    }
}
