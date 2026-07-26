//! The byte-cap policy for a supervised child's captured output.
//!
//! This is the pure core of "how much of a child's output do we keep, and what
//! do we do when it writes more than that". It is deliberately free of IO: it
//! accepts chunks of bytes in whatever sizes a reader happens to deliver and
//! answers with a decision, so the blocking and async supervisors can share one
//! policy instead of each reimplementing the accounting against their own IO
//! model. Two supervisors with two subtly different caps is the failure mode
//! this module exists to prevent.
//!
//! The central correctness property is **chunk-boundary independence**: the
//! result depends only on the concatenated bytes, never on how a reader split
//! them. A tail cap computed per-chunk rather than over the stream is exactly the
//! kind of bug that shows up only under a specific read size, so the property
//! tests below check every policy against a whole-input reference
//! implementation over arbitrary chunkings.

/// What to do with a writer that exceeds its byte cap.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CapturePolicy {
    /// Reject the *whole* capture once the writer exceeds `cap`.
    ///
    /// For output a caller parses (one object id per `rev-list` line), a
    /// truncated prefix is worse than nothing: it looks like a complete, shorter
    /// answer. So [`CaptureBuffer::finish`] yields no bytes at all after an
    /// overrun, and the caller is expected to fail the run.
    RejectOverCap { cap: usize },
    /// Retain a line-aligned tail of at most `cap` bytes and keep reading.
    ///
    /// For diagnostics, a verbose child must not be able to make the host buffer
    /// unbounded bytes, but the informative part — a tool's fatal message — is
    /// its *last* output, so the tail is what we keep.
    ///
    /// On truncation the retained tail's first line is a fragment of whatever
    /// preceded the cap, so it is dropped: every retained line is complete. That
    /// is a soundness property, not tidiness. A downstream secret redactor works
    /// line by line, and a credential (a newline-free token) that straddled the
    /// cap would otherwise survive as an unredactable partial fragment at the
    /// front. When the whole tail is one unbroken line there is no complete line
    /// to keep, so it is dropped entirely — safe over sorry.
    TailCap { cap: usize },
}

/// Accumulates a child's output under a [`CapturePolicy`].
#[derive(Debug)]
pub(crate) struct CaptureBuffer {
    policy: CapturePolicy,
    buf: Vec<u8>,
    /// `TailCap` only: bytes were dropped off the front, so the retained tail
    /// begins mid-line and needs alignment at `finish`.
    truncated: bool,
    /// `RejectOverCap` only: the cap was exceeded, so the capture is void.
    overran: bool,
}

impl CaptureBuffer {
    pub(crate) fn new(policy: CapturePolicy) -> Self {
        Self {
            policy,
            buf: Vec::new(),
            truncated: false,
            overran: false,
        }
    }

    /// Absorb the next `chunk` of output.
    ///
    /// Returns [`Absorb::Continue`] if the reader should keep going, or
    /// [`Absorb::Stop`] once further bytes cannot change the outcome — under
    /// `RejectOverCap` the capture is already void, so reading on would only
    /// burn time against a hostile child. Memory stays bounded by
    /// `cap` plus one chunk regardless of how much the child emits.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Absorb {
        if self.overran {
            return Absorb::Stop;
        }
        self.buf.extend_from_slice(chunk);
        match self.policy {
            CapturePolicy::RejectOverCap { cap } => {
                if self.buf.len() > cap {
                    self.overran = true;
                    // Release the buffer now: its contents can never be
                    // surfaced, so holding cap-plus-a-chunk bytes until the
                    // supervisor joins the drain is pure waste.
                    self.buf = Vec::new();
                    return Absorb::Stop;
                }
                Absorb::Continue
            }
            CapturePolicy::TailCap { cap } => {
                if self.buf.len() > cap {
                    let excess = self.buf.len() - cap;
                    self.buf.drain(..excess);
                    self.truncated = true;
                }
                Absorb::Continue
            }
        }
    }

    /// True once a `RejectOverCap` writer has exceeded its cap. Always false
    /// under `TailCap`, which truncates rather than rejects.
    pub(crate) fn overran(&self) -> bool {
        self.overran
    }

    /// Yield the retained bytes: line-aligned under `TailCap`, and empty after a
    /// `RejectOverCap` overrun so no caller can act on a partial prefix.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.overran {
            return Vec::new();
        }
        if self.truncated {
            match self.buf.iter().position(|&b| b == b'\n') {
                Some(newline) => {
                    self.buf.drain(..=newline);
                }
                None => self.buf.clear(),
            }
        }
        self.buf
    }
}

/// Whether a reader feeding a [`CaptureBuffer`] should keep reading.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Absorb {
    Continue,
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Whole-input reference for [`CapturePolicy::TailCap`]: keep the last `cap`
    /// bytes, and if anything was dropped, discard through the first newline so
    /// only complete lines remain.
    fn tail_cap_reference(input: &[u8], cap: usize) -> Vec<u8> {
        if input.len() <= cap {
            return input.to_vec();
        }
        let tail = &input[input.len() - cap..];
        match tail.iter().position(|&b| b == b'\n') {
            Some(newline) => tail[newline + 1..].to_vec(),
            None => Vec::new(),
        }
    }

    /// Feed `input` through a `CaptureBuffer` in the given chunk sizes, stopping
    /// when the buffer says to.
    fn drive(policy: CapturePolicy, input: &[u8], chunk_sizes: &[usize]) -> (Vec<u8>, bool) {
        let mut buffer = CaptureBuffer::new(policy);
        let mut offset = 0;
        // Cycle the chunk sizes so any input length can be consumed by any
        // non-empty size list.
        for size in chunk_sizes.iter().copied().cycle() {
            if offset >= input.len() {
                break;
            }
            let end = (offset + size.max(1)).min(input.len());
            let absorb = buffer.push(&input[offset..end]);
            offset = end;
            if absorb == Absorb::Stop {
                break;
            }
        }
        let overran = buffer.overran();
        (buffer.finish(), overran)
    }

    proptest! {
        /// The retained tail depends only on the concatenated bytes, never on how
        /// the reader split them. This is the property that a per-chunk (rather
        /// than per-stream) cap would violate, and it would only show up under
        /// one particular read size.
        #[test]
        fn tail_cap_matches_reference_for_any_chunking(
            input in proptest::collection::vec(any::<u8>(), 0..2048),
            cap in 1usize..512,
            chunk_sizes in proptest::collection::vec(1usize..300, 1..8),
        ) {
            let (got, overran) = drive(CapturePolicy::TailCap { cap }, &input, &chunk_sizes);
            prop_assert_eq!(got, tail_cap_reference(&input, cap));
            prop_assert!(!overran, "TailCap truncates; it never rejects");
        }

        /// A tail cap must actually bound memory: the retained bytes never exceed
        /// the cap, whatever the input or chunking.
        #[test]
        fn tail_cap_never_exceeds_the_cap(
            input in proptest::collection::vec(any::<u8>(), 0..2048),
            cap in 1usize..512,
            chunk_sizes in proptest::collection::vec(1usize..300, 1..8),
        ) {
            let (got, _) = drive(CapturePolicy::TailCap { cap }, &input, &chunk_sizes);
            prop_assert!(got.len() <= cap, "retained {} exceeds cap {}", got.len(), cap);
        }

        /// Every line in a truncated tail is complete: the capture either starts
        /// at the very beginning of the input or immediately after a newline.
        /// This is what a line-based secret redactor relies on.
        #[test]
        fn tail_cap_retains_only_complete_lines(
            input in proptest::collection::vec(any::<u8>(), 0..2048),
            cap in 1usize..512,
        ) {
            let got = tail_cap_reference(&input, cap);
            let (driven, _) = drive(CapturePolicy::TailCap { cap }, &input, &[64]);
            prop_assert_eq!(&driven, &got);
            if input.len() > cap && !got.is_empty() {
                // The retained bytes appear in the input immediately after a '\n'.
                let start = input.len() - got.len();
                prop_assert_eq!(input[start - 1], b'\n',
                    "retained tail must begin just after a newline");
            }
        }

        /// A rejecting capture overruns exactly when the child wrote more than
        /// the cap — no more, no less — and yields nothing when it does, so a
        /// caller can never act on a truncated prefix.
        #[test]
        fn reject_over_cap_overruns_exactly_when_input_exceeds_cap(
            input in proptest::collection::vec(any::<u8>(), 0..2048),
            cap in 1usize..512,
            chunk_sizes in proptest::collection::vec(1usize..300, 1..8),
        ) {
            let (got, overran) = drive(CapturePolicy::RejectOverCap { cap }, &input, &chunk_sizes);
            prop_assert_eq!(overran, input.len() > cap);
            if overran {
                prop_assert!(got.is_empty(), "an over-cap capture must yield no bytes");
            } else {
                prop_assert_eq!(got, input);
            }
        }
    }

    /// Exactly `cap` bytes is not an overrun — the boundary is `>`, not `>=` —
    /// so a caller sizing its cap to the largest legitimate output is not
    /// rejected for producing exactly that.
    #[test]
    fn reject_over_cap_accepts_exactly_the_cap() {
        let (got, overran) = drive(CapturePolicy::RejectOverCap { cap: 4 }, b"aaaa", &[1]);
        assert!(!overran);
        assert_eq!(got, b"aaaa");
        let (got, overran) = drive(CapturePolicy::RejectOverCap { cap: 4 }, b"aaaaa", &[1]);
        assert!(overran);
        assert!(got.is_empty());
    }

    /// The worked example from the previous inline implementation, kept so the
    /// rewrite is pinned to the same observable behaviour: the last 8 bytes of
    /// `aaaa\nbbbb\ncccc\n` are `bb\ncccc\n`, whose leading `bb` is a fragment.
    #[test]
    fn tail_cap_drops_the_partial_leading_line() {
        let (got, _) = drive(
            CapturePolicy::TailCap { cap: 8 },
            b"aaaa\nbbbb\ncccc\n",
            &[4],
        );
        assert_eq!(got, b"cccc\n");
    }

    /// An under-cap capture passes through verbatim even with no newline at all.
    #[test]
    fn tail_cap_keeps_everything_under_the_cap() {
        let (got, _) = drive(CapturePolicy::TailCap { cap: 4096 }, b"short output", &[3]);
        assert_eq!(got, b"short output");
    }

    /// A single over-cap line has no complete line to retain, so nothing is
    /// surfaced rather than a fragment.
    #[test]
    fn tail_cap_clears_an_unbroken_over_cap_line() {
        let (got, _) = drive(CapturePolicy::TailCap { cap: 4 }, b"aaaaaaaaaa", &[3]);
        assert!(got.is_empty(), "expected empty, got {got:?}");
    }
}
