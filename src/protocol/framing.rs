//! Newline-delimited JSON framing for the host Unix socket: one message per
//! line in each direction, nothing else. Both ends of the wire read and
//! write frames through this module, so the line cap and the CR/EOF rules
//! cannot drift between the broker and its clients.

use std::io;

use serde::Serialize;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};

/// Maximum bytes either end will buffer for a single newline-terminated
/// frame, exclusive of the terminator.
///
/// The largest honest frame is a `RunAgent` carrying a 1 MiB
/// [`AgentPrompt`](crate::agent_run::AgentPrompt) (the cap pinned by
/// [`MAX_AGENT_PROMPT_BYTES`](crate::agent_run::MAX_AGENT_PROMPT_BYTES));
/// every other message is at most a few KiB. `serde_json` escapes ASCII
/// control bytes as `\u00XX`, expanding worst-case input 6:1, so that frame
/// is up to 6 MiB before envelope overhead — the same `6 * MAX + small`
/// convention `vm_http` uses. Replies are far smaller, but both ends share
/// one ceiling so the contract stays symmetric. Without a cap a peer that
/// never sends a newline would grow the buffer until the process OOMs.
pub const MAX_LINE_BYTES: usize = 6 * crate::agent_run::MAX_AGENT_PROMPT_BYTES + 64 * 1024;

/// One message as the bytes that go on the wire: its JSON, then the newline
/// that ends the frame. `serde_json` never emits a raw newline (control
/// characters are escaped), so the terminator is unambiguous.
pub fn encode_frame<T: Serialize>(msg: &T) -> serde_json::Result<String> {
    let mut json = serde_json::to_string(msg)?;
    json.push('\n');
    Ok(json)
}

/// [`encode_frame`] and write it. A message that fails to serialise is an
/// `InvalidData` error; callers that must tell that apart from a transport
/// failure call [`encode_frame`] themselves.
pub async fn write_frame<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> io::Result<()> {
    let json = encode_frame(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    writer.write_all(json.as_bytes()).await
}

/// Read one newline-terminated line from `reader`, failing with
/// `InvalidData` if the line would exceed `max` bytes (exclusive of the
/// terminator), without ever buffering more than `max` bytes. A trailing
/// `\r` before the newline is stripped. Returns `Ok(None)` on clean EOF
/// before any bytes are seen, mirroring `AsyncBufReadExt::read_line`'s
/// convention; EOF after some bytes yields those bytes, and the caller's
/// JSON decode decides whether an unterminated final frame is an error.
pub async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + i > max {
                return Err(oversize(max));
            }
            buf.extend_from_slice(&available[..i]);
            reader.consume(i + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(buf));
        }
        let len = available.len();
        if buf.len() + len > max {
            return Err(oversize(max));
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
}

fn oversize(max: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("line exceeds {max}-byte limit"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::BufReader;

    /// Bytes that cannot contain the terminator, so the frame boundary is
    /// exactly where the test puts it.
    fn line() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(
            any::<u8>().prop_filter("not a newline", |b| *b != b'\n'),
            0..300,
        )
    }

    /// Drive the reader through a `BufReader` of a small capacity so the
    /// line arrives in several `fill_buf` chunks, which is the path a real
    /// socket takes and the one a naive implementation gets wrong.
    fn read(input: &[u8], capacity: usize, max: usize) -> io::Result<Option<Vec<u8>>> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let mut reader = BufReader::with_capacity(capacity, input);
                read_line_bounded(&mut reader, max).await
            })
    }

    proptest! {
        /// A terminated line at or under the cap comes back without its
        /// terminator (and one trailing `\r`); over the cap it is refused
        /// as `InvalidData`. The cap counts the bytes before the newline,
        /// `\r` included.
        #[test]
        fn terminated_lines_are_read_or_refused_by_the_cap(
            line in line(),
            max in 0usize..300,
            capacity in 1usize..8,
        ) {
            let mut input = line.clone();
            input.push(b'\n');
            let result = read(&input, capacity, max);
            if line.len() <= max {
                let mut expected = line.clone();
                if expected.last() == Some(&b'\r') {
                    expected.pop();
                }
                prop_assert_eq!(result.unwrap(), Some(expected));
            } else {
                prop_assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }

        /// An unterminated tail at EOF comes back as-is (the caller's decode
        /// decides what to make of it); an empty stream is `None`; and the
        /// cap still applies.
        #[test]
        fn unterminated_tails_are_returned_verbatim(
            line in line(),
            max in 0usize..300,
            capacity in 1usize..8,
        ) {
            let result = read(&line, capacity, max);
            if line.is_empty() {
                prop_assert_eq!(result.unwrap(), None);
            } else if line.len() <= max {
                prop_assert_eq!(result.unwrap(), Some(line));
            } else {
                prop_assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }

        /// What `encode_frame` writes, `read_line_bounded` reads back as one
        /// frame that decodes to the original, whatever the payload holds.
        #[test]
        fn frames_round_trip(text in any::<String>(), capacity in 1usize..8) {
            let msg = serde_json::json!({ "text": text, "n": 7 });
            let frame = encode_frame(&msg).unwrap();
            let bytes = read(frame.as_bytes(), capacity, MAX_LINE_BYTES).unwrap().unwrap();
            prop_assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(), msg);
        }
    }

    /// A writer-side stream that closes without writing yields `Ok(None)`
    /// over a real socket pair, matching the EOF the clients translate to
    /// "closed without reply".
    #[tokio::test]
    async fn clean_eof_over_a_socket_pair_is_none() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        drop(b);
        let mut reader = BufReader::new(a);
        let line = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_line_bounded(&mut reader, 64),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(line.is_none());
    }
}
