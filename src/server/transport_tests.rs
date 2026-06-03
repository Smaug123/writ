//! Socket round-trip, bounded line reads, and socket-bind handling.

use super::test_support::*;
use super::*;
use crate::core::AgentKind;
use wiremock::MockServer;

#[tokio::test]
async fn socket_roundtrip_open_and_close_session() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");

    let dir = tempfile::tempdir().unwrap();
    // The permission check in run() requires the parent to be 0700;
    // tempfile creates 0755, so fix it before spawning.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = dir.path().join("test.sock");

    // Spawn the listener
    let state_clone = Arc::clone(&state);
    let path_clone = sock_path.clone();
    tokio::spawn(async move {
        let _ = run(&path_clone, state_clone).await;
    });

    let stream = connect_with_retries(&sock_path).await;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // Open session
    let open_msg = serde_json::to_string(&ClientMessage::OpenSession {
        label: Some("integration".into()),
        agent_kind: Some(AgentKind::Claude),
        agent_model: None,
    })
    .unwrap()
        + "\n";
    writer.write_all(open_msg.as_bytes()).await.unwrap();
    let reply = lines.next_line().await.unwrap().unwrap();
    let server_msg: ServerMessage = serde_json::from_str(&reply).unwrap();
    let session_id = match server_msg {
        ServerMessage::SessionOpened { session_id } => session_id,
        other => panic!("expected SessionOpened, got {other:?}"),
    };

    // Close session
    let close_msg =
        serde_json::to_string(&ClientMessage::CloseSession { session_id }).unwrap() + "\n";
    writer.write_all(close_msg.as_bytes()).await.unwrap();
    let reply = lines.next_line().await.unwrap().unwrap();
    let server_msg: ServerMessage = serde_json::from_str(&reply).unwrap();
    assert_eq!(server_msg, ServerMessage::SessionClosed);

    // Verify the DB was updated by the server
    let record = state.audit.get_session(session_id).unwrap().unwrap();
    assert!(record.closed_at.is_some());
}
/// Normal line within the cap: reads cleanly, strips trailing `\r`.
#[tokio::test]
async fn read_line_bounded_reads_up_to_newline() {
    let mut input = &b"hello\r\n"[..];
    let line = read_line_bounded(&mut input, 64).await.unwrap().unwrap();
    assert_eq!(&line, b"hello");
}

/// EOF before any bytes is `Ok(None)`, matching AsyncBufReadExt::read_line.
#[tokio::test]
async fn read_line_bounded_returns_none_on_clean_eof() {
    let mut input: &[u8] = b"";
    assert!(read_line_bounded(&mut input, 64).await.unwrap().is_none());
}

/// EOF after bytes but without a newline yields whatever was read —
/// lets the caller decide whether a final unterminated frame is an
/// error (our caller treats the JSON parse failure as the error).
#[tokio::test]
async fn read_line_bounded_returns_partial_on_eof_without_newline() {
    let mut input = &b"abc"[..];
    let line = read_line_bounded(&mut input, 64).await.unwrap().unwrap();
    assert_eq!(&line, b"abc");
}

/// A line exceeding the cap (even without a newline) is rejected
/// rather than buffered to completion — that's the whole point of
/// the cap.
#[tokio::test]
async fn read_line_bounded_rejects_oversize_without_newline() {
    let big = vec![b'x'; 128];
    let mut input = big.as_slice();
    let err = read_line_bounded(&mut input, 64).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

/// Oversize with a newline also rejects, and does so without having
/// grown the internal buffer past the cap.
#[tokio::test]
async fn read_line_bounded_rejects_oversize_with_newline() {
    let mut big = vec![b'x'; 128];
    big.push(b'\n');
    let mut input = big.as_slice();
    let err = read_line_bounded(&mut input, 64).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

/// After the cap is hit, the connection-level handler reports a
/// structured error to the peer so a CLI surfaces something
/// actionable rather than a mystery-close.
#[tokio::test]
async fn oversize_request_over_socket_returns_structured_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = dir.path().join("test.sock");

    let state_clone = Arc::clone(&state);
    let path_clone = sock_path.clone();
    tokio::spawn(async move {
        let _ = run(&path_clone, state_clone).await;
    });

    let stream = connect_with_retries(&sock_path).await;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // Write > MAX_LINE_BYTES non-newline bytes, then a newline. The
    // writes may fail with BrokenPipe/ConnectionReset: the server
    // trips the cap mid-read, sends its Error reply, and closes,
    // which can race ahead of our later writes on Linux. Tolerating
    // a write failure here is correct — the invariant under test is
    // that the *read* side sees a structured Error reply, not that
    // every byte we tried to send was acknowledged.
    let oversize = vec![b'x'; MAX_LINE_BYTES + 1];
    let _ = writer.write_all(&oversize).await;
    let _ = writer.write_all(b"\n").await;

    let reply = lines.next_line().await.unwrap().unwrap();
    let msg: ServerMessage = serde_json::from_str(&reply).unwrap();
    match msg {
        ServerMessage::Error { message } => {
            assert!(message.contains("exceeds"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}
/// Fresh parent directory with no pre-existing socket file: bind succeeds.
#[tokio::test]
async fn bind_socket_succeeds_on_empty_path() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("w.sock");
    let l = bind_socket(&sock).await.unwrap();
    assert!(sock.exists());
    drop(l);
}

/// A leftover socket file with no live listener (stale) is detected
/// (connect fails), cleaned up, and the rebind succeeds.
///
/// The reclaim is retried on a bounded deadline. In the parallel test
/// harness a sibling `fork()` in another test can transiently inherit
/// this just-dropped listener's fd — `O_CLOEXEC` closes it only at the
/// child's `exec`, not at `fork` — keeping the AF_UNIX socket
/// momentarily connectable (into the listen backlog) so `bind_socket`'s
/// liveness probe reports `AddrInUse`. The window is sub-millisecond:
/// once the forked child `exec`s, the socket is truly gone and the
/// reclaim succeeds. Production `writd` startup binds the socket once
/// with no concurrent listener being dropped, so it never sees this
/// transient; only the test harness manufactures it, so only the test
/// tolerates it. A genuine reclaim failure still surfaces: any other
/// error fails immediately, and exhausting the deadline panics rather
/// than hanging.
#[tokio::test]
async fn bind_socket_reclaims_stale_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("w.sock");
    {
        // Bind, then drop the listener. The socket *file* lingers
        // (Rust doesn't rm on drop) but nothing is listening.
        let _listener = UnixListener::bind(&sock).unwrap();
    }
    assert!(sock.exists(), "precondition: stale socket file present");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let l = loop {
        match bind_socket(&sock).await {
            Ok(l) => break l,
            Err(e)
                if e.kind() == io::ErrorKind::AddrInUse && std::time::Instant::now() < deadline =>
            {
                // Transient fork-inherited connectability; retry once
                // the holding child has had a chance to exec.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(e) => panic!("bind_socket failed to reclaim stale socket: {e}"),
        }
    };
    assert!(sock.exists());
    drop(l);
}

/// A live listener at the path must be refused — we don't want two
/// daemons fighting over the same credential socket.
#[tokio::test]
async fn bind_socket_refuses_to_displace_live_listener() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("w.sock");
    let _live = UnixListener::bind(&sock).unwrap();
    let err = bind_socket(&sock).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert!(err.to_string().contains("already running"), "got: {err}");
}

/// A regular file (not a socket) at the configured path is operator
/// error; refuse rather than silently deleting arbitrary files.
#[tokio::test]
async fn bind_socket_refuses_to_delete_non_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("w.sock");
    std::fs::write(&sock, b"not a socket").unwrap();
    let err = bind_socket(&sock).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
}
