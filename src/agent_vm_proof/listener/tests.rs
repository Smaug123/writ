//! Tests for listener-log grading.
//!
//! A serve is met only by a well-formed access line; silence is broken by any
//! mention of an address in the subnet, however it is rendered.

use proptest::prelude::*;

use super::*;

fn cidr(text: &str) -> Ipv4Cidr {
    text.parse().expect("a valid CIDR")
}

fn served(peer: &str, path: &str) -> ListenerExpectation {
    ListenerExpectation::Served {
        peer: peer.parse().unwrap(),
        path: path.to_string(),
    }
}

fn silent(peers: &str) -> ListenerExpectation {
    ListenerExpectation::Silent { peers: cidr(peers) }
}

/// The readiness check the harness makes from loopback, then the guest's
/// request, as `scripts/lib/accept-logging-http-server.py` logs them: an
/// `accept` line per connection, then `http.server`'s access line.
const BROKER_LOG: &str = "\
accept 127.0.0.1 50100
127.0.0.1 - - [25/Sep/2026 10:00:00] \"GET /broker.txt HTTP/1.1\" 200 -
accept 192.168.252.2 41234
192.168.252.2 - - [25/Sep/2026 10:00:03] \"GET /broker.txt HTTP/1.1\" 200 -
";

#[test]
fn a_serve_is_a_well_formed_line_to_that_peer_for_that_path_with_200() {
    assert_eq!(
        grade_listener_log(BROKER_LOG, &served("192.168.252.2", "/broker.txt")),
        Ok(1)
    );
    for (log, why) in [
        (
            "127.0.0.1 - - [25/Sep/2026 10:00:00] \"GET /broker.txt HTTP/1.1\" 200 -\n",
            "loopback is the harness, not the guest",
        ),
        (
            "192.168.252.3 - - [25/Sep/2026 10:00:03] \"GET /broker.txt HTTP/1.1\" 200 -\n",
            "another peer",
        ),
        (
            "192.168.252.2 - - [25/Sep/2026 10:00:03] \"GET /other.txt HTTP/1.1\" 200 -\n",
            "another path",
        ),
        (
            "192.168.252.2 - - [25/Sep/2026 10:00:03] \"GET /broker.txt HTTP/1.1\" 404 -\n",
            "not answered 200",
        ),
        (
            "192.168.252.2 - - [25/Sep/2026 10:00:03] \"HEAD /broker.txt HTTP/1.1\" 200 -\n",
            "not a GET",
        ),
        (
            "192.168.252.2 - - [25/Sep/2026 10:00:03] code 400, message Bad request\n",
            "an error line",
        ),
        (
            "accept 192.168.252.2 41234\n",
            "an accept with no request answered",
        ),
        (
            "----------------------------------------\n\
             Exception occurred during processing of request from ('192.168.252.2', 51234)\n",
            "an accept() that was never answered",
        ),
        ("", "nothing at all"),
        (
            // The request line is the guest's: http.server logs it verbatim,
            // quotes and all, so a guest can write a status of its own into
            // it. This is the 400 it actually got.
            "192.168.252.2 - - [25/Sep/2026 10:00:03] \"GET /broker.txt HTTP/1.1\" 200 -\" 400 -\n",
            "a status forged inside the request line",
        ),
        (
            "192.168.252.2 - - [25/Sep/2026 10:00:03] \"GET /broker.txt HTTP/1.1 extra\" 200 -\n",
            "a request line that is not exactly a GET of the path",
        ),
    ] {
        assert!(
            grade_listener_log(log, &served("192.168.252.2", "/broker.txt")).is_err(),
            "{why}"
        );
    }
}

#[test]
fn silence_is_broken_by_any_mention_of_the_subnet() {
    let quiet = "127.0.0.1 - - [25/Sep/2026 10:00:00] \"GET /forbidden.txt HTTP/1.1\" 200 -\n";
    assert_eq!(
        grade_listener_log(quiet, &silent("192.168.252.0/24")),
        Ok(0)
    );
    for log in [
        "192.168.252.2 - - [25/Sep/2026 10:00:03] \"GET /forbidden.txt HTTP/1.1\" 200 -\n",
        "192.168.252.2 - - [25/Sep/2026 10:00:03] code 400, message Bad request\n",
        "Exception occurred during processing of request from ('192.168.252.2', 51234)\n",
        // A connection accepted and closed without a request: the only line
        // it leaves, and the one plain `http.server` never wrote.
        "accept 192.168.252.2 51234\n",
        "peer 192.168.252.9.51234 reset\n",
        "from 192.168.252.9.\n",
    ] {
        assert!(
            matches!(
                grade_listener_log(log, &silent("192.168.252.0/24")),
                Err(ListenerRefusal::Contacted { .. })
            ),
            "{log:?}"
        );
    }
}

proptest! {
    /// Wherever an address of the subnet lands in a line, and whatever
    /// surrounds it, silence is refused; and an address outside it never
    /// breaks silence.
    #[test]
    fn any_embedded_subnet_address_breaks_silence(
        host in 0_u8..=255,
        inside in any::<bool>(),
        before in "[ -~]{0,12}",
        after in "[ -~]{0,12}",
    ) {
        // The surrounding text must not itself run into the address's digits.
        prop_assume!(!before.ends_with(|c: char| c.is_ascii_digit() || c == '.'));
        prop_assume!(!after.starts_with(|c: char| c.is_ascii_digit() || c == '.'));
        // Nor carry an address of its own, which would answer for it.
        prop_assume!(ipv4_tokens(&before).next().is_none());
        prop_assume!(ipv4_tokens(&after).next().is_none());
        let addr = if inside {
            Ipv4Addr::new(192, 168, 252, host)
        } else {
            Ipv4Addr::new(192, 168, 253, host)
        };
        let log = format!("{before}{addr}{after}\n");
        let graded = grade_listener_log(&log, &silent("192.168.252.0/24"));
        prop_assert_eq!(graded.is_err(), inside);
    }
}
