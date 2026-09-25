//! What a listener the host runs logged, graded.
//!
//! Evidence protocol rule 1 names "accept and connect logs of listeners the
//! host runs" among the facts the host owns. Until Stage E3b the proof's
//! positive control — the guest reaching the broker — was graded on the
//! guest's own `wget` exit status, which is a claim; it is graded here on the
//! broker listener's access log instead, and the forbidden listener's log is
//! the host's own witness that nothing reached it.
//!
//! The listeners are `python3 -m http.server`, whose access log is one line per
//! answered request:
//!
//! ```text
//! 192.168.252.2 - - [25/Sep/2026 10:00:00] "GET /broker.txt HTTP/1.1" 200 -
//! ```
//!
//! The two questions are read with different strictness on purpose, because
//! they fail in opposite directions.
//!
//! * **Served** is a positive: it is met only by a well-formed line naming
//!   the guest's address, the path, and status 200. A line that does not
//!   parse is not a serve.
//! * **Silent** is a negative, so it is read fail-closed: *any* IPv4 address
//!   in the session's subnet anywhere in the log is contact — an access line,
//!   an error line, or the `request from ('192.168.252.2', …)` of a Python
//!   traceback, which is the listener reporting an `accept()` the access log
//!   never got to record.

use std::net::Ipv4Addr;

use writ_core::core::Ipv4Cidr;

/// What a listener's log must show.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerExpectation {
    /// The listener answered `GET <path>` with 200 to `peer`.
    Served { peer: Ipv4Addr, path: String },
    /// No address in `peers` appears anywhere in the log.
    Silent { peers: Ipv4Cidr },
}

/// Why a log does not meet its expectation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ListenerRefusal {
    #[error(
        "the listener logged no `GET {path}` answered 200 to {peer} ({lines} line(s) read); \
         the request did not reach the process"
    )]
    NotServed {
        peer: Ipv4Addr,
        path: String,
        lines: usize,
    },
    #[error("the listener logged contact from {peer}, inside {peers}: {line:?}")]
    Contacted {
        peers: Ipv4Cidr,
        peer: Ipv4Addr,
        line: String,
    },
}

/// Grade one listener's log.
///
/// Returns the number of lines that met a [`ListenerExpectation::Served`], or
/// zero for a met [`ListenerExpectation::Silent`].
pub fn grade_listener_log(
    log: &str,
    expected: &ListenerExpectation,
) -> Result<usize, ListenerRefusal> {
    match expected {
        ListenerExpectation::Served { peer, path } => {
            let served = log
                .lines()
                .filter(|line| access_line(line) == Some((*peer, "GET", path.as_str(), 200)))
                .count();
            if served == 0 {
                Err(ListenerRefusal::NotServed {
                    peer: *peer,
                    path: path.clone(),
                    lines: log.lines().count(),
                })
            } else {
                Ok(served)
            }
        }
        ListenerExpectation::Silent { peers } => {
            for line in log.lines() {
                if let Some(peer) = ipv4_tokens(line).find(|addr| peers.contains_addr(*addr)) {
                    return Err(ListenerRefusal::Contacted {
                        peers: *peers,
                        peer,
                        line: line.to_string(),
                    });
                }
            }
            Ok(0)
        }
    }
}

/// One access line: `<peer> - - [<date>] "<method> <path> <version>" <status> <size>`.
fn access_line(line: &str) -> Option<(Ipv4Addr, &str, &str, u16)> {
    let (peer, rest) = line.split_once(" - - [")?;
    let peer = peer.parse().ok()?;
    let (_date, rest) = rest.split_once("] \"")?;
    let (request, rest) = rest.split_once("\" ")?;
    let mut request = request.split(' ');
    let (method, path, version) = (request.next()?, request.next()?, request.next()?);
    if request.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    let status = rest.split(' ').next()?.parse().ok()?;
    Some((peer, method, path, status))
}

/// Every IPv4 address in `line`: each four consecutive dot-separated numbers
/// inside a run of digits and dots. Windows rather than whole runs, so an
/// address followed by a dot or a `.port` suffix is still found — this is the
/// fail-closed reading, and one it misses is contact it would call silence.
fn ipv4_tokens(line: &str) -> impl Iterator<Item = Ipv4Addr> + '_ {
    line.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .flat_map(|run| {
            let parts: Vec<&str> = run.split('.').collect();
            (0..parts.len().saturating_sub(3))
                .filter_map(|start| parts[start..start + 4].join(".").parse().ok())
                .collect::<Vec<Ipv4Addr>>()
        })
}

#[cfg(test)]
mod tests;
