//! The host socket's version handshake: one rule for the whole connection.
//!
//! [`admit`] is a pure function of `(handshake state, message)`, so the rule can
//! be stated and tested without a socket, and `handle_connection` is left
//! holding only the state. The alternative — checking a version per message
//! variant — would have to be re-decided by every future capability, and the
//! thing being protected is the *connection*: nothing may be dispatched on it
//! until the peer has said what it speaks.
//!
//! See [`HOST_PROTOCOL_VERSION`] for why the check exists and what it does and
//! does not buy.

use crate::protocol::{ClientMessage, HOST_PROTOCOL_VERSION, ServerMessage};

/// Where a connection is in its handshake.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) enum Handshake {
    /// Nothing has been dispatched on this connection, and nothing will be
    /// until a matching [`ClientMessage::Hello`] arrives.
    #[default]
    AwaitingHello,
    /// The peer declared [`HOST_PROTOCOL_VERSION`]; requests may flow.
    Negotiated,
}

/// What a connection should do with its next message.
///
/// A DU rather than a `Result<(), ServerMessage>` because there are three
/// outcomes, not two, and the caller acts differently on each: only
/// [`Self::Dispatch`] reaches [`dispatch_message`](super::dispatch_message), and
/// only [`Self::Refused`] closes the connection.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Admission {
    /// The handshake succeeded. Write this reply and move to
    /// [`Handshake::Negotiated`]; nothing was dispatched.
    Accepted(ServerMessage),
    /// Hand the message to the dispatcher.
    Dispatch,
    /// Write this reply and close the connection. **Nothing was dispatched** —
    /// which is the whole point, since the failure this prevents is a daemon
    /// that acts on a request whose answer the caller cannot read.
    Refused(ServerMessage),
}

/// Decide what to do with `message`, given where the connection's handshake has
/// got to.
///
/// Every refusal is a [`ServerMessage::Error`], never a new variant, and that is
/// load-bearing rather than lazy: `ServerMessage` is `#[serde(tag = "type")]`,
/// so an unknown tag is a deserialization error at the peer. A refusal the
/// refused peer cannot parse is not a refusal — it is the original bug wearing a
/// different name. `Error` is the one variant every shipped version has
/// understood, so it is the only thing safe to refuse *with*.
pub(super) fn admit(handshake: Handshake, message: &ClientMessage) -> Admission {
    match (handshake, message) {
        (
            Handshake::AwaitingHello,
            ClientMessage::Hello {
                protocol_version: declared,
            },
        ) => {
            if *declared == HOST_PROTOCOL_VERSION {
                Admission::Accepted(ServerMessage::HelloAccepted {
                    protocol_version: HOST_PROTOCOL_VERSION,
                })
            } else {
                Admission::Refused(ServerMessage::Error {
                    message: format!(
                        "host protocol version mismatch: this client speaks {declared}, \
                         writd speaks {HOST_PROTOCOL_VERSION}. {UPGRADE_HINT}"
                    ),
                })
            }
        }
        // A client too old to negotiate. Distinguishable from a mismatch by the
        // message, per the decision: "no version at all" and "the wrong
        // version" are different situations for the operator even though both
        // end the connection.
        (Handshake::AwaitingHello, _) => Admission::Refused(ServerMessage::Error {
            message: format!(
                "this client declared no host protocol version; writd speaks \
                 {HOST_PROTOCOL_VERSION}. {UPGRADE_HINT}"
            ),
        }),
        // A second Hello is a client bug, not a re-negotiation. Refusing keeps
        // the state machine two-valued: there is no way to un-negotiate a
        // connection, so there is no state in which a dispatched message could
        // have been admitted under one version and answered under another.
        (Handshake::Negotiated, ClientMessage::Hello { .. }) => {
            Admission::Refused(ServerMessage::Error {
                message: "host protocol version was already declared on this connection".into(),
            })
        }
        (Handshake::Negotiated, _) => Admission::Dispatch,
    }
}

/// Named once so the two refusals cannot drift apart, and so the fix is in the
/// message rather than in the reader's head. Both failures have the same cause
/// — two builds talking to each other — and the same remedy.
const UPGRADE_HINT: &str = "writ and writd are one build: restart writd after upgrading, and check that the \
     `writ` on your PATH comes from the same build.";

/// Perform the **broker side** of the handshake on a freshly-accepted
/// connection: read one line, and answer it per `admit`. Returns whether the
/// connection may now carry requests.
///
/// `pub` for the stub brokers that stand in for writd in tests (bailiff has
/// two, `writ_client` a third). They exist to script canned replies, and the
/// moment the daemon grew a handshake every one of them became a *second*
/// implementation of it — which is the shape that drifts. Routing them through
/// this means a stub cannot accept a version the daemon would refuse, and a
/// future bump reaches all four call sites at once.
///
/// It reads exactly one line and writes exactly one, so a caller that scripts
/// replies keeps its own lockstep with the client's *requests* rather than
/// having to know a handshake happened at all.
pub async fn answer_host_handshake<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<bool>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(false);
    }
    let admission = match serde_json::from_str::<ClientMessage>(line.trim_end()) {
        Ok(message) => admit(Handshake::AwaitingHello, &message),
        Err(err) => Admission::Refused(ServerMessage::Error {
            message: format!("invalid request: {err}"),
        }),
    };
    let (reply, negotiated) = match admission {
        Admission::Accepted(reply) => (reply, true),
        Admission::Refused(reply) => (reply, false),
        // Unreachable: `admit` never returns `Dispatch` from `AwaitingHello`,
        // which is the property `nothing_dispatches_before_a_matching_hello`
        // pins. Answered rather than asserted, so a stub is not a crash site.
        Admission::Dispatch => (
            ServerMessage::Error {
                message: "the first message on a connection must declare a protocol version".into(),
            },
            false,
        ),
    };
    let mut json = serde_json::to_string(&reply).expect("ServerMessage always serializes");
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    Ok(negotiated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::SessionId;

    fn hello(protocol_version: u32) -> ClientMessage {
        ClientMessage::Hello { protocol_version }
    }

    fn a_request() -> ClientMessage {
        ClientMessage::CloseSession {
            session_id: SessionId::new(),
        }
    }

    #[test]
    fn a_matching_hello_opens_the_connection() {
        assert_eq!(
            admit(Handshake::AwaitingHello, &hello(HOST_PROTOCOL_VERSION)),
            Admission::Accepted(ServerMessage::HelloAccepted {
                protocol_version: HOST_PROTOCOL_VERSION,
            }),
        );
        assert_eq!(
            admit(Handshake::Negotiated, &a_request()),
            Admission::Dispatch
        );
    }

    /// **Nothing is dispatched before the version is known.** The refusal
    /// itself matters less than the fact that `Dispatch` is unreachable from
    /// `AwaitingHello` for anything but a matching `Hello` — that is the
    /// property, and it is total over the message set rather than checked at
    /// each variant.
    #[test]
    fn nothing_dispatches_before_a_matching_hello() {
        for message in [a_request(), hello(HOST_PROTOCOL_VERSION + 1), hello(0)] {
            let admission = admit(Handshake::AwaitingHello, &message);
            assert!(
                matches!(admission, Admission::Refused(_)),
                "{message:?} was not refused before the handshake: {admission:?}",
            );
        }
    }

    /// Both refusals must be `Error`, which is the only variant a peer of any
    /// vintage can parse — a refusal in a variant the refused peer does not
    /// know is the very bug the handshake exists to prevent.
    #[test]
    fn every_refusal_is_an_error_naming_the_fix() {
        for message in [a_request(), hello(HOST_PROTOCOL_VERSION + 1)] {
            let Admission::Refused(ServerMessage::Error { message: text }) =
                admit(Handshake::AwaitingHello, &message)
            else {
                panic!("{message:?} was not refused with an Error");
            };
            assert!(text.contains(UPGRADE_HINT), "{text}");
        }
    }

    /// The two refusals are distinguishable, per the decision: an operator
    /// staring at "no version" is looking for a stale client binary, and one
    /// staring at a mismatch is looking at two numbers that tell them which
    /// side is behind.
    #[test]
    fn an_absent_version_reads_differently_from_a_wrong_one() {
        let Admission::Refused(ServerMessage::Error { message: absent }) =
            admit(Handshake::AwaitingHello, &a_request())
        else {
            panic!("expected a refusal");
        };
        let Admission::Refused(ServerMessage::Error { message: wrong }) =
            admit(Handshake::AwaitingHello, &hello(HOST_PROTOCOL_VERSION + 1))
        else {
            panic!("expected a refusal");
        };

        assert!(
            absent.contains("declared no host protocol version"),
            "{absent}"
        );
        assert!(wrong.contains("mismatch"), "{wrong}");
        assert!(
            wrong.contains(&(HOST_PROTOCOL_VERSION + 1).to_string()),
            "a mismatch must name the version the client actually sent: {wrong}",
        );
        assert_ne!(absent, wrong);
    }

    #[test]
    fn a_second_hello_is_refused_rather_than_renegotiated() {
        assert!(matches!(
            admit(Handshake::Negotiated, &hello(HOST_PROTOCOL_VERSION)),
            Admission::Refused(_),
        ));
    }
}
