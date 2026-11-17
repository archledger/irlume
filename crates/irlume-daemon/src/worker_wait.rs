// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Connection-side worker waiting, session pumping and final response.

use super::{
    arbiter::CancelToken, enrollment_session, peer_gone, position_session, ClientLink, Response,
    WorkerReply, CLIENT_ALIVE_POLL,
};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Instant;

/// Wait for the worker while checking this connection and pumping session events.
///
/// Polling notices departed clients while waiting for the worker's reply, so
/// their queued work becomes unclaimable or their running job is asked to stop.
///
/// The caller supplies the normal reply deadline; tests can exercise the same
/// expiration branch without waiting the full worker budget.
///
/// # Errors
///
/// Returns a session-pump, response-admission or write error.
pub(super) fn wait_and_respond(
    stream: UnixStream,
    answer: Receiver<WorkerReply>,
    link: &ClientLink,
    stop: &CancelToken,
    mut session_connection: Option<enrollment_session::Connection>,
    mut position_connection: Option<position_session::Connection>,
    deadline: Instant,
) -> io::Result<()> {
    let resp = loop {
        if let Some(connection) = &mut session_connection {
            if let Err(error) = connection.pump(&stream) {
                link.abandon(stop);
                return Err(error);
            }
        }
        if let Some(connection) = &mut position_connection {
            if let Err(error) = connection.pump(&stream) {
                link.abandon(stop);
                return Err(error);
            }
        }
        match answer.recv_timeout(CLIENT_ALIVE_POLL) {
            Ok(resp) => {
                if let Some(connection) = &mut session_connection {
                    connection.pump(&stream)?;
                }
                if let Some(connection) = &mut position_connection {
                    connection.pump(&stream)?;
                }
                break resp;
            }
            Err(RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    // Expiry ends every waiter, not only interactive sessions.
                    // The link asks only its own job to stop, under its lock.
                    link.abandon(stop);
                    break Response::Error("request did not complete".into()).into();
                }
                if peer_gone(&stream) {
                    // Cancel only while this link owns the worker. Queued
                    // requests instead become unclaimable.
                    if link.abandon(stop) {
                        irlume_common::dlog!(
                            "client disconnected mid-request; asked the capture to stop"
                        );
                    }
                    return Ok(());
                }
            }
            // A missing worker reply keeps password fallback available.
            Err(RecvTimeoutError::Disconnected) => {
                break Response::Error("request did not complete".into()).into()
            }
        }
    };
    resp.respond(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;
    use std::time::Duration;

    fn read_reply(client: UnixStream) -> Response {
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_response(&mut BufReader::new(client))
    }

    fn read_response(reader: &mut impl BufRead) -> Response {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).expect("one complete response")
    }

    fn expire_waiter(
        link: &ClientLink,
        stop: &CancelToken,
        session: Option<enrollment_session::Connection>,
        position: Option<position_session::Connection>,
    ) {
        let (reply, answer) = mpsc::channel();
        let (server, client) = UnixStream::pair().unwrap();
        wait_and_respond(
            server,
            answer,
            link,
            stop,
            session,
            position,
            Instant::now(),
        )
        .unwrap();
        // Keep the sender alive through the wait so only Timeout can end it.
        drop(reply);
        assert!(matches!(
            read_reply(client),
            Response::Error(message) if message == "request did not complete"
        ));
    }

    #[test]
    fn expired_ordinary_waiter_abandons_queued_request_without_stopping_owner() {
        let stop = CancelToken::new();
        let owner = ClientLink::default();
        assert!(owner.claim());
        let queued = ClientLink::default();

        expire_waiter(&queued, &stop, None, None);

        assert!(
            !stop.stop_requested(),
            "a queued timeout must not stop the worker's other request"
        );
        assert!(
            !queued.claim(),
            "a timed-out queued request must not become claimable"
        );
        assert!(matches!(*owner.lock(), crate::ClientState::Running));
    }

    #[test]
    fn expired_ordinary_waiter_stops_its_own_running_request() {
        let stop = CancelToken::new();
        let link = ClientLink::default();
        assert!(link.claim());

        expire_waiter(&link, &stop, None, None);

        assert!(
            stop.cancel_requested(),
            "waiter expiry must cancel its own running request"
        );
        assert!(!link.claim(), "an expired request must not restart");
    }

    #[test]
    fn late_waiter_expiry_does_not_stop_the_next_owner() {
        let stop = CancelToken::new();
        let previous = ClientLink::default();
        assert!(previous.claim());
        previous.released();
        let next = ClientLink::default();
        assert!(next.claim());

        expire_waiter(&previous, &stop, None, None);

        assert!(
            !stop.stop_requested(),
            "late expiry must not stop the next job"
        );
        assert!(!previous.claim());
        assert!(matches!(*next.lock(), crate::ClientState::Running));
    }

    #[test]
    fn session_waiter_expiry_keeps_its_existing_cancellation() {
        for enrollment in [true, false] {
            let stop = CancelToken::new();
            let link = ClientLink::default();
            assert!(link.claim());
            let (_enrollment_worker, session) = if enrollment {
                let (worker, connection) = enrollment_session::channel(stop.clone());
                (Some(worker), Some(connection))
            } else {
                (None, None)
            };
            let (_position_worker, position) = if enrollment {
                (None, None)
            } else {
                let (worker, connection) = position_session::channel(stop.clone());
                (Some(worker), Some(connection))
            };

            expire_waiter(&link, &stop, session, position);

            assert!(stop.cancel_requested());
            assert!(!link.claim());
        }
    }

    #[test]
    fn available_reply_is_written_without_abandoning_its_request() {
        let stop = CancelToken::new();
        let link = ClientLink::default();
        assert!(link.claim());
        let (reply, answer) = mpsc::channel();
        assert!(reply.send(Response::Ok("ready".into()).into()).is_ok());
        let (server, client) = UnixStream::pair().unwrap();

        wait_and_respond(server, answer, &link, &stop, None, None, Instant::now()).unwrap();

        assert!(matches!(read_reply(client), Response::Ok(message) if message == "ready"));
        assert!(!stop.stop_requested());
        assert!(matches!(*link.lock(), crate::ClientState::Running));
    }

    #[test]
    fn session_event_is_written_before_an_already_available_reply() {
        let stop = CancelToken::new();
        let link = ClientLink::default();
        assert!(link.claim());
        let (worker, connection) = enrollment_session::channel(stop.clone());
        worker.started().unwrap();
        let (reply, answer) = mpsc::channel();
        assert!(reply.send(Response::Ok("ready".into()).into()).is_ok());
        let (server, client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        wait_and_respond(
            server,
            answer,
            &link,
            &stop,
            Some(connection),
            None,
            Instant::now(),
        )
        .unwrap();

        let mut reader = BufReader::new(client);
        assert!(matches!(
            read_response(&mut reader),
            Response::EnrollmentSession(irlume_common::EnrollmentEvent::Started)
        ));
        assert!(matches!(
            read_response(&mut reader),
            Response::Ok(message) if message == "ready"
        ));
        assert!(!stop.stop_requested());
        assert!(matches!(*link.lock(), crate::ClientState::Running));
    }
}
