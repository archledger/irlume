// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded interaction on one authorized enrollment connection.
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

use irlume_auth::EnrollmentObserver;
use irlume_common::{EnrollmentDecision, EnrollmentEvent, Response};

pub(super) struct Worker {
    events: SyncSender<EnrollmentEvent>,
    decisions: Receiver<bool>,
    stop: super::arbiter::CancelToken,
    deadline: Instant,
}

pub(super) struct Connection {
    events: Receiver<EnrollmentEvent>,
    decisions: SyncSender<bool>,
    waiting: bool,
    input: Vec<u8>,
}

pub(super) fn channel(stop: super::arbiter::CancelToken) -> (Worker, Connection) {
    let (events, read_events) = mpsc::sync_channel(8);
    let (decisions, read_decisions) = mpsc::sync_channel(1);
    (
        Worker {
            events,
            decisions: read_decisions,
            stop,
            deadline: Instant::now() + super::WORKER_REPLY_TIMEOUT,
        },
        Connection {
            events: read_events,
            decisions,
            waiting: false,
            input: Vec::new(),
        },
    )
}

fn stopped() -> irlume_common::Error {
    irlume_common::Error::Preempted("enrollment stopped; pending scans were not saved".into())
}

impl Worker {
    pub(super) fn started(&self) -> irlume_common::Result<()> {
        self.send(EnrollmentEvent::Started)
    }

    fn send(&self, event: EnrollmentEvent) -> irlume_common::Result<()> {
        self.check()?;
        self.events.try_send(event).map_err(|_| stopped())
    }
}

impl EnrollmentObserver for Worker {
    fn check(&self) -> irlume_common::Result<()> {
        if self.stop.stop_requested() || Instant::now() >= self.deadline {
            Err(stopped())
        } else {
            Ok(())
        }
    }

    fn progress(&self, captured: usize, target: usize) -> irlume_common::Result<()> {
        self.send(EnrollmentEvent::Progress { captured, target })
    }

    fn confirm_merge(&self, profile: &str, remaining: usize) -> irlume_common::Result<()> {
        self.send(EnrollmentEvent::Merge {
            profile: profile.into(),
            remaining,
        })?;
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(60));
        loop {
            self.check()?;
            if Instant::now() >= deadline {
                return Err(stopped());
            }
            match self.decisions.recv_timeout(Duration::from_millis(100)) {
                Ok(true) => return self.check(),
                Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => return Err(stopped()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

impl Connection {
    /// Only the connection thread writes to the socket. A slow reader cannot
    /// hold the camera worker in a write syscall.
    pub(super) fn pump(&mut self, stream: &UnixStream) -> io::Result<()> {
        while let Ok(event) = self.events.try_recv() {
            if matches!(event, EnrollmentEvent::Merge { .. }) {
                if self.waiting {
                    return Err(io::Error::other("duplicate merge prompt"));
                }
                self.waiting = true;
            }
            let mut line = serde_json::to_vec(&Response::EnrollmentSession(event))?;
            line.push(b'\n');
            (&*stream).write_all(&line)?;
        }
        if self.waiting {
            let mut bytes = [0u8; 64];
            // SAFETY: stream is a live fd and bytes is writable for its full
            // length. MSG_DONTWAIT affects this receive only.
            let n = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    return Ok(());
                }
                return Err(error);
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "enrollment client left",
                ));
            }
            self.input.extend_from_slice(&bytes[..n as usize]);
            if self.input.len() > 64 {
                return Err(io::Error::other("oversized enrollment decision"));
            }
            if let Some(end) = self.input.iter().position(|b| *b == b'\n') {
                if end + 1 != self.input.len() {
                    return Err(io::Error::other("extra enrollment decision data"));
                }
                let answer: EnrollmentDecision = serde_json::from_slice(&self.input[..end])?;
                self.decisions
                    .try_send(answer.accept)
                    .map_err(|_| io::Error::other("enrollment no longer awaits a decision"))?;
                self.input.clear();
                self.waiting = false;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_decline_and_authentication_preemption_end_the_wait() {
        for accept in [false, true] {
            let stop = super::super::arbiter::CancelToken::new();
            let (worker, connection) = channel(stop.clone());
            if accept {
                stop.request_stop();
            }
            connection.decisions.send(accept).unwrap();
            assert!(worker.confirm_merge("Existing", 9).is_err());
        }
    }

    #[test]
    fn expired_operation_and_full_event_queue_refuse_further_work() {
        let (mut worker, _connection) = channel(super::super::arbiter::CancelToken::new());
        for _ in 0..8 {
            worker.progress(1, 10).unwrap();
        }
        assert!(worker.progress(2, 10).is_err());
        worker.deadline = Instant::now();
        assert!(worker.check().is_err());
    }

    #[test]
    fn extra_decision_fields_are_not_accepted() {
        let (worker, mut connection) = channel(super::super::arbiter::CancelToken::new());
        let (server, mut client) = UnixStream::pair().unwrap();
        worker
            .send(EnrollmentEvent::Merge {
                profile: "Existing".into(),
                remaining: 9,
            })
            .unwrap();
        client
            .write_all(b"{\"accept\":true,\"user\":\"other\"}\n")
            .unwrap();
        assert!(connection.pump(&server).is_err());
        assert!(worker.decisions.try_recv().is_err());
    }
}
