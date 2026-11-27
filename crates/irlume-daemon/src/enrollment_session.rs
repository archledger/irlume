// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded interaction on one authorized enrollment connection.
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use irlume_auth::EnrollmentObserver;
use irlume_common::{EnrollmentDecision, EnrollmentEvent, FramingPosition, Response};

type FramingSlot = Arc<Mutex<Option<EnrollmentEvent>>>;

pub(super) struct Worker {
    events: SyncSender<EnrollmentEvent>,
    decisions: Receiver<bool>,
    stop: super::arbiter::CancelToken,
    deadline: Instant,
    framing: Option<FramingSlot>,
}

pub(super) struct Connection {
    events: Receiver<EnrollmentEvent>,
    decisions: SyncSender<bool>,
    waiting: bool,
    input: Vec<u8>,
    framing: Option<FramingSlot>,
    optional_tail: Vec<u8>,
}

#[cfg(test)]
pub(super) fn channel(stop: super::arbiter::CancelToken) -> (Worker, Connection) {
    channel_with_framing(stop, false)
}

pub(super) fn channel_with_framing(
    stop: super::arbiter::CancelToken,
    framing: bool,
) -> (Worker, Connection) {
    let (events, read_events) = mpsc::sync_channel(8);
    let (decisions, read_decisions) = mpsc::sync_channel(1);
    let framing = framing.then(|| Arc::new(Mutex::new(None)));
    (
        Worker {
            events,
            decisions: read_decisions,
            stop,
            deadline: Instant::now() + super::WORKER_REPLY_TIMEOUT,
            framing: framing.clone(),
        },
        Connection {
            events: read_events,
            decisions,
            waiting: false,
            input: Vec::new(),
            framing,
            optional_tail: Vec::new(),
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

    fn wants_framing(&self) -> bool {
        self.framing.is_some()
    }

    fn framing(&self, position: Option<FramingPosition>) {
        if self.check().is_err() {
            return;
        }
        if let Some(mut slot) = self.framing.as_ref().and_then(|slot| slot.try_lock().ok()) {
            let sampled_mono_ms = irlume_common::enrollment_monotonic_ms();
            *slot = sampled_mono_ms.map(|sampled_mono_ms| EnrollmentEvent::Framing {
                position: position.filter(|position| position.in_bounds()),
                sampled_mono_ms,
            });
        }
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
        self.pump_inner(stream, true)
    }

    pub(super) fn pump_final(&mut self, stream: &UnixStream) -> io::Result<()> {
        self.pump_inner(stream, false)
    }

    fn complete_optional_line(&mut self, mut stream: &UnixStream) -> io::Result<()> {
        if !self.optional_tail.is_empty() {
            stream.write_all(&self.optional_tail)?;
            self.optional_tail.clear();
        }
        Ok(())
    }

    fn pump_inner(&mut self, stream: &UnixStream, allow_optional: bool) -> io::Result<()> {
        if !allow_optional {
            self.complete_optional_line(stream)?;
        }
        while let Ok(event) = self.events.try_recv() {
            self.complete_optional_line(stream)?;
            if matches!(event, EnrollmentEvent::Merge { .. }) {
                if self.waiting {
                    return Err(io::Error::other("duplicate merge prompt"));
                }
                self.waiting = true;
                if let Some(mut slot) = self.framing.as_ref().and_then(|slot| slot.try_lock().ok())
                {
                    *slot = None;
                }
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
        if allow_optional && !self.waiting {
            self.pump_optional(stream);
        }
        Ok(())
    }

    fn pump_optional(&mut self, stream: &UnixStream) {
        if !self.optional_tail.is_empty() {
            let sent = try_write_optional(stream, &self.optional_tail);
            self.optional_tail.drain(..sent);
            return;
        }
        let sample = self
            .framing
            .as_ref()
            .and_then(|slot| slot.try_lock().ok())
            .and_then(|mut slot| slot.take());
        let Some(
            event @ EnrollmentEvent::Framing {
                sampled_mono_ms, ..
            },
        ) = sample
        else {
            return;
        };
        let Some(now) = irlume_common::enrollment_monotonic_ms() else {
            return;
        };
        if !irlume_common::enrollment_framing_is_fresh(sampled_mono_ms, now) {
            return;
        }
        if let Ok(mut line) = serde_json::to_vec(&Response::EnrollmentSession(event)) {
            line.push(b'\n');
            let sent = try_write_optional(stream, &line);
            if sent != 0 && sent < line.len() {
                self.optional_tail.extend_from_slice(&line[sent..]);
            }
        }
    }
}

fn try_write_optional(stream: &UnixStream, line: &[u8]) -> usize {
    // SAFETY: line is valid for the syscall; only this connection writes to
    // the socket. A full buffer drops new feedback instead of blocking.
    let sent = unsafe {
        libc::send(
            stream.as_raw_fd(),
            line.as_ptr().cast(),
            line.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    usize::try_from(sent).unwrap_or(0).min(line.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_framing_does_not_block_control_events() {
        use irlume_common::FramingPosition;
        use std::io::{BufRead, BufReader};

        let (worker, mut connection) =
            channel_with_framing(super::super::arbiter::CancelToken::new(), true);
        let (mut server, client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        worker.started().unwrap();
        for _ in 0..24 {
            worker.framing(None);
        }
        let expected = FramingPosition {
            x: 5,
            y: 4,
            size: 2,
        };
        worker.framing(Some(expected));
        worker.progress(1, 10).unwrap();
        connection.pump(&server).unwrap();
        let mut reader = BufReader::new(client);
        let mut event = || {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<Response>(&line).unwrap()
        };
        assert!(matches!(
            event(),
            Response::EnrollmentSession(EnrollmentEvent::Started)
        ));
        assert!(matches!(
            event(),
            Response::EnrollmentSession(EnrollmentEvent::Progress {
                captured: 1,
                target: 10
            })
        ));
        assert!(
            matches!(event(), Response::EnrollmentSession(EnrollmentEvent::Framing { position: Some(p), .. }) if p == expected)
        );

        // Deterministically model a short optional write, then drain a real
        // control event and prove both wire lines are still well-formed.
        server.write_all(b"{\"EnrollmentSession\":").unwrap();
        connection.optional_tail =
            b"{\"Framing\":{\"position\":null,\"sampled_mono_ms\":0}}}\n".to_vec();
        worker.progress(2, 10).unwrap();
        connection.pump_final(&server).unwrap();
        assert!(matches!(
            event(),
            Response::EnrollmentSession(EnrollmentEvent::Framing { position: None, .. })
        ));
        assert!(matches!(
            event(),
            Response::EnrollmentSession(EnrollmentEvent::Progress {
                captured: 2,
                target: 10
            })
        ));
        assert!(connection.optional_tail.is_empty());
    }

    #[test]
    fn enrollment_framing_requires_opt_in() {
        let (worker, mut connection) = channel(super::super::arbiter::CancelToken::new());
        worker.framing(None);
        assert!(!worker.wants_framing());
        let (server, mut client) = UnixStream::pair().unwrap();
        connection.pump(&server).unwrap();
        client.set_nonblocking(true).unwrap();
        use std::io::Read;
        assert_eq!(
            client.read(&mut [0_u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn enrollment_framing_is_disposable_when_the_socket_is_full() {
        use std::io::Read;
        let (worker, mut connection) =
            channel_with_framing(super::super::arbiter::CancelToken::new(), true);
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        server.set_nonblocking(true).unwrap();
        let mut filled = 0;
        let buffer = [0_u8; 4096];
        loop {
            match server.write(&buffer) {
                Ok(n) if n != 0 => filled += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                other => panic!("unexpected synthetic socket write: {other:?}"),
            }
            assert!(filled < 1_000_000, "synthetic socket did not fill");
        }
        worker.framing(None);
        connection.pump(&server).unwrap();
        assert!(connection.optional_tail.is_empty());
        worker.progress(2, 10).unwrap();
        client.read_exact(&mut vec![0; filled]).unwrap();
        server.set_nonblocking(false).unwrap();
        connection.pump(&server).unwrap();
        let expected = b"{\"EnrollmentSession\":{\"Progress\":{\"captured\":2,\"target\":10}}}\n";
        let mut progress = [0; 64];
        client.read_exact(&mut progress[..expected.len()]).unwrap();
        assert_eq!(expected, &progress[..expected.len()]);
    }

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
