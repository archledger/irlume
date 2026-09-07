// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! One bounded, explicitly paced framing connection. Socket writes belong to
//! the connection thread; the camera worker only uses nonblocking channels.
use std::cell::Cell;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

use irlume_auth::PositionObserver;
use irlume_common::{PositionReport, PositionSessionControl, Response};

pub(super) struct Worker {
    commands: Receiver<PositionSessionControl>,
    events: SyncSender<Response>,
    stop: super::arbiter::CancelToken,
    deadline: Instant,
    pending: Cell<bool>,
    processing: Cell<bool>,
    next_sample: Cell<Instant>,
}

pub(super) struct Connection {
    commands: SyncSender<PositionSessionControl>,
    events: Receiver<Response>,
    input: Vec<u8>,
    waiting: bool,
    finishing: bool,
}

pub(super) fn channel(stop: super::arbiter::CancelToken) -> (Worker, Connection) {
    let (commands, requests) = mpsc::sync_channel(1);
    let (events, replies) = mpsc::sync_channel(1);
    let now = Instant::now();
    (
        Worker {
            commands: requests,
            events,
            stop,
            deadline: now + Duration::from_secs(irlume_common::POSITION_SESSION_SECONDS),
            pending: Cell::new(false),
            processing: Cell::new(false),
            next_sample: Cell::new(now),
        },
        Connection {
            commands,
            events: replies,
            input: Vec::new(),
            waiting: false,
            finishing: false,
        },
    )
}

fn stopped() -> irlume_common::Error {
    irlume_common::Error::Preempted("framing stopped; restart the guide".into())
}

impl Worker {
    fn check(&self) -> irlume_common::Result<()> {
        if self.stop.stop_requested() || Instant::now() >= self.deadline {
            Err(stopped())
        } else {
            Ok(())
        }
    }

    pub(super) fn started(&self) -> irlume_common::Result<()> {
        self.check()?;
        self.events
            .try_send(Response::PositionSessionStarted)
            .map_err(|_| stopped())
    }
}

impl PositionObserver for Worker {
    fn next(&self) -> irlume_common::Result<Option<PositionSessionControl>> {
        self.check()?;
        match self.commands.try_recv() {
            Ok(PositionSessionControl::Finish) => return Ok(Some(PositionSessionControl::Finish)),
            Ok(PositionSessionControl::Sample) => {
                if self.pending.replace(true) || self.processing.get() {
                    return Err(stopped());
                }
            }
            Err(TryRecvError::Disconnected) => return Err(stopped()),
            Err(TryRecvError::Empty) => {}
        }
        if self.pending.get() && Instant::now() >= self.next_sample.get() {
            self.pending.set(false);
            self.processing.set(true);
            Ok(Some(PositionSessionControl::Sample))
        } else {
            Ok(None)
        }
    }

    fn report(&self, report: PositionReport) -> irlume_common::Result<()> {
        self.check()?;
        if !self.processing.replace(false) {
            return Err(stopped());
        }
        self.events
            .try_send(Response::Position(report))
            .map_err(|_| stopped())?;
        self.next_sample
            .set(Instant::now() + Duration::from_millis(250));
        Ok(())
    }
}

impl Connection {
    pub(super) fn pump(&mut self, stream: &UnixStream) -> io::Result<()> {
        while let Ok(event) = self.events.try_recv() {
            if matches!(event, Response::Position(_)) {
                if !self.waiting || self.finishing {
                    return Err(io::Error::other("unsolicited framing report"));
                }
                self.waiting = false;
            }
            let mut line = serde_json::to_vec(&event)?;
            line.push(b'\n');
            (&*stream).write_all(&line)?;
        }
        let mut bytes = [0u8; 64];
        // SAFETY: stream owns a live descriptor and bytes is writable for its
        // full length. MSG_DONTWAIT affects this call only.
        let read = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(())
            } else {
                Err(error)
            };
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "framing client left",
            ));
        }
        self.input.extend_from_slice(&bytes[..read as usize]);
        if self.input.len() > 64 {
            return Err(io::Error::other("oversized framing command"));
        }
        if let Some(end) = self.input.iter().position(|b| *b == b'\n') {
            if self.waiting || self.finishing || end + 1 != self.input.len() {
                return Err(io::Error::other("extra framing command"));
            }
            let command: PositionSessionControl = serde_json::from_slice(&self.input[..end])?;
            self.finishing = matches!(command, PositionSessionControl::Finish);
            self.waiting = true;
            self.commands
                .try_send(command)
                .map_err(|_| io::Error::other("framing is no longer waiting"))?;
            self.input.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_report_needs_a_credit_and_finish_does_not_wait_for_sample_pacing() {
        let (worker, mut connection) = channel(super::super::arbiter::CancelToken::new());
        let (server, mut client) = UnixStream::pair().unwrap();
        assert!(worker.report(PositionReport::default()).is_err());
        client.write_all(b"\"Sample\"\n").unwrap();
        connection.pump(&server).unwrap();
        assert!(matches!(
            worker.next().unwrap(),
            Some(PositionSessionControl::Sample)
        ));
        worker.report(PositionReport::default()).unwrap();
        connection.pump(&server).unwrap();
        assert!(worker.next().unwrap().is_none());
        client.write_all(b"\"Finish\"\n").unwrap();
        connection.pump(&server).unwrap();
        assert!(matches!(
            worker.next().unwrap(),
            Some(PositionSessionControl::Finish)
        ));
    }

    #[test]
    fn expired_preempted_and_disconnected_framing_cannot_request_another_frame() {
        for condition in 0..3 {
            let stop = super::super::arbiter::CancelToken::new();
            let (mut worker, connection) = channel(stop.clone());
            match condition {
                0 => worker.deadline = Instant::now(),
                1 => stop.request_stop(),
                _ => drop(connection),
            }
            assert!(worker.next().is_err());
        }
    }

    #[test]
    fn framing_rejects_pipelined_or_unknown_commands() {
        for input in [
            b"\"Sample\"\n\"Sample\"\n".as_slice(),
            b"{\"Sample\":{\"user\":\"other\"}}\n",
            b"\"Unknown\"\n",
        ] {
            let (_worker, mut connection) = channel(super::super::arbiter::CancelToken::new());
            let (server, mut client) = UnixStream::pair().unwrap();
            client.write_all(input).unwrap();
            assert!(connection.pump(&server).is_err());
        }
    }
}
