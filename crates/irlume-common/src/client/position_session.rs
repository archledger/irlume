// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::{PositionReport, PositionSessionControl, Request, Response};

/// One explicitly paced framing connection. Call [`Self::finish`] before
/// enrollment authorization to confirm release of the camera. Drop cancels.
pub struct PositionSession {
    stream: UnixStream,
    deadline: Instant,
    samples: usize,
}

impl PositionSession {
    /// Start a framing session. `None` means an older daemon rejected the new
    /// request with its exact pre-acceptance `bad request` response.
    ///
    /// # Errors
    /// Returns transport, cancellation, deadline or protocol errors. All other
    /// daemon refusals are errors and must not trigger compatibility fallback.
    pub fn connect(user: &str, cancelled: &AtomicBool) -> io::Result<Option<Self>> {
        let stream = super::connect_stream(Duration::from_millis(100))?;
        let mut session = Self {
            stream,
            deadline: Instant::now() + Duration::from_secs(crate::POSITION_SESSION_SECONDS + 5),
            samples: 0,
        };
        session.check(cancelled)?;
        (&session.stream).write_all(&super::serialize_request(&Request::PositionSession {
            user: Some(user.to_owned()),
        })?)?;
        match session.reply(cancelled)? {
            Response::PositionSessionStarted => Ok(Some(session)),
            Response::Error(error) if error == "bad request" => Ok(None),
            Response::Error(error) => Err(io::Error::other(error)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected framing-session reply",
            )),
        }
    }

    /// Ask for a newly computed report from the continuously drained stream.
    ///
    /// # Errors
    /// Returns transport, cancellation, bounded-session or daemon errors. A
    /// failed accepted session is never retried as a one-shot request.
    pub fn sample(&mut self, cancelled: &AtomicBool) -> io::Result<PositionReport> {
        self.check(cancelled)?;
        if self.samples >= crate::POSITION_SESSION_MAX_SAMPLES {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "framing sample limit reached",
            ));
        }
        self.samples += 1;
        let mut line = serde_json::to_vec(&PositionSessionControl::Sample)?;
        line.push(b'\n');
        (&self.stream).write_all(&line)?;
        match self.reply(cancelled)? {
            Response::Position(report) => Ok(report),
            Response::Error(error) => Err(io::Error::other(error)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected framing sample reply",
            )),
        }
    }

    /// End the guide and wait until the daemon has released the camera slot.
    /// Merely dropping a socket would race the next enrollment request against
    /// the daemon's disconnect polling.
    ///
    /// # Errors
    /// Returns cancellation, deadline, transport or unexpected-reply errors.
    /// A failure must stop the guide rather than begin enrollment anyway.
    pub fn finish(mut self, cancelled: &AtomicBool) -> io::Result<()> {
        self.check(cancelled)?;
        let mut line = serde_json::to_vec(&PositionSessionControl::Finish)?;
        line.push(b'\n');
        (&self.stream).write_all(&line)?;
        match self.reply(cancelled)? {
            Response::PositionSessionEnded => Ok(()),
            Response::Error(error) => Err(io::Error::other(error)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "camera release was not confirmed",
            )),
        }
    }

    fn check(&self, cancelled: &AtomicBool) -> io::Result<()> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "framing cancelled",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "framing session expired",
            ));
        }
        Ok(())
    }

    fn reply(&mut self, cancelled: &AtomicBool) -> io::Result<Response> {
        let mut reader = super::CancellableReply {
            stream: &self.stream,
            cancelled,
            deadline: self.deadline.min(Instant::now() + Duration::from_secs(10)),
        };
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            let read = reader.read(&mut chunk[..])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "framing connection closed",
                ));
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() as u64 >= super::MAX_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized framing reply",
                ));
            }
            if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
                // One credit permits exactly one reply, never a queue of old
                // reports for future countdown beats.
                if end + 1 != bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsolicited framing replies",
                    ));
                }
                return serde_json::from_slice(bytes.trim_ascii())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_session() -> (PositionSession, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        (
            PositionSession {
                stream,
                deadline: Instant::now() + Duration::from_secs(2),
                samples: 0,
            },
            peer,
        )
    }

    #[test]
    fn cancellation_expiry_and_sample_cap_do_not_send_another_command() {
        for condition in 0..3 {
            let (mut session, mut peer) = local_session();
            let stop = AtomicBool::new(condition == 0);
            if condition == 1 {
                session.deadline = Instant::now();
            }
            if condition == 2 {
                session.samples = crate::POSITION_SESSION_MAX_SAMPLES;
            }
            assert!(session.sample(&stop).is_err());
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.read(&mut [0u8; 64]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn malformed_truncated_and_unsolicited_replies_are_refused() {
        use std::io::BufRead;
        let reply = serde_json::to_string(&Response::Position(PositionReport::default())).unwrap();
        let fixtures = [
            (b"not json\n".to_vec(), io::ErrorKind::InvalidData),
            (reply.as_bytes().to_vec(), io::ErrorKind::UnexpectedEof),
            (
                format!("{reply}\n{reply}\n").into_bytes(),
                io::ErrorKind::InvalidData,
            ),
            (
                vec![b'x'; super::super::MAX_RESPONSE_BYTES as usize],
                io::ErrorKind::InvalidData,
            ),
        ];
        for (bytes, expected) in fixtures {
            let (mut session, mut peer) = local_session();
            let server = std::thread::spawn(move || {
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&peer).read_line(&mut line).unwrap();
                assert_eq!(line, "\"Sample\"\n");
                peer.write_all(&bytes).unwrap();
            });
            let result = session.sample(&AtomicBool::new(false));
            server.join().unwrap();
            assert_eq!(result.unwrap_err().kind(), expected);
        }
    }

    #[test]
    fn finish_requires_the_release_acknowledgment() {
        use std::io::BufRead;
        for acknowledged in [true, false] {
            let (session, mut peer) = local_session();
            let server = std::thread::spawn(move || {
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&peer).read_line(&mut line).unwrap();
                assert_eq!(line, "\"Finish\"\n");
                peer.write_all(if acknowledged {
                    b"\"PositionSessionEnded\"\n"
                } else {
                    b"{\"Ok\":\"not released\"}\n"
                })
                .unwrap();
                assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
            });
            assert_eq!(
                session.finish(&AtomicBool::new(false)).is_ok(),
                acknowledged
            );
            server.join().unwrap();
        }
    }
}
