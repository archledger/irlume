// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Trace-local lifetime and delivery bounds, separate from authentication I/O.
//!
//! Timeout scope: <https://man7.org/linux/man-pages/man7/socket.7.html>.
//! Retry semantics: <https://raw.githubusercontent.com/rust-lang/rust/1.88.0/library/std/src/io/mod.rs>.
//! Per-call nonblocking sends: <https://man7.org/linux/man-pages/man2/send.2.html>.

use crate::diagnostics::{DiagnosticState, TraceSubscribeError};
use irlume_common::diagnostics::{CategoricalOutcome, MAX_TRACE_LINE_BYTES};
use irlume_common::Response;
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

// Reuse the ordinary socket's 15-second allowance as one total grace, not a
// fresh allowance per record. It permits only already-admitted data/control.
const DELIVERY_GRACE: Duration = Duration::from_secs(15);
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// Serve one authorized, bounded observation and its bounded delivery phase.
///
/// # Errors
///
/// Returns socket, encoding, line-bound and delivery-timeout errors. A failed
/// transport may end on a partial line, never a fabricated terminal record.
pub(super) fn serve_trace(
    stream: UnixStream,
    diagnostic_state: &DiagnosticState,
    peer_uid: u32,
    duration_ms: u64,
    trace_schema: Option<u32>,
) -> io::Result<()> {
    serve_with_grace(
        stream,
        diagnostic_state,
        peer_uid,
        duration_ms,
        trace_schema,
        DELIVERY_GRACE,
    )
}

fn serve_with_grace(
    stream: UnixStream,
    diagnostic_state: &DiagnosticState,
    peer_uid: u32,
    duration_ms: u64,
    trace_schema: Option<u32>,
    grace: Duration,
) -> io::Result<()> {
    let subscription = match diagnostic_state.subscribe_trace(peer_uid, duration_ms, trace_schema) {
        Ok(subscription) => subscription,
        Err(TraceSubscribeError::NotRoot) => {
            return crate::respond(
                stream,
                &Response::Error(format!("trace record requires root (peer uid {peer_uid})")),
            );
        }
        Err(TraceSubscribeError::Busy) => {
            return crate::respond(
                stream,
                &Response::Error("a diagnostic trace is already active".into()),
            );
        }
        Err(TraceSubscribeError::UnsupportedSchema) => {
            return crate::respond(
                stream,
                &Response::Error("unsupported diagnostic trace schema".into()),
            );
        }
    };
    let observation_end = subscription.observation_deadline();
    let mut writer = DeadlineWriter {
        stream: &stream,
        deadline: observation_end + grace,
        // Never widen the caller's existing per-write timeout.
        per_write_limit: stream.write_timeout()?.unwrap_or(DELIVERY_GRACE),
    };
    write_json_line(
        &mut writer,
        &Response::TraceAccepted {
            limits: subscription.limits(),
        },
    )?;

    loop {
        if peer_gone(&stream)? {
            return Ok(());
        }
        let remaining = observation_end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match subscription.recv_timeout(remaining.min(IDLE_CHECK_INTERVAL)) {
            Ok(record) => write_json_line(&mut writer, &record)?,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // Close admission before draining all already-sequenced records, followed
    // by drop/terminal controls. The same delivery deadline covers every byte.
    let terminal = subscription.finish(CategoricalOutcome::Completed);
    while let Ok(record) = subscription.recv_timeout(Duration::ZERO) {
        write_json_line(&mut writer, &record)?;
    }
    for record in terminal {
        write_json_line(&mut writer, &record)?;
    }
    writer.flush()
}

fn peer_gone(stream: &UnixStream) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    // SAFETY: descriptor is initialized and exclusive; stream keeps its fd
    // alive. Zero-timeout poll cannot block and does not consume input.
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(error)
        };
    }
    // POLLRDHUP alone is a legitimate one-shot client's write-half-close.
    // HUP/ERR/NVAL are reported even with events=0, including buffered input.
    // AF_UNIX distinguishes these in unix_poll (also pinned by socket tests):
    // https://raw.githubusercontent.com/torvalds/linux/v7.2/net/unix/af_unix.c
    Ok(descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
}

struct DeadlineWriter<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
    per_write_limit: Duration,
}

impl io::Write for DeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let per_write_end = Instant::now()
            .checked_add(self.per_write_limit)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        loop {
            if Instant::now() >= per_write_end {
                return Err(delivery_timeout());
            }
            // A blocking AF_UNIX send can refresh SO_SNDTIMEO for each kernel
            // chunk while a reader progresses. Per-call DONTWAIT keeps that
            // wait out of the syscall without changing shared descriptor flags.
            // SAFETY: stream owns the live fd; bytes is a valid immutable slice
            // throughout send, and flags neither consume input nor send SIGPIPE.
            let sent = unsafe {
                libc::send(
                    self.stream.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent >= 0 {
                return usize::try_from(sent).map_err(io::Error::other);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => self.wait_writable(per_write_end)?,
                _ => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.stream).flush()
    }
}

impl DeadlineWriter<'_> {
    fn wait_writable(&self, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(delivery_timeout());
            }
            let milliseconds = remaining.as_millis();
            let rounded_up = if remaining.subsec_nanos() % 1_000_000 == 0 {
                milliseconds
            } else {
                milliseconds.saturating_add(1)
            };
            let timeout = libc::c_int::try_from(rounded_up).unwrap_or(libc::c_int::MAX);
            let mut descriptor = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: descriptor is initialized/exclusive and stream keeps its
            // fd alive. Poll rounds to milliseconds; send rechecks the absolute
            // end before retrying, so readiness cannot extend the byte budget.
            let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "diagnostic trace peer disconnected",
                ));
            }
            if descriptor.revents & libc::POLLOUT != 0 {
                return Ok(());
            }
            // Timeout/spurious readiness rechecks the same end, never now+grace.
        }
    }
}

fn delivery_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "diagnostic trace delivery timed out",
    )
}

fn write_json_line<T: serde::Serialize>(
    writer: &mut DeadlineWriter<'_>,
    value: &T,
) -> io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > MAX_TRACE_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "diagnostic trace line exceeds its bound",
        ));
    }
    writer.write_all(&line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::TraceSubscribeError;
    use irlume_common::diagnostics::{
        DiagnosticSink as _, OperationClass, TraceEventKind, TraceRecord, TraceStage,
        CURRENT_TRACE_SCHEMA_VERSION,
    };
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::net::Shutdown;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};

    fn small_pair() -> (UnixStream, UnixStream) {
        let (server, client) = UnixStream::pair().unwrap();
        let bytes: libc::c_int = 4096;
        let length = libc::socklen_t::try_from(std::mem::size_of_val(&bytes)).unwrap();
        // SAFETY: server owns the descriptor and bytes is initialized; its
        // pointer and exact length remain valid throughout this call.
        let result = unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::addr_of!(bytes).cast(),
                length,
            )
        };
        assert_eq!(result, 0);
        server
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        (server, client)
    }

    #[test]
    fn full_hangup_with_buffered_input_is_not_a_write_half_close() {
        const NAME: &str =
            "trace_stream::tests::full_hangup_with_buffered_input_is_not_a_write_half_close";
        if crate::test_support::isolated(NAME) {
            return;
        }
        let (server, mut client) = small_pair();
        client.write_all(b"unconsumed fixture input").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(!peer_gone(&server).unwrap());
        client.shutdown(Shutdown::Both).unwrap();
        drop(client);
        assert!(peer_gone(&server).unwrap());
    }

    #[test]
    fn jsonl_line_bound_includes_the_newline_before_any_write() {
        let (server, mut client) = small_pair();
        let mut writer = DeadlineWriter {
            stream: &server,
            deadline: Instant::now() + Duration::from_secs(1),
            per_write_limit: Duration::from_millis(250),
        };
        // JSON quotes fit exactly at the payload bound; the newline would not.
        let content = "x".repeat(MAX_TRACE_LINE_BYTES - 2);
        assert_eq!(
            write_json_line(&mut writer, &content).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        client.set_nonblocking(true).unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(
            client.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn trickling_progress_does_not_restart_the_delivery_deadline() {
        const NAME: &str =
            "trace_stream::tests::trickling_progress_does_not_restart_the_delivery_deadline";
        if crate::test_support::isolated(NAME) {
            return;
        }
        let (server, mut client) = small_pair();
        client
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicUsize::new(0));
        let reader_stop = stopped.clone();
        let reader_count = received.clone();
        let reader = std::thread::spawn(move || {
            let mut buffer = [0_u8; 128];
            while !reader_stop.load(Ordering::Acquire) {
                match client.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        reader_count.fetch_add(count, Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => panic!("fixture reader failed: {error}"),
                }
            }
        });
        let started = Instant::now();
        let result = {
            let mut writer = DeadlineWriter {
                stream: &server,
                deadline: started + Duration::from_millis(120),
                per_write_limit: Duration::from_millis(250),
            };
            writer.write_all(&vec![b'x'; MAX_TRACE_LINE_BYTES])
        };
        let elapsed = started.elapsed();
        stopped.store(true, Ordering::Release);
        drop(server);
        reader.join().unwrap();
        assert!(
            received.load(Ordering::Relaxed) > 0,
            "fixture made no partial progress"
        );
        assert!(
            matches!(&result, Err(error) if error.kind() == io::ErrorKind::TimedOut),
            "fixed delivery budget not enforced: result={result:?}, elapsed={elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "progress reset the fixed budget: {elapsed:?}"
        );
    }

    #[test]
    fn a_non_reading_transport_has_a_fixed_end_without_blocking_a_replacement() {
        const NAME: &str = "trace_stream::tests::a_non_reading_transport_has_a_fixed_end_without_blocking_a_replacement";
        if crate::test_support::isolated(NAME) {
            return;
        }
        let state = DiagnosticState::default();
        let operation = state.begin(OperationClass::Status);
        let server_state = state.clone();
        let (socket, client) = small_pair();
        let (completed, completion) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let result = serve_with_grace(
                socket,
                &server_state,
                0,
                50,
                Some(CURRENT_TRACE_SCHEMA_VERSION),
                Duration::from_millis(100),
            );
            let _ = completed.send(());
            result
        });
        let mut client = BufReader::new(client);
        let mut line = String::new();
        client.read_line(&mut line).unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&line).unwrap(),
            Response::TraceAccepted { .. }
        ));
        line.clear();
        client.read_line(&mut line).unwrap();
        assert!(matches!(
            serde_json::from_str::<TraceRecord>(&line).unwrap().event,
            TraceEventKind::TraceStarted { .. }
        ));
        for _ in 0..64 {
            operation.emit_trace(TraceEventKind::StageTiming {
                stage: TraceStage::IdentityInference,
                elapsed_us: 1,
            });
        }
        std::thread::sleep(Duration::from_millis(80));
        let replacement = state.subscribe_trace(0, 2_000, Some(CURRENT_TRACE_SCHEMA_VERSION));
        let ended_within_budget = completion.recv_timeout(Duration::from_millis(500)).is_ok();
        let _ = client.get_ref().shutdown(Shutdown::Both);
        drop(client);
        let result = server.join().unwrap();
        let replacement =
            replacement.expect("expired collection must not retain the slot while draining");
        assert!(
            ended_within_budget,
            "stalled delivery outlived its fixed grace"
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(matches!(
            state.subscribe_trace(0, 2_000, Some(CURRENT_TRACE_SCHEMA_VERSION)),
            Err(TraceSubscribeError::Busy)
        ));
        drop(replacement);
    }
}
