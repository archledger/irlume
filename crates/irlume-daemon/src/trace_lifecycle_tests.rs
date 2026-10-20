// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic lifecycle regressions: no engine, devices or installed daemon.

use super::{diagnostics::DiagnosticState, serve_trace};
use irlume_common::diagnostics::{
    DiagnosticSink as _, OperationClass, TraceEventKind, TraceRecord, TraceStage,
    CURRENT_TRACE_SCHEMA_VERSION,
};
use irlume_common::Response;
use std::io::{BufRead as _, BufReader, Read as _};
use std::net::Shutdown;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn an_idle_disconnected_socket_releases_the_single_trace_slot_promptly() {
    const NAME: &str =
        "trace_lifecycle_tests::an_idle_disconnected_socket_releases_the_single_trace_slot_promptly";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let state = DiagnosticState::default();
    let server_state = state.clone();
    let (socket, client) = UnixStream::pair().unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (completed, completion) = mpsc::channel();
    let server = std::thread::spawn(move || {
        // Fixture UID0 exercises the existing trace endpoint, not OS elevation.
        let result = serve_trace(
            socket,
            &server_state,
            0,
            10_000,
            Some(CURRENT_TRACE_SCHEMA_VERSION),
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
    let disconnected = Instant::now();
    client.get_ref().shutdown(Shutdown::Both).unwrap();
    drop(client);

    let exited_without_a_new_event = completion.recv_timeout(Duration::from_millis(750)).is_ok();
    let observed_idle_wait = disconnected.elapsed();
    let replacement_before_rescue = state
        .subscribe_trace(0, 1, Some(CURRENT_TRACE_SCHEMA_VERSION))
        .is_ok();
    if !exited_without_a_new_event {
        // Force a failed write only for bounded cleanup. This must not count as
        // successful idle-disconnect detection or leave a detached fixture.
        let operation = state.begin(OperationClass::Status);
        operation.emit_trace(TraceEventKind::StageTiming {
            stage: TraceStage::IdentityInference,
            elapsed_us: 1,
        });
    }
    let result = server.join().unwrap();
    let replacement_available = state
        .subscribe_trace(0, 1, Some(CURRENT_TRACE_SCHEMA_VERSION))
        .is_ok();
    assert!(
        exited_without_a_new_event && replacement_before_rescue,
        "idle disconnect retained the trace for {observed_idle_wait:?}; replacement before rescue={replacement_before_rescue}; rescue result {result:?}"
    );
    assert!(replacement_available);
}

#[test]
fn an_expired_subscription_refuses_new_producer_observations() {
    let state = DiagnosticState::default();
    let operation = state.begin(OperationClass::Status);
    let subscription = state
        .subscribe_trace(0, 1, Some(CURRENT_TRACE_SCHEMA_VERSION))
        .unwrap();
    assert!(matches!(
        subscription.recv_timeout(Duration::ZERO).unwrap().event,
        TraceEventKind::TraceStarted { .. }
    ));
    std::thread::sleep(Duration::from_millis(20));
    operation.emit_trace(TraceEventKind::StageTiming {
        stage: TraceStage::IdentityInference,
        elapsed_us: 424_242,
    });
    let mut late = Vec::new();
    while let Ok(record) = subscription.recv_timeout(Duration::ZERO) {
        if !record.terminal {
            late.push(record);
        }
    }
    assert!(
        late.is_empty(),
        "a nonterminal observation crossed the {} ms boundary: {late:?}",
        subscription.limits().duration_ms
    );
}

#[test]
fn a_write_half_closed_client_still_receives_a_complete_trace() {
    const NAME: &str =
        "trace_lifecycle_tests::a_write_half_closed_client_still_receives_a_complete_trace";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let state = DiagnosticState::default();
    let (socket, mut client) = UnixStream::pair().unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let server = std::thread::spawn(move || {
        serve_trace(socket, &state, 0, 1, Some(CURRENT_TRACE_SCHEMA_VERSION))
    });
    let mut payload = String::new();
    let read_result = client.read_to_string(&mut payload);
    drop(client);
    let result = server.join().unwrap();
    assert!(read_result.is_ok(), "{read_result:?}");
    assert!(result.is_ok(), "{result:?}");
    let (header, trace) = payload.split_once('\n').unwrap();
    let Response::TraceAccepted { limits } = serde_json::from_str(header).unwrap() else {
        panic!("expected trace acceptance");
    };
    let parsed =
        irlume_common::diagnostics::parse_trace(BufReader::new(trace.as_bytes()), limits).unwrap();
    assert!(matches!(
        parsed.records()[0].event,
        TraceEventKind::TraceStarted { .. }
    ));
    assert!(parsed.records().last().unwrap().terminal);
}

#[test]
fn socket_backpressure_does_not_extend_the_observation_window() {
    const NAME: &str =
        "trace_lifecycle_tests::socket_backpressure_does_not_extend_the_observation_window";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let state = DiagnosticState::default();
    let operation = state.begin(OperationClass::Status);
    let server_state = state.clone();
    let (socket, client) = UnixStream::pair().unwrap();
    let send_buffer: libc::c_int = 4096;
    let option_len = libc::socklen_t::try_from(std::mem::size_of_val(&send_buffer)).unwrap();
    // SAFETY: socket owns the descriptor; send_buffer is initialized and its
    // pointer and exact size remain valid for this synchronous setsockopt call.
    let option_result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::addr_of!(send_buffer).cast(),
            option_len,
        )
    };
    assert_eq!(option_result, 0);
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let witness = socket.try_clone().unwrap();
    let (completed, completion) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let result = serve_trace(
            socket,
            &server_state,
            0,
            200,
            Some(CURRENT_TRACE_SCHEMA_VERSION),
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
    let startup_line = line.clone();
    // Fill the socket while leaving ample room in the 1024-record queue.
    for _ in 0..64 {
        operation.emit_trace(TraceEventKind::StageTiming {
            stage: TraceStage::IdentityInference,
            elapsed_us: 1,
        });
    }
    let setup_deadline = Instant::now() + Duration::from_millis(100);
    let mut blocked = false;
    while Instant::now() < setup_deadline {
        let mut descriptor = libc::pollfd {
            fd: witness.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: descriptor is one initialized pollfd, witness keeps its fd
        // alive, and a zero timeout never blocks or consumes socket data.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        assert!(ready >= 0);
        if ready == 0 {
            blocked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(300));
    let handler_waiting_after_window =
        matches!(completion.try_recv(), Err(mpsc::TryRecvError::Empty));
    operation.emit_trace(TraceEventKind::StageTiming {
        stage: TraceStage::IdentityInference,
        elapsed_us: 424_242,
    });
    // The witness must not hold the server endpoint open during EOF draining.
    drop(witness);
    let mut payload = String::new();
    let read_result = client.read_to_string(&mut payload);
    let _ = client.get_ref().shutdown(Shutdown::Both);
    drop(client);
    let result = server.join().unwrap();
    assert!(blocked, "fixture never established socket backpressure");
    assert!(
        read_result.is_ok(),
        "fixture drain failed: {read_result:?}; server={result:?}"
    );
    // Reading resumes within both grace and the caller's timeout, so previously
    // admitted records must still form a complete, contiguous trace.
    assert!(result.is_ok(), "{result:?}");
    let complete = startup_line + &payload;
    let parsed = irlume_common::diagnostics::parse_trace(
        BufReader::new(complete.as_bytes()),
        irlume_common::diagnostics::TraceLimits::bounded(200),
    )
    .unwrap();
    assert!(parsed.records().last().unwrap().terminal);
    let late: Vec<_> = parsed
        .records()
        .iter()
        .filter(|record| {
            matches!(
                record.event,
                TraceEventKind::StageTiming {
                    elapsed_us: 424_242,
                    ..
                }
            )
        })
        .collect();
    assert!(
        late.is_empty(),
        "late observations crossed the 200ms socket window; handler_waiting={handler_waiting_after_window}: {late:?}"
    );
}
