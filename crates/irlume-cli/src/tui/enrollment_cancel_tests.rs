// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#[test]
fn enrollment_cancel_before_guidance_skips_sampling() {
    let stop = AtomicBool::new(true);
    let outcome = guide_until_capture(
        "test-user",
        &stop,
        &|_| panic!("cancelled guidance must not emit a message"),
        &mut |_| panic!("cancelled guidance must not sample"),
        &mut 0,
    );
    assert!(matches!(outcome, GuideOutcome::Halt));
}

#[test]
fn enrollment_cancel_during_framing_emits_no_late_cue() {
    let stop = AtomicBool::new(false);
    let sent = std::cell::Cell::new(0);
    let outcome = guide_until_capture(
        "test-user",
        &stop,
        &|_| {
            sent.set(sent.get() + 1);
            true
        },
        &mut |_| {
            stop.store(true, Ordering::Relaxed);
            Ok(Response::Position(good_report("hold still")))
        },
        &mut 0,
    );
    assert!(matches!(outcome, GuideOutcome::Halt));
    assert_eq!(sent.get(), 0);
}

#[test]
fn enrollment_cancel_during_final_sample_does_not_admit_capture() {
    let stop = AtomicBool::new(false);
    let mut samples = 0;
    let outcome = guide_until_capture(
        "test-user",
        &stop,
        &|_| true,
        &mut |_| {
            samples += 1;
            if samples == GOOD_STREAK + 3 {
                stop.store(true, Ordering::Relaxed);
            }
            Ok(Response::Position(good_report("hold still")))
        },
        &mut 0,
    );
    assert_eq!(samples, GOOD_STREAK + 3);
    assert!(matches!(outcome, GuideOutcome::Halt));
}

#[test]
fn enrollment_cancel_during_countdown_skips_the_next_sample() {
    let stop = AtomicBool::new(false);
    let mut samples = 0;
    let outcome = guide_until_capture(
        "test-user",
        &stop,
        &|message| {
            if matches!(message, WMsg::Count(_)) {
                stop.store(true, Ordering::Relaxed);
            }
            true
        },
        &mut |_| {
            samples += 1;
            Ok(Response::Position(good_report("hold still")))
        },
        &mut 0,
    );
    assert!(matches!(outcome, GuideOutcome::Halt));
    assert_eq!(samples, GOOD_STREAK);
}

// Exercise the real worker, both compatibility refusals and the socket client.
// The endpoint cancels during the final legacy sample, before replying, just
// as Esc sets the stop flag and drops the UI receiver during a blocking poll.
struct EnrollmentTestSocket(std::path::PathBuf);

impl Drop for EnrollmentTestSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn enrollment_fallback_requests(improve: bool, cancel: bool) -> Vec<(Request, bool)> {
    use std::io::{BufRead, Write};

    let _guard = dead_socket();
    let socket = EnrollmentTestSocket(std::env::temp_dir().join(format!(
        "irlume-enrollment-{}-{improve}-{cancel}.sock",
        std::process::id()
    )));
    let listener = std::os::unix::net::UnixListener::bind(&socket.0).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::env::set_var("IRLUME_SOCKET", &socket.0);
    let stop = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let inbox = Arc::new(std::sync::Mutex::new(Some(rx)));
    let server = {
        let stop = stop.clone();
        let finished = finished.clone();
        let inbox = inbox.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut requests = Vec::new();
            let mut samples = 0;
            let mut session_requests = 0;
            let mut finished_observed = false;
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // Observe completion before the final accept attempt:
                        // a cancelled client can enqueue and return without
                        // waiting for this server to consume its request.
                        if finished_observed {
                            break;
                        }
                        finished_observed = finished.load(Ordering::Relaxed);
                        assert!(Instant::now() < deadline, "enrollment worker stalled");
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fake endpoint: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&stream)
                    .read_line(&mut line)
                    .unwrap();
                let request: Request = serde_json::from_str(&line).unwrap();
                let cancelled = stop.load(Ordering::Relaxed);
                let response = match &request {
                    Request::PositionSession { user } => {
                        assert_eq!(user.as_deref(), Some("test-user"));
                        Response::Error("bad request".into())
                    }
                    Request::PositionSample { user } => {
                        assert_eq!(user.as_deref(), Some("test-user"));
                        samples += 1;
                        if cancel && samples == 2 * (GOOD_STREAK + 3) {
                            stop.store(true, Ordering::Relaxed);
                            assert!(inbox.lock().unwrap().take().is_some());
                        }
                        Response::Position(good_report("hold still"))
                    }
                    Request::EnrollmentSession {
                        user,
                        profile,
                        scans,
                        improve: requested,
                    } => {
                        assert_eq!(user, "test-user");
                        assert_eq!(profile.as_deref(), Some("test-profile"));
                        assert_eq!(*scans, 1);
                        assert_eq!(*requested, improve);
                        session_requests += 1;
                        assert_eq!(samples, GOOD_STREAK + 3);
                        Response::Error("bad request".into())
                    }
                    Request::Enroll {
                        user,
                        profile,
                        scans,
                        reset,
                    } => {
                        assert!(!improve);
                        assert_eq!(user, "test-user");
                        assert_eq!(profile.as_deref(), Some("test-profile"));
                        assert_eq!(*scans, Some(1));
                        assert!(!reset);
                        assert_eq!(samples, 2 * (GOOD_STREAK + 3));
                        Response::Enrolled {
                            profile: "test-profile".into(),
                            created: true,
                            added: 1,
                            total: 1,
                            room: Some(29),
                            added_scans: Vec::new(),
                            ambient_lit: Some(0),
                        }
                    }
                    Request::AddScan {
                        user,
                        profile,
                        scans,
                        report_enrollment,
                    } => {
                        assert!(improve);
                        assert_eq!(user, "test-user");
                        assert_eq!(profile, "test-profile");
                        assert_eq!(*scans, None);
                        assert!(report_enrollment);
                        assert_eq!(samples, 2 * (GOOD_STREAK + 3));
                        Response::Ok("added".into())
                    }
                    _ => panic!("unexpected enrollment request"),
                };
                requests.push((request, cancelled));
                // Cancellation may close the client before the reply is read.
                let _ = writeln!(stream, "{}", serde_json::to_string(&response).unwrap());
            }
            assert_eq!(samples, 2 * (GOOD_STREAK + 3));
            assert_eq!(session_requests, 1);
            requests
        })
    };
    enroll_worker(
        "test-user".into(),
        "test-profile".into(),
        improve.then(|| "test-profile".into()),
        1,
        stop.clone(),
        tx,
    );
    finished.store(true, Ordering::Relaxed);
    let requests = server.join().unwrap();
    if cancel {
        assert!(
            stop.load(Ordering::Relaxed),
            "cancellation was not injected"
        );
        assert!(
            inbox.lock().unwrap().is_none(),
            "UI receiver was not dropped"
        );
    } else {
        let messages: Vec<_> = inbox.lock().unwrap().take().unwrap().into_iter().collect();
        assert!(messages.iter().any(|m| matches!(m, WMsg::Captured(1, 1))));
        assert!(messages.iter().any(|m| matches!(m, WMsg::Done { .. })));
    }
    requests
}

fn assert_no_cancelled_enrollment_dispatch(requests: &[(Request, bool)]) {
    assert!(
        requests.iter().all(|(request, cancelled)| {
            !cancelled
                || !matches!(
                    request,
                    Request::Enroll { .. }
                        | Request::AddScan { .. }
                        | Request::EnrollmentSession { .. }
                )
        }),
        "an enrollment request was sent after cancellation"
    );
}

#[test]
fn enrollment_cancel_full_fallback_skips_enroll_after_receiver_drop() {
    assert_no_cancelled_enrollment_dispatch(&enrollment_fallback_requests(false, true));
}

#[test]
fn enrollment_cancel_full_fallback_skips_add_scan_after_receiver_drop() {
    assert_no_cancelled_enrollment_dispatch(&enrollment_fallback_requests(true, true));
}

#[test]
fn enrollment_fallback_without_cancellation_enrolls_once() {
    let requests = enrollment_fallback_requests(false, false);
    assert_eq!(
        requests
            .iter()
            .filter(|(r, _)| matches!(r, Request::Enroll { .. }))
            .count(),
        1
    );
}

#[test]
fn enrollment_fallback_without_cancellation_adds_once() {
    let requests = enrollment_fallback_requests(true, false);
    assert_eq!(
        requests
            .iter()
            .filter(|(r, _)| matches!(r, Request::AddScan { .. }))
            .count(),
        1
    );
}
