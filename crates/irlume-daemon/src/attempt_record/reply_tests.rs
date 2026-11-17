// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Instant;

struct ReplyState {
    dir: PathBuf,
    previous: Option<std::ffi::OsString>,
    uid: u32,
    user: String,
}

impl ReplyState {
    // The caller holds the environment write guard through this fixture's Drop.
    fn new(tag: &str) -> Self {
        let previous = std::env::var_os("IRLUME_STATE_DIR");
        let (dir, uid, user) = super::tests::own_state_dir(tag);
        let state = Self {
            dir,
            previous,
            uid,
            user,
        };
        record(
            state.uid,
            &state.user,
            Filed {
                at: unix_now(),
                kind: AttemptKind::Identify,
                surface: AttemptSurface::Other,
                result: AttemptResult::Refused,
                cause: Some(OutcomeCause::NoFace),
                elapsed_ms: 1,
                capture_ms: None,
                camera: None,
            },
        )
        .expect("the throwaway history store must accept its seed");
        assert!(state.saved().record.latest_identify.is_some());
        state
    }

    fn saved(&self) -> Stored {
        store()
            .unwrap()
            .read(self.uid, &self.user)
            .expect("read the throwaway history")
    }

    fn budget(&self) -> u64 {
        // Read only the injected test retry store, never installed state.
        let path = self.dir.join("retry").join(format!("{}.json", self.uid));
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        record["budget"]["unsuccessful_requests"]
            .as_u64()
            .expect("a reserved request has a durable count")
    }

    fn reply(&self, credential: bool) -> crate::WorkerReply {
        let response = if credential {
            crate::Response::PasswordUnsealed {
                secret: irlume_common::SecretBytes::new(b"synthetic dropped reply".to_vec()),
                kind: irlume_common::KeyringSecretKind::LoginPassword,
            }
        } else {
            crate::Response::AuthResult {
                granted: true,
                score: 1.0,
                live: true,
                reason: "synthetic".into(),
                declined_by_gesture: false,
                refused_by_policy: false,
                situation: String::from(""),
                cause: None,
            }
        };
        crate::WorkerReply {
            response,
            completion: Some(crate::FaceCompletion {
                // cfg(test) injects this same IRLUME_STATE_DIR and its owner.
                attempt: crate::retry_throttle::FaceAttempt::for_account(Some(self.uid))
                    .expect("reserve only in the throwaway retry store"),
                window: irlume_auth::AuthenticationWindow::for_service(None),
                shared_unlock: None,
                withheld_line: Some(crate::WithheldLine {
                    prefix: "irlumed: synthetic dropped reply: ".into(),
                    notice: false,
                }),
            }),
            filing: Some(Pending::new(
                self.uid,
                self.user.clone(),
                Filed {
                    at: unix_now(),
                    kind: AttemptKind::Authenticate,
                    surface: AttemptSurface::Lock,
                    result: AttemptResult::Granted,
                    cause: None,
                    elapsed_ms: 20,
                    capture_ms: Some(17),
                    camera: None,
                },
            )),
        }
    }
}

impl Drop for ReplyState {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var("IRLUME_STATE_DIR", value),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn accepted_reply_discarded_without_receiving_is_filed_and_journaled_once() {
    if crate::test_support::isolated(
        "attempt_record::reply_tests::accepted_reply_discarded_without_receiving_is_filed_and_journaled_once",
    ) {
        return;
    }
    let _env = crate::tests::env_lock();
    for (credential, receiver_first) in [(false, true), (true, true), (false, false), (true, false)]
    {
        let state = ReplyState::new("queued-drop");
        let before_seq = state.saved().next_seq;
        let reply = state.reply(credential);
        let (sender, receiver) = mpsc::channel();
        let before_lines = irlume_common::journal_out::emitted_lines();
        assert!(
            sender.send(reply).is_ok(),
            "the reply was accepted, not refused"
        );

        if receiver_first {
            drop(receiver);
            drop(sender);
        } else {
            drop(sender);
            drop(receiver);
        }

        let saved = state.saved();
        assert_eq!(
            (
                saved.next_seq - before_seq,
                irlume_common::journal_out::emitted_lines() - before_lines,
                state.budget(),
            ),
            (1, 1, 1),
            "one cancelled history entry and withheld line, without resetting the charge"
        );
        let latest = saved
            .record
            .latest_authenticate
            .expect("the discarded reply is recorded");
        assert_eq!(latest.result, AttemptResult::Failed);
        assert_eq!(latest.cause, Some(OutcomeCause::Cancelled));
        assert_eq!(latest.capture_ms, Some(17));
    }
}

#[test]
fn written_reply_is_filed_as_granted_once_without_a_withheld_line() {
    if crate::test_support::isolated(
        "attempt_record::reply_tests::written_reply_is_filed_as_granted_once_without_a_withheld_line",
    ) {
        return;
    }
    let _env = crate::tests::env_lock();
    for credential in [false, true] {
        let state = ReplyState::new("written-once");
        let before_seq = state.saved().next_seq;
        let reply = state.reply(credential);
        let (server, client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let before_lines = irlume_common::journal_out::emitted_lines();

        reply.respond(server).unwrap();

        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        let response: crate::Response = serde_json::from_str(&line).unwrap();
        assert!(crate::is_face_grant(&response));
        let saved = state.saved();
        assert_eq!(
            (
                saved.next_seq - before_seq,
                irlume_common::journal_out::emitted_lines() - before_lines,
                state.budget(),
            ),
            (1, 0, 0),
            "a written grant files once and alone resets its charge"
        );
        let latest = saved.record.latest_authenticate.unwrap();
        assert_eq!(latest.result, AttemptResult::Granted);
        assert_eq!(latest.cause, None);
    }
}

#[test]
fn armed_early_send_error_files_once_before_ordinary_failure() {
    if crate::test_support::isolated(
        "attempt_record::reply_tests::armed_early_send_error_files_once_before_ordinary_failure",
    ) {
        return;
    }
    let _env = crate::tests::env_lock();
    for credential in [false, true] {
        let state = ReplyState::new("armed-failure");
        let before_seq = state.saved().next_seq;
        let mut reply = state.reply(credential);
        let response = reply.response.clone();
        // The actual Delivery::attempt path prepares this history entry.
        reply.filing = None;
        let (sender, receiver) = mpsc::channel();
        drop(receiver);
        let mut delivery = crate::Delivery::attached(&sender, Instant::now());
        crate::reset_reply_facts();
        let diagnostics = crate::diagnostics::DiagnosticState::default();
        delivery.attempt = Some((
            crate::AttemptContext {
                uid: state.uid,
                user: state.user.clone(),
                kind: AttemptKind::Authenticate,
                surface: AttemptSurface::Lock,
                started: Instant::now(),
                camera: None,
            },
            diagnostics.begin(irlume_common::diagnostics::OperationClass::Authentication),
        ));
        let mut unsent_completion = None;
        let before_lines = irlume_common::journal_out::emitted_lines();

        assert!(!delivery.send(reply, &mut unsent_completion));

        assert!(delivery.attempt.is_none());
        let ordinary = crate::WorkerReply {
            response,
            completion: unsent_completion,
            filing: None,
        };
        let mpsc::SendError(mut ordinary) = sender
            .send(ordinary)
            .expect_err("the receiver is still gone");
        // Production relies on Drop; this explicit call also pins idempotence.
        ordinary.journal_unreceived();
        drop(ordinary);
        let saved = state.saved();
        assert_eq!(
            (
                saved.next_seq - before_seq,
                irlume_common::journal_out::emitted_lines() - before_lines,
                state.budget(),
            ),
            (1, 2, 1),
            "an armed send failure files and journals only once"
        );
        let latest = saved.record.latest_authenticate.unwrap();
        assert_eq!(latest.result, AttemptResult::Failed);
        assert_eq!(latest.cause, Some(OutcomeCause::Cancelled));
    }
}
