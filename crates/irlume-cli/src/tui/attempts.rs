// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The Overview's last-attempt line (ADR-0030 §2, §5): the account's attempt
//! record phrased for people, independent of I/O and drawing. Every function
//! takes the clock it reads, so the phrasing is the same in tests and live.

use super::dates::{civil_date, MONTHS};
use irlume_common::{
    AttemptEntry, AttemptKind, AttemptRecord, AttemptResult, AttemptSurface, CameraPairInfo,
    OutcomeCause, Response,
};

/// What one `LastAttempts` request established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AttemptsReply {
    /// The record. Empty both when nothing is retained and when the daemon
    /// could not read the account's store.
    Loaded(Box<AttemptRecord>),
    /// The daemon predates the request and answered `bad request`.
    OlderDaemon,
    /// The daemon refused this peer for the account (root or the account
    /// itself only).
    NotPermitted,
    /// No answer, or one this build does not expect.
    Unavailable,
}

impl AttemptsReply {
    pub(super) fn decode(reply: std::io::Result<Response>) -> Self {
        match reply {
            Ok(Response::LastAttempts(record)) => Self::Loaded(Box::new(record)),
            // What a daemon without the request answers any unknown variant.
            Ok(Response::Error(error)) if error == "bad request" => Self::OlderDaemon,
            Ok(Response::Error(error)) if error.starts_with("not authorized") => Self::NotPermitted,
            Ok(_) | Err(_) => Self::Unavailable,
        }
    }
}

/// The attempt's name: for an authentication the surface's own word, so an
/// unlock or an admin prompt never reads as a login.
pub(super) fn label(entry: &AttemptEntry) -> &'static str {
    match entry.kind {
        AttemptKind::Identify => "Last recognition test",
        AttemptKind::Authenticate => match entry.surface {
            AttemptSurface::Login => "Last login",
            AttemptSurface::Lock => "Last unlock",
            AttemptSurface::Elevation => "Last admin prompt",
            AttemptSurface::App => "Last app sign-in",
            AttemptSurface::Other => "Last authentication",
        },
    }
}

pub(super) fn outcome(result: AttemptResult) -> &'static str {
    match result {
        AttemptResult::Granted => "granted",
        AttemptResult::Refused => "refused",
        AttemptResult::Failed => "did not complete",
    }
}

/// Why a face attempt did not grant, in plain words: the closed vocabulary
/// of ADR-0030 §5 and the one place the TUI phrases a cause, for the
/// Overview's last attempt and a recognition test's result alike. It says
/// what happened, never how the matcher measured it, so no phrase names a
/// score, a threshold or a similarity. No wildcard: a new cause does not
/// compile until it has words here.
pub(crate) fn cause_phrase(cause: Option<OutcomeCause>) -> &'static str {
    let Some(cause) = cause else {
        return "no reason recorded";
    };
    match cause {
        OutcomeCause::NoFace => "no face seen (were you in frame?)",
        OutcomeCause::LivenessRefused => "the liveness check did not pass",
        OutcomeCause::BelowThreshold => "not recognized as an enrolled face",
        OutcomeCause::PrivacyShutter => "camera shutter closed",
        OutcomeCause::CameraUnavailable => "camera unavailable",
        OutcomeCause::NotEnrolledOnThisCamera => "not enrolled on this camera",
        OutcomeCause::SetupUnavailable => "nothing enrolled to compare with",
        OutcomeCause::Cancelled => "cancelled",
        OutcomeCause::TimedOut => "timed out",
        OutcomeCause::MethodNotAvailable => "face unlock is not the configured method",
        OutcomeCause::Policy => "refused by policy",
        OutcomeCause::Configuration => "configuration problem",
        OutcomeCause::RetryThrottled => "too many attempts; wait a moment",
        OutcomeCause::DaemonStarting => "the daemon was still starting",
        OutcomeCause::Other | OutcomeCause::Unknown => "no reason recorded",
    }
}

/// When an attempt happened, relative to `now` (both unix seconds). Older
/// than two weeks it is a local date, with the year when that is not the
/// current one. `utc_offset` gives the local zone's offset east of UTC at a
/// time: daylight saving moves it, so the attempt's date takes the offset
/// in force when it happened, not today's. A time after `now` (the clock
/// was stepped back) reads "just now".
pub(super) fn relative_time(at: u64, now: u64, utc_offset: &dyn Fn(u64) -> i64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    let age = now.saturating_sub(at);
    if age < 45 {
        "just now".into()
    } else if age < 90 {
        "1 min ago".into()
    } else if age < HOUR {
        format!("{} min ago", ((age + MINUTE / 2) / MINUTE).clamp(2, 59))
    } else if age < 36 * HOUR {
        format!("{} h ago", ((age + HOUR / 2) / HOUR).clamp(1, 35))
    } else if age < 14 * DAY {
        format!("{} days ago", ((age + DAY / 2) / DAY).clamp(2, 13))
    } else {
        let (year, month, day) = civil_date(at, utc_offset(at));
        let month = MONTHS[month - 1];
        if year == civil_date(now, utc_offset(now)).0 {
            format!("{month} {day}")
        } else {
            format!("{month} {day}, {year}")
        }
    }
}

/// An attempt's duration to a tenth of a second: "0.9 s", "12.5 s".
pub(super) fn elapsed(ms: u64) -> String {
    let tenths = ms.saturating_add(50) / 100;
    format!("{}.{} s", tenths / 10, tenths % 10)
}

/// The account's most recent attempt of either kind. The record keeps the
/// latest of each kind; `seq` is the account's completion order shared by
/// both, and `at` orders what an older daemon left without one. A tie keeps
/// the authentication.
pub(super) fn latest(record: &AttemptRecord) -> Option<&AttemptEntry> {
    match (&record.latest_authenticate, &record.latest_identify) {
        (Some(authenticate), Some(identify)) => Some(
            if (identify.seq, identify.at) > (authenticate.seq, authenticate.at) {
                identify
            } else {
                authenticate
            },
        ),
        (authenticate, identify) => authenticate.as_ref().or(identify.as_ref()),
    }
}

/// Device-supplied text as one printable line, `None` when nothing is left.
fn scrubbed(text: &str) -> Option<String> {
    let text = super::printable(text);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The camera an attempt used, in words: the record's own name for it (else
/// its model), and where it is now, as (name, suffix) so a narrow line can
/// shorten the name alone. The daemon decides at serve time whether the
/// unit is attached (`connected`); a listed pair (only from a listing that
/// is still current, never requested for this) then tells a unit replaced
/// in the same port, or the same model moved to another port, from one that
/// is gone. The attempt is never attributed to the listed camera, which may
/// be another unit.
pub(super) fn camera(
    entry: &AttemptEntry,
    record: &AttemptRecord,
    listed: Option<&[CameraPairInfo]>,
) -> (String, &'static str) {
    let Some(camera) = &entry.camera else {
        return ("before a camera was chosen".into(), "");
    };
    let model = format!(
        "camera {}",
        scrubbed(&camera.model).unwrap_or_else(|| "of unknown model".into())
    );
    let Some(bucket) = record
        .cameras
        .iter()
        .find(|bucket| bucket.camera == *camera)
    else {
        // Evicted from the record: nothing says the unit is still attached.
        return (model, ", no longer connected");
    };
    let name = bucket.name.as_deref().and_then(scrubbed).unwrap_or(model);
    let whereabouts = match bucket.connected {
        // An older daemon does not say; claim nothing.
        Some(true) | None => "",
        Some(false) => {
            let same_token = |pair: &&CameraPairInfo| {
                camera.descriptor_token.is_some()
                    && pair.descriptor_token == camera.descriptor_token
            };
            let listed = listed.unwrap_or_default();
            if listed
                .iter()
                .filter(same_token)
                .any(|pair| camera.port_chain.is_some() && pair.port_chain == camera.port_chain)
            {
                ", replaced unit"
            } else if listed
                .iter()
                .filter(same_token)
                .any(|pair| pair.port_chain != camera.port_chain)
            {
                ", different port"
            } else {
                ", no longer connected"
            }
        }
    };
    (name, whereabouts)
}

/// The narrowest a shortened camera name gets; below it the line leaves the
/// camera out rather than show a stub that names nothing.
const MIN_CAMERA_NAME: usize = 8;

/// Terminal cells `text` takes.
fn cells(text: &str) -> usize {
    ratatui::text::Span::raw(text).width()
}

/// The latest attempt's line, within `width` cells where it can be, and
/// the camera's own line when it moved there. What happened and why stay on
/// the first line (ADR-0030 §2). When the whole attempt does not fit and the
/// pane has a `spare_row`, the camera moves to a line of its own, whole.
/// Otherwise the camera's name (device text of any length) gives way first,
/// keeping where the unit is now; then the elapsed time; then the camera.
/// What still does not fit is the drawer's to end in an ellipsis.
fn first_line(
    head: &str,
    (name, whereabouts): (&str, &str),
    on_camera: bool,
    result: &str,
    elapsed: &str,
    width: usize,
    spare_row: bool,
) -> (String, Option<String>) {
    let without_camera = || {
        let with_elapsed = format!("{head} · {result} · {elapsed}");
        if cells(&with_elapsed) <= width {
            with_elapsed
        } else {
            format!("{head} · {result}")
        }
    };
    let full = format!("{head} · {name}{whereabouts} · {result} · {elapsed}");
    if cells(&full) <= width {
        return (full, None);
    }
    if spare_row {
        let camera = if on_camera {
            format!("    on {name}{whereabouts}")
        } else {
            format!("    {name}")
        };
        return (without_camera(), Some(camera));
    }
    for elapsed in [Some(elapsed), None] {
        let line = |camera: &str| match elapsed {
            Some(elapsed) => format!("{head} · {camera} · {result} · {elapsed}"),
            None => format!("{head} · {camera} · {result}"),
        };
        let full = line(&format!("{name}{whereabouts}"));
        if cells(&full) <= width {
            return (full, None);
        }
        let room = width.saturating_sub(cells(&line("")) + cells(whereabouts));
        if room >= MIN_CAMERA_NAME {
            return (
                line(&format!("{}{whereabouts}", super::clip_columns(name, room))),
                None,
            );
        }
    }
    (without_camera(), None)
}

/// The Overview's attempt block for an installed record, its first line
/// fitted to `width` cells where it can be ([`first_line`], which may use a
/// `spare_row` for the camera): the latest attempt, then the last
/// authentication when the latest is a recognition test, so a test never
/// hides how the last real sign-in went.
pub(super) fn record_lines(
    record: &AttemptRecord,
    now: u64,
    utc_offset: &dyn Fn(u64) -> i64,
    listed: Option<&[CameraPairInfo]>,
    width: usize,
    spare_row: bool,
) -> Vec<String> {
    let Some(latest) = latest(record) else {
        // An empty record also stands for a store the daemon could not
        // read: say what is retained, never that the account never tried.
        return vec!["  No face attempt retained yet".into()];
    };
    let result = match latest.result {
        AttemptResult::Granted => outcome(latest.result).to_owned(),
        AttemptResult::Refused | AttemptResult::Failed => {
            format!("{}: {}", outcome(latest.result), cause_phrase(latest.cause))
        }
    };
    let (name, whereabouts) = camera(latest, record, listed);
    let (first, camera_line) = first_line(
        &format!(
            "  {} · {}",
            label(latest),
            relative_time(latest.at, now, utc_offset)
        ),
        (&name, whereabouts),
        latest.camera.is_some(),
        &result,
        &elapsed(latest.elapsed_ms),
        width,
        spare_row,
    );
    let mut lines = vec![first];
    lines.extend(camera_line);
    if latest.kind == AttemptKind::Identify {
        if let Some(authenticate) = &record.latest_authenticate {
            lines.push(format!(
                "  {}: {}, {}",
                label(authenticate),
                outcome(authenticate.result),
                relative_time(authenticate.at, now, utc_offset),
            ));
        }
    }
    lines
}

/// The Overview's whole attempt block, for a pane `width` cells wide with
/// or without a `spare_row` for the camera. `reply` is the installed
/// answer; with none installed the block is checking, or unavailable when
/// the last request got no answer (`failed`).
#[allow(
    clippy::too_many_arguments,
    reason = "one pure view of the pane's inputs"
)]
pub(super) fn block(
    reply: Option<&AttemptsReply>,
    failed: bool,
    user: &str,
    now: u64,
    utc_offset: &dyn Fn(u64) -> i64,
    listed: Option<&[CameraPairInfo]>,
    width: usize,
    spare_row: bool,
) -> Vec<String> {
    match reply {
        Some(AttemptsReply::Loaded(record)) => {
            record_lines(record, now, utc_offset, listed, width, spare_row)
        }
        Some(AttemptsReply::OlderDaemon) => {
            vec!["  Last attempt: this daemon predates the attempt record".into()]
        }
        Some(AttemptsReply::NotPermitted) => vec![format!(
            "  Last attempt: readable only by root or {}",
            scrubbed(user).unwrap_or_else(|| "the account".into())
        )],
        Some(AttemptsReply::Unavailable) => unavailable(),
        None if failed => unavailable(),
        None => vec!["  Last attempt: checking…".into()],
    }
}

fn unavailable() -> Vec<String> {
    vec!["  Last attempt: unavailable (daemon not answering)".into()]
}

/// Words a person must never read about a face attempt: they describe the
/// matcher's measurement, not what happened (ADR-0030 §2).
#[cfg(test)]
pub(super) const FORBIDDEN_WORDS: [&str; 4] = ["score", "threshold", "similarity", "cosine"];

/// Every cause, in declaration order; the test beside `cause_phrase` keeps
/// it complete.
#[cfg(test)]
pub(super) const ALL_CAUSES: [OutcomeCause; 16] = [
    OutcomeCause::NoFace,
    OutcomeCause::LivenessRefused,
    OutcomeCause::BelowThreshold,
    OutcomeCause::PrivacyShutter,
    OutcomeCause::CameraUnavailable,
    OutcomeCause::NotEnrolledOnThisCamera,
    OutcomeCause::SetupUnavailable,
    OutcomeCause::Cancelled,
    OutcomeCause::TimedOut,
    OutcomeCause::MethodNotAvailable,
    OutcomeCause::Policy,
    OutcomeCause::Configuration,
    OutcomeCause::RetryThrottled,
    OutcomeCause::DaemonStarting,
    OutcomeCause::Other,
    OutcomeCause::Unknown,
];

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::{AttemptCamera, CameraAttempts};

    /// 2026-09-23 12:00:00 UTC.
    const NOW: u64 = 1_790_164_800;

    fn entry(kind: AttemptKind, surface: AttemptSurface, result: AttemptResult) -> AttemptEntry {
        AttemptEntry {
            at: NOW - 2 * 3600,
            seq: 1,
            kind,
            surface,
            result,
            cause: None,
            elapsed_ms: 1234,
            capture_ms: None,
            camera: None,
        }
    }

    fn located(model: &str, port: &str, token: &str) -> AttemptCamera {
        AttemptCamera {
            model: model.into(),
            port_chain: Some(port.into()),
            descriptor_token: Some(token.into()),
            unit: None,
        }
    }

    fn bucket(
        camera: &AttemptCamera,
        name: Option<&str>,
        connected: Option<bool>,
    ) -> CameraAttempts {
        CameraAttempts {
            camera: camera.clone(),
            attempts: Vec::new(),
            connected,
            name: name.map(Into::into),
        }
    }

    /// The camera's words as one piece, the way a wide line shows them.
    fn camera_text(
        entry: &AttemptEntry,
        record: &AttemptRecord,
        listed: Option<&[CameraPairInfo]>,
    ) -> String {
        let (name, whereabouts) = camera(entry, record, listed);
        format!("{name}{whereabouts}")
    }

    fn pair(name: &str, port: &str, token: &str) -> CameraPairInfo {
        CameraPairInfo {
            rgb: "/dev/video40".into(),
            ir: "/dev/video42".into(),
            id: Some("046d:085e".into()),
            fixed: false,
            privacy: false,
            name: Some(name.into()),
            identity: None,
            serial_present: false,
            port_chain: Some(port.into()),
            descriptor_token: Some(token.into()),
            handle: None,
        }
    }

    #[test]
    fn replies_decode_into_the_four_states() {
        let record = AttemptRecord {
            latest_authenticate: Some(entry(
                AttemptKind::Authenticate,
                AttemptSurface::Lock,
                AttemptResult::Granted,
            )),
            ..AttemptRecord::default()
        };
        assert_eq!(
            AttemptsReply::decode(Ok(Response::LastAttempts(record.clone()))),
            AttemptsReply::Loaded(Box::new(record))
        );
        assert_eq!(
            AttemptsReply::decode(Ok(Response::Error("bad request".into()))),
            AttemptsReply::OlderDaemon
        );
        assert_eq!(
            AttemptsReply::decode(Ok(Response::Error(
                "not authorized to query 'alice'".into()
            ))),
            AttemptsReply::NotPermitted
        );
        // Only the exact older-daemon answer means an older daemon.
        for other in [
            "bad request: trailing",
            "daemon is starting",
            "invalid username",
        ] {
            assert_eq!(
                AttemptsReply::decode(Ok(Response::Error(other.into()))),
                AttemptsReply::Unavailable,
                "{other}"
            );
        }
        assert_eq!(
            AttemptsReply::decode(Ok(Response::Pong)),
            AttemptsReply::Unavailable
        );
        assert_eq!(
            AttemptsReply::decode(Err(std::io::Error::from(std::io::ErrorKind::TimedOut))),
            AttemptsReply::Unavailable
        );
    }

    #[test]
    fn labels_name_the_surface_and_never_call_an_unlock_a_login() {
        use AttemptSurface as S;
        for (surface, expected) in [
            (S::Login, "Last login"),
            (S::Lock, "Last unlock"),
            (S::Elevation, "Last admin prompt"),
            (S::App, "Last app sign-in"),
            (S::Other, "Last authentication"),
        ] {
            let attempt = entry(AttemptKind::Authenticate, surface, AttemptResult::Granted);
            assert_eq!(label(&attempt), expected);
            if surface != S::Login {
                assert!(!expected.to_lowercase().contains("login"), "{expected}");
            }
        }
        // An identify entry carries `other`; its kind names it.
        let test = entry(AttemptKind::Identify, S::Other, AttemptResult::Granted);
        assert_eq!(label(&test), "Last recognition test");
        assert_eq!(outcome(AttemptResult::Granted), "granted");
        assert_eq!(outcome(AttemptResult::Refused), "refused");
        assert_eq!(outcome(AttemptResult::Failed), "did not complete");
    }

    #[test]
    fn every_cause_has_plain_words_without_matcher_vocabulary() {
        // Exhaustive without a wildcard, like `cause_phrase`: a new cause
        // stops this compiling, and its arm's index is the next slot
        // ALL_CAUSES must fill.
        fn position(cause: OutcomeCause) -> usize {
            match cause {
                OutcomeCause::NoFace => 0,
                OutcomeCause::LivenessRefused => 1,
                OutcomeCause::BelowThreshold => 2,
                OutcomeCause::PrivacyShutter => 3,
                OutcomeCause::CameraUnavailable => 4,
                OutcomeCause::NotEnrolledOnThisCamera => 5,
                OutcomeCause::SetupUnavailable => 6,
                OutcomeCause::Cancelled => 7,
                OutcomeCause::TimedOut => 8,
                OutcomeCause::MethodNotAvailable => 9,
                OutcomeCause::Policy => 10,
                OutcomeCause::Configuration => 11,
                OutcomeCause::RetryThrottled => 12,
                OutcomeCause::DaemonStarting => 13,
                OutcomeCause::Other => 14,
                OutcomeCause::Unknown => 15,
            }
        }
        for (index, cause) in ALL_CAUSES.iter().enumerate() {
            assert_eq!(position(*cause), index);
        }
        let mut phrases: Vec<(Option<OutcomeCause>, &str)> = ALL_CAUSES
            .iter()
            .map(|cause| (Some(*cause), cause_phrase(Some(*cause))))
            .collect();
        phrases.push((None, cause_phrase(None)));
        for (cause, phrase) in &phrases {
            assert!(!phrase.is_empty(), "{cause:?}");
            let lower = phrase.to_lowercase();
            for word in FORBIDDEN_WORDS {
                assert!(!lower.contains(word), "{cause:?} reads {phrase:?}");
            }
        }
        // Each named cause reads differently; only the causes that name
        // nothing share the fallback.
        let fallback = "no reason recorded";
        for (cause, phrase) in &phrases {
            let unnamed = matches!(
                cause,
                None | Some(OutcomeCause::Other | OutcomeCause::Unknown)
            );
            assert_eq!(*phrase == fallback, unnamed, "{cause:?}");
            if !unnamed {
                assert_eq!(
                    phrases.iter().filter(|(_, other)| other == phrase).count(),
                    1,
                    "{phrase}"
                );
            }
        }
        assert_eq!(
            cause_phrase(Some(OutcomeCause::NoFace)),
            "no face seen (were you in frame?)"
        );
        assert_eq!(
            cause_phrase(Some(OutcomeCause::BelowThreshold)),
            "not recognized as an enrolled face"
        );
    }

    #[test]
    fn relative_time_reads_like_a_person_would_say_it() {
        const HOUR: u64 = 3600;
        const DAY: u64 = 24 * HOUR;
        for (age, expected) in [
            (0, "just now"),
            (44, "just now"),
            (45, "1 min ago"),
            (89, "1 min ago"),
            (90, "2 min ago"),
            (149, "2 min ago"),
            (150, "3 min ago"),
            (HOUR - 1, "59 min ago"),
            (HOUR, "1 h ago"),
            (HOUR + 1799, "1 h ago"),
            (HOUR + 1800, "2 h ago"),
            (36 * HOUR - 1, "35 h ago"),
            (36 * HOUR, "2 days ago"),
            (5 * DAY, "5 days ago"),
            (14 * DAY - 1, "13 days ago"),
            // 2026-09-09 12:00 UTC.
            (14 * DAY, "Sep 9"),
        ] {
            assert_eq!(relative_time(NOW - age, NOW, &|_| 0), expected, "{age}");
        }
        // A clock stepped back never shows a negative age.
        assert_eq!(relative_time(NOW + 600, NOW, &|_| 0), "just now");
        assert_eq!(relative_time(u64::MAX, NOW, &|_| 0), "just now");
    }

    #[test]
    fn old_attempts_read_as_a_local_date_with_the_year_only_when_it_differs() {
        // 2025-12-31 23:30 UTC.
        let new_year_eve = 1_767_223_800;
        assert_eq!(relative_time(new_year_eve, NOW, &|_| 0), "Dec 31, 2025");
        // One hour east of UTC it is already 2026 there.
        assert_eq!(relative_time(new_year_eve, NOW, &|_| 3600), "Jan 1");
        // Five hours west, the evening before.
        assert_eq!(
            relative_time(new_year_eve, NOW, &|_| -5 * 3600),
            "Dec 31, 2025"
        );
        // Across a daylight-saving change the attempt's date takes the
        // offset of its own time. A New York-like zone: UTC-5 until
        // 2026-03-08 07:00 UTC, UTC-4 after. 2026-03-02 04:30 UTC was
        // 23:30 on Mar 1 there; today's offset would say Mar 2.
        let new_york = |at: u64| {
            if at < 1_772_953_200 {
                -5 * 3600
            } else {
                -4 * 3600
            }
        };
        assert_eq!(relative_time(1_772_425_800, NOW, &new_york), "Mar 1");
    }

    #[test]
    fn elapsed_reads_to_a_tenth_of_a_second() {
        for (ms, expected) in [
            (0, "0.0 s"),
            (49, "0.0 s"),
            (900, "0.9 s"),
            (949, "0.9 s"),
            (950, "1.0 s"),
            (1234, "1.2 s"),
            (12_450, "12.5 s"),
            (12_549, "12.5 s"),
            (61_000, "61.0 s"),
        ] {
            assert_eq!(elapsed(ms), expected, "{ms}");
        }
    }

    #[test]
    fn the_latest_attempt_is_chosen_by_completion_order_then_time() {
        let mut authenticate = entry(
            AttemptKind::Authenticate,
            AttemptSurface::Lock,
            AttemptResult::Granted,
        );
        let mut identify = entry(
            AttemptKind::Identify,
            AttemptSurface::Other,
            AttemptResult::Refused,
        );
        let record = |a: &AttemptEntry, i: &AttemptEntry| AttemptRecord {
            latest_authenticate: Some(a.clone()),
            latest_identify: Some(i.clone()),
            cameras: Vec::new(),
        };
        assert!(latest(&AttemptRecord::default()).is_none());
        // seq orders within one second, whatever the clock says.
        authenticate.seq = 7;
        identify.seq = 8;
        identify.at = authenticate.at;
        assert_eq!(
            latest(&record(&authenticate, &identify)).unwrap().kind,
            AttemptKind::Identify
        );
        authenticate.seq = 9;
        assert_eq!(
            latest(&record(&authenticate, &identify)).unwrap().kind,
            AttemptKind::Authenticate
        );
        // An older daemon's entries (seq 0) order by time; a tie keeps the
        // authentication.
        authenticate.seq = 0;
        identify.seq = 0;
        identify.at = authenticate.at + 1;
        assert_eq!(
            latest(&record(&authenticate, &identify)).unwrap().kind,
            AttemptKind::Identify
        );
        identify.at = authenticate.at;
        assert_eq!(
            latest(&record(&authenticate, &identify)).unwrap().kind,
            AttemptKind::Authenticate
        );
        let only_identify = AttemptRecord {
            latest_identify: Some(identify.clone()),
            ..AttemptRecord::default()
        };
        assert_eq!(latest(&only_identify).unwrap().kind, AttemptKind::Identify);
    }

    #[test]
    fn the_camera_is_named_by_the_record_and_placed_by_the_daemon_and_listing() {
        let desk = located("046d:085e", "1-2", "0011223344556677");
        let mut attempt = entry(
            AttemptKind::Authenticate,
            AttemptSurface::Lock,
            AttemptResult::Refused,
        );
        attempt.camera = Some(desk.clone());
        let record = |name: Option<&str>, connected: Option<bool>| AttemptRecord {
            latest_authenticate: Some(attempt.clone()),
            latest_identify: None,
            cameras: vec![bucket(&desk, name, connected)],
        };
        let attached = record(Some("Desk Camera"), Some(true));
        assert_eq!(camera_text(&attempt, &attached, None), "Desk Camera");
        // No recorded name: the model, which is what the record has.
        assert_eq!(
            camera_text(&attempt, &record(None, Some(true)), None),
            "camera 046d:085e"
        );
        assert_eq!(
            camera_text(&attempt, &record(Some(" \u{1b}[2J "), Some(true)), None),
            "[2J",
            "control characters are blanked, not echoed to the terminal"
        );
        // An older daemon does not say whether it is attached.
        assert_eq!(
            camera_text(&attempt, &record(Some("Desk Camera"), None), None),
            "Desk Camera"
        );
        let gone = record(Some("Desk Camera"), Some(false));
        assert_eq!(
            camera_text(&attempt, &gone, None),
            "Desk Camera, no longer connected"
        );
        assert_eq!(
            camera_text(&attempt, &gone, Some(&[])),
            "Desk Camera, no longer connected"
        );
        // Same port and token, yet not the recorded unit: replaced.
        let same_place = [pair("Listed Camera", "1-2", "0011223344556677")];
        assert_eq!(
            camera_text(&attempt, &gone, Some(&same_place)),
            "Desk Camera, replaced unit"
        );
        // The same model at another port: never the listed camera's name.
        let elsewhere = [pair("Listed Dock Camera", "3-1.4", "0011223344556677")];
        let moved = camera_text(&attempt, &gone, Some(&elsewhere));
        assert_eq!(moved, "Desk Camera, different port");
        assert!(!moved.contains("Listed Dock Camera"));
        // Another model at the same port says nothing about this one.
        let other_model = [pair("Other Camera", "1-2", "8899aabbccddeeff")];
        assert_eq!(
            camera_text(&attempt, &gone, Some(&other_model)),
            "Desk Camera, no longer connected"
        );
        // Evicted from the record: the model, and no claim it is attached.
        let evicted = AttemptRecord {
            latest_authenticate: Some(attempt.clone()),
            ..AttemptRecord::default()
        };
        assert_eq!(
            camera_text(&attempt, &evicted, None),
            "camera 046d:085e, no longer connected"
        );
        attempt.camera = None;
        assert_eq!(
            camera_text(&attempt, &attached, None),
            "before a camera was chosen"
        );
    }

    #[test]
    fn the_block_leads_with_the_latest_and_keeps_the_last_authentication() {
        let desk = located("046d:085e", "1-2", "0011223344556677");
        let mut unlock = entry(
            AttemptKind::Authenticate,
            AttemptSurface::Lock,
            AttemptResult::Refused,
        );
        unlock.cause = Some(OutcomeCause::LivenessRefused);
        unlock.camera = Some(desk.clone());
        unlock.seq = 4;
        let mut record = AttemptRecord {
            latest_authenticate: Some(unlock.clone()),
            latest_identify: None,
            cameras: vec![bucket(&desk, Some("Desk Camera"), Some(true))],
        };
        assert_eq!(
            record_lines(&record, NOW, &|_| 0, None, usize::MAX, false),
            ["  Last unlock · 2 h ago · Desk Camera · refused: the liveness check did not pass · 1.2 s"]
        );
        let mut test = entry(
            AttemptKind::Identify,
            AttemptSurface::Other,
            AttemptResult::Granted,
        );
        test.at = NOW - 30;
        test.seq = 5;
        test.elapsed_ms = 900;
        test.camera = Some(desk);
        record.latest_identify = Some(test);
        assert_eq!(
            record_lines(&record, NOW, &|_| 0, None, usize::MAX, false),
            [
                "  Last recognition test · just now · Desk Camera · granted · 0.9 s",
                "  Last unlock: refused, 2 h ago",
            ]
        );
        // A failure names its cause too; a cause-less one says so.
        let mut failed = unlock.clone();
        failed.result = AttemptResult::Failed;
        failed.cause = None;
        failed.camera = None;
        let failed = AttemptRecord {
            latest_authenticate: Some(failed),
            ..AttemptRecord::default()
        };
        assert_eq!(
            record_lines(&failed, NOW, &|_| 0, None, usize::MAX, false),
            ["  Last unlock · 2 h ago · before a camera was chosen · did not complete: no reason recorded · 1.2 s"]
        );
        assert_eq!(
            record_lines(
                &AttemptRecord::default(),
                NOW,
                &|_| 0,
                None,
                usize::MAX,
                false
            ),
            ["  No face attempt retained yet"]
        );
    }

    #[test]
    fn a_narrow_line_gives_up_the_camera_name_then_the_time_then_the_camera() {
        let desk = located("046d:085e", "1-2", "0011223344556677");
        let mut unlock = entry(
            AttemptKind::Authenticate,
            AttemptSurface::Lock,
            AttemptResult::Refused,
        );
        unlock.cause = Some(OutcomeCause::PrivacyShutter);
        unlock.camera = Some(desk.clone());
        let record = AttemptRecord {
            latest_authenticate: Some(unlock),
            latest_identify: None,
            cameras: vec![bucket(
                &desk,
                Some("Synthetic camera with a very long product name"),
                Some(false),
            )],
        };
        let first = |width: usize| record_lines(&record, NOW, &|_| 0, None, width, false).remove(0);
        let full = "  Last unlock · 2 h ago · Synthetic camera with a very long product name, no longer connected · refused: camera shutter closed · 1.2 s";
        assert_eq!(first(cells(full)), full);
        // The name shortens; where the unit is now stays.
        assert_eq!(
            first(100),
            "  Last unlock · 2 h ago · Synthetic c…, no longer connected · refused: camera shutter closed · 1.2 s"
        );
        // Then the elapsed time goes.
        assert_eq!(
            first(92),
            "  Last unlock · 2 h ago · Synthetic c…, no longer connected · refused: camera shutter closed"
        );
        // Then the camera; the time comes back when it fits.
        assert_eq!(
            first(74),
            "  Last unlock · 2 h ago · refused: camera shutter closed · 1.2 s"
        );
        assert_eq!(
            first(60),
            "  Last unlock · 2 h ago · refused: camera shutter closed"
        );
        // Narrower still, the drawer cuts what is left with an ellipsis.
        assert_eq!(
            first(40),
            "  Last unlock · 2 h ago · refused: camera shutter closed"
        );
        for width in [40, 60, 74, 80, 92, 100, 120] {
            let line = first(width);
            assert!(
                line.contains("refused: camera shutter closed"),
                "{width}: {line}"
            );
            assert!(cells(&line) <= width.max(56), "{width}: {line}");
        }
    }

    /// With a row to spare, a camera that does not fit beside the attempt
    /// moves to its own line whole (where the unit is now included) rather
    /// than being shortened or left out.
    #[test]
    fn a_spare_row_carries_the_camera_that_does_not_fit_beside_the_attempt() {
        let desk = located("046d:085e", "1-2", "0011223344556677");
        let mut unlock = entry(
            AttemptKind::Authenticate,
            AttemptSurface::Lock,
            AttemptResult::Refused,
        );
        unlock.cause = Some(OutcomeCause::PrivacyShutter);
        unlock.camera = Some(desk.clone());
        let record = AttemptRecord {
            latest_authenticate: Some(unlock.clone()),
            latest_identify: None,
            cameras: vec![bucket(
                &desk,
                Some("Synthetic camera with a very long product name"),
                Some(false),
            )],
        };
        assert_eq!(
            record_lines(&record, NOW, &|_| 0, None, 96, true),
            [
                "  Last unlock · 2 h ago · refused: camera shutter closed · 1.2 s",
                "    on Synthetic camera with a very long product name, no longer connected",
            ]
        );
        // A line that fits keeps the camera beside the attempt, spare row or not.
        assert_eq!(
            record_lines(&record, NOW, &|_| 0, None, usize::MAX, true).len(),
            1
        );
        // Before a camera was chosen, the camera line says so.
        let mut early = record.clone();
        let mut refused = unlock;
        refused.camera = None;
        refused.cause = Some(OutcomeCause::RetryThrottled);
        early.latest_authenticate = Some(refused);
        assert_eq!(
            record_lines(&early, NOW, &|_| 0, None, 60, true),
            [
                "  Last unlock · 2 h ago · refused: too many attempts; wait a moment",
                "    before a camera was chosen",
            ]
        );
    }

    #[test]
    fn states_without_a_record_say_why() {
        let lines = |reply: Option<&AttemptsReply>, failed: bool| {
            block(reply, failed, "alice", NOW, &|_| 0, None, usize::MAX, false).join("\n")
        };
        assert_eq!(lines(None, false), "  Last attempt: checking…");
        assert_eq!(
            lines(None, true),
            "  Last attempt: unavailable (daemon not answering)"
        );
        assert_eq!(
            lines(Some(&AttemptsReply::Unavailable), false),
            "  Last attempt: unavailable (daemon not answering)"
        );
        assert_eq!(
            lines(Some(&AttemptsReply::OlderDaemon), false),
            "  Last attempt: this daemon predates the attempt record"
        );
        assert_eq!(
            lines(Some(&AttemptsReply::NotPermitted), false),
            "  Last attempt: readable only by root or alice"
        );
        // An installed answer stands even while a later request failed.
        assert_eq!(
            lines(Some(&AttemptsReply::Loaded(Box::default())), true),
            "  No face attempt retained yet"
        );
    }
}
