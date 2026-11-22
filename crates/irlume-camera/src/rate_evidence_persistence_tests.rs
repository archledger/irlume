// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Rate evidence across daemon restarts (ADR-0021, amendment 2026-11-22): a
// full window's completion is kept under the stream's USB identity and
// consulted at session start, exactly as the in-memory cache is. The probe
// on the current session stays what admits it. Every fixture is
// software-only; records live in a scratch state directory.

use crate::capture_qualification::{
    AcceptedStream, CameraEndpoint, ConnectionContext, ExactInterval, ExactRate,
    QualifiedStreamRole, RequestedStream, StreamContract,
};
use crate::rate_evidence_store::Store;
use crate::rate_amortization::test_support::restart;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const DAY: Duration = crate::rate_amortization::MAX_STALENESS;

/// A scratch state directory for one test. Its record store is
/// `rate-evidence/` inside it, which is where the production store lives
/// under `/var/lib/irlume`.
struct StateDir(PathBuf);

impl StateDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "irlume-rate-evidence-{label}-{:08x}",
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn store(&self) -> Store {
        Store::at(self.0.join("rate-evidence"))
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The facts one stream's identity is bound to.
#[derive(Clone)]
struct Facts {
    vid: u16,
    pid: u16,
    serial: Option<&'static str>,
    port: u8,
    speed: u64,
    descriptor: &'static str,
    interface: u8,
    controller: &'static str,
    role: QualifiedStreamRole,
    fourcc: &'static str,
    interval: (u32, u32),
}

impl Facts {
    const RGB: Self = Self {
        vid: 0x04f2,
        pid: 0xb6bf,
        serial: Some("200901010001"),
        port: 4,
        speed: 480_000,
        descriptor: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        interface: 2,
        controller: "/devices/pci0000:00/0000:00:14.0",
        role: QualifiedStreamRole::Rgb,
        fourcc: "YUYV",
        interval: (1, 30),
    };

    fn with(self, change: impl FnOnce(&mut Self)) -> Self {
        let mut facts = self;
        change(&mut facts);
        facts
    }

    fn other_port(self, port: u8) -> Self {
        self.with(|facts| facts.port = port)
    }

    fn endpoint(&self) -> CameraEndpoint {
        CameraEndpoint::new(
            self.descriptor.to_owned(),
            self.vid,
            self.pid,
            self.serial.map(str::to_owned),
            self.interface,
            format!("{}/usb1/1-{}", self.controller, self.port),
            self.role,
            ConnectionContext::new(
                self.controller.to_owned(),
                self.speed,
                "uvcvideo".to_owned(),
                "uvc-v4l2".to_owned(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn stream(&self) -> StreamContract {
        let interval = ExactInterval::new(self.interval.0, self.interval.1).unwrap();
        let (width, height, floor) = match self.role {
            QualifiedStreamRole::Rgb => (640, 480, (15, 2)),
            QualifiedStreamRole::Ir => (640, 360, (15, 1)),
        };
        StreamContract::new(
            self.role,
            RequestedStream::new(width, height, self.fourcc.to_owned(), interval).unwrap(),
            AcceptedStream::new(
                width,
                height,
                self.fourcc.to_owned(),
                width * 2,
                width * height * 2,
                0,
                1,
                1,
                1,
                0,
                interval,
            )
            .unwrap(),
            ExactRate::new(floor.0, floor.1).unwrap(),
        )
        .unwrap()
    }

    fn identity(&self) -> crate::rate_amortization::Identity {
        crate::rate_amortization::Identity::for_stream(&self.endpoint(), &self.stream())
            .expect("a USB endpoint and a stream give an identity")
    }

    fn role(&self) -> contracts::StreamRole {
        match self.role {
            QualifiedStreamRole::Rgb => contracts::StreamRole::Rgb,
            QualifiedStreamRole::Ir => contracts::StreamRole::Ir,
        }
    }
}

/// A session on `node` whose rate evidence is also kept under `facts`,
/// delivering `frames` frames after the seed, each `delta_us` apart.
fn session_on(
    node: &str,
    facts: &Facts,
    delta_us: i64,
    frames: usize,
) -> TrackedStream<QueuedContinuityFixture> {
    TrackedStream::new(
        delta_queue(&vec![delta_us; frames]),
        role_config(facts.role()),
    )
    .with_rate_amortization(node)
    .with_rate_identity(Some(facts.identity()))
}

/// The recorded `(decision, deltas, probe_deltas, persisted)`.
fn recorded<S>(
    stream: &TrackedStream<S>,
) -> (RateEvidenceDecision, u32, Option<u32>, bool) {
    match stream.rate_evidence.clone() {
        Some(TraceEventKind::RateEvidence {
            decision,
            deltas,
            probe_deltas,
            persisted,
            ..
        }) => (decision, deltas, probe_deltas, persisted),
        other => panic!("no rate evidence recorded: {other:?}"),
    }
}

const FULL_WINDOW: (RateEvidenceDecision, u32, Option<u32>, bool) =
    (RateEvidenceDecision::FullWindow, 30, None, false);

fn at_ms(unix_ms: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(unix_ms)
}

#[test]
fn a_completion_is_kept_in_a_record_only_its_owner_can_read_and_reads_back_with_its_age() {
    let _lock = env_lock();
    let state = StateDir::new("round-trip");
    let _env = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let facts = Facts::RGB;
    let identity = facts.identity();
    let now = at_ms(1_700_000_000_123);
    let store = state.store();
    assert_eq!(store.load(&identity, now), None, "nothing is kept yet");

    store.record(&identity, now).unwrap();

    assert_eq!(store.load(&identity, now), Some(Duration::ZERO));
    assert_eq!(
        store.load(&identity, now + Duration::from_secs(60)),
        Some(Duration::from_secs(60))
    );
    // The record is named by the digest alone and lives where the
    // production store keeps it under the state directory.
    let path = state
        .0
        .join("rate-evidence")
        .join(format!("{}.json", identity.hex()));
    assert_eq!(store.record_path(&identity), path);
    assert_eq!(Store::system().record_path(&identity), path, "IRLUME_STATE_DIR moves it");
    let entries: Vec<_> = std::fs::read_dir(state.0.join("rate-evidence"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [path.file_name().unwrap()], "no temporary file is left behind");
    let metadata = std::fs::metadata(&path).unwrap();
    // SAFETY: geteuid reads this process's own credentials and cannot fail.
    let euid = unsafe { libc::geteuid() };
    assert!(metadata.is_file(), "not a link or anything else");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), euid, "the record belongs to the user that wrote it");
    let directory = std::fs::metadata(state.0.join("rate-evidence")).unwrap();
    assert_eq!(directory.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "{\"schema\":1,\"completed_unix_ms\":1700000000123}\n",
        "the schema and the time, nothing else: no path, serial or payload"
    );

    store.remove(&identity).unwrap();
    assert!(!path.exists());
    assert_eq!(store.load(&identity, now), None);
    store.remove(&identity).expect("an absent record is already removed");
}

#[test]
fn a_completion_past_the_bound_or_in_the_future_is_no_record_and_is_removed() {
    let _lock = env_lock();
    let state = StateDir::new("staleness");
    let _env = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let store = state.store();
    let now = at_ms(1_700_000_000_000);
    let second = Duration::from_secs(1);
    for (port, age, expected) in [
        (1_u8, Duration::ZERO, Some(Duration::ZERO)),
        (2, DAY - second, Some(DAY - second)),
        (3, DAY, Some(DAY)),
        (4, DAY + second, None),
        (5, 30 * DAY, None),
    ] {
        let identity = Facts::RGB.other_port(port).identity();
        store.record(&identity, now - age).unwrap();
        assert_eq!(store.load(&identity, now), expected, "age {age:?}");
    }
    // However a file came to name a completion later than now.
    let forged = Facts::RGB.other_port(9).identity();
    store.record(&forged, now + second).unwrap();
    assert_eq!(store.load(&forged, now), None);
    // What is no record is not left behind to be read again, either.
    for port in [4_u8, 5, 9] {
        let identity = Facts::RGB.other_port(port).identity();
        assert!(!store.record_path(&identity).exists(), "port {port}");
    }
    // What is still a record stays.
    assert!(store
        .record_path(&Facts::RGB.other_port(3).identity())
        .exists());
}

#[test]
fn an_untrusted_or_unsound_record_is_no_record() {
    let _lock = env_lock();
    let state = StateDir::new("untrusted");
    let _env = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let store = state.store();
    let now = at_ms(1_700_000_000_000);
    let mut port = 20_u8;
    let mut fresh = || {
        port += 1;
        Facts::RGB.other_port(port).identity()
    };

    // Sound control: the store's own write reads back.
    let sound = fresh();
    store.record(&sound, now).unwrap();
    assert_eq!(store.load(&sound, now), Some(Duration::ZERO));

    // Missing.
    assert_eq!(store.load(&fresh(), now), None);

    // Any access for group or other, however sound the contents.
    for mode in [0o640_u32, 0o604, 0o660, 0o666, 0o644] {
        let identity = fresh();
        store.record(&identity, now).unwrap();
        std::fs::set_permissions(
            store.record_path(&identity),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert_eq!(store.load(&identity, now), None, "mode {mode:o}");
    }

    // A link standing in for the record, even to a sound one: never followed.
    let link = fresh();
    std::os::unix::fs::symlink(store.record_path(&sound), store.record_path(&link)).unwrap();
    assert_eq!(store.load(&link, now), None);
    assert_eq!(store.load(&sound, now), Some(Duration::ZERO), "the target is untouched");

    // A directory in its place.
    let directory = fresh();
    std::fs::create_dir(store.record_path(&directory)).unwrap();
    assert_eq!(store.load(&directory, now), None);

    // Contents that are not a sound record of this schema.
    let bodies: Vec<Vec<u8>> = [
        &b""[..],
        b"not json\n",
        b"{\"schema\":1}\n",
        b"{\"completed_unix_ms\":1700000000000}\n",
        b"{\"schema\":2,\"completed_unix_ms\":1700000000000}\n",
        b"{\"schema\":0,\"completed_unix_ms\":1700000000000}\n",
        b"{\"schema\":1,\"completed_unix_ms\":1700000000000,\"extra\":1}\n",
        b"{\"schema\":1,\"completed_unix_ms\":\"1700000000000\"}\n",
        b"{\"schema\":1,\"completed_unix_ms\":-1}\n",
        b"{\"schema\":1,\"completed_unix_ms\":1700000000000} trailing\n",
    ]
    .into_iter()
    .map(<[u8]>::to_vec)
    .chain([vec![b'{'; 4096]])
    .collect();
    for body in bodies {
        let identity = fresh();
        store.record(&identity, now).unwrap();
        std::fs::write(store.record_path(&identity), &body).unwrap();
        assert_eq!(
            store.load(&identity, now),
            None,
            "body {:?}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[test]
fn an_identity_follows_every_fact_it_is_bound_to() {
    let base = Facts::RGB;
    let identity = base.identity();
    let hex = identity.hex();
    assert_eq!(hex.len(), 64);
    assert!(
        hex.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(base.clone().identity(), identity, "equal facts, one identity");
    assert_eq!(crate::rate_amortization::Identity::from_hex(&hex), Some(identity));
    for malformed in [
        String::new(),
        hex.to_uppercase(),
        hex[..63].to_owned(),
        format!("{hex}0"),
        hex.replace('0', "g"),
    ] {
        assert_eq!(
            crate::rate_amortization::Identity::from_hex(&malformed),
            None,
            "{malformed:?}"
        );
    }
    for (name, other) in [
        ("vendor id", base.clone().with(|facts| facts.vid += 1)),
        ("product id", base.clone().with(|facts| facts.pid += 1)),
        (
            "serial",
            base.clone().with(|facts| facts.serial = Some("200901010002")),
        ),
        ("absent serial", base.clone().with(|facts| facts.serial = None)),
        ("port", base.clone().other_port(5)),
        (
            "controller",
            base.clone().with(|facts| facts.controller = "/devices/pci0000:00/0000:00:0d.0"),
        ),
        (
            "link speed",
            base.clone().with(|facts| facts.speed = 5_000_000),
        ),
        ("descriptor", base.clone().with(|facts| {
            facts.descriptor = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        })),
        (
            "interface",
            base.clone().with(|facts| facts.interface = 3),
        ),
        (
            "stream format",
            base.clone().with(|facts| facts.fourcc = "NV12"),
        ),
        (
            "stream interval",
            base.clone().with(|facts| facts.interval = (1, 15)),
        ),
        (
            "role",
            base.clone().with(|facts| facts.role = QualifiedStreamRole::Ir),
        ),
    ] {
        assert_ne!(
            identity,
            other.identity(),
            "a change of the {name} is another identity"
        );
    }
}

#[test]
fn a_restart_restores_the_completion_and_the_next_session_admits_on_its_probe() {
    let _lock = env_lock();
    let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let state = StateDir::new("restart");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let facts = Facts::RGB;
    let node = "/dev/video-restore";
    let key = rate_amortization::Key::new(node, facts.role()).with_identity(Some(facts.identity()));
    restart();

    // Before the restart the full window is paid and kept on disk.
    let mut before = session_on(node, &facts, 66_667, 60);
    before.fill_rate_evidence().expect("cold full fill");
    assert_eq!(recorded(&before), FULL_WINDOW);
    let path = state.store().record_path(&facts.identity());
    let kept = std::fs::read_to_string(&path).expect("the completion is kept on disk");
    assert!(!rate_amortization::test_support::restored(&key));

    // The daemon restarts: nothing of it is left in memory.
    restart();
    assert!(!rate_amortization::amortizable(&key));

    // The first session after it admits on the probe, on the record, and
    // says that the completion came from before the restart.
    let mut after = session_on(node, &facts, 66_667, 60);
    assert!(rate_amortization::test_support::restored(&key));
    after.fill_rate_evidence().expect("probe admission");
    assert_eq!(
        recorded(&after),
        (RateEvidenceDecision::ProbeAdmitted, 5, None, true)
    );
    assert!(after.health_admitted);
    // A probe admission renews nothing: the record still states the one
    // completion that was observed, so the bound still runs from it.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), kept);

    // A stream with no record still pays the full window.
    let stranger = Facts::RGB.other_port(8);
    let mut cold = session_on(node, &stranger, 66_667, 60);
    cold.fill_rate_evidence().expect("cold full fill");
    assert_eq!(recorded(&cold), FULL_WINDOW);
    restart();
}

#[test]
fn a_renumbered_node_keeps_its_completion_and_a_changed_identity_does_not() {
    let _lock = env_lock();
    let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let state = StateDir::new("renumbered");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let facts = Facts::RGB;
    restart();
    session_on("/dev/video0", &facts, 66_667, 60)
        .fill_rate_evidence()
        .expect("cold full fill");
    restart();

    // The same camera answering on another node number.
    let mut renumbered = session_on("/dev/video7", &facts, 66_667, 60);
    renumbered.fill_rate_evidence().expect("probe admission");
    assert_eq!(
        recorded(&renumbered),
        (RateEvidenceDecision::ProbeAdmitted, 5, None, true)
    );

    // The same node number, another camera or connection.
    for (index, other) in [
        Facts::RGB.other_port(4).with(|facts| facts.serial = Some("200901010002")),
        Facts::RGB.other_port(5),
        Facts::RGB.with(|facts| facts.speed = 5_000_000),
    ]
    .into_iter()
    .enumerate()
    {
        let mut stranger = session_on("/dev/video0", &other, 66_667, 60);
        stranger.fill_rate_evidence().expect("cold full fill");
        assert_eq!(recorded(&stranger), FULL_WINDOW, "identity variant {index}");
    }
    restart();
}

#[test]
fn a_forged_stale_or_corrupt_record_never_admits_a_slow_stream() {
    let _lock = env_lock();
    let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let state = StateDir::new("forged");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let store = state.store();
    let now = SystemTime::now();
    // IR at 10 fps is below its 14.55 fps floor in every window.
    let slow = Facts::RGB.with(|facts| facts.role = QualifiedStreamRole::Ir);
    let node = "/dev/video-forged";
    let key = rate_amortization::Key::new(node, slow.role()).with_identity(Some(slow.identity()));
    let path = store.record_path(&slow.identity());
    for (label, on_disk, expected, record_left) in [
        (
            "a record claiming a completion just now",
            Some(now),
            (RateEvidenceDecision::ProbeMissed, 30, Some(15), true),
            false,
        ),
        (
            "a record 23 hours old",
            Some(now - 23 * Duration::from_secs(3600)),
            (RateEvidenceDecision::ProbeMissed, 30, Some(15), true),
            false,
        ),
        (
            "a stale record, 25 hours old",
            Some(now - DAY - Duration::from_secs(3600)),
            FULL_WINDOW,
            false,
        ),
        (
            "a record naming a completion in the future",
            Some(now + Duration::from_secs(3600)),
            FULL_WINDOW,
            false,
        ),
        (
            "a corrupt record",
            Some(now),
            FULL_WINDOW,
            true,
        ),
        ("no record", None, FULL_WINDOW, false),
    ] {
        restart();
        // Whatever the previous case left behind is not this case's record.
        let _ = std::fs::remove_file(&path);
        if let Some(at) = on_disk {
            store.record(&slow.identity(), at).unwrap();
            if label.contains("corrupt") {
                // Torn: a completion no reader can make sense of.
                std::fs::write(&path, b"{\"schema\":1,\"completed_unix_ms\":17000000").unwrap();
            }
        }
        let mut stream = session_on(node, &slow, 100_000, 80);
        stream.fill_rate_evidence().expect("the window fills on readiness");
        assert_eq!(recorded(&stream), expected, "{label}");
        // However the session was established, the stream is refused.
        assert!(
            matches!(
                stream.next().map(|_| ()),
                Err(DeliveryError::BelowFloor(_))
            ),
            "{label}"
        );
        assert!(
            !rate_amortization::amortizable(&key),
            "{label}: nothing of the record survives a below-floor session"
        );
        assert_eq!(path.exists(), record_left, "{label}");
    }
    // Positive control: the same record with a stream at its floor admits
    // on the probe and delivers.
    restart();
    store.record(&slow.identity(), now).unwrap();
    let mut at_floor = session_on(node, &slow, 66_667, 60);
    at_floor.fill_rate_evidence().expect("probe admission");
    assert_eq!(
        recorded(&at_floor),
        (RateEvidenceDecision::ProbeAdmitted, 5, None, true)
    );
    assert!(at_floor.next().is_ok());
    restart();
}

#[test]
fn the_kill_switch_leaves_the_record_alone_and_a_fault_removes_it() {
    let _lock = env_lock();
    let state = StateDir::new("switch");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let facts = Facts::RGB;
    let node = "/dev/video-switch";
    let key = rate_amortization::Key::new(node, facts.role()).with_identity(Some(facts.identity()));
    let path = state.store().record_path(&facts.identity());
    restart();
    {
        let _off = EnvGuard::set("IRLUME_RATE_AMORTIZATION", "0");
        let mut stream = session_on(node, &facts, 66_667, 60);
        stream.fill_rate_evidence().expect("full fill");
        assert_eq!(
            recorded(&stream).0,
            RateEvidenceDecision::DisabledFullWindow
        );
        assert!(!path.exists(), "nothing is kept with reuse switched off");
        stream.invalidate_rate_evidence();
    }
    // A record the switch did not let this process write is read again once
    // reuse is back on.
    state.store().record(&facts.identity(), SystemTime::now()).unwrap();
    restart();
    let mut stream = session_on(node, &facts, 66_667, 60);
    stream.fill_rate_evidence().expect("probe admission");
    assert_eq!(recorded(&stream).0, RateEvidenceDecision::ProbeAdmitted);
    {
        let _off = EnvGuard::set("IRLUME_RATE_AMORTIZATION", "0");
        stream.invalidate_rate_evidence();
        assert!(path.exists(), "nothing is removed with reuse switched off");
    }
    // A held-side fault revokes the evidence everywhere it is kept.
    stream.invalidate_rate_evidence();
    assert!(!path.exists());
    assert!(!rate_amortization::amortizable(&key));
    restart();
    let mut stream = session_on(node, &facts, 66_667, 60);
    stream.fill_rate_evidence().expect("full fill after the fault");
    assert_eq!(recorded(&stream), FULL_WINDOW);
    restart();
}

#[test]
fn a_restore_never_replaces_what_this_process_observed() {
    let _lock = env_lock();
    let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let state = StateDir::new("observed");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let facts = Facts::RGB;
    let node = "/dev/video-observed";
    let key = rate_amortization::Key::new(node, facts.role()).with_identity(Some(facts.identity()));
    restart();
    session_on(node, &facts, 66_667, 60)
        .fill_rate_evidence()
        .expect("cold full fill");
    // Someone rewrites the record to an older completion.
    state
        .store()
        .record(&facts.identity(), SystemTime::now() - Duration::from_secs(3600))
        .unwrap();
    rate_amortization::restore(&key);
    assert!(
        !rate_amortization::test_support::restored(&key),
        "this process observed the newer completion itself"
    );
    assert!(rate_amortization::amortizable(&key));
    restart();
}

#[test]
fn the_store_keeps_a_bounded_number_of_records() {
    let _lock = env_lock();
    let state = StateDir::new("bounded");
    let _env = EnvGuard::set("IRLUME_STATE_DIR", &state.0);
    let store = state.store();
    let now = at_ms(1_700_000_000_000);
    let identities: Vec<_> = (0..34)
        .map(|index| Facts::RGB.other_port(index).identity())
        .collect();
    for (index, identity) in identities.iter().enumerate() {
        store
            .record(identity, now + Duration::from_secs(index as u64 * 60))
            .unwrap();
    }
    let kept: Vec<_> = identities
        .iter()
        .enumerate()
        .filter(|(_, identity)| store.record_path(identity).exists())
        .map(|(index, _)| index)
        .collect();
    assert_eq!(kept, (2..34).collect::<Vec<_>>(), "the oldest two went first");
    // A file that is no sound record goes before any sound one.
    std::fs::write(store.record_path(&identities[33]), b"garbage").unwrap();
    store.record(&identities[2], now).unwrap();
    assert!(
        !store.record_path(&identities[33]).exists(),
        "the unsound file was removed"
    );
    assert!(store.record_path(&identities[2]).exists());
    assert!(store.record_path(&identities[3]).exists());
}

/// `RgbCamera` and `IrCamera` sessions exist only with a camera, so the
/// wiring that gives a production stream its identity is pinned by shape:
/// each session constructor collects it once, first, from the facts of its
/// own open descriptor and hands it to the rate evidence. The store and
/// the policy are exercised by the tests above.
#[test]
fn sessions_collect_their_identity_from_their_own_open_descriptor() {
    let lib = include_str!("lib.rs");
    // The text of the item that starts at `signature`, up to the closing
    // brace at column 4 of an item inside an `impl`.
    fn item<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} moved; update this test"));
        let end = source[start..]
            .find("\n    }")
            .expect("an item that ends at column 4");
        &source[start..start + end]
    }
    for (owner, constructor) in [
        ("\nimpl RgbCamera {", "pub fn session_with_control("),
        ("\nimpl IrCamera {", "fn session_with_control_startup_metadata<'a>("),
    ] {
        let body = source_body(lib, owner);
        let collector = item(body, "fn rate_evidence_identity(&self)");
        assert!(
            collector.contains("self.qualification_facts()"),
            "{owner}: the identity is the fd-bound qualification facts"
        );
        assert!(
            collector.contains("Identity::for_stream("),
            "{owner}: the identity is the digest of those facts"
        );
        let constructor = item(body, constructor);
        assert!(
            constructor.contains(".with_rate_identity(rate_identity)"),
            "{owner}: the session hands its identity to its rate evidence"
        );
        let collected = constructor
            .find("let rate_identity = self.rate_evidence_identity();")
            .expect("the identity is collected once");
        assert!(
            collected < constructor.find("SafeStream::open(").expect("the stream opens"),
            "{owner}: the identity is collected before the stream opens"
        );
    }
    // The two hand-built diagnostic readers keep process-local evidence.
    for reader in [
        "\npub fn capture_ir_streaming<B>(",
        "\npub fn capture_ir_sequence(",
    ] {
        assert!(
            !source_body(lib, reader).contains("with_rate_identity("),
            "{reader} is a diagnostic reader and keeps no record"
        );
    }
}
