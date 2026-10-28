// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

fn packet() -> [u8; REQUEST_BYTES] {
    let mut data = [0; REQUEST_BYTES];
    data[..8].copy_from_slice(b"IRLMJOB1");
    data[8] = 6;
    data[9..15].copy_from_slice(b"run-01");
    data[73] = 0;
    data[80..88].copy_from_slice(&41_u64.to_le_bytes());
    data[88..96].copy_from_slice(&100_u64.to_le_bytes());
    data[96..104].copy_from_slice(&(100 + 20 * kernel::SECOND).to_le_bytes());
    data[104..108].copy_from_slice(&4242_u32.to_le_bytes());
    data[108..116].copy_from_slice(&3_u64.to_le_bytes());
    data[116..124].copy_from_slice(&123_u64.to_le_bytes());
    data[124..156].fill(0xaa);
    data[156..188].fill(0xbb);
    data[188..220].fill(0xcc);
    data[220..236].fill(0x11);
    data
}

#[test]
fn request_decodes_exact_fixed_protocol_and_keeps_reservation() {
    let request = Request::decode(&packet()).unwrap();
    assert_eq!(request.run_id, "run-01");
    assert_eq!(request.epoch, 41);
    assert_eq!(request.case, kernel::Case::SupervisorOnly);
    assert_eq!(request.reservation.origin(), 100);
    assert_eq!(request.reservation.deadline(), 100 + 20 * kernel::SECOND);
    assert_eq!(
        request.context().build_sha256,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        request.context().guest_boot_id,
        "11111111-1111-1111-1111-111111111111"
    );
}

#[test]
fn request_rejects_unbounded_unknown_and_noncanonical_fields() {
    assert!(Request::decode(&packet()[..REQUEST_BYTES - 1]).is_err());
    let mut extra = packet().to_vec();
    extra.push(0);
    assert!(Request::decode(&extra).is_err());
    for (index, value) in [
        (0, b'X'),
        (8, 0),
        (8, 65),
        (9, b'/'),
        (15, 1),
        (73, 21),
        (74, 6),
        (75, 1),
    ] {
        let mut data = packet();
        data[index] = value;
        assert!(Request::decode(&data).is_err(), "offset {index}");
    }
    for range in [80..88, 96..104, 104..108, 116..124] {
        let mut data = packet();
        data[range.clone()].fill(0);
        assert!(Request::decode(&data).is_err(), "range {range:?}");
    }
}

fn facts() -> Facts {
    let mut ns = std::array::from_fn(|i| FileId {
        device: 7,
        inode: i as u64 + 1,
    });
    ns[8] = ns[2];
    ns[9] = ns[7];
    let fd = |n, kind, readable, writable, nonblocking| FdFacts {
        id: FileId {
            device: 3,
            inode: n,
        },
        kind,
        readable,
        writable,
        nonblocking,
        cgroup2: kind == FdKind::Directory,
        peer: if kind == FdKind::UnixStream {
            Some(Peer {
                pid: 4242,
                uid: 0,
                gid: 0,
            })
        } else {
            None
        },
    };
    Facts {
        pid: 4243,
        parent_pid: 4242,
        proc_pid: 4243,
        uids: [0; 4],
        gids: [0; 4],
        threads: 1,
        children: 0,
        tracer: 0,
        signals: [0; 3],
        auto_reap: false,
        procfs: true,
        argv_ok: true,
        env_empty: true,
        parent_live: true,
        current_ns: ns,
        initial_ns: ns,
        parent_ns: ns,
        namespace_owners: [ns[0]; 10],
        roots: [FileId {
            device: 3,
            inode: 99,
        }; 3],
        boot_uuid: [0x11; 16],
        executable_sha256: [0xbb; 32],
        fds: [
            fd(1, FdKind::Null, true, false, false),
            fd(2, FdKind::Pipe, false, true, true),
            fd(3, FdKind::Pipe, false, true, true),
            fd(123, FdKind::Directory, true, false, false),
            fd(5, FdKind::UnixStream, true, true, true),
        ],
        fd_inventory: vec![0, 1, 2, 3, 4],
        manager_path: "/system.slice/irlume-job-run-01.service/managers".into(),
        jobs_path: "/sys/fs/cgroup/system.slice/irlume-job-run-01.service/jobs".into(),
        expected_jobs: FileId {
            device: 3,
            inode: 123,
        },
        jobs_domain: true,
        jobs_empty: true,
        controllers: vec!["cpu".into(), "memory".into(), "pids".into()],
    }
}

#[test]
fn preflight_requires_exact_process_and_descriptor_roles() {
    let request = Request::decode(&packet()).unwrap();
    validate_facts(&request, &facts()).unwrap();
    for change in 0..18 {
        let mut f = facts();
        match change {
            0 => f.uids[2] = 1000,
            1 => f.gids[3] = 1,
            2 => f.threads = 2,
            3 => f.children = 1,
            4 => f.tracer = 1,
            5 => f.signals[0] = 1,
            6 => f.signals[1] = 1,
            7 => f.signals[2] = 1,
            8 => f.auto_reap = true,
            9 => f.proc_pid += 1,
            10 => f.parent_pid += 1,
            11 => f.parent_live = false,
            12 => f.argv_ok = false,
            13 => f.env_empty = false,
            14 => f.procfs = false,
            15 => f.fds[1].nonblocking = false,
            16 => f.fds[4].peer.as_mut().unwrap().uid = 1,
            17 => f.fd_inventory.push(5),
            _ => unreachable!(),
        }
        assert!(validate_facts(&request, &f).is_err(), "change {change}");
    }
}

#[test]
fn preflight_requires_shared_namespaces_exact_objects_and_empty_domain() {
    let request = Request::decode(&packet()).unwrap();
    for change in 0..12 {
        let mut f = facts();
        match change {
            0 => f.current_ns[2].inode += 100,
            1 => f.namespace_owners[3].inode += 1,
            2 => f.parent_ns[0].inode += 1,
            3 => f.initial_ns[9].inode += 1,
            4 => f.roots[2].inode += 1,
            5 => f.executable_sha256[0] ^= 1,
            6 => f.boot_uuid[0] ^= 1,
            7 => f.fds[3].id.inode += 1,
            8 => f.manager_path = f.jobs_path.clone(),
            9 => f.jobs_domain = false,
            10 => f.jobs_empty = false,
            11 => f.controllers.push("cpu".into()),
            _ => unreachable!(),
        }
        assert!(validate_facts(&request, &f).is_err(), "change {change}");
    }
    for slot in 0..5 {
        let mut f = facts();
        f.fds[slot].kind = FdKind::Other;
        assert!(validate_facts(&request, &f).is_err());
    }
}

fn report() -> kernel::Report {
    kernel::Report {
        bounds: None,
        case: kernel::Case::SupervisorOnly,
        reached: None,
        injected: false,
        registered: false,
        placed: false,
        placement_verified: false,
        worker_pid: None,
        descendant_pid: None,
        worker_reaped: false,
        descendant_reaped: false,
        oom_observations: 0,
        oom_kills: [0; 3],
        epoch: 41,
        outcome: kernel::Outcome::Complete,
        reserved: true,
        leases_held: [false; 2],
        custody_retained: false,
        releases: 1,
        first: None,
        errors: [None; 16],
        errors_truncated: false,
        kill: true,
        empty: true,
        direct_reaped: true,
        drained: true,
        consumers: 0,
        adopted: 0,
        terminal: [None; 33],
        operations: 30,
        native_authorized: false,
        full_contract_proven: false,
    }
}

struct Token(std::rc::Rc<std::cell::Cell<usize>>);
impl Drop for Token {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

struct Fake {
    now: u64,
    fault: Option<&'static str>,
    advance: Option<&'static str>,
    invalid_facts: bool,
    bytes: Vec<u8>,
    calls: Vec<&'static str>,
    transaction: Option<Transaction<Token, Token>>,
    request: Vec<u8>,
    confirmation_clock: Option<Result<u64>>,
}

impl Fake {
    fn step(&mut self, name: &'static str) -> Result<()> {
        self.calls.push(name);
        if self.advance == Some(name) {
            self.now = 100 + 20 * kernel::SECOND;
        }
        if self.fault == Some(name)
            || (self.fault == Some("clock-after-execute")
                && name == "clock"
                && self.calls.contains(&"execute"))
        {
            Err(failure(name, 5))
        } else {
            Ok(())
        }
    }
}

impl Platform for Fake {
    type Handle = Token;
    type Quarantine = Token;
    fn now(&mut self) -> Result<u64> {
        self.step("clock")?;
        Ok(self.now)
    }
    fn read_request(&mut self, _: Reservation) -> Result<Vec<u8>> {
        self.step("request")?;
        Ok(self.request.clone())
    }
    fn observe(&mut self, _: &Request) -> Result<Facts> {
        self.step("observe")?;
        let mut value = facts();
        if self.invalid_facts {
            value.threads = 2;
        }
        Ok(value)
    }
    fn execute(&mut self, _: &Request) -> Result<Transaction<Token, Token>> {
        self.step("execute")?;
        Ok(self.transaction.take().unwrap())
    }
    fn close_sentinel(&mut self, _: Token) -> Result<()> {
        self.step("sentinel-close")
    }
    fn prepare_report(&mut self) -> Result<()> {
        self.step("prepare-report")
    }
    fn write_report(&mut self, data: &[u8]) -> Result<usize> {
        self.step("write")?;
        if self.fault == Some("write-epipe") {
            return Err(failure("write", 32));
        }
        if self.fault == Some("write-retry") {
            return Err(failure("write", 11));
        }
        if self.fault == Some("write-zero") {
            return Ok(0);
        }
        let count = if self.fault == Some("write-short") {
            data.len().min(64)
        } else {
            data.len()
        };
        self.bytes.extend_from_slice(&data[..count]);
        Ok(count)
    }
    fn wait_report(&mut self, _: Reservation) -> Result<()> {
        self.step("wait")
    }
    fn close_report(&mut self) -> Result<()> {
        self.step("report-close")
    }
    fn confirm_quarantine(&mut self, reservation: Reservation) -> Result<()> {
        self.step("quarantine-stop")?;
        let now = self.confirmation_clock.take().unwrap_or(Ok(self.now))?;
        reservation.remaining(now).map(|_| ())
    }
}

fn fake(quarantine: bool) -> (Fake, std::rc::Rc<std::cell::Cell<usize>>, Admission) {
    let drops = std::rc::Rc::new(std::cell::Cell::new(0));
    let request = Request::decode(&packet()).unwrap();
    let reservation = Some(request.reservation);
    let transaction = if quarantine {
        let mut r = report();
        r.outcome = kernel::Outcome::Incomplete;
        r.releases = 0;
        r.leases_held = [true; 2];
        r.custody_retained = true;
        Transaction::Quarantined {
            report: r,
            reservation,
            owner: Box::new(Token(drops.clone())),
        }
    } else {
        Transaction::Clean {
            report: report(),
            reservation,
            sentinel: Some(Token(drops.clone())),
        }
    };
    (
        Fake {
            now: 100,
            fault: None,
            advance: None,
            invalid_facts: false,
            bytes: vec![],
            calls: vec![],
            transaction: Some(transaction),
            request: packet().to_vec(),
            confirmation_clock: None,
        },
        drops,
        Admission { expected: request },
    )
}

#[test]
fn missing_admission_or_mismatched_input_never_invokes_native() {
    let (mut os, _, admission) = fake(false);
    assert!(matches!(
        drive(&mut os, None),
        RunOutcome::Exit { code: 77, .. }
    ));
    assert!(os.calls.is_empty());
    os.request[80] += 1;
    assert!(matches!(
        drive(&mut os, Some(&admission)),
        RunOutcome::Exit { code: 77, .. }
    ));
    assert!(!os.calls.contains(&"execute"));
    let (mut os, _, admission) = fake(false);
    os.invalid_facts = true;
    assert!(matches!(
        drive(&mut os, Some(&admission)),
        RunOutcome::Exit { code: 77, .. }
    ));
    assert!(!os.calls.contains(&"execute"));
}

#[test]
fn clean_finalization_closes_once_then_reports_within_same_budget() {
    let (mut os, drops, admission) = fake(false);
    assert!(matches!(
        drive(&mut os, Some(&admission)),
        RunOutcome::Exit { code: 0, .. }
    ));
    assert_eq!(drops.get(), 1);
    assert_eq!(
        os.calls.iter().filter(|n| **n == "sentinel-close").count(),
        1
    );
    assert_eq!(os.calls.iter().filter(|n| **n == "report-close").count(), 1);
    assert!(
        os.calls.iter().position(|n| *n == "sentinel-close")
            < os.calls.iter().position(|n| *n == "write")
    );
    let value: serde_json::Value = serde_json::from_slice(&os.bytes[4..]).unwrap();
    assert_eq!(value["report"]["epoch"], 41);
    assert_eq!(value["report"]["native_authorized"], false);
}

#[test]
fn finalization_failures_and_overruns_cannot_return_success() {
    for stage in ["execute", "sentinel-close", "write", "report-close"] {
        for expired in [false, true] {
            let (mut os, _, admission) = fake(false);
            if expired {
                os.advance = Some(stage);
            } else {
                os.fault = Some(stage);
            }
            assert!(
                matches!(
                    drive(&mut os, Some(&admission)),
                    RunOutcome::Exit { code: 77, .. }
                ),
                "{stage}/{expired}"
            );
            assert!(os.calls.iter().filter(|n| **n == "report-close").count() <= 1);
        }
    }
}

#[test]
fn quarantine_confirmation_follows_finalization_and_never_failed_reporting() {
    for stage in [
        None,
        Some("write"),
        Some("report-close"),
        Some("quarantine-stop"),
    ] {
        let (mut os, drops, admission) = fake(true);
        os.fault = stage;
        let result = drive(&mut os, Some(&admission));
        assert_eq!(drops.get(), 0);
        assert!(matches!(&result, RunOutcome::Hold { .. }));
        if stage.is_none() {
            assert_eq!(os.calls.last(), Some(&"quarantine-stop"));
            let stop = os
                .calls
                .iter()
                .position(|n| *n == "quarantine-stop")
                .unwrap();
            assert!(os.calls.iter().position(|n| *n == "report-close").unwrap() < stop);
            assert!(matches!(&result, RunOutcome::Hold { failure: None, .. }));
        } else {
            assert!(matches!(
                &result,
                RunOutcome::Hold {
                    failure: Some(_),
                    ..
                }
            ));
            if stage != Some("quarantine-stop") {
                assert!(!os.calls.contains(&"quarantine-stop"));
            }
        }
        drop(result);
        assert_eq!(drops.get(), 1);
    }
    let (mut os, drops, admission) = fake(true);
    os.advance = Some("report-close");
    let result = drive(&mut os, Some(&admission));
    assert!(matches!(
        &result,
        RunOutcome::Hold {
            failure: Some(_),
            ..
        }
    ));
    assert!(!os.calls.contains(&"quarantine-stop"));
    assert_eq!(drops.get(), 0);
    let (mut clean, _, admission) = fake(false);
    assert!(matches!(
        drive(&mut clean, Some(&admission)),
        RunOutcome::Exit { code: 0, .. }
    ));
    assert!(!clean.calls.contains(&"quarantine-stop"));
}

#[test]
fn confirmation_clock_failure_or_expiry_keeps_owner_without_retry() {
    for observation in [
        Ok(99),
        Ok(100 + 20 * kernel::SECOND),
        Ok(101 + 20 * kernel::SECOND),
        Err(failure("confirmation-clock", 5)),
    ] {
        let (mut os, drops, admission) = fake(true);
        os.confirmation_clock = Some(observation);
        let result = drive(&mut os, Some(&admission));
        assert!(matches!(
            result,
            RunOutcome::Hold {
                failure: Some(_),
                ..
            }
        ));
        assert_eq!(drops.get(), 0);
        assert_eq!(
            os.calls
                .iter()
                .filter(|call| **call == "quarantine-stop")
                .count(),
            1
        );
        assert!(
            os.calls.iter().position(|call| *call == "report-close")
                < os.calls.iter().position(|call| *call == "quarantine-stop")
        );
        assert!(!os.bytes.is_empty());
        assert!(!os.calls.contains(&"sentinel-close"));
        drop(result);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn quarantined_owner_survives_every_post_native_failure() {
    for stage in [None, Some("write"), Some("report-close")] {
        for expired in [false, true] {
            let (mut os, drops, admission) = fake(true);
            os.fault = stage;
            if expired {
                os.advance = Some("execute");
            }
            let result = drive(&mut os, Some(&admission));
            assert!(matches!(result, RunOutcome::Hold { .. }));
            assert_eq!(drops.get(), 0);
            assert!(!os.calls.contains(&"sentinel-close"));
            drop(result);
            assert_eq!(drops.get(), 1);
        }
    }
}

#[test]
fn process_status_parser_requires_unique_complete_numeric_fields() {
    let good = b"Name:\tfixture\nPid:\t4243\nPPid:\t4242\nUid:\t0 0 0 0\nGid:\t0 0 0 0\nThreads:\t1\nTracerPid:\t0\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\n";
    let parsed = parse_status(good).unwrap();
    assert_eq!(parsed.pid, 4243);
    assert_eq!(parsed.parent_pid, 4242);
    assert_eq!(parsed.uids, [0; 4]);
    for bad in [
        String::from_utf8(good.to_vec())
            .unwrap()
            .replace("Threads:\t1\n", ""),
        String::from_utf8(good.to_vec()).unwrap() + "Pid: 4243\n",
        String::from_utf8(good.to_vec())
            .unwrap()
            .replace("0 0 0 0", "0 0 0"),
        String::from_utf8(good.to_vec())
            .unwrap()
            .replace("4243", "+4243"),
        String::from_utf8(good.to_vec())
            .unwrap()
            .replace("0000000000000000", "xyz"),
    ] {
        assert!(parse_status(bad.as_bytes()).is_err());
    }
}

#[test]
fn startup_failure_or_expiry_never_calls_execute() {
    for stage in ["request", "observe"] {
        for expired in [false, true] {
            let (mut os, _, admission) = fake(false);
            if expired {
                os.advance = Some(stage);
            } else {
                os.fault = Some(stage);
            }
            assert!(matches!(
                drive(&mut os, Some(&admission)),
                RunOutcome::Exit { code: 77, .. }
            ));
            assert!(!os.calls.contains(&"execute"));
        }
    }
}

#[test]
fn missing_completion_budget_cannot_restart_finalization() {
    for quarantine in [false, true] {
        let (mut os, drops, admission) = fake(quarantine);
        match os.transaction.as_mut().unwrap() {
            Transaction::Clean { reservation, .. }
            | Transaction::Quarantined { reservation, .. } => *reservation = None,
        }
        let result = drive(&mut os, Some(&admission));
        assert_eq!(drops.get(), 0);
        assert!(os.bytes.is_empty());
        if quarantine {
            assert!(matches!(result, RunOutcome::Hold { .. }));
        } else {
            assert!(matches!(
                result,
                RunOutcome::Exit {
                    code: 77,
                    retained: Some(_),
                    ..
                }
            ));
        }
    }
}

#[test]
fn partial_writes_complete_but_zero_and_infinite_retry_refuse() {
    for mode in ["write-short", "write-zero", "write-retry"] {
        let (mut os, _, admission) = fake(false);
        os.fault = Some(mode);
        let outcome = drive(&mut os, Some(&admission));
        let expected = if mode == "write-short" { 0 } else { 77 };
        assert!(matches!(outcome, RunOutcome::Exit { code, .. } if code == expected));
        assert!(os.calls.iter().filter(|n| **n == "write").count() <= 1024);
        if mode == "write-short" {
            assert!(os.calls.iter().filter(|n| **n == "write").count() > 1);
        }
    }
}

#[test]
fn post_native_clock_and_encoding_failure_hold_quarantine() {
    for encoding in [false, true] {
        let (mut os, drops, admission) = fake(true);
        if encoding {
            let Transaction::Quarantined { report, .. } = os.transaction.as_mut().unwrap() else {
                unreachable!()
            };
            report.native_authorized = true;
        } else {
            os.fault = Some("clock-after-execute");
        }
        let outcome = drive(&mut os, Some(&admission));
        assert!(matches!(
            outcome,
            RunOutcome::Hold {
                failure: Some(_),
                ..
            }
        ));
        assert_eq!(drops.get(), 0);
        assert!(os.bytes.is_empty());
    }
}

#[test]
fn expired_clean_return_retains_unclosed_sentinel_for_process_exit() {
    let (mut os, drops, admission) = fake(false);
    os.advance = Some("execute");
    let outcome = drive(&mut os, Some(&admission));
    assert!(matches!(
        outcome,
        RunOutcome::Exit {
            code: 77,
            retained: Some(_),
            ..
        }
    ));
    assert_eq!(drops.get(), 0);
    assert!(!os.calls.contains(&"sentinel-close"));
    drop(outcome);
    assert_eq!(drops.get(), 1);
}

#[test]
fn jobs_path_uses_the_native_filesystem_coordinate_system() {
    let request = Request::decode(&packet()).unwrap();
    let mut observed = facts();
    observed.jobs_path = "/sys/fs/cgroup/system.slice/irlume-job-run-01.service/jobs".into();
    validate_facts(&request, &observed).unwrap();
    observed.expected_jobs.inode += 1;
    assert!(validate_facts(&request, &observed).is_err());
    observed.expected_jobs.inode -= 1;
    observed.jobs_path = "/system.slice/irlume-job-run-01.service/jobs".into();
    assert!(validate_facts(&request, &observed).is_err());
}

// A small supervisor-only effect model executes the original run_reserved and
// disposal code. Descriptor numbers are synthetic; no syscalls or native entry.
struct CleanupPlatform {
    alive: std::collections::BTreeSet<u32>,
    closed: Vec<u32>,
    killed: bool,
    fail_parent_close: bool,
    prepared: bool,
    bytes: Vec<u8>,
}

impl CleanupPlatform {
    fn new(fail_parent_close: bool) -> Self {
        Self {
            alive: [0, 1, 2, 3, 4].into(),
            closed: vec![],
            killed: false,
            fail_parent_close,
            prepared: false,
            bytes: vec![],
        }
    }
    fn allocate(&mut self, n: u32) -> u32 {
        assert!(self.alive.insert(n));
        n
    }
}

impl kernel::Effects for CleanupPlatform {
    type Handle = u32;
    fn clock(&mut self) -> Result<u64> {
        Ok(100)
    }
    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }
    fn acquire(&mut self, kind: kernel::Kind, _: &kernel::Resources<u32>) -> Result<u32> {
        Ok(match kind {
            kernel::Kind::Parent => 3,
            kernel::Kind::Evidence => 4,
            _ => self.allocate(10 + kind as u32),
        })
    }
    fn mkdir(&mut self, _: kernel::Group, _: &kernel::Resources<u32>) -> Result<()> {
        Ok(())
    }
    fn configure(&mut self, _: &kernel::Resources<u32>) -> Result<()> {
        Ok(())
    }
    fn channels(&mut self) -> Result<(u32, u32)> {
        Ok((self.allocate(30), self.allocate(31)))
    }
    fn handle_number(&self, handle: &u32) -> u64 {
        u64::from(*handle)
    }
    fn birth(
        &mut self,
        _: kernel::CloneRequest,
        _: &kernel::Resources<u32>,
        _: u64,
        _: u64,
    ) -> Result<kernel::Child<u32>> {
        Ok(kernel::Child {
            pid: 77,
            pidfd: Some(self.allocate(42)),
            valid: true,
        })
    }
    fn parked(&mut self, _: &kernel::Resources<u32>, _: &kernel::Child<u32>) -> Result<()> {
        Ok(())
    }
    fn read(
        &mut self,
        kind: kernel::Read,
        _: &kernel::Resources<u32>,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize> {
        let message;
        let data = match kind {
            kernel::Read::Population => &b"populated 0\nfrozen 0\n"[..],
            kernel::Read::Ready | kernel::Read::Complete => {
                message = kernel::message(if kind == kernel::Read::Ready { 1 } else { 2 }, 41);
                &message[..]
            }
            _ => panic!("unexpected supervisor-only read"),
        };
        let count = output.len().min(data.len().saturating_sub(offset));
        output[..count].copy_from_slice(&data[offset..offset + count]);
        Ok(count)
    }
    fn write(
        &mut self,
        kind: kernel::Write,
        _: &kernel::Resources<u32>,
        data: &[u8],
    ) -> Result<usize> {
        if kind == kernel::Write::Kill {
            self.killed = true;
        }
        Ok(data.len())
    }
    fn wait(&mut self, child: Option<&kernel::Child<u32>>, consume: bool) -> Result<kernel::Wait> {
        Ok(if let Some(child) = child {
            if consume {
                assert!(self.killed);
                kernel::Wait::Terminal {
                    pid: child.pid,
                    code: 1,
                    status: 0,
                }
            } else {
                kernel::Wait::Pending
            }
        } else {
            kernel::Wait::NoChildren
        })
    }
    fn pause(&mut self, _: u64) -> Result<()> {
        panic!("unexpected supervisor-only pause")
    }
    fn remove(&mut self, _: kernel::Group, _: &kernel::Resources<u32>) -> Result<()> {
        assert!(self.killed);
        Ok(())
    }
    fn close(&mut self, handle: u32) -> Result<()> {
        assert!(
            self.alive.remove(&handle),
            "unowned or repeated close {handle}"
        );
        self.closed.push(handle);
        if handle == 3 && self.fail_parent_close {
            Err(failure("parent-close", 5))
        } else {
            Ok(())
        }
    }
    fn registration(
        &mut self,
        _: &kernel::Resources<u32>,
        _: &mut [u8],
    ) -> Result<kernel::Transfer<u32>> {
        panic!("unexpected registration")
    }
    fn worker_identity(&mut self, _: &kernel::Child<u32>, _: kernel::Case, _: u32) -> Result<()> {
        panic!("unexpected worker")
    }
    fn members(&mut self, _: &kernel::Resources<u32>, _: &[u32], _: &[u32]) -> Result<()> {
        panic!("unexpected members")
    }
    fn place(&mut self, _: &kernel::Resources<u32>, _: &kernel::Child<u32>) -> Result<()> {
        panic!("unexpected placement")
    }
    fn signal(&mut self, _: &kernel::Child<u32>) -> Result<()> {
        panic!("unexpected signal")
    }
    fn oom_kills(&mut self, _: &kernel::Resources<u32>) -> Result<[u64; 3]> {
        panic!("unexpected OOM check")
    }
    fn initialize_sentinel(&mut self, _: &kernel::Resources<u32>, _: u64) -> Result<()> {
        panic!("unexpected sentinel")
    }
    fn verify_sentinel(&mut self, _: &kernel::Resources<u32>, _: u64, _: bool) -> Result<()> {
        panic!("unexpected sentinel")
    }
    fn arm_work(&mut self, _: u64) -> Result<()> {
        panic!("unexpected work cap")
    }
    fn worker_terminal(&mut self, _: &kernel::Child<u32>) -> Result<bool> {
        panic!("unexpected worker")
    }
}

impl Platform for CleanupPlatform {
    type Handle = u32;
    type Quarantine = kernel::Quarantine<u32>;
    fn now(&mut self) -> Result<u64> {
        Ok(100)
    }
    fn read_request(&mut self, _: Reservation) -> Result<Vec<u8>> {
        Ok(packet().to_vec())
    }
    fn observe(&mut self, _: &Request) -> Result<Facts> {
        Ok(facts())
    }
    fn execute(&mut self, request: &Request) -> Result<Transaction<u32, Self::Quarantine>> {
        let result = kernel::run_reserved(
            self,
            request.epoch,
            request.case,
            request.reservation.origin(),
            request.reservation.deadline(),
        );
        let reservation = result.reservation();
        Ok(match result {
            kernel::Completion::Clean {
                report, sentinel, ..
            } => Transaction::Clean {
                report,
                reservation,
                sentinel,
            },
            kernel::Completion::Quarantined(owner) => Transaction::Quarantined {
                report: owner.report.clone(),
                reservation,
                owner: Box::new(owner),
            },
        })
    }
    fn close_sentinel(&mut self, handle: u32) -> Result<()> {
        kernel::Effects::close(self, handle)
    }
    fn prepare_report(&mut self) -> Result<()> {
        assert!(!self.prepared);
        assert!(
            !self.alive.contains(&4),
            "E channel not disposed before reporting"
        );
        assert!(self.closed.contains(&4));
        self.prepared = true;
        Ok(())
    }
    fn write_report(&mut self, bytes: &[u8]) -> Result<usize> {
        assert!(self.prepared && self.alive.contains(&1));
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn wait_report(&mut self, _: Reservation) -> Result<()> {
        panic!("unexpected report wait")
    }
    fn close_report(&mut self) -> Result<()> {
        kernel::Effects::close(self, 1)
    }
    fn confirm_quarantine(&mut self, reservation: Reservation) -> Result<()> {
        assert!(!self.alive.contains(&1));
        reservation.remaining(100).map(|_| ())
    }
}

#[test]
fn original_kernel_disposal_preserves_report_fd_and_late_failure_custody() {
    for late_failure in [false, true] {
        let mut os = CleanupPlatform::new(late_failure);
        let admission = Admission {
            expected: Request::decode(&packet()).unwrap(),
        };
        let outcome = drive(&mut os, Some(&admission));
        let value: serde_json::Value = serde_json::from_slice(&os.bytes[4..]).unwrap();
        assert_eq!(value["report"]["epoch"], 41);
        assert_eq!(os.closed.iter().filter(|n| **n == 1).count(), 1);
        assert!(os.closed.iter().position(|n| *n == 4) < os.closed.iter().position(|n| *n == 1));
        if late_failure {
            let RunOutcome::Hold {
                owner,
                failure: None,
            } = outcome
            else {
                panic!("lost disposal-failure custody")
            };
            assert_eq!(owner.report.first, Some(failure("parent-close", 5)));
            assert_eq!(owner.report.releases, 0);
            assert_eq!(owner.report.leases_held, [true; 2]);
            assert_eq!(owner.child.as_ref().unwrap().pidfd, Some(42));
            assert!(os.alive.contains(&42));
            assert_eq!(value["report"]["custody_retained"], true);
        } else {
            assert!(matches!(outcome, RunOutcome::Exit { code: 0, .. }));
            assert_eq!(value["report"]["releases"], 1);
            assert_eq!(os.alive, [0, 2].into());
        }
    }
}

#[test]
fn report_preparation_is_after_native_and_epipe_retains_quarantine() {
    let (mut os, drops, admission) = fake(true);
    os.fault = Some("write-epipe");
    let outcome = drive(&mut os, Some(&admission));
    assert!(matches!(
        outcome,
        RunOutcome::Hold {
            failure: Some(Failure { errno: 32, .. }),
            ..
        }
    ));
    let execute = os.calls.iter().position(|n| *n == "execute").unwrap();
    let prepared = os
        .calls
        .iter()
        .position(|n| *n == "prepare-report")
        .expect("report preparation missing");
    let written = os.calls.iter().position(|n| *n == "write").unwrap();
    assert!(execute < prepared && prepared < written);
    assert_eq!(drops.get(), 0);
}

#[test]
fn report_preparation_failure_and_overrun_never_release_quarantine() {
    for quarantine in [false, true] {
        for expired in [false, true] {
            let (mut os, drops, admission) = fake(quarantine);
            if expired {
                os.advance = Some("prepare-report");
            } else {
                os.fault = Some("prepare-report");
            }
            let outcome = drive(&mut os, Some(&admission));
            if quarantine {
                assert!(matches!(
                    outcome,
                    RunOutcome::Hold {
                        failure: Some(_),
                        ..
                    }
                ));
                assert_eq!(drops.get(), 0);
            } else {
                assert!(matches!(outcome, RunOutcome::Exit { code: 77, .. }));
            }
            assert!(os.bytes.is_empty());
        }
    }
}
