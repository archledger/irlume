// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Source-prepared private M entry. Protected boot admission is supplied only by
//! a future reviewed E integration; ordinary invocation remains unavailable.

use super::{kernel, report};
use kernel::{failure, Failure, Reservation};

pub type Result<T> = std::result::Result<T, Failure>;
pub const REQUEST_BYTES: usize = 236;
pub const ENTRY_PATH: &str = "/opt/irlume/measurement_job_fixture";
pub const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileId {
    pub device: u64,
    pub inode: u64,
}

/// Fixed little-endian request, deliberately separate from the JSON report.
/// Offsets: magic0..8, run length8, run9..73, case73, sequence74, reserved75..80,
/// epoch80..88, origin88..96, total96..104, E PID104..108, jobs device108..116,
/// jobs inode116..124, boot/build/input SHA256 bytes124..220, boot UUID220..236.
/// This parsed object supplies no authority; it must equal protected expectations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    run_id: String,
    case: kernel::Case,
    sequence: u32,
    epoch: u64,
    reservation: Reservation,
    parent_pid: u32,
    jobs: FileId,
    boot_input_sha256: String,
    build_sha256: String,
    input_manifest_sha256: String,
    boot_uuid: [u8; 16],
    guest_boot_id: String,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

fn word(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| failure("request-word", 0))?,
    ))
}

impl Request {
    /// # Errors
    /// Rejects incorrect size/magic, noncanonical run ID/padding, unknown cases,
    /// out-of-range scalars or a reservation that changes the fixed time budget.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != REQUEST_BYTES || &bytes[..8] != b"IRLMJOB1" {
            return Err(failure("request-frame", 0));
        }
        let length = usize::from(bytes[8]);
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if !(1..=64).contains(&length)
            || !alnum(bytes[9])
            || !bytes[9..9 + length].iter().all(|b| alnum(*b) || *b == b'-')
            || bytes[9 + length..73].iter().any(|b| *b != 0)
            || bytes[75..80].iter().any(|b| *b != 0)
            || bytes[74] >= 6
        {
            return Err(failure("request-fields", 0));
        }
        let case = *report::CASES
            .get(usize::from(bytes[73]))
            .ok_or(failure("request-case", 0))?;
        let epoch = word(&bytes[80..88])?;
        let parent_pid = u32::from_le_bytes(
            bytes[104..108]
                .try_into()
                .map_err(|_| failure("request-pid", 0))?,
        );
        let jobs = FileId {
            device: word(&bytes[108..116])?,
            inode: word(&bytes[116..124])?,
        };
        if epoch == 0 || !(2..=i32::MAX as u32).contains(&parent_pid) || jobs.inode == 0 {
            return Err(failure("request-identity", 0));
        }
        let boot_uuid: [u8; 16] = bytes[220..236]
            .try_into()
            .map_err(|_| failure("request-uuid", 0))?;
        let uuid = hex(&boot_uuid);
        Ok(Self {
            run_id: String::from_utf8(bytes[9..9 + length].to_vec())
                .map_err(|_| failure("request-run", 0))?,
            case,
            sequence: u32::from(bytes[74]),
            epoch,
            reservation: Reservation::new(word(&bytes[88..96])?, word(&bytes[96..104])?)?,
            parent_pid,
            jobs,
            boot_input_sha256: hex(&bytes[124..156]),
            build_sha256: hex(&bytes[156..188]),
            input_manifest_sha256: hex(&bytes[188..220]),
            boot_uuid,
            guest_boot_id: format!(
                "{}-{}-{}-{}-{}",
                &uuid[..8],
                &uuid[8..12],
                &uuid[12..16],
                &uuid[16..20],
                &uuid[20..]
            ),
        })
    }

    pub fn context(&self) -> report::Context<'_> {
        report::Context {
            run_id: &self.run_id,
            boot_input_sha256: &self.boot_input_sha256,
            guest_boot_id: &self.guest_boot_id,
            build_sha256: &self.build_sha256,
            input_manifest_sha256: &self.input_manifest_sha256,
            sequence: self.sequence,
        }
    }

    pub fn unit_path(&self) -> String {
        format!("/system.slice/irlume-job-{}.service", self.run_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdKind {
    Null,
    Pipe,
    Directory,
    UnixStream,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdFacts {
    pub id: FileId,
    pub kind: FdKind,
    pub readable: bool,
    pub writable: bool,
    pub nonblocking: bool,
    pub cgroup2: bool,
    pub peer: Option<Peer>,
}

/// Bounded observations collected by the concrete backend. Namespace order is
/// user,mnt,pid,net,ipc,uts,cgroup,time,pid_for_children,time_for_children.
/// Matching observations corroborate the separately protected boot origin;
/// they do not establish that origin or exclude an inherited malicious tracer.
#[derive(Clone, Debug)]
pub struct Facts {
    pub pid: u32,
    pub parent_pid: u32,
    pub proc_pid: u32,
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub threads: u32,
    pub children: usize,
    pub tracer: u32,
    pub signals: [u64; 3],
    pub auto_reap: bool,
    pub procfs: bool,
    pub argv_ok: bool,
    pub env_empty: bool,
    pub parent_live: bool,
    pub current_ns: [FileId; 10],
    pub initial_ns: [FileId; 10],
    pub parent_ns: [FileId; 10],
    pub namespace_owners: [FileId; 10],
    pub roots: [FileId; 3],
    pub boot_uuid: [u8; 16],
    pub executable_sha256: [u8; 32],
    pub fds: [FdFacts; 5],
    pub fd_inventory: Vec<u32>,
    pub manager_path: String,
    pub jobs_path: String,
    pub expected_jobs: FileId,
    pub jobs_domain: bool,
    pub jobs_empty: bool,
    pub controllers: Vec<String>,
}

pub struct ProcessFields {
    pub pid: u32,
    pub parent_pid: u32,
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub threads: u32,
    pub tracer: u32,
    pub signals: [u64; 3],
}

/// # Errors
/// Refuses oversized/non-UTF-8 status data, missing/duplicate required fields,
/// malformed identity tuples and nonnumeric signal or process fields.
pub fn parse_status(bytes: &[u8]) -> Result<ProcessFields> {
    if bytes.len() > 16 * 1024 {
        return Err(failure("status-size", 0));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| failure("status-utf8", 0))?;
    let field = |name: &str| -> Result<&str> {
        let mut found = text.lines().filter_map(|line| line.strip_prefix(name));
        let value = found.next().ok_or(failure("status-missing", 0))?.trim();
        if found.next().is_some() {
            return Err(failure("status-duplicate", 0));
        }
        Ok(value)
    };
    let number = |value: &str| -> Result<u32> {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(failure("status-number", 0));
        }
        value.parse().map_err(|_| failure("status-number", 0))
    };
    let tuple = |name: &str| -> Result<[u32; 4]> {
        let values = field(name)?
            .split_ascii_whitespace()
            .map(number)
            .collect::<Result<Vec<_>>>()?;
        values.try_into().map_err(|_| failure("status-tuple", 0))
    };
    let mask = |name: &str| -> Result<u64> {
        let value = field(name)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(failure("status-mask", 0));
        }
        u64::from_str_radix(value, 16).map_err(|_| failure("status-mask", 0))
    };
    Ok(ProcessFields {
        pid: number(field("Pid:")?)?,
        parent_pid: number(field("PPid:")?)?,
        uids: tuple("Uid:")?,
        gids: tuple("Gid:")?,
        threads: number(field("Threads:")?)?,
        tracer: number(field("TracerPid:")?)?,
        signals: [mask("SigBlk:")?, mask("SigIgn:")?, mask("SigCgt:")?],
    })
}

/// # Errors
/// Rejects any missing or mismatched live precondition. This does not replace
/// the origin/exclusivity obligations of [`Admission::from_protected_boot`].
pub fn validate_facts(request: &Request, facts: &Facts) -> Result<()> {
    let f = facts;
    if f.pid < 2
        || f.pid == f.parent_pid
        || f.parent_pid != request.parent_pid
        || f.proc_pid != f.pid
        || f.uids != [0; 4]
        || f.gids != [0; 4]
        || f.threads != 1
        || f.children != 0
        || f.tracer != 0
        || f.signals != [0; 3]
        || f.auto_reap
        || !f.procfs
        || !f.argv_ok
        || !f.env_empty
        || !f.parent_live
    {
        return Err(failure("entry-process", 0));
    }
    if f.current_ns != f.initial_ns
        || f.parent_ns != f.initial_ns
        || f.current_ns.iter().any(|id| id.inode == 0)
        || f.current_ns[2] != f.current_ns[8]
        || f.current_ns[7] != f.current_ns[9]
        || f.namespace_owners.iter().any(|id| *id != f.initial_ns[0])
        || f.roots[0].inode == 0
        || f.roots[0] != f.roots[1]
        || f.roots[0] != f.roots[2]
    {
        return Err(failure("entry-view", 0));
    }
    if f.boot_uuid != request.boot_uuid || hex(&f.executable_sha256) != request.build_sha256 {
        return Err(failure("entry-build", 0));
    }
    if f.fd_inventory != [0, 1, 2, 3, 4] {
        return Err(failure("entry-descriptors", 0));
    }
    let [input, report, diagnostics, jobs, control] = f.fds;
    if input.kind != FdKind::Null
        || !input.readable
        || input.writable
        || [report, diagnostics]
            .iter()
            .any(|fd| fd.kind != FdKind::Pipe || fd.readable || !fd.writable || !fd.nonblocking)
        || jobs.kind != FdKind::Directory
        || !jobs.readable
        || jobs.writable
        || !jobs.cgroup2
        || jobs.id != request.jobs
        || control.kind != FdKind::UnixStream
        || !control.readable
        || !control.writable
        || !control.nonblocking
        || control.peer
            != Some(Peer {
                pid: request.parent_pid,
                uid: 0,
                gid: 0,
            })
    {
        return Err(failure("entry-descriptor-role", 0));
    }
    for (i, fd) in f.fds.iter().enumerate() {
        if fd.id.inode == 0 || f.fds[..i].iter().any(|other| other.id == fd.id) {
            return Err(failure("entry-descriptor-alias", 0));
        }
    }
    let unit = request.unit_path();
    let mut controllers = f.controllers.clone();
    controllers.sort();
    if f.manager_path != format!("{unit}/managers")
        || f.jobs_path != format!("{CGROUP_MOUNT}{unit}/jobs")
        || f.expected_jobs != jobs.id
        || !f.jobs_domain
        || !f.jobs_empty
        || controllers != ["cpu", "memory", "pids"]
    {
        return Err(failure("entry-cgroup", 0));
    }
    Ok(())
}

/// Separate protected expectations, never constructed from the incoming packet
/// by the ordinary entry. No such producer is installed in the R2b executable.
pub struct Admission {
    expected: Request,
}

impl Admission {
    /// # Safety
    /// The caller must be the reviewed boot/E producer in the initial user and
    /// PID namespaces, supplying independently pinned expectations. It must
    /// guarantee a fresh single-threaded M with clean ancestry and signal/FD
    /// history, exclusive cgroup ownership, no concurrent FD-table users or
    /// foreign child signals, and independent E/G timeout and recovery owners.
    /// Matching process observations or a packet flag cannot prove these facts.
    /// Only successful report finalization may stop M. No other actor may stop,
    /// resume or re-stop M during an eligible attempt; any external intervention
    /// irrevocably invalidates the outer result, even if a terminal frame exists.
    pub unsafe fn from_protected_boot(expected: Request) -> Self {
        Self { expected }
    }

    pub fn request(&self) -> &Request {
        &self.expected
    }
}

/// Native ownership is transferred exactly once. A quarantine owner is never
/// converted into a clean sentinel or discarded by the finalization path.
pub enum Transaction<H, Q> {
    Clean {
        report: kernel::Report,
        reservation: Option<Reservation>,
        sentinel: Option<H>,
    },
    Quarantined {
        report: kernel::Report,
        reservation: Option<Reservation>,
        owner: Box<Q>,
    },
}

#[must_use = "the native entry must retain Hold and terminate Exit without dropping retained resources"]
pub enum RunOutcome<H, Q> {
    Exit {
        code: i32,
        failure: Option<Failure>,
        retained: Option<H>,
    },
    Hold {
        owner: Box<Q>,
        failure: Option<Failure>,
    },
}

/// Effects for one invocation only. execute must return Err only before it
/// owns a native transaction; after that, all ownership travels in Transaction.
/// The concrete backend is available only in the separate static build.
///
/// # Errors
/// Methods preserve operation/errno failures. Closing a handle consumes it even
/// when close reports an error; callers must never retry the descriptor number.
pub trait Platform {
    type Handle;
    type Quarantine;
    /// # Errors
    /// Refuses an unavailable or malformed CLOCK_BOOTTIME observation.
    fn now(&mut self) -> Result<u64>;
    /// # Errors
    /// Refuses a wrong channel, incomplete/extra input or expired startup budget.
    fn read_request(&mut self, reservation: Reservation) -> Result<Vec<u8>>;
    /// # Errors
    /// Refuses unavailable observations or any violated live precondition.
    fn observe(&mut self, expected: &Request) -> Result<Facts>;
    /// # Errors
    /// May fail only before acquiring native transaction ownership; once acquired,
    /// ownership and all failures must be returned inside Transaction.
    fn execute(&mut self, request: &Request)
        -> Result<Transaction<Self::Handle, Self::Quarantine>>;
    /// # Errors
    /// Reports a close failure while consuming the handle exactly once.
    fn close_sentinel(&mut self, handle: Self::Handle) -> Result<()>;
    /// # Errors
    /// Refuses failed or repeated post-native report setup. Signal changes must
    /// occur only after execute returns; no later native invocation is allowed.
    fn prepare_report(&mut self) -> Result<()>;
    /// # Errors
    /// Returns the write errno; only EINTR/EAGAIN permit a bounded retry.
    fn write_report(&mut self, bytes: &[u8]) -> Result<usize>;
    /// # Errors
    /// Refuses a lost channel or an expired original reservation.
    fn wait_report(&mut self, reservation: Reservation) -> Result<()>;
    /// # Errors
    /// Reports a close failure; never retries the descriptor number.
    fn close_report(&mut self) -> Result<()>;
    /// Confirm completed quarantine reporting by stopping this manager while
    /// retaining its entire transaction. Called only after report close succeeds.
    /// # Errors
    /// Rejects an expired reservation or failed signal send. No fallible work
    /// follows successful confirmation; a continued manager parks without sending
    /// another confirmation, and the external collector rejects continuation.
    fn confirm_quarantine(&mut self, reservation: Reservation) -> Result<()>;
}

fn startup<P: Platform>(os: &mut P, reservation: Reservation) -> Result<()> {
    let now = os.now()?;
    reservation.remaining(now)?;
    if now >= reservation.origin() + 5 * kernel::SECOND {
        return Err(failure("entry-startup-expired", 0));
    }
    Ok(())
}

fn remaining<P: Platform>(os: &mut P, reservation: Reservation) -> Result<()> {
    reservation.remaining(os.now()?).map(|_| ())
}

fn report_identity(
    report: &kernel::Report,
    reservation: Option<Reservation>,
    expected: &Request,
) -> Result<()> {
    if reservation != Some(expected.reservation)
        || report.epoch != expected.epoch
        || report.case != expected.case
    {
        return Err(failure("entry-result-identity", 0));
    }
    Ok(())
}

fn emit<P: Platform>(
    os: &mut P,
    report: &kernel::Report,
    kind: report::CompletionKind,
    expected: &Request,
) -> Result<()> {
    remaining(os, expected.reservation)?;
    os.prepare_report()?;
    remaining(os, expected.reservation)?;
    let bytes = report::encode(report, kind, &expected.context())
        .map_err(|_| failure("entry-encode", 0))?;
    remaining(os, expected.reservation)?;
    let mut offset = 0;
    for _ in 0..1024 {
        remaining(os, expected.reservation)?;
        if offset == bytes.len() {
            os.close_report()?;
            return remaining(os, expected.reservation);
        }
        match os.write_report(&bytes[offset..]) {
            Ok(n) if n > 0 && n <= bytes.len() - offset => offset += n,
            Ok(_) => return Err(failure("entry-short-write", 0)),
            Err(error) if matches!(error.errno, 4 | 11) => os.wait_report(expected.reservation)?,
            Err(error) => return Err(error),
        }
    }
    Err(failure("entry-write-budget", 0))
}

/// Drive one protected invocation with bounded, separately testable effects.
/// Ordinary entry supplies None and returns 77 before any effect. Exit zero
/// means report finalization completed, not native acceptance or qualification.
pub fn drive<P: Platform>(
    os: &mut P,
    admission: Option<&Admission>,
) -> RunOutcome<P::Handle, P::Quarantine> {
    let Some(admission) = admission else {
        return RunOutcome::Exit {
            code: 77,
            failure: Some(failure("boot-unqualified", 0)),
            retained: None,
        };
    };
    let expected = admission.request();
    let prepared = (|| {
        startup(os, expected.reservation)?;
        let request = Request::decode(&os.read_request(expected.reservation)?)?;
        if &request != expected {
            return Err(failure("entry-request-mismatch", 0));
        }
        startup(os, expected.reservation)?;
        let facts = os.observe(expected)?;
        validate_facts(expected, &facts)?;
        startup(os, expected.reservation)?;
        os.execute(expected)
    })();
    let transaction = match prepared {
        Ok(value) => value,
        Err(error) => {
            return RunOutcome::Exit {
                code: 77,
                failure: Some(error),
                retained: None,
            }
        }
    };
    match transaction {
        Transaction::Clean {
            report,
            reservation,
            mut sentinel,
        } => {
            let finished = (|| {
                report_identity(&report, reservation, expected)?;
                remaining(os, expected.reservation)?;
                if let Some(handle) = sentinel.take() {
                    os.close_sentinel(handle)?;
                    remaining(os, expected.reservation)?;
                }
                emit(os, &report, report::CompletionKind::Clean, expected)
            })();
            RunOutcome::Exit {
                code: if finished.is_ok() && report.outcome != kernel::Outcome::NoJobCreated {
                    0
                } else {
                    77
                },
                failure: finished.err(),
                retained: sentinel,
            }
        }
        Transaction::Quarantined {
            report,
            reservation,
            owner,
        } => {
            // No fallible `?` crosses the ownership boundary: even a failed clock,
            // encoder, write or close returns the full owner to the parking loop.
            let finished = report_identity(&report, reservation, expected)
                .and_then(|()| emit(os, &report, report::CompletionKind::Quarantined, expected))
                .and_then(|()| os.confirm_quarantine(expected.reservation));
            RunOutcome::Hold {
                owner,
                failure: finished.err(),
            }
        }
    }
}

#[cfg(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    not(test)
))]
#[path = "runtime_native.rs"]
pub mod native;

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
