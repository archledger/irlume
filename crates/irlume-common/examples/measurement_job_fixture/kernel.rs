// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Private M/S experiment. Ordinary entry points never call this module.

#[path = "bounds.rs"]
pub mod bounds;

pub const SECOND: u64 = 1_000_000_000;
pub const MAX_OPERATIONS: u32 = 8192;
pub const BUFFER: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub operation: &'static str,
    pub errno: i32,
}

pub type Result<T> = std::result::Result<T, Failure>;

pub const fn failure(operation: &'static str, errno: i32) -> Failure {
    Failure { operation, errno }
}

/// Fixed stack-only name construction, before any fallible native preparation.
pub fn job_name(epoch: u64) -> [u8; 21] {
    let mut name = *b"job-0000000000000000\0";
    for (index, byte) in name[4..20].iter_mut().enumerate() {
        *byte = b"0123456789abcdef"[((epoch >> ((15 - index) * 4)) & 15) as usize];
    }
    name
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloneRequest {
    pub flags: u64,
    pub exit_signal: u64,
    pub cgroup: u64,
    pub unused: [u64; 7],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    BeforeBirth,
    BeforeDelivery,
    BeforeRegistration,
    BeforePlacement,
    BeforeReadback,
    AfterReadback,
}

impl Cut {
    pub const ALL: [Self; 6] = [
        Self::BeforeBirth,
        Self::BeforeDelivery,
        Self::BeforeRegistration,
        Self::BeforePlacement,
        Self::BeforeReadback,
        Self::AfterReadback,
    ];
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Case {
    #[default]
    SupervisorOnly,
    Loss(Cut),
    DoubleFork,
    Zombie,
    Bounds(bounds::BoundCase),
}

impl Case {
    pub const fn cut(self) -> Option<Cut> {
        match self {
            Self::SupervisorOnly | Self::Bounds(_) => None,
            Self::Loss(cut) => Some(cut),
            Self::DoubleFork | Self::Zombie => Some(Cut::BeforePlacement),
        }
    }
    pub const fn shape(self) -> u8 {
        match self {
            Self::DoubleFork => 1,
            Self::Zombie => 2,
            _ => 0,
        }
    }
    pub const fn bounds(self) -> Option<bounds::BoundCase> {
        match self {
            Self::Bounds(case) => Some(case),
            _ => None,
        }
    }
}

pub const WORKER_RECORD: usize = 18;

pub fn worker_message(
    tag: u8,
    epoch: u64,
    pid: u32,
    descendant: u32,
    shape: u8,
) -> [u8; WORKER_RECORD] {
    let mut bytes = [0; WORKER_RECORD];
    bytes[0] = tag;
    bytes[1..9].copy_from_slice(&epoch.to_le_bytes());
    bytes[9..13].copy_from_slice(&pid.to_le_bytes());
    bytes[13..17].copy_from_slice(&descendant.to_le_bytes());
    bytes[17] = shape;
    bytes
}

/// Decode only a complete record for this job and the selected fixed topology.
///
/// # Errors
/// Refuses foreign epochs, malformed records and invalid or aliased identities.
pub fn worker_record(bytes: &[u8], epoch: u64, supervisor: u32, case: Case) -> Result<(u32, u32)> {
    let bad = failure("worker-record", 0);
    if bytes.len() != WORKER_RECORD || epoch == 0 {
        return Err(bad);
    }
    let pid = u32::from_le_bytes(bytes[9..13].try_into().map_err(|_| bad)?);
    let descendant = u32::from_le_bytes(bytes[13..17].try_into().map_err(|_| bad)?);
    let valid_pid = |p| p > 0 && p <= i32::MAX as u32 && p != supervisor;
    if !valid_pid(pid)
        || (case == Case::DoubleFork && (!valid_pid(descendant) || descendant == pid))
        || (case != Case::DoubleFork && descendant != 0)
        || bytes != worker_message(4, epoch, pid, descendant, case.shape())
    {
        return Err(bad);
    }
    Ok((pid, descendant))
}

/// Installed SCM_RIGHTS prefix, owned before any protocol rejection. The native
/// ancillary buffer admits at most two descriptors, including alignment padding.
pub struct Transfer<H> {
    pub count: usize,
    pub handles: [Option<H>; 2],
    pub valid: bool,
}

#[derive(Default)]
pub struct RightsProgress {
    pub offset: usize,
}

impl RightsProgress {
    pub fn send_rights(&self) -> bool {
        self.offset == 0
    }

    /// # Errors
    /// Rejects zero progress, a surplus count or an already completed frame.
    pub fn advance(&mut self, count: usize) -> Result<()> {
        if count == 0 || count > WORKER_RECORD.saturating_sub(self.offset) {
            return Err(failure("rights-send-count", 0));
        }
        self.offset += count;
        Ok(())
    }
}

/// Read an OOM kill counter from a complete memory.events.local record.
///
/// # Errors
/// Rejects missing, duplicate, truncated or malformed counter evidence.
pub fn oom_count(bytes: &[u8]) -> Result<u64> {
    let bad = failure("oom-record", 0);
    if bytes.len() >= BUFFER || !bytes.ends_with(b"\n") {
        return Err(bad);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad)?;
    let mut found = None;
    for line in text.lines() {
        let (key, value) = line.split_once(' ').ok_or(bad)?;
        if key.is_empty() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad);
        }
        let count: u64 = value.parse().map_err(|_| bad)?;
        if key == "oom_kill" && found.replace(count).is_some() {
            return Err(bad);
        }
    }
    found.ok_or(bad)
}

impl CloneRequest {
    pub const fn new(cgroup: u64) -> Self {
        Self {
            // Linux UAPI sched.h: CLONE_INTO_CGROUP | CLONE_PIDFD.
            flags: (1u64 << 33) | 0x1000,
            exit_signal: 17,
            cgroup,
            unused: [0; 7],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Startup = 0,
    Exercise = 1,
    Cleanup = 2,
}

/// One validated CLOCK_BOOTTIME reservation. Values are correlation data, not
/// proof that E supplied them or that the caller shares E's clock namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    origin: u64,
    deadline: u64,
}

impl Reservation {
    /// Validate the fixed total, without sampling or restarting a clock.
    ///
    /// # Errors
    /// Refuses overflow and any total other than exactly origin plus 20 seconds.
    pub fn new(origin: u64, deadline: u64) -> Result<Self> {
        if origin.checked_add(20 * SECOND) != Some(deadline) {
            return Err(failure("deadline", 0));
        }
        Ok(Self { origin, deadline })
    }

    pub const fn origin(self) -> u64 {
        self.origin
    }

    pub const fn deadline(self) -> u64 {
        self.deadline
    }

    /// Remaining time for any native or finalization operation. The caller must
    /// also arrange independent supervision for blocking I/O; this is arithmetic.
    ///
    /// # Errors
    /// Refuses an observation before the origin or at/after the total deadline.
    pub fn remaining(self, now: u64) -> Result<u64> {
        if now < self.origin {
            return Err(failure("clock-before-reservation", 0));
        }
        if now >= self.deadline {
            return Err(failure("expired", 0));
        }
        Ok(self.deadline - now)
    }
}

#[derive(Clone, Debug)]
pub struct Deadlines {
    pub caps: [u64; 4],
    tightened: [bool; 3],
}

impl Deadlines {
    /// Construct reservation-origin caps; overflow refuses the job.
    ///
    /// # Errors
    /// Returns an error if a finite total deadline cannot be represented.
    #[cfg(test)]
    pub fn new(now: u64) -> Result<Self> {
        let total = now.checked_add(20 * SECOND).ok_or(failure("deadline", 0))?;
        Self::from_reservation(Reservation::new(now, total)?, now)
    }

    /// Retain E's origin even when M enters late. All phase caps precede the
    /// validated total; current time cannot extend any cap.
    ///
    /// # Errors
    /// Refuses a clock before the reservation or entry at/after its startup cap.
    pub fn from_reservation(reservation: Reservation, now: u64) -> Result<Self> {
        reservation.remaining(now)?;
        let origin = reservation.origin();
        // Reservation construction proved origin + 20 seconds fits, so these
        // smaller positive additions fit as well.
        if now >= origin + 5 * SECOND {
            return Err(failure("expired", 0));
        }
        Ok(Self {
            caps: [
                origin + 5 * SECOND,
                origin + 10 * SECOND,
                origin + 15 * SECOND,
                reservation.deadline(),
            ],
            tightened: [false; 3],
        })
    }

    pub fn cap(&self, phase: Phase) -> u64 {
        self.caps[phase as usize].min(self.caps[3])
    }

    pub fn expired(&self, phase: Phase, now: u64) -> bool {
        now >= self.cap(phase)
    }

    /// Tighten once; a retry cannot restart a phase's clock.
    ///
    /// # Errors
    /// Returns an error on clock arithmetic overflow.
    pub fn tighten(&mut self, phase: Phase, now: u64) -> Result<()> {
        let index = phase as usize;
        if !self.tightened[index] {
            let local = now.checked_add(5 * SECOND).ok_or(failure("deadline", 0))?;
            self.caps[index] = self.caps[index].min(local);
            self.tightened[index] = true;
        }
        Ok(())
    }
}

/// Parse a complete bounded cgroup.events snapshot. Only populated/frozen are
/// accepted for this fixed fixture profile; each must be unique and Boolean.
///
/// # Errors
/// Refuses missing, duplicate, truncated, oversized or unknown fields.
pub fn population(bytes: &[u8]) -> Result<bool> {
    let bad = failure("population-record", 0);
    if bytes.is_empty() || bytes.len() >= BUFFER || !bytes.ends_with(b"\n") {
        return Err(bad);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad)?;
    let mut populated = None;
    let mut frozen = None;
    for line in text.lines() {
        let (name, value) = line.split_once(' ').ok_or(bad)?;
        let parsed = match value {
            "0" => false,
            "1" => true,
            _ => return Err(bad),
        };
        let slot = match name {
            "populated" => &mut populated,
            "frozen" => &mut frozen,
            _ => return Err(bad),
        };
        if slot.replace(parsed).is_some() {
            return Err(bad);
        }
    }
    populated.ok_or(bad)
}

/// Check a complete cgroup.procs snapshot against a fixed owned live set.
///
/// # Errors
/// Rejects truncated, oversized, noncanonical, duplicate or unexpected PIDs.
pub fn membership(bytes: &[u8], expected: &[u32]) -> Result<()> {
    let bad = failure("membership-record", 0);
    if bytes.len() >= BUFFER || expected.len() > 32 {
        return Err(bad);
    }
    for (index, pid) in expected.iter().enumerate() {
        if *pid == 0 || *pid > i32::MAX as u32 || expected[..index].contains(pid) {
            return Err(bad);
        }
    }
    if bytes.is_empty() {
        return if expected.is_empty() {
            Ok(())
        } else {
            Err(bad)
        };
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad)?;
    let text = text.strip_suffix('\n').ok_or(bad)?;
    let mut seen = [false; 32];
    for line in text.split('\n') {
        if line.is_empty() || line.starts_with('0') || !line.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad);
        }
        let pid: u32 = line.parse().map_err(|_| bad)?;
        let index = expected.iter().position(|p| *p == pid).ok_or(bad)?;
        if seen[index] {
            return Err(bad);
        }
        seen[index] = true;
    }
    if seen[..expected.len()].iter().all(|value| *value) {
        Ok(())
    } else {
        Err(bad)
    }
}

/// Bind pidfd fdinfo to the owned PID in the fixture's single visible namespace.
///
/// # Errors
/// Rejects missing, duplicate, stale, truncated or differently namespaced fields.
pub fn pidfd_identity(bytes: &[u8], pid: u32) -> Result<()> {
    let bad = failure("pidfd-identity", 0);
    if pid == 0 || pid > i32::MAX as u32 || bytes.len() >= BUFFER || !bytes.ends_with(b"\n") {
        return Err(bad);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad)?;
    let mut observed = [None; 2];
    for line in text.lines() {
        let field = if let Some(value) = line.strip_prefix("Pid:") {
            Some((0, value))
        } else {
            line.strip_prefix("NSpid:").map(|value| (1, value))
        };
        if let Some((index, value)) = field {
            if observed[index].replace(value).is_some() {
                return Err(bad);
            }
        }
    }
    let expected = format!("\t{pid}");
    if observed == [Some(expected.as_str()); 2] {
        Ok(())
    } else {
        Err(bad)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Parent,
    Evidence,
    Job,
    Leaf,
    Kill,
    Events,
    Control,
    Peer,
    Worker,
    Sentinel,
}

impl Kind {
    pub const ALL: [Self; 10] = [
        Self::Parent,
        Self::Evidence,
        Self::Job,
        Self::Leaf,
        Self::Kill,
        Self::Events,
        Self::Control,
        Self::Peer,
        Self::Worker,
        Self::Sentinel,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Evidence => "evidence",
            Self::Job => "job",
            Self::Leaf => "leaf",
            Self::Kill => "kill",
            Self::Events => "events",
            Self::Control => "control",
            Self::Peer => "peer",
            Self::Worker => "worker",
            Self::Sentinel => "sentinel",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Job,
    Leaf,
    Worker,
}
impl Group {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Job => "job-create",
            Self::Leaf => "leaf-create",
            Self::Worker => "worker-create",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    Ready,
    Complete,
    Population,
    Born,
    Active,
}
impl Read {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Complete => "complete",
            Self::Population => "population",
            Self::Born => "born",
            Self::Active => "active",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Command,
    Kill,
}
impl Write {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Kill => "kill-write",
        }
    }
}

#[derive(Debug)]
pub struct Resources<H> {
    slots: [Option<H>; 10],
}
impl<H> Resources<H> {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
        }
    }
    pub fn get(&self, kind: Kind) -> Option<&H> {
        self.slots[kind as usize].as_ref()
    }
    fn put(&mut self, kind: Kind, handle: H) {
        self.slots[kind as usize] = Some(handle);
    }
    fn take(&mut self, kind: Kind) -> Option<H> {
        self.slots[kind as usize].take()
    }
    pub fn child_closes(&self) -> impl Iterator<Item = &H> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != Kind::Peer as usize)
            .filter_map(|(_, slot)| slot.as_ref())
    }
}

#[derive(Debug)]
pub struct Child<H> {
    pub pid: u32,
    pub pidfd: Option<H>,
    pub valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    Pending,
    NoChildren,
    Terminal { pid: u32, code: i32, status: i32 },
}

/// This interface belongs only to the private M/S transaction. No methods
/// spawn a shell, perform late placement, or accept an arbitrary command.
///
/// # Errors
/// Every fallible method returns the operation and observed errno. Returning a
/// new handle transfers ownership even when a subsequent operation fails.
pub trait Effects {
    type Handle;
    /// # Errors
    /// Fails when BOOTTIME cannot supply a finite valid value.
    fn clock(&mut self) -> Result<u64>;
    /// # Errors
    /// Fails when the dedicated-M subreaper/signal prerequisites are unavailable.
    fn prepare(&mut self) -> Result<()>;
    /// # Errors
    /// Fails on a missing, invalid or inaccessible resource.
    fn acquire(&mut self, kind: Kind, resources: &Resources<Self::Handle>) -> Result<Self::Handle>;
    /// # Errors
    /// Fails without adopting an existing directory.
    fn mkdir(&mut self, group: Group, resources: &Resources<Self::Handle>) -> Result<()>;
    /// # Errors
    /// Fails for invalid topology, missing controls or failed limit readback.
    fn configure(&mut self, resources: &Resources<Self::Handle>) -> Result<()>;
    /// # Errors
    /// Fails if the nonblocking channel pair cannot be created.
    fn channels(&mut self) -> Result<(Self::Handle, Self::Handle)>;
    fn handle_number(&self, handle: &Self::Handle) -> u64;
    /// # Errors
    /// Returns creation errors without adopting a dirty output slot.
    fn birth(
        &mut self,
        request: CloneRequest,
        resources: &Resources<Self::Handle>,
        epoch: u64,
        deadline: u64,
    ) -> Result<Child<Self::Handle>>;
    /// # Errors
    /// Fails if parked S membership differs from the owned leaf.
    fn parked(
        &mut self,
        resources: &Resources<Self::Handle>,
        child: &Child<Self::Handle>,
    ) -> Result<()>;
    /// # Errors
    /// Returns the read error; interruption does not imply progress.
    fn read(
        &mut self,
        kind: Read,
        resources: &Resources<Self::Handle>,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize>;
    /// # Errors
    /// Returns write errors; callers must check the byte count.
    fn write(
        &mut self,
        kind: Write,
        resources: &Resources<Self::Handle>,
        data: &[u8],
    ) -> Result<usize>;
    /// # Errors
    /// Fails on an unusable handle or failed wait without inventing reaping.
    fn wait(&mut self, child: Option<&Child<Self::Handle>>, consume: bool) -> Result<Wait>;
    /// # Errors
    /// Fails on timeout or poll error without renewing the deadline.
    fn pause(&mut self, deadline: u64) -> Result<()>;
    /// # Errors
    /// Fails on changed directory identity or failed removal.
    fn remove(&mut self, group: Group, resources: &Resources<Self::Handle>) -> Result<()>;
    /// # Errors
    /// Consumes the handle even on a close error; callers must not retry it.
    fn close(&mut self, handle: Self::Handle) -> Result<()>;
    /// # Errors
    /// Returns syscall errors; successfully installed handles must be returned
    /// as owned values even when the packet is otherwise invalid.
    fn registration(
        &mut self,
        resources: &Resources<Self::Handle>,
        output: &mut [u8],
    ) -> Result<Transfer<Self::Handle>>;
    /// # Errors
    /// Refuses a foreign pidfd, wrong live/zombie state or wrong control session.
    fn worker_identity(
        &mut self,
        child: &Child<Self::Handle>,
        case: Case,
        descendant: u32,
    ) -> Result<()>;
    /// # Errors
    /// Refuses any mismatch in complete J/root, supervisor and worker snapshots.
    fn members(
        &mut self,
        resources: &Resources<Self::Handle>,
        supervisor: &[u32],
        worker: &[u32],
    ) -> Result<()>;
    /// # Errors
    /// Refuses unsuccessful or short placement. Caller holds the no-reap epoch.
    fn place(
        &mut self,
        resources: &Resources<Self::Handle>,
        child: &Child<Self::Handle>,
    ) -> Result<()>;
    /// # Errors
    /// Signals only the supplied retained pidfd; never falls back to numeric PID.
    fn signal(&mut self, child: &Child<Self::Handle>) -> Result<()>;
    /// # Errors
    /// Refuses absent/malformed memory.events.local evidence for J, supervisor
    /// and worker, in that order. This is independent of memory_localevents.
    fn oom_kills(&mut self, resources: &Resources<Self::Handle>) -> Result<[u64; 3]>;
    /// # Errors
    /// Initializes only the already-owned sentinel, refusing failed writes/seals.
    fn initialize_sentinel(
        &mut self,
        resources: &Resources<Self::Handle>,
        epoch: u64,
    ) -> Result<()>;
    /// # Errors
    /// Refuses incomplete bytes, seals, size or mode evidence for the retained object.
    fn verify_sentinel(
        &mut self,
        resources: &Resources<Self::Handle>,
        epoch: u64,
        after: bool,
    ) -> Result<()>;
    /// # Errors
    /// Arms one finite exercise cap; re-arming is forbidden.
    fn arm_work(&mut self, cap: u64) -> Result<()>;
    /// # Errors
    /// Observes pidfd readiness without requiring parenthood or consuming a wait.
    fn worker_terminal(&mut self, child: &Child<Self::Handle>) -> Result<bool>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    AbortedClean,
    NoJobCreated,
    Incomplete,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub bounds: Option<bounds::State>,
    pub case: Case,
    pub reached: Option<Cut>,
    pub injected: bool,
    pub registered: bool,
    pub placed: bool,
    pub placement_verified: bool,
    pub worker_pid: Option<u32>,
    pub descendant_pid: Option<u32>,
    pub worker_reaped: bool,
    pub descendant_reaped: bool,
    pub oom_observations: u32,
    pub oom_kills: [u64; 3],
    pub epoch: u64,
    pub outcome: Outcome,
    pub reserved: bool,
    /// Identity and generation dummy leases, never real allocated identities.
    pub leases_held: [bool; 2],
    pub custody_retained: bool,
    pub releases: u32,
    pub first: Option<Failure>,
    pub errors: [Option<Failure>; 16],
    pub errors_truncated: bool,
    pub kill: bool,
    pub empty: bool,
    pub direct_reaped: bool,
    pub drained: bool,
    pub consumers: u32,
    pub adopted: u32,
    /// Slot 0 is direct S; following slots are consumed adopted-child waits.
    pub terminal: [Option<Wait>; 33],
    pub operations: u32,
    pub native_authorized: bool,
    pub full_contract_proven: bool,
}

impl Report {
    /// A synthetic cut case passes only with its exact witness and clean terminal
    /// evidence. It grants no native authority or complete-contract proof.
    pub fn case_passed(&self) -> bool {
        if let Case::Bounds(case) = self.case {
            return bounds::case_passed(self, case);
        }
        self.case != Case::SupervisorOnly
            && self.reached == self.case.cut()
            && self.injected
            && self.first == Some(failure("supervisor-loss-injected", 0))
            && self.errors.iter().flatten().count() == 1
            && self.outcome == Outcome::AbortedClean
            && self.kill
            && self.empty
            && self.direct_reaped
            && self.drained
            && self.consumers == 0
            && self.releases == 1
            && self.leases_held == [false; 2]
            && !self.custody_retained
            && !self.errors_truncated
            && !self.native_authorized
            && !self.full_contract_proven
            && self.oom_observations == 3
            && self.oom_kills == [0; 3]
            && self.adopted
                == if self.case == Case::DoubleFork {
                    2
                } else {
                    u32::from(self.case.cut() != Some(Cut::BeforeBirth))
                }
            && self.worker_pid.is_none_or(|_| self.worker_reaped)
            && self.descendant_pid.is_none_or(|_| self.descendant_reaped)
    }
}

/// The caller must retain this owner if cleanup is incomplete. Dropping it
/// merely closes handles; it neither reaps nor releases synthetic leases.
#[derive(Debug)]
pub struct Quarantine<H> {
    pub report: Report,
    pub resources: Resources<H>,
    pub child: Option<Child<H>>,
    pub created: [bool; 3],
    pub worker: Option<Child<H>>,
    pub transferred: [Option<H>; 3],
    pub deadlines: Option<Deadlines>,
    reservation: Option<Reservation>,
    cleanup_guard_failed: bool,
}

#[must_use = "an incomplete job still has an owner which must be retained"]
#[derive(Debug)]
pub enum Completion<H> {
    Clean {
        report: Report,
        sentinel: Option<H>,
        reservation: Option<Reservation>,
    },
    Quarantined(Quarantine<H>),
}
impl<H> Completion<H> {
    /// The original finalization budget survives both completion variants.
    /// None means no valid reservation was established, never permission to
    /// allocate a new budget. This metadata does not grant runtime acceptance.
    pub fn reservation(&self) -> Option<Reservation> {
        match self {
            Self::Clean { reservation, .. } => *reservation,
            Self::Quarantined(owner) => owner.reservation,
        }
    }

    pub fn report(&self) -> &Report {
        match self {
            Self::Clean { report, .. } => report,
            Self::Quarantined(owner) => &owner.report,
        }
    }
}

impl<H> Quarantine<H> {
    fn new(epoch: u64) -> Self {
        Self {
            report: Report {
                bounds: None,
                case: Case::SupervisorOnly,
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
                epoch,
                outcome: Outcome::Incomplete,
                reserved: true,
                leases_held: [true; 2],
                custody_retained: true,
                releases: 0,
                first: None,
                errors: [None; 16],
                errors_truncated: false,
                kill: false,
                empty: false,
                direct_reaped: false,
                drained: false,
                consumers: 0,
                adopted: 0,
                terminal: [None; 33],
                operations: 0,
                native_authorized: false,
                full_contract_proven: false,
            },
            resources: Resources::new(),
            child: None,
            created: [false; 3],
            worker: None,
            transferred: std::array::from_fn(|_| None),
            deadlines: None,
            reservation: None,
            cleanup_guard_failed: false,
        }
    }
    fn fail(&mut self, error: Failure) {
        self.report.first.get_or_insert(error);
        if self.report.errors.iter().flatten().any(|old| *old == error) {
            return;
        }
        if let Some(slot) = self.report.errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.report.errors_truncated = true;
        }
    }
}

fn guard<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>, phase: Phase) -> Result<()> {
    // Startup/exercise cannot spend the cleanup reserve. The total is finite
    // even when a fake or broken clock never advances.
    let limit = if phase == Phase::Cleanup {
        MAX_OPERATIONS
    } else {
        MAX_OPERATIONS / 2
    };
    let result = (|| {
        if owner.report.operations >= limit {
            return Err(failure("operation-cap", 0));
        }
        owner.report.operations += 1;
        let now = os.clock()?;
        if let Some(state) = &mut owner.report.bounds {
            if phase == Phase::Exercise && state.result_postcheck_pending {
                state.result_return = Some(now);
                state.result_postcheck_pending = false;
            }
        }
        if let Some(reservation) = owner.reservation {
            reservation.remaining(now)?;
        }
        if owner
            .deadlines
            .as_ref()
            .is_none_or(|d| d.expired(phase, now))
        {
            return Err(failure("expired", 0));
        }
        Ok(())
    })();
    if phase == Phase::Cleanup && result.is_err() {
        // A later successful clock read cannot restore cleanup admission.
        owner.cleanup_guard_failed = true;
    }
    result
}

fn step<E: Effects, T>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    phase: Phase,
    action: impl FnOnce(&mut E, &mut Quarantine<E::Handle>) -> Result<T>,
) -> Result<T> {
    guard(os, owner, phase)?;
    let value = action(os, owner)?;
    guard(os, owner, phase)?;
    Ok(value)
}

fn acquire<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    kind: Kind,
    phase: Phase,
) -> Result<()> {
    step(os, owner, phase, |os, owner| {
        let fd = os.acquire(kind, &owner.resources)?;
        owner.resources.put(kind, fd); // Ownership precedes the post-operation clock/readback.
        if kind == Kind::Sentinel {
            if let Some(state) = &mut owner.report.bounds {
                state.sentinel_created = true;
            }
        }
        Ok(())
    })
}

pub fn message(tag: u8, epoch: u64) -> [u8; 9] {
    let mut bytes = [0; 9];
    bytes[0] = tag;
    bytes[1..].copy_from_slice(&epoch.to_le_bytes());
    bytes
}

fn receive<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    kind: Read,
    phase: Phase,
) -> Result<()> {
    let expected = message(if kind == Read::Ready { 1 } else { 2 }, owner.report.epoch);
    let mut actual = [0; 9];
    read_record(os, owner, kind, phase, &mut actual, |_, _| Ok(()))?;
    if actual != expected {
        return Err(failure("channel-record", 0));
    }
    Ok(())
}

fn read_record<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    kind: Read,
    phase: Phase,
    actual: &mut [u8],
    mut retain: impl FnMut(&mut Quarantine<E::Handle>, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut offset = 0;
    while offset < actual.len() {
        let mut part = [0; WORKER_RECORD + 1];
        let remaining = actual.len() - offset;
        let mut retryable_read = false;
        let result = step(os, owner, phase, |os, owner| {
            let count = os
                .read(kind, &owner.resources, offset, &mut part[..remaining + 1])
                .inspect_err(|error| {
                    retryable_read = matches!(error.errno, 4 | 11);
                })?;
            if count > 0 && count <= remaining {
                if let Some(state) = &mut owner.report.bounds {
                    state.output.charge(count)?;
                }
                actual[offset..offset + count].copy_from_slice(&part[..count]);
                offset += count;
                if offset == actual.len() {
                    retain(owner, actual)?;
                }
            }
            Ok(count)
        });
        match result {
            Ok(0) => return Err(failure("channel-eof", 0)),
            Ok(count) if count <= remaining => {}
            Ok(_) => return Err(failure("channel-surplus", 0)),
            Err(_) if retryable_read => {
                step(os, owner, phase, |os, owner| {
                    os.pause(owner.deadlines.as_ref().map_or(0, |d| d.cap(phase)))
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn attempt<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>) -> Result<()> {
    let phase = Phase::Startup;
    acquire(os, owner, Kind::Parent, phase)?;
    acquire(os, owner, Kind::Evidence, phase)?;
    if owner.report.bounds.is_some() {
        acquire(os, owner, Kind::Sentinel, phase)?;
        step(os, owner, phase, |os, owner| {
            os.initialize_sentinel(&owner.resources, owner.report.epoch)
        })?;
        step(os, owner, phase, |os, owner| {
            os.verify_sentinel(&owner.resources, owner.report.epoch, false)?;
            if let Some(state) = &mut owner.report.bounds {
                state.sentinel_pre = true;
            }
            Ok(())
        })?;
    }
    step(os, owner, phase, |os, _| os.prepare())?;
    step(os, owner, phase, |os, owner| {
        os.mkdir(Group::Job, &owner.resources)?;
        owner.created[0] = true;
        Ok(())
    })?;
    for kind in [Kind::Job, Kind::Kill, Kind::Events] {
        acquire(os, owner, kind, phase)?;
    }
    step(os, owner, phase, |os, owner| os.configure(&owner.resources))?;
    step(os, owner, phase, |os, owner| {
        os.mkdir(Group::Leaf, &owner.resources)?;
        owner.created[1] = true;
        Ok(())
    })?;
    acquire(os, owner, Kind::Leaf, phase)?;
    if owner.report.case != Case::SupervisorOnly {
        step(os, owner, phase, |os, owner| {
            os.mkdir(Group::Worker, &owner.resources)?;
            owner.created[2] = true;
            Ok(())
        })?;
        acquire(os, owner, Kind::Worker, phase)?;
    }
    step(os, owner, phase, |os, owner| {
        let (control, peer) = os.channels()?;
        owner.resources.put(Kind::Control, control);
        owner.resources.put(Kind::Peer, peer);
        Ok(())
    })?;
    step(os, owner, phase, |os, owner| {
        let leaf = owner
            .resources
            .get(Kind::Leaf)
            .ok_or(failure("leaf-missing", 0))?;
        let request = CloneRequest::new(os.handle_number(leaf));
        let child = os.birth(
            request,
            &owner.resources,
            owner.report.epoch,
            owner.deadlines.as_ref().map_or(0, |d| d.caps[3]),
        )?;
        owner.child = Some(child); // Even malformed success retains the child and pidfd.
        owner.report.consumers = 1;
        if owner
            .child
            .as_ref()
            .is_none_or(|c| !c.valid || c.pid == 0 || c.pidfd.is_none())
        {
            return Err(failure("clone-success-invalid", 0));
        }
        Ok(())
    })?;
    close_one(os, owner, Kind::Peer, phase)?;
    receive(os, owner, Read::Ready, phase)?;
    peek(os, owner, phase)?;
    step(os, owner, phase, |os, owner| {
        os.parked(
            &owner.resources,
            owner.child.as_ref().ok_or(failure("child-missing", 0))?,
        )
    })?;
    let now = os.clock()?;
    if let Some(deadlines) = &mut owner.deadlines {
        deadlines.tighten(Phase::Exercise, now)?;
    }
    if owner.report.case != Case::SupervisorOnly {
        return inheritance(os, owner);
    }
    send_command(os, owner, 3)?;
    receive(os, owner, Read::Complete, Phase::Exercise)?;
    peek(os, owner, Phase::Exercise)
}

fn send_command<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>, tag: u8) -> Result<()> {
    let command = message(tag, owner.report.epoch);
    let mut offset = 0;
    while offset < command.len() {
        match step(os, owner, Phase::Exercise, |os, owner| {
            os.write(Write::Command, &owner.resources, &command[offset..])
        }) {
            Ok(count) if count > 0 && count <= command.len() - offset => offset += count,
            Ok(_) => return Err(failure("command-write", 0)),
            Err(error) if matches!(error.errno, 4 | 11) => {
                step(os, owner, Phase::Exercise, |os, owner| {
                    os.pause(
                        owner
                            .deadlines
                            .as_ref()
                            .map_or(0, |d| d.cap(Phase::Exercise)),
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn check_oom<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    phase: Phase,
) -> Result<()> {
    step(os, owner, phase, |os, owner| {
        let counts = os.oom_kills(&owner.resources)?;
        for (retained, count) in owner.report.oom_kills.iter_mut().zip(counts) {
            *retained = (*retained).max(count);
        }
        owner.report.oom_observations += 1;
        if counts == [0; 3] {
            Ok(())
        } else {
            Err(failure("oom-contaminated", 0))
        }
    })
}

fn cut<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>, at: Cut) -> Result<()> {
    if owner.report.case.cut() != Some(at) {
        return Ok(());
    }
    peek(os, owner, Phase::Exercise)?;
    check_oom(os, owner, Phase::Exercise)?;
    owner.report.reached = Some(at);
    stop_supervisor(os, owner)?;
    owner.report.injected = true;
    Err(failure("supervisor-loss-injected", 0))
}

fn stop_supervisor<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>) -> Result<()> {
    step(os, owner, Phase::Exercise, |os, owner| {
        os.signal(owner.child.as_ref().ok_or(failure("child-missing", 0))?)
    })?;
    loop {
        match step(os, owner, Phase::Exercise, |os, owner| {
            os.wait(owner.child.as_ref(), false)
        })? {
            Wait::Pending => {
                step(os, owner, Phase::Exercise, |os, owner| {
                    os.pause(
                        owner
                            .deadlines
                            .as_ref()
                            .map_or(0, |d| d.cap(Phase::Exercise)),
                    )
                })?;
            }
            Wait::Terminal {
                pid,
                code: 2,
                status: 9,
            } if owner.child.as_ref().is_some_and(|child| child.pid == pid) => break,
            _ => return Err(failure("injection-terminal", 0)),
        }
    }
    check_oom(os, owner, Phase::Exercise)?;
    Ok(())
}

fn worker_members<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    placed: bool,
) -> Result<()> {
    let s = owner.child.as_ref().ok_or(failure("child-missing", 0))?.pid;
    let b = owner
        .worker
        .as_ref()
        .ok_or(failure("worker-missing", 0))?
        .pid;
    let c = owner.report.descendant_pid;
    step(os, owner, Phase::Exercise, |os, owner| {
        if placed {
            os.members(&owner.resources, &[s], &[b])
        } else if let Some(c) = c {
            os.members(&owner.resources, &[s, c], &[])
        } else if owner.report.case == Case::Zombie {
            os.members(&owner.resources, &[s], &[])
        } else {
            os.members(&owner.resources, &[s, b], &[])
        }
    })
}

fn receive_registration<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
) -> Result<[u8; WORKER_RECORD]> {
    let mut actual = [0; WORKER_RECORD];
    let mut offset = 0;
    while offset < actual.len() {
        let mut part = [0; WORKER_RECORD + 1];
        let remaining = actual.len() - offset;
        let result = step(os, owner, Phase::Exercise, |os, owner| {
            let transfer = os.registration(&owner.resources, &mut part[..remaining + 1])?;
            // recvmsg installed these handles already. Take every one before
            // considering invalid control flags, payload lengths or the clock.
            for handle in transfer.handles.into_iter().flatten() {
                if let Some(slot) = owner.transferred.iter_mut().find(|slot| slot.is_none()) {
                    *slot = Some(handle);
                } else {
                    os.close(handle)?;
                    return Err(failure("registration-cap", 0));
                }
            }
            if !transfer.valid || owner.transferred.iter().flatten().count() > 1 {
                return Err(failure("registration-rights", 0));
            }
            if let Some(state) = &mut owner.report.bounds {
                state.output.charge(transfer.count)?;
            }
            Ok(transfer.count)
        });
        match result {
            Ok(n) if n > 0 && n <= remaining => {
                actual[offset..offset + n].copy_from_slice(&part[..n]);
                offset += n;
            }
            Ok(_) => return Err(failure("registration-size", 0)),
            Err(error) if matches!(error.errno, 4 | 11) => {
                step(os, owner, Phase::Exercise, |os, owner| {
                    os.pause(
                        owner
                            .deadlines
                            .as_ref()
                            .map_or(0, |d| d.cap(Phase::Exercise)),
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    if owner.transferred.iter().flatten().count() != 1 {
        return Err(failure("registration-rights", 0));
    }
    Ok(actual)
}

fn register_worker<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    born: &[u8; WORKER_RECORD],
    actual: &[u8; WORKER_RECORD],
) -> Result<()> {
    let mut expected = *born;
    expected[0] = 6;
    if actual != &expected || owner.transferred.iter().flatten().count() != 1 {
        return Err(failure("registration-record", 0));
    }
    let worker = owner.worker.as_mut().ok_or(failure("worker-missing", 0))?;
    worker.pidfd = owner.transferred[0].take();
    step(os, owner, Phase::Exercise, |os, owner| {
        os.worker_identity(
            owner.worker.as_ref().ok_or(failure("worker-missing", 0))?,
            owner.report.case,
            owner.report.descendant_pid.unwrap_or(0),
        )
    })
}

fn retain_birth<H>(owner: &mut Quarantine<H>, born: &[u8]) -> Result<()> {
    let (pid, descendant) = worker_record(
        born,
        owner.report.epoch,
        owner.child.as_ref().ok_or(failure("child-missing", 0))?.pid,
        owner.report.case,
    )?;
    owner.worker = Some(Child {
        pid,
        pidfd: None,
        valid: true,
    });
    owner.report.worker_pid = Some(pid);
    owner.report.descendant_pid = (descendant != 0).then_some(descendant);
    owner.report.consumers += 1 + u32::from(descendant != 0);
    Ok(())
}

fn inheritance<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>) -> Result<()> {
    cut(os, owner, Cut::BeforeBirth)?;
    send_command(os, owner, 3)?;
    let mut born = [0; WORKER_RECORD];
    read_record(
        os,
        owner,
        Read::Born,
        Phase::Exercise,
        &mut born,
        retain_birth,
    )?;
    worker_members(os, owner, false)?;
    cut(os, owner, Cut::BeforeDelivery)?;
    send_command(os, owner, 5)?;
    let delivery = receive_registration(os, owner)?;
    cut(os, owner, Cut::BeforeRegistration)?;
    register_worker(os, owner, &born, &delivery)?;
    owner.report.registered = true;
    worker_members(os, owner, false)?;
    cut(os, owner, Cut::BeforePlacement)?;
    peek(os, owner, Phase::Exercise)?;
    step(os, owner, Phase::Exercise, |os, owner| {
        os.place(
            &owner.resources,
            owner.worker.as_ref().ok_or(failure("worker-missing", 0))?,
        )?;
        owner.report.placed = true;
        Ok(())
    })?;
    cut(os, owner, Cut::BeforeReadback)?;
    worker_members(os, owner, true)?;
    owner.report.placement_verified = true;
    if owner.report.bounds.is_some() {
        return bounds::exercise(os, owner);
    }
    cut(os, owner, Cut::AfterReadback)?;
    Err(failure("cut-unreached", 0))
}

fn peek<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>, phase: Phase) -> Result<()> {
    match step(os, owner, phase, |os, owner| {
        os.wait(owner.child.as_ref(), false)
    })? {
        Wait::Pending => Ok(()),
        _ => Err(failure("supervisor-early", 0)),
    }
}

fn close_one<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
    kind: Kind,
    phase: Phase,
) -> Result<()> {
    if owner.resources.get(kind).is_none() {
        return Ok(());
    }
    step(os, owner, phase, |os, owner| {
        if let Some(fd) = owner.resources.take(kind) {
            os.close(fd)?;
        }
        Ok(())
    })
}

fn cleanup_pass<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>) {
    let phase = Phase::Cleanup;
    // A partially created name remains owned before its first successful open.
    for kind in [Kind::Job, Kind::Kill, Kind::Events] {
        if owner.resources.get(kind).is_none() {
            if let Err(error) = acquire(os, owner, kind, phase) {
                owner.fail(error);
            }
        }
    }
    if owner.created[1] && owner.resources.get(Kind::Leaf).is_none() {
        if let Err(error) = acquire(os, owner, Kind::Leaf, phase) {
            owner.fail(error);
        }
    }
    if owner.created[2] && owner.resources.get(Kind::Worker).is_none() {
        if let Err(error) = acquire(os, owner, Kind::Worker, phase) {
            owner.fail(error);
        }
    }
    if !owner.report.kill {
        match step(os, owner, phase, |os, owner| {
            os.write(Write::Kill, &owner.resources, b"1\n")
        }) {
            Ok(2) => owner.report.kill = true,
            Ok(_) => owner.fail(failure("kill-short", 0)),
            Err(error) => owner.fail(error),
        }
    }
    if !owner.report.empty {
        let mut bytes = [0; BUFFER];
        let mut offset = 0;
        let snapshot = (|| loop {
            let count = step(os, owner, phase, |os, owner| {
                os.read(
                    Read::Population,
                    &owner.resources,
                    offset,
                    &mut bytes[offset..],
                )
            })?;
            if count == 0 {
                return population(&bytes[..offset]);
            }
            if count >= BUFFER - offset {
                return Err(failure("population-size", 0));
            }
            offset += count;
        })();
        match snapshot {
            Ok(false) => owner.report.empty = true,
            Ok(true) => {}
            Err(error) => owner.fail(error),
        }
    }
    if owner.child.is_some() && !owner.report.direct_reaped {
        let result = step(os, owner, phase, |os, owner| {
            // Consuming wait evidence belongs to the owner before the postcheck.
            match os.wait(owner.child.as_ref(), true)? {
                event @ Wait::Terminal {
                    pid, code: 1..=3, ..
                } if owner.child.as_ref().is_some_and(|c| c.pid == pid) => {
                    owner.report.direct_reaped = true;
                    owner.report.terminal[0] = Some(event);
                    owner.report.consumers = owner.report.consumers.saturating_sub(1);
                }
                Wait::Pending => {}
                _ => owner.fail(failure("direct-wait-missing", 0)),
            }
            Ok(())
        });
        if let Err(error) = result {
            owner.fail(error);
        }
    }
    if let Err(error) = bounds::observe_stopped(os, owner) {
        owner.fail(error);
    }
    if (owner.child.is_none() || owner.report.direct_reaped) && !owner.report.drained {
        let result = step(os, owner, phase, |os, owner| {
            match os.wait(None, true)? {
                Wait::NoChildren => owner.report.drained = true,
                Wait::Pending => {}
                event @ Wait::Terminal {
                    pid, code: 1..=3, ..
                } if owner.report.adopted < 32 => {
                    owner.report.adopted += 1;
                    owner.report.terminal[owner.report.adopted as usize] = Some(event);
                    if owner.report.worker_pid == Some(pid) && !owner.report.worker_reaped {
                        owner.report.worker_reaped = true;
                        owner.report.consumers = owner.report.consumers.saturating_sub(1);
                        if owner.report.bounds.as_ref().is_some_and(|s| s.cutover)
                            && event
                                != (Wait::Terminal {
                                    pid,
                                    code: 1,
                                    status: 0,
                                })
                        {
                            owner.fail(failure("worker-terminal-status", 0));
                        }
                    } else if owner.report.descendant_pid == Some(pid)
                        && !owner.report.descendant_reaped
                    {
                        owner.report.descendant_reaped = true;
                        owner.report.consumers = owner.report.consumers.saturating_sub(1);
                    } else {
                        owner.fail(failure("unexpected-adopted-child", 0));
                    }
                }
                Wait::Terminal { .. } if owner.report.adopted >= 32 => {
                    owner.report.errors_truncated = true;
                    owner.fail(failure("terminal-evidence-cap", 0));
                }
                _ => owner.fail(failure("adopted-wait-invalid", 0)),
            }
            Ok(())
        });
        if let Err(error) = result {
            owner.fail(error);
        }
    }
}

fn dispose<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>) -> Result<()> {
    for (group, index) in [(Group::Worker, 2), (Group::Leaf, 1), (Group::Job, 0)] {
        if owner.created[index] {
            step(os, owner, Phase::Cleanup, |os, owner| {
                os.remove(group, &owner.resources)?;
                owner.created[index] = false;
                Ok(())
            })?;
        }
    }
    for kind in Kind::ALL.into_iter().rev() {
        if kind != Kind::Sentinel {
            close_one(os, owner, kind, Phase::Cleanup)?;
        }
    }
    for index in 0..owner.transferred.len() {
        step(os, owner, Phase::Cleanup, |os, owner| {
            if let Some(handle) = owner.transferred[index].take() {
                os.close(handle)?;
            }
            Ok(())
        })?;
    }
    if owner
        .worker
        .as_ref()
        .is_some_and(|worker| worker.pidfd.is_some())
    {
        step(os, owner, Phase::Cleanup, |os, owner| {
            if let Some(fd) = owner.worker.as_mut().and_then(|worker| worker.pidfd.take()) {
                os.close(fd)?;
            }
            Ok(())
        })?;
    }
    step(os, owner, Phase::Cleanup, |os, owner| {
        if let Some(child) = &mut owner.child {
            if let Some(fd) = child.pidfd.take() {
                os.close(fd)?;
            }
        }
        Ok(())
    })
}

fn initialization_refusal<H>(mut owner: Quarantine<H>, error: Failure) -> Completion<H> {
    owner.fail(error);
    let untouched = owner.deadlines.is_none()
        && owner.created == [false; 3]
        && owner.resources.slots.iter().all(Option::is_none)
        && owner.child.is_none()
        && owner.worker.is_none()
        && owner.transferred.iter().all(Option::is_none)
        && owner.report.consumers == 0
        && owner.report.operations == 0
        && owner.report.releases == 0
        && !owner.cleanup_guard_failed;
    if !untouched {
        return Completion::Quarantined(owner);
    }
    // No OS ownership was acquired. Consume the initial synthetic reservation
    // without inventing cleanup facts or requiring a clock that already failed.
    owner.report.releases = 1;
    owner.report.leases_held = [false; 2];
    owner.report.custody_retained = false;
    owner.report.outcome = Outcome::NoJobCreated;
    Completion::Clean {
        report: owner.report,
        sentinel: None,
        reservation: owner.reservation,
    }
}

/// Execute only through an injected effect boundary. Native callers must obey
/// the adapter's unsafe boot contract and retain any returned quarantine owner.
#[cfg(test)]
pub fn run<E: Effects>(os: &mut E, epoch: u64) -> Completion<E::Handle> {
    run_case(os, epoch, Case::SupervisorOnly)
}

fn case_owner<H>(epoch: u64, case: Case) -> Quarantine<H> {
    let mut owner = Quarantine::new(epoch); // Synthetic custody precedes every fallible operation.
    owner.report.case = case;
    if case.bounds().is_some() {
        owner.report.bounds = Some(bounds::State::default());
    }
    owner
}

/// Legacy pure-test convenience. No normal native build exposes this fresh-clock entry.
#[cfg(test)]
pub fn run_case<E: Effects>(os: &mut E, epoch: u64, case: Case) -> Completion<E::Handle> {
    let mut owner = case_owner(epoch, case);
    let initialized = os.clock().and_then(|now| {
        let total = now.checked_add(20 * SECOND).ok_or(failure("deadline", 0))?;
        let reservation = Reservation::new(now, total)?;
        owner.reservation = Some(reservation);
        Deadlines::from_reservation(reservation, now)
    });
    execute_case(os, owner, initialized)
}

/// Run only within the supplied reservation. Invalid pairs refuse before any
/// effect, and delayed entry cannot restart startup or total time. The returned
/// reservation is also the adapter's finalization budget. Native callers must
/// obey sys::run's unsafe boot/custody contract.
pub fn run_reserved<E: Effects>(
    os: &mut E,
    epoch: u64,
    case: Case,
    origin: u64,
    total: u64,
) -> Completion<E::Handle> {
    let mut owner = case_owner(epoch, case);
    let reservation = match Reservation::new(origin, total) {
        Ok(value) => value,
        Err(error) => return initialization_refusal(owner, error),
    };
    owner.reservation = Some(reservation);
    let initialized = os
        .clock()
        .and_then(|now| Deadlines::from_reservation(reservation, now));
    execute_case(os, owner, initialized)
}

fn execute_case<E: Effects>(
    os: &mut E,
    mut owner: Quarantine<E::Handle>,
    initialized: Result<Deadlines>,
) -> Completion<E::Handle> {
    match initialized {
        Ok(deadlines) if owner.report.epoch != 0 => owner.deadlines = Some(deadlines),
        Ok(_) => return initialization_refusal(owner, failure("epoch", 0)),
        Err(error) => return initialization_refusal(owner, error),
    }
    if owner.report.first.is_none() {
        if let Err(error) = attempt(os, &mut owner) {
            owner.fail(error);
        }
    }
    finish(os, owner)
}

fn finish<E: Effects>(os: &mut E, mut owner: Quarantine<E::Handle>) -> Completion<E::Handle> {
    if let Some(deadlines) = &mut owner.deadlines {
        match os
            .clock()
            .and_then(|now| deadlines.tighten(Phase::Cleanup, now))
        {
            Ok(()) => {}
            Err(error) => owner.fail(error),
        }
    }
    if let (Some(state), Some(deadlines)) = (&mut owner.report.bounds, &owner.deadlines) {
        state.caps = deadlines.caps;
    }
    let no_job = !owner.created[0] && owner.child.is_none();
    if !no_job {
        loop {
            if let Err(error) = guard(os, &mut owner, Phase::Cleanup) {
                owner.fail(error);
                break;
            }
            cleanup_pass(os, &mut owner);
            if owner.report.kill
                && owner.report.empty
                && (owner.child.is_none() || owner.report.direct_reaped)
                && owner.report.drained
                && owner.report.consumers == 0
                && !owner.report.errors_truncated
            {
                break;
            }
            if let Err(error) = step(os, &mut owner, Phase::Cleanup, |os, owner| {
                os.pause(
                    owner
                        .deadlines
                        .as_ref()
                        .map_or(0, |d| d.cap(Phase::Cleanup)),
                )
            }) {
                owner.fail(error);
                break;
            }
        }
    }
    let clean = no_job
        || (owner.report.kill
            && owner.report.empty
            && owner.report.drained
            && (owner.child.is_none() || owner.report.direct_reaped)
            && owner.report.consumers == 0);
    if clean && !owner.report.errors_truncated && !owner.cleanup_guard_failed {
        if owner
            .report
            .bounds
            .as_ref()
            .is_some_and(|s| s.sentinel_failed || (s.sentinel_created && !s.sentinel_pre))
        {
            return Completion::Quarantined(owner);
        }
        if !no_job && owner.report.case != Case::SupervisorOnly {
            if let Err(error) = check_oom(os, &mut owner, Phase::Cleanup) {
                owner.fail(error);
            }
            if owner.cleanup_guard_failed {
                return Completion::Quarantined(owner);
            }
        }
        if owner.resources.get(Kind::Sentinel).is_some() {
            if let Err(error) = step(os, &mut owner, Phase::Cleanup, |os, owner| {
                os.verify_sentinel(&owner.resources, owner.report.epoch, true)?;
                if let Some(state) = &mut owner.report.bounds {
                    state.sentinel_post = true;
                }
                Ok(())
            }) {
                owner.fail(error);
                return Completion::Quarantined(owner);
            }
        }
        // With no acquired resources, a failed initial clock needs no OS cleanup.
        let disposed = if owner.resources.slots.iter().all(Option::is_none) && owner.child.is_none()
        {
            Ok(())
        } else {
            dispose(os, &mut owner)
        };
        match disposed.and_then(|()| guard(os, &mut owner, Phase::Cleanup)) {
            Ok(()) => {
                owner.report.releases += 1;
                owner.report.leases_held = [false; 2];
                owner.report.custody_retained = false;
                owner.report.outcome = if no_job {
                    Outcome::NoJobCreated
                } else if owner.report.first.is_some() {
                    Outcome::AbortedClean
                } else {
                    Outcome::Complete
                };
                let sentinel = owner.resources.take(Kind::Sentinel);
                return Completion::Clean {
                    report: owner.report,
                    sentinel,
                    reservation: owner.reservation,
                };
            }
            Err(error) => owner.fail(error),
        }
    }
    Completion::Quarantined(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};

    #[derive(Default)]
    struct Fake {
        case: Case,
        oom_at: u32,
        oom_reads: u32,
        local_ooms: [u64; 3],
        registration_offset: usize,
        rights_sent: bool,
        signal_sent: bool,
        workers_created: bool,
        worker_live: bool,
        descendant_live: bool,
        placed: bool,
        killed: bool,
        transfer_fault: Option<&'static str>,
        pending_adopted: bool,
        leaf_only_kill: bool,
        bad_readback: bool,
        born_postcheck: Option<Result<u64>>,
        cleanup_started: bool,
        work_cap: Option<u64>,
        sentinel_initialized: bool,
        ready_retries: u32,
        premature_result: bool,
        incomplete_result: bool,
        bad_worker_status: bool,
        result_tag: Option<u8>,
        result_epoch: Option<u64>,
        log: Vec<String>,
        alive: BTreeSet<u32>,
        faults: VecDeque<&'static str>,
        now: u64,
        chunk: usize,
        pending: bool,
        dirty_error: bool,
        malformed: bool,
        truncated: bool,
        extra: VecDeque<Wait>,
        birth_errno: i32,
        wait_reply: Option<Wait>,
        wait_handle: u32,
        population_live: bool,
        kill_denied: bool,
        advance_on: Option<(&'static str, u64)>,
        stopped_clock: bool,
        stall_ready: bool,
        direct_consumed: bool,
        early_at_peek: Option<usize>,
        peeks: usize,
        wait_postcheck: Option<(bool, Result<u64>)>,
        next_clock: Option<Result<u64>>,
        close_at: Option<(u32, u64)>,
        pidfd_closed: bool,
        after_pidfd_clocks: VecDeque<Result<u64>>,
    }

    impl Fake {
        fn record(&mut self, name: &'static str) -> Result<()> {
            self.log.push(name.into());
            if self.advance_on.is_some_and(|(at, _)| at == name) {
                self.now = self.advance_on.take().unwrap().1;
            }
            if self.faults.front() == Some(&name) {
                self.faults.pop_front();
                return Err(failure(name, 5));
            }
            Ok(())
        }
    }

    impl Effects for Fake {
        type Handle = u32;

        fn clock(&mut self) -> Result<u64> {
            self.record("clock")?;
            if let Some(result) = self.next_clock.take() {
                if let Ok(now) = result {
                    self.now = now;
                }
                return result;
            }
            if self.pidfd_closed {
                if let Some(result) = self.after_pidfd_clocks.pop_front() {
                    return result;
                }
            }
            Ok(self.now)
        }
        fn prepare(&mut self) -> Result<()> {
            self.record("prepare")
        }
        fn acquire(&mut self, kind: Kind, _: &Resources<u32>) -> Result<u32> {
            self.record(kind.name())?;
            let fd = kind as u32 + 10;
            self.alive.insert(fd);
            Ok(fd)
        }
        fn mkdir(&mut self, group: Group, _: &Resources<u32>) -> Result<()> {
            self.record(group.name())
        }
        fn configure(&mut self, _: &Resources<u32>) -> Result<()> {
            self.record("configure")
        }
        fn channels(&mut self) -> Result<(u32, u32)> {
            self.record("channels")?;
            self.alive.extend([16, 17]);
            Ok((16, 17))
        }
        fn birth(
            &mut self,
            request: CloneRequest,
            _: &Resources<u32>,
            _: u64,
            _: u64,
        ) -> Result<Child<u32>> {
            self.log.push(format!("flags:{}", request.flags));
            self.record("birth")?;
            if self.birth_errno != 0 {
                return Err(failure("clone3", self.birth_errno));
            }
            if self.dirty_error {
                self.alive.insert(99); // An unrelated fd now occupies the stale output number.
                return Err(failure("clone3", 38));
            }
            let handle = if self.wait_handle == 0 {
                42
            } else {
                self.wait_handle
            };
            self.alive.insert(handle);
            Ok(Child {
                pid: 77,
                pidfd: Some(handle),
                valid: !self.malformed,
            })
        }
        fn handle_number(&self, fd: &u32) -> u64 {
            u64::from(*fd)
        }
        fn parked(&mut self, _: &Resources<u32>, _: &Child<u32>) -> Result<()> {
            self.record("parked")
        }
        fn read(
            &mut self,
            kind: Read,
            _: &Resources<u32>,
            offset: usize,
            output: &mut [u8],
        ) -> Result<usize> {
            self.record(kind.name())?;
            if kind == Read::Ready && self.ready_retries > 0 {
                self.ready_retries -= 1;
                return Err(failure("read", 11));
            }
            if kind == Read::Complete && self.incomplete_result && offset >= 3 {
                return Ok(0);
            }
            if kind == Read::Population
                && self.case.bounds() == Some(bounds::BoundCase::WithheldPopulation)
            {
                return Err(failure("fixture-withheld-population", 0));
            }
            if kind == Read::Complete
                && matches!(
                    self.case.bounds(),
                    Some(bounds::BoundCase::SupervisorStall | bounds::BoundCase::WorkerStall)
                )
            {
                return Err(failure("read", 11));
            }
            if kind == Read::Ready && self.stall_ready {
                return Err(failure("ready", 11));
            }
            let record;
            let born;
            let flood = [0xff; 18];
            let data = match kind {
                Read::Population
                    if self.population_live || self.worker_live || self.descendant_live =>
                {
                    &b"populated 1\nfrozen 0\n"[..]
                }
                Read::Population => &b"populated 0\nfrozen 0\n"[..],
                Read::Born => {
                    born = worker_message(
                        4,
                        9,
                        88,
                        if self.case == Case::DoubleFork { 99 } else { 0 },
                        self.case.shape(),
                    );
                    &born[..]
                }
                Read::Complete
                    if matches!(
                        self.case.bounds(),
                        Some(bounds::BoundCase::ExtensionFlood | bounds::BoundCase::OutputFlood)
                    ) =>
                {
                    &flood[..]
                }
                Read::Ready | Read::Complete | Read::Active => {
                    let epoch = if kind == Read::Complete {
                        self.result_epoch.unwrap_or(
                            if self.case.bounds() == Some(bounds::BoundCase::Replay) {
                                8
                            } else {
                                9
                            },
                        )
                    } else {
                        9
                    };
                    record = message(
                        match kind {
                            Read::Ready => 1,
                            Read::Active => 9,
                            _ => self.result_tag.unwrap_or(2),
                        },
                        epoch,
                    );
                    &record[..]
                }
            };
            if self.truncated && kind == Read::Ready && offset >= 3 {
                return Ok(0);
            }
            let count = (data.len().saturating_sub(offset))
                .min(output.len())
                .min(if self.chunk == 0 { 4096 } else { self.chunk });
            output[..count].copy_from_slice(&data[offset..offset + count]);
            if kind == Read::Born && offset + count == data.len() {
                self.next_clock = self.born_postcheck.take();
            }
            if kind == Read::Complete
                && self.case.bounds() == Some(bounds::BoundCase::LateRead)
                && offset + count == data.len()
            {
                self.next_clock = Some(Ok(self.work_cap.unwrap()));
            }
            Ok(count)
        }
        fn write(&mut self, kind: Write, _: &Resources<u32>, data: &[u8]) -> Result<usize> {
            if kind == Write::Kill {
                self.cleanup_started = true;
            }
            if kind == Write::Command
                && data == message(10, 9)
                && self.case.bounds().is_some()
                && !matches!(
                    self.case.bounds(),
                    Some(bounds::BoundCase::SupervisorStall | bounds::BoundCase::WorkerStall)
                )
            {
                if !self.premature_result {
                    self.worker_live = false;
                }
                self.extra = VecDeque::from([Wait::Terminal {
                    pid: 88,
                    code: 1,
                    status: i32::from(self.bad_worker_status),
                }]);
            }
            self.record(kind.name())?;
            if kind == Write::Kill && self.kill_denied {
                return Err(failure("kill-denied", 13));
            }
            if kind == Write::Kill {
                if !self.leaf_only_kill || self.placed {
                    self.worker_live = false;
                }
                if !self.leaf_only_kill {
                    self.descendant_live = false;
                }
                self.killed = true;
            }
            if kind == Write::Command && data == message(3, 9) && self.case != Case::SupervisorOnly
            {
                self.workers_created = true;
                self.worker_live = self.case.shape() == 0;
                self.descendant_live = self.case == Case::DoubleFork;
                self.extra.push_back(Wait::Terminal {
                    pid: 88,
                    code: if self.worker_live { 2 } else { 1 },
                    status: if self.worker_live { 9 } else { 0 },
                });
                if self.descendant_live {
                    self.extra.push_back(Wait::Terminal {
                        pid: 99,
                        code: 2,
                        status: 9,
                    });
                }
            }
            Ok(data.len())
        }
        fn wait(&mut self, child: Option<&Child<u32>>, consume: bool) -> Result<Wait> {
            assert!(
                !consume || self.cleanup_started,
                "consuming wait before placement ended or aborted"
            );
            if let Some(child) = child {
                assert_eq!(child.pid, 77, "M cannot waitid B before adoption");
                self.log
                    .push(format!("wait:{}:{consume}", child.pidfd.unwrap_or(0)));
                self.record("wait-direct")?;
                if self.direct_consumed {
                    return Ok(Wait::NoChildren);
                }
                if !consume {
                    self.peeks += 1;
                    if !self.signal_sent && self.early_at_peek.is_none_or(|at| self.peeks < at) {
                        return Ok(Wait::Pending);
                    }
                } else if self.pending {
                    return Ok(Wait::Pending);
                }
                if let Some(reply) = self.wait_reply {
                    return Ok(reply);
                }
                if consume {
                    self.direct_consumed = true;
                    if self.wait_postcheck.is_some_and(|(direct, _)| direct) {
                        self.next_clock = self.wait_postcheck.take().map(|(_, result)| result);
                    }
                }
                Ok(Wait::Terminal {
                    pid: 77,
                    code: if self.signal_sent { 2 } else { 1 },
                    status: if self.signal_sent { 9 } else { 0 },
                })
            } else {
                self.record("wait-all")?;
                if self.case.bounds() == Some(bounds::BoundCase::WithheldWait) {
                    return Err(failure("fixture-withheld-wait", 0));
                }
                if self.pending_adopted
                    || self.worker_live
                    || self.descendant_live
                    || (self.workers_created && !self.killed)
                {
                    return Ok(Wait::Pending);
                }
                let event = self.extra.pop_front().unwrap_or(Wait::NoChildren);
                if matches!(event, Wait::Terminal { .. })
                    && self.wait_postcheck.is_some_and(|(direct, _)| !direct)
                {
                    self.next_clock = self.wait_postcheck.take().map(|(_, result)| result);
                }
                Ok(event)
            }
        }
        fn pause(&mut self, _: u64) -> Result<()> {
            if !self.stopped_clock {
                self.now += if self.case.bounds().is_some() {
                    bounds::POLL_MS as u64 * 1_000_000
                } else {
                    SECOND
                };
            }
            self.record("pause")
        }
        fn remove(&mut self, group: Group, _: &Resources<u32>) -> Result<()> {
            self.log.push(format!("remove:{}", group.name()));
            self.record("remove")
        }
        fn close(&mut self, handle: u32) -> Result<()> {
            self.log.push(format!("close:{handle}"));
            assert!(
                self.alive.remove(&handle),
                "closed unowned/reused fd {handle}"
            );
            if self.close_at.is_some_and(|(fd, _)| fd == handle) {
                self.now = self.close_at.take().unwrap().1;
            }
            if handle == 42 {
                self.pidfd_closed = true;
            }
            self.record("close")
        }
        fn registration(&mut self, _: &Resources<u32>, output: &mut [u8]) -> Result<Transfer<u32>> {
            self.record("registration")?;
            let mut bytes = worker_message(
                6,
                9,
                88,
                if self.case == Case::DoubleFork { 99 } else { 0 },
                self.case.shape(),
            );
            match self.transfer_fault {
                Some("epoch") => bytes[1] ^= 1,
                Some("pid") => bytes[9] ^= 1,
                _ => {}
            }
            if self.transfer_fault == Some("eof") && self.rights_sent {
                return Ok(Transfer {
                    count: 0,
                    handles: [None, None],
                    valid: true,
                });
            }
            let count = (bytes.len() - self.registration_offset)
                .min(output.len())
                .min(if matches!(self.transfer_fault, Some("eof" | "repeat")) {
                    3
                } else if self.chunk == 0 {
                    BUFFER
                } else {
                    self.chunk
                });
            output[..count].copy_from_slice(
                &bytes[self.registration_offset..self.registration_offset + count],
            );
            self.registration_offset += count;
            let fd = if self.transfer_fault == Some("missing") {
                None
            } else if self.rights_sent {
                if self.transfer_fault == Some("repeat") {
                    self.alive.insert(44);
                    Some(44)
                } else {
                    None
                }
            } else {
                self.rights_sent = true;
                self.alive.insert(43);
                Some(43)
            };
            let extra = if self.transfer_fault == Some("extra") {
                self.alive.insert(44);
                Some(44)
            } else {
                None
            };
            Ok(Transfer {
                count,
                handles: [fd, extra],
                valid: self.transfer_fault != Some("truncated"),
            })
        }
        fn worker_identity(&mut self, child: &Child<u32>, _: Case, _: u32) -> Result<()> {
            self.record("worker-identity")?;
            if self.transfer_fault == Some("identity") {
                return Err(failure("pidfd-identity", 0));
            }
            assert_eq!(child.pid, 88);
            assert_eq!(child.pidfd, Some(43));
            Ok(())
        }
        fn members(
            &mut self,
            _: &Resources<u32>,
            supervisor: &[u32],
            worker: &[u32],
        ) -> Result<()> {
            self.record("worker-membership")?;
            if self.bad_readback && self.placed {
                return Err(failure("wrong-worker-leaf", 0));
            }
            let mut actual = vec![77];
            if self.worker_live && !self.placed {
                actual.push(88);
            }
            if self.descendant_live {
                actual.push(99);
            }
            let bytes = actual
                .iter()
                .map(|pid| format!("{pid}\n"))
                .collect::<String>();
            membership(bytes.as_bytes(), supervisor)?;
            membership(if self.placed { b"88\n" } else { b"" }, worker)
        }
        fn place(&mut self, resources: &Resources<u32>, child: &Child<u32>) -> Result<()> {
            self.record("placement")?;
            assert!(self.worker_live && !self.killed && !self.direct_consumed);
            assert!(resources.get(Kind::Worker).is_some());
            assert_eq!(child.pidfd, Some(43));
            self.placed = true;
            Ok(())
        }
        fn signal(&mut self, child: &Child<u32>) -> Result<()> {
            self.record("signal")?;
            assert_eq!(child.pidfd, Some(42));
            assert!(!self.direct_consumed);
            self.signal_sent = true;
            Ok(())
        }
        fn oom_kills(&mut self, _: &Resources<u32>) -> Result<[u64; 3]> {
            self.record("oom")?;
            self.oom_reads += 1;
            let mut counts = self.local_ooms;
            counts[0] = counts[0].max(u64::from(self.oom_at != 0 && self.oom_reads >= self.oom_at));
            Ok(counts)
        }
        fn initialize_sentinel(&mut self, resources: &Resources<u32>, _: u64) -> Result<()> {
            assert_eq!(resources.get(Kind::Sentinel), Some(&19));
            self.record("sentinel-write")?;
            self.record("sentinel-seal")?;
            self.sentinel_initialized = true;
            Ok(())
        }
        fn verify_sentinel(
            &mut self,
            resources: &Resources<u32>,
            _: u64,
            after: bool,
        ) -> Result<()> {
            assert_eq!(resources.get(Kind::Sentinel), Some(&19));
            assert!(self.alive.contains(&19));
            self.record(if after {
                "sentinel-after"
            } else {
                "sentinel-before"
            })?;
            if !self.sentinel_initialized {
                return Err(failure("sentinel-proof", 0));
            }
            if after && self.case.bounds() == Some(bounds::BoundCase::WithheldSentinel) {
                return Err(failure("fixture-withheld-sentinel", 0));
            }
            Ok(())
        }
        fn arm_work(&mut self, cap: u64) -> Result<()> {
            self.record("arm-work")?;
            if self.work_cap.is_some() {
                return Err(failure("work-rearm", 0));
            }
            self.work_cap = Some(cap);
            Ok(())
        }
        fn worker_terminal(&mut self, child: &Child<u32>) -> Result<bool> {
            self.record("worker-terminal")?;
            assert_eq!(child.pidfd, Some(43));
            Ok(!self.worker_live)
        }
    }

    fn completed(result: Completion<u32>) -> Report {
        match result {
            Completion::Clean { report, .. } => report,
            Completion::Quarantined(owner) => panic!("unexpected quarantine: {:?}", owner.report),
        }
    }

    #[test]
    fn c04_initialization_refusal_releases_only_unstarted_owner() {
        for (now, epoch, fault, expected) in [
            (0, 9, Some("clock"), failure("clock", 5)),
            (u64::MAX, 9, None, failure("deadline", 0)),
            (0, 0, None, failure("epoch", 0)),
        ] {
            let mut os = Fake {
                now,
                faults: fault.into_iter().collect(),
                ..Fake::default()
            };
            let result = run(&mut os, epoch);
            assert!(
                matches!(result, Completion::Clean { .. }),
                "initial refusal must not quarantine an unstarted job"
            );
            let report = result.report();
            assert_eq!(report.outcome, Outcome::NoJobCreated);
            assert_eq!(report.first, Some(expected));
            assert_eq!(report.releases, 1);
            assert_eq!(report.leases_held, [false; 2]);
            assert!(!report.custody_retained);
            assert!(!report.kill && !report.empty && !report.direct_reaped && !report.drained);
            assert_eq!(report.consumers, 0);
            assert_eq!(report.adopted, 0);
            assert_eq!(report.terminal, [None; 33]);
            assert_eq!(report.operations, 0);
            assert_eq!(os.log, ["clock"]);
            assert!(os.alive.is_empty());
            // Clean contains only the report, not an owner that can be finished again.
            assert_eq!(result.report().releases, 1);
            assert_eq!(os.log, ["clock"]);
        }
    }

    #[test]
    fn c04_initialization_refusal_cannot_release_acquired_or_used_owner() {
        for state in 0..8 {
            let mut owner = Quarantine::<u32>::new(9);
            match state {
                0 => owner.created[0] = true,
                1 => owner.created[1] = true,
                2 => owner.resources.put(Kind::Parent, 10),
                3 => {
                    owner.child = Some(Child {
                        pid: 77,
                        pidfd: Some(42),
                        valid: true,
                    })
                }
                4 => owner.report.consumers = 1,
                5 => owner.report.operations = 1,
                6 => owner.deadlines = Some(Deadlines::new(0).unwrap()),
                7 => owner.report.releases = 1,
                _ => unreachable!(),
            }
            let releases = owner.report.releases;
            let result = initialization_refusal(owner, failure("clock", 5));
            assert!(matches!(result, Completion::Quarantined(_)));
            assert_eq!(result.report().releases, releases);
            assert_eq!(result.report().first, Some(failure("clock", 5)));
        }
    }

    #[test]
    fn c06_late_pidfd_close_keeps_custody_and_terminal_facts() {
        let mut os = Fake {
            close_at: Some((42, 5 * SECOND)),
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_eq!(result.report().releases, 0);
        let Completion::Quarantined(owner) = result else {
            panic!("late close released custody");
        };
        assert_eq!(owner.report.first, Some(failure("expired", 0)));
        assert!(owner.report.kill && owner.report.empty && owner.report.drained);
        assert!(owner.report.direct_reaped && owner.report.terminal[0].is_some());
        assert_eq!(owner.report.leases_held, [true; 2]);
        assert!(owner.report.custody_retained);
        assert!(owner.child.unwrap().pidfd.is_none());
        assert_eq!(os.log.iter().filter(|s| *s == "close:42").count(), 1);
    }

    #[test]
    fn c06_release_rechecks_clock_after_successful_close_postcheck() {
        let mut os = Fake {
            after_pidfd_clocks: VecDeque::from([Ok(0), Ok(5 * SECOND)]),
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_eq!(result.report().releases, 0);
        assert!(matches!(result, Completion::Quarantined(_)));
        assert_eq!(result.report().first, Some(failure("expired", 0)));
        assert!(result.report().direct_reaped);
    }

    #[test]
    fn c06_expired_dispose_keeps_unconsumed_pidfd() {
        let mut os = Fake {
            now: 15 * SECOND,
            ..Fake::default()
        };
        os.alive.insert(42);
        let mut owner = Quarantine::new(9);
        owner.deadlines = Some(Deadlines::new(0).unwrap());
        owner.child = Some(Child {
            pid: 77,
            pidfd: Some(42),
            valid: true,
        });
        assert_eq!(dispose(&mut os, &mut owner), Err(failure("expired", 0)));
        assert!(os.alive.contains(&42));
        assert_eq!(owner.child.unwrap().pidfd, Some(42));
    }

    #[test]
    fn c08_consumed_direct_terminal_survives_failed_postcheck() {
        for postcheck in [Err(failure("clock", 5)), Ok(5 * SECOND)] {
            let mut os = Fake {
                wait_postcheck: Some((true, postcheck)),
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert!(os.direct_consumed);
            assert!(
                result.report().direct_reaped,
                "consumed wait evidence was lost"
            );
            assert_eq!(
                result.report().terminal[0],
                Some(Wait::Terminal {
                    pid: 77,
                    code: 1,
                    status: 0
                })
            );
            assert_eq!(result.report().consumers, 0);
            assert_eq!(
                result.report().first,
                Some(postcheck.err().unwrap_or(failure("expired", 0)))
            );
            assert_eq!(result.report().releases, 0);
            let Completion::Quarantined(owner) = result else {
                panic!("failed cleanup postcheck released custody");
            };
            assert_eq!(os.wait(owner.child.as_ref(), true), Ok(Wait::NoChildren));
        }
    }

    #[test]
    fn c12_consumed_adopted_terminal_survives_failed_postcheck() {
        for postcheck in [Err(failure("clock", 5)), Ok(5 * SECOND)] {
            let event = Wait::Terminal {
                pid: 88,
                code: 2,
                status: 9,
            };
            let mut os = Fake {
                extra: VecDeque::from([event]),
                wait_postcheck: Some((false, postcheck)),
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert!(os.extra.is_empty());
            assert_eq!(
                result.report().adopted,
                1,
                "consumed adopted evidence was lost"
            );
            assert_eq!(result.report().terminal[1], Some(event));
            assert_eq!(
                result.report().first,
                Some(failure("unexpected-adopted-child", 0))
            );
            assert!(result
                .report()
                .errors
                .iter()
                .flatten()
                .any(|e| *e == postcheck.err().unwrap_or(failure("expired", 0))));
            assert_eq!(result.report().releases, 0);
            assert!(matches!(result, Completion::Quarantined(_)));
            assert_eq!(os.wait(None, true), Ok(Wait::NoChildren));
        }
    }

    #[test]
    fn c08_early_terminal_peek_prevents_success_and_still_reaps() {
        for early in [1, 2] {
            let mut os = Fake {
                early_at_peek: Some(early),
                ..Fake::default()
            };
            let report = completed(run(&mut os, 9));
            assert_eq!(report.outcome, Outcome::AbortedClean);
            assert_eq!(report.first, Some(failure("supervisor-early", 0)));
            assert_eq!(report.releases, 1);
            assert!(report.direct_reaped && os.direct_consumed);
            assert!(report.terminal[0].is_some());
            assert_eq!(os.log.iter().filter(|s| *s == "command").count(), early - 1);
            assert_eq!(os.log.iter().filter(|s| *s == "wait:42:true").count(), 1);
        }
    }

    #[test]
    fn c13_sparse_child_close_plan_includes_zero_and_excludes_peer() {
        let mut resources = Resources::new();
        resources.put(Kind::Parent, 0u32);
        resources.put(Kind::Events, 55);
        resources.put(Kind::Peer, 77);
        assert_eq!(
            resources.child_closes().copied().collect::<Vec<_>>(),
            vec![0, 55]
        );
    }

    #[test]
    fn c01_exact_birth_request() {
        let request = CloneRequest::new(17);
        assert_eq!(request.flags, 0x0000_0002_0000_1000);
        assert_eq!(request.exit_signal, 17);
        assert_eq!(request.cgroup, 17);
        assert_eq!(request.unused, [0; 7]);
        assert_eq!(&job_name(u64::MAX), b"job-ffffffffffffffff\0");
        assert_eq!(&job_name(9), b"job-0000000000000009\0");
    }

    #[test]
    fn c07_population_is_complete_bounded_and_unique() {
        assert_eq!(population(b"populated 0\nfrozen 0\n"), Ok(false));
        assert_eq!(population(b"frozen 1\npopulated 1\n"), Ok(true));
        for bytes in [
            &b"frozen 0\n"[..],
            &b"populated 0"[..],
            &b"populated 0\npopulated 1\n"[..],
            &b"populated 2\n"[..],
            &b"populated 0\nfrozen x\n"[..],
        ] {
            assert!(population(bytes).is_err(), "{bytes:?}");
        }
        assert!(population(&[b'x'; 4096]).is_err());
    }

    #[test]
    fn c10_absolute_checked_caps_and_equality() {
        let mut deadlines = Deadlines::new(11).unwrap();
        assert_eq!(
            deadlines.caps,
            [5000000011, 10000000011, 15000000011, 20000000011]
        );
        assert!(!deadlines.expired(Phase::Startup, 5000000010));
        assert!(deadlines.expired(Phase::Startup, 5000000011));
        deadlines.tighten(Phase::Cleanup, 12).unwrap();
        assert_eq!(deadlines.cap(Phase::Cleanup), 5000000012);
        deadlines.tighten(Phase::Cleanup, 1000).unwrap();
        assert_eq!(deadlines.cap(Phase::Cleanup), 5000000012);
        assert!(Deadlines::new(u64::MAX).is_err());
        let mut os = Fake {
            advance_on: Some(("configure", 5 * SECOND)),
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_eq!(result.report().first, Some(failure("expired", 0)));
        assert!(!os.log.iter().any(|s| s == "birth"));
        let mut os = Fake {
            pending: true,
            stopped_clock: true,
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_eq!(result.report().releases, 0);
        assert!(result.report().operations <= MAX_OPERATIONS);
        assert!(result
            .report()
            .errors
            .iter()
            .flatten()
            .any(|e| e.operation == "operation-cap"));
        let mut os = Fake {
            stall_ready: true,
            stopped_clock: true,
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert!(
            result.report().kill,
            "exercise exhausted cleanup's operation reserve"
        );
        assert_eq!(result.report().outcome, Outcome::AbortedClean);
    }

    #[test]
    fn c02_positive_order_and_single_release() {
        let mut os = Fake::default();
        let report = completed(run(&mut os, 9));
        assert_eq!(report.outcome, Outcome::Complete);
        assert_eq!(report.releases, 1);
        assert!(!report.native_authorized && !report.full_contract_proven);
        assert_eq!(report.leases_held, [false; 2]);
        assert!(!report.custody_retained);
        assert_eq!(
            report.terminal[0],
            Some(Wait::Terminal {
                pid: 77,
                code: 1,
                status: 0
            })
        );
        assert!(report.kill && report.empty && report.direct_reaped && report.drained);
        assert!(os.alive.is_empty());
        assert!(
            os.log.iter().position(|s| s == "configure").unwrap()
                < os.log.iter().position(|s| s == "birth").unwrap()
        );
        assert!(
            os.log.iter().position(|s| s == "wait:42:true").unwrap()
                < os.log.iter().position(|s| s == "wait-all").unwrap()
        );
    }

    #[test]
    fn c03_setup_refusals_have_no_fallback() {
        for stage in [
            "prepare",
            "parent",
            "evidence",
            "job-create",
            "job",
            "configure",
            "leaf-create",
            "leaf",
            "channels",
        ] {
            let mut os = Fake {
                faults: VecDeque::from([stage]),
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert_ne!(result.report().outcome, Outcome::Complete, "{stage}");
            assert!(!os.log.iter().any(|s| s == "birth"), "{stage}");
        }
        for errno in [38, 95, 13, 1, 22, 9, 7, 12, 11] {
            let mut os = Fake {
                birth_errno: errno,
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert_eq!(result.report().first, Some(failure("clone3", errno)));
            assert_eq!(os.log.iter().filter(|s| *s == "birth").count(), 1);
        }
    }

    #[test]
    fn c04_every_acquisition_failure_retains_custody() {
        for stage in ["clock", "kill", "events", "birth"] {
            let mut os = Fake {
                faults: VecDeque::from([stage]),
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert!(result.report().reserved, "{stage}");
            assert!(result.report().first.is_some(), "{stage}");
            if matches!(result, Completion::Clean { .. }) {
                assert!(os.alive.is_empty());
            } else {
                assert_eq!(result.report().releases, 0);
            }
        }
    }

    #[test]
    fn c05_failed_dirty_slot_and_successful_child_ownership() {
        let mut os = Fake {
            dirty_error: true,
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert!(result.report().first.is_some());
        assert_eq!(os.alive, BTreeSet::from([99]));
        assert!(!os.log.iter().any(|s| s == "close:99"));
        let mut os = Fake {
            malformed: true,
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_ne!(result.report().outcome, Outcome::Complete);
        assert!(os.log.iter().any(|s| s == "wait:42:true"));
    }

    #[test]
    fn c06_independent_cleanup_and_quarantine_owner() {
        let mut os = Fake {
            pending: true,
            ..Fake::default()
        };
        let Completion::Quarantined(owner) = run(&mut os, 9) else {
            panic!("missing owner");
        };
        assert!(owner.report.kill && owner.report.empty);
        assert!(!owner.report.direct_reaped);
        assert_eq!(owner.report.releases, 0);
        assert_eq!(owner.report.leases_held, [true; 2]);
        assert!(owner.report.custody_retained);
        assert!(owner.child.is_some());
        assert!(owner.resources.get(Kind::Job).is_some());
        assert!(os.alive.contains(&42));
        for (population_live, kill_denied) in [(true, false), (false, true)] {
            let mut os = Fake {
                population_live,
                kill_denied,
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert!(matches!(result, Completion::Quarantined(_)));
            assert_eq!(result.report().releases, 0);
        }
        let mut os = Fake::default();
        let mut owner = Quarantine::new(9);
        owner.deadlines = Some(Deadlines::new(0).unwrap());
        attempt(&mut os, &mut owner).unwrap();
        owner.report.consumers += 1;
        let result = finish(&mut os, owner);
        assert_eq!(result.report().releases, 0, "remaining consumer lost");
    }

    #[test]
    fn c08_pending_observation_is_not_a_consuming_wait() {
        let mut os = Fake {
            pending: true,
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert!(!result.report().direct_reaped);
        assert!(!os.log.iter().any(|s| s == "wait-all"));
        assert_eq!(result.report().releases, 0);
        for reply in [
            Wait::NoChildren,
            Wait::Terminal {
                pid: 77,
                code: 5,
                status: 0,
            },
            Wait::Terminal {
                pid: 999,
                code: 1,
                status: 0,
            },
        ] {
            let mut os = Fake {
                wait_reply: Some(reply),
                ..Fake::default()
            };
            let result = run(&mut os, 9);
            assert_eq!(result.report().releases, 0);
            assert!(!result.report().direct_reaped);
        }
    }

    #[test]
    fn c09_wait_uses_owned_handle_not_reported_pid() {
        let mut os = Fake::default();
        let _ = completed(run(&mut os, 9));
        assert!(os.log.iter().any(|s| s == "wait:42:true"));
        assert!(!os.log.iter().any(|s| s.starts_with("wait:77:")));
        let mut replacement = Fake {
            wait_handle: 142,
            ..Fake::default()
        };
        let _ = completed(run(&mut replacement, 9));
        assert!(replacement.log.iter().any(|s| s == "wait:142:true"));
        assert!(!replacement.log.iter().any(|s| s == "wait:42:true"));
    }

    #[test]
    fn c11_partial_record_and_eof_have_distinct_results() {
        let mut os = Fake {
            chunk: 2,
            ..Fake::default()
        };
        assert_eq!(completed(run(&mut os, 9)).outcome, Outcome::Complete);
        let mut os = Fake {
            chunk: 3,
            truncated: true,
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_eq!(result.report().first, Some(failure("channel-eof", 0)));
        assert_ne!(result.report().outcome, Outcome::Complete);
    }

    #[test]
    fn c12_one_cleanup_path_drains_adopted_after_direct() {
        let mut os = Fake {
            faults: VecDeque::from(["ready"]),
            extra: VecDeque::from([Wait::Terminal {
                pid: 88,
                code: 2,
                status: 9,
            }]),
            ..Fake::default()
        };
        let report = completed(run(&mut os, 9));
        assert_eq!(report.outcome, Outcome::AbortedClean);
        assert_eq!(report.adopted, 1);
        assert_eq!(
            report.terminal[1],
            Some(Wait::Terminal {
                pid: 88,
                code: 2,
                status: 9
            })
        );
        assert_eq!(report.first, Some(failure("ready", 5)));
    }

    #[test]
    fn c13_transfer_closes_exact_owned_descriptors() {
        let mut os = Fake {
            faults: VecDeque::from(["close"]),
            ..Fake::default()
        };
        let result = run(&mut os, 9);
        assert_ne!(result.report().outcome, Outcome::Complete);
        assert_eq!(os.log.iter().filter(|s| *s == "close:17").count(), 1);
        let mut resources = Resources::new();
        for kind in Kind::ALL {
            resources.put(kind, kind as u32 + 10);
        }
        let close: BTreeSet<_> = resources.child_closes().copied().collect();
        assert_eq!(close, (10..17).chain([18, 19]).collect());
    }

    #[test]
    fn c14_first_error_survives_successful_cleanup_and_secondary_error() {
        let mut os = Fake {
            faults: VecDeque::from(["ready", "kill-write"]),
            ..Fake::default()
        };
        let report = completed(run(&mut os, 9));
        assert_eq!(report.outcome, Outcome::AbortedClean);
        assert_eq!(report.first, Some(failure("ready", 5)));
        assert!(report
            .errors
            .iter()
            .flatten()
            .any(|e| *e == failure("kill-write", 5)));
        assert_eq!(report.releases, 1);
    }

    #[test]
    fn c19_membership_requires_complete_exact_unordered_unique_live_set() {
        assert_eq!(membership(b"", &[]), Ok(()));
        assert_eq!(membership(b"77\n88\n", &[88, 77]), Ok(()));
        for bytes in [
            &b"77\n"[..],
            &b"77\n88"[..],
            &b"77\n77\n88\n"[..],
            &b"77\n88\n99\n"[..],
            &b"77\n+88\n"[..],
            &b"77\n 88\n"[..],
            &b"77\n0\n"[..],
            &b"77\n2147483648\n"[..],
        ] {
            assert!(membership(bytes, &[77, 88]).is_err(), "{bytes:?}");
        }
        assert!(membership(b"77\n", &[]).is_err());
        assert!(membership(b"77\n77\n", &[77, 77]).is_err());
        assert!(membership(b"0\n", &[0]).is_err());
        assert!(membership(&[b'7'; BUFFER], &[77]).is_err());
    }

    #[test]
    fn c20_pidfd_record_matches_one_visible_namespace_and_owned_pid() {
        assert_eq!(
            pidfd_identity(b"pos:\t0\nflags:\t02000002\nPid:\t88\nNSpid:\t88\n", 88),
            Ok(())
        );
        for data in [
            &b"Pid:\t89\nNSpid:\t89\n"[..],
            &b"Pid:\t88\n"[..],
            &b"Pid:\t88\nNSpid:\t88\t1\n"[..],
            &b"Pid:\t88\nPid:\t88\nNSpid:\t88\n"[..],
            &b"Pid:\t88\nNSpid:\t88\nNSpid:\t88\n"[..],
            &b"Pid:\t-1\nNSpid:\t-1\n"[..],
            &b"Pid:\t0\nNSpid:\t0\n"[..],
            &b"Pid:\t88\nNSpid:\t88"[..],
        ] {
            assert!(pidfd_identity(data, 88).is_err(), "{data:?}");
        }
        assert!(pidfd_identity(b"Pid:\t0\nNSpid:\t0\n", 0).is_err());
        assert!(pidfd_identity(b"Pid:\t2147483648\nNSpid:\t2147483648\n", 2147483648).is_err());
    }

    #[test]
    fn c21_each_loss_cut_requires_its_actual_witness_and_complete_reaping() {
        assert_eq!(
            Cut::ALL,
            [
                Cut::BeforeBirth,
                Cut::BeforeDelivery,
                Cut::BeforeRegistration,
                Cut::BeforePlacement,
                Cut::BeforeReadback,
                Cut::AfterReadback
            ]
        );
        for cut in Cut::ALL {
            let case = Case::Loss(cut);
            let mut os = Fake {
                case,
                ..Fake::default()
            };
            let report = completed(run_case(&mut os, 9, case));
            assert!(report.case_passed(), "{cut:?}: {report:?}");
            assert_eq!(report.reached, Some(cut));
            assert_eq!(report.adopted, u32::from(cut != Cut::BeforeBirth));
            assert_eq!(
                report.placed,
                matches!(cut, Cut::BeforeReadback | Cut::AfterReadback)
            );
            assert_eq!(report.placement_verified, cut == Cut::AfterReadback);
            assert!(os.alive.is_empty(), "{cut:?}");
        }
    }

    #[test]
    fn c22_unreached_cut_or_oom_cannot_be_credited_as_injection() {
        let case = Case::Loss(Cut::AfterReadback);
        for stage in [
            "born",
            "registration",
            "worker-identity",
            "placement",
            "worker-membership",
            "signal",
        ] {
            let mut os = Fake {
                case,
                faults: VecDeque::from([stage]),
                ..Fake::default()
            };
            let report = run_case(&mut os, 9, case);
            assert!(!report.report().case_passed(), "{stage}");
        }
        for at in [1, 2, 3] {
            let mut os = Fake {
                case,
                oom_at: at,
                ..Fake::default()
            };
            let report = run_case(&mut os, 9, case);
            assert!(!report.report().case_passed(), "OOM observation {at}");
        }
    }

    #[test]
    fn c23_delivered_handle_survives_postcheck_failure_and_is_closed_once() {
        let case = Case::Loss(Cut::AfterReadback);
        let mut os = Fake {
            case,
            advance_on: Some(("registration", 10 * SECOND)),
            ..Fake::default()
        };
        let report = run_case(&mut os, 9, case);
        assert!(!report.report().case_passed());
        assert!(report.report().worker_pid.is_some());
        assert_eq!(os.log.iter().filter(|s| *s == "close:43").count(), 1);
        assert!(!os.alive.contains(&43));
    }

    #[test]
    fn c24_partial_positive_send_transfers_rights_only_once() {
        for first in 1..=WORKER_RECORD {
            let mut progress = RightsProgress::default();
            assert!(progress.send_rights());
            assert!(progress.advance(0).is_err());
            assert!(progress.send_rights());
            progress.advance(first).unwrap();
            assert!(!progress.send_rights());
            if first < WORKER_RECORD {
                progress.advance(WORKER_RECORD - first).unwrap();
            }
            assert_eq!(progress.offset, WORKER_RECORD);
            assert!(progress.advance(1).is_err());
            assert!(!progress.send_rights());
        }
    }

    #[test]
    fn c25_oom_evidence_must_be_complete_unique_and_numeric() {
        assert_eq!(
            oom_count(b"low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\noom_group_kill 0\n"),
            Ok(0)
        );
        assert_eq!(oom_count(b"oom_kill 4\n"), Ok(4));
        for bytes in [
            &b"oom 0\n"[..],
            &b"oom_kill 0"[..],
            &b"oom_kill 0\noom_kill 1\n"[..],
            &b"oom_kill -1\n"[..],
            &b"oom_kill +1\n"[..],
        ] {
            assert!(oom_count(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn c26_double_fork_and_zombie_require_every_adopted_wait() {
        for case in [Case::DoubleFork, Case::Zombie] {
            let mut os = Fake {
                case,
                ..Fake::default()
            };
            let report = completed(run_case(&mut os, 9, case));
            assert!(report.case_passed(), "{case:?}: {report:?}");
            assert!(report.worker_reaped);
            assert_eq!(report.descendant_reaped, case == Case::DoubleFork);
            assert!(!report.placed);
            let mut os = Fake {
                case,
                pending_adopted: true,
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            assert!(matches!(result, Completion::Quarantined(_)));
            assert_eq!(result.report().releases, 0);
            assert!(result.report().empty && result.report().direct_reaped);
            assert!(!result.report().worker_reaped);
        }
    }

    #[test]
    fn c27_rejected_and_fragmented_rights_preserve_exact_handle_ownership() {
        let case = Case::Loss(Cut::AfterReadback);
        let mut fragmented = Fake {
            case,
            chunk: 1,
            ..Fake::default()
        };
        assert!(completed(run_case(&mut fragmented, 9, case)).case_passed());
        for fault in [
            "missing",
            "extra",
            "truncated",
            "epoch",
            "pid",
            "eof",
            "repeat",
            "identity",
        ] {
            let mut os = Fake {
                case,
                transfer_fault: Some(fault),
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            assert!(!result.report().case_passed(), "{fault}");
            assert!(!os.placed, "{fault}");
            assert!(os.alive.is_empty(), "{fault}: {:?}", os.alive);
            assert_eq!(
                os.log.iter().filter(|s| *s == "close:43").count(),
                usize::from(fault != "missing"),
                "{fault}"
            );
            assert_eq!(
                os.log.iter().filter(|s| *s == "close:44").count(),
                usize::from(matches!(fault, "extra" | "repeat")),
                "{fault}"
            );
        }
    }

    #[test]
    fn c28_leaf_only_cleanup_and_unverified_placement_cannot_complete() {
        let case = Case::Loss(Cut::BeforePlacement);
        let mut os = Fake {
            case,
            leaf_only_kill: true,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert!(matches!(result, Completion::Quarantined(_)));
        assert_eq!(result.report().releases, 0);
        assert!(os.worker_live);
        assert!(
            !result.report().worker_reaped,
            "the live-child model cannot yield a terminal wait"
        );
        let case = Case::Loss(Cut::AfterReadback);
        let mut os = Fake {
            case,
            bad_readback: true,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert!(result.report().placed);
        assert!(!result.report().placement_verified);
        assert!(!result.report().case_passed());
        assert!(!os.signal_sent);
    }

    #[test]
    fn c29_natural_or_wrong_signal_exit_is_not_an_effective_cut() {
        let case = Case::Loss(Cut::BeforePlacement);
        let mut os = Fake {
            case,
            early_at_peek: Some(1),
            ..Fake::default()
        };
        assert!(!run_case(&mut os, 9, case).report().case_passed());
        assert!(!os.signal_sent);
        for (code, status) in [(1, 0), (2, 15), (3, 9)] {
            let mut os = Fake {
                case,
                wait_reply: Some(Wait::Terminal {
                    pid: 77,
                    code,
                    status,
                }),
                ..Fake::default()
            };
            assert!(!run_case(&mut os, 9, case).report().case_passed());
        }
    }

    #[test]
    fn c30_born_identity_is_epoch_bound_and_disjoint() {
        let valid = worker_message(4, 9, 88, 0, 0);
        assert_eq!(
            worker_record(&valid, 9, 77, Case::Loss(Cut::BeforePlacement)),
            Ok((88, 0))
        );
        for bytes in [
            worker_message(4, 8, 88, 0, 0),
            worker_message(4, 9, 77, 0, 0),
            worker_message(4, 9, 0, 0, 0),
            worker_message(4, 9, 88, 99, 0),
            worker_message(4, 9, 88, 0, 1),
        ] {
            assert!(worker_record(&bytes, 9, 77, Case::Loss(Cut::BeforePlacement)).is_err());
        }
        for descendant in [0, 77, 88, u32::MAX] {
            assert!(worker_record(
                &worker_message(4, 9, 88, descendant, 1),
                9,
                77,
                Case::DoubleFork
            )
            .is_err());
        }
    }

    #[test]
    fn c31_oom_before_injection_stops_signaling_not_only_case_acceptance() {
        let case = Case::Loss(Cut::BeforeBirth);
        let mut os = Fake {
            case,
            oom_at: 1,
            ..Fake::default()
        };
        let report = run_case(&mut os, 9, case);
        assert!(!os.signal_sent);
        assert!(!report.report().injected);
        assert_eq!(report.report().first, Some(failure("oom-contaminated", 0)));
        assert!(!report.report().case_passed());
    }

    #[test]
    fn c32_delivery_cut_precedes_all_registration_validation() {
        let case = Case::Loss(Cut::BeforeRegistration);
        let mut os = Fake {
            case,
            transfer_fault: Some("identity"),
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert!(!os.log.iter().any(|event| event == "worker-identity"));
        assert!(result.report().case_passed());
        assert!(!result.report().registered);
        assert_eq!(
            os.log.iter().filter(|event| *event == "close:43").count(),
            1
        );
    }

    #[test]
    fn c33_complete_birth_is_owned_before_final_fragment_postcheck() {
        let case = Case::DoubleFork;
        for error in [Err(failure("clock-after-born", 5)), Ok(10 * SECOND)] {
            let mut os = Fake {
                case,
                chunk: 3,
                born_postcheck: Some(error),
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            let report = result.report();
            assert_eq!(report.worker_pid, Some(88));
            assert_eq!(report.descendant_pid, Some(99));
            assert!(report.worker_reaped && report.descendant_reaped);
            assert!(!report
                .errors
                .iter()
                .flatten()
                .any(|error| error.operation == "unexpected-adopted-child"));
            assert!(!report.case_passed());
        }
    }

    #[test]
    fn c34_leaf_local_ooms_cannot_hide_behind_zero_parent_counter() {
        let case = Case::Loss(Cut::BeforePlacement);
        for local_ooms in [[1, 0, 0], [0, 1, 0], [0, 0, 1]] {
            let mut os = Fake {
                case,
                local_ooms,
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            assert!(!os.signal_sent, "{local_ooms:?}");
            assert!(!result.report().case_passed(), "{local_ooms:?}");
        }
    }

    fn named_cut(cut: Cut) {
        let case = Case::Loss(cut);
        let mut os = Fake {
            case,
            ..Fake::default()
        };
        let report = completed(run_case(&mut os, 9, case));
        assert!(report.case_passed(), "{cut:?}: {report:?}");
        assert_eq!(report.reached, Some(cut));
    }

    #[test]
    fn c35_before_birth() {
        named_cut(Cut::BeforeBirth);
    }
    #[test]
    fn c36_before_delivery() {
        named_cut(Cut::BeforeDelivery);
    }
    #[test]
    fn c37_before_registration() {
        named_cut(Cut::BeforeRegistration);
    }
    #[test]
    fn c38_before_placement() {
        named_cut(Cut::BeforePlacement);
    }
    #[test]
    fn c39_before_readback() {
        named_cut(Cut::BeforeReadback);
    }
    #[test]
    fn c40_after_readback() {
        named_cut(Cut::AfterReadback);
    }

    #[test]
    fn b01_complete_requires_cutover_and_returns_owned_sentinel() {
        let case = Case::Bounds(bounds::BoundCase::Complete);
        let mut os = Fake {
            case,
            ..Fake::default()
        };
        let Completion::Clean {
            report, sentinel, ..
        } = run_case(&mut os, 9, case)
        else {
            panic!("complete control quarantined");
        };
        assert!(report.case_passed(), "{report:?}");
        assert!(report.bounds.as_ref().unwrap().cutover);
        assert_eq!(sentinel, Some(19));
        assert!(os.alive.contains(&19));
        os.close(sentinel.unwrap()).unwrap();
        assert!(os.alive.is_empty());
    }

    #[test]
    fn b02_withheld_predicates_retain_sentinel_and_leases() {
        for kind in [
            bounds::BoundCase::WithheldWait,
            bounds::BoundCase::WithheldPopulation,
            bounds::BoundCase::WithheldConsumer,
            bounds::BoundCase::WithheldSentinel,
        ] {
            let case = Case::Bounds(kind);
            let mut os = Fake {
                case,
                ..Fake::default()
            };
            let Completion::Quarantined(owner) = run_case(&mut os, 9, case) else {
                panic!("withheld predicate released {kind:?}");
            };
            assert!(owner.report.case_passed(), "{kind:?}: {:?}", owner.report);
            assert_eq!(owner.resources.get(Kind::Sentinel), Some(&19));
            assert_eq!(owner.report.leases_held, [true; 2]);
            assert_eq!(owner.report.releases, 0);
            assert!(os.alive.contains(&19));
        }
    }

    #[test]
    fn b03_native_cadence_stalls_reach_deadline_before_operation_cap() {
        for kind in [
            bounds::BoundCase::SupervisorStall,
            bounds::BoundCase::WorkerStall,
        ] {
            let case = Case::Bounds(kind);
            let mut os = Fake {
                case,
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            assert!(
                result.report().case_passed(),
                "{kind:?}: {:?}",
                result.report()
            );
            assert_eq!(result.report().first, Some(failure("expired", 0)));
            assert!(result.report().operations < MAX_OPERATIONS / 2);
            assert_eq!(
                result.report().bounds.as_ref().unwrap().caps[3],
                20 * SECOND
            );
        }
    }

    fn bounded_case(kind: bounds::BoundCase) {
        let case = Case::Bounds(kind);
        let mut os = Fake {
            case,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert!(
            result.report().case_passed(),
            "{kind:?}: {:?}",
            result.report()
        );
        match result {
            Completion::Clean { sentinel, .. } => {
                assert_eq!(sentinel, Some(19));
                os.close(sentinel.unwrap()).unwrap();
                assert!(os.alive.is_empty());
            }
            Completion::Quarantined(owner) => {
                assert_eq!(owner.resources.get(Kind::Sentinel), Some(&19));
                assert!(!os.log.iter().any(|s| s == "close:19"));
            }
        }
    }

    #[test]
    fn b04_bounds_case_inventory_is_exact_and_unique() {
        use bounds::BoundCase::*;
        assert_eq!(
            bounds::BoundCase::ALL,
            [
                Complete,
                SupervisorStall,
                WorkerStall,
                ExtensionFlood,
                OutputFlood,
                Replay,
                LateRead,
                PreCutoverLoss,
                WithheldWait,
                WithheldPopulation,
                WithheldConsumer,
                WithheldSentinel
            ]
        );
        assert_eq!(bounds::POLL_MS, 10);
    }

    #[test]
    fn b05_valid_result_cannot_replace_terminal_worker_or_complete_record() {
        let case = Case::Bounds(bounds::BoundCase::Complete);
        for (premature_result, incomplete_result) in [(true, false), (false, true)] {
            let mut os = Fake {
                case,
                premature_result,
                incomplete_result,
                chunk: 3,
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            assert!(!result.report().bounds.as_ref().unwrap().cutover);
            assert!(!result.report().case_passed());
        }
        let mut os = Fake {
            case,
            bad_worker_status: true,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert_eq!(
            result.report().first,
            Some(failure("worker-terminal-status", 0))
        );
        assert_ne!(result.report().outcome, Outcome::Complete);
    }

    #[test]
    fn b06_near_startup_limit_and_stopped_clock_preserve_both_bounds() {
        let case = Case::Bounds(bounds::BoundCase::WorkerStall);
        let mut os = Fake {
            case,
            ready_retries: 400,
            chunk: 1,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert!(result.report().case_passed(), "{:?}", result.report());
        assert_eq!(
            result.report().bounds.as_ref().unwrap().work_cap,
            9 * SECOND
        );
        assert!(result.report().operations < MAX_OPERATIONS);
        let mut os = Fake {
            case,
            stopped_clock: true,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert_eq!(result.report().first, Some(failure("operation-cap", 0)));
        assert!(!result.report().case_passed());
    }

    #[test]
    fn b07_sentinel_survives_each_initialization_and_final_guard_failure() {
        let case = Case::Bounds(bounds::BoundCase::Complete);
        for at in [
            "sentinel-write",
            "sentinel-seal",
            "sentinel-before",
            "sentinel-after",
        ] {
            let mut os = Fake {
                case,
                faults: VecDeque::from([at]),
                ..Fake::default()
            };
            let Completion::Quarantined(owner) = run_case(&mut os, 9, case) else {
                panic!("lost sentinel at {at}");
            };
            assert_eq!(owner.resources.get(Kind::Sentinel), Some(&19));
            assert!(!os.log.iter().any(|s| s == "close:19"));
            assert_eq!(owner.report.releases, 0);
        }
        for at in ["sentinel", "sentinel-write", "sentinel-seal"] {
            let mut os = Fake {
                case,
                advance_on: Some((at, 5 * SECOND)),
                ..Fake::default()
            };
            let Completion::Quarantined(owner) = run_case(&mut os, 9, case) else {
                panic!("lost postcheck sentinel at {at}");
            };
            assert_eq!(owner.resources.get(Kind::Sentinel), Some(&19));
        }
        let mut os = Fake {
            case,
            close_at: Some((42, 5 * SECOND)),
            ..Fake::default()
        };
        let Completion::Quarantined(owner) = run_case(&mut os, 9, case) else {
            panic!("late close released sentinel");
        };
        assert_eq!(owner.resources.get(Kind::Sentinel), Some(&19));
        assert_eq!(owner.report.releases, 0);
    }

    #[test]
    fn b08_unreached_fault_or_unrelated_error_cannot_pass_negative_case() {
        for kind in bounds::BoundCase::ALL {
            let case = Case::Bounds(kind);
            let mut os = Fake {
                case,
                faults: VecDeque::from(["active"]),
                ..Fake::default()
            };
            assert!(
                !run_case(&mut os, 9, case).report().case_passed(),
                "{kind:?}"
            );
        }
        let case = Case::Bounds(bounds::BoundCase::WithheldWait);
        let mut os = Fake {
            case,
            faults: VecDeque::from(["wait-all"]),
            ..Fake::default()
        };
        assert!(!run_case(&mut os, 9, case).report().case_passed());
        let mut os = Fake {
            case,
            oom_at: 2,
            ..Fake::default()
        };
        assert!(!run_case(&mut os, 9, case).report().case_passed());
    }

    #[test]
    fn b09_supervisor_loss_before_cutover_never_commits_success() {
        let case = Case::Bounds(bounds::BoundCase::Complete);
        let mut os = Fake {
            case,
            early_at_peek: Some(3),
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert_eq!(result.report().first, Some(failure("supervisor-early", 0)));
        assert!(!result.report().bounds.as_ref().unwrap().cutover);
        assert!(!result.report().case_passed());
    }

    #[test]
    fn b10_channel_budget_refusal_retains_delivered_descriptors() {
        let case = Case::Bounds(bounds::BoundCase::Complete);
        let mut os = Fake {
            case,
            ..Fake::default()
        };
        let mut owner = Quarantine::new(9);
        owner.deadlines = Some(Deadlines::new(0).unwrap());
        let mut state = bounds::State::default();
        state.output.bytes = bounds::OUTPUT_LIMIT - 1;
        owner.report.bounds = Some(state.clone());
        let mut bytes = [0; 9];
        assert_eq!(
            read_record(
                &mut os,
                &mut owner,
                Read::Active,
                Phase::Exercise,
                &mut bytes,
                |_, _| Ok(())
            ),
            Err(failure("output-cap", 0))
        );
        owner.report.bounds = Some(state);
        assert_eq!(
            receive_registration(&mut os, &mut owner),
            Err(failure("output-cap", 0))
        );
        assert_eq!(owner.transferred[0], Some(43));
        assert!(os.alive.contains(&43));
        assert!(!os.log.iter().any(|s| s == "close:43"));
    }

    #[test]
    fn b11_withholding_case_rejects_combined_sentinel_failure() {
        for kind in [
            bounds::BoundCase::WithheldWait,
            bounds::BoundCase::WithheldPopulation,
            bounds::BoundCase::WithheldConsumer,
        ] {
            let case = Case::Bounds(kind);
            let mut os = Fake {
                case,
                faults: VecDeque::from(["sentinel-after"]),
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, case);
            assert!(!result.report().case_passed(), "{kind:?}");
            assert_eq!(result.report().releases, 0);
        }
    }

    #[test]
    fn b12_replay_requires_a_well_formed_completion_frame() {
        let case = Case::Bounds(bounds::BoundCase::Replay);
        for result_tag in [0, 9, 255] {
            let mut os = Fake {
                case,
                result_tag: Some(result_tag),
                ..Fake::default()
            };
            assert!(
                !run_case(&mut os, 9, case).report().case_passed(),
                "{result_tag}"
            );
            let complete = Case::Bounds(bounds::BoundCase::Complete);
            let mut os = Fake {
                case: complete,
                result_tag: Some(result_tag),
                ..Fake::default()
            };
            let result = run_case(&mut os, 9, complete);
            assert!(
                !result.report().bounds.as_ref().unwrap().cutover,
                "{result_tag}"
            );
            assert_eq!(
                result.report().first,
                Some(failure("bounds-result-record", 0))
            );
        }
        let mut os = Fake {
            case,
            result_epoch: Some(0),
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        assert_eq!(
            result.report().first,
            Some(failure("bounds-result-record", 0))
        );
        assert!(!result.report().case_passed());
    }

    #[test]
    fn b13_late_result_retains_exact_frame_and_postcheck_time() {
        let case = Case::Bounds(bounds::BoundCase::LateRead);
        let mut os = Fake {
            case,
            ..Fake::default()
        };
        let result = run_case(&mut os, 9, case);
        let state = result.report().bounds.as_ref().unwrap();
        assert_eq!(state.result_frame, Some(message(2, 9)));
        assert_eq!(state.result_return, Some(state.work_cap));
        assert!(!state.result_valid && !state.cutover);
        assert!(result.report().case_passed());
    }

    #[test]
    fn b20_complete() {
        bounded_case(bounds::BoundCase::Complete);
    }
    #[test]
    fn b21_supervisor_stall() {
        bounded_case(bounds::BoundCase::SupervisorStall);
    }
    #[test]
    fn b22_worker_stall() {
        bounded_case(bounds::BoundCase::WorkerStall);
    }
    #[test]
    fn b23_extension_flood() {
        bounded_case(bounds::BoundCase::ExtensionFlood);
    }
    #[test]
    fn b24_output_flood() {
        bounded_case(bounds::BoundCase::OutputFlood);
    }
    #[test]
    fn b25_replay() {
        bounded_case(bounds::BoundCase::Replay);
    }
    #[test]
    fn b26_late_read() {
        bounded_case(bounds::BoundCase::LateRead);
    }
    #[test]
    fn b27_pre_cutover_loss() {
        bounded_case(bounds::BoundCase::PreCutoverLoss);
    }
    #[test]
    fn b28_withheld_wait() {
        bounded_case(bounds::BoundCase::WithheldWait);
    }
    #[test]
    fn b29_withheld_population() {
        bounded_case(bounds::BoundCase::WithheldPopulation);
    }
    #[test]
    fn b30_withheld_consumer() {
        bounded_case(bounds::BoundCase::WithheldConsumer);
    }
    #[test]
    fn b31_withheld_sentinel() {
        bounded_case(bounds::BoundCase::WithheldSentinel);
    }

    #[test]
    fn r2a_reservation_requires_exact_finite_origin_budget() {
        let origin = 100 * SECOND;
        let reservation = Reservation::new(origin, origin + 20 * SECOND).unwrap();
        assert_eq!(reservation.origin(), origin);
        assert_eq!(reservation.deadline(), origin + 20 * SECOND);
        for (start, end) in [
            (0, 0),
            (origin, origin - 1),
            (origin, origin + 19 * SECOND),
            (origin, origin + 20 * SECOND + 1),
            (u64::MAX, u64::MAX),
        ] {
            assert_eq!(Reservation::new(start, end), Err(failure("deadline", 0)));
        }
        assert!(Reservation::new(u64::MAX - 20 * SECOND, u64::MAX).is_ok());
    }

    #[test]
    fn r2a_delayed_entry_does_not_restart_phase_or_total_caps() {
        let origin = 100 * SECOND;
        let reservation = Reservation::new(origin, origin + 20 * SECOND).unwrap();
        let mut deadlines = Deadlines::from_reservation(reservation, origin + 4 * SECOND).unwrap();
        assert_eq!(
            deadlines.caps,
            [
                origin + 5 * SECOND,
                origin + 10 * SECOND,
                origin + 15 * SECOND,
                origin + 20 * SECOND
            ]
        );
        deadlines
            .tighten(Phase::Exercise, origin + 4 * SECOND)
            .unwrap();
        assert_eq!(deadlines.cap(Phase::Exercise), origin + 9 * SECOND);
        deadlines
            .tighten(Phase::Exercise, origin + 8 * SECOND)
            .unwrap();
        assert_eq!(deadlines.cap(Phase::Exercise), origin + 9 * SECOND);
        assert_eq!(deadlines.caps[3], reservation.deadline());
    }

    #[test]
    fn r2a_invalid_reservation_refuses_before_any_os_effect() {
        for (origin, total) in [(0, 0), (1, 20 * SECOND), (u64::MAX, u64::MAX)] {
            let mut os = Fake::default();
            let done = run_reserved(&mut os, 9, Case::SupervisorOnly, origin, total);
            assert_eq!(done.report().outcome, Outcome::NoJobCreated);
            assert_eq!(done.report().first, Some(failure("deadline", 0)));
            assert_eq!(done.reservation(), None);
            assert_eq!(done.report().operations, 0);
            assert!(os.log.is_empty());
        }
    }

    #[test]
    fn r2a_pre_origin_and_expired_start_refuse_before_acquisition() {
        let origin = 10 * SECOND;
        let total = origin + 20 * SECOND;
        for (now, reason) in [
            (origin - 1, "clock-before-reservation"),
            (origin + 5 * SECOND, "expired"),
            (total, "expired"),
            (total + 1, "expired"),
        ] {
            let mut os = Fake {
                now,
                ..Fake::default()
            };
            let done = run_reserved(&mut os, 9, Case::SupervisorOnly, origin, total);
            assert_eq!(done.report().outcome, Outcome::NoJobCreated);
            assert_eq!(done.report().first, Some(failure(reason, 0)));
            assert_eq!(done.report().operations, 0);
            assert_eq!(os.log, ["clock"]);
            assert_eq!(done.reservation().unwrap().deadline(), total);
            assert!(!done.report().kill && !done.report().direct_reaped);
        }
    }

    #[test]
    fn r2a_clean_completion_retains_original_finalization_deadline() {
        let origin = 10 * SECOND;
        let total = origin + 20 * SECOND;
        let case = Case::Bounds(bounds::BoundCase::Complete);
        let mut os = Fake {
            case,
            now: origin + 4 * SECOND,
            ..Fake::default()
        };
        let done = run_reserved(&mut os, 9, case, origin, total);
        assert!(done.report().case_passed());
        let reservation = done.reservation().unwrap();
        assert_eq!(reservation.origin(), origin);
        assert_eq!(reservation.deadline(), total);
        assert_eq!(done.report().bounds.as_ref().unwrap().caps[3], total);
        assert_eq!(reservation.remaining(total - 1), Ok(1));
        assert_eq!(reservation.remaining(total), Err(failure("expired", 0)));
        assert_eq!(reservation.remaining(total + 1), Err(failure("expired", 0)));
        assert_eq!(
            reservation.remaining(origin - 1),
            Err(failure("clock-before-reservation", 0))
        );
    }

    #[test]
    fn r2a_quarantine_and_late_native_return_cannot_refresh_budget() {
        let origin = 10 * SECOND;
        let total = origin + 20 * SECOND;
        let case = Case::Bounds(bounds::BoundCase::WithheldWait);
        let mut os = Fake {
            case,
            now: origin,
            ..Fake::default()
        };
        let done = run_reserved(&mut os, 9, case, origin, total);
        assert!(matches!(done, Completion::Quarantined(_)));
        assert_eq!(done.reservation().unwrap().deadline(), total);
        assert_eq!(done.report().releases, 0);
        let mut os = Fake {
            now: origin,
            advance_on: Some(("parked", total)),
            ..Fake::default()
        };
        let late = run_reserved(&mut os, 9, Case::SupervisorOnly, origin, total);
        assert!(matches!(late, Completion::Quarantined(_)));
        assert_eq!(late.report().first, Some(failure("expired", 0)));
        assert_eq!(late.report().releases, 0);
        assert_eq!(
            late.reservation().unwrap().remaining(os.now),
            Err(failure("expired", 0))
        );
    }

    #[test]
    fn r2a_clock_regression_after_birth_retains_custody() {
        let origin = 10 * SECOND;
        let total = origin + 20 * SECOND;
        let mut os = Fake {
            now: origin,
            advance_on: Some(("parked", origin - 1)),
            ..Fake::default()
        };
        let done = run_reserved(&mut os, 9, Case::SupervisorOnly, origin, total);
        assert!(matches!(done, Completion::Quarantined(_)));
        assert_eq!(
            done.report().first,
            Some(failure("clock-before-reservation", 0))
        );
        assert_eq!(done.report().releases, 0);
        assert_eq!(done.reservation().unwrap().deadline(), total);
    }
}
