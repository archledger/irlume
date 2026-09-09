// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Account requests are charged durably before face work. Ambiguous completion
//! keeps its charge; only an admitted response or verified recovery resets it.
//! Disk is authoritative: no cached counter can disagree with a visible rename.

use irlume_common::{write_atomic_reporting, AtomicWrite};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) mod recovery;

const MAX_RECORD: u64 = 4096;
const NANOS: u64 = 1_000_000_000;
const FACE_LIMIT: u32 = 50;
pub(crate) const UNAVAILABLE: &str =
    "face retry state unavailable; use your password and ask an administrator to check /var/lib/irlume/retry";
pub(crate) const LIMITED: &str = "too many recent face attempts; use your password";

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid face retry state")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Account {
    uid: u32,
    name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Policy {
    limit: u32,
    seconds: u64,
}

impl Policy {
    fn configured() -> Self {
        let (policy, invalid) = Self::parse(
            &crate::env_or("IRLUME_RATE_LIMIT", "5"),
            &crate::env_or("IRLUME_RATE_COOLDOWN_SECS", "30"),
        );
        if invalid {
            eprintln!("irlumed: invalid face retry configuration; using safe defaults for invalid settings");
        }
        policy
    }

    fn parse(limit: &str, seconds: &str) -> (Self, bool) {
        let limit = limit.parse::<u32>().ok().filter(|n| (1..=5).contains(n));
        let seconds = seconds
            .parse::<u64>()
            .ok()
            .filter(|n| (30..=86400).contains(n));
        (
            Self {
                limit: limit.unwrap_or(5),
                seconds: seconds.unwrap_or(30),
            },
            limit.is_none() || seconds.is_none(),
        )
    }
}

#[derive(Clone)]
struct Tick {
    boot: String,
    nanos: u64,
}

fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn linux_clock() -> io::Result<Tick> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim().to_owned();
    if !valid_boot(&boot) {
        return Err(invalid());
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a writable timespec and CLOCK_MONOTONIC is a Linux clock ID.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(ts.tv_sec).map_err(|_| invalid())?;
    let fractional = u64::try_from(ts.tv_nsec).map_err(|_| invalid())?;
    if fractional >= NANOS {
        return Err(invalid());
    }
    let nanos = seconds
        .checked_mul(NANOS)
        .and_then(|n| n.checked_add(fractional))
        .ok_or_else(invalid)?;
    Ok(Tick { boot, nanos })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Cooldown {
    boot_id: String,
    deadline_nanos: u64,
    duration_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    uid: u32,
    account: String,
    strikes: u32,
    #[serde(deserialize_with = "Option::deserialize")]
    cooldown: Option<Cooldown>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<FaceBudget>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FaceBudget {
    unsuccessful_requests: u32,
    pending: bool,
}

impl Record {
    fn empty(account: &Account) -> Self {
        Self {
            version: 1,
            uid: account.uid,
            account: account.name.clone(),
            strikes: 0,
            cooldown: None,
            budget: None,
        }
    }

    fn initialize_budget(&mut self) {
        self.version = 2;
        self.budget = Some(FaceBudget {
            unsuccessful_requests: 0,
            pending: false,
        });
    }

    fn reset(account: &Account) -> Self {
        let mut record = Self::empty(account);
        record.initialize_budget();
        record
    }

    fn validate(&self, account: &Account) -> io::Result<()> {
        if !matches!((self.version, &self.budget), (1, None) | (2, Some(_)))
            || self.budget.as_ref().is_some_and(|b| {
                b.unsuccessful_requests > FACE_LIMIT || (b.pending && b.unsuccessful_requests == 0)
            })
            || self.uid != account.uid
            || self.account != account.name
            || self.account.is_empty()
            || self.account.len() > 256
            || self.account.chars().any(char::is_control)
            || self.cooldown.as_ref().is_some_and(|c| {
                !valid_boot(&c.boot_id) || c.deadline_nanos < c.duration_nanos || self.strikes != 0
            })
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn arm(&mut self, now: &Tick, duration: u64) -> io::Result<()> {
        self.cooldown = Some(Cooldown {
            boot_id: now.boot.clone(),
            deadline_nanos: now.nanos.checked_add(duration).ok_or_else(invalid)?,
            duration_nanos: duration,
        });
        self.strikes = 0;
        Ok(())
    }

    fn strike(&mut self, policy: Policy, now: &Tick) -> io::Result<()> {
        if self.cooldown.is_none() {
            self.strikes = self.strikes.checked_add(1).ok_or_else(invalid)?;
            if self.strikes >= policy.limit {
                self.arm(now, policy.seconds.checked_mul(NANOS).ok_or_else(invalid)?)?;
            }
        }
        Ok(())
    }

    fn settle_abandoned(&mut self, policy: Policy, now: &Tick) -> io::Result<()> {
        if let Some(budget) = &mut self.budget {
            if budget.pending {
                budget.pending = false;
                self.strike(policy, now)?;
            }
        }
        Ok(())
    }
}

/// The parent is daemon-selected, never request-selected. Production additionally
/// verifies its fixed ancestors. Tests supply a private parent and its owner.
struct Store {
    parent: PathBuf,
    owner: u32,
}

fn open_dir(path: &Path, owner: u32, private: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    let mode = meta.mode() & 0o7777;
    if meta.uid() != owner
        || !meta.is_dir()
        || if private {
            mode != 0o700
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(invalid());
    }
    Ok(file)
}

/// Own the flock lifetime separately from duplicate File descriptors.
/// Kept inside retry accounting; callers retain it for the complete operation.
pub(crate) struct RetryLock {
    file: File,
    owner_pid: libc::pid_t,
}

impl RetryLock {
    fn acquire(file: File, flags: libc::c_int) -> io::Result<Self> {
        // SAFETY: file owns a live descriptor throughout acquisition.
        if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: getpid has no preconditions and identifies this acquisition's owner.
        let owner_pid = unsafe { libc::getpid() };
        Ok(Self { file, owner_pid })
    }
}

impl std::ops::Deref for RetryLock {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

impl Drop for RetryLock {
    fn drop(&mut self) {
        // flock belongs to the open file description shared by dup/fork. Closing
        // our fd alone can leave the lock held by a child until exec. Conversely,
        // a copied guard in that child must not unlock a still-active parent.
        // SAFETY: getpid has no preconditions (including in a post-fork child).
        if unsafe { libc::getpid() } == self.owner_pid {
            // SAFETY: self.file remains live until after this destructor. Unlock
            // explicitly before File closes; no other owner can clone this guard.
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

impl Store {
    /// Open and exclusively lock the directory inode. All subsequent accesses are
    /// pinned through its fd, including the existing atomic writer, so a renamed
    /// parent cannot redirect publication. The owning guard releases flock on error.
    fn lock(&self) -> io::Result<RetryLock> {
        let parent = open_dir(&self.parent, self.owner, false)?;
        let path = PathBuf::from(format!("/proc/self/fd/{}/retry", parent.as_raw_fd()));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        let dir = open_dir(&path, self.owner, true)?;
        // Also retries directory-creation durability following an earlier error.
        parent.sync_all()?;
        RetryLock::acquire(dir, libc::LOCK_EX)
    }

    fn path(dir: &File, account: &Account) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}.json",
            dir.as_raw_fd(),
            account.uid
        ))
    }

    fn read(&self, dir: &File, account: &Account) -> io::Result<Record> {
        let Some(bytes) = self.read_bytes(dir, &Self::path(dir, account))? else {
            return Ok(Record::empty(account));
        };
        // Version 1's original strict schema had no budget field, including
        // null. Do not turn a malformed legacy record into a fresh epoch.
        let shape: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if shape.get("version").and_then(serde_json::Value::as_u64) == Some(1)
            && shape.get("budget").is_some()
        {
            return Err(invalid());
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        record.validate(account)?;
        Ok(record)
    }

    fn read_bytes(&self, dir: &File, path: &Path) -> io::Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
            || meta.len() > MAX_RECORD
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&file).take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD as usize {
            return Err(invalid());
        }
        // A previous rename may have been visible but not durable. Re-read and
        // establish durability before permitting face again, including after a
        // process restart. There is no stale in-memory copy to restore on error.
        file.sync_all()?;
        dir.sync_all()?;
        Ok(Some(bytes))
    }

    fn operation(&self, account: &Account) -> io::Result<RetryLock> {
        let dir = self.lock()?;
        let path = format!(
            "/proc/self/fd/{}/{}.operation",
            dir.as_raw_fd(),
            account.uid
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != self.owner
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() != 0
        {
            return Err(invalid());
        }
        let file = RetryLock::acquire(file, libc::LOCK_EX | libc::LOCK_NB)?;
        file.sync_all()?;
        dir.sync_all()?;
        Ok(file)
    }

    fn commit(&self, dir: &File, record: &Record, writer: Writer) -> io::Result<()> {
        record.validate(&Account {
            uid: record.uid,
            name: record.account.clone(),
        })?;
        let bytes = serde_json::to_vec(record).map_err(|_| invalid())?;
        if bytes.len() > MAX_RECORD as usize {
            return Err(invalid());
        }
        let account = Account {
            uid: record.uid,
            name: record.account.clone(),
        };
        match writer(&Self::path(dir, &account), &bytes, 0o600)? {
            AtomicWrite::Durable => Ok(()),
            AtomicWrite::VisibleNotDurable(error) => Err(error),
        }
    }

    fn check(
        &self,
        account: &Account,
        policy: Policy,
        clock: Clock,
        writer: Writer,
    ) -> io::Result<bool> {
        let now = clock()?;
        if !valid_boot(&now.boot) {
            return Err(invalid());
        }
        let dir = self.lock()?;
        let mut record = self.read(&dir, account)?;
        let before = record.clone();
        record.settle_abandoned(policy, &now)?;
        if let Some(c) = &record.cooldown {
            if c.boot_id != now.boot {
                record.arm(&now, c.duration_nanos)?;
            } else if c.deadline_nanos.saturating_sub(now.nanos) > c.duration_nanos {
                return Err(invalid()); // Clock moved backwards or impossible deadline.
            } else if now.nanos >= c.deadline_nanos {
                record.cooldown = None;
                record.strikes = 0;
            }
        } else if record.strikes >= policy.limit {
            // A lowered threshold cannot replenish the already recorded budget.
            record.arm(&now, policy.seconds.checked_mul(NANOS).ok_or_else(invalid)?)?;
        }
        if record != before {
            self.commit(&dir, &record, writer)?;
        }
        Ok(record
            .budget
            .as_ref()
            .is_some_and(|b| b.unsuccessful_requests >= FACE_LIMIT)
            || record
                .cooldown
                .as_ref()
                .is_some_and(|c| now.nanos < c.deadline_nanos))
    }

    #[cfg(test)]
    fn record(
        &self,
        account: &Account,
        policy: Policy,
        outcome: &irlume_auth::Outcome,
        clock: Clock,
        writer: Writer,
    ) -> io::Result<()> {
        self.record_if(account, policy, outcome, clock, writer, || true)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn record_if(
        &self,
        account: &Account,
        policy: Policy,
        outcome: &irlume_auth::Outcome,
        clock: Clock,
        writer: Writer,
        active: impl Fn() -> bool,
    ) -> io::Result<()> {
        // Capture retryability and account strikes are separate decisions:
        // setup failures are terminal but must not spend or replenish history.
        // Keep this exhaustive so every new outcome needs an accounting choice.
        if !outcome.granted {
            use irlume_auth::OutcomeKind;
            match outcome.kind {
                OutcomeKind::NoFace
                | OutcomeKind::Uncertain
                | OutcomeKind::SpoofNoIrFace
                | OutcomeKind::SetupUnavailable => return Ok(()),
                OutcomeKind::Granted
                | OutcomeKind::Spoof
                | OutcomeKind::BelowThreshold
                // These terminal refusals previously used OtherDeny and
                // consumed strikes; diagnostic labels do not change that policy.
                | OutcomeKind::DeadlineExpired
                | OutcomeKind::RuntimeUnavailable
                | OutcomeKind::OtherDeny => (),
            }
        }
        let now = clock()?;
        if !valid_boot(&now.boot) {
            return Err(invalid());
        }
        let dir = self.lock()?;
        let mut record = self.read(&dir, account)?;
        if outcome.granted {
            // Lock acquisition and durable read may block. Revalidate after
            // them and before replenishing history. Atomic persistence can
            // itself cross expiry; callers must still gate response admission.
            if !active() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "authentication no longer eligible",
                ));
            }
            record.strikes = 0;
            record.cooldown = None;
        } else if record.cooldown.is_none() {
            record.strikes = record.strikes.checked_add(1).ok_or_else(invalid)?;
            if record.strikes >= policy.limit {
                record.arm(&now, policy.seconds.checked_mul(NANOS).ok_or_else(invalid)?)?;
            }
        }
        self.commit(&dir, &record, writer)
    }
}

/// A durable account-exclusive reservation. Drop retains an ambiguous charge.
pub(crate) struct FaceAttempt {
    store: Store,
    account: Account,
    policy: Policy,
    clock: Clock,
    writer: Writer,
    _operation: RetryLock,
}

impl FaceAttempt {
    pub(crate) fn for_user(user: &str) -> Result<Self, &'static str> {
        let result = account(user).and_then(|a| {
            Self::begin(
                production_store()?,
                a,
                Policy::configured(),
                linux_clock,
                write_atomic_reporting,
            )
        });
        match result {
            Ok(Some(attempt)) => Ok(attempt),
            Ok(None) => Err(LIMITED),
            Err(_) => Err(UNAVAILABLE),
        }
    }

    fn begin(
        store: Store,
        account: Account,
        policy: Policy,
        clock: Clock,
        writer: Writer,
    ) -> io::Result<Option<Self>> {
        let operation = store.operation(&account)?;
        if store.check(&account, policy, clock, writer)? {
            return Ok(None);
        }
        let dir = store.lock()?;
        let mut record = store.read(&dir, &account)?;
        if record.budget.is_none() {
            // Prospective epoch only; v1 cannot reconstruct erased history.
            record.initialize_budget();
        }
        let budget = record.budget.as_mut().ok_or_else(invalid)?;
        if budget.unsuccessful_requests >= FACE_LIMIT {
            return Ok(None);
        }
        budget.unsuccessful_requests = budget
            .unsuccessful_requests
            .checked_add(1)
            .ok_or_else(invalid)?;
        budget.pending = true;
        store.commit(&dir, &record, writer)?;
        drop(dir);
        Ok(Some(Self {
            store,
            account,
            policy,
            clock,
            writer,
            _operation: operation,
        }))
    }

    pub(crate) fn denied(self, outcome: &irlume_auth::Outcome) -> Result<(), &'static str> {
        self.denied_inner(outcome).map_err(|_| UNAVAILABLE)
    }

    fn denied_inner(&self, outcome: &irlume_auth::Outcome) -> io::Result<()> {
        if outcome.granted {
            return Err(invalid());
        }
        let dir = self.store.lock()?;
        let mut record = self.store.read(&dir, &self.account)?;
        let budget = record.budget.as_mut().ok_or_else(invalid)?;
        if !budget.pending {
            return Err(invalid());
        }
        budget.pending = false;
        use irlume_auth::OutcomeKind;
        match outcome.kind {
            OutcomeKind::NoFace
            | OutcomeKind::Uncertain
            | OutcomeKind::SpoofNoIrFace
            | OutcomeKind::SetupUnavailable => (),
            OutcomeKind::Granted
            | OutcomeKind::Spoof
            | OutcomeKind::BelowThreshold
            | OutcomeKind::DeadlineExpired
            | OutcomeKind::RuntimeUnavailable
            | OutcomeKind::OtherDeny => {
                let now = (self.clock)()?;
                if !valid_boot(&now.boot) {
                    return Err(invalid());
                }
                record.strike(self.policy, &now)?;
            }
        }
        self.store.commit(&dir, &record, self.writer)
    }

    /// Called only after the daemon admitted and wrote the complete grant.
    pub(crate) fn delivered(self) -> Result<(), &'static str> {
        let reset = || -> io::Result<()> {
            let dir = self.store.lock()?;
            let record = self.store.read(&dir, &self.account)?;
            if !record.budget.as_ref().is_some_and(|b| b.pending) {
                return Err(invalid());
            }
            self.store
                .commit(&dir, &Record::reset(&self.account), self.writer)
        };
        reset().map_err(|_| UNAVAILABLE)
    }
}

type Clock = fn() -> io::Result<Tick>;
type Writer = fn(&Path, &[u8], u32) -> io::Result<AtomicWrite>;

fn account(user: &str) -> io::Result<Account> {
    let uid = crate::users::uid_for_name(user).ok_or_else(invalid)?;
    let name = crate::users::name_for_uid(uid).ok_or_else(invalid)?;
    Ok(Account { uid, name })
}

#[cfg(not(test))]
fn production_store() -> io::Result<Store> {
    // Fixed trusted ancestors. Do not accept an unprivileged socket path or
    // reuse the enrollment store's environment override for retry enforcement.
    for path in ["/", "/var", "/var/lib"] {
        open_dir(Path::new(path), 0, false)?;
    }
    match std::fs::DirBuilder::new()
        .mode(0o700)
        .create("/var/lib/irlume")
    {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    File::open("/var/lib")?.sync_all()?;
    Ok(Store {
        parent: "/var/lib/irlume".into(),
        owner: 0,
    })
}

// Unit/engine fixtures must never access installed retry records, even when
// cargo test is run as root. Only the store location/owner is injected; parsing,
// transitions, locking, clock, writer and NSS resolution are unchanged.
#[cfg(test)]
fn production_store() -> io::Result<Store> {
    let parent = std::env::var_os("IRLUME_STATE_DIR").ok_or_else(invalid)?;
    Ok(Store {
        parent: parent.into(),
        // SAFETY: geteuid has no preconditions.
        owner: unsafe { libc::geteuid() },
    })
}

#[cfg(test)]
pub(crate) fn record(user: &str, outcome: &irlume_auth::Outcome) -> Result<(), &'static str> {
    record_if(user, outcome, || true)
}

#[cfg(test)]
pub(crate) fn record_if(
    user: &str,
    outcome: &irlume_auth::Outcome,
    active: impl Fn() -> bool,
) -> Result<(), &'static str> {
    let policy = Policy::configured();
    let result = account(user).and_then(|a| {
        production_store()?.record_if(
            &a,
            policy,
            outcome,
            linux_clock,
            write_atomic_reporting,
            active,
        )
    });
    result.map_err(|e| {
        eprintln!("irlumed: face retry recording failed: {e}");
        UNAVAILABLE
    })
}

#[cfg(test)]
mod tests;
