// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Recorded account failures survive daemon restarts. Terminal recording is not
//! a write-ahead reservation of every matcher opportunity or an overall ceiling.
//! Disk is authoritative: no cached counter can disagree with a visible rename.

use irlume_common::{write_atomic_reporting, AtomicWrite};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_RECORD: u64 = 4096;
const NANOS: u64 = 1_000_000_000;
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

#[derive(Clone, Copy)]
struct Policy {
    limit: u32,
    seconds: u64,
}

impl Policy {
    fn configured() -> Self {
        Self {
            limit: crate::env_or("IRLUME_RATE_LIMIT", "5").parse().unwrap_or(5),
            seconds: crate::env_or("IRLUME_RATE_COOLDOWN_SECS", "30")
                .parse()
                .unwrap_or(30),
        }
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
}

impl Record {
    fn empty(account: &Account) -> Self {
        Self {
            version: 1,
            uid: account.uid,
            account: account.name.clone(),
            strikes: 0,
            cooldown: None,
        }
    }

    fn validate(&self, account: &Account) -> io::Result<()> {
        if self.version != 1
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

impl Store {
    /// Open and exclusively lock the directory inode. All subsequent accesses are
    /// pinned through its fd, including the existing atomic writer, so a renamed
    /// parent cannot redirect publication. Closing the fd releases flock even on error.
    fn lock(&self) -> io::Result<File> {
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
        // SAFETY: dir owns a valid fd throughout the lock lifetime.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(dir)
    }

    fn path(dir: &File, account: &Account) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}.json",
            dir.as_raw_fd(),
            account.uid
        ))
    }

    fn read(&self, dir: &File, account: &Account) -> io::Result<Record> {
        let path = Self::path(dir, account);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Record::empty(account)),
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
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        record.validate(account)?;
        // A previous rename may have been visible but not durable. Re-read and
        // establish durability before permitting face again, including after a
        // process restart. There is no stale in-memory copy to restore on error.
        file.sync_all()?;
        dir.sync_all()?;
        Ok(record)
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
        if policy.limit == 0 {
            return Ok(false);
        }
        let now = clock()?;
        if !valid_boot(&now.boot) {
            return Err(invalid());
        }
        let dir = self.lock()?;
        let mut record = self.read(&dir, account)?;
        let before = record.clone();
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
            .cooldown
            .as_ref()
            .is_some_and(|c| now.nanos < c.deadline_nanos))
    }

    fn record(
        &self,
        account: &Account,
        policy: Policy,
        outcome: &irlume_auth::Outcome,
        clock: Clock,
        writer: Writer,
    ) -> io::Result<()> {
        if policy.limit == 0 {
            return Ok(());
        }
        // Capture retryability and account strikes are separate decisions:
        // setup failures are terminal but must not spend or replenish history.
        // Keep this exhaustive so every new outcome needs an accounting choice.
        if !outcome.granted {
            use irlume_auth::OutcomeKind;
            match outcome.kind {
                OutcomeKind::NoFace
                | OutcomeKind::Uncertain
                | OutcomeKind::SpoofNoIrFace
                | OutcomeKind::GestureDeclined
                | OutcomeKind::SetupUnavailable => return Ok(()),
                OutcomeKind::Granted
                | OutcomeKind::Spoof
                | OutcomeKind::BelowThreshold
                // Grouped expiry previously used OtherDeny and consumed a
                // strike; the diagnostic label does not change that policy.
                | OutcomeKind::DeadlineExpired
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

pub(crate) fn check(user: &str) -> Result<(), &'static str> {
    let policy = Policy::configured();
    if policy.limit == 0 {
        return Ok(());
    }
    let result = account(user)
        .and_then(|a| production_store()?.check(&a, policy, linux_clock, write_atomic_reporting));
    match result {
        Ok(false) => Ok(()),
        Ok(true) => Err(LIMITED),
        Err(e) => {
            eprintln!("irlumed: face retry preflight failed: {e}");
            Err(UNAVAILABLE)
        }
    }
}

pub(crate) fn record(user: &str, outcome: &irlume_auth::Outcome) -> Result<(), &'static str> {
    let policy = Policy::configured();
    if policy.limit == 0 {
        return Ok(());
    }
    let result = account(user).and_then(|a| {
        production_store()?.record(&a, policy, outcome, linux_clock, write_atomic_reporting)
    });
    result.map_err(|e| {
        eprintln!("irlumed: face retry recording failed: {e}");
        UNAVAILABLE
    })
}

#[cfg(test)]
mod tests;
