//! Independently verified retry recovery; face policy is unchanged.
use super::*;

#[cfg(test)]
mod tests;

const LIMIT: u32 = 50;
const DELAY_AFTER: u32 = 5;
const DELAY: u64 = 30 * NANOS;
const REFUSED: &str = "password verification failed or was cancelled; retry state unchanged";
const UNCONFIRMED: &str = "retry reset was not confirmed; inspect retry status before trying again";
const BLOCKED: &str =
    "retry reset is rate limited; use your password for normal login or ask an administrator";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempts {
    version: u32,
    uid: u32,
    account: String,
    failures: u32,
    pending: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    cooldown: Option<Cooldown>,
}
impl Attempts {
    fn empty(a: &Account) -> Self {
        Self {
            version: 1,
            uid: a.uid,
            account: a.name.clone(),
            failures: 0,
            pending: false,
            cooldown: None,
        }
    }
    fn validate(&self, a: &Account) -> io::Result<()> {
        if self.version != 1
            || self.uid != a.uid
            || self.account != a.name
            || self.failures > LIMIT
            || (self.pending && self.failures == 0)
            || self.cooldown.as_ref().is_some_and(|c| {
                !valid_boot(&c.boot_id)
                    || c.duration_nanos != DELAY
                    || c.deadline_nanos < DELAY
                    || self.failures < DELAY_AFTER
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn settle(&mut self, now: &Tick) -> io::Result<bool> {
        let rearm = self.pending
            || self
                .cooldown
                .as_ref()
                .is_some_and(|c| c.boot_id != now.boot);
        if rearm {
            self.pending = false;
            if self.failures >= DELAY_AFTER {
                self.cooldown = Some(Cooldown {
                    boot_id: now.boot.clone(),
                    deadline_nanos: now.nanos.checked_add(DELAY).ok_or_else(invalid)?,
                    duration_nanos: DELAY,
                });
            }
            return Ok(true);
        }
        if let Some(c) = &self.cooldown {
            if c.deadline_nanos.saturating_sub(now.nanos) > DELAY {
                return Err(invalid());
            }
            if now.nanos >= c.deadline_nanos {
                self.cooldown = None;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub(crate) struct Status {
    pub face_budget: irlume_common::FaceRetryBudget,
    pub failures: u32,
    pub cooldown_seconds: u64,
    pub recovery_failures: u32,
    pub recovery_cooldown_seconds: u64,
    pub recovery_required: bool,
}

pub(crate) struct Recovery {
    store: Store,
    account: Account,
    clock: Clock,
    writer: Writer,
    _operation: RetryLock,
}
impl Recovery {
    pub(crate) fn for_user(user: &str) -> Result<Self, &'static str> {
        let a = account(user).map_err(|_| UNAVAILABLE)?;
        Self::begin(
            production_store().map_err(|_| UNAVAILABLE)?,
            a,
            linux_clock,
            write_atomic_reporting,
        )
        .map_err(|_| UNAVAILABLE)
    }
    fn begin(store: Store, account: Account, clock: Clock, writer: Writer) -> io::Result<Self> {
        let operation = store.operation(&account)?;
        Ok(Self {
            store,
            account,
            clock,
            writer,
            _operation: operation,
        })
    }
    fn now(&self) -> io::Result<Tick> {
        let t = (self.clock)()?;
        if !valid_boot(&t.boot) {
            return Err(invalid());
        }
        Ok(t)
    }
    fn path(&self, dir: &File) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}.reset.json",
            dir.as_raw_fd(),
            self.account.uid
        ))
    }
    fn read(&self, dir: &File) -> io::Result<Attempts> {
        let a = match self.store.read_bytes(dir, &self.path(dir))? {
            Some(b) => serde_json::from_slice(&b).map_err(|_| invalid())?,
            None => Attempts::empty(&self.account),
        };
        a.validate(&self.account)?;
        Ok(a)
    }
    fn commit(&self, dir: &File, a: &Attempts) -> io::Result<()> {
        a.validate(&self.account)?;
        let bytes = serde_json::to_vec(a).map_err(|_| invalid())?;
        if bytes.len() > MAX_RECORD as usize {
            return Err(invalid());
        }
        match (self.writer)(&self.path(dir), &bytes, 0o600)? {
            AtomicWrite::Durable => Ok(()),
            AtomicWrite::VisibleNotDurable(e) => Err(e),
        }
    }
    pub(crate) fn status(&self) -> Result<Status, &'static str> {
        self.status_inner().map_err(|_| UNAVAILABLE)
    }
    fn status_inner(&self) -> io::Result<Status> {
        let dir = self.store.lock()?;
        let mut face = self.store.read(&dir, &self.account)?;
        let mut recovery = self.read(&dir)?;
        let now = self.now()?;
        let before = face.clone();
        face.settle_abandoned(Policy::configured(), &now)?;
        if face != before {
            self.store.commit(&dir, &face, self.writer)?;
        }
        if recovery.settle(&now)? {
            self.commit(&dir, &recovery)?;
        }
        let remaining = |c: &Option<Cooldown>| {
            c.as_ref().map_or(0, |c| {
                let n = if c.boot_id == now.boot {
                    c.deadline_nanos.saturating_sub(now.nanos)
                } else {
                    c.duration_nanos
                };
                n.div_ceil(NANOS)
            })
        };
        Ok(Status {
            face_budget: irlume_common::FaceRetryBudget {
                unsuccessful_requests: face.budget.as_ref().map(|b| b.unsuccessful_requests),
                limit: FACE_LIMIT,
                reset_required: face
                    .budget
                    .as_ref()
                    .is_some_and(|b| b.unsuccessful_requests >= FACE_LIMIT),
            },
            failures: face.strikes,
            cooldown_seconds: remaining(&face.cooldown),
            recovery_failures: recovery.failures,
            recovery_cooldown_seconds: remaining(&recovery.cooldown),
            recovery_required: recovery.failures >= LIMIT,
        })
    }
    pub(crate) fn reset(
        &self,
        admin: bool,
        active: impl Fn() -> bool,
        verify: impl FnOnce() -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        if !active() {
            return Err(REFUSED);
        }
        {
            let dir = self.store.lock().map_err(|_| UNAVAILABLE)?;
            self.store
                .read(&dir, &self.account)
                .map_err(|_| UNAVAILABLE)?;
            let mut a = self.read(&dir).map_err(|_| UNAVAILABLE)?;
            if !admin {
                let now = self.now().map_err(|_| UNAVAILABLE)?;
                if a.settle(&now).map_err(|_| UNAVAILABLE)? {
                    self.commit(&dir, &a).map_err(|_| UNAVAILABLE)?;
                }
                if a.failures >= LIMIT || a.cooldown.is_some() {
                    return Err(BLOCKED);
                }
                a.failures += 1;
                a.pending = true;
                self.commit(&dir, &a).map_err(|_| UNAVAILABLE)?;
            }
        }
        if !admin && (!active() || verify().is_err()) {
            // A completed refusal or abandoned reservation retains its charge.
            // Settlement arms the delay from completion, not verifier start.
            self.status()?;
            return Err(REFUSED);
        }
        let dir = self.store.lock().map_err(|_| UNAVAILABLE)?;
        self.store
            .read(&dir, &self.account)
            .map_err(|_| UNAVAILABLE)?;
        self.read(&dir).map_err(|_| UNAVAILABLE)?;
        if !active() {
            return Err(REFUSED);
        }
        self.store
            .commit(&dir, &Record::reset(&self.account), self.writer)
            .map_err(|_| UNCONFIRMED)?;
        // Face first: a torn two-file reset leaves a conservative recovery
        // charge. It cannot replenish password guesses without verified proof.
        if !active() {
            return Err(UNCONFIRMED);
        }
        self.commit(&dir, &Attempts::empty(&self.account))
            .map_err(|_| UNCONFIRMED)?;
        if !active() {
            return Err(UNCONFIRMED);
        }
        Ok(())
    }
}
