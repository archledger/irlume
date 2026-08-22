// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Tiny `key=value` config files under the config dir (`/etc/irlume`, override
//! `IRLUME_CONFIG_DIR`), e.g. `cameras.conf`, `settings.conf`. Blank lines and
//! `#` comments are ignored. These hold operator-tunable knobs the setup flow
//! writes and the daemon reads; secrets never live here (those are sealed
//! envelopes elsewhere).

use std::path::PathBuf;

/// Default config root.
pub const CONFIG_ROOT: &str = "/etc/irlume";

/// The config file that pins the camera pair (`rgb`, `ir`, `rgb_id`, `ir_id`)
/// plus the per-camera capture mode. Named in one place so the reader
/// ([`read_camera_pin`]) and the writer ([`write_camera_pin`]) cannot disagree
/// on which file holds the pin.
pub const CAMERAS_CONF: &str = "cameras.conf";

fn config_root() -> PathBuf {
    std::env::var_os("IRLUME_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CONFIG_ROOT))
}

/// Absolute path to a config file under the config root.
pub fn config_path(file: &str) -> PathBuf {
    config_root().join(file)
}

/// An exclusive advisory lock over one config file's check-then-write
/// sequences. Dropping the guard releases it.
pub struct ConfigLock {
    /// Held only for its flock; closing the fd releases the lock.
    _file: std::fs::File,
}

/// Take the writer lock for `file` (blocking until free).
///
/// Guards a read-decide-write window against other PROCESSES: `write_kv`'s
/// atomic rename keeps every individual write whole, but a caller that first
/// READS a key and then writes based on what it saw (the enrollment
/// capture-mode probe, whose check and write are separated by a minute of
/// measuring) can otherwise overwrite a value another process landed in
/// between. The lock is a sidecar `<file>.lock` under the config root, taken
/// with flock, so plain readers are never blocked and see whole files either
/// way; only check-then-write callers need to take it.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn lock_exclusive(file: &str) -> std::io::Result<ConfigLock> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let path = config_path(&format!("{file}.lock"));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    // SAFETY: flock on an owned, open fd; no memory is handed to the kernel.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ConfigLock { _file: f })
}

/// What one read of a config key established. `Absent` and `Unknown` are
/// different facts: a missing file or key was OBSERVED to hold nothing, while
/// an unreadable file established nothing at all, and a caller that reports
/// state to others must not present the second as the first.
pub enum KvObservation {
    /// The key is present with this (trimmed, non-empty) value.
    Value(String),
    /// The file, the key, or a non-empty value is genuinely not there.
    Absent,
    /// The file could not be read, so nothing was established.
    Unknown(std::io::Error),
}

/// Read a single key from a `key=value` file, classifying the outcome.
///
/// Does not log; [`read_kv`] wraps this with the warning policy most callers
/// want.
pub fn observe_kv(file: &str, key: &str) -> KvObservation {
    let path = config_path(file);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return KvObservation::Absent,
        Err(e) => return KvObservation::Unknown(e),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                if !v.is_empty() {
                    return KvObservation::Value(v.to_string());
                }
            }
        }
    }
    KvObservation::Absent
}

/// Read a single key from a `key=value` file. Returns the trimmed value, or
/// `None` if the file is missing, the key is absent, or the value is empty.
///
/// `None` collapses "absent" and "unreadable"; a caller for whom that
/// difference matters (anything that REPORTS the state rather than just
/// falling back on a default) must use [`observe_kv`].
pub fn read_kv(file: &str, key: &str) -> Option<String> {
    match observe_kv(file, key) {
        KvObservation::Value(v) => Some(v),
        KvObservation::Absent => None,
        KvObservation::Unknown(e) => {
            warn_unreadable(file, &format!("key '{key}'"), &e);
            None
        }
    }
}

/// Warn (or stay quiet) when a config file exists but could not be read.
///
/// A present-but-unreadable config (classically a wrong SELinux label) must NOT
/// be ignored silently for the *daemon*: that sends it to auto-detect and it
/// can bind the wrong device. Make it loud (daemon stderr ⇒ journald). But these
/// files are deliberately root-only (0600), so an *unprivileged* CLI caller
/// hitting Permission denied is expected, not a fault; the root daemon reads
/// them fine. Warning there just alarms new users into needlessly loosening
/// permissions. So: stay loud for root and for non-permission errors; stay quiet
/// for the expected EACCES an ordinary user gets. `ignored` names what the caller
/// gave up on, e.g. `key 'rgb'` or `keys rgb, ir`. Factored out of [`read_kv`] so
/// the single-key and multi-key readers cannot drift on that policy.
fn warn_unreadable(file: &str, ignored: &str, e: &std::io::Error) {
    // SAFETY: `geteuid` takes no arguments, reads only the calling process's own
    // credentials, and is specified as always succeeding, so it has no
    // preconditions for the caller to uphold.
    let unprivileged_eacces =
        e.kind() == std::io::ErrorKind::PermissionDenied && unsafe { libc::geteuid() } != 0;
    if unprivileged_eacces {
        return;
    }
    let p = config_path(file);
    eprintln!(
        "irlume: WARNING: config {p} exists but is unreadable ({e}); {ignored} ignored; \
         check permissions / SELinux label (try: restorecon -v {p})",
        p = p.display(),
    );
}

/// Read several keys from a `key=value` file in ONE read, returning one slot per
/// requested key in order (each `Some(trimmed)` for a present non-empty value,
/// `None` for absent/empty), matching [`observe_kv`]'s per-key rules.
///
/// The point is the single read. A caller that wants a group of keys as one
/// value must NOT open the file once per key: a writer that replaces the file
/// (an atomic rename) between two of those opens hands the caller a value from
/// the old version and a value from the new one, a pair that was never written
/// as a unit. `rename(2)` guarantees each *open* sees a whole file, not that N
/// separate opens see the same one. Reading every key from a single snapshot is
/// what makes the group whole. See [`read_camera_pin`].
pub fn read_kvs(file: &str, keys: &[&str]) -> Vec<Option<String>> {
    let mut out = vec![None; keys.len()];
    let text = match std::fs::read_to_string(config_path(file)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
        Err(e) => {
            warn_unreadable(file, &format!("keys {}", keys.join(", ")), &e);
            return out;
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        // First non-empty occurrence wins, like `observe_kv`; a later duplicate
        // of the same key does not override it.
        if let Some(idx) = keys.iter().position(|want| *want == k.trim()) {
            if out[idx].is_none() {
                out[idx] = Some(v.to_string());
            }
        }
    }
    out
}

/// Apply `updates` (`(key, value)` pairs) to the lines of `existing`: replace
/// the first line for each key in place, drop any later duplicates of those
/// keys, keep every other line and comment untouched, and append any key not
/// already present, in the order given. Pure (no I/O), so [`write_kv`] and
/// [`write_kvs`] share exactly one parse and cannot drift on it.
fn apply_kv_updates(existing: &str, updates: &[(&str, &str)]) -> String {
    let mut out = String::new();
    let mut written = vec![false; updates.len()];
    for line in existing.lines() {
        let trimmed = line.trim();
        // A comment is never a target. Otherwise, if this line sets one of the
        // keys we are updating, `target` is which one.
        let target = if trimmed.starts_with('#') {
            None
        } else if let Some((k, _)) = trimmed.split_once('=') {
            updates.iter().position(|(uk, _)| *uk == k.trim())
        } else {
            None
        };
        if let Some(idx) = target {
            if !written[idx] {
                out.push_str(&format!("{}={}\n", updates[idx].0, updates[idx].1));
                written[idx] = true;
            }
            continue; // drop duplicates and superseded lines
        }
        out.push_str(line);
        out.push('\n');
    }
    for (idx, (k, v)) in updates.iter().enumerate() {
        if !written[idx] {
            out.push_str(&format!("{k}={v}\n"));
        }
    }
    out
}

/// Insert or update `key=value`, preserving every other line (including
/// comments) and dropping duplicate keys. Creates the file at 0600 if absent.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn write_kv(file: &str, key: &str, val: &str) -> std::io::Result<()> {
    write_kvs(file, &[(key, val)])
}

/// Insert or update several keys in ONE atomic publish, preserving every other
/// line (including comments) and dropping duplicate keys. Creates the file at
/// 0600 if absent.
///
/// The whole point over calling [`write_kv`] in a loop is that the group lands
/// as a unit. Each `write_kv` reads the file, rewrites it, and renames a new
/// version over the old, so four `write_kv` calls publish four times: a reader
/// (or a partial failure, say a full disk on the third call) can land between
/// them and leave keys that belong together split across two versions of the
/// file. Building the whole updated text once and publishing it in a single
/// [`crate::write_0600_atomic`] rename means a reader sees either the complete
/// old file or the complete new one, and a failure rolls the whole group back
/// because nothing was renamed. See [`write_camera_pin`].
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn write_kvs(file: &str, updates: &[(&str, &str)]) -> std::io::Result<()> {
    let path = config_path(file);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let out = apply_kv_updates(&existing, updates);

    // Published atomically, not truncated in place. Truncate-then-write means a
    // full disk or a power loss mid-write leaves a partial file, and these hold
    // the camera binding and the third-party model selection: on a full tmpfs
    // this left cameras.conf as 4096 bytes of half a config. `write_0600_atomic`
    // creates the temp at the final mode, fsyncs it, renames, then fsyncs the
    // directory, so a reader sees either the whole old file or the whole new
    // one, and the same helper already protects the envelopes and template keys.
    crate::write_0600_atomic(&path, out.as_bytes())
}

/// The camera pin read as one value: the RGB and IR node paths and their
/// optional device identities (`vid:pid:serial`). Each field is `Some(trimmed)`
/// for a present non-empty key and `None` otherwise, matching [`read_kv`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CameraPin {
    /// The pinned RGB node path.
    pub rgb: Option<String>,
    /// The pinned IR node path.
    pub ir: Option<String>,
    /// The RGB node's stable device identity, when it was recorded.
    pub rgb_id: Option<String>,
    /// The IR node's stable device identity, when it was recorded.
    pub ir_id: Option<String>,
}

/// Read the camera pin from a SINGLE snapshot of `cameras.conf`.
///
/// The four keys are the anti-injection binding: the point of pinning
/// `vid:pid:serial` next to each path is that the RGB and IR nodes are known to
/// belong to one physical camera. Reading them with four separate opens lets a
/// repin landing between two of the opens combine an RGB path from the old pin
/// with an IR path or identity from the new one, so a caller would evaluate a
/// pair that was never written. `flock` does not help: it is advisory, so it
/// only constrains other lock takers, and the readers do not (and should not
/// have to) take it. One read of the whole file is what keeps the pin whole.
pub fn read_camera_pin() -> CameraPin {
    // One read of the file. `read_kvs` returns one slot per key, in the order
    // asked for, so the four values come back rgb, ir, rgb_id, ir_id.
    let mut vals = read_kvs(CAMERAS_CONF, &["rgb", "ir", "rgb_id", "ir_id"]).into_iter();
    CameraPin {
        rgb: vals.next().flatten(),
        ir: vals.next().flatten(),
        rgb_id: vals.next().flatten(),
        ir_id: vals.next().flatten(),
    }
}

/// Publish the camera pin (all four keys) in ONE atomic rename, under the
/// file's own lock.
///
/// Replaces four chained [`write_kv`] calls, which published the pin four times
/// and could leave `cameras.conf` holding one camera's RGB path with another's
/// IR path if a reader raced the sequence or a later write failed. An empty
/// `rgb_id`/`ir_id` clears a stale identity, exactly as the per-key writes did.
/// The `capture_mode` keys in the same file are untouched: the write rewrites
/// only the keys it is given.
///
/// The lock and the single rename fix DIFFERENT halves and both are needed
/// (#365 and #374). `write_kv` rewrites the whole file from a snapshot it read,
/// so an unlocked writer racing `store_capture_mode_if_absent`, which does take
/// this lock, erased keys that writer had just written; the lock stops that.
/// But `flock` is advisory and the readers in irlume-camera do not take it, so
/// only publishing once, by rename, stops a reader observing a torn pair. A
/// lock alone cannot make four renames one event, and one rename alone does not
/// exclude the other locked writer.
///
/// Not nested: `write_kvs` takes no lock of its own, so this is the only
/// acquisition on the path.
///
/// # Errors
/// Propagates a failure to take the lock, and the failed write.
pub fn write_camera_pin(rgb: &str, ir: &str, rgb_id: &str, ir_id: &str) -> std::io::Result<()> {
    let _guard = lock_exclusive(CAMERAS_CONF)?;
    write_kvs(
        CAMERAS_CONF,
        &[
            ("rgb", rgb),
            ("ir", ir),
            ("rgb_id", rgb_id),
            ("ir_id", ir_id),
        ],
    )
}

/// The settings.conf key for the credential-release temporal-liveness gate.
pub const CREDENTIAL_RELEASE_CHALLENGE_KEY: &str = "credential_release_challenge";

/// Is the credential-release temporal challenge required? DEFAULT OFF.
///
/// Releasing the TPM-sealed login-keyring password happens on a greeter cold
/// login (from reboot) and after logout. Requiring a nod there was measured to
/// be intent, not liveness: the gesture fired on a hand-held print 2 times in 24
/// (2026-07-27), so it never stood between a photograph and the credential;
/// cross-spectrum liveness and the PAD cue do, and the typed password is always
/// the fallback. So this defaults OFF: a cold login and logout release the
/// keyring after the face match with no nod. Only an explicit truthy spelling
/// turns it on, for a user who wants the extra deliberate-intent step. Everything
/// else (lock screen, sudo, polkit) is decided by its own service policy.
///
/// Read live per request (no daemon restart needed). An unrecognized value reads
/// as the default (off), not as on. `IRLUME_CREDENTIAL_RELEASE_CHALLENGE`
/// overrides the file.
pub fn credential_release_challenge() -> bool {
    if let Ok(v) = std::env::var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE") {
        return truthy(&v);
    }
    read_kv("settings.conf", CREDENTIAL_RELEASE_CHALLENGE_KEY).is_some_and(|v| truthy(&v))
}

/// The settings.conf key prefix for per-service consent-gesture overrides.
///
/// Each key is `service_gesture.<service_name>`, where `<service_name>` is the
/// PAM service name (e.g. `sudo`, `polkit-1`) or the special token
/// `credential_release` for the cold-login keyring-unlock path. Values are `1`
/// (gesture required) or `0` (no gesture). An absent key is off: the gesture is
/// an experimental additional gate, never the privileged intent boundary.
pub const SERVICE_GESTURE_KEY: &str = "service_gesture";

/// Read the per-service consent-gesture override from settings.conf.
///
/// Returns `Some(true)` when the gesture is explicitly required for this
/// service, `Some(false)` when explicitly disabled, and `None` when no
/// override is set (the caller applies the default).
pub fn service_gesture(service: &str) -> Option<bool> {
    read_kv("settings.conf", &format!("{SERVICE_GESTURE_KEY}.{service}")).map(|v| !falsy(&v))
}

/// The compatibility default for a service with no explicit gesture setting.
/// Conventional PAM confirmation carries privileged intent, so every optional
/// head gesture defaults off regardless of service class.
pub fn service_gesture_default(_service: &str) -> bool {
    false
}

/// Is the polkit (app-consent) gesture switched on at all?
///
/// `IRLUME_POLKIT_GESTURE`, else `polkit_gesture` in settings.conf, else off.
/// Only a recognized truthy value opts in; malformed or non-UTF-8 environment
/// values stay off rather than inheriting a file value.
///
/// Lives HERE rather than in the engine because three surfaces answer "does
/// this service need a gesture" and they must not answer it differently: the
/// engine enforces it, `credential-release-challenge status` reports it, and
/// the TUI renders a badge for it.
pub fn polkit_gesture_enabled() -> bool {
    if let Some(value) = std::env::var_os("IRLUME_POLKIT_GESTURE") {
        return value.to_str().is_some_and(truthy);
    }
    read_kv("settings.conf", "polkit_gesture").is_some_and(|value| truthy(&value))
}

/// [`service_gesture_required`] when the answer can be KNOWN, `None` when the
/// config cannot be read.
///
/// settings.conf ships 0600 root-owned, so an unprivileged reader gets EACCES,
/// and [`read_kv`] reports that as "absent" like any other miss. Every caller
/// that REPORTS state to a person needs the third answer instead: a TUI running
/// without sudo was rendering the elevation/polkit defaults as a definite
/// "required" for a file it had never read, and deriving its toggle direction
/// from the same guess, so the key could only ever turn a gesture off and the row
/// went on asserting a gate the user had just removed through it.
pub fn service_gesture_required_visible(service: &str) -> Option<bool> {
    match observe_kv("settings.conf", &format!("{SERVICE_GESTURE_KEY}.{service}")) {
        KvObservation::Value(v) => Some(!falsy(&v)),
        KvObservation::Unknown(_) => None,
        // No per-service override: app consent can still opt in through the
        // legacy polkit switch, which lives in the same root-only file.
        KvObservation::Absent => {
            if matches!(
                crate::pam_service::classify(service),
                Some(crate::pam_service::ServiceKind::AppConsent)
            ) {
                if std::env::var_os("IRLUME_POLKIT_GESTURE").is_some() {
                    return Some(polkit_gesture_enabled());
                }
                match observe_kv("settings.conf", "polkit_gesture") {
                    KvObservation::Value(value) => Some(truthy(&value)),
                    KvObservation::Absent => Some(false),
                    KvObservation::Unknown(_) => None,
                }
            } else {
                Some(service_gesture_default(service))
            }
        }
    }
}

/// The EFFECTIVE consent-gesture state for a PAM service: what the engine will
/// actually do, not what one config key says.
///
/// Every service defaults off. An explicit `service_gesture.<service>` override
/// wins; app-consent services also retain the explicit legacy polkit switch.
///
/// Written because the three surfaces had drifted: the TUI applied the
/// elevation default to polkit and rendered `polkit-1: no` on a default install
/// while the daemon required the gesture and the CLI printed `REQUIRED`, and the
/// TUI's toggle then read the same wrong value, so the first press wrote an `on`
/// that changed nothing instead of offering to turn it off.
pub fn service_gesture_required(service: &str) -> bool {
    if let Some(explicit) = service_gesture(service) {
        return explicit;
    }
    if matches!(
        crate::pam_service::classify(service),
        Some(crate::pam_service::ServiceKind::AppConsent)
    ) {
        return polkit_gesture_enabled();
    }
    service_gesture_default(service)
}

/// Whether releasing the sealed login-keyring password requires the deliberate
/// consent gesture, as ONE definition both the daemon (which enforces it) and
/// the PAM module (which tells the user to perform it) call.
///
/// Precedence: the per-service `service_gesture.credential_release` override
/// wins; absent, it falls back to [`credential_release_challenge`] (itself
/// `IRLUME_CREDENTIAL_RELEASE_CHALLENGE` over the global `settings.conf` key).
/// This existed inline in the auth engine while `irlume-pam` computed the
/// instruction from only the global key, so the greeter could tell a user to
/// gesture on a release the daemon granted ungated, or stay silent on a release
/// the daemon gated. One helper keeps the message and the enforcement in step.
pub fn credential_release_gesture_required() -> bool {
    service_gesture("credential_release").unwrap_or_else(credential_release_challenge)
}

/// Source of the transitional accepted-method setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadConsentSource {
    /// `IRLUME_CONSENT_GESTURE`, which takes precedence over the settings file.
    Environment,
    /// `consent_gesture` in `settings.conf`.
    Settings,
}

impl HeadConsentSource {
    fn remedy(self) -> &'static str {
        match self {
            Self::Environment => "unset IRLUME_CONSENT_GESTURE or set it to nod",
            Self::Settings => "remove consent_gesture from settings.conf or set it to nod",
        }
    }
}

/// Whether the configured consent gesture is ready for the head-only gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadConsentPolicy {
    /// The setting is absent or explicitly selects the supported head nod.
    Ready,
    /// The setting still selects the retired eye-closure method.
    LegacyClosure(HeadConsentSource),
    /// The setting is present but is neither `nod` nor `closure`.
    Misconfigured(HeadConsentSource),
}

impl HeadConsentPolicy {
    /// One line telling the user how to satisfy or repair the consent gate.
    pub fn instruction(self, what: &str) -> String {
        match self {
            Self::Ready => format!("keep nodding your head to {what}"),
            Self::LegacyClosure(source) => {
                format!("cannot {what}: eye closure is retired; {}", source.remedy())
            }
            Self::Misconfigured(source) => {
                format!(
                    "cannot {what}: consent_gesture is invalid; {}",
                    source.remedy()
                )
            }
        }
    }
}

/// One-release compile-compatibility adapter for callers awaiting migration to
/// [`HeadConsentPolicy`]. Authorization code must use [`head_consent_policy`]
/// directly; this type never maps retired closure configuration to an accepted
/// gesture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentGesture {
    /// Compatibility result for a ready, nod-only policy.
    Nod,
    /// Exhaustiveness-only legacy variant; [`consent_gesture_mode`] never returns it.
    Closure,
    /// Exhaustiveness-only legacy variant; [`consent_gesture_mode`] never returns it.
    Either,
    /// Compatibility result for every blocked policy.
    Misconfigured,
}

impl ConsentGesture {
    /// Compatibility prompt; legacy closure remains a repair instruction.
    pub fn instruction(self, what: &str) -> String {
        match self {
            Self::Nod | Self::Either => format!("keep nodding your head to {what}"),
            Self::Closure => format!(
                "cannot {what}: eye closure is retired; unset IRLUME_CONSENT_GESTURE or remove consent_gesture from settings.conf, or set whichever source wins to nod"
            ),
            Self::Misconfigured => format!(
                "cannot {what}: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or remove consent_gesture from settings.conf, or set whichever source wins to nod"
            ),
        }
    }
}

fn parse_head_consent_policy(value: Option<&str>, source: HeadConsentSource) -> HeadConsentPolicy {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("nod") => HeadConsentPolicy::Ready,
        Some("closure") => HeadConsentPolicy::LegacyClosure(source),
        Some(_) => HeadConsentPolicy::Misconfigured(source),
    }
}

/// Resolve the head-consent policy using the environment-over-settings precedence.
pub fn head_consent_policy() -> HeadConsentPolicy {
    head_consent_policy_reporting(std::io::stderr())
}

/// One-release compile adapter for callers not yet migrated to
/// [`head_consent_policy`]. Retired or malformed configuration always maps to
/// the fail-closed compatibility result.
pub fn consent_gesture_mode() -> ConsentGesture {
    match head_consent_policy() {
        HeadConsentPolicy::Ready => ConsentGesture::Nod,
        HeadConsentPolicy::LegacyClosure(_) | HeadConsentPolicy::Misconfigured(_) => {
            ConsentGesture::Misconfigured
        }
    }
}

fn head_consent_policy_reporting(mut out: impl std::io::Write) -> HeadConsentPolicy {
    let configured = std::env::var_os("IRLUME_CONSENT_GESTURE")
        .map(|value| {
            (
                value.into_string().ok(),
                "IRLUME_CONSENT_GESTURE",
                HeadConsentSource::Environment,
            )
        })
        .or_else(|| {
            read_kv("settings.conf", "consent_gesture")
                .map(|value| (Some(value), "consent_gesture", HeadConsentSource::Settings))
        });
    let policy = match configured.as_ref() {
        Some((Some(value), _, source)) => parse_head_consent_policy(Some(value), *source),
        Some((None, _, source)) => HeadConsentPolicy::Misconfigured(*source),
        None => HeadConsentPolicy::Ready,
    };
    if let Some((_, source_name, _)) = configured {
        let message = match policy {
            HeadConsentPolicy::Ready => None,
            HeadConsentPolicy::LegacyClosure(source) => Some(format!(
                "configures retired eye closure; {}",
                source.remedy()
            )),
            HeadConsentPolicy::Misconfigured(source) => {
                Some(format!("is invalid; {}", source.remedy()))
            }
        };
        if let Some(message) = message {
            let _ = writeln!(out, "irlume: {source_name} {message}");
        }
    }
    policy
}

#[cfg(test)]
mod camera_pin_tests {
    use super::{read_kv, write_camera_pin};

    /// The pin's keys all land, and the write goes through the file's lock.
    ///
    /// Scoped deliberately: this checks that all four keys are published and
    /// that the lock sidecar was opened, which is what distinguishes this from
    /// four loose writes, since `store_capture_mode_if_absent` takes the same
    /// lock and exclusion needs BOTH sides to take it.
    ///
    /// It does NOT prove mutual exclusion, one publication, or reader
    /// coherence. The sidecar existing shows `OpenOptions::open` ran, not that
    /// `flock` succeeded, and observing a concurrent reader seeing only the
    /// complete old or complete new tuple needs a harness this repo does not
    /// have (#365 review).
    #[test]
    fn the_camera_pin_lands_whole_and_takes_the_lock() {
        let _g = crate::testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        write_camera_pin("/dev/video0", "/dev/video2", "rgbid", "irid").expect("pin writes");

        let got = |k: &str| read_kv("cameras.conf", k);
        assert_eq!(got("rgb").as_deref(), Some("/dev/video0"));
        assert_eq!(got("ir").as_deref(), Some("/dev/video2"));
        assert_eq!(got("rgb_id").as_deref(), Some("rgbid"));
        assert_eq!(got("ir_id").as_deref(), Some("irid"));
        assert!(
            dir.join("cameras.conf.lock").exists(),
            "the write must go through the same lock store_capture_mode_if_absent takes"
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod service_gesture_default_tests {
    use super::service_gesture_default;

    /// Conventional confirmation now carries privileged intent, so no service
    /// may acquire an optional head-gesture gate merely because its setting is
    /// absent. The compatibility helper remains, but its only safe default is
    /// false for every normalized or unknown spelling.
    #[test]
    fn every_service_gesture_default_is_off() {
        for svc in [
            "sudo",
            "sudo-i",
            "su",
            "su-l",
            "runuser",
            "runuser-l",
            "doas",
            "kde",
            "sddm",
            "sshd",
            "polkit-1",
            "totally-made-up",
            " SUDO ",
        ] {
            assert!(
                !service_gesture_default(svc),
                "service {svc:?} must default the optional head gesture OFF"
            );
        }
    }
}

#[cfg(test)]
mod consent_gesture_tests {
    use super::{head_consent_policy_reporting, HeadConsentPolicy, HeadConsentSource};

    #[test]
    fn environment_legacy_closure_instruction_names_the_environment_remedy() {
        let _g = crate::testenv::lock();
        std::env::set_var("IRLUME_CONSENT_GESTURE", "closure");
        let policy = head_consent_policy_reporting(Vec::new());
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        assert_eq!(
            policy.instruction("approve"),
            "cannot approve: eye closure is retired; unset IRLUME_CONSENT_GESTURE or set it to nod"
        );
    }

    #[test]
    fn an_unrecognised_gesture_reports_its_source_and_remedy() {
        let _g = crate::testenv::lock();
        std::env::set_var("IRLUME_CONSENT_GESTURE", "blink");
        let mut out = Vec::new();
        let policy = head_consent_policy_reporting(&mut out);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        assert_eq!(
            policy,
            HeadConsentPolicy::Misconfigured(HeadConsentSource::Environment)
        );
        assert_eq!(
            policy.instruction("approve"),
            "cannot approve: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod"
        );

        let warned = String::from_utf8_lossy(&out);
        assert_eq!(
            warned,
            "irlume: IRLUME_CONSENT_GESTURE is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_environment_gesture_fails_closed_without_echoing_bytes() {
        use std::os::unix::ffi::OsStringExt as _;

        let _g = crate::testenv::lock();
        std::env::set_var(
            "IRLUME_CONSENT_GESTURE",
            std::ffi::OsString::from_vec(vec![0xff]),
        );
        let mut out = Vec::new();
        let policy = head_consent_policy_reporting(&mut out);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        assert_eq!(
            policy,
            HeadConsentPolicy::Misconfigured(HeadConsentSource::Environment)
        );
        assert_eq!(
            policy.instruction("approve"),
            "cannot approve: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod"
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "irlume: IRLUME_CONSENT_GESTURE is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod\n"
        );
    }

    #[test]
    fn nod_policy_is_silent() {
        let _g = crate::testenv::lock();
        for raw in ["nod", "NOD", " nod "] {
            std::env::set_var("IRLUME_CONSENT_GESTURE", raw);
            let mut out = Vec::new();
            let policy = head_consent_policy_reporting(&mut out);
            std::env::remove_var("IRLUME_CONSENT_GESTURE");
            assert_eq!(policy, HeadConsentPolicy::Ready, "{raw}");
            assert!(
                out.is_empty(),
                "{raw} warned: {}",
                String::from_utf8_lossy(&out)
            );
        }
    }

    #[test]
    fn legacy_closure_reports_its_source_and_retirement_remedy() {
        let _g = crate::testenv::lock();
        std::env::set_var("IRLUME_CONSENT_GESTURE", " closure ");
        let mut out = Vec::new();
        let policy = head_consent_policy_reporting(&mut out);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        assert_eq!(
            policy,
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Environment)
        );
        assert_eq!(
            policy.instruction("approve"),
            "cannot approve: eye closure is retired; unset IRLUME_CONSENT_GESTURE or set it to nod"
        );
        let warned = String::from_utf8_lossy(&out);
        assert_eq!(
            warned,
            "irlume: IRLUME_CONSENT_GESTURE configures retired eye closure; unset IRLUME_CONSENT_GESTURE or set it to nod\n"
        );
    }

    #[test]
    fn settings_file_blockers_name_only_the_settings_remedy() {
        let _g = crate::testenv::lock();
        let dir =
            std::env::temp_dir().join(format!("irlume-cg-settings-remedy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        for (value, expected) in [
            (
                "closure",
                "cannot approve: eye closure is retired; remove consent_gesture from settings.conf or set it to nod",
            ),
            (
                "banana",
                "cannot approve: consent_gesture is invalid; remove consent_gesture from settings.conf or set it to nod",
            ),
        ] {
            std::fs::write(
                dir.join("settings.conf"),
                format!("consent_gesture={value}\n"),
            )
            .unwrap();
            assert_eq!(head_consent_policy_reporting(Vec::new()).instruction("approve"), expected);
        }

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The spellings that turn a boolean settings.conf key off.
pub fn falsy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// The spellings that turn a boolean settings.conf key ON. Not the complement of
/// [`falsy`]: an unrecognized value is neither, and a default-off key reads it as
/// off. The single set both the value read and its `_visible` display use, so
/// they cannot disagree on what `yes` means.
pub fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// [`credential_release_challenge`], but honest about not knowing.
///
/// `None` when settings.conf exists and this process may not read it. That is
/// every unprivileged caller: the file is 0600 root-only, so `irlume status` as an
/// ordinary user cannot tell "key absent" (off, the default) from "key set to on".
/// Reporting a guessed security state is worse than saying to re-run under sudo,
/// so the display paths take the `None` and say so. The daemon is root and never
/// sees it. Mirrors [`enforce_biopolicy_visible`]: same truthy set, same env
/// override, Absent means the default.
pub fn credential_release_challenge_visible() -> Option<bool> {
    // An explicit env override answers regardless of file permissions.
    if std::env::var_os("IRLUME_CREDENTIAL_RELEASE_CHALLENGE").is_some() {
        return Some(credential_release_challenge());
    }
    match observe_kv("settings.conf", CREDENTIAL_RELEASE_CHALLENGE_KEY) {
        KvObservation::Value(v) => Some(truthy(&v)),
        // No file, or no key in it, is unambiguous: the default is off.
        KvObservation::Absent => Some(false),
        KvObservation::Unknown(_) => None,
    }
}

/// The EFFECTIVE keyring-release gesture rule as an unprivileged display can
/// honestly see it: the per-service `service_gesture.credential_release`
/// override first (the key `credential-release-challenge credential_release
/// on|off` writes), then the global gate, `None` when the root-only file is
/// unreadable.
///
/// `status` and `doctor` used to read only the global key through
/// [`credential_release_challenge_visible`], so with the per-service key set
/// to 1 they reported "off (default)" and doctor told the user to enable a
/// gate already enabled, and with the global on but the per-service key 0
/// (the daemon releases ungated) doctor asserted a consent gate that does
/// not exist and told the user to nod for it. The daemon's own rule is
/// [`credential_release_gesture_required`]; this is its observe_kv twin.
pub fn credential_release_gesture_required_visible() -> Option<bool> {
    match observe_kv(
        "settings.conf",
        &format!("{SERVICE_GESTURE_KEY}.credential_release"),
    ) {
        // Per-service keys use the daemon's `!falsy` reading, not `truthy`.
        KvObservation::Value(v) => Some(!falsy(&v)),
        KvObservation::Absent => credential_release_challenge_visible(),
        KvObservation::Unknown(_) => None,
    }
}

/// Whether the operation-class gate (`enforce_biopolicy`) is on, or `None` when
/// settings.conf exists and this process may not read it.
///
/// Same reasoning as [`credential_release_challenge_visible`]: the file is 0600
/// root-only, so an unprivileged `irlume status` cannot tell "key absent" (off,
/// the default) from "key set to on". Printing "off (default)" in that case
/// reports a guessed security state as a fact, which is what this returns None
/// to prevent.
pub fn enforce_biopolicy_visible() -> Option<bool> {
    // Must agree with the daemon's `biopolicy_enforced()`, which is the only
    // opinion that decides anything: same truthy set, same env override. The two
    // display sites used to accept "1"|"true" alone, so `enforce_biopolicy=yes`
    // printed "off" while the daemon was enforcing.
    if let Ok(v) = std::env::var("IRLUME_ENFORCE_BIOPOLICY") {
        return Some(truthy(&v));
    }
    match observe_kv("settings.conf", "enforce_biopolicy") {
        KvObservation::Value(v) => Some(truthy(&v)),
        // No file, or no key in it, is unambiguous: the default is off.
        KvObservation::Absent => Some(false),
        KvObservation::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv;

    #[test]
    fn read_write_round_trip_preserves_comments() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        std::fs::write(
            config_path("cameras.conf"),
            "# header\n\n  rgb = /dev/video1 \nir=/dev/video3\n",
        )
        .unwrap();
        assert_eq!(
            read_kv("cameras.conf", "rgb").as_deref(),
            Some("/dev/video1")
        );
        assert_eq!(
            read_kv("cameras.conf", "ir").as_deref(),
            Some("/dev/video3")
        );
        assert_eq!(read_kv("cameras.conf", "missing"), None);

        // Update rgb, add a new key; comments + ir must survive.
        write_kv("cameras.conf", "rgb", "/dev/video9").unwrap();
        write_kv("cameras.conf", "fps", "30").unwrap();
        let text = std::fs::read_to_string(config_path("cameras.conf")).unwrap();
        assert!(text.contains("# header"));
        assert_eq!(
            read_kv("cameras.conf", "rgb").as_deref(),
            Some("/dev/video9")
        );
        assert_eq!(
            read_kv("cameras.conf", "ir").as_deref(),
            Some("/dev/video3")
        );
        assert_eq!(read_kv("cameras.conf", "fps").as_deref(), Some("30"));
        // No duplicate rgb line.
        assert_eq!(
            text.matches("rgb=").count() + text.matches("rgb ").count(),
            1
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The writer lock is held for the guard's lifetime and released on drop:
    /// a second exclusive take succeeds after the first guard is gone, and it
    /// serializes against a concurrent holder rather than failing. Two
    /// threads, not two processes; flock's cross-process behavior is the
    /// kernel's contract, and what irlume adds (guard scope, sidecar path,
    /// release on drop) is what this covers.
    #[test]
    fn lock_exclusive_serializes_and_releases_on_drop() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        let first = lock_exclusive("cameras.conf").unwrap();
        assert!(
            config_path("cameras.conf.lock").exists(),
            "the sidecar lock file must live under the config root"
        );
        // A contender on another thread must not get through while the
        // first guard lives.
        let (tx, rx) = std::sync::mpsc::channel();
        let dir2 = dir.clone();
        let contender = std::thread::spawn(move || {
            // The var is process-global and already set; the clone only
            // keeps the dir alive for the assert below.
            let _ = &dir2;
            let _second = lock_exclusive("cameras.conf").unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "the second take must block while the first guard is held"
        );
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("dropping the guard must release the lock");
        contender.join().unwrap();

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_path_defaults_to_etc_irlume_without_the_override() {
        let _g = testenv::lock();
        std::env::remove_var("IRLUME_CONFIG_DIR");
        assert_eq!(
            config_path("cameras.conf"),
            PathBuf::from("/etc/irlume/cameras.conf")
        );
    }

    #[test]
    fn explicit_service_gestures_are_opt_in() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-svcgest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_POLKIT_GESTURE");

        // No overrides: every service is off, including elevation and polkit.
        std::fs::write(config_path("settings.conf"), "").unwrap();
        for svc in [
            "sudo",
            "sudo-i",
            "su",
            "su-l",
            "runuser",
            "runuser-l",
            "doas",
            "polkit-1",
            "kde",
        ] {
            assert!(!service_gesture_required(svc), "{svc} must default off");
            assert_eq!(
                service_gesture_required_visible(svc),
                Some(false),
                "{svc} must visibly default off"
            );
        }

        // Per-service settings remain the highest-precedence explicit opt-in.
        std::fs::write(
            config_path("settings.conf"),
            "service_gesture.sudo=1\nservice_gesture.polkit-1=1\n",
        )
        .unwrap();
        assert!(service_gesture_required("sudo"));
        assert!(service_gesture_required("polkit-1"));

        // The legacy polkit switch is also an explicit opt-in, but malformed
        // values do not accidentally enable it.
        std::fs::write(config_path("settings.conf"), "polkit_gesture=1\n").unwrap();
        assert!(service_gesture_required("polkit-1"));
        assert!(!service_gesture_required("sudo"));
        std::fs::write(config_path("settings.conf"), "polkit_gesture=banana\n").unwrap();
        assert!(!service_gesture_required("polkit-1"));
        assert_eq!(service_gesture_required_visible("polkit-1"), Some(false));

        // The environment wins over the file and uses the same strict truthy
        // parser in both the enforcement and visible readers.
        std::env::set_var("IRLUME_POLKIT_GESTURE", "yes");
        assert!(service_gesture_required("polkit-1"));
        assert_eq!(service_gesture_required_visible("polkit-1"), Some(true));
        std::env::set_var("IRLUME_POLKIT_GESTURE", "banana");
        assert!(!service_gesture_required("polkit-1"));
        assert_eq!(service_gesture_required_visible("polkit-1"), Some(false));
        std::env::remove_var("IRLUME_POLKIT_GESTURE");

        // A present but non-UTF-8 environment value still wins over a truthy
        // file value and fails closed to the optional gate being off.
        use std::os::unix::ffi::OsStringExt as _;
        std::fs::write(config_path("settings.conf"), "polkit_gesture=1\n").unwrap();
        std::env::set_var(
            "IRLUME_POLKIT_GESTURE",
            std::ffi::OsString::from_vec(vec![0xff]),
        );
        assert!(!service_gesture_required("polkit-1"));
        assert_eq!(service_gesture_required_visible("polkit-1"), Some(false));
        std::env::remove_var("IRLUME_POLKIT_GESTURE");

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_kv_skips_malformed_lines_and_empty_values() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-lines-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        std::fs::write(
            config_path("settings.conf"),
            "# comment with = sign\nnot a kv line\nempty=\nreal=value\n",
        )
        .unwrap();
        // A line without '=' and a commented '=' are both ignored.
        assert_eq!(read_kv("settings.conf", "not a kv line"), None);
        assert_eq!(read_kv("settings.conf", "# comment with "), None);
        // `key=` (empty value) reads as absent, not Some("").
        assert_eq!(read_kv("settings.conf", "empty"), None);
        assert_eq!(read_kv("settings.conf", "real").as_deref(), Some("value"));

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_config_reads_as_absent_not_a_crash() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-eperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        // A directory where a file is expected: a non-NotFound, non-EACCES read
        // error (EISDIR). Takes the loud-warning branch and still yields None.
        std::fs::create_dir_all(config_path("weird.conf")).unwrap();
        assert_eq!(read_kv("weird.conf", "k"), None);

        // 0600-root-style file we cannot read: the expected unprivileged EACCES
        // is the quiet branch. Only meaningful when not running as root.
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let p = config_path("locked.conf");
            std::fs::write(&p, "k=v\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(read_kv("locked.conf", "k"), None);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_kv_collapses_preexisting_duplicate_keys() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        // A hand-edited file can carry the same key twice; an update must
        // leave exactly one line, holding the new value, and keep other keys.
        std::fs::write(
            config_path("cameras.conf"),
            "rgb=/dev/video0\nir=/dev/video2\nrgb=/dev/video4\n",
        )
        .unwrap();
        write_kv("cameras.conf", "rgb", "/dev/video8").unwrap();
        let text = std::fs::read_to_string(config_path("cameras.conf")).unwrap();
        assert_eq!(text.matches("rgb=").count(), 1);
        assert!(text.contains("rgb=/dev/video8"));
        assert_eq!(
            read_kv("cameras.conf", "ir").as_deref(),
            Some("/dev/video2")
        );

        // The file is (re)written 0600: these can hold device choices only the
        // operator should edit.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(config_path("cameras.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_camera_pin_publishes_four_keys_and_leaves_other_lines_alone() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        // A pre-existing comment, a capture-mode key the pin writer must not
        // touch, and stale rgb/ir lines to be replaced in place.
        std::fs::write(
            config_path("cameras.conf"),
            "# operator notes\ncapture_mode=sequential\nrgb=/dev/videoOLD\nir=/dev/videoOLDIR\n",
        )
        .unwrap();

        write_camera_pin("/dev/video0", "/dev/video2", "1d6b:0002:S1", "1d6b:0003:S1").unwrap();

        let pin = read_camera_pin();
        assert_eq!(pin.rgb.as_deref(), Some("/dev/video0"));
        assert_eq!(pin.ir.as_deref(), Some("/dev/video2"));
        assert_eq!(pin.rgb_id.as_deref(), Some("1d6b:0002:S1"));
        assert_eq!(pin.ir_id.as_deref(), Some("1d6b:0003:S1"));

        let text = std::fs::read_to_string(config_path("cameras.conf")).unwrap();
        assert!(text.contains("# operator notes"), "comment preserved");
        assert_eq!(
            read_kv("cameras.conf", "capture_mode").as_deref(),
            Some("sequential"),
            "an unrelated key in the same file is not disturbed"
        );
        // Exactly one line per pin key: the stale rgb/ir were replaced, not
        // appended alongside.
        for k in ["rgb", "ir", "rgb_id", "ir_id"] {
            assert_eq!(
                text.matches(&format!("{k}=")).count(),
                1,
                "key {k} must appear once"
            );
        }
        assert!(!text.contains("/dev/videoOLD"), "old paths are gone");

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_camera_pin_with_empty_identity_clears_a_stale_one() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-pinclr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        write_camera_pin("/dev/video0", "/dev/video2", "1d6b:0002:S1", "1d6b:0003:S1").unwrap();
        // Repin to nodes with no USB descriptor: empty ids must clear, not keep,
        // the old identity, so a reader does not re-anchor to the wrong sensor.
        write_camera_pin("/dev/video4", "/dev/video6", "", "").unwrap();

        let pin = read_camera_pin();
        assert_eq!(pin.rgb.as_deref(), Some("/dev/video4"));
        assert_eq!(pin.ir.as_deref(), Some("/dev/video6"));
        assert_eq!(pin.rgb_id, None, "empty id reads back as absent");
        assert_eq!(pin.ir_id, None, "empty id reads back as absent");

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_camera_pin_of_a_missing_file_is_all_absent() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-pinabs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        assert_eq!(read_camera_pin(), CameraPin::default());

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The property that makes the pin an anti-injection binding: a reader
    /// racing a repin sees the complete old tuple or the complete new one, never
    /// a mix. `read_camera_pin` reads the whole file once, so a rename between
    /// what used to be four separate opens can no longer split the pin. The
    /// harness the issue (#374) asked for: a reader thread in a tight loop while
    /// the writer alternates between two full tuples. The `saw_a && saw_b`
    /// assertion proves the writer actually raced the reader rather than the
    /// reader finishing first and reading one static value. The two atomic
    /// fsyncs inside each publish yield the CPU, so the reader interleaves even
    /// on a single core. This test would trip on the old four-open reader.
    #[test]
    fn read_camera_pin_never_observes_a_torn_pair_under_concurrent_writes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-pinrace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);

        let pin_a = CameraPin {
            rgb: Some("/dev/videoA0".into()),
            ir: Some("/dev/videoA2".into()),
            rgb_id: Some("aaaa:0001:AA".into()),
            ir_id: Some("aaaa:0002:AA".into()),
        };
        let pin_b = CameraPin {
            rgb: Some("/dev/videoB0".into()),
            ir: Some("/dev/videoB2".into()),
            rgb_id: Some("bbbb:0001:BB".into()),
            ir_id: Some("bbbb:0002:BB".into()),
        };
        // Start on A so a reader that beats the writer still sees a valid tuple.
        write_camera_pin(
            "/dev/videoA0",
            "/dev/videoA2",
            "aaaa:0001:AA",
            "aaaa:0002:AA",
        )
        .unwrap();

        let done = Arc::new(AtomicBool::new(false));
        let done_r = Arc::clone(&done);
        let (a, b) = (pin_a.clone(), pin_b.clone());
        let reader = std::thread::spawn(move || {
            let (mut saw_a, mut saw_b, mut reads) = (false, false, 0u64);
            while !done_r.load(Ordering::Relaxed) {
                let p = read_camera_pin();
                reads += 1;
                if p == a {
                    saw_a = true;
                } else if p == b {
                    saw_b = true;
                } else {
                    panic!("torn camera pin observed after {reads} reads: {p:?}");
                }
            }
            (saw_a, saw_b, reads)
        });

        for i in 0..400 {
            if i % 2 == 0 {
                write_camera_pin(
                    "/dev/videoB0",
                    "/dev/videoB2",
                    "bbbb:0001:BB",
                    "bbbb:0002:BB",
                )
                .unwrap();
            } else {
                write_camera_pin(
                    "/dev/videoA0",
                    "/dev/videoA2",
                    "aaaa:0001:AA",
                    "aaaa:0002:AA",
                )
                .unwrap();
            }
        }
        done.store(true, Ordering::Relaxed);

        let (saw_a, saw_b, reads) = reader.join().expect("reader must not observe a torn pin");
        assert!(reads > 0, "the reader loop must have run");
        assert!(
            saw_a && saw_b,
            "the writer must have raced the reader (saw_a={saw_a}, saw_b={saw_b}, reads={reads})"
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_gesture_config_never_silently_widens_to_nod() {
        assert_eq!(
            parse_head_consent_policy(None, HeadConsentSource::Settings),
            HeadConsentPolicy::Ready
        );
        assert_eq!(
            parse_head_consent_policy(Some("nod"), HeadConsentSource::Settings),
            HeadConsentPolicy::Ready
        );
        assert_eq!(
            parse_head_consent_policy(Some("closure"), HeadConsentSource::Settings),
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Settings)
        );
        assert_eq!(
            parse_head_consent_policy(Some(" CLOSURE "), HeadConsentSource::Environment),
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Environment)
        );
        assert_eq!(
            parse_head_consent_policy(Some("clousure"), HeadConsentSource::Environment),
            HeadConsentPolicy::Misconfigured(HeadConsentSource::Environment)
        );
    }

    #[test]
    fn legacy_closure_instruction_is_actionable_and_names_no_eye_action() {
        let message =
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Settings).instruction("approve");
        assert_eq!(
            message,
            "cannot approve: eye closure is retired; remove consent_gesture from settings.conf or set it to nod"
        );
        assert!(!message.contains("close your eyes"));
    }

    #[test]
    fn head_consent_policy_preserves_environment_over_settings_precedence() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        assert_eq!(head_consent_policy(), HeadConsentPolicy::Ready);
        write_kv("settings.conf", "consent_gesture", "closure").unwrap();
        assert_eq!(
            head_consent_policy(),
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Settings),
            "the settings file remains the fallback source"
        );
        std::env::set_var("IRLUME_CONSENT_GESTURE", "nod");
        assert_eq!(
            head_consent_policy(),
            HeadConsentPolicy::Ready,
            "the environment override must continue to win"
        );

        write_kv("settings.conf", "consent_gesture", "nod").unwrap();
        std::env::set_var("IRLUME_CONSENT_GESTURE", "closure");
        let policy = head_consent_policy();
        assert_eq!(
            policy,
            HeadConsentPolicy::LegacyClosure(HeadConsentSource::Environment),
            "a blocking environment override must outrank ready settings"
        );
        assert_eq!(
            policy.instruction("approve"),
            "cannot approve: eye closure is retired; unset IRLUME_CONSENT_GESTURE or set it to nod"
        );

        std::env::set_var("IRLUME_CONSENT_GESTURE", "banana");
        let policy = head_consent_policy();
        assert_eq!(
            policy,
            HeadConsentPolicy::Misconfigured(HeadConsentSource::Environment),
            "a malformed environment override must outrank ready settings"
        );
        assert_eq!(
            policy.instruction("approve"),
            "cannot approve: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod"
        );

        std::env::remove_var("IRLUME_CONSENT_GESTURE");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compatibility_gesture_keeps_the_original_unit_variant_shape() {
        fn unchanged_consumer(value: ConsentGesture) -> &'static str {
            match value {
                ConsentGesture::Nod => "nod",
                ConsentGesture::Closure => "closure",
                ConsentGesture::Either => "either",
                ConsentGesture::Misconfigured => "blocked",
            }
        }

        assert_eq!(unchanged_consumer(ConsentGesture::Misconfigured), "blocked");
        assert_eq!(
            ConsentGesture::Misconfigured.instruction("approve"),
            "cannot approve: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or remove consent_gesture from settings.conf, or set whichever source wins to nod"
        );
    }

    #[test]
    fn compatibility_gesture_mode_maps_ready_policy_to_nod() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cg-compat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        assert_eq!(consent_gesture_mode(), ConsentGesture::Nod);
        write_kv("settings.conf", "consent_gesture", "nod").unwrap();
        assert_eq!(consent_gesture_mode(), ConsentGesture::Nod);

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compatibility_gesture_mode_maps_legacy_and_malformed_to_fail_closed() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cg-compat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CONSENT_GESTURE");

        for value in ["closure", "clousure"] {
            write_kv("settings.conf", "consent_gesture", value).unwrap();
            assert_eq!(
                consent_gesture_mode(),
                ConsentGesture::Misconfigured,
                "consent_gesture={value:?}"
            );
        }

        std::env::set_var("IRLUME_CONSENT_GESTURE", "closure");
        assert_eq!(consent_gesture_mode(), ConsentGesture::Misconfigured);

        std::env::remove_var("IRLUME_CONSENT_GESTURE");
        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DEFAULT OFF: absent means OFF, only an explicit truthy spelling turns it
    /// on, and an unrecognized value reads as the default (off), not on. The nod
    /// on a greeter cold login / logout was retired to intent-not-liveness, so the
    /// keyring releases after the face match with no nod unless a user opts in.
    #[test]
    fn credential_release_challenge_defaults_off() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-crc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        let key = CREDENTIAL_RELEASE_CHALLENGE_KEY;
        // No settings.conf at all -> off (the default).
        assert!(!credential_release_challenge(), "missing file must be off");

        // Every truthy spelling, in either case, turns it on.
        for v in ["1", "true", "yes", "on", "ON", "True"] {
            write_kv("settings.conf", key, v).unwrap();
            assert!(credential_release_challenge(), "'{v}' must enable the gate");
        }
        // Falsy spellings and an unrecognized value all read as off (the default).
        for v in ["0", "false", "no", "off", "0ff", "enabled", "maybe"] {
            write_kv("settings.conf", key, v).unwrap();
            assert!(!credential_release_challenge(), "'{v}' must leave it off");
        }
        // An empty value reads as absent -> off.
        write_kv("settings.conf", key, "").unwrap();
        assert!(!credential_release_challenge(), "empty value must be off");

        // The env override wins over the file, both directions.
        write_kv("settings.conf", key, "off").unwrap();
        std::env::set_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE", "1");
        assert!(credential_release_challenge(), "env on must win");
        std::env::set_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE", "0");
        write_kv("settings.conf", key, "on").unwrap();
        assert!(!credential_release_challenge(), "env off must win");
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        // Unrelated keys survive a write of ours.
        write_kv("settings.conf", "consent_gesture", "nod").unwrap();
        write_kv("settings.conf", key, "1").unwrap();
        assert_eq!(
            read_kv("settings.conf", "consent_gesture").as_deref(),
            Some("nod")
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The VISIBLE twin must apply the same order the daemon does: per-service
    /// override first, then the global gate. `status` and `doctor` used to read
    /// only the global key, so with `service_gesture.credential_release=1` and
    /// no global key they said "off (default)" while the daemon required the
    /// gesture, and with the global on but the per-service key 0 doctor told
    /// the user to nod for a gate the daemon does not apply.
    #[test]
    fn credential_release_gesture_required_visible_reads_the_effective_rule() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-crgv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        // Nothing set: the global default (off).
        assert_eq!(credential_release_gesture_required_visible(), Some(false));

        // Scenario A: per-service 1, no global. The daemon requires the
        // gesture, so the display must say required.
        let svc_key = format!("{SERVICE_GESTURE_KEY}.credential_release");
        write_kv("settings.conf", &svc_key, "1").unwrap();
        assert_eq!(credential_release_gesture_required_visible(), Some(true));
        assert_eq!(
            credential_release_gesture_required_visible(),
            Some(credential_release_gesture_required()),
            "the display must agree with the daemon's rule"
        );

        // Scenario B: global 1, per-service 0. The daemon releases ungated,
        // so asserting a gate here told the user to nod for nothing.
        write_kv("settings.conf", CREDENTIAL_RELEASE_CHALLENGE_KEY, "1").unwrap();
        write_kv("settings.conf", &svc_key, "0").unwrap();
        assert_eq!(credential_release_gesture_required_visible(), Some(false));
        assert_eq!(
            credential_release_gesture_required_visible(),
            Some(credential_release_gesture_required()),
            "the display must agree with the daemon's rule"
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The credential-release gesture helper the daemon and PAM share must give
    /// the per-service override priority over the global key, so the greeter
    /// instruction and the daemon's enforcement cannot disagree.
    #[test]
    fn credential_release_gesture_required_prefers_the_service_override() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-crgr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_CREDENTIAL_RELEASE_CHALLENGE");

        // No override and no global key: defaults OFF (the greeter/logout nod was
        // retired to intent-not-liveness), so the keyring releases with no nod.
        assert!(
            !credential_release_gesture_required(),
            "default is off: a cold login releases the keyring with no nod"
        );

        // A per-service override ON requires it even against the default/global.
        write_kv("settings.conf", CREDENTIAL_RELEASE_CHALLENGE_KEY, "off").unwrap();
        assert!(
            !credential_release_gesture_required(),
            "global off with no override disables it"
        );
        write_kv("settings.conf", "service_gesture.credential_release", "1").unwrap();
        assert!(
            credential_release_gesture_required(),
            "service override ON wins over global off"
        );

        // Global ON, but a per-service override OFF wins.
        write_kv("settings.conf", CREDENTIAL_RELEASE_CHALLENGE_KEY, "on").unwrap();
        write_kv("settings.conf", "service_gesture.credential_release", "0").unwrap();
        assert!(
            !credential_release_gesture_required(),
            "service override OFF wins over global on"
        );

        std::env::remove_var("IRLUME_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
