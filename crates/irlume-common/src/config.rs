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

/// Machine-wide sensor selection, independent of two-camera scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaceSensorPolicy {
    Dual,
    IrOnlyExperimental,
}

/// One observed policy snapshot. Errors never imply permission to use RGB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaceSensorPolicyObservation {
    DefaultDual,
    Explicit(FaceSensorPolicy),
    Invalid,
    Unreadable,
}

impl FaceSensorPolicyObservation {
    /// Resolve the single observation without defaulting on malformed policy.
    ///
    /// # Errors
    /// Invalid or unreadable policy requires password fallback.
    pub fn resolve(self) -> crate::Result<FaceSensorPolicy> {
        match self {
            Self::DefaultDual => Ok(FaceSensorPolicy::Dual),
            Self::Explicit(policy) => Ok(policy),
            Self::Invalid | Self::Unreadable => Err(crate::Error::Policy(
                "face sensor policy is invalid or unreadable; use your password".into(),
            )),
        }
    }
}

/// Read the sensor setting once without probing cameras or loading enrollment.
/// Empty, duplicate and malformed settings are invalid, not the dual default.
pub fn observe_face_sensor_policy() -> FaceSensorPolicyObservation {
    use FaceSensorPolicyObservation::{DefaultDual, Explicit, Invalid, Unreadable};
    let text = match std::fs::read_to_string(config_path("settings.conf")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return DefaultDual,
        Err(_) => return Unreadable,
    };
    let mut selected = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Recognize malformed attempts to set this exact key too. Otherwise
        // a missing '=' or a ':' separator silently restores the dual default.
        // Distinct keys sharing the prefix remain unrelated settings.
        let is_policy = line.strip_prefix("face_sensor_policy").is_some_and(|tail| {
            tail.is_empty() || tail.starts_with(|c: char| c.is_whitespace() || c == '=' || c == ':')
        });
        if !is_policy {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Invalid;
        };
        if key.trim() != "face_sensor_policy" {
            return Invalid;
        }
        if selected.is_some() {
            return Invalid;
        }
        selected = Some(match value.trim() {
            "dual" => FaceSensorPolicy::Dual,
            "ir-only-experimental" => FaceSensorPolicy::IrOnlyExperimental,
            _ => return Invalid,
        });
    }
    selected.map_or(DefaultDual, Explicit)
}

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

/// Whether the operation-class gate (`enforce_biopolicy`) is on, or `None` when
/// settings.conf exists and this process may not read it.
///
/// Same reasoning as [`observe_kv`]: the file is 0600
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

/// Whether the external-camera prohibition (`forbid_external_cameras`) is on,
/// or `None` when settings.conf exists and this process may not read it.
///
/// The policy twin of Windows' `ShouldForbidExternalCameras` (hardened after
/// CVE-2021-34466): with the key set, only cameras the kernel reports as
/// `removable: fixed` may authenticate. Mirrors [`enforce_biopolicy_visible`]:
/// same truthy set, same env override shape, Absent means the default (off,
/// external Hello cameras work).
pub fn forbid_external_cameras_visible() -> Option<bool> {
    if let Ok(v) = std::env::var("IRLUME_FORBID_EXTERNAL_CAMERAS") {
        return Some(truthy(&v));
    }
    match observe_kv("settings.conf", "forbid_external_cameras") {
        KvObservation::Value(v) => Some(truthy(&v)),
        KvObservation::Absent => Some(false),
        KvObservation::Unknown(_) => None,
    }
}

/// Whether privileged services must collect the literal `yes` before a face
/// attempt (`privileged_face_consent`), or `None` when settings.conf exists and
/// this process may not read it.
///
/// The odd one out among these keys: it defaults **on**, so an absent file or an
/// absent key means the confirmation is required, and the key exists to turn a
/// protection off rather than on. That asymmetry is deliberate. No surface
/// irlume wires runs hands-free by default, and this key does not make one: it
/// puts privileged prompts on a standing-consent footing as the machine owner's
/// own choice, distinct from every default surface, without moving that line
/// for anyone who does not ask (ADR-0018).
///
/// Read by both sides. The PAM module skips the prompt, and the daemon consults
/// it again before honouring [`crate::IntentAttestation::PolicyWaived`], so a client
/// cannot waive a confirmation the machine's own policy still requires.
pub fn privileged_face_consent_visible() -> Option<bool> {
    // Waiving confirmation requires an explicit opt-out. A typo, empty or
    // non-Unicode environment value cannot silently remove the intent gate.
    if let Some(v) = std::env::var_os("IRLUME_PRIVILEGED_FACE_CONSENT") {
        return Some(!v.to_str().is_some_and(falsy));
    }
    match observe_kv("settings.conf", "privileged_face_consent") {
        KvObservation::Value(v) => Some(!falsy(&v)),
        // Absent is unambiguous here too, but the default is ON.
        KvObservation::Absent => Some(true),
        KvObservation::Unknown(_) => None,
    }
}

/// [`privileged_face_consent_visible`] resolved for a decision: unreadable
/// settings keep the confirmation, because a policy this process cannot read is
/// not a policy that waived anything.
#[must_use]
pub fn privileged_face_consent_required() -> bool {
    privileged_face_consent_visible().unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv;

    /// The privileged-consent key reads env-over-settings like its neighbours,
    /// but Absent means ON: it exists to switch a protection off, so anything
    /// that fails to say otherwise has to leave it standing.
    #[test]
    fn privileged_face_consent_defaults_on_and_env_wins_over_settings() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-consent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT");

        // Absent key: required, and unambiguously so.
        assert_eq!(privileged_face_consent_visible(), Some(true));
        assert!(privileged_face_consent_required());

        // Settings file turns it off.
        write_kv("settings.conf", "privileged_face_consent", "0").unwrap();
        assert_eq!(privileged_face_consent_visible(), Some(false));
        assert!(!privileged_face_consent_required());

        // The env override wins over the file, in both directions.
        std::env::set_var("IRLUME_PRIVILEGED_FACE_CONSENT", "1");
        assert_eq!(privileged_face_consent_visible(), Some(true));
        std::env::set_var("IRLUME_PRIVILEGED_FACE_CONSENT", "no");
        assert_eq!(privileged_face_consent_visible(), Some(false));

        std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn privileged_consent_requires_an_explicit_opt_out() {
        let _g = testenv::lock();
        let dir =
            std::env::temp_dir().join(format!("irlume-consent-invalid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT");
        for (value, required) in [
            ("0", false),
            (" OFF ", false),
            ("false", false),
            ("no", false),
            ("yes", true),
            ("1", true),
            ("on", true),
            ("true", true),
            ("typo", true),
            ("2", true),
            ("", true),
        ] {
            write_kv("settings.conf", "privileged_face_consent", value).unwrap();
            assert_eq!(
                privileged_face_consent_required(),
                required,
                "file value {value:?}"
            );
            std::env::set_var("IRLUME_PRIVILEGED_FACE_CONSENT", value);
            assert_eq!(
                privileged_face_consent_required(),
                required,
                "env value {value:?}"
            );
            std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT");
        }
        // A non-Unicode override must not fall through to a file waiver.
        use std::os::unix::ffi::OsStringExt as _;
        write_kv("settings.conf", "privileged_face_consent", "0").unwrap();
        std::env::set_var(
            "IRLUME_PRIVILEGED_FACE_CONSENT",
            std::ffi::OsString::from_vec(vec![0xff]),
        );
        assert!(privileged_face_consent_required());
        std::env::remove_var("IRLUME_PRIVILEGED_FACE_CONSENT");
        std::fs::remove_file(dir.join("settings.conf")).unwrap();
        std::fs::create_dir(dir.join("settings.conf")).unwrap();
        assert_eq!(privileged_face_consent_visible(), None);
        assert!(privileged_face_consent_required());
        std::env::remove_var("IRLUME_CONFIG_DIR");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The external-camera prohibition reads env-over-settings with Absent
    /// meaning off, exactly like the biopolicy gate it mirrors.
    #[test]
    fn forbid_external_cameras_env_wins_then_settings_then_default_off() {
        let _g = testenv::lock();
        let dir = std::env::temp_dir().join(format!("irlume-cfg-extcam-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("IRLUME_CONFIG_DIR", &dir);
        std::env::remove_var("IRLUME_FORBID_EXTERNAL_CAMERAS");

        // Absent key: off, and unambiguously so.
        assert_eq!(forbid_external_cameras_visible(), Some(false));

        // Settings file turns it on.
        write_kv("settings.conf", "forbid_external_cameras", "1").unwrap();
        assert_eq!(forbid_external_cameras_visible(), Some(true));

        // The env override wins over the file, in both directions.
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "0");
        assert_eq!(forbid_external_cameras_visible(), Some(false));
        std::env::set_var("IRLUME_FORBID_EXTERNAL_CAMERAS", "yes");
        assert_eq!(forbid_external_cameras_visible(), Some(true));

        std::env::remove_var("IRLUME_FORBID_EXTERNAL_CAMERAS");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
}
