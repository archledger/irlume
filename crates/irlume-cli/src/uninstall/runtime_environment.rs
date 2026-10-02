// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Disk settings describe a future exec. Verify a running system service's
//! initial environment before treating those settings as its selected store.

use std::io::Read;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn show(args: &[&str]) -> Result<String, String> {
    let out = irlume_common::process::output_until(
        Command::new("systemctl").args(args),
        Instant::now() + Duration::from_secs(2),
    )
    .map_err(|e| format!("cannot establish irlumed environment: {e}"))?;
    if !out.status.success() {
        return Err("cannot establish irlumed environment from systemd".into());
    }
    String::from_utf8(out.stdout).map_err(|_| "invalid systemd response".into())
}

const PROPERTIES: &[&str] = &[
    "show",
    "irlumed.service",
    "--no-pager",
    "--all",
    "-p",
    "MainPID",
    "-p",
    "LoadState",
    "-p",
    "ActiveState",
    "-p",
    "NeedDaemonReload",
    "-p",
    "RootDirectory",
    "-p",
    "RootImage",
    "-p",
    "InvocationID",
    "-p",
    "ExecMainPID",
    "-p",
    "ExecMainStartTimestampMonotonic",
];

pub(super) const ACTIVATORS: &[&str] = &[
    "irlume-reconcile.path",
    "irlume-reconcile.timer",
    "irlume-reconcile.service",
    "irlume-runner-prune.timer",
    "irlume-runner-prune.service",
    "irlumed.socket",
];

fn property<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|s| s.strip_prefix(name)?.strip_prefix('='))
}

fn main_pid(text: &str) -> Result<Option<u32>, String> {
    if property(text, "LoadState") == Some("not-found")
        && property(text, "MainPID") == Some("0")
        && matches!(property(text, "ActiveState"), Some("inactive" | "failed"))
    {
        return Ok(None);
    }
    if property(text, "LoadState") != Some("loaded")
        || property(text, "NeedDaemonReload") != Some("no")
        || property(text, "RootDirectory") != Some("")
        || property(text, "RootImage") != Some("")
    {
        return Err(
            "irlumed unit is unresolved, changed on disk, or uses a different filesystem root"
                .into(),
        );
    }
    let pid: u32 = property(text, "MainPID")
        .ok_or("missing MainPID")?
        .parse()
        .map_err(|_| "invalid MainPID")?;
    match (property(text, "ActiveState"), pid) {
        (Some("active"), 1..) => Ok(Some(pid)),
        (Some("inactive" | "failed"), 0) => Ok(None),
        _ => Err("irlumed is in a transitional or uninspectable state".into()),
    }
}

fn process_value(bytes: &[u8], var: &str) -> Result<Option<PathBuf>, String> {
    let prefix = format!("{var}=");
    let mut found = None;
    for entry in bytes.split(|b| *b == 0) {
        if let Some(value) = entry.strip_prefix(prefix.as_bytes()) {
            if found.is_some() {
                return Err("duplicate daemon directory variable".into());
            }
            let value = std::str::from_utf8(value).map_err(|_| "non-UTF8 daemon directory")?;
            found = Some(super::unit_environment::absolute(value, var)?);
        }
    }
    Ok(found)
}

fn agree(disk: &Option<PathBuf>, running: Option<PathBuf>) -> Result<(), String> {
    if *disk != running {
        return Err(
            "irlumed's running environment differs from disk; reconcile it before removing stores"
                .into(),
        );
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub disk: super::unit_environment::Disk,
    status: Option<String>,
}

pub(super) fn capture() -> Result<Snapshot, String> {
    capture_with(Path::new("/"), Path::new("/proc"), 0, show)
}

impl Snapshot {
    /// Re-read the complete identified snapshot before stopping anything.
    pub fn revalidate(&self) -> Result<(), String> {
        if *self != capture()? {
            return Err("irlumed selection changed before quiescence".into());
        }
        Ok(())
    }

    /// Disk input must survive the stop unchanged. ExecMain and InvocationID
    /// identify the last execution even after MainPID becomes zero. If systemd
    /// garbage-collected that evidence, refuse rather than infer continuity.
    pub fn quiescent(&self) -> Result<(), String> {
        self.still_quiescent()?;
        if self.disk != super::unit_environment::snapshot(Path::new("/"))? {
            return Err("unit environment changed while stopping irlumed".into());
        }
        Ok(())
    }

    pub fn still_quiescent(&self) -> Result<(), String> {
        self.still_quiescent_with(show)
    }

    fn still_quiescent_with(
        &self,
        mut show: impl FnMut(&[&str]) -> Result<String, String>,
    ) -> Result<(), String> {
        self.check_stopped(&show(PROPERTIES)?)?;
        for unit in ACTIVATORS {
            let state = show(&[
                "show",
                unit,
                "--all",
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
            ])?;
            if !matches!(property(&state, "ActiveState"), Some("inactive" | "failed")) {
                return Err(format!("{unit} is not quiescent"));
            }
        }
        Ok(())
    }

    fn check_stopped(&self, text: &str) -> Result<(), String> {
        let prior = self
            .status
            .as_deref()
            .ok_or("cannot prove daemon quiescence offline")?;
        if main_pid(text)?.is_some() || generation(prior)? != generation(text)? {
            return Err(
                "irlumed execution changed during teardown; data and SRK are retained".into(),
            );
        }
        Ok(())
    }
}

fn generation(text: &str) -> Result<(&str, &str, &str), String> {
    let id = property(text, "InvocationID").ok_or("missing invocation identity")?;
    let pid = property(text, "ExecMainPID").ok_or("missing last execution PID")?;
    let start =
        property(text, "ExecMainStartTimestampMonotonic").ok_or("missing execution timestamp")?;
    if (!id.is_empty() && (id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit())))
        || pid.parse::<u32>().is_err()
        || start.parse::<u64>().is_err()
    {
        return Err("invalid execution identity".into());
    }
    if main_pid(text)?.is_some() && (id.is_empty() || pid == "0" || start == "0") {
        return Err("incomplete running execution identity".into());
    }
    Ok((id, pid, start))
}

fn capture_with(
    root: &Path,
    proc_root: &Path,
    owner: u32,
    mut show: impl FnMut(&[&str]) -> Result<String, String>,
) -> Result<Snapshot, String> {
    // Observe the generation before reading any directory variable. All four
    // values share one envfile cache and one process-environment read.
    let before = show(PROPERTIES);
    let disk = super::unit_environment::snapshot(root)?;
    let text = match before {
        Ok(text) if !text.trim().is_empty() => text,
        _ if !disk.installed => return Ok(Snapshot { disk, status: None }),
        _ => {
            return Err(
                "installed irlumed unit cannot be observed; store selection is unknown".into(),
            )
        }
    };
    generation(&text)?;
    let Some(pid) = main_pid(&text)? else {
        if disk.installed && property(&text, "LoadState") == Some("not-found") {
            return Err("irlumed disk unit is not loaded by the service manager".into());
        }
        // A manager-wide assignment is another source even without
        // PassEnvironment=. Do not silently turn it into a default store.
        let global = show(&["show-environment"])?;
        for var in super::unit_environment::STORE_VARS {
            if super::global_env_in(&global, var)
                .map_err(|_| "unresolved global environment")?
                .is_some()
            {
                return Err(format!(
                    "{var} is set in the manager environment; store selection is unresolved"
                ));
            }
        }
        return finish_capture(root, disk, text, &mut show);
    };
    let dir = super::open_dir(&proc_root.join(pid.to_string()))
        .map_err(|_| "cannot read the running irlumed process")?;
    if dir
        .metadata()
        .map_err(|_| "cannot inspect daemon owner")?
        .uid()
        != owner
    {
        return Err("irlumed process is not root-owned".into());
    }
    let pinned = super::fd_path(&dir).map_err(|_| "cannot pin daemon process")?;
    if std::fs::read_to_string(pinned.join("comm"))
        .map_err(|_| "cannot identify irlumed")?
        .trim()
        != "irlumed"
    {
        return Err("unit MainPID does not identify irlumed".into());
    }
    // Do not retain or print other environment variables: they can be secrets.
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(pinned.join("environ"))
        .map_err(|_| "cannot read daemon environment")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read daemon environment")?;
    if bytes.len() > 1024 * 1024 {
        return Err("daemon environment exceeds observation limit".into());
    }
    for (index, var) in super::unit_environment::STORE_VARS.iter().enumerate() {
        let value = &disk.values[index];
        agree(value, process_value(&bytes, var)?)?;
        let selected = match value {
            Some(path) => path.clone(),
            None => {
                let observed = process_value(&bytes, "IRLUME_STATE_DIR")?;
                let state = irlume_common::state_dir_from_override(
                    observed.as_deref().map(Path::as_os_str),
                );
                match *var {
                    "IRLUME_STATE_DIR" => state,
                    "IRLUME_KEYRING_DIR" => state.join("keyring"),
                    "IRLUME_RECOVERY_DIR" => state.join("recovery"),
                    "IRLUME_TEMPLATE_KEY_DIR" => state.join("template-keys"),
                    _ => return Err("unknown daemon directory variable".into()),
                }
            }
        };
        {
            // A bind mount/PrivateTmp can make an identical absolute name designate
            // another store. Compare the closest existing ancestor in both views.
            let mut path = selected.as_path();
            loop {
                match (
                    std::fs::metadata(path),
                    std::fs::metadata(
                        pinned
                            .join("root")
                            .join(path.strip_prefix("/").map_err(|_| "relative store")?),
                    ),
                ) {
                    (Ok(a), Ok(b)) if (a.dev(), a.ino()) == (b.dev(), b.ino()) => break,
                    (Err(a), Err(b))
                        if a.kind() == std::io::ErrorKind::NotFound
                            && b.kind() == std::io::ErrorKind::NotFound =>
                    {
                        path = path.parent().ok_or("store filesystem cannot be resolved")?;
                    }
                    _ => {
                        return Err(
                            "daemon store is not the same path in the uninstall filesystem".into(),
                        )
                    }
                }
            }
        }
    }
    finish_capture(root, disk, text, &mut show)
}

fn finish_capture(
    root: &Path,
    disk: super::unit_environment::Disk,
    text: String,
    show: &mut impl FnMut(&[&str]) -> Result<String, String>,
) -> Result<Snapshot, String> {
    if disk != super::unit_environment::snapshot(root)? || show(PROPERTIES)? != text {
        return Err("irlumed changed during environment observation".into());
    }
    Ok(Snapshot {
        disk,
        status: Some(text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_review_generation_switch_between_directory_reads_refuses() {
        let root =
            std::env::temp_dir().join(format!("irlume-review-generation-{}", std::process::id()));
        let pid = root.join("42");
        std::fs::create_dir_all(&pid).unwrap();
        let uid = std::fs::metadata(&pid).unwrap().uid();
        std::fs::write(pid.join("comm"), "irlumed\n").unwrap();
        std::os::unix::fs::symlink("/", pid.join("root")).unwrap();
        let a = root.join("a");
        let b = root.join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let status = "LoadState=loaded\nActiveState=active\nMainPID=42\nNeedDaemonReload=no\nRootDirectory=\nRootImage=\nExecMainPID=42\nExecMainStartTimestampMonotonic=100\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        std::fs::write(
            pid.join("environ"),
            format!("IRLUME_STATE_DIR={}\0", a.display()),
        )
        .unwrap();
        let unit = root.join("etc/systemd/system/irlumed.service");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, "[Service]\nEnvironmentFile=/daemon.env\n").unwrap();
        let envfile = root.join("daemon.env");
        std::fs::write(&envfile, format!("IRLUME_STATE_DIR={}\n", a.display())).unwrap();
        let retained =
            super::super::retention::Retention::begin(&root.join("retain"), uid).unwrap();
        let mut observations = 0;
        let result = capture_with(&root, &root, uid, |_| {
            observations += 1;
            if observations == 1 {
                Ok(status.into())
            } else {
                std::fs::write(
                    pid.join("environ"),
                    format!("IRLUME_STATE_DIR={}\0", b.display()),
                )
                .unwrap();
                std::fs::write(&envfile, format!("IRLUME_STATE_DIR={}\n", b.display())).unwrap();
                Ok(status.replace(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ))
            }
        });
        assert!(
            result.is_err(),
            "one snapshot must refuse a generation switch"
        );
        drop(retained);
        let retry = super::super::retention::Retention::begin(&root.join("retain"), uid).unwrap();
        assert!(
            retry.require_fresh().is_err(),
            "a retry must not forget generation A"
        );
        let now_b = capture_with(&root, &root, uid, |_| {
            Ok(status.replace(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ))
        })
        .unwrap();
        assert_eq!(now_b.disk.values[0], Some(b));
        assert!(now_b.disk.values[1..].iter().all(Option::is_none));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn environment_running_snapshot_cannot_be_replaced_by_current_disk() {
        let old =
            process_value(b"LANG=C\0IRLUME_KEYRING_DIR=/old\0", "IRLUME_KEYRING_DIR").unwrap();
        assert!(agree(&Some("/new".into()), old.clone()).is_err());
        assert!(agree(&Some("/old".into()), old).is_ok());
        assert!(process_value(b"IRLUME_KEYRING_DIR=relative\0", "IRLUME_KEYRING_DIR").is_err());
        assert!(process_value(
            b"IRLUME_KEYRING_DIR=/a\0IRLUME_KEYRING_DIR=/b\0",
            "IRLUME_KEYRING_DIR"
        )
        .is_err());
    }

    #[test]
    fn environment_manager_requires_stable_loaded_service() {
        let active = "LoadState=loaded\nActiveState=active\nMainPID=42\nNeedDaemonReload=no\nRootDirectory=\nRootImage=\nExecMainPID=42\nExecMainStartTimestampMonotonic=100\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        assert_eq!(main_pid(active).unwrap(), Some(42));
        assert!(main_pid(&active.replace("NeedDaemonReload=no", "NeedDaemonReload=yes")).is_err());
        assert!(main_pid(&active.replace("MainPID=42", "MainPID=0")).is_err());
        assert!(main_pid(&active.replace("RootDirectory=\n", "RootDirectory=/other\n")).is_err());
        assert!(main_pid("").is_err());
        assert!(main_pid(&active.replace("LoadState=loaded", "LoadState=not-found")).is_err());
    }

    #[test]
    fn environment_process_observation_is_pinned_and_fails_closed() {
        let root = std::env::temp_dir().join(format!("irlume-env-process-{}", std::process::id()));
        let proc = root.join("proc");
        let pid = proc.join("42");
        std::fs::create_dir_all(&pid).unwrap();
        let owner = std::fs::metadata(&pid).unwrap().uid();
        std::fs::write(pid.join("comm"), "irlumed\n").unwrap();
        std::os::unix::fs::symlink("/", pid.join("root")).unwrap();
        let store = root.join("keys");
        std::fs::create_dir(&store).unwrap();
        let active = "LoadState=loaded\nActiveState=active\nMainPID=42\nNeedDaemonReload=no\nRootDirectory=\nRootImage=\nExecMainPID=42\nExecMainStartTimestampMonotonic=100\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        std::fs::write(
            pid.join("environ"),
            format!("IRLUME_KEYRING_DIR={}\0", store.display()),
        )
        .unwrap();
        let unit = root.join("etc/systemd/system/irlumed.service");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironment=IRLUME_KEYRING_DIR={}\n",
                store.display()
            ),
        )
        .unwrap();
        let run = || capture_with(&root, &proc, owner, |_| Ok(active.into()));
        let snapshot = run().unwrap();
        assert_eq!(snapshot.disk.values[1], Some(store));
        let stopped = active
            .replace("ActiveState=active", "ActiveState=inactive")
            .replace("MainPID=42\n", "MainPID=0\n");
        // Preserve ExecMainPID: the broad replacement above also matches its suffix.
        let stopped = stopped.replace("ExecMainPID=0", "ExecMainPID=42");
        assert!(snapshot.check_stopped(&stopped).is_ok());
        assert!(snapshot
            .still_quiescent_with(|args| {
                Ok(if args == PROPERTIES {
                    stopped.clone()
                } else {
                    "LoadState=loaded\nActiveState=inactive\n".into()
                })
            })
            .is_ok());
        assert!(
            snapshot
                .still_quiescent_with(|args| {
                    Ok(if args == PROPERTIES {
                        stopped.clone()
                    } else if args.contains(&"irlume-reconcile.path") {
                        "LoadState=loaded\nActiveState=active\n".into()
                    } else {
                        "LoadState=loaded\nActiveState=inactive\n".into()
                    })
                })
                .is_err(),
            "automatic reconciliation must not reactivate the daemon during cleanup"
        );
        assert!(snapshot
            .check_stopped(&stopped.replace(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ))
            .is_err());
        assert!(snapshot.check_stopped(active).is_err());
        assert!(capture_with(&root, &proc, owner.wrapping_add(1), |_| Ok(active.into())).is_err());
        std::fs::write(pid.join("environ"), "IRLUME_KEYRING_DIR=/old\0").unwrap();
        assert!(run().is_err());
        std::fs::remove_file(pid.join("environ")).unwrap();
        std::fs::create_dir(pid.join("environ")).unwrap();
        assert!(
            run().is_err(),
            "unreadable process environment is not a default"
        );
        assert!(capture_with(&root, &proc, owner, |_| Err("unavailable".into())).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
