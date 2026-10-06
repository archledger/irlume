// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The production [`Source`]: the service manager's own view of the unit, the
//! producer's receipt under LightDM's runtime root, and the target's lifetime
//! through a process descriptor.
//!
//! Every fact here is one an unprivileged `login plan` and a root
//! `login apply` read identically, and none comes from `/proc`:
//!
//! - `systemctl show` answers unit properties to every client: read access to
//!   the manager is "generally granted to all clients"
//!   (org.freedesktop.systemd1(5)). `InvocationID` prints as the 32 lowercase
//!   hex digits of its 16 bytes and `ExecMainStartTimestampMonotonic` as
//!   decimal microseconds (systemd `src/shared/bus-print-properties.c`).
//! - The receipt is a root-owned regular file in the root-owned, world-readable
//!   runtime root the view preparation already creates, so both callers read
//!   the same bytes and only root can write them.
//! - `pidfd_open(2)` has no permission check and does not consult procfs, so
//!   `hidepid` cannot hide the target from it. The descriptor polls readable
//!   once the process has exited, zombie included.
//!
//! The lifetime check is sound only between the verdict machine's two manager
//! samples. The manager is the main process's parent or reaper, so its PID
//! cannot be reused before the manager reaps it, and reaping changes
//! `MainPID`. Both samples naming the same invocation, PID and monotonic start
//! therefore pin the descriptor opened between them to that launch.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::{AbsenceProof, ManagerObservation, Receipt, Source, LIGHTDM_UNIT};

/// The receipt's name inside LightDM's runtime root.
pub(crate) const RECEIPT_NAME: &str = "managed-start.json";

/// A receipt is a few hundred bytes; anything near this is not one.
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

/// One `systemctl show` call, bounded so a stalled manager cannot hang a plan.
const SHOW_DEADLINE: Duration = Duration::from_secs(2);

/// Properties requested from the manager. It prints them in its own order.
const PROPERTIES: [&str; 5] = [
    "LoadState",
    "ActiveState",
    "MainPID",
    "InvocationID",
    "ExecMainStartTimestampMonotonic",
];

type Show = fn(&str) -> Result<String, String>;

/// The production source for one unit.
pub(crate) struct SystemSource {
    unit: &'static str,
    runtime_root: PathBuf,
    trusted_uid: u32,
    show: Show,
}

impl SystemSource {
    /// The managed LightDM unit, its runtime root and the real manager.
    pub(crate) fn lightdm() -> Self {
        SystemSource {
            unit: LIGHTDM_UNIT,
            runtime_root: PathBuf::from(super::super::super::lightdm_view::RUN),
            trusted_uid: 0,
            show: systemctl_show,
        }
    }
}

impl Source for SystemSource {
    fn observe_manager(&self) -> Option<ManagerObservation> {
        let text = (self.show)(self.unit).ok()?;
        parse_manager(self.unit, &text)
    }

    fn read_receipt(&self) -> Option<Result<Receipt, String>> {
        read_receipt(&self.runtime_root, self.trusted_uid)
    }

    fn target_alive(&self, observation: &ManagerObservation) -> bool {
        process_alive(observation.main_pid)
    }

    /// No qualified startup authority exists yet: an inactive or missing unit
    /// never proves that no remote-serving LightDM runs on this machine.
    fn absence_proof(&self) -> Option<AbsenceProof> {
        None
    }
}

fn systemctl_show(unit: &str) -> Result<String, String> {
    let mut command = Command::new("systemctl");
    command.args(["show", unit, "--no-pager"]);
    for property in PROPERTIES {
        command.args(["-p", property]);
    }
    let out = irlume_common::process::output_until(&mut command, Instant::now() + SHOW_DEADLINE)
        .map_err(|e| format!("systemctl show {unit}: {e}"))?;
    if !out.status.success() {
        return Err(format!("systemctl show {unit} failed"));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("systemctl show {unit}: not UTF-8"))
}

/// Read one sample of the manager's view of `unit` from `systemctl show`
/// output. `None` when the answer is incomplete, duplicated, malformed or
/// describes a unit in transition: only a settled state is evidence.
pub(crate) fn parse_manager(unit: &str, text: &str) -> Option<ManagerObservation> {
    let mut values: [Option<&str>; 5] = [None; 5];
    for line in text.lines() {
        let (name, value) = line.split_once('=')?;
        let slot = PROPERTIES.iter().position(|property| *property == name)?;
        if values[slot].replace(value).is_some() {
            return None;
        }
    }
    let [Some(load), Some(active), Some(pid), Some(invocation), Some(start)] = values else {
        return None;
    };
    let main_pid = u32::try_from(decimal(pid)?).ok()?;
    let exec_start_monotonic_us = decimal(start)?;
    let stopped = matches!(active, "inactive" | "failed");
    match load {
        "loaded" => {}
        // A masked unit can keep running; only a stopped one is settled.
        "not-found" | "masked" if stopped => {}
        _ => return None,
    }
    let active = match (active, main_pid) {
        ("active", _) => true,
        (_, 0) if stopped => false,
        _ => return None,
    };
    Some(ManagerObservation {
        unit: unit.into(),
        invocation_id: invocation.into(),
        main_pid,
        exec_start_monotonic_us,
        active,
    })
}

/// Plain decimal digits only: no sign, space or unit suffix.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Read and validate the producer's receipt under `runtime_root`. `None` when
/// no receipt exists; an untrusted, oversized, special or unparsable record is
/// an error, never an absent one.
pub(crate) fn read_receipt(
    runtime_root: &Path,
    trusted_uid: u32,
) -> Option<Result<Receipt, String>> {
    let root = match std::fs::symlink_metadata(runtime_root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("{}: {e}", runtime_root.display()))),
    };
    if let Err(e) = trusted(&root, trusted_uid, true) {
        return Some(Err(format!("{}: {e}", runtime_root.display())));
    }
    let path = runtime_root.join(RECEIPT_NAME);
    // No symlink, no wait on a FIFO, no controlling terminal: the type and
    // owner are checked on the open descriptor before any byte is read.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("{}: {e}", path.display()))),
    };
    Some(read_trusted(file, &path, trusted_uid).and_then(|text| Receipt::from_json(&text)))
}

fn read_trusted(file: File, path: &Path, trusted_uid: u32) -> Result<String, String> {
    let meta = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    trusted(&meta, trusted_uid, false).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_RECEIPT_BYTES {
        return Err(format!("{}: receipt too large", path.display()));
    }
    let mut text = String::new();
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if text.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(format!("{}: receipt too large", path.display()));
    }
    Ok(text)
}

/// Owned by the trusted user and writable by nobody else, of the expected type.
fn trusted(meta: &Metadata, uid: u32, directory: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let kind = if directory {
        meta.is_dir()
    } else {
        meta.is_file()
    };
    if meta.uid() != uid || meta.mode() & 0o022 != 0 || !kind {
        return Err(if directory {
            "not a trusted runtime directory".into()
        } else {
            "not a trusted regular receipt".into()
        });
    }
    Ok(())
}

/// Whether `pid` names a process that has not exited, judged through a
/// process descriptor rather than `/proc`. A zombie counts as exited: its
/// descriptor already polls readable.
pub(crate) fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: pidfd_open takes a PID and flags by value and returns a new
    // descriptor or -1; no memory is shared with the kernel.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let Ok(raw) = libc::c_int::try_from(raw) else {
        return false;
    };
    if raw < 0 {
        return false;
    }
    // SAFETY: the kernel just returned this descriptor and nothing else owns
    // it; OwnedFd closes it exactly once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd that outlives the call, and a zero timeout.
    let ready = unsafe { libc::poll(&mut poll, 1, 0) };
    ready == 0
}

#[cfg(test)]
mod tests {
    use super::super::{evaluate, Verdict};
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const INVOCATION: &str = "0cd639d2e7c04ddea8c9f1b508f68700";

    fn running(pid: u32) -> String {
        format!(
            "LoadState=loaded\nActiveState=active\nMainPID={pid}\n\
             InvocationID={INVOCATION}\nExecMainStartTimestampMonotonic=15720777\n"
        )
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "irlume-managed-start-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Dir(path)
        }

        fn receipt(&self, text: &str, mode: u32) -> PathBuf {
            let path = self.0.join(RECEIPT_NAME);
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn receipt_json(pid: u32, xdmcp: bool) -> String {
        format!(
            "{{\"schema\":1,\"unit\":\"lightdm.service\",\"invocation_id\":\"{INVOCATION}\",\
             \"main_pid\":{pid},\"exec_start_monotonic_us\":15720777,\
             \"target_digest\":\"{}\",\"config_generation\":\"g-1\",\
             \"xdmcp_enabled\":{xdmcp},\"vnc_enabled\":false,\
             \"pam_generation_roots\":[\"/run/irlume-lightdm/pam.d\"],\
             \"producer_version\":\"1\"}}",
            "c".repeat(64)
        )
    }

    #[test]
    fn a_running_unit_is_observed_with_its_launch_identity() {
        let seen = parse_manager(LIGHTDM_UNIT, &running(2055)).expect("observed");
        assert_eq!(
            seen,
            ManagerObservation {
                unit: LIGHTDM_UNIT.into(),
                invocation_id: INVOCATION.into(),
                main_pid: 2055,
                exec_start_monotonic_us: 15_720_777,
                active: true,
            }
        );
    }

    #[test]
    fn property_order_does_not_matter() {
        let reordered = "ExecMainStartTimestampMonotonic=15720777\nMainPID=2055\n\
                         InvocationID=0cd639d2e7c04ddea8c9f1b508f68700\n\
                         ActiveState=active\nLoadState=loaded\n";
        let reordered = parse_manager(LIGHTDM_UNIT, reordered).expect("observed");
        assert_eq!(Some(reordered), parse_manager(LIGHTDM_UNIT, &running(2055)));
    }

    #[test]
    fn a_missing_or_masked_stopped_unit_is_an_inactive_observation() {
        for load in ["not-found", "masked", "loaded"] {
            for active in ["inactive", "failed"] {
                let text = format!(
                    "LoadState={load}\nActiveState={active}\nMainPID=0\nInvocationID=\n\
                     ExecMainStartTimestampMonotonic=0\n"
                );
                let seen = parse_manager(LIGHTDM_UNIT, &text).expect("observed");
                assert!(!seen.active, "{load}/{active}");
                assert_eq!(seen.main_pid, 0);
            }
        }
    }

    #[test]
    fn transitional_or_contradictory_states_are_not_evidence() {
        for active in [
            "activating",
            "deactivating",
            "reloading",
            "refreshing",
            "maintenance",
        ] {
            let text =
                running(2055).replace("ActiveState=active", &format!("ActiveState={active}"));
            assert_eq!(parse_manager(LIGHTDM_UNIT, &text), None, "{active}");
        }
        // An inactive unit still holding a main process is not settled.
        let text = running(2055).replace("ActiveState=active", "ActiveState=inactive");
        assert_eq!(parse_manager(LIGHTDM_UNIT, &text), None);
        // A load state other than loaded, not-found or masked is not trusted.
        for load in ["error", "bad-setting", "stub", "merged"] {
            let text = running(2055).replace("LoadState=loaded", &format!("LoadState={load}"));
            assert_eq!(parse_manager(LIGHTDM_UNIT, &text), None, "{load}");
        }
    }

    #[test]
    fn incomplete_duplicated_or_malformed_answers_are_not_evidence() {
        let base = running(2055);
        let cases = [
            base.replace("MainPID=2055\n", ""),
            base.replace("InvocationID=", "InvocationId="),
            format!("{base}MainPID=2056\n"),
            base.replace("MainPID=2055", "MainPID=-1"),
            base.replace("MainPID=2055", "MainPID=4294967296"),
            base.replace(
                "ExecMainStartTimestampMonotonic=15720777",
                "ExecMainStartTimestampMonotonic=Mon 2026-10-06",
            ),
            base.replace("LoadState=loaded", "LoadState=loaded extra"),
            String::new(),
        ];
        for text in cases {
            assert_eq!(
                parse_manager(LIGHTDM_UNIT, &text),
                None,
                "accepted: {text:?}"
            );
        }
    }

    #[test]
    fn a_trusted_receipt_is_read_and_validated() {
        let dir = Dir::new("trusted");
        dir.receipt(&receipt_json(4211, false), 0o644);
        let receipt = read_receipt(&dir.0, uid())
            .expect("present")
            .expect("valid");
        assert_eq!(
            receipt,
            Receipt::from_json(&receipt_json(4211, false)).unwrap()
        );
    }

    #[test]
    fn no_receipt_file_is_no_receipt() {
        let dir = Dir::new("none");
        assert!(read_receipt(&dir.0, uid()).is_none());
    }

    #[test]
    fn a_receipt_another_user_could_write_is_refused() {
        for mode in [0o664, 0o646, 0o666] {
            let dir = Dir::new("writable");
            dir.receipt(&receipt_json(4211, false), mode);
            assert!(
                matches!(read_receipt(&dir.0, uid()), Some(Err(_))),
                "mode {mode:o} accepted"
            );
        }
    }

    #[test]
    fn a_receipt_owned_by_someone_else_is_refused() {
        let dir = Dir::new("owner");
        dir.receipt(&receipt_json(4211, false), 0o644);
        assert!(matches!(
            read_receipt(&dir.0, uid().wrapping_add(1)),
            Some(Err(_))
        ));
    }

    #[test]
    fn a_runtime_root_another_user_could_change_is_refused() {
        let dir = Dir::new("root-writable");
        dir.receipt(&receipt_json(4211, false), 0o644);
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(read_receipt(&dir.0, uid()), Some(Err(_))));
    }

    #[test]
    fn a_symlinked_receipt_is_refused_not_followed() {
        let dir = Dir::new("symlink");
        let elsewhere = dir.0.join("elsewhere.json");
        std::fs::write(&elsewhere, receipt_json(4211, false)).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&elsewhere, dir.0.join(RECEIPT_NAME)).unwrap();
        assert!(matches!(read_receipt(&dir.0, uid()), Some(Err(_))));
    }

    #[test]
    fn a_fifo_receipt_is_refused_without_waiting_for_a_writer() {
        let dir = Dir::new("fifo");
        let path = dir.0.join(RECEIPT_NAME);
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let started = Instant::now();
        assert!(matches!(read_receipt(&dir.0, uid()), Some(Err(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn an_oversized_or_unparsable_receipt_is_refused() {
        let dir = Dir::new("oversized");
        dir.receipt(&" ".repeat(MAX_RECEIPT_BYTES as usize + 1), 0o644);
        assert!(matches!(read_receipt(&dir.0, uid()), Some(Err(_))));
        let dir = Dir::new("garbage");
        dir.receipt("{\"schema\":1}", 0o644);
        assert!(matches!(read_receipt(&dir.0, uid()), Some(Err(_))));
    }

    #[test]
    fn a_live_process_is_alive_and_an_exited_one_is_not() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        assert!(process_alive(child.id()), "running child");
        child.kill().unwrap();
        // Before the reap the child is a zombie: exited, PID still held.
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_alive(child.id()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_alive(child.id()), "zombie child");
        child.wait().unwrap();
        assert!(!process_alive(child.id()), "reaped child");
    }

    #[test]
    fn impossible_pids_are_never_alive() {
        assert!(!process_alive(0));
        assert!(!process_alive(u32::MAX));
    }

    #[test]
    fn a_root_owned_process_is_observable_without_privilege() {
        // PID 1 belongs to root; pidfd_open has no permission check.
        assert!(process_alive(1));
    }

    /// The whole production path with only the manager scripted: a real
    /// receipt file, a real process descriptor and the verdict machine.
    #[test]
    fn the_production_source_verifies_a_live_matching_launch() {
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let mut child = scopeguard_child(child);
        let dir = Dir::new("verdict");
        dir.receipt(&receipt_json(child.0.id(), false), 0o644);
        let source = scripted(&dir.0, child.0.id());
        assert_eq!(
            evaluate(&source),
            Verdict::VerifiedOff {
                invocation_id: INVOCATION.into(),
                config_generation: "g-1".into()
            }
        );
        dir.receipt(&receipt_json(child.0.id(), true), 0o644);
        assert!(matches!(evaluate(&source), Verdict::RemoteOn { .. }));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("target lifetime unconfirmed".into())
        );
    }

    #[test]
    fn the_production_source_never_turns_a_stopped_unit_into_absence() {
        let dir = Dir::new("stopped");
        let source = SystemSource {
            unit: LIGHTDM_UNIT,
            runtime_root: dir.0.clone(),
            trusted_uid: uid(),
            show: |_| {
                Ok(
                    "LoadState=not-found\nActiveState=inactive\nMainPID=0\nInvocationID=\n\
                    ExecMainStartTimestampMonotonic=0\n"
                        .into(),
                )
            },
        };
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("lightdm.service is inactive".into())
        );
    }

    struct Reaped(std::process::Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn scopeguard_child(child: std::process::Child) -> Reaped {
        Reaped(child)
    }

    thread_local! {
        static SCRIPTED_PID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn scripted(root: &Path, pid: u32) -> SystemSource {
        SCRIPTED_PID.with(|cell| cell.set(pid));
        SystemSource {
            unit: LIGHTDM_UNIT,
            runtime_root: root.to_path_buf(),
            trusted_uid: uid(),
            show: |_| Ok(running(SCRIPTED_PID.with(std::cell::Cell::get))),
        }
    }
}
