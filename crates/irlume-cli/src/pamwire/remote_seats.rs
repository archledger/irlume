// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! LightDM login screens that a remote user reaches.
//!
//! LightDM's XDMCP server gives a remote X server a login screen, and its VNC
//! server gives one to each VNC client. Both authenticate through the same
//! `lightdm` PAM service as the local screen, and neither sets PAM_RHOST, so
//! pam_irlume there cannot tell a remote login screen from the local one: a
//! remote user picks the owner's account, presses Enter, and the camera at
//! this machine answers for whoever sits at it. An Xvnc seat's display is
//! `:N` like a local one, so only LightDM's configuration shows it. While
//! either server is on, irlume keeps its face and fingerprint lines out of
//! `lightdm` and leaves only its `reseal` lines, which never reach the camera
//! and are what hands a GNOME keyring token over. Both servers are off by
//! default.
//!
//! A running LightDM keeps the configuration it started with, so the face
//! lines also stay out while the running LightDM started before its
//! configuration last changed: until it restarts, it may still serve remote
//! login screens a file no longer turns on.

mod evidence;

use super::autologin::{assignments, on, LIGHTDM_DROP_IN_DIRS, LIGHTDM_MAIN};
use evidence::{files as lightdm_files, read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// LightDM's remote servers that are on (`XDMCP`, `VNC`), each with the file
/// that turned it on, read in LightDM's order with the last `enabled=` of a
/// section winning. An error names a file that exists and could not be read.
pub(super) fn lightdm_remote_servers() -> Result<Vec<(&'static str, PathBuf)>, String> {
    lightdm_remote_servers_in(Path::new("/"))
}

fn lightdm_remote_servers_in(root: &Path) -> Result<Vec<(&'static str, PathBuf)>, String> {
    let mut xdmcp: Option<(bool, PathBuf)> = None;
    let mut vnc: Option<(bool, PathBuf)> = None;
    for path in lightdm_files(root)? {
        let Some(text) = read(&path)? else { continue };
        for (section, key, value) in
            assignments(&text).map_err(|e| format!("{}: {e}", path.display()))?
        {
            let slot = match section.as_str() {
                "XDMCPServer" => &mut xdmcp,
                "VNCServer" => &mut vnc,
                _ => continue,
            };
            if key == "enabled" {
                *slot = Some((on(&value), path.clone()));
            }
        }
    }
    Ok([("XDMCP", xdmcp), ("VNC", vnc)]
        .into_iter()
        .filter_map(|(name, state)| match state {
            Some((true, path)) => Some((name, path)),
            _ => None,
        })
        .collect())
}

/// Whether `service` is one this rule governs.
pub(super) fn governs(service: &str) -> bool {
    service == "lightdm"
}

/// Why irlume keeps its face and fingerprint lines out of `service` whatever
/// the configuration wants, or `None`. Only `lightdm` has such a reason. A
/// LightDM configuration that cannot be read counts as one: whether it serves
/// remote login screens is then unknown, and the password is the floor.
pub(super) fn face_blocked(service: &str) -> Option<String> {
    reason_with(
        service,
        lightdm_remote_servers,
        running_lightdm_predates_its_configuration,
    )
}

fn reason_with(
    service: &str,
    servers: impl FnOnce() -> Result<Vec<(&'static str, PathBuf)>, String>,
    stale: impl FnOnce() -> Result<bool, String>,
) -> Option<String> {
    if !governs(service) {
        return None;
    }
    match servers() {
        Ok(on) if on.is_empty() => match stale() {
            Ok(false) => None,
            Ok(true) => Some(
                "LightDM's configuration changed after the running LightDM started, and \
                 until it restarts it may still serve remote login screens"
                    .to_string(),
            ),
            Err(e) => Some(format!(
                "irlume could not tell whether the running LightDM uses its current \
                 configuration ({e})"
            )),
        },
        Ok(on) => {
            let which: Vec<String> = on
                .iter()
                .map(|(name, path)| format!("{name} ({})", path.display()))
                .collect();
            Some(format!(
                "LightDM's {} server is on, so a remote user can reach this login screen \
                 and the camera here would answer for whoever is at it",
                which.join(" and ")
            ))
        }
        Err(e) => Some(format!(
            "irlume could not read {e} to check whether LightDM serves remote login screens"
        )),
    }
}

/// Whether a running LightDM started before its configuration last changed.
/// No LightDM running, or no configuration-change evidence, is "no".
fn running_lightdm_predates_its_configuration() -> Result<bool, String> {
    running_lightdm_predates_in(Path::new("/"), Path::new("/proc"))
}

fn running_lightdm_predates_in(root: &Path, proc: &Path) -> Result<bool, String> {
    // Retain the existing wall-clock gate. Clock-step-independent positive
    // proof remains separate work; current unit timestamps alone cannot fix it.
    let changed = latest_change(root)?;
    Ok(predates(lightdm_started_in(proc)?, changed))
}

fn predates(started: Option<SystemTime>, changed: Option<SystemTime>) -> bool {
    matches!((started, changed), (Some(started), Some(changed)) if started < changed)
}

/// When LightDM's configuration last changed: the newest change time of the
/// files it reads, of the directories holding them and of those directories'
/// parents (a deleted file or drop-in directory leaves no time of its own but
/// changes its parent's). Both the modification time and the inode change
/// time count: an overwrite that puts the old mtime back still moves the
/// ctime, which ordinary userspace cannot set.
fn latest_change(root: &Path) -> Result<Option<SystemTime>, String> {
    // Each drop-in directory and its parent, which is LightDM's own
    // (`.../lightdm`), and the main file's directory. Only when the main
    // directory is missing do we consult its parent (/etc): its deletion
    // changed that parent, but unrelated /etc changes must not count while
    // the LightDM directory still exists.
    let mut dirs: Vec<PathBuf> = Vec::new();
    let main_dir = Path::new(LIGHTDM_MAIN).parent().map(|dir| root.join(dir));
    for dir in LIGHTDM_DROP_IN_DIRS.iter().map(Path::new) {
        for path in [Some(dir), dir.parent()].into_iter().flatten() {
            let path = root.join(path);
            if !dirs.contains(&path) {
                dirs.push(path);
            }
        }
    }
    if let Some(main_dir) = &main_dir {
        if !dirs.contains(main_dir) {
            dirs.push(main_dir.clone());
        }
    }
    let mut latest = None;
    for mut path in lightdm_files(root)?.into_iter().chain(dirs) {
        let change = match evidence::change_time(&path)? {
            None if Some(&path) == main_dir.as_ref() => {
                path.pop();
                evidence::change_time(&path)?
            }
            result => result,
        };
        latest = latest.max(change);
    }
    Ok(latest)
}

/// The oldest LightDM's estimated wall start, retaining the existing gate's
/// clock domain. Explicit config and unreadable process evidence refuse.
/// Privilege-independent and clock-step-independent proof remain unresolved.
fn lightdm_started_in(proc: &Path) -> Result<Option<SystemTime>, String> {
    let stat =
        evidence::read_bytes(&proc.join("stat"), 1024 * 1024)?.ok_or("/proc/stat unavailable")?;
    let stat = std::str::from_utf8(&stat).map_err(|_| "invalid /proc/stat")?;
    let boot = stat
        .lines()
        .find_map(|line| line.strip_prefix("btime ")?.trim().parse::<u64>().ok())
        .ok_or("/proc/stat has no boot time")?;
    // PID 1 is root's; an ordinary user who cannot read its stat cannot see
    // other users' processes either.
    evidence::read_bytes(&proc.join("1/stat"), 8192)?
        .filter(|bytes| !bytes.is_empty())
        .ok_or("/proc/1/stat unavailable; other users' processes may be hidden")?;
    // SAFETY: sysconf takes no pointers and only reads a system constant.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|hz| *hz > 0)
        .ok_or("no clock tick rate")?;
    let entries = std::fs::read_dir(proc).map_err(|e| format!("/proc: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut oldest = None;
    for (count, entry) in entries.enumerate() {
        if count >= 65536 || std::time::Instant::now() >= deadline {
            return Err("LightDM process inspection limit".into());
        }
        let entry = entry.map_err(|e| format!("/proc: {e}"))?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let Some(stat) = evidence::read_bytes(&entry.path().join("stat"), 8192)? else {
            continue; // ENOENT: the process exited, not a permission failure.
        };
        // Linux comm is bytes, not UTF-8. Unrelated process names must not
        // invalidate an otherwise usable LightDM observation.
        let open = stat
            .iter()
            .position(|b| *b == b'(')
            .ok_or("invalid process stat")?;
        let close = stat
            .iter()
            .rposition(|b| *b == b')')
            .ok_or("invalid process stat")?;
        let name = stat.get(open + 1..close).ok_or("invalid process name")?;
        if name != b"lightdm" {
            continue;
        }
        let stat = std::str::from_utf8(&stat).map_err(|_| "invalid LightDM process stat")?;
        let ticks = lightdm_start_ticks(stat).ok_or("invalid LightDM process start")?;
        let argv = evidence::read_bytes(&entry.path().join("cmdline"), 65536)?
            .ok_or("LightDM command line disappeared during inspection")?;
        require_standard_command_line(&argv)?;
        oldest = Some(oldest.map_or(ticks, |old: u64| old.min(ticks)));
    }
    oldest
        .map(|ticks| {
            let millis = ticks
                .checked_mul(1000)
                .ok_or("LightDM start time overflow")?
                / hz;
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(boot))
                .and_then(|start| start.checked_add(Duration::from_millis(millis)))
                .ok_or_else(|| "LightDM start time overflow".into())
        })
        .transpose()
}

/// Explicit config changes the file set, even when it names the default main
/// file. Refuse rather than combine it with the wrong admin drop-ins. Unknown
/// or truncated argv also cannot establish the implicit standard invocation.
/// This is a conservative flag check, not a GOption parser: an option-looking
/// argument value can also trigger refusal.
fn require_standard_command_line(argv: &[u8]) -> Result<(), String> {
    if argv.is_empty() || argv.last() != Some(&0) {
        return Err("LightDM command line is unavailable or truncated".into());
    }
    let mut args = argv[..argv.len() - 1].split(|b| *b == 0);
    if args.next().is_none_or(|arg| arg.is_empty()) {
        return Err("LightDM command line has no executable".into());
    }
    for arg in args {
        if arg == b"--config"
            || arg.starts_with(b"--config=")
            || (arg.starts_with(b"-") && !arg.starts_with(b"--") && arg.contains(&b'c'))
        {
            return Err("LightDM command line may select an explicit -c/--config; standard configuration is not proof of its remote-login settings".into());
        }
    }
    Ok(())
}

/// A `/proc/<pid>/stat` line's start time, in clock ticks after boot, when
/// the process is named `lightdm`. The name sits in parentheses and may hold
/// spaces or parentheses itself, so the fields are counted from the last `)`.
fn lightdm_start_ticks(stat: &str) -> Option<u64> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if stat.get(open + 1..close)? != "lightdm" {
        return None;
    }
    // After the name: state (field 3) ... starttime (field 22).
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Root(PathBuf);

    impl Root {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "irlume-remote-seats-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Root(dir)
        }

        fn put(&self, file: &str, text: &str) -> PathBuf {
            let path = self.0.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }

        fn servers(&self) -> Vec<(&'static str, PathBuf)> {
            lightdm_remote_servers_in(&self.0).unwrap()
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn malformed_gkeyfile_cannot_clear_a_remote_server() {
        let root = Root::new("malformed-gkeyfile");
        root.put(
            "etc/lightdm/lightdm.conf.d/10-remote.conf",
            "[XDMCPServer]\nenabled=true\n",
        );
        for text in [
            "[XDMCPServer]\nenabled=true\n[Seat:*] # comment\nenabled=false\n",
            "[XDMCPServer]\nenabled=false\n[Seat:*] # comment\n",
            "[XDMCPServer]\nenabled=false\nnot an assignment\n",
            "[XDMCPServer]\nenabled=false\n[Seat:*]\r",
        ] {
            let path = root.put("etc/lightdm/lightdm.conf", text);
            let why = reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || Ok(false),
            )
            .expect("malformed main configuration must block the face path");
            assert!(why.contains("could not read"), "{why}");
            assert!(why.contains(path.to_str().unwrap()), "{why}");
            assert!(lightdm_remote_servers_in(&root.0).is_err());
        }
        // Ordinary, valid higher-priority configuration can still turn it off.
        root.put("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        assert_eq!(
            reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || Ok(false)
            ),
            None
        );
        root.put(
            "etc/lightdm/lightdm.conf",
            "[XDMCPServer]\r\nenabled=false\r\n",
        );
        assert_eq!(lightdm_remote_servers_in(&root.0), Ok(Vec::new()));
    }

    #[test]
    fn xdmcp_and_vnc_count_only_when_the_last_word_is_on() {
        let root = Root::new("servers");
        assert!(root.servers().is_empty(), "no configuration");
        // The shipped example: both present and off.
        root.put(
            "etc/lightdm/lightdm.conf",
            "[Seat:*]\n#xserver-allow-tcp=false\n[XDMCPServer]\nenabled=false\nport=177\n\
             [VNCServer]\nenabled=false\ncommand=Xvnc\n",
        );
        assert!(root.servers().is_empty());
        let xdmcp = root.put(
            "etc/lightdm/lightdm.conf.d/50-xdmcp.conf",
            "[XDMCPServer]\nenabled=true\n",
        );
        // The main file is read last, and says off.
        assert!(root.servers().is_empty(), "main file wins");
        let main = root.put(
            "etc/lightdm/lightdm.conf",
            "[XDMCPServer]\nport=177\n[VNCServer]\nenabled=true\n",
        );
        assert_eq!(root.servers(), vec![("XDMCP", xdmcp), ("VNC", main)]);
        // `enabled` elsewhere is someone else's key.
        let root = Root::new("other-sections");
        root.put("etc/lightdm/lightdm.conf", "[Seat:*]\nenabled=true\n");
        assert!(root.servers().is_empty());
    }

    #[test]
    fn only_lightdm_is_blocked_and_only_for_a_reason() {
        let unasked = || -> Result<Vec<(&'static str, PathBuf)>, String> {
            panic!("only lightdm reads the configuration")
        };
        let not_asked = || -> Result<bool, String> { panic!("LightDM's start not asked") };
        let fresh = || Ok(false);
        assert_eq!(reason_with("sddm", unasked, not_asked), None);
        assert_eq!(reason_with("lightdm", || Ok(Vec::new()), fresh), None);
        let xdmcp = || Ok(vec![("XDMCP", PathBuf::from("/etc/lightdm/lightdm.conf"))]);
        let why = reason_with("lightdm", xdmcp, not_asked).expect("xdmcp");
        assert!(
            why.contains("XDMCP (/etc/lightdm/lightdm.conf) server is on"),
            "{why}"
        );
        let why = reason_with(
            "lightdm",
            || Err("/etc/lightdm/lightdm.conf: Permission denied".to_string()),
            not_asked,
        )
        .expect("unreadable");
        assert!(
            why.contains("could not read /etc/lightdm/lightdm.conf"),
            "{why}"
        );
    }

    #[test]
    fn a_running_lightdm_older_than_its_configuration_blocks_face() {
        let off = || Ok(Vec::new());
        let why = reason_with("lightdm", off, || Ok(true)).expect("stale");
        assert!(why.contains("until it restarts"), "{why}");
        assert_eq!(reason_with("lightdm", off, || Ok(false)), None);
        let why = reason_with("lightdm", off, || Err("/proc: denied".into())).expect("unknown");
        assert!(why.contains("could not tell"), "{why}");
    }

    #[test]
    fn a_lightdm_started_before_its_last_change_predates_it() {
        let t = |secs| Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
        assert!(predates(t(100), t(200)));
        assert!(!predates(t(300), t(200)));
        assert!(!predates(None, t(200)), "no LightDM running");
        assert!(!predates(t(100), None), "no configuration");
    }

    #[test]
    fn only_a_process_named_lightdm_has_a_start_time() {
        let stat = |name: &str| {
            format!(
                "1234 ({name}) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5555 1000 10"
            )
        };
        assert_eq!(lightdm_start_ticks(&stat("lightdm")), Some(5555));
        assert_eq!(lightdm_start_ticks(&stat("lightdm-gtk-gre")), None);
        assert_eq!(lightdm_start_ticks(&stat("x) (lightdm")), None);
        assert_eq!(lightdm_start_ticks("garbage"), None);
    }

    #[test]
    fn removing_the_main_configuration_directory_blocks_until_restart() {
        let root = Root::new("removed-main-dir");
        let main = root.put("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=true\n");
        assert_eq!(root.servers(), vec![("XDMCP", main.clone())]);
        // Pin the observed ordering without sleeping for filesystem timestamps.
        let started = SystemTime::now() + Duration::from_secs(60);
        assert!(!predates(Some(started), latest_change(&root.0).unwrap()));
        std::fs::remove_dir_all(main.parent().unwrap()).unwrap();
        let removed = started + Duration::from_secs(60);
        std::fs::File::open(root.0.join("etc"))
            .unwrap()
            .set_modified(removed)
            .unwrap();
        assert!(root.servers().is_empty(), "disk no longer enables XDMCP");
        let changed = latest_change(&root.0).unwrap();
        let why = reason_with(
            "lightdm",
            || lightdm_remote_servers_in(&root.0),
            || Ok(predates(Some(started), changed)),
        )
        .expect("the running daemon may still serve its removed XDMCP configuration");
        assert!(why.contains("until it restarts"), "{why}");
        assert_eq!(changed, Some(removed));
        let restarted = removed + Duration::from_secs(1);
        assert_eq!(
            reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || Ok(predates(Some(restarted), changed)),
            ),
            None,
            "a restart after removal reads the current configuration"
        );
        assert!(!predates(None, changed), "no running daemon");
    }

    #[test]
    fn an_existing_empty_main_directory_does_not_count_unrelated_etc_changes() {
        let root = Root::new("existing-empty-main-dir");
        std::fs::create_dir_all(root.0.join("etc/lightdm")).unwrap();
        let started = SystemTime::now() + Duration::from_secs(60);
        let before = latest_change(&root.0).unwrap();
        root.put("etc/unrelated.conf", "x\n");
        std::fs::File::open(root.0.join("etc"))
            .unwrap()
            .set_modified(started + Duration::from_secs(60))
            .unwrap();
        let changed = latest_change(&root.0).unwrap();
        assert_eq!(
            changed, before,
            "a missing main file is not a missing directory"
        );
        assert_eq!(
            reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || Ok(predates(Some(started), changed)),
            ),
            None
        );
    }

    #[test]
    fn intact_symlink_ignores_unrelated_target_parent_changes_but_not_deletion() {
        use std::os::unix::fs::symlink;
        let root = Root::new("intact-directory-link");
        root.put("srv/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        std::fs::create_dir_all(root.0.join("etc")).unwrap();
        symlink(root.0.join("srv/lightdm"), root.0.join("etc/lightdm")).unwrap();
        let boot = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        root.put("proc/stat", &format!("btime {boot}\n"));
        root.put("proc/1/stat", &process_stat("systemd"));
        root.put("proc/42/stat", &process_stat("lightdm"));
        root.put("proc/42/cmdline", "lightdm\0");
        let reason = || {
            reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || running_lightdm_predates_in(&root.0, &root.0.join("proc")),
            )
        };
        assert_eq!(reason(), None);
        let before = latest_change(&root.0).unwrap();
        root.put("srv/other", "unrelated");
        let changed = SystemTime::UNIX_EPOCH + Duration::from_secs(boot + 100_000);
        std::fs::File::open(root.0.join("srv"))
            .unwrap()
            .set_modified(changed)
            .unwrap();
        assert_eq!(
            reason(),
            None,
            "intact target excludes its unrelated parent changes"
        );
        assert_eq!(latest_change(&root.0).unwrap(), before);
        std::fs::remove_dir_all(root.0.join("srv/lightdm")).unwrap();
        std::fs::File::open(root.0.join("srv"))
            .unwrap()
            .set_modified(changed)
            .unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(changed)));
        assert!(reason().unwrap().contains("until it restarts"));
    }

    #[test]
    fn unrelated_non_utf8_comm_does_not_block_a_standard_fresh_daemon() {
        let root = Root::new("non-utf8-comm");
        root.put("etc/lightdm/lightdm.conf", "[VNCServer]\nenabled=false\n");
        root.put("proc/stat", "btime 4000000000\n");
        root.put("proc/1/stat", &process_stat("systemd"));
        root.put("proc/42/stat", &process_stat("lightdm"));
        root.put("proc/42/cmdline", "lightdm\0");
        let proc = root.0.join("proc");
        let started = lightdm_started_in(&proc).unwrap();
        assert!(started.is_some());
        let other = root.put("proc/2/stat", "");
        std::fs::write(other, b"2 (other\xff) S 1 2 3\n").unwrap();
        assert_eq!(lightdm_started_in(&proc), Ok(started));
        assert_eq!(
            reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || running_lightdm_predates_in(&root.0, &proc),
            ),
            None
        );
    }

    #[test]
    fn special_configuration_is_rejected_without_a_normal_open() {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let root = Root::new("no-special-open");
        let path = root.0.join("special");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a live NUL-terminated fixture path.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        // SAFETY: inotify_init1 takes flags only and returns a new owned fd.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: fd is valid, newly owned and transferred once into File.
        let mut events = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(
            // SAFETY: the inotify fd and NUL-terminated path remain valid for the call.
            unsafe { libc::inotify_add_watch(events.as_raw_fd(), cpath.as_ptr(), libc::IN_OPEN) }
                >= 0
        );
        assert!(evidence::read_bytes(&path, 1024).is_err());
        let observed = events.read(&mut [0u8; 256]);
        assert!(
            matches!(observed, Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "special file was normally opened before rejection: {observed:?}"
        );
    }

    #[test]
    fn pinned_reads_preserve_symlinks_proc_and_byte_limits() {
        use std::os::unix::fs::symlink;
        let root = Root::new("pinned-read-compatibility");
        let file = root.put("value", "test");
        let relative = root.0.join("relative");
        let absolute = root.0.join("absolute");
        symlink("value", &relative).unwrap();
        symlink(&file, &absolute).unwrap();
        for path in [&file, &relative, &absolute] {
            assert_eq!(evidence::read_bytes(path, 4).unwrap().unwrap(), b"test");
            assert!(evidence::read_bytes(path, 3).is_err());
        }
        let proc = Path::new("/proc/self/cmdline");
        let expected = std::fs::read(proc).unwrap();
        assert!(!expected.is_empty());
        assert_eq!(evidence::read_bytes(proc, 65536), Ok(Some(expected)));
        assert!(
            evidence::read_bytes(proc, 0).is_err(),
            "proc length zero is not a read bound"
        );
    }

    #[test]
    fn a_standard_running_daemon_keeps_the_existing_restart_gate() {
        let root = Root::new("standard-running");
        let main = root.put("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        // Stipulate ordered timestamps without changing the host clock. This
        // pins baseline availability, not clock-step-independent proof.
        let boot = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        root.put("proc/stat", &format!("btime {boot}\n"));
        root.put("proc/1/stat", &process_stat("systemd"));
        root.put("proc/42/stat", &process_stat("lightdm"));
        root.put("proc/42/cmdline", "/usr/sbin/lightdm\0");
        let proc = root.0.join("proc");
        let reason = || {
            reason_with(
                "lightdm",
                || lightdm_remote_servers_in(&root.0),
                || running_lightdm_predates_in(&root.0, &proc),
            )
        };
        assert_eq!(reason(), None, "standard fresh daemon remains available");
        std::fs::File::open(main)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(boot + 100_000))
            .unwrap();
        assert!(reason().unwrap().contains("until it restarts"));
        root.put("proc/stat", &format!("btime {}\n", boot + 200_000));
        assert_eq!(
            reason(),
            None,
            "restart after the change restores availability"
        );
        std::fs::remove_dir_all(proc.join("42")).unwrap();
        assert_eq!(reason(), None, "no daemon retains baseline behavior");
    }

    #[test]
    fn alternate_configuration_is_never_certified_by_standard_files() {
        let root = Root::new("alternate-config");
        root.put("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        root.put("proc/stat", "btime 4000000000\n");
        root.put("proc/1/stat", &process_stat("systemd"));
        root.put("proc/42/stat", &process_stat("lightdm"));
        for args in [
            "-c\0/remote.conf",
            "--config\0/remote.conf",
            "--config=/remote.conf",
            "-c\0/etc/lightdm/lightdm.conf",
            "-dc\0relative.conf",
        ] {
            root.put("proc/42/cmdline", &format!("/usr/sbin/lightdm\0{args}\0"));
            let result = running_lightdm_predates_in(&root.0, &root.0.join("proc"));
            assert!(
                result.unwrap_err().contains("explicit -c/--config"),
                "{args:?}"
            );
        }
    }

    #[test]
    fn unreadable_or_unbounded_process_evidence_never_means_absent() {
        let root = Root::new("process-errors");
        let proc = root.0.join("proc");
        root.put("proc/stat", "btime 1000\n");
        root.put("proc/1/stat", &process_stat("systemd"));
        assert_eq!(lightdm_started_in(&proc), Ok(None));
        root.put("proc/42/stat", &process_stat("lightdm"));
        assert!(lightdm_started_in(&proc).is_err(), "missing cmdline");
        let cmdline = root.put("proc/42/cmdline", "/usr/sbin/lightdm\0--debug\0");
        assert!(lightdm_started_in(&proc).unwrap().is_some());
        std::fs::write(&cmdline, b"lightdm").unwrap();
        assert!(lightdm_started_in(&proc).is_err(), "truncated cmdline");
        std::fs::write(&cmdline, []).unwrap();
        assert!(lightdm_started_in(&proc).is_err(), "empty cmdline");
        std::fs::write(&cmdline, vec![b'x'; 65537]).unwrap();
        assert!(lightdm_started_in(&proc).is_err(), "oversized cmdline");
        std::fs::remove_dir_all(proc.join("42")).unwrap();
        std::fs::create_dir_all(proc.join("42/stat")).unwrap();
        assert!(
            lightdm_started_in(&proc).is_err(),
            "cannot inspect another process"
        );
        std::fs::remove_dir_all(proc.join("42")).unwrap();
        std::fs::remove_file(proc.join("1/stat")).unwrap();
        assert!(lightdm_started_in(&proc).is_err(), "hidden process view");
    }

    #[test]
    fn explicit_configuration_is_refused_even_if_a_standard_child_is_seen_first() {
        let root = Root::new("daemon-and-child");
        root.put("proc/stat", "btime 1000\n");
        root.put("proc/1/stat", &process_stat("systemd"));
        root.put("proc/42/stat", &process_stat("lightdm"));
        root.put(
            "proc/42/cmdline",
            concat!("lightdm\0--session-child\0", "12\0", "13\0"),
        );
        root.put("proc/43/stat", &process_stat("lightdm"));
        root.put("proc/43/cmdline", "lightdm\0--config=/outside.conf\0");
        assert!(lightdm_started_in(&root.0.join("proc"))
            .unwrap_err()
            .contains("explicit"));
    }

    #[test]
    fn configuration_read_limits_and_symlink_cycles_fail_closed() {
        use std::os::unix::fs::symlink;
        let root = Root::new("file-limits");
        let main = root.put("etc/lightdm/lightdm.conf", "");
        std::fs::write(&main, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(lightdm_remote_servers_in(&root.0).is_err());
        std::fs::write(&main, [0xff]).unwrap();
        assert!(lightdm_remote_servers_in(&root.0).is_err());
        std::fs::remove_file(&main).unwrap();
        symlink("lightdm.conf", &main).unwrap();
        assert!(latest_change(&root.0).is_err(), "self cycle");
        assert!(lightdm_remote_servers_in(&root.0).is_err());
        std::fs::remove_file(&main).unwrap();
        symlink("other", &main).unwrap();
        symlink("lightdm.conf", main.with_file_name("other")).unwrap();
        assert!(latest_change(&root.0).is_err(), "two-link cycle");
    }

    #[test]
    fn a_configuration_fifo_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let root = Root::new("fifo");
        let main = root.put("etc/lightdm/lightdm.conf", "");
        std::fs::remove_file(&main).unwrap();
        let cpath = std::ffi::CString::new(main.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a live NUL-terminated fixture path for this call.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(lightdm_remote_servers_in(&root.0).is_err());
    }

    #[test]
    fn a_deleted_target_directory_uses_the_nearest_surviving_ancestor() {
        use std::os::unix::fs::symlink;
        let root = Root::new("missing-target-parent");
        root.put("outside/nested/remote.conf", "[VNCServer]\nenabled=true\n");
        let main = root.put("etc/lightdm/lightdm.conf", "");
        std::fs::remove_file(&main).unwrap();
        symlink("../../outside/nested/remote.conf", &main).unwrap();
        std::fs::remove_dir_all(root.0.join("outside/nested")).unwrap();
        let removed = SystemTime::now() + Duration::from_secs(120);
        std::fs::File::open(root.0.join("outside"))
            .unwrap()
            .set_modified(removed)
            .unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(removed)));
    }

    #[test]
    fn standard_file_precedence_is_preserved_across_all_directories() {
        let root = Root::new("all-precedence");
        for (i, dir) in LIGHTDM_DROP_IN_DIRS.iter().enumerate() {
            root.put(&format!("{dir}/Z.conf"), "[VNCServer]\nenabled=true\n");
            let last = root.put(&format!("{dir}/a.conf"), "[VNCServer]\nenabled=false\n");
            assert!(root.servers().is_empty(), "byte-wise order in layer {i}");
            std::fs::write(&last, "[VNCServer]\nenabled=true\n").unwrap();
            assert_eq!(root.servers(), vec![("VNC", last)], "layer {i} wins");
        }
        root.put("etc/lightdm/lightdm.conf", "[VNCServer]\nenabled=false\n");
        assert!(root.servers().is_empty(), "main wins");
    }

    fn process_stat(name: &str) -> String {
        format!("42 ({name}) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5555 1000 10")
    }

    #[test]
    fn a_dropin_directory_entry_limit_is_a_refusal_not_a_partial_configuration() {
        let root = Root::new("directory-limit");
        for i in 0..4097 {
            root.put(&format!("etc/lightdm/lightdm.conf.d/{i}.ignored"), "");
        }
        assert!(lightdm_remote_servers_in(&root.0).is_err());
        assert!(latest_change(&root.0).is_err());
    }

    #[test]
    fn symlink_resolution_keeps_dotdot_after_directory_links() {
        use std::os::unix::fs::symlink;
        let root = Root::new("link-dotdot");
        root.put("outside/real/remote.conf", "[VNCServer]\nenabled=true\n");
        std::fs::create_dir_all(root.0.join("outside/real/nested")).unwrap();
        symlink("real/nested", root.0.join("outside/alias")).unwrap();
        let main = root.put("etc/lightdm/lightdm.conf", "");
        std::fs::remove_file(&main).unwrap();
        symlink("../../outside/alias/../remote.conf", &main).unwrap();
        assert_eq!(root.servers(), vec![("VNC", main)]);
        std::fs::remove_file(root.0.join("outside/real/remote.conf")).unwrap();
        let removed = SystemTime::now() + Duration::from_secs(120);
        std::fs::File::open(root.0.join("outside/real"))
            .unwrap()
            .set_modified(removed)
            .unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(removed)));
    }

    #[test]
    fn deleting_a_symlink_target_keeps_its_parent_as_change_evidence() {
        use std::os::unix::fs::symlink;
        for name in ["lightdm.conf", "lightdm.conf.d/50-remote.conf"] {
            let root = Root::new(name.replace('/', "-").as_str());
            let target = root.put("outside/remote.conf", "[XDMCPServer]\nenabled=true\n");
            let link = root.0.join("etc/lightdm").join(name);
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            symlink(&target, &link).unwrap();
            assert_eq!(root.servers(), vec![("XDMCP", link)]);
            std::fs::remove_file(&target).unwrap();
            let removed = SystemTime::now() + Duration::from_secs(120);
            std::fs::File::open(target.parent().unwrap())
                .unwrap()
                .set_modified(removed)
                .unwrap();
            assert!(root.servers().is_empty());
            assert_eq!(latest_change(&root.0), Ok(Some(removed)), "{name}");
        }
    }

    #[test]
    fn deleted_intermediate_symlink_target_keeps_deletion_evidence() {
        use std::os::unix::fs::symlink;
        let root = Root::new("link-chain");
        let target = root.put("outside/real.conf", "[VNCServer]\nenabled=true\n");
        let intermediate = root.0.join("outside/middle.conf");
        symlink("real.conf", &intermediate).unwrap();
        let main = root.put("etc/lightdm/lightdm.conf", "");
        std::fs::remove_file(&main).unwrap();
        symlink("../../outside/middle.conf", &main).unwrap();
        assert_eq!(root.servers(), vec![("VNC", main)]);
        std::fs::remove_file(intermediate).unwrap();
        let removed = SystemTime::now() + Duration::from_secs(120);
        std::fs::File::open(target.parent().unwrap())
            .unwrap()
            .set_modified(removed)
            .unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(removed)));
    }

    #[test]
    fn removing_a_symlinked_directory_target_keeps_its_parent_evidence() {
        use std::os::unix::fs::symlink;
        let root = Root::new("directory-link");
        let target = root.put(
            "outside/dropins/50-remote.conf",
            "[VNCServer]\nenabled=true\n",
        );
        std::fs::create_dir_all(root.0.join("etc/lightdm")).unwrap();
        symlink(
            "../../outside/dropins",
            root.0.join("etc/lightdm/lightdm.conf.d"),
        )
        .unwrap();
        assert_eq!(root.servers().len(), 1);
        std::fs::remove_dir_all(target.parent().unwrap()).unwrap();
        let removed = SystemTime::now() + Duration::from_secs(120);
        std::fs::File::open(root.0.join("outside"))
            .unwrap()
            .set_modified(removed)
            .unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(removed)));
    }

    #[test]
    fn the_latest_change_counts_files_directories_and_their_parents() {
        use std::os::unix::fs::MetadataExt as _;
        let root = Root::new("latest");
        let newest = |path: &Path| {
            let meta = std::fs::metadata(path).unwrap();
            let ctime = SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::try_from(meta.ctime()).unwrap())
                + Duration::from_nanos(u64::try_from(meta.ctime_nsec()).unwrap());
            meta.modified().unwrap().max(ctime)
        };
        let main = root.put("etc/lightdm/lightdm.conf", "[Seat:*]\n");
        let before = latest_change(&root.0).unwrap().expect("a change");
        assert!(before >= newest(&main));
        // Deleting a drop-in changes its directory.
        let dropin = root.put(
            "etc/lightdm/lightdm.conf.d/50-xdmcp.conf",
            "[XDMCPServer]\n",
        );
        std::thread::sleep(Duration::from_millis(20));
        std::fs::remove_file(&dropin).unwrap();
        let dir = dropin.parent().unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(newest(dir))));
        // Deleting a whole drop-in directory changes its parent.
        let xdg = root.put(
            "etc/xdg/lightdm/lightdm.conf.d/50-vnc.conf",
            "[VNCServer]\n",
        );
        std::thread::sleep(Duration::from_millis(20));
        std::fs::remove_dir_all(xdg.parent().unwrap()).unwrap();
        let parent = root.0.join("etc/xdg/lightdm");
        assert_eq!(latest_change(&root.0), Ok(Some(newest(&parent))));
        // Putting an old mtime back still moves the ctime.
        std::thread::sleep(Duration::from_millis(20));
        let old = std::fs::metadata(&main).unwrap().modified().unwrap();
        std::fs::write(&main, "[XDMCPServer]\nenabled=false\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&main)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert_eq!(latest_change(&root.0), Ok(Some(newest(&main))));
        assert!(newest(&main) > newest(&parent));
        // A change elsewhere under /etc is not LightDM's.
        std::thread::sleep(Duration::from_millis(20));
        root.put("etc/unrelated.conf", "x\n");
        assert_eq!(latest_change(&root.0), Ok(Some(newest(&main))));
    }
}
