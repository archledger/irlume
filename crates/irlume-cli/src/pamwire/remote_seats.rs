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

use super::autologin::{assignments, lightdm_files, on, read, LIGHTDM_DROP_IN_DIRS, LIGHTDM_MAIN};
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
        for (section, key, value) in assignments(&text) {
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
/// No LightDM running, or no configuration file, is "no".
fn running_lightdm_predates_its_configuration() -> Result<bool, String> {
    let changed = latest_change(Path::new("/"))?;
    Ok(predates(lightdm_started()?, changed))
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
    use std::os::unix::fs::MetadataExt as _;
    // Each drop-in directory and its parent, which is LightDM's own
    // (`.../lightdm`), and the main file's directory, but not that
    // directory's parent: that is /etc, which every package transaction
    // changes.
    let mut dirs: Vec<PathBuf> = Vec::new();
    let main_dir = Path::new(LIGHTDM_MAIN).parent();
    for dir in LIGHTDM_DROP_IN_DIRS.iter().map(Path::new) {
        for path in [Some(dir), dir.parent()].into_iter().flatten() {
            let path = root.join(path);
            if !dirs.contains(&path) {
                dirs.push(path);
            }
        }
    }
    if let Some(main_dir) = main_dir.map(|dir| root.join(dir)) {
        if !dirs.contains(&main_dir) {
            dirs.push(main_dir);
        }
    }
    let mut latest = None;
    for path in lightdm_files(root)?.into_iter().chain(dirs) {
        match std::fs::metadata(&path) {
            Ok(meta) => {
                let ctime = u64::try_from(meta.ctime()).ok().map(|secs| {
                    SystemTime::UNIX_EPOCH
                        + Duration::from_secs(secs)
                        + Duration::from_nanos(u64::try_from(meta.ctime_nsec()).unwrap_or(0))
                });
                latest = latest.max(meta.modified().ok()).max(ctime);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Ok(latest)
}

/// When the oldest process named `lightdm` started (the daemon, which forks
/// its session children under the same name), `None` when none runs. An
/// error when this process cannot see every process: `/proc` mounted with
/// `hidepid` hides root's from an ordinary user, and a LightDM that cannot be
/// seen is not one that is not running.
fn lightdm_started() -> Result<Option<SystemTime>, String> {
    let stat = std::fs::read_to_string("/proc/stat").map_err(|e| format!("/proc/stat: {e}"))?;
    let boot = stat
        .lines()
        .find_map(|line| line.strip_prefix("btime ")?.trim().parse::<u64>().ok())
        .ok_or("/proc/stat has no boot time")?;
    // PID 1 is root's; an ordinary user who cannot read its stat cannot see
    // other users' processes either.
    std::fs::read_to_string("/proc/1/stat")
        .map_err(|e| format!("/proc/1/stat: {e}; other users' processes are hidden"))?;
    // SAFETY: sysconf takes no pointers and only reads a system constant.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|hz| *hz > 0)
        .ok_or("no clock tick rate")?;
    let ticks = std::fs::read_dir("/proc")
        .map_err(|e| format!("/proc: {e}"))?
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        // A process that exits between the listing and the read is gone.
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("stat")).ok())
        .filter_map(|stat| lightdm_start_ticks(&stat))
        .min();
    Ok(ticks.map(|ticks| {
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(boot)
            + Duration::from_millis(ticks * 1000 / hz)
    }))
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
