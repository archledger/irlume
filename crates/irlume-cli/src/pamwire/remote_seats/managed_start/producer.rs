// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The root side of the managed-start receipt, run by `lightdm.service`'s own
//! invocation through irlume's drop-in.
//!
//! `lightdm-managed-prepare` runs as an `ExecStartPre=` command: before the
//! main process exists, it records the digest of LightDM's whole
//! configuration input closure and the remote-server policy those bytes give.
//! LightDM then loads its configuration and only afterwards takes its bus
//! name (`src/lightdm.c:742` before `:856-862` in 1.32), and systemd runs the
//! `ExecStartPost=` command `lightdm-managed-commit` once that name is taken
//! (`Type=dbus`, implied by the distributions' `BusName=`). The commit
//! recomputes the digest: equal digests on both sides of the load mean the
//! running daemon loaded exactly those bytes. It then binds the result to the
//! invocation, main process and monotonic start the manager reports and
//! publishes the public receipt the verdict machine reads.
//!
//! Every failure publishes nothing, and the drop-in's `-` prefix keeps
//! LightDM running: no receipt means `Unknown`, and the existing rule decides.
//! The producer reads `/proc` for its own target only; readers never do.
//!
//! Residual, recorded in the design: a root writer that changes the
//! configuration after the first digest and restores it before the second
//! within one startup is not detected. Root can rewrite PAM outright.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::loader::{self, Profile};
use super::system::{parse_manager, read_trusted_text, RECEIPT_NAME};
use super::{Receipt, LIGHTDM_UNIT, SCHEMA_VERSION};

/// The prepare-time record, private to root.
pub(crate) const PREPARED_NAME: &str = "managed-start.prepared.json";

/// The LightDM executables a supported distribution unit starts.
const LIGHTDM_EXECUTABLES: [&str; 2] = ["/usr/sbin/lightdm", "/usr/bin/lightdm"];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    schema: u32,
    unit: String,
    invocation_id: String,
    digest: String,
    xdmcp_enabled: bool,
    vnc_enabled: bool,
}

/// What the producer reads about the target process (root only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The full argument vector, each element without its NUL.
    pub(crate) argv: Vec<Vec<u8>>,
    /// Device and inode of the executable the process runs.
    pub(crate) exe: (u64, u64),
    /// Sixty-four lowercase hex digits over the executable's bytes.
    pub(crate) exe_digest: String,
    pub(crate) xdg_data_dirs: Option<OsString>,
    pub(crate) xdg_config_dirs: Option<OsString>,
}

/// Everything the producer observes, so tests can supply it.
pub(crate) trait Host {
    fn env(&self, name: &str) -> Option<OsString>;
    /// `systemctl show` output for `unit` with the properties
    /// [`parse_manager`] needs.
    fn show(&self, unit: &str) -> Result<String, String>;
    /// The unit's `Type=` as the manager reports it.
    fn unit_type(&self, unit: &str) -> Result<String, String>;
    fn target(&self, pid: u32) -> Result<Target, String>;
    /// Device and inode of an executable path, following links.
    fn identity(&self, path: &Path) -> Result<(u64, u64), String>;
    /// Filesystem root LightDM's configuration is read under.
    fn root(&self) -> &Path;
    /// LightDM's runtime root, where records are published.
    fn runtime(&self) -> &Path;
    /// The owner every record must have.
    fn trusted_uid(&self) -> u32;
}

/// The executable is read whole to digest it; LightDM's is about 1 MiB.
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// The real host: this process's environment, the system manager, and the
/// target's `/proc` entries (root, producer side only).
pub(crate) struct RealHost;

impl Host for RealHost {
    fn env(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }

    fn show(&self, unit: &str) -> Result<String, String> {
        super::system::systemctl_show(unit)
    }

    fn unit_type(&self, unit: &str) -> Result<String, String> {
        super::system::systemctl_unit_type(unit)
    }

    fn target(&self, pid: u32) -> Result<Target, String> {
        use sha2::{Digest as _, Sha256};
        use std::io::Read as _;
        use std::os::unix::fs::MetadataExt as _;
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let read = |name: &str| {
            std::fs::read(proc.join(name)).map_err(|e| format!("/proc/{pid}/{name}: {e}"))
        };
        let split = |bytes: Vec<u8>| -> Vec<Vec<u8>> {
            bytes
                .split(|b| *b == 0)
                .filter(|part| !part.is_empty())
                .map(<[u8]>::to_vec)
                .collect()
        };
        let argv = split(read("cmdline")?);
        let environment = split(read("environ")?);
        let variable = |name: &str| {
            let prefix = format!("{name}=");
            environment.iter().find_map(|entry| {
                entry
                    .strip_prefix(prefix.as_bytes())
                    .map(|value| OsString::from(std::ffi::OsStr::from_bytes(value)))
            })
        };
        let exe_path = proc.join("exe");
        let meta =
            std::fs::metadata(&exe_path).map_err(|e| format!("{}: {e}", exe_path.display()))?;
        let mut bytes = Vec::new();
        std::fs::File::open(&exe_path)
            .map_err(|e| format!("{}: {e}", exe_path.display()))?
            .take(MAX_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("{}: {e}", exe_path.display()))?;
        if bytes.len() as u64 > MAX_EXECUTABLE_BYTES {
            return Err("LightDM's executable is unexpectedly large".into());
        }
        let exe_digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Target {
            argv,
            exe: (meta.dev(), meta.ino()),
            exe_digest,
            xdg_data_dirs: variable("XDG_DATA_DIRS"),
            xdg_config_dirs: variable("XDG_CONFIG_DIRS"),
        })
    }

    fn identity(&self, path: &Path) -> Result<(u64, u64), String> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((meta.dev(), meta.ino()))
    }

    fn root(&self) -> &Path {
        Path::new("/")
    }

    fn runtime(&self) -> &Path {
        Path::new(super::super::super::lightdm_view::RUN)
    }

    fn trusted_uid(&self) -> u32 {
        0
    }
}

/// `irlume login lightdm-managed-prepare|lightdm-managed-commit <unit>`, run by
/// the LightDM drop-in. A failure is reported and publishes nothing.
pub(crate) fn run(action: &str, args: &[String]) -> std::process::ExitCode {
    let unit = args
        .iter()
        .position(|arg| arg == action)
        .and_then(|at| args.get(at + 1))
        .map_or("", String::as_str);
    let result = if super::super::super::effective_uid() != 0 {
        Err("LightDM managed start requires root".to_string())
    } else if action == "lightdm-managed-prepare" {
        prepare(&RealHost, unit)
    } else {
        commit(&RealHost, unit).map(|_| ())
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[login] LightDM managed start: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Record the configuration LightDM is about to load.
pub(crate) fn prepare(host: &dyn Host, unit: &str) -> Result<(), String> {
    // A new launch retires whatever the previous one published.
    retire(host)?;
    supported_unit(unit)?;
    let invocation_id = invocation(host)?;
    let profile = Profile::from_environment(
        host.env("XDG_DATA_DIRS").as_deref(),
        host.env("XDG_CONFIG_DIRS").as_deref(),
    )
    .ok_or("LightDM's XDG search path is not GLib's default")?;
    let observed = loader::observe(host.root(), &profile, true)?;
    let record = Prepared {
        schema: SCHEMA_VERSION,
        unit: unit.into(),
        invocation_id,
        digest: observed.digest,
        xdmcp_enabled: observed.xdmcp_enabled,
        vnc_enabled: observed.vnc_enabled,
    };
    let text = serde_json::to_string(&record).map_err(|e| e.to_string())?;
    publish(&host.runtime().join(PREPARED_NAME), &text, 0o600)
}

/// Bind the loaded configuration to the running invocation and publish the
/// public receipt.
pub(crate) fn commit(host: &dyn Host, unit: &str) -> Result<Receipt, String> {
    retire(host)?;
    supported_unit(unit)?;
    let invocation_id = invocation(host)?;
    let main_pid: u32 = host
        .env("MAINPID")
        .and_then(|pid| pid.to_str()?.parse().ok())
        .filter(|pid| *pid > 0)
        .ok_or("MAINPID is missing or malformed")?;
    let record: Prepared =
        match read_trusted_text(host.runtime(), PREPARED_NAME, host.trusted_uid()) {
            Some(text) => {
                serde_json::from_str(&text?).map_err(|e| format!("prepared record: {e}"))?
            }
            None => return Err("no prepared record for this launch".into()),
        };
    if record.schema != SCHEMA_VERSION
        || record.unit != unit
        || record.invocation_id != invocation_id
    {
        return Err("the prepared record names another launch".into());
    }
    // Only Type=dbus starts ExecStartPost= after the bus name, which LightDM
    // takes after loading configuration; any other type could run this
    // before the load and bind bytes LightDM had not read yet.
    let unit_type = host.unit_type(unit)?;
    if unit_type != "dbus" {
        return Err(format!(
            "{unit} has Type={unit_type}; only dbus orders this commit after the load"
        ));
    }
    let before = launch(host, unit, &invocation_id, main_pid)?;
    let target = host.target(main_pid)?;
    supported_target(host, &target)?;
    let profile = Profile::from_environment(
        target.xdg_data_dirs.as_deref(),
        target.xdg_config_dirs.as_deref(),
    )
    .ok_or("the running LightDM's XDG search path is not GLib's default")?;
    let observed = loader::observe(host.root(), &profile, true)?;
    if observed.digest != record.digest
        || observed.xdmcp_enabled != record.xdmcp_enabled
        || observed.vnc_enabled != record.vnc_enabled
    {
        return Err("LightDM's configuration changed while it loaded".into());
    }
    // The second sample proves the facts above describe this same launch.
    if launch(host, unit, &invocation_id, main_pid)? != before {
        return Err("the launch changed while it was being bound".into());
    }
    let receipt = Receipt {
        schema: SCHEMA_VERSION,
        unit: unit.into(),
        invocation_id,
        main_pid,
        exec_start_monotonic_us: before,
        target_digest: target.exe_digest,
        config_generation: observed.digest,
        xdmcp_enabled: observed.xdmcp_enabled,
        vnc_enabled: observed.vnc_enabled,
        pam_generation_roots: vec![super::super::super::lightdm_view::VIEW.into()],
        producer_version: env!("CARGO_PKG_VERSION").into(),
    };
    receipt.validate()?;
    let text = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
    publish(&host.runtime().join(RECEIPT_NAME), &text, 0o644)?;
    Ok(receipt)
}

fn supported_unit(unit: &str) -> Result<(), String> {
    if unit != LIGHTDM_UNIT {
        return Err(format!("{unit} is not the managed LightDM unit"));
    }
    Ok(())
}

/// This launch's invocation identifier, which systemd gives every command of
/// the unit's start, `ExecStartPre=` and `ExecStartPost=` included.
fn invocation(host: &dyn Host) -> Result<String, String> {
    host.env("INVOCATION_ID")
        .and_then(|id| id.into_string().ok())
        .filter(|id| id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| "INVOCATION_ID is missing or malformed".into())
}

/// The manager's monotonic start of the running launch, after checking it is
/// this invocation with this main process.
fn launch(host: &dyn Host, unit: &str, invocation_id: &str, main_pid: u32) -> Result<u64, String> {
    let seen = parse_manager(unit, &host.show(unit)?)
        .ok_or("the manager's view of LightDM is unsettled or unreadable")?;
    if !seen.active
        || seen.invocation_id != invocation_id
        || seen.main_pid != main_pid
        || seen.exec_start_monotonic_us == 0
    {
        return Err("the manager does not report this launch as running".into());
    }
    Ok(seen.exec_start_monotonic_us)
}

/// The target runs a supported LightDM executable with no arguments, and
/// that path is the very file the process executes.
fn supported_target(host: &dyn Host, target: &Target) -> Result<(), String> {
    let [argv0] = target.argv.as_slice() else {
        return Err("LightDM runs with arguments; only a plain start is supported".into());
    };
    let path = std::str::from_utf8(argv0)
        .ok()
        .filter(|path| LIGHTDM_EXECUTABLES.contains(path))
        .ok_or("LightDM runs from an unsupported executable path")?;
    if host.identity(Path::new(path))? != target.exe {
        return Err("LightDM's executable changed after it started".into());
    }
    Ok(())
}

/// Remove a receipt left by an earlier launch, so nothing stale stands while
/// this one is bound.
fn retire(host: &dyn Host) -> Result<(), String> {
    match std::fs::remove_file(host.runtime().join(RECEIPT_NAME)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("retire the previous receipt: {e}")),
    }
}

/// Replace `path` atomically with `text` at `mode`, owned by the caller.
fn publish(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let dir = path.parent().ok_or("record path has no directory")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("record path has no name")?;
    let staging = dir.join(format!(".{name}.{}", std::process::id()));
    let _ = std::fs::remove_file(&staging);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staging)
            .map_err(|e| format!("{}: {e}", staging.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&staging, path).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::File::open(dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::system::SystemSource;
    use super::super::{evaluate, Verdict};
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;

    const INVOCATION: &str = "4f1c2b3a4d5e6f708192a3b4c5d6e7f8";
    const PID: u32 = 4242;
    const EXE: (u64, u64) = (64769, 1_048_577);

    struct Fake {
        root: PathBuf,
        runtime: PathBuf,
        env: RefCell<Vec<(&'static str, Option<OsString>)>>,
        manager: RefCell<String>,
        unit_type: RefCell<String>,
        target: RefCell<Result<Target, String>>,
        identities: RefCell<Vec<(PathBuf, (u64, u64))>>,
    }

    impl Fake {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "irlume-managed-producer-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&base);
            let root = base.join("root");
            let runtime = base.join("run");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(&runtime).unwrap();
            for dir in [&base, &root, &runtime] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Fake {
                root,
                runtime,
                env: RefCell::new(vec![
                    ("INVOCATION_ID", Some(INVOCATION.into())),
                    ("MAINPID", Some(PID.to_string().into())),
                ]),
                manager: RefCell::new(running(PID)),
                unit_type: RefCell::new("dbus".into()),
                target: RefCell::new(Ok(target("/usr/sbin/lightdm"))),
                identities: RefCell::new(vec![("/usr/sbin/lightdm".into(), EXE)]),
            }
        }

        fn config(&self, relative: &str, text: &str) {
            let path = self.root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        fn set_env(&self, name: &'static str, value: Option<&str>) {
            let mut env = self.env.borrow_mut();
            env.retain(|(key, _)| *key != name);
            env.push((name, value.map(OsString::from)));
        }

        fn source(&self) -> SystemSource {
            SystemSource::for_tests(self.runtime.clone(), uid(), running_now)
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.root.parent().unwrap());
        }
    }

    impl Host for Fake {
        fn env(&self, name: &str) -> Option<OsString> {
            self.env
                .borrow()
                .iter()
                .find(|(key, _)| *key == name)
                .and_then(|(_, value)| value.clone())
        }
        fn show(&self, _unit: &str) -> Result<String, String> {
            Ok(self.manager.borrow().clone())
        }
        fn unit_type(&self, _unit: &str) -> Result<String, String> {
            Ok(self.unit_type.borrow().clone())
        }
        fn target(&self, _pid: u32) -> Result<Target, String> {
            self.target.borrow().clone()
        }
        fn identity(&self, path: &Path) -> Result<(u64, u64), String> {
            self.identities
                .borrow()
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, id)| *id)
                .ok_or_else(|| format!("{}: no such executable", path.display()))
        }
        fn root(&self) -> &Path {
            &self.root
        }
        fn runtime(&self) -> &Path {
            &self.runtime
        }
        fn trusted_uid(&self) -> u32 {
            uid()
        }
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn running(pid: u32) -> String {
        format!(
            "LoadState=loaded\nActiveState=active\nMainPID={pid}\n\
             InvocationID={INVOCATION}\nExecMainStartTimestampMonotonic=15720777\n"
        )
    }

    thread_local! {
        static LIVE_PID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn running_now(_unit: &str) -> Result<String, String> {
        Ok(running(LIVE_PID.with(std::cell::Cell::get)))
    }

    fn target(path: &str) -> Target {
        Target {
            argv: vec![path.as_bytes().to_vec()],
            exe: EXE,
            exe_digest: "e".repeat(64),
            xdg_data_dirs: None,
            xdg_config_dirs: None,
        }
    }

    fn prepared(fake: &Fake) -> Option<Prepared> {
        read_trusted_text(&fake.runtime, PREPARED_NAME, uid())
            .map(|text| serde_json::from_str(&text.unwrap()).unwrap())
    }

    #[test]
    fn prepare_records_the_digest_for_this_invocation_privately() {
        let fake = Fake::new("prepare");
        fake.config("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        prepare(&fake, LIGHTDM_UNIT).expect("prepared");
        let record = prepared(&fake).expect("record");
        assert_eq!(record.invocation_id, INVOCATION);
        assert_eq!(record.unit, LIGHTDM_UNIT);
        assert_eq!(
            record.digest,
            loader::observe(&fake.root, &Profile::standard(), true)
                .unwrap()
                .digest
        );
        let mode = std::fs::metadata(fake.runtime.join(PREPARED_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "root-only");
    }

    #[test]
    fn commit_binds_an_unchanged_configuration_to_the_running_invocation() {
        let fake = Fake::new("commit");
        fake.config("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        prepare(&fake, LIGHTDM_UNIT).unwrap();
        let receipt = commit(&fake, LIGHTDM_UNIT).expect("committed");
        assert_eq!(receipt.invocation_id, INVOCATION);
        assert_eq!(receipt.main_pid, PID);
        assert_eq!(receipt.exec_start_monotonic_us, 15_720_777);
        assert_eq!(receipt.config_generation, prepared(&fake).unwrap().digest);
        assert!(!receipt.xdmcp_enabled && !receipt.vnc_enabled);
        let mode = std::fs::metadata(fake.runtime.join(RECEIPT_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "public");
    }

    #[test]
    fn a_published_receipt_verifies_off_through_the_production_source() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let fake = Fake::new("verify");
        fake.config(
            "etc/lightdm/lightdm.conf.d/50-remote.conf",
            "[VNCServer]\nenabled=true\n",
        );
        fake.set_env("MAINPID", Some(&child.id().to_string()));
        *fake.manager.borrow_mut() = running(child.id());
        LIVE_PID.with(|cell| cell.set(child.id()));
        prepare(&fake, LIGHTDM_UNIT).unwrap();
        commit(&fake, LIGHTDM_UNIT).unwrap();
        let verdict = evaluate(&fake.source());
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            matches!(verdict, Verdict::RemoteOn { ref invocation_id, .. } if invocation_id == INVOCATION),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_configuration_change_across_the_load_publishes_nothing() {
        let fake = Fake::new("changed");
        fake.config("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        prepare(&fake, LIGHTDM_UNIT).unwrap();
        fake.config(
            "etc/lightdm/lightdm.conf.d/remote.conf",
            "[XDMCPServer]\nenabled=true\n",
        );
        assert!(commit(&fake, LIGHTDM_UNIT).is_err());
        assert!(!fake.runtime.join(RECEIPT_NAME).exists());
    }

    #[test]
    fn a_record_for_another_invocation_publishes_nothing() {
        let fake = Fake::new("stale");
        prepare(&fake, LIGHTDM_UNIT).unwrap();
        fake.set_env("INVOCATION_ID", Some(&"a".repeat(32)));
        assert!(commit(&fake, LIGHTDM_UNIT).is_err());
        assert!(!fake.runtime.join(RECEIPT_NAME).exists());
    }

    #[test]
    fn commit_requires_the_managers_own_launch_identity() {
        for manager in [
            running(PID + 1),
            running(PID).replace(INVOCATION, &"b".repeat(32)),
            running(PID).replace("ActiveState=active", "ActiveState=activating"),
            running(PID).replace(
                "ExecMainStartTimestampMonotonic=15720777",
                "ExecMainStartTimestampMonotonic=0",
            ),
        ] {
            let fake = Fake::new("identity");
            prepare(&fake, LIGHTDM_UNIT).unwrap();
            *fake.manager.borrow_mut() = manager.clone();
            assert!(commit(&fake, LIGHTDM_UNIT).is_err(), "{manager}");
            assert!(!fake.runtime.join(RECEIPT_NAME).exists());
        }
    }

    #[test]
    fn commit_requires_the_plain_supported_executable() {
        let unsupported = [
            {
                let mut t = target("/usr/sbin/lightdm");
                t.argv.push(b"--config=/etc/other.conf".to_vec());
                t
            },
            target("/usr/local/sbin/lightdm"),
            {
                let mut t = target("/usr/sbin/lightdm");
                t.exe = (1, 2);
                t
            },
            {
                let mut t = target("/usr/sbin/lightdm");
                t.xdg_config_dirs = Some("/opt/xdg".into());
                t
            },
        ];
        for target in unsupported {
            let fake = Fake::new("target");
            prepare(&fake, LIGHTDM_UNIT).unwrap();
            *fake.target.borrow_mut() = Ok(target.clone());
            assert!(commit(&fake, LIGHTDM_UNIT).is_err(), "{target:?}");
            assert!(!fake.runtime.join(RECEIPT_NAME).exists());
        }
    }

    #[test]
    fn prepare_refuses_unsupported_contexts_and_records_nothing() {
        let fake = Fake::new("unsupported");
        fake.set_env("XDG_DATA_DIRS", Some("/opt/share"));
        assert!(prepare(&fake, LIGHTDM_UNIT).is_err(), "non-default XDG");
        fake.set_env("XDG_DATA_DIRS", None);
        fake.set_env("INVOCATION_ID", Some("not-an-id"));
        assert!(
            prepare(&fake, LIGHTDM_UNIT).is_err(),
            "malformed invocation"
        );
        fake.set_env("INVOCATION_ID", Some(INVOCATION));
        assert!(prepare(&fake, "sddm.service").is_err(), "another unit");
        fake.config("etc/lightdm/lightdm.conf", "[XDMCPServer]\nenabled=false\n");
        std::fs::set_permissions(
            fake.root.join("etc/lightdm/lightdm.conf"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(
            prepare(&fake, LIGHTDM_UNIT).is_err(),
            "an input others cannot read"
        );
        assert!(prepared(&fake).is_none());
        std::fs::set_permissions(
            fake.root.join("etc/lightdm/lightdm.conf"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(prepare(&fake, LIGHTDM_UNIT).is_ok(), "positive control");
    }

    #[test]
    fn commit_requires_a_unit_that_starts_post_commands_after_the_load() {
        // Only Type=dbus orders ExecStartPost= after LightDM's bus name,
        // which it takes after loading configuration. Any other type could
        // run the commit before the load.
        for unit_type in ["simple", "exec", "notify", "forking", "oneshot", ""] {
            let fake = Fake::new("type");
            prepare(&fake, LIGHTDM_UNIT).unwrap();
            *fake.unit_type.borrow_mut() = unit_type.into();
            assert!(commit(&fake, LIGHTDM_UNIT).is_err(), "{unit_type:?}");
            assert!(!fake.runtime.join(RECEIPT_NAME).exists());
        }
    }

    #[test]
    fn a_failed_commit_removes_an_earlier_receipt() {
        let fake = Fake::new("retire");
        prepare(&fake, LIGHTDM_UNIT).unwrap();
        commit(&fake, LIGHTDM_UNIT).unwrap();
        assert!(fake.runtime.join(RECEIPT_NAME).exists());
        fake.set_env("INVOCATION_ID", Some(&"c".repeat(32)));
        *fake.manager.borrow_mut() = running(PID).replace(INVOCATION, &"c".repeat(32));
        assert!(
            commit(&fake, LIGHTDM_UNIT).is_err(),
            "no record for the new launch"
        );
        assert!(
            !fake.runtime.join(RECEIPT_NAME).exists(),
            "a later launch must not leave the old receipt standing"
        );
    }
}
