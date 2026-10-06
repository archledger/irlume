// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A private PAM view for LightDM. Shared host stacks are never rewritten.
//! Each protected root names immutable, generation-specific include copies;
//! unrelated services resolve through the unit's read-only host-directory bind.

use super::{files, grammar::*};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

pub(super) const RUN: &str = "/run/irlume-lightdm";
pub(super) const VIEW: &str = "/run/irlume-lightdm/pam.d";
const SOURCE: &str = "/run/irlume-lightdm-source/etc";
const PREFIX: &str = "irlume-lightdm-copy-";
const MAX_FILE: u64 = 64 * 1024;
const MAX_FILES: usize = 128;
const MAX_VIEW: u64 = 32 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    blocked: bool,
    services: BTreeSet<String>,
    permit: String,
    unit: String,
    session_module: String,
}

pub(super) fn run(action: &str, args: &[String]) -> ExitCode {
    let result = (|| {
        if super::effective_uid() != 0 {
            return Err("LightDM PAM view requires root".to_string());
        }
        if action == "lightdm-view-check" {
            let actual = fs::metadata("/etc/pam.d").map_err(|e| e.to_string())?;
            let prepared = fs::metadata(VIEW).map_err(|e| e.to_string())?;
            if (actual.dev(), actual.ino()) != (prepared.dev(), prepared.ino()) {
                return Err("LightDM PAM view is not mounted; refusing unprotected startup".into());
            }
            if !pam_irlume_view::detach_private_pam_view()
                .map_err(|e| format!("session namespace cleanup unavailable: {e}"))?
            {
                return Err("LightDM PAM view disappeared during startup check".into());
            }
            return Ok(());
        }
        if action == "lightdm-refresh" && !Path::new(RUN).exists() {
            return Ok(());
        }
        directory(Path::new(RUN))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(Path::new(RUN).join("view.lock"))
            .map_err(|e| e.to_string())?;
        trusted(&lock.metadata().map_err(|e| e.to_string())?, false)?;
        // SAFETY: the live File owns this descriptor until this function returns.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another LightDM view preparation is active; refusing to wait".into());
        }
        let policy = if action == "lightdm-prestart" {
            let unit = args
                .iter()
                .position(|arg| arg == action)
                .and_then(|at| args.get(at + 1))
                .map(String::as_str)
                .unwrap_or("");
            let mut policy = prospective(unit)?;
            policy.session_module = retain_session_module(crate::flag(args, "--session-module"))?;
            if let Some(permit) = crate::flag(args, "--permit-module") {
                if !permit.starts_with("/nix/store/")
                    || !permit.ends_with("/lib/security/pam_permit.so")
                    || permit.bytes().any(|b| b.is_ascii_whitespace())
                    || permit.contains("/../")
                {
                    return Err("unsupported permit module".into());
                }
                policy.permit = permit.into();
            }
            if let Some(previous) = read_regular(&Path::new(RUN).join("policy.json"))? {
                let previous: Policy =
                    serde_json::from_str(&previous).map_err(|e| e.to_string())?;
                // An administrator can invoke this command while LightDM is
                // still serving its old configuration. Only a positive stopped
                // unit observation permits relaxing a previous remote view.
                if previous.blocked && !policy.blocked && !unit_stopped(&previous.unit) {
                    policy.blocked = true;
                }
            }
            policy
        } else {
            let Some(text) = read_regular(&Path::new(RUN).join("policy.json"))? else {
                return Ok(());
            };
            serde_json::from_str::<Policy>(&text).map_err(|e| e.to_string())?
        };
        if policy.version != 1
            || policy.services.is_empty()
            || policy.services.len() > 16
            || policy.services.iter().any(|name| !service_name(name))
            || !matches!(
                policy.unit.as_str(),
                "lightdm.service" | "display-manager.service"
            )
        {
            return Err("invalid LightDM view policy".into());
        }
        publish(&policy)?;
        let text = serde_json::to_string(&policy).map_err(|e| e.to_string())?;
        write(&Path::new(RUN).join("policy.json"), &text, None)?;
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[login] LightDM PAM view: {e}");
            ExitCode::FAILURE
        }
    }
}

fn directory(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.to_string()),
    }
    trusted(
        &fs::symlink_metadata(path).map_err(|e| e.to_string())?,
        true,
    )
}

fn trusted(meta: &fs::Metadata, directory: bool) -> Result<(), String> {
    if meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
    {
        return Err("expected a root-owned, non-writable regular file or directory".into());
    }
    Ok(())
}

/// Pin the resolved inode before opening it for data: never open a FIFO/device.
fn read_regular(path: &Path) -> Result<Option<String>, String> {
    let Some(file) = open_regular(path)? else {
        return Ok(None);
    };
    let mut text = String::new();
    file.take(MAX_FILE + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_FILE {
        return Err("PAM source exceeds size limit".into());
    }
    Ok(Some(text))
}

fn open_regular(path: &Path) -> Result<Option<File>, String> {
    let pin = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(pin) => pin,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let meta = pin.metadata().map_err(|e| e.to_string())?;
    trusted(&meta, false)?;
    let fd_path = format!("/proc/self/fd/{}", pin.as_raw_fd());
    let file = File::open(fd_path).map_err(|e| e.to_string())?;
    Ok(Some(file))
}

fn security_label(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = open_regular(path)?.ok_or("PAM label source disappeared")?;
    let mut bytes = vec![0u8; 4096];
    // SAFETY: the descriptor is live; both the NUL-terminated name and writable
    // buffer are valid for the passed lengths until this call returns.
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if size < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
            return Ok(None);
        }
        return Err(format!("read PAM SELinux label: {error}"));
    }
    bytes.truncate(size as usize);
    Ok(Some(bytes))
}

fn service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.starts_with(PREFIX)
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// ExecStart's typed D-Bus value avoids parsing systemctl's human escaping.
fn prospective(unit: &str) -> Result<Policy, String> {
    // Nix's module asserts the exact generic.execCmd it supplies, since the
    // manager's ExecStart there is a generated shell wrapper rather than LightDM.
    if unit.starts_with("/nix/store/") && unit.ends_with("/sbin/lightdm") && !unit.contains("/../")
    {
        let mut policy = observe_configuration(unit, &[])?;
        policy.unit = "display-manager.service".into();
        return Ok(policy);
    }
    if !matches!(unit, "lightdm.service" | "display-manager.service") {
        return Err("unsupported LightDM unit name".into());
    }
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        unit.replace('-', "_2d").replace('.', "_2e")
    );
    let bus = if Path::new("/usr/bin/busctl").exists() {
        "/usr/bin/busctl"
    } else {
        "/run/current-system/sw/bin/busctl"
    };
    let output = irlume_common::process::output_until(
        Command::new(bus).args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Service",
            "ExecStart",
        ]),
        Instant::now() + Duration::from_millis(500),
    )
    .map_err(|_| "could not read prospective LightDM command within deadline")?;
    if !output.status.success() {
        return Err("could not read prospective LightDM command".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid ExecStart response")?;
    if value["type"] != "a(sasbttttuii)" {
        return Err("unsupported ExecStart response type".into());
    }
    let commands = value["data"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("expected one LightDM command")?;
    let row = commands[0]
        .as_array()
        .filter(|a| a.len() == 10)
        .ok_or("invalid LightDM command")?;
    let executable = row[0].as_str().ok_or("invalid LightDM executable")?;
    let valid_executable = matches!(executable, "/usr/bin/lightdm" | "/usr/sbin/lightdm")
        || (executable.starts_with("/nix/store/")
            && executable.ends_with("/bin/lightdm")
            && !executable.contains("/../"));
    if !valid_executable {
        return Err("unsupported LightDM executable; cannot prove its configuration".into());
    }
    let argv: Vec<&str> = row[1]
        .as_array()
        .ok_or("invalid LightDM argv")?
        .iter()
        .map(|v| v.as_str().ok_or("invalid LightDM argument"))
        .collect::<Result<_, _>>()?;
    if argv.first().copied() != Some(executable)
        || argv.len() > 64
        || argv.contains(&"--session-child")
    {
        return Err("unsupported LightDM argv".into());
    }
    // LightDM 1.32 handles --show-config before starting logging, servers,
    // sessions or devices. Preserve its actual config arguments, including -c.
    let mut policy = observe_configuration(executable, &argv[1..])?;
    policy.unit = unit.into();
    Ok(policy)
}

fn unit_stopped(unit: &str) -> bool {
    if !matches!(unit, "lightdm.service" | "display-manager.service") {
        return false;
    }
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        unit.replace('-', "_2d").replace('.', "_2e")
    );
    let bus = if Path::new("/usr/bin/busctl").exists() {
        "/usr/bin/busctl"
    } else {
        "/run/current-system/sw/bin/busctl"
    };
    let Ok(output) = irlume_common::process::output_until(
        Command::new(bus).args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Unit",
            "ActiveState",
        ]),
        Instant::now() + Duration::from_millis(500),
    ) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return false;
    };
    output.status.success()
        && value["type"] == "s"
        && matches!(value["data"].as_str(), Some("inactive" | "failed"))
}

fn observe_configuration(executable: &str, arguments: &[&str]) -> Result<Policy, String> {
    let pin = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(executable)
        .map_err(|e| e.to_string())?;
    trusted(&pin.metadata().map_err(|e| e.to_string())?, false)?;
    let output = irlume_common::process::output_until(
        Command::new(executable)
            .args(arguments)
            .arg("--show-config"),
        Instant::now() + Duration::from_millis(500),
    )
    .map_err(|_| "LightDM configuration observation exceeded deadline")?;
    if !output.status.success() {
        return Err("LightDM refused configuration observation".into());
    }
    parse_configuration(
        std::str::from_utf8(&output.stderr).map_err(|_| "non-UTF8 LightDM configuration")?,
    )
}

fn parse_configuration(text: &str) -> Result<Policy, String> {
    // --show-config is a human format. GLib unescapes newlines in values;
    // they must not impersonate sections/keys (or an early Sources header).
    // Verify all reported inputs and refuse that ambiguous output domain.
    let (settings, sources) = text
        .rsplit_once("\nSources:\n")
        .ok_or("incomplete LightDM configuration observation")?;
    for (count, line) in sources.lines().filter(|line| !line.is_empty()).enumerate() {
        if count >= MAX_FILES {
            return Err("too many LightDM configuration sources".into());
        }
        let (id, path) = line
            .split_once(char::is_whitespace)
            .ok_or("invalid LightDM source record")?;
        let path = path.trim_start();
        if !id.bytes().all(|b| b.is_ascii_alphanumeric())
            || !path.starts_with('/')
            || path.contains('\r')
        {
            return Err("invalid LightDM source record".into());
        }
        let raw =
            read_regular(Path::new(path))?.ok_or("LightDM configuration source disappeared")?;
        if raw.contains("\\n") || raw.contains("\\r") || raw.contains(['\0', '\r']) {
            return Err("LightDM configuration has ambiguous escaped line breaks".into());
        }
    }
    let mut policy = Policy {
        version: 1,
        blocked: false,
        services: BTreeSet::new(),
        permit: "pam_permit.so".into(),
        unit: "lightdm.service".into(),
        session_module: String::new(),
    };
    let mut defaults = BTreeMap::from([
        ("pam-service", "lightdm"),
        ("pam-autologin-service", "lightdm-autologin"),
        ("pam-greeter-service", "lightdm-greeter"),
    ]);
    let mut section = "";
    for line in settings.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let (_, assignment) = line
            .split_once(char::is_whitespace)
            .ok_or("invalid LightDM configuration output")?;
        let (key, value) = assignment
            .trim_start()
            .split_once('=')
            .ok_or("invalid LightDM assignment")?;
        if matches!(section, "XDMCPServer" | "VNCServer") && key == "enabled" {
            // Invalid values cannot license a local-only view.
            policy.blocked |= !matches!(value, "false" | "0");
        }
        if section.starts_with("Seat:") && defaults.contains_key(key) {
            if !service_name(value) {
                return Err("unsupported LightDM PAM service name".into());
            }
            policy.services.insert(value.into());
            if section == "Seat:*" {
                defaults.insert(key, value);
            }
        }
    }
    policy
        .services
        .extend(defaults.values().map(|value| (*value).to_string()));
    Ok(policy)
}

#[derive(Default)]
struct Graph {
    text: BTreeMap<String, String>,
    source: BTreeMap<PathBuf, String>,
    active: BTreeSet<String>,
    paths: BTreeMap<String, PathBuf>,
}

impl Graph {
    fn load(&mut self, name: &str) -> Result<(), String> {
        if !service_name(name) {
            return Err("unsupported PAM include target".into());
        }
        if self.active.contains(name) {
            return Err("cyclic PAM include graph".into());
        }
        if self.text.contains_key(name) {
            return Ok(());
        }
        if self.text.len() + self.active.len() >= MAX_FILES || self.active.len() >= 32 {
            return Err("PAM include graph exceeds limit".into());
        }
        let machine = Path::new("/etc/pam.d").join(name);
        let (path, text) = match read_regular(&machine)? {
            Some(text) => (machine, text),
            None => {
                let vendor = Path::new("/usr/lib/pam.d").join(name);
                let text =
                    read_regular(&vendor)?.ok_or_else(|| format!("missing PAM service {name}"))?;
                (vendor, text)
            }
        };
        if has_line_continuation(&text) || unreadable_line(&text).is_some() {
            return Err(format!("unsupported PAM grammar in {name}"));
        }
        self.active.insert(name.into());
        for line in text.lines() {
            if let Some(target) = include_target(line) {
                self.load(target)?;
            }
        }
        self.active.remove(name);
        self.paths.insert(name.into(), path.clone());
        self.source.insert(path, text.clone());
        self.text.insert(name.into(), text);
        Ok(())
    }

    fn verify(&self) -> Result<(), String> {
        for (path, text) in &self.source {
            if read_regular(path)?.as_ref() != Some(text) {
                return Err("PAM source changed during preparation".into());
            }
            if path.starts_with("/usr/lib/pam.d")
                && fs::symlink_metadata(Path::new("/etc/pam.d").join(path.file_name().unwrap()))
                    .is_ok()
            {
                return Err("PAM precedence changed during preparation".into());
            }
        }
        Ok(())
    }
}

fn include_target(line: &str) -> Option<&str> {
    at_include_target(line).or_else(|| head(line).as_ref().and_then(stack_name))
}

fn render(text: &str, names: &BTreeMap<String, String>, permit: &str) -> Result<String, String> {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if let Some(target) = include_target(line) {
            let replacement = names.get(target).ok_or("unresolved PAM include")?;
            let at = target.as_ptr() as usize - line.as_ptr() as usize;
            out.push_str(&line[..at]);
            out.push_str(replacement);
            out.push_str(&line[at + target.len()..]);
        } else if directive_has_auth_module(line, "pam_fprintd.so")
            || irlume_auth_rule_beyond_reseal(line)
        {
            let rule = rule(line).ok_or("unreadable biometric PAM rule")?;
            if !control_ignores_module_ignore(rule.control) {
                return Err("biometric rule has a non-inert PAM_IGNORE action".into());
            }
            out.push_str(&format!(
                "auth [default=ignore] {permit} # irlume remote-seat inactive slot"
            ));
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    Ok(out)
}

fn write(path: &Path, text: &str, label: Option<&[u8]>) -> Result<(), String> {
    let old = read_regular(path)?;
    if old.as_deref() == Some(text) {
        return Ok(());
    }
    files::write_private_checked(path, text, old.as_deref(), label).map_err(String::from)
}

fn publish(policy: &Policy) -> Result<(), String> {
    let view = Path::new(VIEW);
    directory(view)?;
    let mut graph = Graph::default();
    for name in &policy.services {
        graph.load(name)?;
    }
    let first = policy.services.first().ok_or("no LightDM PAM service")?;
    let label = security_label(&graph.paths[first])?;
    if label.is_none() && Path::new("/sys/fs/selinux/enforce").exists() {
        return Err("cannot preserve PAM SELinux labeling".into());
    }
    let encoded = serde_json::to_vec(&(policy, &graph.text, &label)).map_err(|e| e.to_string())?;
    let generation = crate::logintx::sha256_hex(&encoded);
    let names: BTreeMap<_, _> = graph
        .text
        .keys()
        .enumerate()
        .map(|(index, name)| (name.clone(), format!("{PREFIX}{generation}-{index}")))
        .collect();
    let prepared: BTreeMap<_, _> = if policy.blocked {
        graph
            .text
            .iter()
            .map(|(name, text)| Ok((name.clone(), render(text, &names, &policy.permit)?)))
            .collect::<Result<_, String>>()?
    } else {
        graph.text.clone()
    };
    // Old generation files remain until reboot: libpam may still be loading
    // one. Bound the retained cache rather than deleting a live include target.
    let used = fs::read_dir(view)
        .map_err(|e| e.to_string())?
        .take(8193)
        .try_fold((0usize, 0u64), |(count, bytes), entry| {
            let meta = fs::symlink_metadata(entry.map_err(|e| e.to_string())?.path())
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((count + 1, bytes.saturating_add(meta.len())))
        })?;
    if used.0 > 8192 || used.1 + encoded.len() as u64 > MAX_VIEW {
        return Err("LightDM PAM view cache is full; reboot required".into());
    }
    graph.verify()?;
    if policy.blocked {
        for (name, text) in &prepared {
            write(&view.join(&names[name]), text, label.as_deref())?;
        }
    }
    // Mirror ordinary names through a host-directory bind, not frozen copies.
    // This also preserves local fingerprint use in desktop descendants that
    // inherit LightDM's mount namespace.
    let mut count = 0;
    for entry in fs::read_dir("/etc/pam.d").map_err(|e| e.to_string())? {
        count += 1;
        if count > 1024 {
            return Err("too many PAM service entries".into());
        }
        let name = entry.map_err(|e| e.to_string())?.file_name();
        let Some(name) = name.to_str() else {
            return Err("non-UTF8 PAM service name".into());
        };
        if !service_name(name) || policy.services.contains(name) {
            continue;
        }
        let destination = view.join(name);
        let target = Path::new(SOURCE).join(name);
        match fs::read_link(&destination) {
            Ok(existing) if existing == target => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::os::unix::fs::symlink(target, destination).map_err(|e| e.to_string())?;
            }
            _ => return Err("unexpected entry in LightDM PAM view".into()),
        }
    }
    graph.verify()?;
    for name in &policy.services {
        // First in the session phase, so no original jump changes its landing
        // and no earlier session success can skip restoration of the host view.
        let root = format!(
            "session [success=ignore default=die] {}\n{}",
            policy.session_module, prepared[name]
        );
        write(&view.join(name), &root, label.as_deref())?;
    }
    Ok(())
}

fn retain_session_module(requested: Option<&str>) -> Result<String, String> {
    const MAX_MODULE: u64 = 16 * 1024 * 1024;
    let standard = [
        "/usr/lib64/security/pam_irlume_view.so",
        "/usr/lib/security/pam_irlume_view.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_irlume_view.so",
        "/lib/x86_64-linux-gnu/security/pam_irlume_view.so",
    ];
    let path = requested
        .or_else(|| standard.into_iter().find(|p| Path::new(p).is_file()))
        .ok_or("the matching pam_irlume_view.so session module is not installed")?;
    if !path.starts_with('/')
        || path.bytes().any(|b| b.is_ascii_whitespace())
        || !path.ends_with("/pam_irlume_view.so")
    {
        return Err("invalid session module path".into());
    }
    let file = open_regular(Path::new(path))?.ok_or("missing session module")?;
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_MODULE {
        return Err("session module exceeds size limit".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_MODULE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_MODULE {
        return Err("session module exceeds size limit".into());
    }
    let hash = crate::logintx::sha256_hex(&bytes);
    let target = Path::new(RUN).join(format!("session-{hash}.so"));
    if let Some(existing) = open_regular(&target)? {
        let mut old = Vec::new();
        existing
            .take(MAX_MODULE + 1)
            .read_to_end(&mut old)
            .map_err(|e| e.to_string())?;
        if old != bytes {
            return Err("retained session module was modified".into());
        }
    } else {
        let used = fs::read_dir(RUN)
            .map_err(|e| e.to_string())?
            .take(257)
            .try_fold((0usize, 0u64), |(count, size), entry| {
                let entry = entry.map_err(|e| e.to_string())?;
                let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
                Ok::<_, String>((count + 1, size.saturating_add(meta.len())))
            })?;
        if used.0 > 256 || used.1 + bytes.len() as u64 > 64 * 1024 * 1024 {
            return Err("retained session module cache is full; reboot required".into());
        }
        let label = security_label(Path::new(path))?;
        files::write_private_bytes_checked(&target, &bytes, None, label.as_deref())
            .map_err(String::from)?;
    }
    Ok(target.to_string_lossy().into_owned())
}
