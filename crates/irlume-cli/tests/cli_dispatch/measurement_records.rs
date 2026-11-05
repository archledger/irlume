// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub(super) const SHARED: &str = "/var/lib/irlume";

pub(super) fn command(sb: &Sandbox, args: &[&str]) -> Command {
    let original = support::isolated_root_command(
        &sb.root,
        BIN,
        args,
        &[],
        &[],
        &[(&sb.path("state"), SHARED)],
    );
    // A nested user namespace sees the host-owned / as unmapped uid 65534.
    // Use a caller-owned fixture root so ancestry validation is not bypassed.
    let rootfs = sb.path("measurement-rootfs");
    for name in [
        "usr",
        "etc",
        "lib",
        "lib64",
        "run",
        "proc",
        "dev",
        "root",
        "tmp",
        "var/lib/irlume",
    ] {
        std::fs::create_dir_all(rootfs.join(name)).unwrap();
    }
    for name in ["bin", "sbin"] {
        if std::fs::symlink_metadata(rootfs.join(name)).is_err() {
            std::os::unix::fs::symlink(format!("usr/{name}"), rootfs.join(name)).unwrap();
        }
    }
    std::fs::create_dir_all(rootfs.join(sb.root.strip_prefix("/").unwrap())).unwrap();
    let binary = rootfs.join(Path::new(BIN).strip_prefix("/").unwrap());
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::File::create(&binary).unwrap();
    let mut argv: Vec<std::ffi::OsString> = original.get_args().map(Into::into).collect();
    let root_bind = argv
        .windows(3)
        .position(|part| part == ["--ro-bind", "/", "/"])
        .unwrap();
    argv[root_bind + 1] = rootfs.clone().into_os_string();
    let mut mounts: Vec<std::ffi::OsString> = Vec::new();
    for path in ["/usr", "/etc", "/lib", "/lib64", BIN] {
        if Path::new(path).exists() {
            mounts.extend(["--ro-bind".into(), path.into(), path.into()]);
        }
    }
    argv.splice(root_bind + 3..root_bind + 3, mounts);
    prepare_mountpoints(&rootfs, &argv);
    let mut command = Command::new(original.get_program());
    command
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in original.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    command.env("IRLUME_STATE_DIR", SHARED);
    command
}

fn prepare_mountpoints(root: &Path, args: &[std::ffi::OsString]) {
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].to_string_lossy();
        if flag == "--" {
            break;
        }
        let (target, is_dir, consumed) = match flag.as_ref() {
            "--bind" | "--ro-bind" => (&args[index + 2], Path::new(&args[index + 1]).is_dir(), 3),
            "--tmpfs" | "--dev" | "--proc" | "--dir" => (&args[index + 1], true, 2),
            _ => {
                index += 1;
                continue;
            }
        };
        let relative = Path::new(target)
            .strip_prefix("/")
            .expect("absolute mount target");
        assert!(!relative
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)));
        if !relative.as_os_str().is_empty() {
            let path = root.join(relative);
            if is_dir {
                std::fs::create_dir_all(path).unwrap();
            } else {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)
                    .unwrap();
            }
        }
        index += consumed;
    }
}

#[test]
fn namespace_fixture_prepares_dynamic_hidden_directories() {
    let sb = Sandbox::new("dynamic-measurement-mountpoints");
    let root = sb.path("root");
    std::fs::create_dir(&root).unwrap();
    prepare_mountpoints(
        &root,
        &[
            "--tmpfs".into(),
            "/home/hidden-account".into(),
            "--ro-bind".into(),
            BIN.into(),
            "/opt/bin/fixture".into(),
        ],
    );
    assert!(root.join("home/hidden-account").is_dir());
    assert!(root.join("opt/bin/fixture").is_file());
}

pub(super) fn disk_path(state: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(SHARED)
        .map_or_else(|_| path.to_path_buf(), |leaf| state.join(leaf))
}

struct Verification {
    code: i32,
    error: String,
    requests: usize,
    emitted: Option<PathBuf>,
    parent_mode: Option<u32>,
    parent_remains: bool,
}

fn invoke(sb: &Sandbox, args: &[&str], fresh: Option<String>, success: bool) -> Verification {
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    let emitted = Arc::new(Mutex::new(None));
    let output = emitted.clone();
    let parent_mode = Arc::new(Mutex::new(None));
    let mode = parent_mode.clone();
    let written = Arc::new(Mutex::new(None));
    let owned = written.clone();
    let state = sb.path("state");
    serve(&sb.sock(), move |request| match request {
        Request::TuneCaptureMode {
            emit_record_path, ..
        } => {
            seen.fetch_add(1, Ordering::SeqCst);
            if let Some(path) = emit_record_path {
                let path = PathBuf::from(path);
                let local = disk_path(&state, &path);
                *mode.lock().unwrap() = local.parent().and_then(|parent| {
                    std::fs::metadata(parent)
                        .ok()
                        .map(|m| m.permissions().mode() & 0o777)
                });
                if let Some(text) = &fresh {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&local)
                        .unwrap();
                    file.write_all(text.as_bytes()).unwrap();
                    let metadata = file.metadata().unwrap();
                    *owned.lock().unwrap() = Some((local, metadata.dev(), metadata.ino()));
                }
                *output.lock().unwrap() = Some(path);
            }
            if success {
                Response::Ok("synthetic measurement".into())
            } else {
                Response::Error("synthetic measurement failure".into())
            }
        }
        _ => Response::Error("unexpected request".into()),
    });
    let (code, _, error) = run(&mut command(sb, args), "measurement verification boundary");
    let emitted = emitted.lock().unwrap().clone();
    let parent_remains = emitted
        .as_ref()
        .map(|p| disk_path(&sb.path("state"), p))
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .is_some_and(|p| p.exists());
    // Remove only a file this fake created exclusively and still identifies.
    // Never delete a path solely because the CLI returned a familiar name.
    if let Some((path, device, inode)) = written.lock().unwrap().as_ref() {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            assert!(metadata.is_file() && metadata.dev() == *device && metadata.ino() == *inode);
            std::fs::remove_file(path).unwrap();
        }
    }
    let parent_mode = *parent_mode.lock().unwrap();
    Verification {
        code,
        error,
        requests: requests.load(Ordering::SeqCst),
        emitted,
        parent_mode,
        parent_remains,
    }
}

fn valid_text() -> String {
    serde_json::to_string(&[measurement_report_record(true, Some(25_000))]).unwrap()
}

#[test]
fn invalid_reference_is_refused_before_any_tuning_request() {
    let mut invalid = measurement_report_record(true, Some(25_000));
    invalid.schema_version += 1;
    let mut nested = measurement_report_record(true, Some(25_000));
    nested.rates[0].1.rounds[0].timestamp_span_us = 0;
    let cases = [
        None,
        Some("not JSON".into()),
        Some(serde_json::to_string(&[invalid]).unwrap()),
        Some(serde_json::to_string(&[nested]).unwrap()),
    ];
    let mut failures = Vec::new();
    for (index, text) in cases.into_iter().enumerate() {
        let sb = Sandbox::new(&format!("invalid-reference-{index}"));
        let path = sb.path("work/reference.json");
        if let Some(text) = text {
            std::fs::write(&path, text).unwrap();
        }
        let result = invoke(
            &sb,
            &["camera-tune", "--verify-record", path.to_str().unwrap()],
            Some(valid_text()),
            true,
        );
        if result.code != 2 || result.requests != 0 {
            failures.push(format!(
                "case {index}: code {}, requests {}, {}",
                result.code, result.requests, result.error
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn invalid_or_missing_fresh_output_fails_verification() {
    let mut invalid = measurement_report_record(true, Some(25_000));
    invalid.rates[0].1.rounds[0].timestamp_span_us = 0;
    let cases = [
        None,
        Some("not JSON".into()),
        Some(serde_json::to_string(&[invalid]).unwrap()),
    ];
    let mut failures = Vec::new();
    for (index, text) in cases.into_iter().enumerate() {
        let sb = Sandbox::new(&format!("invalid-fresh-{index}"));
        let path = sb.path("work/reference.json");
        std::fs::write(&path, valid_text()).unwrap();
        let result = invoke(
            &sb,
            &["camera-tune", "--verify-record", path.to_str().unwrap()],
            text,
            true,
        );
        if result.code != 1 || result.requests != 1 || result.error.contains("drift vs") {
            failures.push(format!(
                "case {index}: code {}, requests {}, {}",
                result.code, result.requests, result.error
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn fresh_output_uses_a_private_shared_state_directory_and_is_removed() {
    let sb = Sandbox::new("shared-measurement-output");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    let result = invoke(
        &sb,
        &["camera-tune", "--verify-record", path.to_str().unwrap()],
        Some(valid_text()),
        true,
    );
    assert_eq!(result.code, 0, "{}", result.error);
    assert_eq!(result.requests, 1);
    assert!(result.emitted.unwrap().starts_with(SHARED));
    assert_eq!(result.parent_mode, Some(0o700));
    assert!(!result.parent_remains);
}

#[test]
fn a_failed_tuning_response_is_not_followed_by_comparison() {
    let sb = Sandbox::new("failed-measurement-output");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    let result = invoke(
        &sb,
        &["camera-tune", "--verify-record", path.to_str().unwrap()],
        Some(valid_text()),
        false,
    );
    assert_eq!(result.code, 1, "{}", result.error);
    assert!(!result.error.contains("drift vs"), "{}", result.error);
    assert!(
        !result.parent_remains,
        "failed operation left its private directory"
    );
}

#[test]
fn combined_emit_and_verify_is_rejected_before_tuning() {
    let sb = Sandbox::new("conflicting-measurement-options");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    let result = invoke(
        &sb,
        &[
            "camera-tune",
            "--verify-record",
            path.to_str().unwrap(),
            "--emit-record",
            "export.json",
        ],
        Some(valid_text()),
        true,
    );
    assert_eq!(result.code, 2, "{}", result.error);
    assert_eq!(result.requests, 0);
    assert!(!sb.path("work/export.json").exists());
}

#[test]
fn the_reference_is_not_reread_after_tuning() {
    let sb = Sandbox::new("cached-measurement-reference");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    let replace = path.clone();
    let state = sb.path("state");
    serve(&sb.sock(), move |request| match request {
        Request::TuneCaptureMode {
            emit_record_path: Some(output),
            rounds,
        } => {
            assert_eq!(*rounds, Some(1));
            std::fs::write(&replace, "replaced while measuring").unwrap();
            let output = disk_path(&state, Path::new(output));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output)
                .unwrap();
            file.write_all(valid_text().as_bytes()).unwrap();
            Response::Ok("measured".into())
        }
        _ => Response::Error("unexpected request".into()),
    });
    let (code, _, error) = run(
        &mut command(
            &sb,
            &[
                "camera-tune",
                "--rounds",
                "4",
                "--verify-record",
                path.to_str().unwrap(),
            ],
        ),
        "cached reference",
    );
    assert_eq!(code, 0, "{error}");
    assert!(error.contains("p50 30.0 -> 30.0"), "{error}");
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "replaced while measuring"
    );
    assert_eq!(std::fs::read_dir(sb.path("state")).unwrap().count(), 0);
}

#[test]
fn separate_verifications_do_not_reuse_the_output_directory() {
    let sb = Sandbox::new("unique-measurement-output");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    let args = ["camera-tune", "--verify-record", path.to_str().unwrap()];
    let first = invoke(&sb, &args, Some(valid_text()), true);
    let second = invoke(&sb, &args, Some(valid_text()), true);
    assert_eq!(first.code, 0, "{}", first.error);
    assert_eq!(second.code, 0, "{}", second.error);
    assert_ne!(first.emitted, second.emitted);
}

#[test]
fn explicit_export_resolves_symlinks_without_overwriting_existing_files() {
    let sb = Sandbox::new("measurement-export-paths");
    std::os::unix::fs::symlink(SHARED, sb.path("work/shared")).unwrap();
    std::os::unix::fs::symlink("/tmp", sb.path("work/private-tmp")).unwrap();
    let result = invoke(
        &sb,
        &["camera-tune", "--emit-record", "shared/export.json"],
        Some(valid_text()),
        true,
    );
    assert_eq!(result.code, 0, "{}", result.error);
    assert_eq!(
        result.emitted,
        Some(PathBuf::from("/var/lib/irlume/export.json"))
    );
    let existing = sb.path("state/existing.json");
    std::fs::write(&existing, "keep me").unwrap();
    std::os::unix::fs::symlink("absent", sb.path("state/dangling")).unwrap();
    for path in [
        "shared/existing.json",
        "shared/dangling",
        "shared/missing/output",
        "shared/",
        "/tmp/forbidden.json",
        "/var/tmp/forbidden.json",
        "private-tmp/forbidden.json",
    ] {
        let result = invoke(&sb, &["camera-tune", "--emit-record", path], None, true);
        assert_eq!(result.code, 2, "{path}: {}", result.error);
        assert_eq!(result.requests, 0, "{path}");
    }
    assert_eq!(std::fs::read_to_string(existing).unwrap(), "keep me");
    assert!(std::fs::symlink_metadata(sb.path("state/dangling"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn private_temp_state_root_fails_without_tuning_or_fallback() {
    let sb = Sandbox::new("private-temp-state");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    serve(&sb.sock(), move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Response::Error("must not tune".into())
    });
    let (code, _, error) = run(
        &mut sb.cmd(&["camera-tune", "--verify-record", path.to_str().unwrap()]),
        "private temp refusal",
    );
    assert_eq!(code, 1, "{error}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(sb.path("state")).unwrap().count(), 0);
}

#[test]
fn another_accounts_writable_ancestor_is_not_a_shared_output_root() {
    let sb = Sandbox::new("untrusted-shared-ancestor");
    let path = sb.path("work/reference.json");
    std::fs::write(&path, valid_text()).unwrap();
    // The state leaf remains caller-owned and private, but the ancestor is not trusted.
    let ancestor = sb.path("measurement-rootfs/var");
    std::fs::create_dir_all(&ancestor).unwrap();
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(sb.path("state"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut cmd = command(
        &sb,
        &["camera-tune", "--verify-record", path.to_str().unwrap()],
    );
    let (code, _, error) = run(&mut cmd, "untrusted shared ancestor");
    assert_eq!(code, 1, "{error}");
    assert!(
        error.contains("untrusted shared-state ancestor: /var"),
        "{error}"
    );
    assert_eq!(std::fs::read_dir(sb.path("state")).unwrap().count(), 0);
}
