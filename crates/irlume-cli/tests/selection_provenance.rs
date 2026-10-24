// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Positive real-CLI checks for the coordinator's externally verified sandbox.
//! The host entry point runs only the external isolation tool. CLI execution
//! and fixture setup happen after its mount, library and descriptor preflight.

use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn run_isolated() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output_dir = std::env::temp_dir().join(format!(
        "irlume-provenance-wrapper-{}-{nonce}",
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&output_dir)
        .unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new("python3");
    command
        .arg(repository.join("scripts/ci/isolated-cli.py"))
        .arg("--subject")
        .arg(std::env::current_exe().unwrap())
        .arg("--cli")
        .arg(env!("CARGO_BIN_EXE_irlume"))
        .arg("--receipt")
        .arg(output_dir.join("receipt.json"))
        .arg("--schema")
        .arg(repository.join("schemas/machine-api-v1.schema.json"))
        .args([
            "--",
            "--exact",
            "isolated_selection_provenance_real_cli_positive_health_cases",
            "--nocapture",
        ])
        .stdin(Stdio::null());
    let output = irlume_common::process::output_until(
        &mut command,
        Instant::now() + Duration::from_secs(300),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "isolation or positive provenance check failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["returncode"], 0);
    assert_eq!(receipt["preflight"]["empty_root"], true);
    assert_eq!(receipt["preflight"]["inherited_fds_absent"], true);
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    std::fs::remove_dir_all(output_dir).unwrap();
}

fn verified_fixture_root() -> PathBuf {
    assert_eq!(
        std::env::var("IRLUME_PROVENANCE_TEST_CLI").as_deref(),
        Ok("/work/irlume"),
        "requires the coordinator's verified empty-root sandbox"
    );
    assert_eq!(std::env::current_exe().unwrap(), Path::new("/work/subject"));
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        mounts.lines().any(|line| {
            let Some((before, after)) = line.split_once(" - ") else {
                return false;
            };
            before.split_whitespace().nth(4) == Some("/")
                && after.split_whitespace().next() == Some("tmpfs")
        }),
        "the sandbox must start from an empty tmpfs root"
    );
    assert_eq!(
        std::fs::read_dir("/sys").unwrap().count(),
        0,
        "host sysfs must not be exposed"
    );
    for entry in std::fs::read_dir("/dev").unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !["video", "media", "tpm", "dri", "accel"]
                .iter()
                .any(|prefix| name.starts_with(prefix)),
            "host device exposed"
        );
    }
    for path in [
        "/run/irlume.sock",
        "/run/dbus/system_bus_socket",
        "/var/lib/irlume",
        "/usr/share/irlume/models",
        "/host",
    ] {
        assert!(!Path::new(path).exists(), "host state exposed: {path}");
    }
    let root = PathBuf::from("/work/state/selection-provenance");
    std::fs::create_dir(&root).unwrap();
    root
}

struct MockHealth {
    stop: Arc<AtomicBool>,
    health_calls: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

impl MockHealth {
    fn start(socket: &Path, health: Value) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_calls = Arc::clone(&health_calls);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !worker_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                let mut line = String::new();
                BufReader::new((&mut stream).take(4096)).read_line(&mut line)?;
                let request: Value = serde_json::from_str(&line)?;
                let reply = if request == json!("Ping") {
                    json!("Pong")
                } else if request == json!("Health") {
                    worker_calls.fetch_add(1, Ordering::Relaxed);
                    health.clone()
                } else {
                    json!({"Error":"selection provenance fixture"})
                };
                writeln!(stream, "{reply}")?;
            }
            Ok(())
        });
        Self {
            stop,
            health_calls,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> usize {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap();
        self.health_calls.load(Ordering::Relaxed)
    }
}

impl Drop for MockHealth {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_cli(directory: &Path, socket: &Path, subcommand: &str) -> Value {
    let binary = std::env::var_os("IRLUME_PROVENANCE_TEST_CLI")
        .expect("sandbox CLI path supplied by coordinator");
    let mut command = Command::new(binary);
    command
        .args([subcommand, "--json"])
        .env_clear()
        .env("HOME", "/home/fixture")
        .env("TMPDIR", directory)
        .env("PATH", "/bin:/usr/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("ASAN_OPTIONS", "detect_stack_use_after_return=1")
        .env("IRLUME_SOCKET", socket)
        .env("IRLUME_CONFIG_DIR", directory.join("config"))
        .env("IRLUME_STATE_DIR", directory.join("state"));
    // SAFETY: the child only marks descriptors close-on-exec before exec; this
    // syscall does not allocate or use locks in the post-fork child. Standard
    // streams remain open, and the exec-error pipe can report any exec failure.
    unsafe {
        command.pre_exec(|| {
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) == -1
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let output = irlume_common::process::output_until(
        &mut command,
        Instant::now() + Duration::from_secs(20),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{subcommand} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        document["ok"], true,
        "positive command envelope required: {document}"
    );
    document
}

#[test]
fn isolated_selection_provenance_real_cli_positive_health_cases() {
    if std::env::var_os("IRLUME_PROVENANCE_TEST_CLI").is_none() {
        run_isolated();
        return;
    }
    let root = verified_fixture_root();
    for (name, provenance, expected, detail) in [
        (
            "present",
            Some(json!({"source":"environment","issue":"invalid_value"})),
            Some(json!({"source":"environment","issue":"invalid_value"})),
            "source: environment; issue: invalid value",
        ),
        ("legacy", None, None, "source not reported"),
        (
            "future",
            Some(json!({"source":"future-source","issue":"future-issue"})),
            Some(json!({"source":"unknown","issue":"unknown"})),
            "source: unknown; issue: unknown",
        ),
        (
            "malformed",
            Some(json!({"source":false,"issue":"none"})),
            None,
            "the daemon did not answer",
        ),
        (
            "unknown-placement",
            None,
            None,
            "the daemon predates this report",
        ),
    ] {
        let directory = root.join(name);
        std::fs::create_dir(&directory).unwrap();
        std::fs::create_dir(directory.join("config")).unwrap();
        std::fs::create_dir(directory.join("state")).unwrap();
        let socket = directory.join("daemon.sock");
        let mut placement = json!({"device":"cpu","reason":"fixture CPU","selection":"auto"});
        if let Some(provenance) = provenance {
            placement["selection_provenance"] = provenance;
        }
        if name == "unknown-placement" {
            placement = Value::Null;
        }
        let server = MockHealth::start(
            &socket,
            json!({"Health": {
                "tier":"none", "rgb_dev":null, "ir_dev":null, "mesh":false,
                "adapter":false, "version":"0.15.0", "recognizer":placement
            }}),
        );
        let status = run_cli(&directory, &socket, "status");
        let doctor = run_cli(&directory, &socket, "doctor");
        assert!(
            server.finish() >= 2,
            "both commands must consume mock Health"
        );
        let recognizer = &status["data"]["recognizer"];
        if matches!(name, "malformed" | "unknown-placement") {
            assert_eq!(recognizer, &json!({"known":false}));
        } else {
            assert_eq!(recognizer["known"], true);
            assert_eq!(recognizer["device"], "cpu");
            assert_eq!(recognizer["selection"], "auto");
            assert_eq!(recognizer.get("selection_provenance"), expected.as_ref());
        }
        let row = doctor["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "recognizer-selection")
            .unwrap();
        if matches!(name, "malformed" | "unknown-placement") {
            assert_eq!(row["state"], "unknown");
            // The existing absent-Health branches may have no selection detail.
            let device = doctor["data"]["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == "recognizer-device")
                .unwrap();
            assert!(device["detail"].as_str().unwrap().contains(detail));
        } else {
            assert_eq!(row["state"], "info");
            assert!(row["detail"].as_str().unwrap().contains(detail));
        }
        // Coordinator validates these synthetic documents against the schema
        // outside the sandbox; it must not rerun the CLI on the host.
        std::fs::write(
            directory.join("status.json"),
            serde_json::to_vec(&status).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("doctor.json"),
            serde_json::to_vec(&doctor).unwrap(),
        )
        .unwrap();
        println!(
            "PROVENANCE_DOCUMENT {}",
            json!({"case":name,"command":"status","output":status})
        );
        println!(
            "PROVENANCE_DOCUMENT {}",
            json!({"case":name,"command":"doctor","output":doctor})
        );
    }
}
