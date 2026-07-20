//! Black-box tests of the `irlume` binary: argument dispatch, usage errors,
//! exit codes, and the offline failure paths of every daemon-backed command.
//!
//! Every invocation runs inside a sandbox: `IRLUME_SOCKET` points at a path
//! nothing listens on (so no request can ever reach a real `irlumed`),
//! `IRLUME_CONFIG_DIR` / `IRLUME_STATE_DIR` / `IRLUME_KEYRING_DIR` point at a
//! per-test temp tree, and system tools the CLI shells out to (journalctl,
//! rpm, curl, semodule, ...) are PATH-shadowed with fake scripts. No test
//! touches the network, a camera, the TPM, or the machine's package database.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_irlume");

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Per-test sandbox tree; dropped (deleted) when the test ends.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("irlume-cli-it-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["cfg", "state", "keyring", "bin", "work"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Sandbox { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Drop a fake `#!/bin/sh` executable into the sandbox bin dir.
    fn fake_tool(&self, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = self.root.join("bin").join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A Command for the irlume binary, isolated from the host system.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .env("IRLUME_SOCKET", self.root.join("no-daemon.sock"))
            .env("IRLUME_CONFIG_DIR", self.root.join("cfg"))
            .env("IRLUME_STATE_DIR", self.root.join("state"))
            .env("IRLUME_KEYRING_DIR", self.root.join("keyring"))
            .env("IRLUME_METHOD_CONF", self.root.join("cfg").join("method"))
            .env_remove("IRLUME_DEV")
            .env_remove("ORT_DYLIB_PATH")
            .env_remove("IRLUME_MODEL")
            .env_remove("IRLUME_DET_MODEL")
            .current_dir(self.root.join("work"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// Like `cmd`, but with the sandbox bin dir prepended to PATH so fake
    /// tools shadow the real ones.
    fn cmd_with_fakes(&self, args: &[&str]) -> Command {
        let mut c = self.cmd(args);
        c.env(
            "PATH",
            format!(
                "{}:{}",
                self.root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        c
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Run and collect (exit code, stdout, stderr).
fn run(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.output().expect("spawn irlume");
    (
        out.status.code().expect("no exit code (signal?)"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run with `input` piped to stdin.
fn run_stdin(cmd: &mut Command, input: &str) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::piped()).spawn().expect("spawn irlume");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait irlume");
    (
        out.status.code().expect("no exit code (signal?)"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------- version/help

#[test]
fn version_prints_the_crate_version_for_all_spellings() {
    let sb = Sandbox::new("version");
    for spelling in ["version", "--version", "-V"] {
        let (code, out, _) = run(&mut sb.cmd(&[spelling]));
        assert_eq!(code, 0, "`irlume {spelling}` exit code");
        assert_eq!(
            out.trim(),
            format!("irlume {}", env!("CARGO_PKG_VERSION")),
            "`irlume {spelling}` output"
        );
    }
}

#[test]
fn help_lists_every_public_command_and_hides_dev_tools() {
    let sb = Sandbox::new("help");
    // `help`, `--help`, `-h`, and no arguments all print the same listing.
    for args in [&["help"][..], &["--help"], &["-h"], &[]] {
        let (code, out, _) = run(&mut sb.cmd(args));
        assert_eq!(code, 0, "help exit code for {args:?}");
        for cmd in [
            "tui",
            "setup",
            "status",
            "detect",
            "doctor",
            "deps",
            "enroll",
            "profiles",
            "identify",
            "keyring",
            "reseal",
            "recovery",
            "diag",
            "login",
            "logs",
            "fingerprint",
            "selinux",
            "ir-setup",
            "set-cameras",
            "models",
            "update",
            "uninstall",
            "version",
        ] {
            assert!(out.contains(cmd), "help must list `{cmd}`");
        }
        assert!(
            out.contains("IRLUME_DEV=1"),
            "help must mention the dev gate"
        );
        for hidden in ["calcapture", "irbench", "padcapture", "normprobe"] {
            assert!(
                !out.contains(hidden),
                "help must not leak the dev tool `{hidden}`"
            );
        }
    }
}

#[test]
fn unknown_command_errors_with_exit_2() {
    let sb = Sandbox::new("unknown");
    let (code, _, err) = run(&mut sb.cmd(&["frobnicate"]));
    assert_eq!(code, 2);
    assert!(
        err.contains("unknown command 'frobnicate'"),
        "stderr: {err}"
    );
    assert!(err.contains("irlume help"), "must point at help: {err}");
}

// ------------------------------------------------------------------ dev gating

const DEV_CMDS: &[&str] = &[
    "capture",
    "eval",
    "irbench",
    "genuine",
    "calcapture",
    "normprobe",
    "liveness",
    "meshprobe",
    "selftest",
    "padcapture",
    "padreport",
    "verify",
    "enrolldev",
    "suncal",
];

#[test]
fn dev_commands_are_gated_without_irlume_dev() {
    let sb = Sandbox::new("devgate");
    for cmd in DEV_CMDS {
        let (code, _, err) = run(&mut sb.cmd(&[cmd]));
        assert_eq!(code, 2, "`{cmd}` must be blocked without IRLUME_DEV");
        assert!(
            err.contains(cmd) && err.contains("developer/benchmark tool"),
            "`{cmd}` gate message: {err}"
        );
        assert!(
            err.contains("IRLUME_DEV=1"),
            "`{cmd}` gate must name the unlock env: {err}"
        );
        assert!(
            !err.contains("usage:"),
            "`{cmd}` must not reach its own arg parsing when gated: {err}"
        );
    }
}

#[test]
fn dev_commands_with_env_reach_their_usage_errors() {
    let sb = Sandbox::new("devusage");
    // (argv, expected exit code, fragment the usage line must carry). Every
    // fragment is a real flag or literal from the command's own usage text.
    let table: &[(&[&str], i32, &str)] = &[
        (&["capture"], 2, "usage: irlume capture --det"),
        (&["eval"], 2, "usage: irlume eval --image"),
        (&["irbench"], 2, "usage: irlume irbench --dir"),
        (&["genuine"], 2, "usage: irlume genuine --det"),
        (&["calcapture"], 2, "--out <cal.jsonl>"),
        (&["normprobe"], 2, "usage: irlume normprobe --dir"),
        (&["liveness"], 2, "usage: irlume liveness --det"),
        (&["meshprobe"], 2, "usage: irlume meshprobe --det"),
        (&["verify"], 2, "usage: irlume verify --user U --det"),
        (&["enrolldev"], 2, "usage: irlume enrolldev --user U --det"),
        (&["padcapture"], 2, "usage: irlume padcapture --species"),
        (&["padreport"], 2, "usage: irlume padreport --in"),
        (&["suncal"], 1, "usage: IRLUME_DEV=1 irlume suncal"),
        (
            &["selftest", "align"],
            2,
            "usage: irlume selftest align --model",
        ),
    ];
    for (argv, want, fragment) in table {
        let (code, _, err) = run(sb.cmd(argv).env("IRLUME_DEV", "1"));
        assert_eq!(code, *want, "exit code for {argv:?}: {err}");
        assert!(err.contains(fragment), "{argv:?} usage text: {err}");
    }
}

#[test]
fn selftest_without_align_is_an_unknown_command() {
    let sb = Sandbox::new("selftest");
    let (code, _, err) = run(sb.cmd(&["selftest"]).env("IRLUME_DEV", "1"));
    assert_eq!(code, 2);
    assert!(err.contains("unknown command 'selftest'"), "stderr: {err}");
}

#[test]
fn padcapture_validates_kind_and_path_values() {
    let sb = Sandbox::new("padargs");
    let (code, _, err) = run(sb
        .cmd(&[
            "padcapture",
            "--species",
            "s",
            "--kind",
            "maybe",
            "--det",
            "d",
            "--out",
            "o",
        ])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 2);
    assert!(
        err.contains("--kind must be 'attack' or 'bonafide'"),
        "{err}"
    );

    let (code, _, err) = run(sb
        .cmd(&[
            "padcapture",
            "--species",
            "s",
            "--kind",
            "attack",
            "--det",
            "d",
            "--out",
            "o",
            "--path",
            "weird",
        ])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 2);
    assert!(err.contains("--path must be 'full' or 'ir-only'"), "{err}");
}

#[test]
fn irbench_rejects_an_empty_dataset_before_loading_models() {
    let sb = Sandbox::new("irbench");
    let empty = sb.path("work");
    let dir = empty.to_str().unwrap();
    let (code, _, err) = run(sb
        .cmd(&["irbench", "--dir", dir, "--det", "x", "--model", "y"])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 1);
    assert!(err.contains("no jpg/png/bmp images under"), "{err}");

    // Impostor-only (farbench) mode has its own floor: at least two images.
    let (code, _, err) = run(sb
        .cmd(&[
            "irbench",
            "--dir",
            dir,
            "--det",
            "x",
            "--model",
            "y",
            "--impostor-only",
        ])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 1);
    assert!(err.contains("need >=2 images"), "{err}");
}

#[test]
fn eval_and_capture_report_an_unreadable_image() {
    let sb = Sandbox::new("badimage");
    let missing = sb.path("work/nope.jpg");
    let img = missing.to_str().unwrap();
    for argv in [
        vec!["eval", "--image", img, "--det", "d", "--model", "m"],
        vec!["capture", "--image", img, "--det", "d", "--model", "m"],
    ] {
        let (code, _, err) = run(sb.cmd(&argv).env("IRLUME_DEV", "1"));
        assert_eq!(code, 1, "{argv:?}");
        assert!(err.contains("image load failed"), "{argv:?}: {err}");
    }
}

#[test]
fn suncal_reports_a_missing_detector_model() {
    let sb = Sandbox::new("suncal");
    let dataset = sb.path("work");
    let (code, _, err) = run(sb
        .cmd(&["suncal", "/nonexistent/det.onnx", dataset.to_str().unwrap()])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 1);
    assert!(err.contains("load detector"), "{err}");
}

// -------------------------------------------------------------------- profiles

#[test]
fn profiles_usage_errors_exit_2() {
    let sb = Sandbox::new("profusage");
    let cases: &[&[&str]] = &[
        &["profiles", "bogus"],
        &["profiles", "add-scan"],
        &["profiles", "delete"],
        &["profiles", "rename", "--profile", "P"],
        &["profiles", "eyes-open"],
        &["profiles", "eyes-open", "on", "off"],
        &["profiles", "challenge"],
    ];
    for argv in cases {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 2, "{argv:?} should be a usage error: {err}");
        assert!(err.contains("usage:"), "{argv:?}: {err}");
    }
    // The full usage text names the real subcommands and flags.
    let (_, _, err) = run(&mut sb.cmd(&["profiles", "bogus"]));
    for frag in [
        "add-scan --profile P",
        "rename --profile P [--scan S] --name N",
        "delete --profile P [--scan S]",
        "eyes-open <on|off>",
        "challenge <on|off>",
    ] {
        assert!(
            err.contains(frag),
            "profiles usage must name `{frag}`: {err}"
        );
    }
}

#[test]
fn profiles_valid_subcommands_build_requests_and_fail_without_a_daemon() {
    let sb = Sandbox::new("profreq");
    // Each of these parses cleanly, constructs the daemon request, and then
    // fails at the (dead) socket with exit 1, never a usage error.
    let cases: &[&[&str]] = &[
        &["profiles"],
        &["profiles", "list"],
        &["profiles", "add-scan", "--profile", "P"],
        &["profiles", "delete", "--profile", "P"],
        &["profiles", "delete", "--profile", "P", "--scan", "S"],
        &["profiles", "rename", "--profile", "P", "--name", "N"],
        &[
            "profiles",
            "rename",
            "--profile",
            "P",
            "--scan",
            "S",
            "--name",
            "N",
        ],
        &["profiles", "eyes-open", "on"],
        &["profiles", "challenge", "off"],
    ];
    for argv in cases {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 1, "{argv:?}: {err}");
        assert!(
            err.contains("irlumed is not running"),
            "{argv:?} must have reached the socket: {err}"
        );
        assert!(!err.contains("usage:"), "{argv:?} parsed fine: {err}");
    }
}

// ---------------------------------------------------------- daemon-backed cmds

#[test]
fn enroll_fails_cleanly_without_a_daemon() {
    let sb = Sandbox::new("enroll");
    let (code, _, err) = run(&mut sb.cmd(&[
        "enroll", "--user", "tester", "--name", "Work", "--scans", "3", "--reset",
    ]));
    assert_eq!(code, 1);
    assert!(err.contains("[enroll] --reset: wiping 'tester'"), "{err}");
    assert!(err.contains("capturing a new face profile"), "{err}");
    assert!(err.contains("irlumed is not running"), "{err}");
}

#[test]
fn keyring_usage_and_daemon_failures() {
    let sb = Sandbox::new("keyring");
    let (code, _, err) = run(&mut sb.cmd(&["keyring"]));
    assert_eq!(code, 2);
    assert!(
        err.contains("usage: irlume keyring <arm|status|forget>"),
        "{err}"
    );

    // Piped empty stdin: the arm aborts before any request is built.
    let (code, _, err) = run_stdin(&mut sb.cmd(&["keyring", "arm", "--user", "tester"]), "");
    assert_eq!(code, 2);
    assert!(err.contains("empty password; aborted"), "{err}");

    // A piped password reaches the (dead) socket and reports the failure.
    let (code, out, err) = run_stdin(
        &mut sb.cmd(&["keyring", "arm", "--user", "tester"]),
        "sekrit\n",
    );
    assert_eq!(code, 1);
    assert!(
        out.contains("Arming face-driven keyring unlock for 'tester'"),
        "{out}"
    );
    assert!(
        err.contains("arm failed") && err.contains("irlumed is not running"),
        "{err}"
    );

    let (code, _, err) = run(&mut sb.cmd(&["keyring", "status", "--user", "tester"]));
    assert_eq!(code, 1);
    assert!(err.contains("status failed"), "{err}");

    let (code, _, err) = run(&mut sb.cmd(&["keyring", "forget", "--user", "tester"]));
    assert_eq!(code, 1);
    assert!(err.contains("forget failed"), "{err}");
}

#[test]
fn recovery_usage_and_daemon_failures() {
    let sb = Sandbox::new("recovery");
    let (code, _, err) = run(&mut sb.cmd(&["recovery", "bogus"]));
    assert_eq!(code, 2);
    assert!(
        err.contains("usage: irlume recovery <status|setup|restore|forget>"),
        "{err}"
    );

    let (code, _, err) = run(&mut sb.cmd(&["recovery", "status", "--user", "tester"]));
    assert_eq!(code, 1);
    assert!(err.contains("status failed"), "{err}");

    let (code, _, err) = run_stdin(
        &mut sb.cmd(&["recovery", "setup", "--user", "tester"]),
        "passphrase\n",
    );
    assert_eq!(code, 1);
    assert!(err.contains("setup failed"), "{err}");

    // Restore with an empty piped passphrase aborts before any request.
    let (code, _, err) = run_stdin(
        &mut sb.cmd(&["recovery", "restore", "--user", "tester"]),
        "",
    );
    assert_eq!(code, 2);
    assert!(err.contains("empty passphrase; aborted"), "{err}");

    let (code, _, err) = run_stdin(
        &mut sb.cmd(&["recovery", "restore", "--user", "tester"]),
        "passphrase\n",
    );
    assert_eq!(code, 1);
    assert!(err.contains("restore failed"), "{err}");

    let (code, _, err) = run(&mut sb.cmd(&["recovery", "forget", "--user", "tester"]));
    assert_eq!(code, 1);
    assert!(err.contains("forget failed"), "{err}");
}

#[test]
fn set_cameras_usage_and_daemon_failure() {
    let sb = Sandbox::new("setcam");
    let (code, _, err) = run(&mut sb.cmd(&["set-cameras"]));
    assert_eq!(code, 2);
    assert!(
        err.contains("usage: irlume set-cameras <rgb-node> <ir-node>"),
        "{err}"
    );
    // One node is not enough either.
    let (code, _, _) = run(&mut sb.cmd(&["set-cameras", "/dev/video0"]));
    assert_eq!(code, 2);

    let (code, _, err) = run(&mut sb.cmd(&["set-cameras", "/dev/video0", "/dev/video2"]));
    assert_eq!(code, 1);
    assert!(
        err.contains("[set-cameras]") && err.contains("irlumed is not running"),
        "{err}"
    );
}

#[test]
fn ir_setup_daemon_failure_and_dry_run_skip_the_probe_banner() {
    let sb = Sandbox::new("irsetup");
    let (code, _, err) = run(&mut sb.cmd(&["ir-setup"]));
    assert_eq!(code, 1);
    assert!(err.contains("probing the IR camera"), "{err}");
    assert!(err.contains("[ir-setup]"), "{err}");

    let (code, _, err) = run(&mut sb.cmd(&["ir-setup", "--dry-run"]));
    assert_eq!(code, 1);
    assert!(
        !err.contains("probing the IR camera"),
        "--dry-run must not print the probe banner: {err}"
    );
}

#[test]
fn identify_reports_the_daemon_error() {
    let sb = Sandbox::new("identify");
    let (code, _, err) = run(&mut sb.cmd(&["identify"]));
    assert_eq!(code, 1);
    assert!(err.contains("irlumed is not running"), "{err}");
}

#[test]
fn reseal_requires_a_reachable_daemon() {
    let sb = Sandbox::new("reseal");
    let (code, _, err) = run(&mut sb.cmd(&["reseal", "--user", "tester"]));
    assert_eq!(code, 1);
    assert!(err.contains("[reseal] daemon unreachable"), "{err}");
}

#[test]
fn setup_stops_at_the_preflight_without_a_daemon() {
    let sb = Sandbox::new("setup");
    let (code, out, err) = run(&mut sb.cmd(&["setup", "--user", "tester"]));
    assert_eq!(code, 1);
    assert!(out.contains("=== irlume setup for 'tester' ==="), "{out}");
    assert!(
        err.contains("daemon not reachable; start it first"),
        "{err}"
    );
}

#[test]
fn status_reports_an_unreachable_daemon_and_defaults() {
    let sb = Sandbox::new("status");
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]));
    assert_eq!(
        code, 0,
        "status always exits 0 (it reports, it doesn't gate)"
    );
    assert!(out.contains("irlume status for 'tester'"), "{out}");
    assert!(out.contains("NOT reachable"), "{out}");
    assert!(
        out.contains("Auto"),
        "method file absent must read Auto: {out}"
    );
    assert!(
        out.contains("enrollment    : unknown (daemon unreachable)"),
        "{out}"
    );
    assert!(out.contains("keyring unlock: unknown"), "{out}");
    assert!(out.contains("biopolicy     : off (default)"), "{out}");
}

#[test]
fn detect_never_reports_ready_without_a_daemon() {
    let sb = Sandbox::new("detect");
    let (code, out, _) = run(&mut sb.cmd(&["detect", "--user", "tester"]));
    // 20 = irlumed binary absent from this machine, 10 = installed but the
    // daemon is down; either way a dead socket must never yield 0/"ready".
    match code {
        10 => assert!(out.starts_with("partial:"), "{out}"),
        20 => assert!(out.starts_with("absent:"), "{out}"),
        other => panic!("detect returned {other} with a dead daemon: {out}"),
    }
}

#[test]
fn diag_falls_back_to_the_daemon_summary_and_reports_unknown() {
    let sb = Sandbox::new("diag");
    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("irlume diag for 'tester'"), "{out}");
    // No envelope in the sandboxed keyring dir + dead socket:
    assert!(
        out.contains("seal envelope : unknown (daemon unreachable)"),
        "{out}"
    );
}

#[test]
fn doctor_runs_fully_offline_with_a_source_origin() {
    let sb = Sandbox::new("doctor");
    // No package manager owns irlume in the sandbox: every probe tool fails.
    for tool in ["rpm", "dnf", "dpkg-query", "apt-cache", "pacman"] {
        sb.fake_tool(tool, "exit 1");
    }
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["doctor"]));
    assert_eq!(code, 0);
    assert!(out.contains("[doctor] platform:"), "{out}");
    assert!(
        out.contains("install origin: source / dev install"),
        "fake package managers must yield a source origin: {out}"
    );
    assert!(out.contains("TPM 2.0:"), "{out}");
    assert!(out.contains("camera nodes"), "{out}");
    assert!(out.contains("[doctor] models:"), "{out}");
    assert!(out.contains("glintr100.onnx"), "{out}");
    assert!(out.contains("face_detection_yunet_2023mar.onnx"), "{out}");
    assert!(out.contains("ORT_DYLIB_PATH: (unset)"), "{out}");
    assert!(
        out.contains("third-party PAD model: none (default"),
        "empty sandbox config/state must report no third-party model: {out}"
    );
    assert!(out.contains("unknown (daemon not reachable"), "{out}");
}

#[test]
fn deps_reports_every_probe() {
    let sb = Sandbox::new("deps");
    let (code, out, _) = run(&mut sb.cmd(&["deps"]));
    assert!(code == 0 || code == 1, "deps exits 0 or 1, got {code}");
    for probe in ["onnxruntime", "glintr100.onnx", "TPM", "camera (v4l)"] {
        assert!(out.contains(probe), "deps must report `{probe}`: {out}");
    }
    assert!(out.contains("deps:"), "{out}");
}

// ------------------------------------------------------------------------ logs

#[test]
fn logs_assembles_the_journalctl_argv() {
    let sb = Sandbox::new("logsargv");
    // The fake journalctl echoes one argument per line.
    sb.fake_tool("journalctl", r#"printf '%s\n' "$@""#);
    const PATTERN: &str = "irlume|pam_kwallet|pam_gnome_keyring";

    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["logs"]));
    assert_eq!(code, 0);
    let args: Vec<&str> = out.lines().collect();
    assert_eq!(
        args,
        ["--no-pager", "-g", PATTERN, "-b"],
        "default view = this boot"
    );

    for follow in ["-f", "--follow"] {
        let (code, out, _) = run(&mut sb.cmd_with_fakes(&["logs", follow]));
        assert_eq!(code, 0);
        let args: Vec<&str> = out.lines().collect();
        assert_eq!(args, ["--no-pager", "-g", PATTERN, "-f"], "{follow} view");
    }

    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["logs", "--since", "10 min ago"]));
    assert_eq!(code, 0);
    let args: Vec<&str> = out.lines().collect();
    assert_eq!(
        args,
        ["--no-pager", "-g", PATTERN, "--since", "10 min ago"],
        "--since must forward its value and drop the -b default"
    );
}

#[test]
fn logs_option_errors_never_run_journalctl() {
    let sb = Sandbox::new("logserr");
    sb.fake_tool("journalctl", r#"printf 'JOURNALCTL RAN\n'"#);

    let (code, out, err) = run(&mut sb.cmd_with_fakes(&["logs", "--since"]));
    assert_eq!(code, 1);
    assert!(err.contains("--since needs a value"), "{err}");
    assert!(
        !out.contains("JOURNALCTL RAN"),
        "must not have run journalctl"
    );

    let (code, out, err) = run(&mut sb.cmd_with_fakes(&["logs", "--bogus"]));
    assert_eq!(code, 1);
    assert!(err.contains("unknown option '--bogus'"), "{err}");
    assert!(
        !out.contains("JOURNALCTL RAN"),
        "must not have run journalctl"
    );
}

#[test]
fn logs_propagates_a_journalctl_failure() {
    let sb = Sandbox::new("logsfail");
    sb.fake_tool("journalctl", "exit 3");
    let (code, _, _) = run(&mut sb.cmd_with_fakes(&["logs"]));
    assert_eq!(code, 1);
}

#[test]
fn logs_debug_status_and_root_guards() {
    let sb = Sandbox::new("logsdebug");
    let (code, out, _) = run(&mut sb.cmd(&["logs", "debug"]));
    assert_eq!(code, 0);
    assert!(out.contains("daemon diagnostic tracing"), "{out}");

    if !is_root() {
        for action in ["on", "off"] {
            let (code, _, err) = run(&mut sb.cmd(&["logs", "debug", action]));
            assert_eq!(code, 1, "debug {action} must need root");
            assert!(err.contains("needs root"), "{err}");
        }
    }

    let (code, _, err) = run(&mut sb.cmd(&["logs", "debug", "bogus"]));
    assert_eq!(code, 1);
    assert!(err.contains("unknown: 'debug bogus'"), "{err}");
}

// ---------------------------------------------------------------------- models

#[test]
fn models_list_reports_catalog_and_enablement_states() {
    let sb = Sandbox::new("modelslist");
    // Default: nothing enabled in the sandbox config.
    let (code, out, _) = run(&mut sb.cmd(&["models"]));
    assert_eq!(code, 0);
    assert!(out.contains("flir"), "catalog entry must be listed: {out}");
    assert!(out.contains("[disabled]"), "{out}");
    assert!(out.contains("none enabled"), "{out}");

    // Enabled in settings.conf but weights never fetched.
    std::fs::write(sb.path("cfg/settings.conf"), "third_party_pad=flir\n").unwrap();
    let (code, out, _) = run(&mut sb.cmd(&["models", "list"]));
    assert_eq!(code, 0);
    assert!(out.contains("ENABLED (weights not fetched)"), "{out}");
    assert!(out.contains("enabled: flir"), "{out}");

    // Weights present but not matching the pinned checksum.
    let tp = sb.path("state/models-thirdparty");
    std::fs::create_dir_all(&tp).unwrap();
    std::fs::write(tp.join("flir.onnx"), b"not the pinned bytes").unwrap();
    let (code, out, _) = run(&mut sb.cmd(&["models", "list"]));
    assert_eq!(code, 0);
    assert!(out.contains("CHECKSUM MISMATCH"), "{out}");
}

#[test]
fn models_usage_and_guards() {
    let sb = Sandbox::new("modelsguard");
    let (code, _, err) = run(&mut sb.cmd(&["models", "bogus"]));
    assert_eq!(code, 2);
    assert!(err.contains("usage: irlume models"), "{err}");

    let (code, _, _) = run(&mut sb.cmd(&["models", "enable"]));
    assert_eq!(code, 2, "enable without a name is a usage error");

    let (code, _, err) = run(&mut sb.cmd(&["models", "enable", "nope"]));
    assert_eq!(code, 1);
    assert!(err.contains("'nope' is not in the catalog"), "{err}");

    if !is_root() {
        let (code, _, err) = run(&mut sb.cmd(&["models", "enable", "flir"]));
        assert_eq!(code, 1);
        assert!(err.contains("needs root"), "{err}");

        let (code, _, err) = run(&mut sb.cmd(&["models", "disable"]));
        assert_eq!(code, 1);
        assert!(err.contains("needs root"), "{err}");
    }
}

// ----------------------------------------------------------- uninstall/selinux

#[test]
fn uninstall_requires_root() {
    if is_root() {
        return; // the guard under test only exists for unprivileged callers
    }
    let sb = Sandbox::new("uninstall");
    let (code, _, err) = run(&mut sb.cmd(&["uninstall"]));
    assert_eq!(code, 1);
    assert!(err.contains("needs root: sudo irlume uninstall"), "{err}");
}

#[test]
fn selinux_status_classifies_module_state_from_probe_output() {
    let sb = Sandbox::new("selinux");
    // Loaded: semodule lists the module and the socket carries our label.
    sb.fake_tool("semodule", r#"printf 'irlume\nother\n'"#);
    sb.fake_tool(
        "ls",
        r#"printf 'system_u:object_r:irlume_runtime_t:s0 /run/irlume.sock\n'"#,
    );
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["selinux", "status"]));
    assert_eq!(code, 0);
    assert!(out.contains("module 'irlume': loaded"), "{out}");

    // Listed modules but ours absent, and no socket label: not loaded.
    sb.fake_tool("semodule", r#"printf 'somethingelse\n'"#);
    sb.fake_tool("ls", "exit 2");
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["selinux", "status"]));
    assert_eq!(code, 0);
    assert!(out.contains("not loaded"), "{out}");

    // semodule prints nothing (non-root): state is unknown, not "not loaded".
    sb.fake_tool("semodule", "exit 1");
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["selinux", "status"]));
    assert_eq!(code, 0);
    assert!(out.contains("unknown"), "{out}");

    let (code, _, err) = run(&mut sb.cmd(&["selinux", "bogus"]));
    assert_eq!(code, 1);
    assert!(err.contains("unknown subcommand 'bogus'"), "{err}");
}

// ----------------------------------------------------------------- fingerprint

#[test]
fn fingerprint_status_and_usage() {
    let sb = Sandbox::new("fingerprint");
    let (code, _, err) = run(&mut sb.cmd(&["fingerprint", "bogus"]));
    assert_eq!(code, 2);
    assert!(
        err.contains("usage: irlume fingerprint [--user U] <status|add|enable|disable>"),
        "{err}"
    );

    let (code, out, _) = run(&mut sb.cmd(&["fingerprint", "status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("fprintd tooling"), "{out}");
    assert!(out.contains("active method"), "{out}");

    if !is_root() {
        let (code, _, err) = run(&mut sb.cmd(&["fingerprint", "disable"]));
        assert_eq!(code, 1);
        assert!(
            err.contains("run with: sudo irlume fingerprint disable"),
            "{err}"
        );
    }
}

// ---------------------------------------------------------------------- update

#[test]
fn update_uses_fake_probes_and_reports_per_scenario() {
    let sb = Sandbox::new("update");
    // No package manager owns irlume: origin resolves to source on any distro.
    for tool in ["rpm", "dnf", "dpkg-query", "apt-cache", "pacman"] {
        sb.fake_tool(tool, "exit 1");
    }

    // Scenario 1: a newer release is out.
    sb.fake_tool(
        "curl",
        r#"printf '%s' '{"tag_name": "v99.99.99", "assets": [{"name": "irlume_99.99.99_amd64.deb"}]}'"#,
    );
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update", "--check"]));
    assert_eq!(code, 0);
    assert!(
        out.contains(&format!(
            "[update] installed: {}",
            env!("CARGO_PKG_VERSION")
        )),
        "source installs fall back to the binary's own version: {out}"
    );
    assert!(
        out.contains("install method: source / dev install"),
        "{out}"
    );
    assert!(out.contains("available: v99.99.99"), "{out}");
    assert!(
        out.contains("Source install. Update the checkout at the tag:"),
        "{out}"
    );
    assert!(out.contains("git checkout v99.99.99"), "{out}");
    assert!(out.contains("Release notes:"), "{out}");

    // Scenario 2: already up to date.
    sb.fake_tool("curl", r#"printf '%s' '{"tag_name": "v0.0.1"}'"#);
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update", "--check"]));
    assert_eq!(code, 0);
    assert!(
        out.contains("up to date (latest release is v0.0.1)"),
        "{out}"
    );

    // Scenario 3: offline; degrade without updating anything.
    sb.fake_tool("curl", "exit 7");
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update", "--check"]));
    assert_eq!(code, 0);
    assert!(out.contains("couldn't reach the release feed"), "{out}");
}

// ------------------------------------------------------------------- padreport

const PAD_FIXTURE: &str = r#"{"species":"print_matte","kind":"attack","path":"full","verdict":"Spoof","caught":["ir_reflectance"]}
{"species":"print_matte","kind":"attack","path":"full","verdict":"Spoof","caught":["ir_reflectance"]}
{"species":"print_matte","kind":"attack","path":"full","verdict":"Live","caught":[]}
{"species":"phone_replay","kind":"attack","path":"ir-only","verdict":"Uncertain","caught":[]}
{"species":"bonafide","kind":"bonafide","path":"full","verdict":"Live","caught":[]}
{"species":"bonafide","kind":"bonafide","path":"full","verdict":"Live","caught":[]}
{"species":"bonafide","kind":"bonafide","path":"full","verdict":"Live","caught":[]}
{"species":"bonafide","kind":"bonafide","path":"full","verdict":"Spoof","caught":[]}
this line is not json
{"species":"x","kind":"weird","verdict":"Live"}
"#;

#[test]
fn padreport_aggregates_a_fixture_into_iso_metrics() {
    let sb = Sandbox::new("padreport");
    let jsonl = sb.path("work/pad.jsonl");
    std::fs::write(&jsonl, PAD_FIXTURE).unwrap();
    let md = sb.path("work/pad.md");

    let (code, out, err) = run(sb
        .cmd(&[
            "padreport",
            "--in",
            jsonl.to_str().unwrap(),
            "--md",
            md.to_str().unwrap(),
        ])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 0, "stderr: {err}");

    // Malformed lines are skipped loudly, not silently.
    assert!(err.contains("skipping malformed line 9"), "{err}");
    assert!(err.contains("skipping line 10"), "{err}");

    // 4 attacks / 4 bona fide, both gate paths seen.
    assert!(out.contains("attack presentations: 4"), "{out}");
    assert!(out.contains("bona-fide: 4"), "{out}");
    assert!(out.contains("full, ir-only"), "{out}");

    // print_matte: 1 accepted of 3 -> APCER 33.3%, caught twice by reflectance.
    assert!(out.contains("print_matte"), "{out}");
    assert!(out.contains("33.3%"), "{out}");
    assert!(out.contains("ir_reflectance:2"), "{out}");
    // phone_replay: the Uncertain outcome is non-response, not acceptance.
    assert!(out.contains("100.0%"), "phone_replay non-response: {out}");
    // Headlines: worst APCER, BPCER 1/4, ACER (33.3 + 25.0)/2.
    assert!(out.contains("WORST-CASE APCER: print_matte"), "{out}");
    assert!(out.contains("25.0%"), "BPCER: {out}");
    assert!(out.contains("(n=4)"), "{out}");
    assert!(out.contains("29.2%"), "ACER: {out}");

    // The markdown twin carries the same numbers plus the honesty note.
    let md_text = std::fs::read_to_string(&md).unwrap();
    assert!(md_text.contains("| print_matte | 3 | 33.3% |"), "{md_text}");
    assert!(md_text.contains("**Worst-case APCER:**"), "{md_text}");
    assert!(md_text.contains("**BPCER:** 25.0%"), "{md_text}");
    assert!(md_text.contains("not a lab-accredited"), "{md_text}");
    assert!(out.contains("wrote markdown report"), "{out}");
}

#[test]
fn padreport_with_attacks_only_flags_the_missing_bonafide_baseline() {
    let sb = Sandbox::new("padnobf");
    let jsonl = sb.path("work/attacks.jsonl");
    std::fs::write(
        &jsonl,
        r#"{"species":"cutout","kind":"attack","path":"full","verdict":"Spoof","caught":["depth"]}
"#,
    )
    .unwrap();
    let (code, out, _) = run(sb
        .cmd(&["padreport", "--in", jsonl.to_str().unwrap()])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 0);
    assert!(out.contains("no bona-fide presentations captured"), "{out}");
    assert!(out.contains("n/a"), "BPCER with den=0 renders n/a: {out}");
    assert!(out.contains("WORST-CASE APCER: cutout"), "{out}");
}

#[test]
fn padreport_input_errors() {
    let sb = Sandbox::new("paderr");
    let (code, _, err) = run(sb
        .cmd(&["padreport", "--in", "/nonexistent/pad.jsonl"])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 1);
    assert!(err.contains("cannot read"), "{err}");

    let empty = sb.path("work/empty.jsonl");
    std::fs::write(&empty, "").unwrap();
    let (code, _, err) = run(sb
        .cmd(&["padreport", "--in", empty.to_str().unwrap()])
        .env("IRLUME_DEV", "1"));
    assert_eq!(code, 1);
    assert!(err.contains("no usable records"), "{err}");
}

// ------------------------------------------------------------- fake daemon

use irlume_common::{ProfileSummary, Request, Response};

/// Serve canned responses on the sandbox socket (same line-JSON protocol as
/// `irlumed`: one request per connection). Returns a log of every parsed
/// request so tests can assert exactly what the CLI sent. The accept thread
/// is detached; it ends with the test process, and the socket file lives in
/// the sandbox, which is deleted on drop.
fn serve(
    sock: &std::path::Path,
    respond: impl Fn(&Request) -> Response + Send + 'static,
) -> std::sync::Arc<std::sync::Mutex<Vec<Request>>> {
    use std::io::{BufRead, BufReader};
    let _ = std::fs::remove_file(sock);
    let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let thread_log = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            let Ok(req) = serde_json::from_str::<Request>(&line) else {
                continue;
            };
            let mut reply = serde_json::to_string(&respond(&req)).unwrap();
            reply.push('\n');
            thread_log.lock().unwrap().push(req);
            let _ = (&stream).write_all(reply.as_bytes());
        }
    });
    log
}

/// The socket path a Sandbox's commands connect to.
fn sock(sb: &Sandbox) -> PathBuf {
    sb.path("no-daemon.sock")
}

#[test]
fn keyring_success_paths_with_a_live_daemon() {
    let sb = Sandbox::new("keyringok");
    let log = serve(&sock(&sb), |req| match req {
        Request::SealPassword { .. } => Response::PasswordSealed,
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        Request::ForgetPassword { .. } => Response::PasswordForgotten,
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run_stdin(
        &mut sb.cmd(&["keyring", "arm", "--user", "tester"]),
        "hunter2\n",
    );
    assert_eq!(code, 0);
    assert!(out.contains("armed. After a face login"), "{out}");
    assert!(
        out.contains("if you change your login password"),
        "the re-arm note must be shown: {out}"
    );

    let (code, out, _) = run(&mut sb.cmd(&["keyring", "status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("ARMED"), "{out}");

    let (code, out, _) = run(&mut sb.cmd(&["keyring", "forget", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(
        out.contains("sealed password erased; keyring unlock disarmed"),
        "{out}"
    );

    // The wire request carried the piped password for the right user.
    let log = log.lock().unwrap();
    let sealed = log
        .iter()
        .find_map(|r| match r {
            Request::SealPassword { user, password } => {
                Some((user.clone(), password.expose().to_vec()))
            }
            _ => None,
        })
        .expect("a SealPassword request was sent");
    assert_eq!(sealed.0, "tester");
    assert_eq!(sealed.1, b"hunter2");
}

#[test]
fn recovery_success_paths_with_a_live_daemon() {
    let sb = Sandbox::new("recoveryok");
    serve(&sock(&sb), |req| match req {
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: false,
            tpm_present: true,
        },
        Request::RecoverySetup { .. } => Response::Ok("recovery passphrase set".into()),
        Request::RecoveryRestore { .. } => Response::Ok("template key restored".into()),
        Request::RecoveryForget { .. } => Response::Ok("recovery envelope erased".into()),
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["recovery", "status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("templates encrypted : yes"), "{out}");
    assert!(out.contains("recovery passphrase : not set"), "{out}");
    assert!(out.contains("TPM present         : yes"), "{out}");
    assert!(
        out.contains("no backstop") && out.contains("irlume recovery setup"),
        "encrypted-but-no-passphrase must warn and name the fix: {out}"
    );

    let (code, out, _) = run_stdin(
        &mut sb.cmd(&["recovery", "setup", "--user", "tester"]),
        "correct horse\n",
    );
    assert_eq!(code, 0);
    assert!(out.contains("recovery passphrase set"), "{out}");

    let (code, out, _) = run_stdin(
        &mut sb.cmd(&["recovery", "restore", "--user", "tester"]),
        "correct horse\n",
    );
    assert_eq!(code, 0);
    assert!(out.contains("face unlock is restored"), "{out}");

    let (code, out, _) = run(&mut sb.cmd(&["recovery", "forget", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("recovery envelope erased"), "{out}");
}

#[test]
fn recovery_setup_error_names_the_enroll_first_remedy() {
    let sb = Sandbox::new("recoveryerr");
    serve(&sock(&sb), |_| {
        Response::Error("no template key for tester".into())
    });
    let (code, _, err) = run_stdin(
        &mut sb.cmd(&["recovery", "setup", "--user", "tester"]),
        "pass\n",
    );
    assert_eq!(code, 1);
    assert!(err.contains("setup failed: no template key"), "{err}");
    assert!(
        err.contains("enroll a face first"),
        "the no-template-key error must add the remedy hint: {err}"
    );
}

#[test]
fn profiles_listing_renders_profiles_and_toggle_state() {
    let sb = Sandbox::new("proflist");
    serve(&sock(&sb), |req| match req {
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: vec![ProfileSummary {
                name: "Face Profile 1".into(),
                scans: vec!["Scan 1".into(), "Glasses".into()],
            }],
            require_eyes_open: true,
            require_challenge: false,
        },
        Request::SetRequireEyesOpen { .. } => Response::Ok("eyes-open now ON".into()),
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("require-eyes-open: ON"), "{out}");
    assert!(out.contains("require-challenge (blink): off"), "{out}");
    assert!(out.contains("Face Profile 1 (2 scans)"), "{out}");
    assert!(out.contains("- Scan 1"), "{out}");
    assert!(out.contains("- Glasses"), "{out}");

    let (code, out, _) = run(&mut sb.cmd(&["profiles", "eyes-open", "on", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("[profiles] eyes-open now ON"), "{out}");
}

#[test]
fn profiles_empty_listing_says_none_enrolled() {
    let sb = Sandbox::new("profempty");
    serve(&sock(&sb), |_| Response::Enrollment {
        profiles: Vec::new(),
        require_eyes_open: false,
        require_challenge: false,
    });
    // Bare `profiles` (no subcommand) defaults to the listing. Note: a flag
    // directly after `profiles` is read as the subcommand word, so --user
    // only combines with an explicit `list`.
    let (code, out, _) = run(&mut sb.cmd(&["profiles"]));
    assert_eq!(code, 0);
    assert!(out.contains("[profiles] none enrolled"), "{out}");
    let (code, out, _) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("[profiles] none enrolled"), "{out}");
}

#[test]
fn enroll_reports_a_new_profile_and_forwards_the_flags() {
    let sb = Sandbox::new("enrollnew");
    let log = serve(&sock(&sb), |_| Response::Enrolled {
        profile: "Night".into(),
        created: true,
        added: 3,
        total: 3,
        added_scans: vec!["Scan 1".into(), "Scan 2".into(), "Scan 3".into()],
    });
    let (code, out, _) = run(&mut sb.cmd(&[
        "enroll", "--user", "tester", "--name", "Night", "--scans", "3",
    ]));
    assert_eq!(code, 0);
    assert!(out.contains("enrolled 'Night' with 3 scans"), "{out}");

    let log = log.lock().unwrap();
    match &log[0] {
        Request::Enroll {
            user,
            profile,
            scans,
            reset,
        } => {
            assert_eq!(user, "tester");
            assert_eq!(profile.as_deref(), Some("Night"));
            assert_eq!(*scans, Some(3));
            assert!(!reset, "--reset was not passed");
        }
        other => panic!("expected an Enroll request, got {other:?}"),
    }
}

#[test]
fn enroll_merge_points_at_add_scan() {
    let sb = Sandbox::new("enrollmerge");
    serve(&sock(&sb), |_| Response::Enrolled {
        profile: "Face Profile 1".into(),
        created: false,
        added: 2,
        total: 8,
        added_scans: vec!["Scan 7".into(), "Scan 8".into()],
    });
    let (code, out, _) = run(&mut sb.cmd(&["enroll", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(
        out.contains("already enrolled as 'Face Profile 1'"),
        "{out}"
    );
    assert!(out.contains("added 2 scans"), "{out}");
    assert!(out.contains("(8 total)"), "{out}");
    assert!(
        out.contains("profiles add-scan --profile 'Face Profile 1'"),
        "the merge message must name the follow-up command: {out}"
    );
}

#[test]
fn identify_reports_match_and_no_match() {
    let sb = Sandbox::new("identok");
    serve(&sock(&sb), |_| Response::Identified {
        user: Some("tester".into()),
        profile: Some("Face Profile 1".into()),
        score: 0.87,
        live: true,
        reason: "match".into(),
    });
    let (code, out, _) = run(&mut sb.cmd(&["identify"]));
    assert_eq!(code, 0);
    assert!(
        out.contains("tester (profile 'Face Profile 1', score 0.870)"),
        "{out}"
    );

    let sb2 = Sandbox::new("identmiss");
    serve(&sock(&sb2), |_| Response::Identified {
        user: None,
        profile: None,
        score: 0.1,
        live: true,
        reason: "below threshold".into(),
    });
    let (code, out, _) = run(&mut sb2.cmd(&["identify"]));
    assert_eq!(code, 1, "a live but unenrolled face is exit 1");
    assert!(
        out.contains("no match: live face, not enrolled (below threshold)"),
        "{out}"
    );
}

#[test]
fn status_renders_the_full_dashboard_from_daemon_answers() {
    let sb = Sandbox::new("statusok");
    serve(&sock(&sb), |req| match req {
        Request::Ping => Response::Pong,
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: vec![ProfileSummary {
                name: "Face Profile 1".into(),
                scans: vec!["Scan 1".into(), "Scan 2".into()],
            }],
            require_eyes_open: false,
            require_challenge: true,
        },
        Request::KeyringInfo { .. } => Response::KeyringInfo {
            armed: true,
            policy: Some("Tier 2 (pcrlock)".into()),
            pcrs: vec![7],
            drifted: Some(true),
        },
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("daemon        : running"), "{out}");
    assert!(out.contains("1 profile(s), 2 scan(s)"), "{out}");
    assert!(out.contains("passive blink liveness"), "{out}");
    assert!(out.contains("Face Profile 1 (2 scan(s))"), "{out}");
    assert!(out.contains("keyring unlock: armed"), "{out}");
    assert!(out.contains("Tier 2 (pcrlock)"), "{out}");
    assert!(
        out.contains("PCR DRIFT") && out.contains("keyring arm"),
        "drift must be flagged with its remedy: {out}"
    );
    assert!(out.contains("templates     : encrypted at rest"), "{out}");
    assert!(out.contains("recovery pass : set"), "{out}");
}

#[test]
fn reseal_rebinds_when_armed_and_refuses_when_not() {
    let sb = Sandbox::new("resealok");
    serve(&sock(&sb), |req| match req {
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        Request::SealPassword { .. } => Response::PasswordSealed,
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run_stdin(&mut sb.cmd(&["reseal", "--user", "tester"]), "pw\n");
    assert_eq!(code, 0);
    assert!(out.contains("re-bound to current PCRs"), "{out}");

    let sb2 = Sandbox::new("resealnone");
    serve(&sock(&sb2), |_| Response::HasPassword(false));
    let (code, _, err) = run(&mut sb2.cmd(&["reseal", "--user", "tester"]));
    assert_eq!(code, 2, "nothing sealed = usage-class refusal");
    assert!(err.contains("has no sealed password"), "{err}");
    assert!(
        err.contains("keyring arm"),
        "must name the setup command: {err}"
    );
}

#[test]
fn set_cameras_and_ir_setup_success_paths() {
    let sb = Sandbox::new("camok");
    let log = serve(&sock(&sb), |req| match req {
        Request::SetCameras { .. } => Response::Ok("cameras saved".into()),
        Request::SetupIrEmitter { .. } => Response::Ok("emitter enabled".into()),
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["set-cameras", "/dev/video0", "/dev/video2"]));
    assert_eq!(code, 0);
    assert!(out.contains("[set-cameras] cameras saved"), "{out}");

    let (code, out, _) = run(&mut sb.cmd(&["ir-setup", "--dry-run"]));
    assert_eq!(code, 0);
    assert!(out.contains("[ir-setup] emitter enabled"), "{out}");

    let log = log.lock().unwrap();
    assert!(
        matches!(&log[0], Request::SetCameras { rgb, ir } if rgb == "/dev/video0" && ir == "/dev/video2"),
        "cameras request must carry both nodes: {:?}",
        log[0]
    );
    assert!(
        matches!(&log[1], Request::SetupIrEmitter { dry_run: true }),
        "--dry-run must be forwarded: {:?}",
        log[1]
    );
}

#[test]
fn setup_walks_every_step_noninteractively() {
    let sb = Sandbox::new("setupok");
    serve(&sock(&sb), |req| match req {
        Request::Ping => Response::Pong,
        Request::Health => Response::Health {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: env!("CARGO_PKG_VERSION").into(),
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            require_challenge: false,
        },
        Request::Enroll { .. } => Response::Enrolled {
            profile: "Face Profile 1".into(),
            created: true,
            added: 6,
            total: 6,
            added_scans: Vec::new(),
        },
        Request::SealPassword { .. } => Response::PasswordSealed,
        _ => Response::Error("unexpected request".into()),
    });
    // Piped stdin: yes/no prompts take their defaults (enroll: yes, arm: yes),
    // and the keyring arm reads this line as the login password.
    let (code, out, _) = run_stdin(&mut sb.cmd(&["setup", "--user", "tester"]), "pw\n");
    assert_eq!(code, 0);
    assert!(out.contains("[1/6] Preflight"), "{out}");
    assert!(
        out.contains("enrolled 'Face Profile 1' with 6 scans"),
        "{out}"
    );
    assert!(out.contains("armed"), "{out}");
    assert!(out.contains("[6/6] PAM login wiring"), "{out}");
    assert!(out.contains("setup complete"), "{out}");
}

#[test]
fn unexpected_daemon_responses_are_reported_not_trusted() {
    let sb = Sandbox::new("pongdaemon");
    // A daemon that answers everything with Pong: every command must fail
    // loudly rather than treat it as success.
    serve(&sock(&sb), |_| Response::Pong);
    let cases: &[&[&str]] = &[
        &["keyring", "status", "--user", "tester"],
        &["profiles", "list", "--user", "tester"],
        &["enroll", "--user", "tester"],
        &["identify"],
        &["set-cameras", "/dev/video0", "/dev/video2"],
        &["ir-setup", "--dry-run"],
        &["recovery", "status", "--user", "tester"],
    ];
    for argv in cases {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 1, "{argv:?} must fail on a nonsense response");
        assert!(
            err.contains("unexpected response"),
            "{argv:?} stderr: {err}"
        );
    }
}

// --------------------------------------------------- repo-backed update paths

/// Minimal mirror of irlume_common::platform::distro_family (ID + ID_LIKE),
/// so this test can pick the branch that will actually run on this host.
fn host_family() -> &'static str {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |key: &str| -> String {
        os.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
    };
    let hay = format!("{} {}", field("ID="), field("ID_LIKE="));
    if ["debian", "ubuntu", "mint", "pop", "raspbian"]
        .iter()
        .any(|d| hay.contains(d))
    {
        "debian"
    } else if ["fedora", "rhel", "centos", "rocky", "alma"]
        .iter()
        .any(|d| hay.contains(d))
    {
        "fedora"
    } else if ["arch", "manjaro", "endeavouros", "garuda"]
        .iter()
        .any(|d| hay.contains(d))
    {
        "arch"
    } else {
        "other"
    }
}

/// Origin detection reads /etc/os-release (no seam), so each host exercises
/// its own family's branch: Copr on Fedora, PPA on Debian/Ubuntu, AUR on
/// Arch. Every probe and package-manager step is PATH-shadowed.
#[test]
fn update_uses_the_repo_channel_of_the_owning_package_manager() {
    let sb = Sandbox::new("updatechan");
    sb.fake_tool("curl", r#"printf '%s' '{"tag_name": "v99.99.99"}'"#);
    match host_family() {
        "fedora" => {
            sb.fake_tool("rpm", "printf '0.0.1'");
            sb.fake_tool(
                "dnf",
                r#"case "$1" in
  repoquery) printf 'copr:copr.fedorainfracloud.org:archledger:irlume\n' ;;
  *) exit 4 ;;
esac"#,
            );
            sb.fake_tool("sudo", r#"exec "$@""#);

            let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update", "--check"]));
            assert_eq!(code, 0);
            assert!(
                out.contains("install method: Fedora Copr (archledger/irlume)"),
                "{out}"
            );
            assert!(out.contains("[update] installed: 0.0.1"), "{out}");
            assert!(out.contains("available: v99.99.99"), "{out}");
            assert!(
                out.contains("would run: sudo dnf upgrade --refresh irlume"),
                "--check must not run the upgrade: {out}"
            );

            // Without --check the dnf step runs (through sudo when unprivileged)
            // and its failure stops the update with exit 1.
            let (code, _, err) = run(&mut sb.cmd_with_fakes(&["update"]));
            assert_eq!(code, 1);
            assert!(
                err.contains("`dnf upgrade --refresh irlume` exited with"),
                "{err}"
            );

            // And a succeeding step completes the update.
            sb.fake_tool(
                "dnf",
                r#"case "$1" in
  repoquery) printf 'copr:copr.fedorainfracloud.org:archledger:irlume\n' ;;
  *) exit 0 ;;
esac"#,
            );
            let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update"]));
            assert_eq!(code, 0);
            assert!(out.contains("[update] done."), "{out}");
        }
        "debian" => {
            sb.fake_tool(
                "dpkg-query",
                r#"case "$*" in
  *Status*) printf 'install ok installed' ;;
  *) printf '0.0.1-0ppa1' ;;
esac"#,
            );
            sb.fake_tool(
                "apt-cache",
                r#"printf '     500 https://ppa.launchpadcontent.net/archledger/irlume/ubuntu resolute/main amd64 Packages\n'"#,
            );
            let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update", "--check"]));
            assert_eq!(code, 0);
            assert!(
                out.contains("install method: Launchpad PPA (ppa:archledger/irlume)"),
                "{out}"
            );
            assert!(out.contains("[update] installed: 0.0.1-0ppa1"), "{out}");
            assert!(
                out.contains(
                    "would run: sudo apt update && sudo apt install --only-upgrade irlume"
                ),
                "{out}"
            );
        }
        "arch" => {
            sb.fake_tool("pacman", "printf 'irlume 0.0.1-1\\n'");
            let (code, out, _) = run(&mut sb.cmd_with_fakes(&["update", "--check"]));
            assert_eq!(code, 0);
            assert!(
                out.contains("install method: pacman package (AUR / makepkg)"),
                "{out}"
            );
            assert!(out.contains("[update] installed: 0.0.1-1"), "{out}");
            assert!(out.contains("yay -Syu irlume"), "{out}");
            assert!(out.contains("aur.archlinux.org/irlume.git"), "{out}");
        }
        _ => {} // unknown family resolves to Source, covered elsewhere
    }
}
