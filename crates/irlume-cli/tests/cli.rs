// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Black-box tests of the `irlume` binary: argument dispatch, usage errors,
//! exit codes, and the offline failure paths of every daemon-backed command.
//!
//! Every invocation runs inside a sandbox: `IRLUME_SOCKET` points at a path
//! nothing listens on (so no request can ever reach a real `irlumed`),
//! `IRLUME_CONFIG_DIR` / `IRLUME_STATE_DIR` / `IRLUME_KEYRING_DIR` point at a
//! per-test temp tree, and system tools the CLI shells out to are fake scripts.
//! Privileged fixed-path probes run in a Bubblewrap namespace with private
//! `/usr/bin` and `/run`. No test touches the network, a camera, the TPM, or the
//! machine's package database.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod support;

const BIN: &str = env!("CARGO_BIN_EXE_irlume");

fn is_root() -> bool {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::geteuid() == 0
    }
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
        let helper = root.join("wallet-salt-helper");
        std::fs::write(
            &helper,
            "#!/bin/sh\n[ \"$1\" = --read-salt ] && [ \"$#\" -eq 2 ] || exit 1\nexit 3\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
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
            .env("IRLUME_KWALLET_INIT", self.root.join("wallet-salt-helper"))
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

    fn isolated_root_cmd(&self, args: &[&str], tools: &[&str]) -> Command {
        support::isolated_root_command(&self.root, BIN, args, tools)
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

#[test]
fn support_report_publishes_one_private_inspectable_text_file() {
    use std::os::unix::fs::PermissionsExt as _;
    let sandbox = Sandbox::new("support-report");
    for tool in ["rpm", "dnf", "dpkg-query", "apt-cache", "pacman"] {
        sandbox.fake_tool(tool, "exit 1");
    }
    let output = sandbox.path("work/report.txt");
    let (code, stdout, stderr) = run(&mut sandbox.cmd_with_fakes(&[
        "support-report",
        "--output",
        output.to_str().unwrap(),
        "--since",
        "5m",
    ]));

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains(output.to_str().unwrap()));
    let text = std::fs::read_to_string(&output).unwrap();
    assert!(text.starts_with("IRLUME SUPPORT REPORT\nPrivacy:"));
    assert!(text.contains("Unavailable sections"));
    assert!(text.contains("SHA-256 (body):"));
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let (second_code, _, _) =
        run(&mut sandbox.cmd_with_fakes(&["support-report", "--output", output.to_str().unwrap()]));
    assert_ne!(second_code, 0, "an existing report must never be replaced");
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
            "retry",
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
fn help_exposes_no_eye_challenge_or_calibration() {
    let sandbox = Sandbox::new("head-only-help");
    let (code, help, stderr) = run(&mut sandbox.cmd(&["--help"]));
    assert_eq!(code, 0, "{stderr}");
    for retired in ["calibrate-closure", "eyes-open on", "eye-closure gesture"] {
        assert!(
            !help.contains(retired),
            "retired surface remains: {retired}"
        );
    }
    assert!(!help.contains("keep nodding to approve"));
    assert!(!help.contains("shake your head to decline"));
}

#[test]
fn retired_closure_calibration_is_not_dispatched() {
    let sandbox = Sandbox::new("retired-calibration");
    let (code, _, stderr) = run(&mut sandbox.cmd(&["calibrate-closure"]));
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("unknown command 'calibrate-closure'"),
        "{stderr}"
    );
}

#[test]
fn retired_meshprobe_is_not_dispatched() {
    let sandbox = Sandbox::new("retired-meshprobe");
    let (code, _, stderr) = run(sandbox.cmd(&["meshprobe"]).env("IRLUME_DEV", "1"));
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("unknown command 'meshprobe'"), "{stderr}");
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
        (&["verify"], 2, "usage: irlume verify --user U --det"),
        (&["enrolldev"], 2, "usage: irlume enrolldev --user U --det"),
        (&["padcapture"], 2, "usage: irlume padcapture --species"),
        (&["padreport"], 2, "usage: irlume padreport --in"),
        (&["suncal"], 2, "usage: IRLUME_DEV=1 irlume suncal"),
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
        // forget-model with no model name; a flag must not be read as one.
        // (A dangling `--user` gets its own specific error, tested in
        // a_dangling_user_flag_never_reaches_the_daemon.)
        &["profiles", "forget-model"],
    ];
    for argv in cases {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 2, "{argv:?} should be a usage error: {err}");
        assert!(err.contains("usage:"), "{argv:?}: {err}");
    }
    // The full usage text names the real subcommands and flags.
    let (_, _, err) = run(&mut sb.cmd(&["profiles", "bogus"]));
    for frag in [
        "add-scan --profile P [--scans N]",
        "rename --profile P [--scan S] --name N",
        "delete --profile P [--scan S]",
        "forget-model <model>",
        "eyes-open off",
    ] {
        assert!(
            err.contains(frag),
            "profiles usage must name `{frag}`: {err}"
        );
    }
    // #386: the daemon refuses to turn this gate on, so the usage must not
    // offer it. Whoever makes the gate work again changes this line
    // deliberately, which is the point of pinning it.
    assert!(
        !err.contains("eyes-open <on|off>"),
        "usage must not advertise an enable the daemon refuses: {err}"
    );
    assert!(
        err.contains("#386"),
        "usage must say where the refusal is recorded: {err}"
    );
}

#[test]
fn profiles_eyes_open_usage_is_off_only_migration() {
    let sb = Sandbox::new("eyes-open-usage");
    for argv in [
        &["profiles", "eyes-open"][..],
        &["profiles", "eyes-open", "yes"],
        &["profiles", "eyes-open", "off", "on"],
    ] {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 2, "{argv:?}: {err}");
        assert!(
            err.contains("usage: irlume profiles eyes-open off [--user U]")
                && err.contains("one-release migration"),
            "{argv:?}: {err}"
        );
        assert!(!err.contains("<on|off>"), "{argv:?}: {err}");
    }
}

#[test]
fn add_scan_rejects_a_non_positive_or_unparseable_count() {
    // A state-changing biometric command must refuse an invalid count rather
    // than silently capturing one scan instead (#290 review). Exit 2 is the
    // usage code, and it must happen before any daemon request: with no
    // daemon running, a request attempt would exit 1.
    let sb = Sandbox::new("addscanbad");
    for bad in ["0", "-1", "abc", ""] {
        let (code, _, err) =
            run(&mut sb.cmd(&["profiles", "add-scan", "--profile", "P", "--scans", bad]));
        assert_eq!(code, 2, "--scans {bad:?} must be a usage error: {err}");
        assert!(
            err.contains("--scans must be a positive integer"),
            "--scans {bad:?}: {err}"
        );
    }
    // A valid count parses and reaches the (dead) socket instead.
    let (code, _, err) =
        run(&mut sb.cmd(&["profiles", "add-scan", "--profile", "P", "--scans", "5"]));
    assert_eq!(code, 1, "a valid count must build a request: {err}");
    assert!(err.contains("adding 5 scans"), "{err}");
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
        &["profiles", "eyes-open", "off"],
        &["profiles", "forget-model", "shipped"],
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

#[test]
fn profiles_eyes_open_on_rejects_before_the_daemon() {
    let sb = Sandbox::new("eyes-open-on");
    let (code, _, err) = run(&mut sb.cmd(&["profiles", "eyes-open", "on"]));
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("can only be turned off"), "{err}");
    assert!(!err.contains("irlumed is not running"), "{err}");
}

#[test]
fn forget_model_refuses_a_name_that_is_not_a_recognizer() {
    // Refused at resolution, before any daemon request: with no daemon
    // running, a request attempt would exit 1, so exit 2 proves the order.
    let sb = Sandbox::new("forgetbad");
    let (code, _, err) = run(&mut sb.cmd(&["profiles", "forget-model", "nonsense"]));
    assert_eq!(code, 2, "an unknown model must be a usage error: {err}");
    assert!(
        err.contains("unknown model") && err.contains("nonsense") && err.contains("shipped"),
        "the error must name the argument and what is accepted: {err}"
    );
    let (code, _, err) = run(&mut sb.cmd(&["profiles", "forget-model", "embed:nothex"]));
    assert_eq!(
        code, 2,
        "a malformed space tag must be a usage error: {err}"
    );
    assert!(err.contains("64 hex"), "{err}");
}

#[test]
fn a_dangling_user_flag_never_reaches_the_daemon() {
    // `--user` with no value used to fall back to SUDO_USER/$USER, so
    // `sudo irlume profiles forget-model shipped --user` would have deleted
    // the INVOKING user's own enrollment (Codex, #292). The request must die
    // as a usage error before the socket: with no daemon running, reaching
    // the socket shows as exit 1 and "irlumed is not running".
    let sb = Sandbox::new("dangleuser");
    let cases: &[&[&str]] = &[
        &["profiles", "forget-model", "shipped", "--user"],
        &["profiles", "delete", "--profile", "P", "--user"],
        // A flag where the username should be is the same omission.
        &["profiles", "forget-model", "shipped", "--user", "--json"],
    ];
    for argv in cases {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 2, "{argv:?} must be a usage error: {err}");
        assert!(
            err.contains("--user requires a username"),
            "{argv:?}: {err}"
        );
        assert!(
            !err.contains("irlumed is not running"),
            "{argv:?} must not build a request: {err}"
        );
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
    assert!(
        err.contains("[enroll] --reset: replacing 'tester'"),
        "{err}"
    );
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
        "correct horse battery\n",
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

/// The real run tells the user it writes to their camera; the dry run must not,
/// because it does not. Getting that backwards would either hide a write or
/// warn about one that never happens, and after #159 neither is acceptable.
#[test]
fn ir_setup_warns_about_writing_and_dry_run_does_not() {
    let sb = Sandbox::new("irsetup");
    let (code, _, err) = run(&mut sb.cmd(&["ir-setup"]));
    assert_eq!(code, 1);
    assert!(err.contains("writes to your camera"), "{err}");
    assert!(err.contains("descriptor documents"), "{err}");
    assert!(err.contains("[ir-setup]"), "{err}");

    let (code, _, err) = run(&mut sb.cmd(&["ir-setup", "--dry-run"]));
    assert_eq!(code, 1);
    assert!(
        !err.contains("writes to your camera"),
        "--dry-run sends the camera nothing and must not claim otherwise: {err}"
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
    // Neither envelope exists in the sandbox + dead socket. They must stay
    // distinct: a generic seal summary can hide the broken template key behind
    // a healthy keyring credential (#472).
    assert!(
        out.contains("keyring seal  : unknown (daemon unreachable)"),
        "{out}"
    );
    assert!(
        out.contains("template seal : unknown (daemon unreachable)"),
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
    // A bad option is a usage error (2), not a runtime failure (1).
    assert_eq!(code, 2);
    assert!(err.contains("--since needs a value"), "{err}");
    assert!(
        !out.contains("JOURNALCTL RAN"),
        "must not have run journalctl"
    );

    let (code, out, err) = run(&mut sb.cmd_with_fakes(&["logs", "--bogus"]));
    assert_eq!(code, 2);
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

    // 2, the usage-error code the rest of the CLI uses and that this command's
    // own option handler already returned for a bad option. It answered 1 here,
    // which tells a wrapper the command ran and failed rather than that it was
    // never a valid invocation.
    let (code, _, err) = run(&mut sb.cmd(&["logs", "debug", "bogus"]));
    assert_eq!(code, 2);
    assert!(err.contains("unknown: 'debug bogus'"), "{err}");
}

// ---------------------------------------------------------------------- models

#[test]
fn models_command_answers_the_removal_notice() {
    // The third-party/BYOM lane is removed (ADR-0015): every invocation gets
    // the same clear refusal, never silence and never a stale catalog.
    let sb = Sandbox::new("modelslist");
    for argv in [
        &["models"][..],
        &["models", "list"][..],
        &["models", "enable", "flir"][..],
    ] {
        let (code, _, err) = run(&mut sb.cmd(argv));
        assert_eq!(code, 2, "`{argv:?}` must refuse: {err}");
        assert!(
            err.contains("third-party model support was removed"),
            "{err}"
        );
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
    support::assert_system_command_isolation(&sb.root, &["semodule", "ls"]);
    let (code, out, _) =
        run(&mut sb.isolated_root_cmd(&["selinux", "status"], &["semodule", "ls"]));
    assert_eq!(code, 0);
    assert!(out.contains("module 'irlume': loaded"), "{out}");

    // Listed modules but ours absent, and no socket label: not loaded.
    sb.fake_tool("semodule", r#"printf 'somethingelse\n'"#);
    sb.fake_tool("ls", "exit 2");
    let (code, out, _) =
        run(&mut sb.isolated_root_cmd(&["selinux", "status"], &["semodule", "ls"]));
    assert_eq!(code, 0);
    assert!(out.contains("not loaded"), "{out}");

    // semodule prints nothing (non-root): state is unknown, not "not loaded".
    sb.fake_tool("semodule", "exit 1");
    let (code, out, _) =
        run(&mut sb.isolated_root_cmd(&["selinux", "status"], &["semodule", "ls"]));
    assert_eq!(code, 0);
    assert!(out.contains("unknown"), "{out}");

    let (code, _, err) = run(&mut sb.cmd(&["selinux", "bogus"]));
    // A bad subcommand is a usage error (2), not a runtime failure (1).
    assert_eq!(code, 2);
    assert!(err.contains("unknown subcommand 'bogus'"), "{err}");
}

// ----------------------------------------------------------------- fingerprint

#[test]
fn fingerprint_status_and_usage() {
    let sb = Sandbox::new("fingerprint");
    let (code, _, err) = run(&mut sb.cmd(&["fingerprint", "bogus"]));
    assert_eq!(code, 2);
    assert!(
        err.contains(
            "usage: irlume fingerprint [--user U] <status|add|verify|reset|enable|disable>"
        ),
        "{err}"
    );

    let (code, out, _) = run(&mut sb.cmd(&["fingerprint", "status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("fprintd tooling"), "{out}");
    assert!(out.contains("active method"), "{out}");

    // Without a reader (or without fprintd at all), verify and reset both fail
    // cleanly instead of hanging or deleting anything. reset additionally
    // refuses non-interactive use without --yes, so a script can never wipe
    // prints by accident; with no reader present every path still exits 1.
    let (code, _, err) = run(&mut sb.cmd(&["fingerprint", "verify", "--user", "tester"]));
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(&mut sb.cmd(&["fingerprint", "reset", "--user", "tester"]));
    assert_eq!(code, 1, "{err}");

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
        r#"{"species":"cutout","kind":"attack","path":"full","verdict":"Spoof","caught":["center_edge"]}
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
        // `forget` asks what is armed before erasing it, and refuses when it
        // cannot tell: erasing a GNOME keyring token leaves the login keyring
        // encrypted under a secret nothing can reproduce. This user has a
        // password armed, which is safe to erase directly.
        Request::KeyringInfo { .. } => Response::KeyringInfo {
            armed: true,
            policy: None,
            pcrs: Vec::new(),
            drifted: None,
            kind: Some(irlume_common::KeyringSecretKind::LoginPassword),
        },
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
        out.contains("sealed secret erased; keyring unlock disarmed"),
        "{out}"
    );

    // The wire request carried the piped password for the right user.
    let log = log.lock().unwrap();
    let sealed = log
        .iter()
        .find_map(|r| match r {
            Request::SealPassword { user, password, .. } => {
                Some((user.clone(), password.expose().to_vec()))
            }
            _ => None,
        })
        .expect("a SealPassword request was sent");
    assert_eq!(sealed.0, "tester");
    assert_eq!(sealed.1, b"hunter2");
}

/// An encrypted store whose template key is gone is the one state the old
/// `encrypted` bool could not express, because it was computed FROM the key's
/// presence. It reported "plaintext at rest", which understates the posture and
/// hides that the enrollment can no longer be opened by anything, then pointed
/// the user at `recovery setup`. It happened for real on 2026-08-05 when a
/// sandboxed root command deleted the live key directory.
#[test]
fn an_encrypted_store_with_no_key_says_so_instead_of_plaintext() {
    let sb = Sandbox::new("orphanedkey");
    serve(&sock(&sb), |req| match req {
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: false,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["recovery", "status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(
        !out.contains("plaintext at rest"),
        "an encrypted store must never be called plaintext: {out}"
    );
    assert!(
        out.contains("TEMPLATE KEY IS GONE"),
        "the user must be told the enrollment cannot be opened: {out}"
    );
    assert!(
        out.contains("Re-enroll"),
        "and told the only remaining move: {out}"
    );
}

/// A flag with nothing after it must never silently become a different, wider
/// operation.
///
/// `flag()` answers None both for "absent" and for "present with no value", and
/// two resolvers read that None as a default: `--user` fell back to SUDO_USER,
/// and `profiles delete`'s missing `--scan` meant "the whole profile". So
/// `sudo irlume enroll --reset --user` deleted the enrollment, the template key
/// and the recovery envelope of the person typing it, unconfirmed, and
/// `profiles delete --profile P --scan` deleted P. The guard existed but only
/// inside `profiles`, so it covered one of four commands.
///
/// The fixture serves nothing: every case here must be refused BEFORE any
/// request reaches a daemon, which the empty request log proves.
#[test]
fn a_flag_with_no_value_is_refused_before_anything_is_destroyed() {
    let sb = Sandbox::new("danglingflag");
    let log = serve(&sock(&sb), |_| Response::Ok("must not be reached".into()));

    let destructive: &[&[&str]] = &[
        &["enroll", "--reset", "--user"],
        &["recovery", "forget", "--user"],
        &["keyring", "forget", "--user"],
        &["profiles", "delete", "--profile", "P", "--user"],
        &["profiles", "forget-model", "shipped", "--user"],
        &["profiles", "delete", "--profile", "P", "--scan"],
    ];
    for argv in destructive {
        let (code, _, err) = run(sb.cmd(argv).env("SUDO_USER", "victim"));
        assert_eq!(code, 2, "`{}` must be a usage error: {err}", argv.join(" "));
        assert!(
            err.contains("requires a"),
            "`{}` must say what is missing: {err}",
            argv.join(" ")
        );
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing may reach the daemon: {:?}",
        log.lock().unwrap()
    );

    // The ordinary forms are untouched.
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("tester"), "{out}");
}

/// A slow daemon is not an absent daemon.
///
/// `caps()` and `camera_pair()` fall back to a local probe when the socket poll
/// fails, and that probe OPENS every video node. The short poll allows 1.2s to
/// connect and 1.5s to read. A daemon busy mid-capture is exactly what blowing
/// that budget looks like, and it is also exactly when it holds the nodes, so
/// treating any failure as absence put the probe at the worst possible moment
/// (#187 again, by a different route). Only an error that PROVES nobody is
/// listening licenses the probe.
///
/// The fixture accepts the connection and then never answers, which no
/// existing test did: every other one either serves promptly or has no socket
/// at all, so both took the success path or the proven-absent path. The
/// cameras.conf pair is reported back, proving the answer came from
/// configuration rather than from enumerating hardware.
#[test]
fn a_daemon_that_accepts_but_never_answers_is_not_treated_as_absent() {
    let sb = Sandbox::new("slowdaemon");
    std::fs::create_dir_all(sb.path("cfg")).unwrap();
    std::fs::write(
        sb.path("cfg").join("cameras.conf"),
        "rgb=/dev/video81
ir=/dev/video82
",
    )
    .unwrap();

    // Accept, read the request, then hold the connection open and answer
    // nothing. The client must time out rather than see a closed socket.
    let sock_path = sock(&sb);
    let _ = std::fs::remove_file(&sock_path);
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader};
                let mut line = String::new();
                let _ = BufReader::new(&stream).read_line(&mut line);
                // Outlive the client's 1.5s read budget, holding the fd so the
                // peer sees a timeout and not an EOF.
                std::thread::sleep(std::time::Duration::from_secs(6));
                drop(stream);
            });
        }
    });

    let (_, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]));
    assert!(
        out.contains("/dev/video81") && out.contains("/dev/video82"),
        "a timed-out poll must fall back to the CONFIGURED pair, never to \
         enumeration, which opens the nodes the daemon may be holding: {out}"
    );
}

/// #187: classifying a video node means OPENING it, and on a UVC module that
/// answers EBUSY to a second open, doing that while the daemon streams fails the
/// user's enrollment. #300 stopped the TUI doing it; `status` was still
/// enumerating, measured with strace as four opens of /dev/video0..3 with the
/// daemon running. The daemon already reports the pair it selected, so a running
/// daemon is the authority here too.
///
/// The fixture reports device paths that exist on no machine, so seeing them in
/// the output proves the answer came over the socket rather than from a probe.
#[test]
fn status_takes_the_camera_pair_from_the_daemon_not_a_local_probe() {
    let sb = Sandbox::new("statuscam");
    serve(&sock(&sb), |req| match req {
        Request::Health => Response::Health {
            tier: "secure".into(),
            rgb_dev: Some("/dev/video91".into()),
            ir_dev: Some("/dev/video92".into()),
            mesh: true,
            adapter: false,
            rgb_pad: Some(irlume_common::PadModelStatus::Loaded),
            ir_pad: Some(irlume_common::PadModelStatus::Loaded),
            version: env!("CARGO_PKG_VERSION").into(),
            apparmor: None,
        },
        _ => Response::Error("unexpected request".into()),
    });

    let (_, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]));
    assert!(
        out.contains("/dev/video91") && out.contains("/dev/video92"),
        "status must report the daemon's pair, not one it probed: {out}"
    );
}

#[test]
fn recovery_success_paths_with_a_live_daemon() {
    let sb = Sandbox::new("recoveryok");
    serve(&sock(&sb), |req| match req {
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: false,
            tpm_present: true,
            key_present: true,
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
    assert!(out.contains("template key restored"), "{out}");
    assert!(!out.contains("face unlock is restored"), "{out}");

    let (code, out, _) = run(&mut sb.cmd(&["recovery", "forget", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("recovery envelope erased"), "{out}");
}

/// The recovery passphrase is the only barrier on the template-key envelope
/// against someone holding the disk, and the strength floor used to live inside
/// the interactive branch. `irlume recovery setup </dev/null` therefore wrapped
/// the key under an EMPTY passphrase and reported success. Both piped rejections
/// must happen in the CLI, before any request reaches the daemon.
#[test]
fn recovery_setup_enforces_the_strength_floor_on_the_piped_path() {
    let sb = Sandbox::new("recoveryfloor");
    // A daemon that would happily accept whatever arrives, so a passing test
    // means the CLI stopped it rather than the socket being dead.
    let log = serve(&sock(&sb), |_| Response::Ok("recovery set".into()));

    for (piped, want) in [("", "empty passphrase"), ("short\n", "too short")] {
        let (code, _, err) = run_stdin(
            &mut sb.cmd(&["recovery", "setup", "--user", "tester"]),
            piped,
        );
        assert_eq!(code, 2, "must exit 2 on a refused passphrase: {err}");
        assert!(err.contains(want), "expected {want:?} in: {err}");
        assert!(
            err.contains("nothing set"),
            "the user must be told no envelope was written: {err}"
        );
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "a refused passphrase must not reach the daemon: {:?}",
        log.lock().unwrap()
    );
}

#[test]
fn recovery_setup_error_names_the_enroll_first_remedy() {
    let sb = Sandbox::new("recoveryerr");
    serve(&sock(&sb), |_| {
        Response::Error("no template key for tester".into())
    });
    let (code, _, err) = run_stdin(
        &mut sb.cmd(&["recovery", "setup", "--user", "tester"]),
        "correct horse battery\n",
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
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
                ir: None,
            }],
            require_eyes_open: true,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::SetRequireEyesOpen { on: false, .. } => Response::Ok("eyes-open now off".into()),
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(
        out.contains("legacy policy blocks authentication")
            && out.contains("sudo irlume profiles eyes-open off --user 'tester'"),
        "{out}"
    );
    assert!(out.contains("Face Profile 1 (2 scans)"), "{out}");
    assert!(out.contains("- Scan 1"), "{out}");
    assert!(out.contains("- Glasses"), "{out}");

    let (code, out, _) = run(&mut sb.cmd(&["profiles", "eyes-open", "off", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("[profiles] eyes-open now off"), "{out}");
}

#[test]
fn profile_ir_listing_text_and_json_keep_counts_and_targeted_refresh_command() {
    let sb = Sandbox::new("profile-ir-guidance");
    serve(&sock(&sb), |req| match req {
        Request::ListProfiles { user, .. } => {
            assert_eq!(user, "tester");
            Response::Enrollment {
                profiles: vec![ProfileSummary {
                    name: "Person's glasses".into(),
                    scans: vec!["s".into()],
                    scans_by_recognizer: Default::default(),
                    live_recognizer: None,
                    ir: Some(irlume_common::ProfileIrSummary {
                        compatible_scans: 2,
                        missing_scans: 1,
                        unknown_scans: 1,
                        incompatible_scans: 1,
                        calibration_withheld: true,
                    }),
                }],
                require_eyes_open: false,
                closure_calibrated: false,
                ir_ratio_calibrated: false,
            }
        }
        _ => panic!("listing must not mutate or capture"),
    });
    let (code, out, err) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester"]));
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("IR for loaded recognizer: 2 compatible scans."),
        "{out}"
    );
    assert!(out.contains("IR: 1 missing, 1 unknown, 1 incompatible scans."));
    assert!(out.contains("IR calibration is paused while unknown IR scans remain."));
    assert!(out.contains("--user 'tester'"));
    // Verify the advertised shell quoting preserves the exact display name.
    let command = out
        .lines()
        .find(|l| l.contains("irlume profiles add-scan"))
        .unwrap();
    assert!(
        command.contains(r#"--profile 'Person'"'"'s glasses' --user 'tester'"#),
        "{command}"
    );
    let (code, out, err) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester", "--json"]));
    assert_eq!(code, 0, "{err}");
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        doc["data"]["profiles"][0]["ir"],
        serde_json::json!({
        "compatible_scans":2,"missing_scans":1,"unknown_scans":1,
        "incompatible_scans":1,"calibration_withheld":true })
    );
}

#[test]
fn profile_recognizer_refresh_hint_keeps_the_selected_account() {
    let sb = Sandbox::new("profile-recognizer-target");
    serve(&sock(&sb), |req| match req {
        Request::ListProfiles { user, .. } => {
            assert_eq!(user, "tester");
            Response::Enrollment {
                profiles: vec![ProfileSummary {
                    name: "Other model".into(),
                    scans: vec!["s".into()],
                    scans_by_recognizer: [("embed:old".into(), 1)].into(),
                    live_recognizer: Some("embed:current".into()),
                    ir: None,
                }],
                require_eyes_open: false,
                closure_calibrated: false,
                ir_ratio_calibrated: false,
            }
        }
        _ => panic!("listing must not mutate"),
    });
    let (code, out, err) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester"]));
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("irlume profiles add-scan --profile 'Other model' --user 'tester'"),
        "{out}"
    );
    assert!(out.contains("IR compatibility: not reported by this daemon."));
}

#[test]
fn profiles_empty_listing_says_none_enrolled() {
    let sb = Sandbox::new("profempty");
    serve(&sock(&sb), |_| Response::Enrollment {
        profiles: Vec::new(),
        require_eyes_open: false,
        closure_calibrated: false,
        ir_ratio_calibrated: false,
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
fn profiles_empty_legacy_listing_keeps_the_targeted_cleanup() {
    let sb = Sandbox::new("profempty-legacy");
    serve(&sock(&sb), |_| Response::Enrollment {
        profiles: Vec::new(),
        require_eyes_open: true,
        closure_calibrated: false,
        ir_ratio_calibrated: false,
    });

    let (code, out, _) = run(&mut sb.cmd(&["profiles", "list", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("[profiles] none enrolled"), "{out}");
    assert!(
        out.contains("legacy policy blocks authentication")
            && out.contains("sudo irlume profiles eyes-open off --user 'tester'"),
        "{out}"
    );
}

#[test]
fn enroll_reports_a_new_profile_and_forwards_the_flags() {
    let sb = Sandbox::new("enrollnew");
    let log = serve(&sock(&sb), |_| Response::Enrolled {
        profile: "Night".into(),
        created: true,
        added: 3,
        total: 3,
        room: Some(27),
        added_scans: vec!["Scan 1".into(), "Scan 2".into(), "Scan 3".into()],
        ambient_lit: None,
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
        room: Some(22),
        added_scans: vec!["Scan 7".into(), "Scan 8".into()],
        ambient_lit: None,
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
                scans_by_recognizer: Default::default(),
                live_recognizer: None,
                ir: None,
            }],
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::KeyringInfo { .. } => Response::KeyringInfo {
            armed: true,
            policy: Some("Tier 2 (pcrlock)".into()),
            pcrs: vec![7],
            drifted: Some(true),
            kind: None,
        },
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: true,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]));
    assert_eq!(code, 0);
    assert!(out.contains("daemon        : running"), "{out}");
    assert!(out.contains("1 profile(s), 2 scan(s)"), "{out}");
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
    assert!(err.contains("has no sealed secret"), "{err}");
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
            rgb_pad: Some(irlume_common::PadModelStatus::Loaded),
            ir_pad: Some(irlume_common::PadModelStatus::Loaded),
            version: env!("CARGO_PKG_VERSION").into(),
            apparmor: None,
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::Enroll { .. } => Response::Enrolled {
            profile: "Face Profile 1".into(),
            created: true,
            added: 6,
            total: 6,
            room: Some(24),
            added_scans: Vec::new(),
            ambient_lit: None,
        },
        Request::SealPassword { .. } => Response::PasswordSealed,
        _ => Response::Error("unexpected request".into()),
    });
    // Piped stdin: yes/no prompts take their defaults (enroll: yes, arm: yes),
    // and the keyring arm reads this line as the login password.
    let (code, out, _) = run_stdin(&mut sb.cmd(&["setup", "--user", "tester"]), "pw\n");
    assert_eq!(code, 0);
    assert!(out.contains("[1/7] Preflight"), "{out}");
    // The third-party offer step is REMOVED (ADR-0015: shipped cues are
    // default-on), so setup must neither fetch external weights nor print the
    // old offer.
    assert!(!out.contains("[3/7] Anti-spoof model"), "{out}");
    assert!(!out.contains("models enable"), "{out}");
    assert!(
        out.contains("[2/7]") && out.contains("[4/7]"),
        "setup must still walk its steps: {out}"
    );
    assert!(
        out.contains("enrolled 'Face Profile 1' with 6 scans"),
        "{out}"
    );
    assert!(out.contains("armed"), "{out}");
    assert!(out.contains("[7/7] PAM login wiring"), "{out}");
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

#[test]
fn retired_blinkcap_is_not_dispatchable() {
    let sandbox = Sandbox::new("blinkcap-retired");
    let (code, _, stderr) = run(&mut sandbox.cmd(&["blinkcap", "replay", "anything"]));
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("unknown command 'blinkcap'"), "{stderr}");
}

#[test]
fn removed_gesture_commands_are_unknown() {
    let sandbox = Sandbox::new("retired-gestures");
    for args in [
        vec!["credential-release-challenge", "on"],
        vec!["gesturecap", "capture"],
    ] {
        let mut cmd = sandbox.cmd(&args);
        cmd.env("IRLUME_DEV", "1");
        let (code, _, _) = run(&mut cmd);
        assert_eq!(code, 2);
    }
}

// Consent control must use the same default and opt-out policy as PAM/daemon.
#[test]
fn auth_sensor_status_distinguishes_default_explicit_invalid_and_unreadable() {
    let sb = Sandbox::new("sensor-status");
    for (contents, expected) in [
        (None, "dual (default)"),
        (
            Some(b"face_sensor_policy=ir-only-experimental\n".as_slice()),
            "EXPERIMENTAL IR-only",
        ),
        (Some(b"face_sensor_policy=\n".as_slice()), "invalid"),
        (Some(b"face_sensor_policy=typo\n".as_slice()), "invalid"),
        (
            Some(b"face_sensor_policy=dual\nface_sensor_policy=ir-only-experimental\n".as_slice()),
            "invalid",
        ),
        (Some(b"\xff".as_slice()), "unreadable"),
    ] {
        if let Some(contents) = contents {
            std::fs::write(sb.path("cfg/settings.conf"), contents).unwrap();
        }
        let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "status"]));
        assert_eq!(code, 0, "{out} {err}");
        assert!(out.contains(expected), "{out} {err}");
        assert!(
            out.contains("local saved"),
            "offline state must not claim daemon observation: {out}"
        );
    }
}

#[test]
fn auth_sensor_malformed_key_cannot_silently_select_dual() {
    let sb = Sandbox::new("sensor-malformed-key");
    for contents in [
        "face_sensor_policy ir-only-experimental\n",
        "face_sensor_policy: ir-only-experimental\n",
        "face_sensor_policy\tir-only-experimental\n",
        "face_sensor_policy : ir-only-experimental\n",
        "face_sensor_policy:=ir-only-experimental\n",
        "face_sensor_policy ir-only-experimental=1\n",
        "face_sensor_policy=dual\nface_sensor_policy: ir-only-experimental\n",
    ] {
        std::fs::write(sb.path("cfg/settings.conf"), contents).unwrap();
        let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "status"]));
        assert_eq!(code, 0, "{out} {err}");
        assert!(
            out.contains("invalid sensor policy"),
            "{contents:?}: {out} {err}"
        );
        assert!(!out.contains("dual (default)"), "{out}");
        let (code, _, _) = run(&mut sb.isolated_root_cmd(&["auth", "sensor", "dual"], &[]));
        assert_ne!(
            code, 0,
            "owner update must not silently retain malformed policy"
        );
        assert_eq!(
            std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap(),
            contents
        );
    }
    for contents in [
        "face_sensor_policy_extra=ir-only-experimental\n",
        "face_sensor_policy_extra ir-only-experimental\n",
        "# face_sensor_policy: ir-only-experimental\n",
    ] {
        std::fs::write(sb.path("cfg/settings.conf"), contents).unwrap();
        let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "status"]));
        assert_eq!(code, 0, "{out} {err}");
        assert!(
            out.contains("dual (default)"),
            "distinct key/comment: {out}"
        );
    }
}

#[test]
fn auth_sensor_status_uses_daemon_observation_and_preflight_is_explicit() {
    use irlume_common::config::{FaceSensorPolicy, FaceSensorPolicyObservation};
    let sb = Sandbox::new("sensor-daemon");
    std::fs::write(sb.path("cfg/settings.conf"), "face_sensor_policy=dual\n").unwrap();
    let requests = serve(&sock(&sb), |req| match req {
        Request::FaceSensorStatus { user } => Response::FaceSensorStatus {
            policy: FaceSensorPolicyObservation::Explicit(FaceSensorPolicy::IrOnlyExperimental),
            ir_readiness: user
                .as_ref()
                .map(|_| irlume_common::IrOnlyReadiness::Unavailable),
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "status"]));
    assert_eq!(code, 0, "{out} {err}");
    assert!(
        out.contains("daemon observed: EXPERIMENTAL IR-only"),
        "{out}"
    );
    assert!(out.contains("not qualified"), "{out}");
    let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "preflight", "alice"]));
    assert_ne!(code, 0);
    assert!(err.contains("preflight unavailable"), "{out} {err}");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(matches!(
        &requests[0],
        Request::FaceSensorStatus { user: None }
    ));
    assert!(
        matches!(&requests[1], Request::FaceSensorStatus { user: Some(user) } if user == "alice")
    );
    assert_eq!(
        std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap(),
        "face_sensor_policy=dual\n"
    );
}

#[test]
fn auth_sensor_preflight_renders_each_readiness_without_exposing_the_account() {
    use irlume_common::config::{FaceSensorPolicy, FaceSensorPolicyObservation};
    use irlume_common::IrOnlyReadiness;

    let sb = Sandbox::new("sensor-preflight-readiness");
    let requests = serve(&sock(&sb), |req| {
        let Request::FaceSensorStatus { user: Some(user) } = req else {
            return Response::Error("unexpected request".into());
        };
        let ir_readiness = match user.as_str() {
            "ready-account" => IrOnlyReadiness::ReadyForExperimentalAttempt,
            "unavailable-account" => IrOnlyReadiness::Unavailable,
            "invalid-policy-account" => IrOnlyReadiness::InvalidPolicy,
            "target-account" => IrOnlyReadiness::TargetUnavailable,
            "binding-absent-account" => IrOnlyReadiness::BindingUnavailable,
            "binding-mismatch-account" => IrOnlyReadiness::BindingMismatch,
            "models-account" => IrOnlyReadiness::ModelsUnavailable,
            "pad-account" => IrOnlyReadiness::PadUnavailable,
            "enrollment-account" => IrOnlyReadiness::EnrollmentUnavailable,
            "incompatible-account" => IrOnlyReadiness::IncompatibleEnrollment,
            _ => return Response::Error("unknown fixture account".into()),
        };
        Response::FaceSensorStatus {
            policy: FaceSensorPolicyObservation::Explicit(FaceSensorPolicy::IrOnlyExperimental),
            ir_readiness: Some(ir_readiness),
        }
    });

    for (account, success, expected) in [
        ("ready-account", true, "prerequisites are ready"),
        ("unavailable-account", false, "preflight unavailable"),
        ("invalid-policy-account", false, "policy is invalid"),
        (
            "target-account",
            false,
            "configured IR target is unavailable",
        ),
        (
            "binding-absent-account",
            false,
            "IR enrollment has no camera binding",
        ),
        ("binding-mismatch-account", false, "different IR camera"),
        ("models-account", false, "face models are unavailable"),
        ("pad-account", false, "IR anti-spoofing is unavailable"),
        (
            "enrollment-account",
            false,
            "face enrollment is unavailable",
        ),
        ("incompatible-account", false, "compatible IR scans"),
    ] {
        let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "preflight", account]));
        assert_eq!(code == 0, success, "{account}: {out} {err}");
        let rendered = format!("{out}{err}");
        assert!(rendered.contains(expected), "{account}: {rendered}");
        assert!(!rendered.contains(account), "{account}: {rendered}");
        assert!(
            rendered.contains("daemon observed: EXPERIMENTAL IR-only"),
            "{account}: {rendered}"
        );
        if success {
            assert!(rendered.contains("EXPERIMENTAL"), "{rendered}");
            assert!(rendered.contains("does not prove capture"), "{rendered}");
            assert!(rendered.contains("not qualified"), "{rendered}");
        } else {
            assert!(rendered.contains("password"), "{account}: {rendered}");
        }
    }
    assert_eq!(requests.lock().unwrap().len(), 10);
}

#[test]
fn auth_sensor_preflight_fails_closed_for_missing_or_future_readiness() {
    use irlume_common::config::{FaceSensorPolicy, FaceSensorPolicyObservation};

    let sb = Sandbox::new("sensor-preflight-unknown");
    let requests = serve(&sock(&sb), |_| Response::FaceSensorStatus {
        policy: FaceSensorPolicyObservation::Explicit(FaceSensorPolicy::IrOnlyExperimental),
        ir_readiness: None,
    });
    let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "preflight", "missing-account"]));
    assert_ne!(code, 0, "{out} {err}");
    assert!(err.contains("could not establish"), "{out} {err}");
    assert!(!format!("{out}{err}").contains("missing-account"));
    drop(requests);

    use std::io::{BufRead, BufReader};
    let socket = sock(&sb);
    let _ = std::fs::remove_file(&socket);
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        let reply = serde_json::to_string(&Response::FaceSensorStatus {
            policy: FaceSensorPolicyObservation::Explicit(FaceSensorPolicy::IrOnlyExperimental),
            ir_readiness: Some(irlume_common::IrOnlyReadiness::Unavailable),
        })
        .unwrap()
        .replace("unavailable", "future_readiness");
        writeln!(stream, "{reply}").unwrap();
    });
    let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "preflight", "future-account"]));
    assert_ne!(code, 0, "{out} {err}");
    assert!(err.contains("could not establish"), "{out} {err}");
    let rendered = format!("{out}{err}");
    assert!(!rendered.contains("future-account"), "{rendered}");
    assert!(!rendered.contains("future_readiness"), "{rendered}");
}

#[test]
fn auth_sensor_owner_change_requires_ack_and_preserves_unrelated_settings() {
    let sb = Sandbox::new("sensor-owner");
    let original = "# retained\nprivileged_face_consent=1\ncapture_mode=sequential\n";
    std::fs::write(sb.path("cfg/settings.conf"), original).unwrap();
    let (code, _, err) = run(&mut sb.isolated_root_cmd(&["auth", "sensor", "ir-only"], &[]));
    assert_eq!(code, 2, "{err}");
    assert_eq!(
        std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap(),
        original
    );
    for (args, expected) in [
        (
            vec!["auth", "sensor", "ir-only", "--yes"],
            "ir-only-experimental",
        ),
        (vec!["auth", "sensor", "dual"], "dual"),
    ] {
        let (code, out, err) = run(&mut sb.isolated_root_cmd(&args, &[]));
        assert_eq!(code, 0, "{out} {err}");
        let saved = std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap();
        assert_eq!(saved, format!("{original}face_sensor_policy={expected}\n"));
        assert!(out.contains("Readiness is not established"), "{out}");
        assert!(!sb.path("cfg/cameras.conf").exists());
        assert!(!sb.path("state/retry").exists());
    }
}

#[test]
fn auth_sensor_refuses_nonroot_invalid_args_and_unreadable_updates() {
    let sb = Sandbox::new("sensor-refusals");
    if !is_root() {
        let (code, _, err) = run(&mut sb.cmd(&["auth", "sensor", "ir-only", "--yes"]));
        assert_ne!(code, 0);
        assert!(err.contains("root"), "{err}");
        assert!(!sb.path("cfg/settings.conf").exists());
    }
    for args in [
        vec!["auth", "sensor", "unknown"],
        vec!["auth", "sensor", "dual", "--yes"],
        vec!["auth", "sensor", "preflight", "--yes"],
        vec!["auth", "sensor", "ir-only", "--yes", "extra"],
    ] {
        assert_eq!(run(&mut sb.cmd(&args)).0, 2);
        assert!(!sb.path("cfg/settings.conf").exists());
    }
    let original = [0xff, 0xfe];
    std::fs::write(sb.path("cfg/settings.conf"), original).unwrap();
    let (code, _, _) = run(&mut sb.isolated_root_cmd(&["auth", "sensor", "dual"], &[]));
    assert_ne!(code, 0);
    assert_eq!(
        std::fs::read(sb.path("cfg/settings.conf")).unwrap(),
        original
    );
    let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "preflight"]));
    assert_ne!(code, 0);
    assert!(err.contains("could not establish"), "{out} {err}");
}

#[test]
fn auth_sensor_and_consent_concurrent_writes_preserve_both_policies() {
    let sb = Sandbox::new("sensor-concurrent");
    let sensor = sb
        .isolated_root_cmd(&["auth", "sensor", "ir-only", "--yes"], &[])
        .spawn()
        .unwrap();
    let consent = sb
        .isolated_root_cmd(&["auth", "consent", "hands-free", "--yes"], &[])
        .spawn()
        .unwrap();
    for child in [sensor, consent] {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let saved = std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap();
    assert!(
        saved.contains("face_sensor_policy=ir-only-experimental\n"),
        "{saved}"
    );
    assert!(saved.contains("privileged_face_consent=0\n"), "{saved}");
}

#[test]
fn auth_consent_status_reports_policy_without_contacting_daemon() {
    let sb = Sandbox::new("consent-status");
    for (value, label) in [
        (None, "required"),
        (Some("0"), "hands-free"),
        (Some("typo"), "required"),
    ] {
        if let Some(v) = value {
            std::fs::write(
                sb.path("cfg/settings.conf"),
                format!("privileged_face_consent={v}\n"),
            )
            .unwrap();
        }
        let (code, out, err) = run(sb
            .cmd(&["auth", "consent", "status"])
            .env_remove("IRLUME_PRIVILEGED_FACE_CONSENT"));
        assert_eq!(code, 0, "{out} {err}");
        assert!(out.contains(label) && out.contains("privileged"), "{out}");
    }
}

#[test]
fn auth_consent_rejects_unknown_arguments_without_writing() {
    let sb = Sandbox::new("consent-args");
    for args in [
        vec!["auth", "consent", "unknown"],
        vec!["auth", "consent", "required", "--yes"],
        vec!["auth", "consent", "hands-free", "--yes", "--user", "root"],
    ] {
        let (code, _, _) = run(&mut sb.cmd(&args));
        assert_eq!(code, 2);
        assert!(!sb.path("cfg/settings.conf").exists());
    }
}

#[test]
fn auth_consent_updates_are_authorized_explicit_and_preserve_other_settings() {
    let sb = Sandbox::new("consent-write");
    let original = "# keep this\nenforce_biopolicy=1\nprivileged_face_consent=1\n";
    std::fs::write(sb.path("cfg/settings.conf"), original).unwrap();
    let (code, _, _) = run(sb
        .cmd(&["auth", "consent", "hands-free"])
        .env_remove("IRLUME_PRIVILEGED_FACE_CONSENT"));
    assert_ne!(code, 0);
    assert_eq!(
        std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap(),
        original
    );
    let (code, out, err) = run(sb
        .cmd(&["auth", "consent", "hands-free", "--yes"])
        .env_remove("IRLUME_PRIVILEGED_FACE_CONSENT"));
    if !is_root() {
        assert_ne!(code, 0);
        assert!(err.contains("root"), "{out} {err}");
        assert_eq!(
            std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap(),
            original
        );
        return;
    }
    assert_eq!(code, 0, "{out} {err}");
    let saved = std::fs::read_to_string(sb.path("cfg/settings.conf")).unwrap();
    assert!(
        saved.contains("enforce_biopolicy=1")
            && saved.contains("# keep this")
            && saved.contains("privileged_face_consent=0"),
        "{saved}"
    );
    let (code, out, err) = run(sb
        .cmd(&["auth", "consent", "required"])
        .env_remove("IRLUME_PRIVILEGED_FACE_CONSENT"));
    assert_eq!(code, 0, "{out} {err}");
    assert!(std::fs::read_to_string(sb.path("cfg/settings.conf"))
        .unwrap()
        .contains("privileged_face_consent=1"));
}

#[test]
fn auth_consent_override_is_visible_and_blocks_misleading_writes() {
    let sb = Sandbox::new("consent-override");
    let (code, out, err) = run(sb
        .cmd(&["auth", "consent", "status"])
        .env("IRLUME_PRIVILEGED_FACE_CONSENT", "0"));
    assert_eq!(code, 0, "{out} {err}");
    assert!(
        out.contains("hands-free") && out.contains("environment override"),
        "{out}"
    );
    let (code, _, err) = run(sb
        .cmd(&["auth", "consent", "required"])
        .env("IRLUME_PRIVILEGED_FACE_CONSENT", "0"));
    assert_ne!(code, 0);
    assert!(err.contains("override"), "{err}");
    assert!(!sb.path("cfg/settings.conf").exists());
}

#[test]
fn auth_consent_never_overwrites_unreadable_settings() {
    let sb = Sandbox::new("consent-unreadable");
    let original = [0xff, 0x00, 0xfe];
    std::fs::write(sb.path("cfg/settings.conf"), original).unwrap();
    let (code, out, err) = run(sb
        .cmd(&["auth", "consent", "status"])
        .env_remove("IRLUME_PRIVILEGED_FACE_CONSENT"));
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("unknown"), "{out}");
    let (code, _, _) = run(sb
        .cmd(&["auth", "consent", "hands-free", "--yes"])
        .env_remove("IRLUME_PRIVILEGED_FACE_CONSENT"));
    assert_ne!(code, 0);
    assert_eq!(
        std::fs::read(sb.path("cfg/settings.conf")).unwrap(),
        original
    );
}

// ------------------------------------------------------------- retry recovery

fn retry_available() -> Response {
    Response::RetryStatus {
        face_budget: None, // Legacy daemon: cumulative enforcement is unknown.
        failures: 4,
        cooldown_seconds: 12,
        recovery_failures: 2,
        recovery_cooldown_seconds: 0,
        recovery_required: false,
        password_reset_available: true,
    }
}

/// Execute the actual password prompt on a private controlling terminal. Input
/// is synthetic and sent only after the prompt is visible AND ECHO is disabled.
/// Waiting for ECHO avoids a race between rpassword's prompt write and tcsetattr.
fn retry_terminal(cmd: &mut Command, input: Option<&str>) -> (i32, String) {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};

    let (mut master_fd, mut slave_fd) = (-1, -1);
    assert_eq!(
        // SAFETY: both output pointers are valid; null optional arguments select
        // default terminal settings and no requested slave pathname.
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: successful openpty transfers two valid, distinct descriptors.
    let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    // SAFETY: slave_fd is owned here exactly once, independently of master_fd.
    let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        assert_eq!(
            // SAFETY: the descriptors remain open throughout this call.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    cmd.stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave.try_clone().unwrap());
    // SAFETY: pre_exec uses only async-signal-safe libc operations. Descriptor
    // zero has already been installed from the slave before this closure runs.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop(slave);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut transcript = Vec::new();
    let mut sent = false;
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("retry command exceeded private terminal fixture deadline");
        }
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized entry and the fd remains open.
        let ready = unsafe { libc::poll(&mut poll, 1, 25) };
        assert!(ready >= 0);
        if ready > 0 && poll.revents & libc::POLLIN != 0 {
            let mut buffer = [0; 1024];
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => transcript.extend_from_slice(&buffer[..n]),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("private terminal read: {error}"),
            }
        }
        if !sent && String::from_utf8_lossy(&transcript).contains("Current login password: ") {
            let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
            assert_eq!(
                // SAFETY: tcgetattr initializes the valid output buffer on success.
                unsafe { libc::tcgetattr(master.as_raw_fd(), termios.as_mut_ptr()) },
                0
            );
            // SAFETY: the successful tcgetattr call initialized termios.
            if unsafe { termios.assume_init() }.c_lflag & libc::ECHO == 0 {
                if let Some(input) = input {
                    master.write_all(input.as_bytes()).unwrap();
                    sent = true;
                }
            }
        }
        status = status.or_else(|| child.try_wait().unwrap());
        if status.is_some() && ready == 0 {
            break;
        }
    }
    let status = status.unwrap_or_else(|| child.wait().unwrap());
    (
        status.code().expect("fixture child terminated by signal"),
        String::from_utf8(transcript).unwrap(),
    )
}

#[test]
fn retry_status_reports_daemon_state_without_camera_access() {
    let sb = Sandbox::new("retry-status");
    let requests = serve(&sock(&sb), |_| retry_available());
    let (code, text, error) = run(&mut sb.cmd(&["retry", "--user", "alice", "status"]));
    assert_eq!(code, 0, "{error}");
    assert!(
        text.contains("'alice': 4 recorded failures, 12s cooldown"),
        "{text}"
    );
    assert!(text.contains("2 failed checks, 0s cooldown"), "{text}");
    assert!(text.contains("Ordinary password login remains available"));
    assert!(
        text.contains("Cumulative face budget unavailable from this daemon; enforcement unknown.")
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(matches!(&requests[0], Request::RetryStatus { user } if user == "alice"));
}

#[test]
fn retry_reset_old_daemon_does_not_prompt_or_send_a_password() {
    let sb = Sandbox::new("retry-old-daemon");
    let requests = serve(&sock(&sb), |_| Response::Error("bad request".into()));
    let (code, transcript) =
        retry_terminal(&mut sb.cmd(&["retry", "reset", "--user", "alice"]), None);
    assert_eq!(code, 1);
    assert!(transcript.contains("support"), "{transcript}");
    assert!(!transcript.contains("Current login password:"));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(matches!(&requests[0], Request::RetryStatus { .. }));
}

#[test]
fn retry_status_distinguishes_prospective_and_exhausted_face_budget() {
    for (tag, count, expected) in [
        ("prospective", None, "earlier history unknown"),
        (
            "face-exhausted",
            Some(50),
            "50/50 consecutive unsuccessful; password-verified retry reset required",
        ),
    ] {
        let sb = Sandbox::new(&format!("retry-{tag}"));
        let _requests = serve(&sock(&sb), move |_| {
            let Response::RetryStatus {
                failures,
                cooldown_seconds,
                recovery_failures,
                recovery_cooldown_seconds,
                recovery_required,
                password_reset_available,
                ..
            } = retry_available()
            else {
                unreachable!()
            };
            Response::RetryStatus {
                failures,
                cooldown_seconds,
                recovery_failures,
                recovery_cooldown_seconds,
                recovery_required,
                password_reset_available,
                face_budget: Some(irlume_common::FaceRetryBudget {
                    unsuccessful_requests: count,
                    limit: 50,
                    reset_required: count == Some(50),
                }),
            }
        });
        let (code, text, error) = run(&mut sb.cmd(&["retry", "status", "--user", "alice"]));
        assert_eq!(code, 0, "{error}");
        assert!(text.contains(expected), "{text}");
        assert!(
            text.contains("Password-verified retry reset: available"),
            "{text}"
        );
        assert!(!text.contains("administrator reset required"), "{text}");
    }
}

#[test]
fn retry_reset_refuses_unavailable_limited_and_denied_status_before_prompting() {
    if is_root() {
        eprintln!("SKIP: non-root retry admission fixture; run default suite unprivileged");
        return;
    }
    for (tag, response) in [
        (
            "unavailable",
            Response::RetryStatus {
                face_budget: None,
                password_reset_available: false,
                failures: 0,
                cooldown_seconds: 0,
                recovery_failures: 0,
                recovery_cooldown_seconds: 0,
                recovery_required: false,
            },
        ),
        (
            "cooldown",
            Response::RetryStatus {
                face_budget: None,
                password_reset_available: true,
                failures: 0,
                cooldown_seconds: 0,
                recovery_failures: 5,
                recovery_cooldown_seconds: 30,
                recovery_required: false,
            },
        ),
        (
            "exhausted",
            Response::RetryStatus {
                face_budget: None,
                password_reset_available: true,
                failures: 0,
                cooldown_seconds: 0,
                recovery_failures: 50,
                recovery_cooldown_seconds: 0,
                recovery_required: true,
            },
        ),
        (
            "denied",
            Response::Error("permission denied: another account".into()),
        ),
    ] {
        let sb = Sandbox::new(&format!("retry-{tag}"));
        let requests = serve(&sock(&sb), move |_| response.clone());
        let (code, transcript) =
            retry_terminal(&mut sb.cmd(&["retry", "reset", "--user", "alice"]), None);
        assert_eq!(code, 1, "{tag}: {transcript}");
        assert!(!transcript.contains("Current login password:"), "{tag}");
        assert_eq!(requests.lock().unwrap().len(), 1, "{tag}");
    }
}

#[test]
fn retry_reset_reads_password_without_echo_and_sends_exact_request() {
    if is_root() {
        eprintln!("SKIP: non-root password fixture; run default suite unprivileged");
        return;
    }
    let sb = Sandbox::new("retry-password-pty");
    let requests = serve(&sock(&sb), |request| match request {
        Request::RetryStatus { .. } => retry_available(),
        Request::RetryReset { .. } => Response::Ok("Retry state reset.".into()),
        _ => Response::Error("unexpected".into()),
    });
    let (code, transcript) = retry_terminal(
        &mut sb.cmd(&["retry", "reset", "--user", "alice"]),
        Some("synthetic-retry-secret\n"),
    );
    assert_eq!(code, 0, "{transcript}");
    assert!(transcript.contains("Current login password: "));
    assert!(transcript.contains("Retry state reset."));
    assert!(!transcript.contains("synthetic-retry-secret"));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(matches!(&requests[0], Request::RetryStatus { user } if user == "alice"));
    assert!(
        matches!(&requests[1], Request::RetryReset { user, password } if user == "alice" && password.expose() == b"synthetic-retry-secret")
    );
}

#[test]
fn retry_reset_rejection_and_unexpected_reply_never_report_success() {
    if is_root() {
        eprintln!("SKIP: non-root password fixture; run default suite unprivileged");
        return;
    }
    for (tag, response) in [
        (
            "rejected",
            Response::Error("password verification failed".into()),
        ),
        ("unexpected", Response::HasPassword(true)),
    ] {
        let sb = Sandbox::new(&format!("retry-reset-{tag}"));
        let requests = serve(&sock(&sb), move |request| match request {
            Request::RetryStatus { .. } => retry_available(),
            _ => response.clone(),
        });
        let (code, out, error) = run_stdin(
            &mut sb.cmd(&["retry", "reset", "--user", "alice"]),
            "synthetic-retry-secret\n",
        );
        assert_eq!(code, 1, "{out} {error}");
        assert!(out.is_empty());
        assert!(!error.contains("synthetic-retry-secret"));
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}

#[test]
fn retry_root_override_is_explicit_and_sends_no_password() {
    if !is_root() {
        eprintln!("SKIP: root-only synthetic fixture; rerun this exact test as root");
        return;
    }
    let sb = Sandbox::new("retry-root");
    let requests = serve(&sock(&sb), |request| match request {
        Request::RetryStatus { .. } => Response::RetryStatus {
            face_budget: None,
            failures: 5,
            cooldown_seconds: 30,
            recovery_failures: 50,
            recovery_cooldown_seconds: 30,
            recovery_required: true,
            password_reset_available: false,
        },
        Request::RetryReset { .. } => Response::Ok("Administrator retry reset.".into()),
        _ => Response::Error("unexpected".into()),
    });
    let (code, transcript) =
        retry_terminal(&mut sb.cmd(&["retry", "reset", "--user", "alice"]), None);
    assert_eq!(code, 0, "{transcript}");
    assert!(transcript.contains("Administrator reset for 'alice'"));
    assert!(!transcript.contains("Current login password:"));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        matches!(&requests[1], Request::RetryReset { user, password } if user == "alice" && password.is_empty())
    );
}

#[test]
fn retry_rejects_ambiguous_arguments_before_contacting_daemon() {
    let sb = Sandbox::new("retry-invalid-args");
    let requests = serve(&sock(&sb), |_| retry_available());
    for args in [
        vec!["retry", "reset", "--user", ""],
        vec!["retry", "reset", "--user=alice", "--user=bob"],
        vec!["retry", "reset", "status"],
        vec!["retry", "reset", "--uesr", "alice"],
        vec!["retry", "--user"],
    ] {
        let (code, _, _) = run(&mut sb.cmd(&args));
        assert_eq!(code, 2, "{args:?}");
    }
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn retry_password_bounds_are_checked_before_reset_request() {
    if is_root() {
        eprintln!("SKIP: non-root password fixture; run default suite unprivileged");
        return;
    }
    for (tag, input, valid) in [
        ("empty", "\n".into(), false),
        ("nul", "synthetic\0secret\n".into(), false),
        ("long", format!("{}\n", "x".repeat(4097)), false),
        ("maximum", format!("{}\n", "x".repeat(4096)), true),
    ] {
        let sb = Sandbox::new(&format!("retry-password-{tag}"));
        let requests = serve(&sock(&sb), |request| match request {
            Request::RetryStatus { .. } => retry_available(),
            Request::RetryReset { .. } => Response::Ok("Retry state reset.".into()),
            _ => Response::Error("unexpected".into()),
        });
        let (code, _, _) = run_stdin(&mut sb.cmd(&["retry", "reset", "--user=alice"]), &input);
        assert_eq!(code, i32::from(!valid), "{tag}");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), if valid { 2 } else { 1 }, "{tag}");
        if valid {
            assert!(
                matches!(&requests[1], Request::RetryReset { password, .. } if password.len() == 4096)
            );
        }
    }
}

#[test]
fn retry_bare_status_reports_unavailable_and_exhausted_recovery() {
    for (tag, required, label) in [
        ("unavailable", false, "unavailable on this installation"),
        ("exhausted", true, "administrator reset required"),
    ] {
        let sb = Sandbox::new(&format!("retry-bare-status-{tag}"));
        let requests = serve(&sock(&sb), move |_| Response::RetryStatus {
            face_budget: None,
            failures: 0,
            cooldown_seconds: 0,
            recovery_failures: if required { 50 } else { 0 },
            recovery_cooldown_seconds: 0,
            recovery_required: required,
            password_reset_available: false,
        });
        let (code, out, err) = run(sb
            .cmd(&["retry"])
            .env("USER", "alice")
            .env_remove("SUDO_USER"));
        assert_eq!(code, 0, "{out} {err}");
        assert!(out.contains(label), "{out}");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(matches!(&requests[0], Request::RetryStatus { user } if user == "alice"));
    }
}

#[test]
fn auth_sensor_preflight_requires_ir_policy_even_if_readiness_claims_ready() {
    use irlume_common::config::{FaceSensorPolicy as Policy, FaceSensorPolicyObservation as State};
    let sb = Sandbox::new("sensor-preflight-policy-consistency");
    let requests = serve(&sock(&sb), |req| {
        let Request::FaceSensorStatus { user: Some(user) } = req else {
            return Response::Error("unexpected request".into());
        };
        let policy = match user.as_str() {
            "default-account" => State::DefaultDual,
            "dual-account" => State::Explicit(Policy::Dual),
            "invalid-account" => State::Invalid,
            "unreadable-account" => State::Unreadable,
            _ => unreachable!("fixture account"),
        };
        Response::FaceSensorStatus {
            policy,
            ir_readiness: Some(irlume_common::IrOnlyReadiness::ReadyForExperimentalAttempt),
        }
    });
    for (account, expected) in [
        ("default-account", "IR-only is not selected"),
        ("dual-account", "IR-only is not selected"),
        ("invalid-account", "sensor policy is invalid or unreadable"),
        (
            "unreadable-account",
            "sensor policy is invalid or unreadable",
        ),
    ] {
        let (code, out, err) = run(&mut sb.cmd(&["auth", "sensor", "preflight", account]));
        assert_ne!(code, 0, "{out} {err}");
        assert!(err.contains(expected), "{out} {err}");
        assert!(err.contains("password"), "{out} {err}");
        assert!(!out.contains("prerequisites are ready"), "{out}");
        assert!(!format!("{out}{err}").contains(account));
    }
    assert_eq!(requests.lock().unwrap().len(), 4);
}
