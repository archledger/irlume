// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `irlume fingerprint <status|add|enable|disable>`: fingerprint as a companion
//! auth modality via stock fprintd + pam_fprintd. irlume never claims the sensor;
//! it orchestrates enrollment (fprintd CLI) and wires pam_fprintd per distro.
//! `enable` also records the active method so the daemon disables face and lets
//! pam_fprintd drive. Ported from linhello.

use irlume_common::platform::{distro_family, DistroFamily};
use irlume_core::policy::{self, Method};
use irlume_fingerprint as fp;
use std::process::{Command, ExitCode};

pub fn run(action: Option<&str>, args: &[String]) -> ExitCode {
    let user = crate::user_arg(args);
    match action {
        None | Some("status") => status(&user),
        Some("add") => {
            if enroll_one(&user) {
                offer_verify(&user);
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("verify") => verify(&user),
        Some("reset") => reset(&user, args),
        Some("enable") => enable(&user, args),
        Some("disable") => disable(),
        _ => {
            eprintln!(
                "usage: irlume fingerprint [--user U] <status|add|verify|reset|enable|disable> [--fingerprint-only]\n  (enable adds fingerprint ALONGSIDE face = unlock with either; --fingerprint-only replaces face)"
            );
            ExitCode::from(2)
        }
    }
}

fn status(user: &str) -> ExitCode {
    println!(
        "[fingerprint] fprintd tooling : {}",
        if fp::fprintd_present() {
            "installed"
        } else {
            "NOT installed (install the 'fprintd' package)"
        }
    );
    let names = fp::device_names();
    let reader = match names.len() {
        0 if fp::reader_present() => "present (unnamed)".into(),
        0 => "none detected".into(),
        _ => names.join(" + "),
    };
    println!("[fingerprint] reader         : {reader}");
    if let Some(unit) = fp::bus_owner_unit() {
        if unit != "fprintd.service" {
            println!(
                "[fingerprint] ⚠ the fprint bus is owned by '{unit}', not fprintd.service: \
                 a vendor driver stack (open-fprintd/python-validity) is answering; \
                 its enrollment data and failure modes differ from stock fprintd"
            );
        }
    }
    // The listing can fail in ways that are NOT "no fingers enrolled" (stale
    // claim, polkit refusal, readerless box); say which, or the advice below
    // points the wrong way.
    let listing = fp::list_fingers(user);
    let mut fingers: Vec<String> = Vec::new();
    let mut list_error = None;
    match &listing {
        fp::ListOutcome::Fingers(v) => {
            fingers = v.clone();
            if fingers.is_empty() {
                println!("[fingerprint] enrolled       : none for '{user}'");
            } else {
                println!(
                    "[fingerprint] enrolled       : {} ({})",
                    fingers.len(),
                    fingers.join(", ")
                );
            }
        }
        fp::ListOutcome::NoDevice => {
            println!("[fingerprint] enrolled       : (fprintd reports no reader)");
        }
        fp::ListOutcome::Error(e) => {
            println!("[fingerprint] enrolled       : could not list: {e}");
            list_error = Some(e.clone());
        }
    }
    println!(
        "[fingerprint] active method   : {}",
        policy::method().as_str()
    );
    // Coverage rides on status too (read-only), so "which prompts does my
    // finger answer" is checkable any time, not only in enable's output the
    // one time it scrolled past. Shown only when a line is wired at all: on a
    // face-only box the table would be twelve ✗ rows of noise.
    if pam_fprintd_wired(&PamSearchPath::live()) {
        report_fprintd_coverage(&PamSearchPath::live());
    }
    // Recommendation. A failed listing means we do NOT know the enrollment
    // state; recommending `add` there sends the user the wrong way (live find:
    // over SSH, polkit refuses the listing while fingers are enrolled fine).
    if !fp::available() {
        println!("  → no usable reader; fingerprint unavailable on this device");
    } else if let Some(e) = list_error {
        println!("  → fix the listing first ({e}); enrollment state is unknown until then");
    } else if fingers.is_empty() {
        println!("  → reader present but no finger enrolled: run  irlume fingerprint add");
    } else {
        match policy::method() {
            Method::Both => {
                println!("  → active alongside face: unlock with either your face or your finger")
            }
            Method::Fingerprint => println!("  → fingerprint is the active unlock method"),
            _ => println!(
                "  → enrolled; enable it (kept alongside face if you have a camera):\n     \
                 sudo irlume fingerprint enable   (or --fingerprint-only to disable face)"
            ),
        }
    }
    ExitCode::SUCCESS
}

/// Enroll the first free finger for `user`. Returns success.
fn enroll_one(user: &str) -> bool {
    if !fp::fprintd_present() {
        eprintln!("[fingerprint] fprintd not installed; install the 'fprintd' package first");
        return false;
    }
    if !fp::reader_present() {
        eprintln!("[fingerprint] no fingerprint reader detected");
        return false;
    }
    let Some(finger) = fp::free_finger(user) else {
        eprintln!("[fingerprint] all 10 fingers are already enrolled for '{user}'");
        return false;
    };
    println!(
        "[fingerprint] enrolling '{finger}' for '{user}': place and lift your finger as prompted…"
    );
    match fp::enroll_finger(user, finger) {
        fp::EnrollOutcome::Enrolled => {
            println!("[fingerprint] ✓ enrolled '{finger}'");
            true
        }
        fp::EnrollOutcome::Duplicate => {
            eprintln!("[fingerprint] that finger is already enrolled");
            false
        }
        fp::EnrollOutcome::Failed(e) => {
            eprintln!("[fingerprint] enroll failed: {e}");
            false
        }
    }
}

/// Interactive yes/no prompt; returns `default_yes` on EOF or a bare Enter.
/// Never called when stdin is not a TTY (callers gate on that), so scripts
/// cannot hang here.
fn confirm(prompt: &str, default_yes: bool) -> bool {
    use std::io::Write;
    print!("{prompt} {} ", if default_yes { "[Y/n]" } else { "[y/N]" });
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return default_yes;
    }
    match line.trim() {
        "" => default_yes,
        s => s.eq_ignore_ascii_case("y") || s.eq_ignore_ascii_case("yes"),
    }
}

/// After a successful enrollment, offer one verification round. "Enroll
/// succeeds, verify never matches" is a top fprintd field complaint; one round
/// here catches it before the user relies on the print at the greeter.
fn offer_verify(user: &str) {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return;
    }
    if !confirm(
        "[fingerprint] verify the new print now?",
        /* default_yes: */ true,
    ) {
        return;
    }
    verify_round(user);
}

/// One verification round with outcome reporting; returns true on a match.
fn verify_round(user: &str) -> bool {
    println!("[fingerprint] place the enrolled finger on the reader…");
    match fp::verify_once(user) {
        fp::VerifyOutcome::Match => {
            println!("[fingerprint] ✓ verified");
            true
        }
        fp::VerifyOutcome::NoMatch => {
            eprintln!(
                "[fingerprint] ⚠ the reader did not match the finger you just enrolled. \
                 The enrollment may be low quality; run  irlume fingerprint reset  and \
                 re-enroll with slow, full placements."
            );
            false
        }
        fp::VerifyOutcome::Error(e) => {
            eprintln!("[fingerprint] verify failed: {e}");
            false
        }
    }
}

fn verify(user: &str) -> ExitCode {
    if !fp::available() {
        eprintln!("[fingerprint] no usable reader (need fprintd + a fingerprint reader)");
        return ExitCode::FAILURE;
    }
    // Use the checked listing: a polkit/claim failure must not masquerade as
    // "no finger enrolled" (live find: SSH sessions get polkit-refused).
    match fp::list_fingers(user) {
        fp::ListOutcome::Fingers(v) if v.is_empty() => {
            eprintln!("[fingerprint] no finger enrolled for '{user}'; run  irlume fingerprint add");
            return ExitCode::FAILURE;
        }
        fp::ListOutcome::Fingers(_) => {}
        fp::ListOutcome::NoDevice => {
            eprintln!("[fingerprint] fprintd reports no reader");
            return ExitCode::FAILURE;
        }
        fp::ListOutcome::Error(e) => {
            eprintln!("[fingerprint] cannot check enrollment: {e}");
            return ExitCode::FAILURE;
        }
    }
    if verify_round(user) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Delete every print fprintd holds for `user` and offer a fresh enrollment.
/// The remedy for chip/host template desync (Windows dual-boot enrollment, OS
/// reinstall, BIOS "clear fingerprints"): fprintd then lists fingers that never
/// verify, and only a full delete + re-enroll recovers.
fn reset(user: &str, args: &[String]) -> ExitCode {
    use std::io::IsTerminal;
    let assume_yes = args.iter().any(|a| a == "--yes");
    let fingers = match fp::list_fingers(user) {
        fp::ListOutcome::Fingers(v) => v,
        fp::ListOutcome::NoDevice => {
            eprintln!("[fingerprint] fprintd reports no reader; nothing to reset");
            return ExitCode::FAILURE;
        }
        fp::ListOutcome::Error(e) => {
            eprintln!("[fingerprint] cannot list current prints: {e}");
            return ExitCode::FAILURE;
        }
    };
    if fingers.is_empty() {
        println!("[fingerprint] no prints recorded for '{user}'; nothing to delete");
        return ExitCode::SUCCESS;
    }
    println!(
        "[fingerprint] this deletes ALL {} enrolled print(s) for '{user}': {}",
        fingers.len(),
        fingers.join(", ")
    );
    if !assume_yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("[fingerprint] refusing to delete without a terminal; pass --yes to force");
            return ExitCode::FAILURE;
        }
        if !confirm("[fingerprint] delete them?", /* default_yes: */ false) {
            println!("[fingerprint] nothing deleted");
            return ExitCode::SUCCESS;
        }
    }
    if let Err(e) = fp::delete_all(user) {
        eprintln!("[fingerprint] delete failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("[fingerprint] ✓ deleted {} print(s)", fingers.len());
    if std::io::stdin().is_terminal()
        && confirm(
            "[fingerprint] enroll a fresh print now?",
            /* default_yes: */ true,
        )
    {
        if enroll_one(user) {
            offer_verify(user);
        } else {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn require_root(op: &str) -> bool {
    if effective_uid() != 0 {
        eprintln!("[fingerprint] '{op}' modifies the system PAM config; run with: sudo irlume fingerprint {op}");
        return false;
    }
    true
}

/// Effective uid, read from `/proc/self/status` (no libc dep in the CLI).
fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Uid:")
                    .map(|v| v.split_whitespace().nth(1).unwrap_or("1000").to_string())
            })
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

fn enable(user: &str, args: &[String]) -> ExitCode {
    if !fp::available() {
        eprintln!("[fingerprint] no usable reader (need fprintd + a fingerprint reader)");
        return ExitCode::FAILURE;
    }
    if !require_root("enable") {
        return ExitCode::FAILURE;
    }
    // COEXIST is the default when a face camera is present: face and fingerprint
    // both stay active and the user unlocks with whichever is convenient.
    // `--fingerprint-only` forces the old fingerprint-only mode (face disabled).
    let fingerprint_only = args.iter().any(|a| a == "--fingerprint-only");
    let coexist = !fingerprint_only && crate::caps().rgb;
    // Enroll a finger first if the user has none.
    if !fp::has_enrollment(user) {
        println!("[fingerprint] no finger enrolled yet; enrolling one now");
        if !enroll_one(user) {
            return ExitCode::FAILURE;
        }
    }
    // Wire pam_fprintd into the auth stacks, per distro.
    let wired = match distro_family() {
        DistroFamily::Fedora => {
            run_cmd("authselect", &["enable-feature", "with-fingerprint"])
                && run_cmd("authselect", &["apply-changes"])
        }
        DistroFamily::Debian => run_cmd("pam-auth-update", &["--enable", "fprintd"]),
        // No supported wiring tool here. Proceed only when the admin has already
        // added the stanza: recording method=fingerprint with nothing wired
        // disables face while no biometric drives the prompt, silently leaving
        // the box password-only.
        DistroFamily::Arch | DistroFamily::Other => {
            let already = pam_fprintd_wired(&PamSearchPath::live());
            if already {
                println!(
                    "[fingerprint] found an active pam_fprintd.so line in {PAM_DIR}; using it"
                );
            } else {
                eprintln!("[fingerprint] no wiring tool on this distro; add the line yourself:");
                eprintln!("                auth  sufficient  pam_fprintd.so");
                eprintln!("              above pam_unix in your login/sudo PAM stacks");
                eprintln!("              (e.g. /etc/pam.d/system-local-login, /etc/pam.d/sudo),");
                eprintln!("              then re-run:  sudo irlume fingerprint enable");
            }
            already
        }
    };
    if !wired {
        eprintln!(
            "[fingerprint] method unchanged: face (irlume) stays active until pam_fprintd is wired"
        );
        return ExitCode::FAILURE;
    }
    // Verify the line actually landed before switching the method, even on the
    // tool paths: authselect/pam-auth-update can exit 0 without producing a
    // pam_fprintd line (e.g. a custom authselect profile lacking the feature).
    if !pam_fprintd_wired(&PamSearchPath::live()) {
        eprintln!(
            "[fingerprint] wiring reported success but {PAM_DIR} has no active pam_fprintd.so line"
        );
        eprintln!(
            "[fingerprint] method unchanged: face (irlume) stays active until pam_fprintd is wired"
        );
        return ExitCode::FAILURE;
    }
    // Disabling face demands more than "a line exists": with --fingerprint-only
    // the line must sit in a stack a tracked surface reaches (#234), or face
    // stands down while every real prompt is password-only. One check here
    // covers the authselect, pam-auth-update and already-wired paths alike.
    // Coexist mode keeps face active, so it stays on the broad check: a
    // custom-stack setup loses nothing there, and a dead finger line costs
    // only a wrong "either factor" message rather than a lost biometric.
    if !fingerprint_only_permitted(&PamSearchPath::live(), fingerprint_only) {
        eprintln!(
            "[fingerprint] an active pam_fprintd.so line exists, but no login surface irlume tracks reaches it"
        );
        eprintln!(
            "[fingerprint] --fingerprint-only refused: it would disable face while no tracked prompt has a fingerprint path"
        );
        eprintln!(
            "[fingerprint] method unchanged: wire pam_fprintd into a stack your login actually uses (see the table below), then re-run"
        );
        report_fprintd_coverage(&PamSearchPath::live());
        return ExitCode::FAILURE;
    }
    let method = if coexist {
        Method::Both
    } else {
        Method::Fingerprint
    };
    if let Err(e) = policy::set_method(method) {
        eprintln!("[fingerprint] wired, but could not record method: {e}");
        return ExitCode::FAILURE;
    }
    // Say what the wiring actually covers before claiming success. "Wired" is
    // satisfied by one active line anywhere; on a box where only the greeter
    // service carries it (#155), the success message used to promise finger
    // unlock at prompts that have no fingerprint path at all.
    report_fprintd_coverage(&PamSearchPath::live());
    if coexist {
        println!("[fingerprint] ✓ enabled alongside face: unlock with EITHER your face or your finger (password is the fallback).");
        println!("[fingerprint] wire the face lines too if you haven't:  sudo irlume login enable --apply");
    } else {
        println!("[fingerprint] ✓ enabled (fingerprint-only): irlume face is disabled, pam_fprintd drives, password is the fallback.");
    }
    ExitCode::SUCCESS
}

fn disable() -> ExitCode {
    if !require_root("disable") {
        return ExitCode::FAILURE;
    }
    let unwired = match distro_family() {
        DistroFamily::Fedora => {
            run_cmd("authselect", &["disable-feature", "with-fingerprint"])
                && run_cmd("authselect", &["apply-changes"])
        }
        DistroFamily::Debian => run_cmd("pam-auth-update", &["--disable", "fprintd"]),
        DistroFamily::Arch | DistroFamily::Other => {
            println!("[fingerprint] Remove the 'auth sufficient pam_fprintd.so' line you added.");
            true
        }
    };
    if !unwired {
        eprintln!("[fingerprint] failed to unwire pam_fprintd; check the output above");
        return ExitCode::FAILURE;
    }
    if let Err(e) = policy::set_method(Method::Auto) {
        eprintln!("[fingerprint] unwired, but could not reset method: {e}");
        return ExitCode::FAILURE;
    }
    println!("[fingerprint] ✓ disabled: face (irlume) is the active method again");
    ExitCode::SUCCESS
}

/// Where PAM service files live; a const so tests can exercise the scan on a
/// directory they control.
const PAM_DIR: &str = "/etc/pam.d";

/// The vendor service directory libpam falls back to when the machine
/// directory has no file for a service.
///
/// This is a build-time option, so it is established by measurement, not by
/// assuming an upstream default. On the two lanes that ship the directory it
/// was confirmed by BEHAVIOUR rather than by the path appearing in the
/// library: a `pam_start` + `pam_authenticate` probe against a service placed
/// only in `/usr/lib/pam.d` returned success, while a service that exists
/// nowhere fell through to `other` and denied.
///
/// - Fedora 44, pam-1.7.2-2.fc44: vendor-only service 0, absent service 7.
/// - Arch, pam 1.7.2-2: vendor-only service 0, absent service 7.
/// - Ubuntu 26.04, libpam 1.7.0-5ubuntu3: the path is compiled in, but the
///   directory does not exist, so `rooted` carries no vendor directory and
///   nothing is read or claimed.
///
/// The Arch measurement matters because that package's changelog records
/// `-Dvendordir=''`, which reads as removing the search directory; the
/// installed library disagrees, and KDE ships `kde-fingerprint` there and
/// nowhere else. Re-run the probe rather than trusting either source if this
/// ever needs revisiting.
const PAM_VENDOR_DIR: &str = "/usr/lib/pam.d";

/// The directories libpam consults for a service, in its order. The machine
/// directory wins: a file in `/etc/pam.d/sudo` overrides `/usr/lib/pam.d/sudo`
/// entirely rather than merging with it, and the vendor file is read only when
/// the machine has none (pam.conf(5)). Scanning the machine directory alone
/// understated coverage, omitting a service whose whole stack is a vendor file
/// even though PAM authenticates through it (#208).
#[derive(Debug, Clone)]
pub(crate) struct PamSearchPath {
    machine: std::path::PathBuf,
    /// `None` when the distro has no vendor directory, which is not the same
    /// as an empty one: nothing is read, and nothing is claimed about it.
    vendor: Option<std::path::PathBuf>,
}

impl PamSearchPath {
    /// The live path this machine's libpam would use.
    pub(crate) fn live() -> Self {
        Self::rooted(
            std::path::Path::new(PAM_DIR),
            Some(std::path::Path::new(PAM_VENDOR_DIR)),
        )
    }

    pub(crate) fn rooted(machine: &std::path::Path, vendor: Option<&std::path::Path>) -> Self {
        Self {
            machine: machine.to_path_buf(),
            vendor: vendor.filter(|v| v.is_dir()).map(|v| v.to_path_buf()),
        }
    }

    /// A machine directory with no vendor fallback, for tests that mean
    /// exactly one directory. Production always resolves through `live()`.
    #[cfg(test)]
    pub(crate) fn machine_only(machine: &std::path::Path) -> Self {
        Self {
            machine: machine.to_path_buf(),
            vendor: None,
        }
    }

    /// The directories this path actually read, for the report to name. A
    /// vendor directory that is not on this machine is not mentioned: telling
    /// a user the scan consulted `/usr/lib/pam.d` where no such directory
    /// exists claims a completeness the scan does not have. Ubuntu 26.04 is
    /// that case, with the path compiled into libpam and no directory shipped.
    fn summary(&self) -> String {
        match &self.vendor {
            Some(v) => format!(
                "per {} with {} as fallback",
                self.machine.display(),
                v.display()
            ),
            None => format!("per {}", self.machine.display()),
        }
    }

    /// The file PAM would open for `service`, or `None` when neither directory
    /// has one.
    pub(crate) fn service_path(&self, service: &str) -> Option<std::path::PathBuf> {
        let machine = self.machine.join(service);
        if Self::shadows(&machine) {
            return Some(machine);
        }
        self.vendor
            .as_ref()
            .map(|dir| dir.join(service))
            .filter(|p| Self::shadows(p))
    }

    /// Whether a path is a service file libpam would open, which is not the
    /// same as `is_file()`. Disabling a service by symlinking it to
    /// `/dev/null` is standard practice, and libpam opens that happily: the
    /// stack is empty and it shadows the vendor copy rather than deferring to
    /// it. `is_file()` follows the symlink to a character device, answers
    /// false, and would send the scan to a vendor file libpam never reads,
    /// reporting a fingerprint prompt as wired where PAM in fact denies.
    /// Verified on archhost (pam 1.7.2-2) with a pam_start probe: a machine
    /// service symlinked to /dev/null over a vendor copy stacking pam_permit
    /// authenticated as 7 (failure), not 0.
    fn shadows(p: &std::path::Path) -> bool {
        // Follows symlinks, so a dangling link is absent (libpam cannot open
        // it either) and a directory is not a stack.
        p.metadata().map(|m| !m.is_dir()).unwrap_or(false)
    }

    /// The service file's contents, following the same precedence.
    fn read_service(&self, service: &str) -> Option<String> {
        std::fs::read_to_string(self.service_path(service)?).ok()
    }

    /// Every service name PAM could load from this path, machine and vendor
    /// together, deduplicated so a service present in both is considered once
    /// and read from the machine copy that shadows the other.
    fn service_names(&self) -> Vec<String> {
        let mut names: std::collections::BTreeSet<String> = Default::default();
        for dir in std::iter::once(&self.machine).chain(self.vendor.iter()) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                // Directory enumeration keys on the dot exactly as before: a
                // service name carries none, and every backup leftover does.
                if !name.contains('.') {
                    names.insert(name);
                }
            }
        }
        names.into_iter().collect()
    }
}

/// [`fprintd_coverage`] over the live `/etc/pam.d`, for surfaces outside this
/// module (the TUI's Fingerprint screen shows the same table `fingerprint
/// status` prints, from the same walk).
pub(crate) fn fprintd_coverage_live() -> Vec<(&'static str, &'static str, bool)> {
    fprintd_coverage(&PamSearchPath::live())
}

/// Does `text` contain an auth RULE whose module-path names `module`?
///
/// This feeds [`pam_fprintd_wired`], the gate that keeps `fingerprint enable`
/// from recording a method nothing drives, so it must recognize what libpam
/// recognizes and nothing more. Matching the raw line let a trailing comment
/// pass the gate; matching the directive as a SUBSTRING still let a `session`
/// line (never run by `pam_authenticate`), a module argument naming the file,
/// or `pam_fprintd.so.disabled` pass it. With `--fingerprint-only` each of
/// those stood face down on a box where no fingerprint rule answers any
/// prompt, the precise outcome the gate exists to prevent. Parsing the rule
/// fields ([`crate::pamwire::directive_has_auth_module`]) closes the class.
/// `faillock_cohabits` (a doctor warning) and `fprintd_in_sudo` (the SSH
/// stall warning) inherit the same semantics through this function.
fn has_auth_module(text: &str, module: &str) -> bool {
    text.lines()
        .any(|l| crate::pamwire::directive_has_auth_module(l, module))
}

/// The contents of every file in `pam_dir` that PAM will actually load.
///
/// `pam_start()` opens `/etc/pam.d/<service>`, and a service name carries no
/// dot: it is the application's own name (`login`, `sudo`, `plasmalogin`).
/// Leftovers in that directory all do carry one. Package managers write
/// `.rpmsave`/`.rpmnew`/`.pacsave`/`.pacnew`/`.dpkg-old`, editors write `.bak`,
/// and irlume's own wiring backs each stack up to `.pre-irlume` BESIDE the
/// original. Reading those as if they were live stacks is how a scan concludes
/// "wired" about a file nothing loads.
///
/// Keying on the dot instead of a list of known backup suffixes is deliberate:
/// a Fedora box in the field carried an active pam_fprintd line in
/// `system-auth.pre-linhello-uninstall`, a name no such list would have held.
///
/// This governs DIRECTORY ENUMERATION only. A live stack may `include` a dotted
/// file by name, and PAM does follow that; [`fprintd_in_sudo`] resolves include
/// targets by name for exactly that reason. The cost here is a false negative in
/// that exotic case, which leaves the method unchanged and face active.
fn live_pam_stacks(path: &PamSearchPath) -> Vec<String> {
    // Read each service ONCE, through the same precedence PAM uses. Reading
    // every file in both directories would let a vendor file that a machine
    // file shadows answer for a stack PAM never loads.
    path.service_names()
        .iter()
        .filter_map(|svc| path.read_service(svc))
        .collect()
}

/// True when a PAM stack PAM actually loads carries an auth rule whose module
/// is `pam_fprintd.so`. Unreadable dirs/files count as not wired, and so does
/// a `\`-continued file: libpam joins those lines before tokenizing, so a
/// physical line reading `auth ... pam_fprintd.so` can really be the tail of
/// a session directive's arguments, executed never.
///
/// This establishes EXISTENCE only, which gates displays and the "did the
/// wiring tool write anything" verify. It says nothing about whether a prompt
/// reaches the line: a package can ship a service file nothing invokes.
/// Standing face down takes [`fprintd_reaches_tracked_surface`] (#234).
fn pam_fprintd_wired(path: &PamSearchPath) -> bool {
    live_pam_stacks(path)
        .iter()
        .any(|s| !crate::pamwire::has_line_continuation(s) && has_auth_module(s, "pam_fprintd.so"))
}

/// True when one PAM service file stacks BOTH pam_faillock and pam_fprintd.
/// That combination locks accounts in the field: a touch sensor misread burns
/// all fingerprint retries in under two seconds, each one counting as a
/// faillock failure (fprintd#209/#215). Doctor surfaces it with the
/// `faillock --reset` remedy.
pub(crate) fn faillock_cohabits(path: &PamSearchPath) -> bool {
    live_pam_stacks(path)
        .iter()
        .any(|s| has_auth_module(s, "pam_faillock.so") && has_auth_module(s, "pam_fprintd.so"))
}

/// True when the sudo PAM service reaches pam_fprintd, either directly or via
/// one level of `include`/`substack` (Fedora's sudo includes system-auth, which
/// is where authselect puts the fingerprint line). Paired with a running sshd
/// this stalls every `sudo` typed in an SSH session for the full fingerprint
/// timeout: the prompt waits on a reader the remote user cannot touch.
pub(crate) fn fprintd_in_sudo(path: &PamSearchPath) -> bool {
    let Some(sudo) = path.read_service("sudo") else {
        return false;
    };
    if has_auth_module(&sudo, "pam_fprintd.so") {
        return true;
    }
    for l in sudo.lines() {
        // Directive part only, like every other PAM read in this file: a
        // full-line comment yields "" (no tokens), and a trailing comment can
        // never contribute an include target.
        let mut parts = crate::pamwire::directive(l).split_whitespace();
        // `auth include system-auth` / `auth substack system-auth`, and the
        // one-word `@include common-auth` Debian form.
        let target = match (parts.next(), parts.next(), parts.next()) {
            (Some("@include"), Some(name), _) => Some(name),
            (Some(_), Some("include" | "substack"), Some(name)) => Some(name),
            _ => None,
        };
        if let Some(name) = target {
            if path
                .read_service(name)
                .is_some_and(|s| has_auth_module(&s, "pam_fprintd.so"))
            {
                return true;
            }
        }
    }
    false
}

/// The auth surfaces whose stacks decide what a recorded fingerprint method
/// actually covers, as `(service file, human label)`. A service missing from
/// the machine is simply not reported on.
///
/// These are the same surfaces `login enable` knows how to wire for face, plus
/// the fingerprint-specific services (`gdm-fingerprint`, `kde-fingerprint`)
/// and `login`, the console; the issue-#155 box had a covered greeter and an
/// uncovered console, and only a list that names both can say so.
const FP_SURFACES: &[(&str, &str)] = &[
    (
        "gdm-fingerprint",
        "login screen (GNOME, fingerprint service)",
    ),
    ("gdm-password", "login screen (GNOME, password service)"),
    ("plasmalogin", "login screen (Plasma)"),
    ("sddm", "login screen (SDDM)"),
    ("lightdm", "login screen (LightDM)"),
    ("greetd", "login screen (greetd)"),
    ("cosmic-greeter", "login screen (COSMIC)"),
    ("ly", "login screen (ly)"),
    ("kde", "lock screen (KDE)"),
    ("kde-fingerprint", "lock screen (KDE, fingerprint slot)"),
    ("login", "console login"),
    ("sudo", "sudo"),
];

/// True when authenticating against `service` can reach an ACTIVE
/// `pam_fprintd.so` auth line, resolving includes transitively.
///
/// The resolution rules mirror what libpam's evaluation was observed to do
/// (each pinned by running a stack through `pam_authenticate` with
/// `pam_exec.so` tracing which modules execute):
///
///   * `auth include X` / `auth substack X` pull in X's auth lines, and X's
///     own includes resolve too (a module two levels down executed);
///   * `@include X` (the Debian form) reaches X's auth lines the same way;
///   * a `session include X` contributes NOTHING to authentication (a
///     session line in an included file did not run during `pam_authenticate`),
///     so only auth-phase includes are followed;
///   * PAM opens include targets by NAME, dotted or not: `auth include
///     system-auth.custom` executed its module. This is why the walk reads
///     files by name instead of reusing [`live_pam_stacks`], whose dot filter
///     is about directory ENUMERATION, not include targets.
///
/// Lines are read with [`crate::pamwire::directive`] semantics (everything
/// before the first `#`), so a commented-out include or module never counts.
/// Cycles terminate because a file is visited at most once; the depth cap is a
/// backstop far above any real stack's include chain.
///
/// The walk is in stack ORDER, because reaching the module is not a set
/// membership question: a rule guaranteed to end authentication earlier in
/// the stack makes every later line unreachable (#261 review). See
/// [`guaranteed_auth_exit`] for exactly which rules are modeled that way, and
/// why the set is that small.
pub(crate) fn stack_reaches_fprintd(path: &PamSearchPath, service: &str) -> bool {
    walk_auth(path, service, &mut Vec::new()) == AuthWalk::ReachesFprintd
}

/// What walking a stack's auth phase in order arrives at first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthWalk {
    /// Fell off the end; an including caller's next line runs.
    Continues,
    /// An executable `pam_fprintd.so` rule.
    ReachesFprintd,
    /// A rule guaranteed to end authentication, so no later line (in this file
    /// OR in an including caller) can let a finger answer. For `include` the
    /// return is immediate; for `substack` the failure is recorded like a
    /// required module's, and a recorded requisite failure blocks any later
    /// `sufficient` success from granting, so a fingerprint line after either
    /// inclusion form cannot complete an authentication (pam.conf(5)).
    Terminates,
}

/// A rule guaranteed to end authentication before any later line matters:
/// `pam_deny` always fails, and a failed `requisite` returns immediately.
///
/// Deliberately the ONLY modeled exit. The other candidates are stateful or
/// conditional, and modeling them from file contents alone would refuse
/// working setups: `sufficient pam_permit.so` short-circuits only when no
/// earlier required module failed, and `requisite pam_nologin.so` fails only
/// while /etc/nologin exists; Arch's real vendor kde-fingerprint stack opens
/// with exactly that line (pinned in the tests) and its finger works. An
/// unmodeled rule falls through to "continues", which errs toward permitting,
/// never toward refusing a finger that genuinely answers.
fn guaranteed_auth_exit(control: Option<&str>, line: &str) -> bool {
    control.is_some_and(|c| c.eq_ignore_ascii_case("requisite"))
        && crate::pamwire::directive_has_auth_module(line, "pam_deny.so")
}

fn walk_auth(path: &PamSearchPath, name: &str, seen: &mut Vec<String>) -> AuthWalk {
    if seen.len() >= 16 || seen.iter().any(|s| s == name) {
        return AuthWalk::Continues;
    }
    seen.push(name.to_string());
    // Each include target resolves through the search path too: a
    // machine stack may include a service whose only file is the vendor's.
    let Some(text) = path.read_service(name) else {
        return AuthWalk::Continues;
    };
    // A `\`-continued file defeats line-oriented reading: libpam joins
    // those lines before tokenizing, so a physical line that LOOKS like
    // `auth ... pam_fprintd.so` can really be the tail of a session
    // directive's arguments, executed never, in any phase (verified: the
    // spliced line did not run under pam_authenticate). Claiming coverage
    // from such a line would rebuild the exact over-promise this walker
    // exists to end, so a continued file contributes nothing: "continues" is
    // the safe direction (an uncovered surface asks the user to check; a
    // covered one tells them to rely on it).
    if crate::pamwire::has_line_continuation(&text) {
        return AuthWalk::Continues;
    }
    for line in text.lines() {
        let d = crate::pamwire::directive(line);
        let mut toks = d.split_whitespace();
        let (t1, t2, t3) = (toks.next(), toks.next(), toks.next());
        let Some(first) = t1 else { continue };
        if first == "@include" {
            if let Some(target) = t2 {
                match walk_auth(path, target, seen) {
                    AuthWalk::Continues => {}
                    ended => return ended,
                }
            }
            continue;
        }
        // Only the auth phase authenticates; `-auth` is auth with PAM's
        // missing-module tolerance.
        if first.strip_prefix('-').unwrap_or(first) != "auth" {
            continue;
        }
        match (t2, t3) {
            (Some("include" | "substack"), Some(target)) => match walk_auth(path, target, seen) {
                AuthWalk::Continues => {}
                ended => return ended,
            },
            // The module-path FIELD, not a substring of the directive: an
            // argument naming the file (`pam_exec.so log=/x/pam_fprintd.so`)
            // is not a fingerprint rule.
            _ if crate::pamwire::directive_has_auth_module(line, "pam_fprintd.so") => {
                return AuthWalk::ReachesFprintd
            }
            _ if guaranteed_auth_exit(t2, line) => return AuthWalk::Terminates,
            _ => {}
        }
    }
    AuthWalk::Continues
}

/// Per-surface fingerprint coverage: which of the stacks present on this
/// machine reach a pam_fprintd prompt. This is the answer #155 asked for;
/// `pam_fprintd_wired` says "an active line exists somewhere", which is the
/// right GATE (face must not stand down while nothing drives a prompt), but
/// the wrong REPORT: on the observed Ubuntu box the only carrier was
/// `gdm-fingerprint`, so "you can unlock with a finger" was true at the
/// greeter and false at sudo and the console.
pub(crate) fn fprintd_coverage(path: &PamSearchPath) -> Vec<(&'static str, &'static str, bool)> {
    FP_SURFACES
        .iter()
        .filter(|(svc, _)| path.service_path(svc).is_some())
        .map(|(svc, label)| (*svc, *label, stack_reaches_fprintd(path, svc)))
        .collect()
}

/// True when a surface irlume tracks can reach an active `pam_fprintd.so`
/// auth rule. This is the gate before `--fingerprint-only` disables face
/// (#234): [`pam_fprintd_wired`] establishes that an active line EXISTS, but a
/// package can ship a service file nothing invokes, and a line no prompt
/// drives must not stand face down. The cost is a false refusal for a login
/// path outside [`FP_SURFACES`]; that failure leaves the method unchanged and
/// face active, and the refusal names the unreachable line so the admin knows
/// what was found.
fn fprintd_reaches_tracked_surface(path: &PamSearchPath) -> bool {
    fprintd_coverage(path)
        .iter()
        .any(|(_, _, reaches)| *reaches)
}

/// The #234 enable decision as a value, because the flow that consults it
/// (`enable`) talks to the live `/etc/pam.d` and needs root plus a reader, so
/// no test can drive it against a fixture. Coexist keeps face active, so only
/// `--fingerprint-only` demands a reached surface.
fn fingerprint_only_permitted(path: &PamSearchPath, fingerprint_only: bool) -> bool {
    !fingerprint_only || fprintd_reaches_tracked_surface(path)
}

/// Print the coverage table. Advisory: it never changes the enable decision,
/// only what the user is told that decision means.
fn report_fprintd_coverage(path: &PamSearchPath) {
    let cov = fprintd_coverage(path);
    if cov.is_empty() {
        return;
    }
    // The scan follows libpam's own search path since #208, so name the
    // directories it actually read. A surface served purely by a vendor stack
    // now appears; before, it was missing from the table entirely.
    println!(
        "[fingerprint] coverage: where a finger can answer the prompt ({}):",
        path.summary()
    );
    for (svc, label, reaches) in &cov {
        println!("    {} {label}  ({svc})", if *reaches { "✓" } else { "✗" });
    }
    if !cov.iter().any(|(_, _, r)| *r) {
        // The gate saw an active line, but it sits in a stack no tracked
        // surface reaches (a custom service, or a file only reachable from
        // one). Say so instead of letting the ✓ message imply otherwise.
        println!(
            "    ⚠ an active pam_fprintd.so line exists, but none of the stacks above\n      \
             reaches it; fingerprint will not answer these prompts as wired."
        );
    }
}

/// True when an OpenSSH server is active or enabled (unit is `sshd` on
/// Fedora/Arch, `ssh` on Debian/Ubuntu).
pub(crate) fn sshd_present() -> bool {
    ["sshd", "ssh"].iter().any(|unit| {
        std::process::Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .is_ok_and(|s| s.success())
            || std::process::Command::new("/usr/bin/systemctl")
                .args(["is-enabled", "--quiet", unit])
                .status()
                .is_ok_and(|s| s.success())
    })
}

/// Run a system command, echoing it (transparency) and reporting success.
fn run_cmd(cmd: &str, args: &[&str]) -> bool {
    println!("[fingerprint] $ {cmd} {}", args.join(" "));
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("[fingerprint] {cmd} exited with {s}");
            false
        }
        Err(e) => {
            eprintln!("[fingerprint] could not run {cmd}: {e} (is it installed?)");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_uid_matches_the_real_euid() {
        // The /proc/self/status parse must yield the kernel's effective uid.
        assert_eq!(effective_uid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn require_root_gates_on_the_effective_uid() {
        // Consistent with effective_uid: only uid 0 clears the gate.
        if effective_uid() == 0 {
            assert!(require_root("enable"));
        } else {
            assert!(!require_root("enable"));
        }
    }

    #[test]
    fn run_cmd_maps_spawn_and_exit_outcomes_to_a_bool() {
        // Zero exit → true, non-zero → false, un-spawnable → false. Uses the
        // harmless true/false shells, never a real authselect/pam-auth-update.
        assert!(run_cmd("true", &[]));
        assert!(!run_cmd("false", &[]));
        assert!(!run_cmd("irlume-no-such-command-xyz", &["arg"]));
    }

    #[test]
    fn pam_fprintd_wired_needs_an_active_line() {
        let dir = std::env::temp_dir().join(format!("irlume-fpwire-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Empty directory: nothing wired.
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        // A commented-out line does not count.
        std::fs::write(dir.join("sudo"), "#auth sufficient pam_fprintd.so\n").unwrap();
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        // Nor a TRAILING comment: libpam tokenizes only up to the first '#',
        // so this stack drives no fingerprint prompt. Passing the gate here
        // records a method nothing serves; with --fingerprint-only, face
        // stands down on a box where no biometric answers any prompt.
        std::fs::write(
            dir.join("sudo"),
            "auth required pam_unix.so   # was pam_fprintd.so\n",
        )
        .unwrap();
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        // Unrelated modules do not count.
        std::fs::write(dir.join("login"), "auth required pam_unix.so\n").unwrap();
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        // An active line in any file does.
        std::fs::write(
            dir.join("system-local-login"),
            "auth  sufficient  pam_fprintd.so\nauth required pam_unix.so\n",
        )
        .unwrap();
        assert!(pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreferenced_carrier_alone_does_not_reach_a_surface() {
        // The #234 acceptance case: a package ships a service file carrying an
        // active pam_fprintd line, but nothing on the machine invokes that
        // service. Existence holds; reachability must not.
        let dir = pam_dir(
            "unref-carrier",
            &[
                ("example-fingerprint", "auth sufficient pam_fprintd.so\n"),
                ("sudo", "auth required pam_unix.so\n"),
            ],
        );
        let path = PamSearchPath::machine_only(&dir);
        assert!(pam_fprintd_wired(&path), "the line exists");
        assert!(
            !fprintd_reaches_tracked_surface(&path),
            "an unreferenced carrier must not license --fingerprint-only"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_vendor_only_carrier_is_also_not_reachable() {
        // Same acceptance case through the vendor directory, where #231 made
        // unreferenced carriers likelier: packages ship there, admins do not.
        let machine = pam_dir("vendor-unref-m", &[("sudo", "auth required pam_unix.so\n")]);
        let vendor = pam_dir(
            "vendor-unref-v",
            &[("example-fingerprint", "auth sufficient pam_fprintd.so\n")],
        );
        let path = PamSearchPath::rooted(&machine, Some(&vendor));
        assert!(pam_fprintd_wired(&path), "the vendor line exists");
        assert!(!fprintd_reaches_tracked_surface(&path));
        std::fs::remove_dir_all(machine).unwrap();
        std::fs::remove_dir_all(vendor).unwrap();
    }

    #[test]
    fn a_tracked_surface_reaching_through_an_include_still_counts() {
        // Fedora's shape: sudo includes system-auth, where authselect puts the
        // fingerprint line. The tightened gate must not refuse this.
        let dir = pam_dir(
            "include-reach",
            &[
                ("sudo", "auth include system-auth\n"),
                (
                    "system-auth",
                    "auth sufficient pam_fprintd.so\nauth required pam_unix.so\n",
                ),
            ],
        );
        assert!(fprintd_reaches_tracked_surface(
            &PamSearchPath::machine_only(&dir)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removing_the_tracked_surface_flips_the_gate_to_refusal() {
        // The negative control from #234's acceptance: with the tracked
        // surface present the gate permits; delete it, leaving only the
        // unreferenced carrier, and the same machine must refuse.
        let dir = pam_dir(
            "negative-control",
            &[
                ("kde-fingerprint", "auth sufficient pam_fprintd.so\n"),
                ("carrier-nobody-calls", "auth sufficient pam_fprintd.so\n"),
            ],
        );
        let path = PamSearchPath::machine_only(&dir);
        assert!(fprintd_reaches_tracked_surface(&path));
        std::fs::remove_file(dir.join("kde-fingerprint")).unwrap();
        assert!(
            !fprintd_reaches_tracked_surface(&path),
            "the carrier alone kept the gate open"
        );
        assert!(
            pam_fprintd_wired(&path),
            "existence still holds, so only the reach check refused"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn requisite_deny_before_fprintd_does_not_count_as_reached() {
        // pam_deny always fails and a failed requisite returns immediately, so
        // PAM is guaranteed never to execute the fingerprint line below it. A
        // walk that reads text instead of control flow counts it, and the gate
        // then stands face down on a stack whose prompt can never be answered
        // by a finger (#261 review).
        let dir = pam_dir(
            "deny-before-fprintd",
            &[(
                "login",
                "auth requisite pam_deny.so\nauth sufficient pam_fprintd.so\n",
            )],
        );
        let path = PamSearchPath::machine_only(&dir);
        assert!(!stack_reaches_fprintd(&path, "login"));
        assert!(!fingerprint_only_permitted(&path, true));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn requisite_deny_inside_an_include_stops_the_parent_too() {
        // The termination has to propagate: an included stack that exits
        // authentication exits it for the caller as well, so a fingerprint
        // line after the include is just as unreachable.
        let dir = pam_dir(
            "deny-in-include",
            &[
                (
                    "login",
                    "auth include blocker\nauth sufficient pam_fprintd.so\n",
                ),
                ("blocker", "auth requisite pam_deny.so\n"),
            ],
        );
        let path = PamSearchPath::machine_only(&dir);
        assert!(!stack_reaches_fprintd(&path, "login"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_measured_arch_layout_keeps_its_permit() {
        // Verbatim from a real Arch machine (archhost, 2026-08-04): the only
        // pam_fprintd carrier is the vendor kde-fingerprint, which
        // kscreenlocker really invokes; the issue-#231 measured case. Note the
        // `-auth` tolerant form: a gate that fails to strip the `-` refuses
        // this whole distro. The tightened #234 gate must keep permitting it.
        let machine = pam_dir(
            "arch-real-m",
            &[(
                "kde",
                "#%PAM-1.0\n\nauth       sufficient   pam_irlume.so unseal ondemand\nauth       include                     system-local-login\n\naccount    include                     system-local-login\n",
            )],
        );
        let vendor = pam_dir(
            "arch-real-v",
            &[(
                "kde-fingerprint",
                "#%PAM-1.0\n\nauth       required                    pam_shells.so\nauth       requisite                   pam_nologin.so\nauth       requisite                   pam_faillock.so      preauth\n-auth      required                    pam_fprintd.so\nauth       optional                    pam_permit.so\nauth       required                    pam_env.so\n\naccount    include                     system-local-login\n",
            )],
        );
        let path = PamSearchPath::rooted(&machine, Some(&vendor));
        assert!(fprintd_reaches_tracked_surface(&path));
        assert!(fingerprint_only_permitted(&path, true));
        std::fs::remove_dir_all(machine).unwrap();
        std::fs::remove_dir_all(vendor).unwrap();
    }

    #[test]
    fn the_enable_decision_keys_on_the_flag_and_the_reach() {
        // Same unreachable-carrier machine, both flag values: coexist stays
        // permitted (face remains active, nothing is lost), --fingerprint-only
        // is refused. A gate that ignores either input fails one of these.
        let dir = pam_dir(
            "decision",
            &[
                ("carrier-nobody-calls", "auth sufficient pam_fprintd.so\n"),
                ("sudo", "auth required pam_unix.so\n"),
            ],
        );
        let path = PamSearchPath::machine_only(&dir);
        assert!(fingerprint_only_permitted(&path, false));
        assert!(!fingerprint_only_permitted(&path, true));
        // And with a reached surface, --fingerprint-only is permitted again.
        std::fs::write(dir.join("sudo"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(fingerprint_only_permitted(&path, true));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn continued_physical_auth_line_does_not_pass_enable_gate() {
        // libpam joins the two physical lines before tokenizing: PAM sees ONE
        // session directive whose arguments happen to contain the text of an
        // auth rule. The gate reading lines independently saw an auth line
        // and licensed --fingerprint-only to disable face with no fingerprint
        // rule anywhere.
        let dir = pam_dir(
            "continued-gate",
            &[(
                "login",
                "session optional pam_exec.so /bin/true \\\nauth optional pam_fprintd.so\n",
            )],
        );
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fingerprint_gate_requires_auth_module_path() {
        // A session rule never runs under pam_authenticate; an argument
        // naming the file is not the module-path field; a different filename
        // is a different module. Each of these passed the substring gate.
        for body in [
            "session optional pam_fprintd.so\n",
            "auth optional pam_exec.so /tmp/pam_fprintd.so\n",
            "auth optional pam_fprintd.so.disabled\n",
        ] {
            let dir = pam_dir("module-field", &[("login", body)]);
            assert!(
                !pam_fprintd_wired(&PamSearchPath::machine_only(&dir)),
                "{body:?}"
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
        // And the parser recognizes what libpam recognizes: a case-insensitive
        // type, a bracketed multi-token control, and a full module path.
        let dir = pam_dir(
            "module-field-positive",
            &[(
                "login",
                "AUTH [success=done default=ignore] /usr/lib64/security/pam_fprintd.so\n",
            )],
        );
        assert!(pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A scratch pam.d directory populated from `(name, content)` pairs.
    fn pam_dir(tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("irlume-fpcov-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
        dir
    }

    /// A machine and a vendor directory, for the precedence tests.
    fn pam_pair(
        tag: &str,
        machine: &[(&str, &str)],
        vendor: &[(&str, &str)],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let m = pam_dir(&format!("{tag}-etc"), machine);
        let v = pam_dir(&format!("{tag}-vendor"), vendor);
        (m, v)
    }

    /// libpam reads a service from the vendor directory when the machine has
    /// no file for it, and a machine file overrides its vendor namesake
    /// outright rather than merging (pam.conf(5)). Scanning `/etc/pam.d` alone
    /// omitted a service whose entire stack is a vendor file, so the coverage
    /// table understated what a finger answers (#208).
    #[test]
    fn a_vendor_service_counts_and_a_machine_file_overrides_it() {
        let wired = "auth sufficient pam_fprintd.so\n";
        let bare = "auth required pam_unix.so\n";
        let (m, v) = pam_pair(
            "vendor-precedence",
            // sudo exists in both, and the machine copy has NO fingerprint
            // line: PAM runs this one, so coverage must follow it.
            &[("sudo", bare)],
            // login exists only in the vendor directory, wired.
            &[("sudo", wired), ("login", wired)],
        );
        let path = PamSearchPath::rooted(&m, Some(&v));

        assert_eq!(path.service_path("sudo"), Some(m.join("sudo")));
        assert_eq!(path.service_path("login"), Some(v.join("login")));
        assert_eq!(path.service_path("nothing-here"), None);

        let cov = fprintd_coverage(&path);
        let by = |svc: &str| cov.iter().find(|(s, _, _)| *s == svc).map(|(_, _, r)| *r);
        // Vendor-only service appears at all, which is the omission #208 names.
        assert_eq!(by("login"), Some(true), "vendor-only stack must count");
        // The machine file shadows the wired vendor one, so sudo is NOT covered.
        assert_eq!(
            by("sudo"),
            Some(false),
            "a machine file overrides its vendor namesake"
        );

        // Machine-only reading sees neither the vendor service nor the truth
        // about sudo being the only surface: this is the old behaviour.
        let old = PamSearchPath::machine_only(&m);
        assert_eq!(fprintd_coverage(&old).len(), 1);

        for d in [m, v] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// `pam_fprintd_wired` is the GATE that lets `--fingerprint-only` stand
    /// face down, so it must not be fooled in either direction: a vendor stack
    /// really does drive a prompt, and a machine file that shadows a wired
    /// vendor file really does mean nothing drives one.
    #[test]
    fn the_wiring_gate_follows_the_same_precedence() {
        let wired = "auth sufficient pam_fprintd.so\n";
        let bare = "auth required pam_unix.so\n";

        let (m, v) = pam_pair("gate-vendor-only", &[], &[("login", wired)]);
        assert!(
            pam_fprintd_wired(&PamSearchPath::rooted(&m, Some(&v))),
            "a vendor stack drives a real prompt"
        );
        assert!(
            !pam_fprintd_wired(&PamSearchPath::machine_only(&m)),
            "and the machine directory alone cannot see it"
        );

        let (m2, v2) = pam_pair("gate-shadowed", &[("login", bare)], &[("login", wired)]);
        assert!(
            !pam_fprintd_wired(&PamSearchPath::rooted(&m2, Some(&v2))),
            "the shadowed vendor file is never loaded, so nothing is wired"
        );

        for d in [m, v, m2, v2] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// Symlinking a service to `/dev/null` is how an admin disables it, and
    /// libpam opens that as an empty stack that shadows the vendor copy. A
    /// scan that reads it as absent falls through to a vendor file libpam
    /// never loads and calls a prompt wired that PAM denies, which is the
    /// fail-open direction in the gate that stands face down. Confirmed on
    /// archhost (pam 1.7.2-2): the probe returned 7, not 0.
    #[test]
    fn a_service_disabled_with_dev_null_still_shadows_the_vendor_copy() {
        let wired = "auth sufficient pam_fprintd.so\n";
        let (m, v) = pam_pair("devnull-shadow", &[], &[("sudo", wired)]);
        std::os::unix::fs::symlink("/dev/null", m.join("sudo")).unwrap();
        let path = PamSearchPath::rooted(&m, Some(&v));

        assert_eq!(
            path.service_path("sudo"),
            Some(m.join("sudo")),
            "the /dev/null stack is what PAM opens"
        );
        assert!(
            !pam_fprintd_wired(&path),
            "an emptied stack must not report the shadowed vendor line as wired"
        );

        for d in [m, v] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// A vendor directory that is not there is not an empty one: nothing is
    /// read and nothing is claimed. Ubuntu 26.04 ships no /usr/lib/pam.d even
    /// though its libpam has the path compiled in.
    #[test]
    fn an_absent_vendor_directory_is_carried_as_none() {
        let m = pam_dir("vendor-absent", &[("login", "auth required pam_unix.so\n")]);
        let absent = std::env::temp_dir().join(format!("irlume-no-vendor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&absent);
        let path = PamSearchPath::rooted(&m, Some(&absent));
        assert_eq!(path.service_path("login"), Some(m.join("login")));
        assert_eq!(path.service_path("sudo"), None);
        // And the report must not claim it consulted a directory that is not
        // there, which is the only place the distinction is observable.
        let summary = path.summary();
        assert!(!summary.contains("fallback"), "{summary}");
        assert!(summary.contains(&m.display().to_string()), "{summary}");

        let present = pam_dir("vendor-present", &[("sudo", "auth required pam_unix.so\n")]);
        let with_vendor = PamSearchPath::rooted(&m, Some(&present));
        assert!(with_vendor.summary().contains("fallback"));
        assert!(with_vendor
            .summary()
            .contains(&present.display().to_string()));

        for d in [m, present] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    // The Ubuntu 26.04 box from issue #155, files verbatim from the report:
    // gdm-fingerprint alone carries the line; common-auth has no fingerprint
    // path; sudo and login reach only common-auth.
    const UBUNTU_GDM_FP: &str = "auth    requisite       pam_nologin.so\n\
auth\trequired\tpam_succeed_if.so user != root quiet_success\n\
auth\trequired\tpam_fprintd.so\n";
    const UBUNTU_COMMON_AUTH: &str = "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n\
auth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\n\
auth\trequisite\t\t\tpam_deny.so\n\
auth\trequired\t\t\tpam_permit.so\n\
auth\toptional\t\t\tpam_cap.so\n";

    #[test]
    fn issue_155_box_covers_the_greeter_and_nothing_else() {
        let dir = pam_dir(
            "ubuntu155",
            &[
                ("gdm-fingerprint", UBUNTU_GDM_FP),
                ("common-auth", UBUNTU_COMMON_AUTH),
                ("sudo", "@include common-auth\n@include common-account\n"),
                (
                    "login",
                    "auth       optional   pam_faildelay.so  delay=3000000\n@include common-auth\n",
                ),
            ],
        );
        // The old bool is truthfully "wired somewhere"…
        assert!(pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        // …and coverage says where that somewhere is, and is not.
        let cov = fprintd_coverage(&PamSearchPath::machine_only(&dir));
        let get = |svc: &str| cov.iter().find(|(s, _, _)| *s == svc).unwrap().2;
        assert!(get("gdm-fingerprint"), "the greeter really is covered");
        assert!(!get("sudo"), "sudo has no fingerprint path");
        assert!(!get("login"), "console login has no fingerprint path");
        // Absent services are not reported on at all.
        assert!(!cov.iter().any(|(s, _, _)| *s == "plasmalogin"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fedora_authselect_shape_covers_everything_through_system_auth() {
        // Rendered from authselect's own templates (profiles/{sssd,local}/…):
        // `with-fingerprint` emits `auth sufficient pam_fprintd.so` into
        // system-auth, and fingerprint-auth carries the [success=done] form.
        let dir = pam_dir(
            "fedora",
            &[
                (
                    "system-auth",
                    "auth        required      pam_env.so\n\
auth        sufficient    pam_fprintd.so\n\
auth        sufficient    pam_unix.so nullok\n\
auth        required      pam_deny.so\n",
                ),
                (
                    "fingerprint-auth",
                    "auth        required      pam_env.so\n\
auth        [success=done default=bad]   pam_fprintd.so\n\
auth        required      pam_deny.so\n",
                ),
                (
                    "gdm-fingerprint",
                    "auth        substack      fingerprint-auth\n\
auth        include       postlogin\n",
                ),
                (
                    "sudo",
                    "auth       include      system-auth\naccount    include      system-auth\n",
                ),
                (
                    "login",
                    "auth       substack     system-auth\naccount    required     pam_nologin.so\n",
                ),
            ],
        );
        let cov = fprintd_coverage(&PamSearchPath::machine_only(&dir));
        let get = |svc: &str| cov.iter().find(|(s, _, _)| *s == svc).unwrap().2;
        assert!(get("gdm-fingerprint"));
        assert!(
            get("sudo"),
            "authselect's line reaches sudo through the include"
        );
        assert!(get("login"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn arch_documented_flow_reports_what_the_admin_line_reaches() {
        // The Arch/Other instructions tell the admin to add the line to
        // system-local-login (and/or sudo) and re-run. Coverage must credit
        // exactly what that line reaches, console login via its include,
        // without pretending sudo gained a path it did not.
        let dir = pam_dir(
            "arch",
            &[
                ("system-local-login", "auth  sufficient  pam_fprintd.so\nauth      include   system-login\n"),
                ("login", "auth       include     system-local-login\naccount    include     system-local-login\n"),
                ("sudo", "auth       include     system-auth\n"),
                ("system-auth", "auth      required  pam_unix.so\n"),
                ("system-login", "auth      required  pam_unix.so\n"),
            ],
        );
        let cov = fprintd_coverage(&PamSearchPath::machine_only(&dir));
        let get = |svc: &str| cov.iter().find(|(s, _, _)| *s == svc).unwrap().2;
        assert!(get("login"), "the documented flow covers console login");
        assert!(!get("sudo"));
        // The enable gate itself stays satisfied, preserving that flow.
        assert!(pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolution_matches_the_observed_pam_semantics() {
        // Each arm mirrors a behaviour executed against libpam via pam_exec.so.
        // 1. Two-level `auth include` chains resolve (the deep module ran).
        let dir = pam_dir(
            "deep",
            &[
                ("login", "auth include level-a\n"),
                ("level-a", "auth include level-b\n"),
                ("level-b", "auth sufficient pam_fprintd.so\n"),
            ],
        );
        assert!(stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        // 2. A `session include` contributes nothing to authentication (the
        //    session line did NOT run during pam_authenticate).
        let dir = pam_dir(
            "sess",
            &[
                (
                    "login",
                    "session include sess-target\nauth required pam_unix.so\n",
                ),
                ("sess-target", "auth sufficient pam_fprintd.so\n"),
            ],
        );
        assert!(!stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        // 3. PAM opens include targets by NAME, dotted included (the module in
        //    system-auth.custom ran). The old any-live-file bool misses this
        //    file entirely (its dot filter is right for enumeration and wrong
        //    for include targets), so coverage can be true where wired() is
        //    false.
        let dir = pam_dir(
            "dotted",
            &[
                ("login", "auth include system-auth.custom\n"),
                ("system-auth.custom", "auth sufficient pam_fprintd.so\n"),
            ],
        );
        assert!(stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
        // 4. Comments are not configuration: a commented include is not
        //    followed and a commented module line is not a hit, while a
        //    trailing comment after a real target changes nothing.
        let dir = pam_dir(
            "comments",
            &[
                ("login", "# auth include real\nauth required pam_unix.so # pam_fprintd.so\nauth include real # trailing note\n"),
                ("real", "auth sufficient pam_fprintd.so\n"),
            ],
        );
        assert!(stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        let dir2 = pam_dir(
            "comments2",
            &[(
                "login",
                "# auth include real\nauth required pam_unix.so # pam_fprintd.so\n",
            )],
        );
        assert!(!stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir2),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    #[test]
    fn a_continued_file_never_claims_coverage() {
        // libpam joins a `\`-continued line with the next one before
        // tokenizing, so the physical line `auth optional pam_fprintd.so`
        // below is really the tail of the SESSION directive's arguments,
        // verified: it does not run during pam_authenticate. Reading it as an
        // auth line would report a finger answering a prompt it cannot,
        // the exact over-promise this walker exists to end.
        let dir = pam_dir(
            "splice",
            &[(
                "login",
                "session optional pam_exec.so /bin/true \\\nauth optional pam_fprintd.so\n",
            )],
        );
        assert!(!stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        // The refusal is per FILE, reached through includes too: a clean
        // service including a continued file gains nothing from it.
        let dir = pam_dir(
            "splice-included",
            &[
                ("login", "auth include tangled\n"),
                (
                    "tangled",
                    "auth optional pam_unix.so \\\n   nullok\nauth sufficient pam_fprintd.so\n",
                ),
            ],
        );
        assert!(!stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        // And a clean sibling path still resolves: only the continued file is
        // opaque, not the whole walk.
        let dir = pam_dir(
            "splice-sibling",
            &[
                ("login", "auth include tangled\nauth include clean\n"),
                ("tangled", "auth optional pam_unix.so \\\n   nullok\n"),
                ("clean", "auth sufficient pam_fprintd.so\n"),
            ],
        );
        assert!(stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolution_terminates_on_an_include_cycle() {
        let dir = pam_dir(
            "cycle",
            &[
                ("login", "auth include loop-a\n"),
                ("loop-a", "auth include loop-b\n"),
                ("loop-b", "auth include loop-a\nauth include login\n"),
            ],
        );
        assert!(!stack_reaches_fprintd(
            &PamSearchPath::machine_only(&dir),
            "login"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn faillock_cohabit_requires_both_modules_in_one_file() {
        let dir = std::env::temp_dir().join(format!("irlume-faillock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Modules in separate files: no cohabitation.
        std::fs::write(dir.join("a"), "auth required pam_faillock.so preauth\n").unwrap();
        std::fs::write(dir.join("b"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(!faillock_cohabits(&PamSearchPath::machine_only(&dir)));
        // Both in one stack: the lockout hazard exists.
        std::fs::write(
            dir.join("system-auth"),
            "auth required pam_faillock.so preauth\nauth sufficient pam_fprintd.so\n",
        )
        .unwrap();
        assert!(faillock_cohabits(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fprintd_in_sudo_follows_one_include_level() {
        let dir = std::env::temp_dir().join(format!("irlume-sudoinc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Not reachable: sudo includes a stack without fingerprint.
        std::fs::write(dir.join("sudo"), "auth include system-auth\n").unwrap();
        std::fs::write(dir.join("system-auth"), "auth required pam_unix.so\n").unwrap();
        assert!(!fprintd_in_sudo(&PamSearchPath::machine_only(&dir)));
        // Fedora shape: sudo → system-auth → pam_fprintd.
        std::fs::write(
            dir.join("system-auth"),
            "auth sufficient pam_fprintd.so\nauth required pam_unix.so\n",
        )
        .unwrap();
        assert!(fprintd_in_sudo(&PamSearchPath::machine_only(&dir)));
        // Debian shape: `@include common-auth`.
        std::fs::write(dir.join("sudo"), "@include common-auth\n").unwrap();
        std::fs::write(dir.join("common-auth"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(fprintd_in_sudo(&PamSearchPath::machine_only(&dir)));
        // Direct line in sudo itself.
        std::fs::write(dir.join("sudo"), "auth sufficient pam_fprintd.so\n").unwrap();
        assert!(fprintd_in_sudo(&PamSearchPath::machine_only(&dir)));
        // Commented lines never count.
        std::fs::write(dir.join("sudo"), "#auth sufficient pam_fprintd.so\n").unwrap();
        std::fs::write(dir.join("common-auth"), "# pam_fprintd.so disabled\n").unwrap();
        assert!(!fprintd_in_sudo(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pam_fprintd_wired_is_false_for_a_missing_dir() {
        // The enable path must fail closed (method unchanged) when the PAM dir
        // cannot be read at all.
        assert!(!pam_fprintd_wired(&PamSearchPath::machine_only(
            std::path::Path::new("/nonexistent-irlume-test-pam.d")
        )));
    }

    #[test]
    fn pam_scans_ignore_files_pam_never_loads() {
        // A backup left in /etc/pam.d is not a PAM stack: pam_start() opens
        // /etc/pam.d/<service>, and no application asks for a service named
        // "system-auth.pre-irlume". Counting one as wiring hands `enable` the
        // green light to stand face down while nothing drives the prompt --
        // the exact password-only outcome the wiring gate exists to prevent.
        // Observed in the field: a Fedora box carried an active pam_fprintd
        // line in `system-auth.pre-linhello-uninstall`, a suffix no list of
        // known backup extensions would have caught.
        let dir = std::env::temp_dir().join(format!("irlume-deadpam-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = "auth required pam_unix.so\n";
        std::fs::write(dir.join("system-auth"), live).unwrap();
        for dead in [
            "system-auth.pre-irlume",
            "system-auth.pre-linhello-uninstall",
            "system-auth.rpmsave",
            "system-auth.pacnew",
            ".system-auth.irlume.tmp",
        ] {
            std::fs::write(
                dir.join(dead),
                "auth sufficient pam_fprintd.so\nauth required pam_faillock.so preauth\n",
            )
            .unwrap();
        }
        assert!(
            !pam_fprintd_wired(&PamSearchPath::machine_only(&dir)),
            "a backup file is not wiring; enable must not record method=fingerprint from one"
        );
        assert!(
            !faillock_cohabits(&PamSearchPath::machine_only(&dir)),
            "a backup file must not raise the doctor lockout warning"
        );
        // The live stack is still read: the skip is about which files count,
        // not about narrowing what a real stack can say.
        std::fs::write(
            dir.join("system-auth"),
            "auth sufficient pam_fprintd.so\nauth required pam_faillock.so preauth\n",
        )
        .unwrap();
        assert!(pam_fprintd_wired(&PamSearchPath::machine_only(&dir)));
        assert!(faillock_cohabits(&PamSearchPath::machine_only(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn enroll_one_refuses_without_fprintd_or_a_reader() {
        // When the tooling or the sensor is missing, enrollment bails early with
        // false and never drives hardware. On a box that has both, this branch
        // isn't reachable without a live sensor, so it is skipped.
        if !fp::fprintd_present() || !fp::reader_present() {
            assert!(!enroll_one("irlume-nonexistent-test-user"));
        }
    }
}
