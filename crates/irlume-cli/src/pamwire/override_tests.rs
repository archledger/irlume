// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! irlume-created overrides end to end: `wire_service`, the machine plan state
//! and apply, and reconcile's maintenance step, on files under a temp root.
//!
//! The case these start from was found on a Fedora 44 ThinkPad. Its
//! `/etc/pam.d/plasmalogin` was an override irlume had created, with a
//! fingerprint line an administrator added by hand. Installing GDM made the
//! reconcile unit re-apply the wiring, which rebuilt the override from the
//! vendor file (by then carrying `pam_oo7` lines) and dropped the hand-added
//! line without a message, so fingerprint at the login screen stopped working.

use super::tests::{fixture, greeter, ship_vendor_only, under_root, TestDir, UPSTREAM_FEDORA};
use super::*;

/// A fingerprint line an administrator adds after the SELinux line. Its
/// `success=2` counts irlume's face line and the password substack, so it
/// lands on irlume's permit landing and the keyring line runs after it.
const LOCAL_JUMP: &str =
    "auth       [success=2 default=ignore]   pam_fprintd.so max-tries=1 timeout=15   # local";

/// An administrator's line with no jump in it.
const LOCAL_LINE: &str = "auth       required     pam_faillock.so preauth   # local";

fn with_line(text: &str, line: &str) -> String {
    let anchor = "pam_selinux_permit.so\n";
    assert!(text.contains(anchor), "{text}");
    text.replacen(anchor, &format!("{anchor}{line}\n"), 1)
}

/// The vendor update the ThinkPad received: `pam_oo7` in both phases.
fn fedora_with_oo7() -> String {
    UPSTREAM_FEDORA
        .replacen(
            "-auth        optional      pam_kwallet.so\n",
            "-auth        optional      pam_kwallet.so\n-auth        optional      pam_oo7.so\n",
            1,
        )
        .replacen(
            "-session     optional      pam_kwallet.so auto_start\n",
            "-session     optional      pam_kwallet.so auto_start\n-session     optional      pam_oo7.so auto_start\n",
            1,
        )
}

/// The override an older irlume wrote: the first header line only.
fn legacy_override(vendor_path: &str, wired: &str) -> String {
    format!("{CREATED_PREFIX}{vendor_path}; delete this file to restore the vendor copy\n{wired}")
}

fn face_and_keyring(content: &str) -> (String, bool) {
    wire_greeter_impl(content, true, true, true)
}

fn keyring_only(content: &str) -> (String, bool) {
    wire_greeter_impl(content, false, true, false)
}

/// A vendor-only plasmalogin under `root`, shipping `vendor`.
fn plasmalogin(root: &Path, vendor: &str) -> Svc {
    ship_vendor_only(root, "plasmalogin", vendor);
    under_root(root, greeter("/etc/pam.d/plasmalogin"))
}

/// The ThinkPad's file before the reconcile that dropped its line: written by
/// an older irlume from the vendor file without `pam_oo7`, plus the hand-added
/// fingerprint line.
fn thinkpad_before(vendor_path: &str) -> String {
    let (wired, ok) = face_and_keyring(&unwire_lines(UPSTREAM_FEDORA).0);
    assert!(ok);
    with_line(&legacy_override(vendor_path, &wired), LOCAL_JUMP)
}

fn read_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

fn backup_of(svc: &Svc) -> String {
    format!("{}{BACKUP}", svc.etc)
}

fn change_id(outcome: &WireOutcome) -> &'static str {
    outcome.change.id()
}

fn detail_text(outcome: &WireOutcome) -> String {
    outcome.detail.clone().unwrap_or_default()
}

/// The `-`/`+` lines of a detail block.
fn diff_lines(detail: &str) -> Vec<String> {
    detail
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("- ") || l.starts_with("+ "))
        .map(str::to_string)
        .collect()
}

fn maintain(svc: &Svc, recipe: overrides::Recipe) -> Option<String> {
    maintain_override(svc, recipe).expect("maintenance must not fail")
}

fn track_line(text: &str) -> String {
    text.lines().nth(1).unwrap_or_default().to_string()
}

// ---- the ThinkPad reproduction ---------------------------------------------------

/// The reported failure, end to end: a vendor update and a re-apply must keep
/// an administrator's line in an override, say so, and show the difference.
#[test]
fn an_admin_line_in_a_legacy_override_survives_a_vendor_update() {
    let dir = TestDir::new("ovr-thinkpad");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    let before = thinkpad_before(vendor_path);
    std::fs::write(svc.etc, &before).unwrap();
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    // The dry run first, then the apply: both keep it and say the same.
    for apply in [false, true] {
        let outcome = wire_service(&svc, true, apply, &face_and_keyring).unwrap();
        assert_eq!(change_id(&outcome), "keep-edited-override", "{outcome}");
        assert!(outcome.message.starts_with('⚠'), "{outcome}");
        assert_eq!(read_file(svc.etc), before, "the file is byte-identical");
        assert!(!exists(&backup_of(&svc)), "and nothing was copied");
        assert_eq!(
            diff_lines(&detail_text(&outcome)),
            vec![
                format!("- {LOCAL_JUMP}"),
                "+ -auth        optional      pam_oo7.so".to_string(),
                "+ -session     optional      pam_oo7.so auto_start".to_string(),
            ],
            "{}",
            detail_text(&outcome)
        );
        assert!(
            detail_text(&outcome).contains("sudo irlume login enable --apply --force"),
            "the way to rebuild it is named"
        );
    }
    assert_eq!(
        read_file(vendor_path),
        fedora_with_oo7(),
        "vendor untouched"
    );
}

/// The ThinkPad as it stands after the line was restored by hand on the new
/// vendor base: the only difference from the vendor copy is that line, and
/// irlume's lines are already where the recipe puts them.
#[test]
fn the_restored_thinkpad_override_is_left_alone() {
    let dir = TestDir::new("ovr-thinkpad-restored");
    let svc = plasmalogin(&dir.0, &fedora_with_oo7());
    let vendor_path = svc.vendor.unwrap();
    let (wired, _) = face_and_keyring(&unwire_lines(&fedora_with_oo7()).0);
    let body = with_line(&wired, LOCAL_JUMP);
    let (rewired, _) = face_and_keyring(&unwire_lines(&body).0);
    assert_eq!(rewired, body, "wire(base(body)) == body for this file");
    let before = legacy_override(vendor_path, &body);
    std::fs::write(svc.etc, &before).unwrap();
    let outcome = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&outcome), "keep-edited-override", "{outcome}");
    assert_eq!(read_file(svc.etc), before);
    assert_eq!(
        diff_lines(&detail_text(&outcome)),
        vec![format!("- {LOCAL_JUMP}")]
    );
}

/// Whatever the capability reading makes a re-apply want, an edited override
/// is never rebuilt from its vendor copy and never loses the admin's line.
#[test]
fn an_edited_override_keeps_its_lines_under_every_greeter_recipe() {
    for line in [LOCAL_JUMP, LOCAL_LINE] {
        for (face, keyring, ondemand) in [
            (true, true, true),
            (true, true, false),
            (true, false, true),
            (true, false, false),
            (false, true, false),
            (false, true, true),
        ] {
            let dir = TestDir::new("ovr-every-recipe");
            let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
            let vendor_path = svc.vendor.unwrap();
            wire_service(&svc, true, true, &face_and_keyring).unwrap();
            let edited = with_line(&read_file(svc.etc), line);
            std::fs::write(svc.etc, &edited).unwrap();
            std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
            let wire = |c: &str| wire_greeter_impl(c, face, keyring, ondemand);
            let outcome = wire_service(&svc, true, true, &wire).unwrap();
            let label = format!("{line} face={face} keyring={keyring} ondemand={ondemand}");
            assert_ne!(
                change_id(&outcome),
                "materialize-override",
                "{label}: {outcome}"
            );
            let after = read_file(svc.etc);
            assert!(after.contains(line), "{label}: the line survives\n{after}");
            assert!(!after.contains("pam_oo7.so"), "{label}: not rebuilt");
            assert_eq!(
                after.lines().take(2).collect::<Vec<_>>(),
                edited.lines().take(2).collect::<Vec<_>>(),
                "{label}: the header is unchanged"
            );
        }
    }
}

/// The jump the ThinkPad's line carries counts irlume's lines. A recipe that
/// moves them (fingerprint only, no face line) would move where it lands, so
/// the file is left exactly as it is.
#[test]
fn a_recipe_change_that_would_move_an_admin_jump_leaves_the_file_alone() {
    let dir = TestDir::new("ovr-jump");
    let svc = plasmalogin(&dir.0, &fedora_with_oo7());
    let vendor_path = svc.vendor.unwrap();
    let (wired, _) = face_and_keyring(&unwire_lines(&fedora_with_oo7()).0);
    let before = legacy_override(vendor_path, &with_line(&wired, LOCAL_JUMP));
    std::fs::write(svc.etc, &before).unwrap();
    let outcome = wire_service(&svc, true, true, &keyring_only).unwrap();
    assert_eq!(change_id(&outcome), "keep-edited-override", "{outcome}");
    assert!(
        outcome.message.contains("pam_fprintd.so") && outcome.message.contains("reseal"),
        "the message quotes the jump and where it would land: {outcome}"
    );
    assert_eq!(read_file(svc.etc), before);
}

// ---- following the vendor copy -----------------------------------------------------

#[test]
fn an_unedited_override_is_rebuilt_when_its_vendor_copy_changes() {
    let dir = TestDir::new("ovr-follow");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    let outcome = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&outcome), "materialize-override", "{outcome}");
    assert!(
        outcome.message.contains("changed since irlume created"),
        "{outcome}"
    );
    let after = read_file(svc.etc);
    assert_eq!(after.matches("pam_oo7.so").count(), 2, "{after}");
    let vendor_sha = crate::logintx::sha256_hex(fedora_with_oo7().as_bytes());
    assert!(
        track_line(&after).starts_with(&format!(
            "# irlume: override v1 vendor-sha256={vendor_sha} "
        )),
        "the digests describe the new generation: {after}"
    );
    assert_eq!(
        read_file(vendor_path),
        fedora_with_oo7(),
        "vendor untouched"
    );
    assert!(!exists(&backup_of(&svc)), "nothing of anybody's to keep");
    let again = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&again), "already-correct", "{again}");
}

/// openSUSE Tumbleweed ships sudo only in /usr/lib/pam.d. A sudo update must
/// reach the override irlume made of it, through reconcile's maintenance step
/// and without a re-apply.
#[test]
fn an_unedited_sudo_override_follows_a_vendor_update() {
    let dir = TestDir::new("ovr-sudo");
    let stock = fixture("opensuse", "sudo");
    ship_vendor_only(&dir.0, "sudo", &stock);
    let svc = under_root(&dir.0, &SUDO);
    wire_service(&svc, true, true, &wire_verify_service).unwrap();
    let updated = format!("{stock}auth     required       pam_faildelay.so delay=2000000\n");
    std::fs::write(svc.vendor.unwrap(), &updated).unwrap();
    let logged = maintain(&svc, overrides::Recipe::Verify);
    let after = read_file(svc.etc);
    assert!(after.contains("pam_faildelay.so"), "{after}");
    assert!(after.contains(VERIFY_STANZA), "{after}");
    assert!(
        logged.is_some_and(|l| l.contains("rebuilt from")),
        "the write is logged"
    );
    assert!(
        maintain(&svc, overrides::Recipe::Verify).is_none(),
        "idempotent"
    );
}

const FEDORA_POLKIT: &str = "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n";

#[test]
fn an_unedited_polkit_override_follows_a_vendor_update() {
    let dir = TestDir::new("ovr-polkit");
    ship_vendor_only(&dir.0, "polkit-1", FEDORA_POLKIT);
    let svc = under_root(&dir.0, &POLKIT);
    wire_service(&svc, true, true, &wire_polkit_service).unwrap();
    let updated = format!("{FEDORA_POLKIT}session    optional     pam_keyinit.so revoke\n");
    std::fs::write(svc.vendor.unwrap(), &updated).unwrap();
    assert!(
        refresh_due_for(&svc, overrides::Recipe::Polkit),
        "a repair is offered"
    );
    maintain(&svc, overrides::Recipe::Polkit);
    let after = read_file(svc.etc);
    assert!(after.contains("pam_keyinit.so revoke"), "{after}");
    assert!(after.contains(POLKIT_VERIFY_STANZA), "{after}");
    assert!(
        !refresh_due_for(&svc, overrides::Recipe::Polkit),
        "and then not"
    );
}

/// An older irlume wired polkit-1 with a plain `sufficient` line. Migrating
/// that line is irlume's own business; the faillock line an administrator
/// added is not, and must survive the migration.
#[test]
fn an_edited_polkit_override_keeps_its_faillock_line_while_its_stanza_migrates() {
    let dir = TestDir::new("ovr-polkit-edited");
    ship_vendor_only(&dir.0, "polkit-1", FEDORA_POLKIT);
    let svc = under_root(&dir.0, &POLKIT);
    let faillock = "auth       required     pam_faillock.so preauth   # local";
    let old = legacy_override(
        svc.vendor.unwrap(),
        &format!(
            "#%PAM-1.0\n{VERIFY_STANZA}\n{faillock}\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n"
        ),
    );
    std::fs::write(svc.etc, &old).unwrap();
    let outcome = wire_service(&svc, true, true, &wire_polkit_service).unwrap();
    assert_eq!(change_id(&outcome), "rewire-override", "{outcome}");
    let after = read_file(svc.etc);
    assert!(after.contains("abort=die"), "{after}");
    assert!(after.contains(faillock), "{after}");
    assert!(
        !after.contains(VERIFY_STANZA),
        "the old stanza is gone: {after}"
    );
    assert_eq!(after.lines().next(), old.lines().next(), "header unchanged");
}

/// Written by an older irlume and still matching its vendor copy: the first
/// reconcile records the vendor file in the header and changes no PAM line.
#[test]
fn a_legacy_override_that_matches_its_vendor_copy_is_recorded_without_changing_a_line() {
    let dir = TestDir::new("ovr-record");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    let (wired, _) = face_and_keyring(&unwire_lines(UPSTREAM_FEDORA).0);
    let old = legacy_override(vendor_path, &wired);
    std::fs::write(svc.etc, &old).unwrap();
    let logged = maintain(&svc, overrides::Recipe::Greeter);
    assert!(
        logged.is_some_and(|l| l.contains("no PAM line changed")),
        "the write is logged"
    );
    let after = read_file(svc.etc);
    let mut lines: Vec<&str> = after.lines().collect();
    let track = lines.remove(1);
    assert!(track.starts_with("# irlume: override v1 "), "{after}");
    assert_eq!(
        format!("{}\n", lines.join("\n")),
        old,
        "no other line moved"
    );
    assert!(
        maintain(&svc, overrides::Recipe::Greeter).is_none(),
        "idempotent"
    );
    assert!(
        !refresh_due_for(&svc, overrides::Recipe::Greeter),
        "not a repair"
    );
}

/// Reconcile's maintenance step never writes a file with lines irlume did not
/// write, whatever its vendor copy did, and does not offer it as a repair.
#[test]
fn maintenance_never_writes_an_edited_or_differing_override() {
    let dir = TestDir::new("ovr-maint-edited");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let tracked = read_file(svc.etc);
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    for text in [
        with_line(&tracked, LOCAL_LINE),
        thinkpad_before(vendor_path),
        legacy_override(
            vendor_path,
            &face_and_keyring(&unwire_lines(UPSTREAM_FEDORA).0).0,
        ),
    ] {
        std::fs::write(svc.etc, &text).unwrap();
        assert!(maintain(&svc, overrides::Recipe::Greeter).is_none());
        assert_eq!(read_file(svc.etc), text);
        assert!(!refresh_due_for(&svc, overrides::Recipe::Greeter));
    }
}

/// A symlinked override is refused by every write, so maintenance skips it
/// rather than failing the unit every half hour, and offers no repair.
#[test]
fn maintenance_skips_a_symlinked_override() {
    let dir = TestDir::new("ovr-maint-symlink");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let real = dir.0.join("real-plasmalogin");
    std::fs::rename(svc.etc, &real).unwrap();
    std::os::unix::fs::symlink(&real, svc.etc).unwrap();
    std::fs::write(svc.vendor.unwrap(), fedora_with_oo7()).unwrap();
    assert!(!refresh_due_for(&svc, overrides::Recipe::Greeter));
    assert!(maintain(&svc, overrides::Recipe::Greeter).is_none());
    assert!(std::fs::symlink_metadata(svc.etc)
        .unwrap()
        .file_type()
        .is_symlink());
}

// ---- --force -----------------------------------------------------------------------

fn force_apply() -> WireOpts {
    WireOpts {
        apply: true,
        force: true,
        expect_vendor: None,
    }
}

#[test]
fn force_rebuilds_an_edited_override_and_keeps_the_old_file() {
    let dir = TestDir::new("ovr-force");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    let before = thinkpad_before(vendor_path);
    std::fs::write(svc.etc, &before).unwrap();
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    let outcome = wire_service_with(&svc, true, &force_apply(), &face_and_keyring).unwrap();
    assert_eq!(change_id(&outcome), "materialize-override", "{outcome}");
    assert!(outcome.message.contains(&backup_of(&svc)), "{outcome}");
    assert_eq!(read_file(&backup_of(&svc)), before, "the old file is kept");
    let after = read_file(svc.etc);
    assert!(!after.contains("pam_fprintd.so"), "{after}");
    assert_eq!(after.matches("pam_oo7.so").count(), 2);
    assert!(track_line(&after).starts_with("# irlume: override v1 "));
    assert_eq!(read_file(vendor_path), fedora_with_oo7());
}

/// Both machines this was found on carry a stale `.pre-irlume` beside an
/// override. `--force` must refuse rather than keep that file and report the
/// new copy, and the preview must say so too.
#[test]
fn force_refuses_when_a_different_backup_is_in_the_way() {
    let dir = TestDir::new("ovr-force-backup");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    let before = thinkpad_before(vendor_path);
    std::fs::write(svc.etc, &before).unwrap();
    std::fs::write(backup_of(&svc), "an older stack\n").unwrap();
    for apply in [false, true] {
        let opts = WireOpts {
            apply,
            ..force_apply()
        };
        let err = wire_service_with(&svc, true, &opts, &face_and_keyring)
            .map_err(String::from)
            .err()
            .expect("a different backup is in the way");
        assert!(err.contains("already holds a different file"), "{err}");
        assert_eq!(read_file(svc.etc), before);
        assert_eq!(read_file(&backup_of(&svc)), "an older stack\n");
    }
    // A backup holding exactly this file is no obstacle.
    std::fs::write(backup_of(&svc), &before).unwrap();
    let outcome = wire_service_with(&svc, true, &force_apply(), &face_and_keyring).unwrap();
    assert_eq!(change_id(&outcome), "materialize-override", "{outcome}");
    assert_eq!(read_file(&backup_of(&svc)), before);
}

// ---- disable -----------------------------------------------------------------------

#[test]
fn disable_removes_an_unedited_override_and_strips_an_edited_one() {
    let dir = TestDir::new("ovr-disable");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let tracked = read_file(svc.etc);
    let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&off), "remove-override", "{off}");
    assert!(!exists(svc.etc));

    let edited = with_line(&tracked, LOCAL_LINE);
    std::fs::write(svc.etc, &edited).unwrap();
    let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&off), "strip-in-place", "{off}");
    let after = read_file(svc.etc);
    assert_eq!(
        after.lines().take(2).collect::<Vec<_>>(),
        tracked.lines().take(2).collect::<Vec<_>>(),
        "both header lines are kept"
    );
    assert!(after.contains(LOCAL_LINE), "{after}");
    assert!(!content_has_module(&after), "{after}");
    assert_eq!(read_file(vendor_path), UPSTREAM_FEDORA);
    // Nothing of irlume's is left, so a second disable has nothing to do.
    let again = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&again), "not-wired", "{again}");
}

/// The ThinkPad file on disable. Its `success=2` counts irlume's face line
/// and lands on irlume's permit landing; without irlume's lines it would land
/// on a wallet line. The lines become inactive in their places, so the jump
/// lands where it did.
#[test]
fn disable_keeps_a_legacy_override_that_differs_from_its_vendor_copy() {
    let dir = TestDir::new("ovr-disable-legacy");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    let before = thinkpad_before(vendor_path);
    std::fs::write(svc.etc, &before).unwrap();
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&off), "strip-in-place", "{off}");
    let after = read_file(svc.etc);
    assert!(after.contains(LOCAL_JUMP), "{after}");
    assert!(!content_has_module(&after), "{after}");
    assert!(after.contains(PERMIT_LANDING), "the landing stays: {after}");
    assert_eq!(
        after.lines().count(),
        before.lines().count(),
        "every line keeps its place"
    );
    assert_eq!(
        lands_after(&after, "pam_fprintd.so", 2),
        lands_after(&before, "pam_fprintd.so", 2),
        "{after}"
    );
    assert!(
        off.message.contains("inactive") && off.message.contains("pam_kwallet5.so"),
        "the run says why: {off}"
    );
    // A second disable finds nothing live of irlume's and writes nothing.
    let again = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&again), "not-wired", "{again}");
    assert_eq!(read_file(svc.etc), after);
}

/// The auth line `n` modules after the first line containing `needle`: where
/// a `success=n` or `default=n` on that line lands.
fn lands_after(text: &str, needle: &str, n: usize) -> String {
    let chain: Vec<&str> = text
        .lines()
        .filter(|l| {
            let d = directive(l);
            let first = d.split_whitespace().next().unwrap_or("");
            first.trim_start_matches('-') == "auth"
        })
        .collect();
    let at = chain
        .iter()
        .position(|l| l.contains(needle))
        .expect("the jump line");
    chain
        .get(at + n + 1)
        .map_or_else(|| "(end)".to_string(), |l| l.to_string())
}

/// An administrator's failure jump above irlume's face line skips the face
/// line and lands on the password stack. After disable, and after disable
/// with the vendor copy gone, it still lands there, and enabling again puts
/// irlume's lines back where they were.
#[test]
fn disable_keeps_a_failure_jump_landing_on_the_password_stack() {
    let fail_jump =
        "auth       [success=done default=1]   pam_fprintd.so max-tries=1 timeout=15   # local";
    for vendor_gone in [false, true] {
        let dir = TestDir::new("ovr-fail-jump");
        let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
        wire_service(&svc, true, true, &face_and_keyring).unwrap();
        let edited = with_line(&read_file(svc.etc), fail_jump);
        std::fs::write(svc.etc, &edited).unwrap();
        assert_eq!(
            lands_after(&edited, "pam_fprintd.so", 1),
            "auth        substack      password-auth"
        );
        if vendor_gone {
            std::fs::remove_file(svc.vendor.unwrap()).unwrap();
        }
        let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
        assert_eq!(change_id(&off), "strip-in-place", "{off}");
        let after = read_file(svc.etc);
        assert!(!content_has_module(&after), "{after}");
        assert!(after.contains(fail_jump), "{after}");
        assert_eq!(
            lands_after(&after, "pam_fprintd.so", 1),
            "auth        substack      password-auth",
            "vendor gone: {vendor_gone}\n{after}"
        );
        // Enabling again puts irlume's lines back where they were.
        let on = wire_service(&svc, true, true, &face_and_keyring).unwrap();
        assert!(!on.unmet, "{on}");
        assert_eq!(read_file(svc.etc), edited, "vendor gone: {vendor_gone}");
    }
}

/// Taking irlume's lines out and putting them back with the same recipe
/// returns the file byte for byte, header and the admin's jump included.
#[test]
fn strip_then_rewire_returns_an_edited_override_byte_for_byte() {
    let dir = TestDir::new("ovr-round-trip");
    let svc = plasmalogin(&dir.0, &fedora_with_oo7());
    let vendor_path = svc.vendor.unwrap();
    let (wired, _) = face_and_keyring(&unwire_lines(&fedora_with_oo7()).0);
    let before = legacy_override(vendor_path, &with_line(&wired, LOCAL_JUMP));
    std::fs::write(svc.etc, &before).unwrap();
    let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&off), "strip-in-place", "{off}");
    let on = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&on), "rewire-override", "{on}");
    assert!(
        !on.message.contains("jump"),
        "irlume's lines go back where they were, so no jump moves: {on}"
    );
    assert_eq!(read_file(svc.etc), before);
}

/// An administrator's rule that names pam_irlume.so only in its arguments.
const EXEC_CHECK: &str =
    "auth       required     pam_exec.so /usr/local/libexec/check-pam_irlume.so";

/// irlume tells its own lines by their module path. A rule that only names
/// pam_irlume.so in an argument is an administrator's line like any other:
/// it counts in the recorded digest, so a vendor update does not rebuild the
/// file without it, and disable and enable leave it where it is.
#[test]
fn an_admin_rule_naming_irlume_in_its_arguments_survives_vendor_updates() {
    let dir = TestDir::new("ovr-exec-arg");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let edited = with_line(&read_file(svc.etc), EXEC_CHECK);
    std::fs::write(svc.etc, &edited).unwrap();

    // The vendor update, then the reconcile unit's run.
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    let logged = maintain(&svc, overrides::Recipe::Greeter);
    let after = read_file(svc.etc);
    assert!(
        after.contains(EXEC_CHECK),
        "reconcile ({logged:?}) left:\n{after}"
    );
    assert_eq!(after, edited, "reconcile wrote nothing");
    assert_eq!(logged, None);
    assert!(
        !refresh_due_for(&svc, overrides::Recipe::Greeter),
        "no rebuild is offered for an edited file"
    );

    // A re-apply keeps the file and shows the rule as the difference.
    let on = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&on), "keep-edited-override", "{on}");
    assert_eq!(read_file(svc.etc), edited);
    let diff = diff_lines(&detail_text(&on));
    assert!(diff.contains(&format!("- {EXEC_CHECK}")), "{diff:?}");

    // Disable removes irlume's lines and keeps the rule.
    let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&off), "strip-in-place", "{off}");
    let stripped = read_file(svc.etc);
    assert!(stripped.contains(EXEC_CHECK), "{stripped}");
    assert!(
        !content_has_module(&stripped),
        "the rule is not irlume's wiring: {stripped}"
    );
    assert!(!stripped.contains("irlume-inert"), "{stripped}");

    // Enable puts irlume's lines back where they were.
    let on = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&on), "rewire-override", "{on}");
    assert_eq!(read_file(svc.etc), edited, "byte for byte");
    assert_eq!(
        read_file(vendor_path),
        fedora_with_oo7(),
        "vendor untouched"
    );
}

/// Lines PAM reads differently from how they look: one led by a no-break
/// space or a vertical tab loads no module at all (libpam skips only spaces
/// and tabs, so its type is unknown), and `[include]` includes a file. Added
/// by an administrator, each is theirs, not irlume's: it counts in the
/// recorded digest, and a vendor update does not rebuild the file without it.
#[test]
fn admin_lines_pam_does_not_load_as_the_module_survive_vendor_updates() {
    for (n, line) in [
        "\u{a0}auth       required     pam_irlume.so",
        "\u{b}auth       required     pam_irlume.so",
        "auth       [include]    pam_irlume.so",
    ]
    .into_iter()
    .enumerate()
    {
        let dir = TestDir::new(&format!("ovr-not-loaded-{n}"));
        let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
        wire_service(&svc, true, true, &face_and_keyring).unwrap();
        let edited = with_line(&read_file(svc.etc), line);
        std::fs::write(svc.etc, &edited).unwrap();
        std::fs::write(svc.vendor.unwrap(), fedora_with_oo7()).unwrap();
        let logged = maintain(&svc, overrides::Recipe::Greeter);
        assert_eq!(logged, None, "{line:?}");
        assert_eq!(
            read_file(svc.etc),
            edited,
            "{line:?}: reconcile wrote nothing"
        );
        assert!(
            !refresh_due_for(&svc, overrides::Recipe::Greeter),
            "{line:?}: no rebuild is offered for an edited file"
        );
    }
}

/// openSUSE Tumbleweed ships sudo only in /usr/lib/pam.d. A faillock line an
/// administrator put above irlume's line stays above it through a disable
/// and an enable, and the file comes back byte for byte.
#[test]
fn a_sudo_override_keeps_irlume_below_faillock_through_disable_and_enable() {
    let dir = TestDir::new("ovr-sudo-faillock");
    let stock = fixture("opensuse", "sudo");
    ship_vendor_only(&dir.0, "sudo", &stock);
    let svc = under_root(&dir.0, &SUDO);
    wire_service(&svc, true, true, &wire_verify_service).unwrap();
    let created = read_file(svc.etc);
    let faillock = "auth       required     pam_faillock.so preauth   # local";
    let edited = created.replacen(
        &format!("{VERIFY_STANZA}\n"),
        &format!("{faillock}\n{VERIFY_STANZA}\n"),
        1,
    );
    assert_ne!(edited, created);
    std::fs::write(svc.etc, &edited).unwrap();
    let pos = |t: &str, n: &str| t.lines().position(|l| l.contains(n)).unwrap();
    let off = wire_service(&svc, false, true, &wire_verify_service).unwrap();
    assert_eq!(change_id(&off), "strip-in-place", "{off}");
    assert!(!content_has_module(&read_file(svc.etc)));
    let on = wire_service(&svc, true, true, &wire_verify_service).unwrap();
    assert_eq!(change_id(&on), "rewire-override", "{on}");
    let after = read_file(svc.etc);
    assert!(
        pos(&after, "pam_faillock") < pos(&after, "pam_irlume"),
        "{after}"
    );
    assert_eq!(after, edited, "byte for byte");
}

fn polkit_override(root: &Path, above: &str) -> (Svc, String) {
    ship_vendor_only(root, "polkit-1", FEDORA_POLKIT);
    let svc = under_root(root, &POLKIT);
    let old = legacy_override(
        svc.vendor.unwrap(),
        &format!(
            "#%PAM-1.0\n{above}{VERIFY_STANZA}\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n"
        ),
    );
    std::fs::write(svc.etc, &old).unwrap();
    (svc, old)
}

/// The polkit stanza migration changes irlume's line only. With a faillock
/// line or a group gate an administrator put above it, the new stanza takes
/// the old one's place instead of going above them, the gate's jump still
/// lands on irlume's line, and the file no longer reads as stale, so
/// reconcile does not re-apply it at every run.
#[test]
fn the_polkit_migration_keeps_irlume_below_an_admin_gate() {
    for above in [
        "auth       required     pam_faillock.so preauth   # local\n",
        "auth       [success=1 default=ignore]   pam_succeed_if.so user ingroup wheel   # local\n\
         auth       requisite    pam_deny.so   # local\n",
    ] {
        let dir = TestDir::new("ovr-polkit-gate");
        let (svc, old) = polkit_override(&dir.0, above);
        assert!(polkit_stanza_stale(Path::new(svc.etc)));
        let outcome = wire_service(&svc, true, true, &wire_polkit_service).unwrap();
        assert_eq!(change_id(&outcome), "rewire-override", "{outcome}");
        let after = read_file(svc.etc);
        assert_eq!(
            after,
            old.replacen(VERIFY_STANZA, POLKIT_VERIFY_STANZA, 1),
            "only irlume's line changed, in its place"
        );
        assert!(!polkit_stanza_stale(Path::new(svc.etc)), "{after}");
        // Kept as it is from now on: irlume's line is right, and the file
        // keeps the administrator's lines.
        let again = wire_service(&svc, true, true, &wire_polkit_service).unwrap();
        assert_eq!(change_id(&again), "keep-edited-override", "{again}");
        assert!(!again.unmet);
        assert_eq!(read_file(svc.etc), after);
    }
}

/// A method switch the ThinkPad's jump refuses leaves irlume's earlier lines
/// in the file, face included. A person's run then fails and says so, rather
/// than report success while face stays on at the login screen; reconcile,
/// which replays what an earlier run saw, does not count it.
#[test]
fn a_refused_update_is_an_unmet_request_for_a_person_only() {
    let dir = TestDir::new("ovr-unmet");
    let svc = plasmalogin(&dir.0, &fedora_with_oo7());
    let vendor_path = svc.vendor.unwrap();
    let (wired, _) = face_and_keyring(&unwire_lines(&fedora_with_oo7()).0);
    let before = legacy_override(vendor_path, &with_line(&wired, LOCAL_JUMP));
    std::fs::write(svc.etc, &before).unwrap();
    let outcome = wire_service(&svc, true, true, &keyring_only).unwrap();
    assert_eq!(change_id(&outcome), "keep-edited-override", "{outcome}");
    assert!(outcome.unmet, "{outcome}");
    assert!(read_file(svc.etc).contains("pam_irlume.so unseal"));
    assert!(kept_unmet(ScopeOrigin::Command, &outcome));
    assert!(!kept_unmet(ScopeOrigin::Marker, &outcome));
    // Keeping a file whose irlume lines are right is no unmet request.
    let same = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&same), "keep-edited-override", "{same}");
    assert!(!same.unmet);
    assert!(!kept_unmet(ScopeOrigin::Command, &same));
}

/// A person at the terminal sees how a kept override differs and how to
/// rebuild it; the reconcile unit's journal gets the one line only.
#[test]
fn only_a_person_gets_the_detail_block() {
    let dir = TestDir::new("ovr-detail");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    std::fs::write(svc.etc, thinkpad_before(svc.vendor.unwrap())).unwrap();
    std::fs::write(svc.vendor.unwrap(), fedora_with_oo7()).unwrap();
    let outcome = wire_service(&svc, true, false, &face_and_keyring).unwrap();
    let person = outcome_lines(&outcome, ScopeOrigin::Command);
    let journal = outcome_lines(&outcome, ScopeOrigin::Marker);
    assert_eq!(journal, vec![format!("  {}", outcome.message)]);
    assert_eq!(person.len(), 2, "{person:?}");
    assert!(person[1].contains("--apply --force"), "{person:?}");
}

#[test]
fn the_root_hint_repeats_the_flags_given() {
    assert_eq!(
        sudo_rerun_hint(true, true, true, true),
        "sudo irlume login enable --with-sudo --with-polkit --apply --force"
    );
    assert_eq!(
        sudo_rerun_hint(true, false, false, false),
        "sudo irlume login enable --apply"
    );
    assert_eq!(
        sudo_rerun_hint(false, false, true, true),
        "sudo irlume login disable --with-polkit --apply",
        "--force is for enable only"
    );
}

// ---- a vendor copy that went away --------------------------------------------------

/// A package that moves its service out of /usr/lib/pam.d leaves irlume's
/// override as the only configuration PAM has for it. Deleting it would put
/// the service on the denying `other` stack, password included.
#[test]
fn a_vendor_removal_never_deletes_an_override() {
    let dir = TestDir::new("ovr-vendor-gone-disable");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let tracked = read_file(svc.etc);
    for text in [tracked.clone(), with_line(&tracked, LOCAL_LINE)] {
        std::fs::write(svc.etc, &text).unwrap();
        let _ = std::fs::remove_file(vendor_path);
        let off = wire_service(&svc, false, true, &face_and_keyring).unwrap();
        assert_eq!(change_id(&off), "strip-in-place", "{off}");
        let after = read_file(svc.etc);
        assert!(!content_has_module(&after), "{after}");
        assert!(after.contains("pam_selinux_permit.so"), "{after}");
        assert!(off.message.contains("only configuration"), "{off}");
    }
}

/// A faillock line an administrator put above irlume's sudo or polkit line
/// stays above it when the vendor file goes away, whether that happens
/// before or after a disable, and with reconcile's maintenance step run in
/// between.
#[test]
fn a_faillock_line_stays_above_irlume_when_the_vendor_file_goes() {
    let faillock = "auth       required     pam_faillock.so preauth   # local";
    let pos = |t: &str, n: &str| t.lines().position(|l| l.contains(n)).unwrap();
    let suse = fixture("opensuse", "sudo");
    let surfaces: [(&str, &str, &Svc, overrides::Recipe, WireFn); 2] = [
        (
            "sudo",
            &suse,
            &SUDO,
            overrides::Recipe::Verify,
            &wire_verify_service,
        ),
        (
            "polkit-1",
            FEDORA_POLKIT,
            &POLKIT,
            overrides::Recipe::Polkit,
            &wire_polkit_service,
        ),
    ];
    for (service, vendor, declared, recipe, wire) in surfaces {
        // 0: disable, vendor gone, enable; 1: vendor gone, disable, enable;
        // 2: disable, vendor gone, reconcile's maintenance, enable.
        for sequence in 0..3 {
            let dir = TestDir::new("ovr-gone-faillock");
            ship_vendor_only(&dir.0, service, vendor);
            let svc = under_root(&dir.0, declared);
            wire_service(&svc, true, true, wire).unwrap();
            let created = read_file(svc.etc);
            let at = pos(&created, "pam_irlume.so");
            let mut lines: Vec<&str> = created.lines().collect();
            lines.insert(at, faillock);
            let edited = format!("{}\n", lines.join("\n"));
            std::fs::write(svc.etc, &edited).unwrap();
            if sequence == 1 {
                std::fs::remove_file(svc.vendor.unwrap()).unwrap();
            }
            let off = wire_service(&svc, false, true, wire).unwrap();
            assert_eq!(change_id(&off), "strip-in-place", "{off}");
            if sequence != 1 {
                std::fs::remove_file(svc.vendor.unwrap()).unwrap();
            }
            if sequence == 2 {
                assert!(maintain(&svc, recipe).is_none());
            }
            let on = wire_service(&svc, true, true, wire).unwrap();
            let after = read_file(svc.etc);
            assert!(
                pos(&after, "pam_faillock") < pos(&after, "pam_irlume"),
                "{service} {sequence}: {on}\n{after}"
            );
            assert_eq!(after, edited, "{service} {sequence}: {on}");
        }
    }
}

type WireFn = &'static dyn Fn(&str) -> (String, bool);

/// A display manager's package removed with its vendor PAM file leaves
/// irlume's override behind, unedited. A later enable that adds face to it
/// (for example after a move from fingerprint to face) wires it rather than
/// failing the run.
#[test]
fn an_unedited_override_left_by_a_removed_package_can_gain_face() {
    let dir = TestDir::new("ovr-gone-gain-face");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    wire_service(&svc, true, true, &keyring_only).unwrap();
    std::fs::remove_file(svc.vendor.unwrap()).unwrap();
    let out = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&out), "rewire-override", "{out}");
    assert!(!kept_unmet(ScopeOrigin::Command, &out), "{out}");
    let after = read_file(svc.etc);
    assert!(after.contains("pam_irlume.so unseal"), "{after}");
    let (fresh, _) = face_and_keyring(&unwire_lines(UPSTREAM_FEDORA).0);
    assert!(after.ends_with(&fresh), "wired as a rebuild would: {after}");
}

/// An administrator's verbatim copy of the vendor's password include above
/// irlume's polkit line: irlume cannot tell which copy is the vendor's, so a
/// disable keeps an inactive line in irlume's place and an enable puts the
/// line back there, never above the copy.
#[test]
fn a_copied_password_include_stays_above_the_polkit_line() {
    for vendor_gone in [false, true] {
        let dir = TestDir::new("ovr-copied-include");
        ship_vendor_only(&dir.0, "polkit-1", FEDORA_POLKIT);
        let svc = under_root(&dir.0, &POLKIT);
        wire_service(&svc, true, true, &wire_polkit_service).unwrap();
        let copy = "auth       include      system-auth";
        let edited = read_file(svc.etc).replacen(
            &format!("{POLKIT_VERIFY_STANZA}\n"),
            &format!("{copy}\n{POLKIT_VERIFY_STANZA}\n"),
            1,
        );
        std::fs::write(svc.etc, &edited).unwrap();
        if vendor_gone {
            std::fs::remove_file(svc.vendor.unwrap()).unwrap();
        }
        let off = wire_service(&svc, false, true, &wire_polkit_service).unwrap();
        assert_eq!(change_id(&off), "strip-in-place", "{off}");
        let disabled = read_file(svc.etc);
        assert!(!content_has_module(&disabled), "{disabled}");
        assert!(disabled.contains("# irlume-inert"), "{off}\n{disabled}");
        let on = wire_service(&svc, true, true, &wire_polkit_service).unwrap();
        assert_eq!(change_id(&on), "rewire-override", "{on}");
        assert_eq!(
            read_file(svc.etc),
            edited,
            "vendor gone: {vendor_gone}: {on}"
        );
    }
}

#[test]
fn an_override_whose_vendor_copy_is_gone_is_wired_in_place() {
    let dir = TestDir::new("ovr-vendor-gone-enable");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let tracked = read_file(svc.etc);
    std::fs::remove_file(svc.vendor.unwrap()).unwrap();
    let same = wire_service(&svc, true, true, &face_and_keyring).unwrap();
    assert_eq!(change_id(&same), "already-correct", "{same}");
    let other = wire_service(&svc, true, true, &keyring_only).unwrap();
    assert_eq!(change_id(&other), "rewire-override", "{other}");
    let after = read_file(svc.etc);
    assert!(!after.contains("unseal"), "{after}");
    assert!(after.contains("pam_irlume.so keyring"), "{after}");
    assert_eq!(track_line(&after), track_line(&tracked), "header kept");
    // A rollback of the transaction that created it must not delete it now.
    assert!(removal_orphans_for(true, false));
    assert!(!removal_orphans_for(true, true));
    assert!(!removal_orphans_for(false, false));
    // A path that is no surface is never guarded.
    assert!(!removal_orphans_service(Path::new(svc.etc)));
}

// ---- the machine plan and apply ------------------------------------------------------

/// A vendor update between `login plan` and `login apply` changes what the
/// apply would write, so it must change the plan state and hence the plan id.
#[test]
fn the_plan_state_covers_the_vendor_copy() {
    let dir = TestDir::new("ovr-plan-state");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let vendor_path = svc.vendor.unwrap();
    let absent = surface_state_for(&svc);
    std::fs::write(vendor_path, fedora_with_oo7()).unwrap();
    assert_ne!(surface_state_for(&svc), absent, "before an override exists");
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let materialized = surface_state_for(&svc);
    std::fs::write(vendor_path, UPSTREAM_FEDORA).unwrap();
    assert_ne!(surface_state_for(&svc), materialized, "and after");
    // A surface without a vendor path keeps its old two-field state.
    let plain = Svc {
        etc: svc.etc,
        vendor: None,
    };
    assert_eq!(surface_state_for(&plain), surface_state(Path::new(svc.etc)));
}

/// The enable plan a panel shows covers the greeters and the lock screen but
/// not polkit or sudo, which only the human command opts into; a vendor change
/// to polkit-1 therefore cannot make an enable plan stale. Each surface the
/// plan does cover carries its vendor copy's digest.
#[test]
fn the_enable_plan_covers_each_greeter_vendor_copy_and_not_polkit() {
    assert!(!polkit_in_scope(true, false));
    assert!(!sudo_in_scope(true, false));
    assert!(polkit_in_scope(false, false) && sudo_in_scope(false, false));
    let dir = TestDir::new("ovr-plan-scope");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    assert_eq!(surface_state_for(&svc).split(' ').count(), 3);
    let planned = plan_surface(&svc, ROLE_LOGIN, &face_and_keyring, true);
    assert_eq!(planned.change, PlannedChange::MaterializeOverride);
    assert_eq!(planned.state, surface_state_for(&svc));
    std::fs::write(svc.vendor.unwrap(), fedora_with_oo7()).unwrap();
    let later = plan_surface(&svc, ROLE_LOGIN, &face_and_keyring, true);
    assert_ne!(later.state, planned.state, "a vendor update makes it stale");
}

#[test]
fn apply_refuses_a_surface_whose_vendor_copy_changed_after_the_plan() {
    let dir = TestDir::new("ovr-apply-drift");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let planned = PlannedSurface {
        id: service_name(svc.etc),
        role: ROLE_LOGIN,
        change: PlannedChange::MaterializeOverride,
        state: surface_state_for(&svc),
    };
    std::fs::write(svc.vendor.unwrap(), fedora_with_oo7()).unwrap();
    let applied = apply_surface(&svc, ROLE_LOGIN, &face_and_keyring, true, &[planned]);
    let error = applied.error.expect("the surface is refused");
    assert!(
        error.contains("changed between the plan and the write"),
        "{error}"
    );
    assert!(!exists(svc.etc), "nothing was written");
}

/// A partial machine apply: one surface written, another refused because its
/// vendor copy changed after the plan. The refused surface is recorded as it
/// stands, its backup included, so `login verify` finds it as applied and
/// `login rollback` puts the written one back.
#[test]
fn a_surface_refused_for_vendor_drift_does_not_block_the_rollback() {
    let dir = TestDir::new("ovr-partial-apply");
    // Written: a vendor-only plasmalogin the enable creates an override of.
    let written = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    // Refused: an sddm override irlume created earlier, with a backup next
    // to it.
    ship_vendor_only(&dir.0, "sddm", UPSTREAM_FEDORA);
    let refused = under_root(&dir.0, greeter("/etc/pam.d/sddm"));
    wire_service(&refused, true, true, &face_and_keyring).unwrap();
    let refused_before = read_file(refused.etc);
    std::fs::write(backup_of(&refused), "an older sddm\n").unwrap();

    let plan = |svc: &Svc| plan_surface(svc, ROLE_LOGIN, &face_and_keyring, true);
    let planned = [plan(&written), plan(&refused)];
    std::fs::write(refused.vendor.unwrap(), fedora_with_oo7()).unwrap();
    let applied = [
        apply_surface(&written, ROLE_LOGIN, &face_and_keyring, true, &planned),
        apply_surface(&refused, ROLE_LOGIN, &face_and_keyring, true, &planned),
    ];
    assert_eq!(applied[0].error, None);
    assert!(content_has_module(&read_file(written.etc)));
    let error = applied[1]
        .error
        .as_deref()
        .expect("the sddm surface is refused");
    assert!(
        error.contains("changed between the plan and the write"),
        "{error}"
    );
    assert_eq!(read_file(refused.etc), refused_before, "and left alone");

    let record = record_of(&applied);
    assert_eq!(
        applied[1].before.as_deref(),
        Some(refused_before.as_str()),
        "the refused surface is recorded as it stands"
    );
    let pairs = [
        (written.etc, written.vendor.unwrap()),
        (refused.etc, refused.vendor.unwrap()),
    ];
    roll_back(&record, &pairs).expect("the rollback runs");
    assert!(!exists(written.etc), "the created override is gone again");
    assert_eq!(read_file(refused.etc), refused_before);
    assert_eq!(read_file(&backup_of(&refused)), "an older sddm\n");
}

/// The transaction record `login apply` writes for these surfaces.
fn record_of(applied: &[AppliedSurface]) -> crate::logintx::Transaction {
    crate::logintx::Transaction {
        id: "0123456789abcdef0123456789abcdef".into(),
        schema_version: crate::logintx::SCHEMA_VERSION,
        status: crate::logintx::TransactionStatus::Applied,
        action: "enable".into(),
        plan_id: "f".repeat(32),
        engine_version: "0.0.0".into(),
        surfaces: crate::machine::surface_records(applied),
    }
}

/// `login verify`, then `login rollback --apply`, for surfaces under a temp
/// root (`pairs` are their `/etc` and vendor paths): the record must read as
/// applied and pass the gate over every surface, then each surface and its
/// backup are restored in order, stopping at the first failure as the
/// rollback does.
fn roll_back(record: &crate::logintx::Transaction, pairs: &[(&str, &str)]) -> Result<(), String> {
    let orphans = |p: &Path| removal_orphans_in(pairs, p);
    let (states, drifted) = crate::machine::verify_surfaces_with(record, &orphans);
    if drifted != 0 {
        return Err(format!("verify: {states:?}"));
    }
    let none = crate::logintx::RollbackProgress::default();
    let blockers = crate::machine::rollback_blockers_with(record, &none, &orphans);
    if blockers.any() {
        return Err(format!(
            "changed {:?}, unreadable {:?}",
            blockers.changed, blockers.unreadable
        ));
    }
    let attrs = |mode: Option<u32>, uid: Option<u32>, gid: Option<u32>| match (mode, uid, gid) {
        (Some(mode), Some(uid), Some(gid)) => Some((mode, uid, gid)),
        _ => None,
    };
    for surface in &record.surfaces {
        restore_surface_with(
            Path::new(&surface.path),
            surface.before.as_deref(),
            attrs(surface.mode, surface.uid, surface.gid),
            &orphans,
        )
        .map_err(|e| format!("{}: {e}", surface.id))?;
        if let Some(sidecar) = &surface.sidecar {
            restore_surface_with(
                Path::new(&sidecar.path),
                sidecar.before.as_deref(),
                attrs(sidecar.mode, sidecar.uid, sidecar.gid),
                &orphans,
            )
            .map_err(|e| format!("{} backup: {e}", surface.id))?;
        }
    }
    Ok(())
}

fn inode(path: &str) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path).unwrap().ino()
}

fn mode(path: &str) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn leak_path(path: &Path) -> &'static str {
    Box::leak(path.to_string_lossy().into_owned().into_boxed_str())
}

/// An administrator's own stack, wired in place rather than overridden.
const ADMIN_STACK: &str =
    "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n";

/// A rollback writes nothing over a surface the apply left alone, or over its
/// backup: the same files stay, and a mode an administrator set after the
/// apply is kept. Rewriting them replaced each file with a new one carrying
/// the recorded mode, although the transaction had not changed either.
#[test]
fn a_rollback_does_not_rewrite_a_surface_the_apply_left_alone() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TestDir::new("ovr-rollback-untouched");
    let written = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    // An administrator's /etc/pam.d/sddm with a backup, whose vendor copy
    // changes after the plan, so the apply leaves both alone.
    ship_vendor_only(&dir.0, "sddm", UPSTREAM_FEDORA);
    let untouched = under_root(&dir.0, greeter("/etc/pam.d/sddm"));
    std::fs::write(untouched.etc, ADMIN_STACK).unwrap();
    std::fs::set_permissions(untouched.etc, std::fs::Permissions::from_mode(0o644)).unwrap();
    let bak = backup_of(&untouched);
    std::fs::write(&bak, "an older sddm\n").unwrap();
    std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o644)).unwrap();

    let plan = |svc: &Svc| plan_surface(svc, ROLE_LOGIN, &face_and_keyring, true);
    let planned = [plan(&written), plan(&untouched)];
    std::fs::write(untouched.vendor.unwrap(), fedora_with_oo7()).unwrap();
    let applied = [
        apply_surface(&written, ROLE_LOGIN, &face_and_keyring, true, &planned),
        apply_surface(&untouched, ROLE_LOGIN, &face_and_keyring, true, &planned),
    ];
    assert_eq!(applied[0].error, None);
    assert!(applied[1].error.is_some(), "the sddm surface is left alone");
    let record = record_of(&applied);

    // After the apply, the administrator tightens both files.
    for path in [untouched.etc, bak.as_str()] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let files = (inode(untouched.etc), inode(&bak));
    let pairs = [
        (written.etc, written.vendor.unwrap()),
        (untouched.etc, untouched.vendor.unwrap()),
    ];
    roll_back(&record, &pairs).expect("the rollback runs");
    assert!(!exists(written.etc), "the created override is gone again");
    assert_eq!(read_file(untouched.etc), ADMIN_STACK);
    assert_eq!(read_file(&bak), "an older sddm\n");
    assert_eq!(
        (inode(untouched.etc), inode(&bak)),
        files,
        "the same files, not replacements"
    );
    assert_eq!(
        (mode(untouched.etc), mode(&bak)),
        (0o600, 0o600),
        "the later chmod is kept"
    );
}

/// A surface refused because it is a symlink, or one of several names for a
/// file, does not stop the rollback: it is left as it is, and the surfaces
/// before and after it in the walk are restored. The restore used to write
/// it, the write refused the link, and the rollback stopped there on every
/// retry, with `login verify` saying it was available.
#[test]
fn a_rollback_passes_over_a_symlinked_surface_the_apply_refused() {
    rollback_passes_over_a_linked_surface("symlink");
}

#[test]
fn a_rollback_passes_over_a_hard_linked_surface_the_apply_refused() {
    rollback_passes_over_a_linked_surface("hardlink");
}

fn rollback_passes_over_a_linked_surface(kind: &str) {
    let dir = TestDir::new(&format!("ovr-rollback-{kind}"));
    let written = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let target = dir.0.join("alternatives-stack");
    std::fs::write(&target, ADMIN_STACK).unwrap();
    let linked_path = |name: &str| {
        let path = dir.0.join("etc/pam.d").join(name);
        if kind == "symlink" {
            std::os::unix::fs::symlink(&target, &path).unwrap();
        } else {
            std::fs::hard_link(&target, &path).unwrap();
        }
        Svc {
            etc: leak_path(&path),
            vendor: None,
        }
    };
    // One before the written surface and one after it.
    let first = linked_path("gdm-password");
    let last = linked_path("kde");
    let target_inode = inode(leak_path(&target));

    let plan = |svc: &Svc| plan_surface(svc, ROLE_LOGIN, &face_and_keyring, true);
    let planned = [plan(&first), plan(&written), plan(&last)];
    let applied = [
        apply_surface(&first, ROLE_LOGIN, &face_and_keyring, true, &planned),
        apply_surface(&written, ROLE_LOGIN, &face_and_keyring, true, &planned),
        apply_surface(&last, ROLE_LOGIN, &face_and_keyring, true, &planned),
    ];
    assert!(applied[0].error.is_some(), "{kind}: refused");
    assert_eq!(applied[1].error, None, "{kind}");
    assert!(applied[2].error.is_some(), "{kind}: refused");
    let record = record_of(&applied);
    let pairs = [(written.etc, written.vendor.unwrap())];
    roll_back(&record, &pairs).unwrap_or_else(|e| panic!("{kind}: {e}"));
    assert!(!exists(written.etc), "{kind}: the created override is gone");
    for svc in [&first, &last] {
        let meta = std::fs::symlink_metadata(svc.etc).unwrap();
        assert_eq!(meta.is_symlink(), kind == "symlink", "{kind}: {}", svc.etc);
        assert_eq!(read_file(svc.etc), ADMIN_STACK, "{kind}: {}", svc.etc);
    }
    assert_eq!(read_file(leak_path(&target)), ADMIN_STACK, "{kind}");
    assert_eq!(inode(leak_path(&target)), target_inode, "{kind}");
    if kind == "hardlink" {
        assert_eq!(inode(first.etc), target_inode, "still one file");
        assert_eq!(inode(last.etc), target_inode, "still one file");
    }
}

/// Another writer's file that a checked write refused to replace is recorded
/// as it stands, so a rollback of the transaction keeps it. Here the /etc
/// file appears between irlume's scratch write and its rename. Recorded as
/// the absent file the apply had read, the rollback deleted it.
#[test]
fn a_rollback_keeps_the_file_a_refused_write_left_in_place() {
    let dir = TestDir::new("ovr-refused-create");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let planned = [plan_surface(&svc, ROLE_LOGIN, &face_and_keyring, true)];
    arm(&SWAP_DURING_WRITE, Path::new(svc.etc));
    let applied = apply_surface(&svc, ROLE_LOGIN, &face_and_keyring, true, &planned);
    disarm(&SWAP_DURING_WRITE, Path::new(svc.etc));
    let error = applied.error.clone().expect("the write is refused");
    assert!(error.contains("left alone"), "{error}");
    assert_eq!(read_file(svc.etc), "SOMEONE ELSE'S FILE\n");
    roll_back(&record_of(&[applied]), &[(svc.etc, svc.vendor.unwrap())])
        .expect("the rollback runs");
    assert_eq!(read_file(svc.etc), "SOMEONE ELSE'S FILE\n", "and kept");
}

/// The same for a removal: a package renames its file over irlume's
/// override after the removal checked it, so the removal puts that file
/// back, and a rollback does not write the override over it.
#[test]
fn a_rollback_keeps_the_file_a_refused_removal_put_back() {
    let dir = TestDir::new("ovr-refused-remove");
    ship_vendor_only(&dir.0, "sddm", UPSTREAM_FEDORA);
    let svc = under_root(&dir.0, greeter("/etc/pam.d/sddm"));
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let planned = [plan_surface(&svc, ROLE_LOGIN, &face_and_keyring, false)];
    assert_eq!(planned[0].change.id(), "remove-override");
    arm(&SWAP_DURING_WRITE, Path::new(svc.etc));
    let applied = apply_surface(&svc, ROLE_LOGIN, &face_and_keyring, false, &planned);
    disarm(&SWAP_DURING_WRITE, Path::new(svc.etc));
    let error = applied.error.clone().expect("the removal is refused");
    assert!(error.contains("not touched"), "{error}");
    assert_eq!(read_file(svc.etc), "SOMEONE ELSE'S FILE\n");
    roll_back(&record_of(&[applied]), &[(svc.etc, svc.vendor.unwrap())])
        .expect("the rollback runs");
    assert_eq!(read_file(svc.etc), "SOMEONE ELSE'S FILE\n", "and kept");
}

/// The same for a stack wired in place: the backup is made, then the stack
/// is replaced before the rename. The replacement stays through a rollback,
/// and the backup this run made goes.
#[test]
fn a_rollback_keeps_the_stack_a_refused_in_place_write_left() {
    let dir = TestDir::new("ovr-refused-in-place");
    std::fs::create_dir_all(dir.0.join("etc/pam.d")).unwrap();
    let svc = Svc {
        etc: leak_path(&dir.0.join("etc/pam.d/sudo")),
        vendor: None,
    };
    std::fs::write(svc.etc, ADMIN_STACK).unwrap();
    let planned = [plan_surface(&svc, ROLE_SUDO, &wire_verify_service, true)];
    arm(&SWAP_DURING_WRITE, Path::new(svc.etc));
    let applied = apply_surface(&svc, ROLE_SUDO, &wire_verify_service, true, &planned);
    disarm(&SWAP_DURING_WRITE, Path::new(svc.etc));
    assert!(applied.error.is_some(), "the write is refused");
    assert_eq!(read_file(svc.etc), "SOMEONE ELSE'S FILE\n");
    assert!(exists(&backup_of(&svc)), "the backup was made first");
    roll_back(&record_of(&[applied]), &[]).expect("the rollback runs");
    assert_eq!(read_file(svc.etc), "SOMEONE ELSE'S FILE\n", "and kept");
    assert!(
        !exists(&backup_of(&svc)),
        "the backup this run made is gone"
    );
}

/// A write that failed only after it landed, when the directory sync that
/// makes it durable failed, did change the file, so it is recorded as a
/// change and a rollback puts back what was there. Only a write that did not
/// land is recorded as the file stands.
#[test]
fn a_write_that_failed_after_landing_is_rolled_back() {
    let dir = TestDir::new("ovr-landed-create");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let planned = [plan_surface(&svc, ROLE_LOGIN, &face_and_keyring, true)];
    arm(&FAIL_SYNC_AFTER_CHANGE, Path::new(svc.etc));
    let applied = apply_surface(&svc, ROLE_LOGIN, &face_and_keyring, true, &planned);
    disarm(&FAIL_SYNC_AFTER_CHANGE, Path::new(svc.etc));
    let error = applied.error.clone().expect("the sync failed");
    assert!(error.contains("failed for the test"), "{error}");
    assert!(
        content_has_module(&read_file(svc.etc)),
        "the override landed"
    );
    assert_eq!(applied.before, None, "where there was none");
    roll_back(&record_of(&[applied]), &[(svc.etc, svc.vendor.unwrap())])
        .expect("the rollback runs");
    assert!(!exists(svc.etc), "the override is gone again");

    let dir = TestDir::new("ovr-landed-remove");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    wire_service(&svc, true, true, &face_and_keyring).unwrap();
    let created = read_file(svc.etc);
    let planned = [plan_surface(&svc, ROLE_LOGIN, &face_and_keyring, false)];
    arm(&FAIL_SYNC_AFTER_CHANGE, Path::new(svc.etc));
    let applied = apply_surface(&svc, ROLE_LOGIN, &face_and_keyring, false, &planned);
    disarm(&FAIL_SYNC_AFTER_CHANGE, Path::new(svc.etc));
    assert!(applied.error.is_some(), "the sync failed");
    assert!(!exists(svc.etc), "the removal landed");
    roll_back(&record_of(&[applied]), &[(svc.etc, svc.vendor.unwrap())])
        .expect("the rollback runs");
    assert_eq!(read_file(svc.etc), created, "the override is back");
}

/// Wiring a stack in place makes its `.pre-irlume` backup, and a rollback of
/// that transaction removes it again: the record names the backup the run
/// created, not only one that was there before.
#[test]
fn a_rollback_removes_the_backup_the_apply_made() {
    let dir = TestDir::new("ovr-rollback-made-backup");
    std::fs::create_dir_all(dir.0.join("etc/pam.d")).unwrap();
    let svc = Svc {
        etc: leak_path(&dir.0.join("etc/pam.d/sudo")),
        vendor: None,
    };
    std::fs::write(svc.etc, ADMIN_STACK).unwrap();
    let planned = [plan_surface(&svc, ROLE_SUDO, &wire_verify_service, true)];
    let applied = apply_surface(&svc, ROLE_SUDO, &wire_verify_service, true, &planned);
    assert_eq!(applied.error, None);
    assert!(content_has_module(&read_file(svc.etc)));
    assert_eq!(read_file(&backup_of(&svc)), ADMIN_STACK);
    let record = record_of(&[applied]);
    let sidecar = record.surfaces[0]
        .sidecar
        .as_ref()
        .expect("the backup is recorded");
    assert_eq!(sidecar.before, None, "it was not there before");
    roll_back(&record, &[]).expect("the rollback runs");
    assert_eq!(read_file(svc.etc), ADMIN_STACK);
    assert!(!exists(&backup_of(&svc)), "no backup is left behind");
}

/// The vendor digest the per-surface check compared is handed to the write,
/// which compares it with the bytes it reads, so a vendor file replaced in
/// between is refused rather than used.
#[test]
fn the_write_refuses_a_vendor_copy_other_than_the_one_checked() {
    let dir = TestDir::new("ovr-apply-late-drift");
    let svc = plasmalogin(&dir.0, UPSTREAM_FEDORA);
    let opts = WireOpts {
        apply: true,
        force: false,
        expect_vendor: Some(crate::logintx::sha256_hex(UPSTREAM_FEDORA.as_bytes())),
    };
    std::fs::write(svc.vendor.unwrap(), fedora_with_oo7()).unwrap();
    let err = wire_service_with(&svc, true, &opts, &face_and_keyring)
        .map_err(String::from)
        .err()
        .expect("refused");
    assert!(err.contains("or its vendor copy changed"), "{err}");
    assert!(!exists(svc.etc));
}

// ---- file helpers ------------------------------------------------------------------

#[test]
fn a_checked_write_refuses_a_file_edited_in_place_meanwhile() {
    let dir = TestDir::new("ovr-checked-write");
    let path = dir.0.join("stack");
    std::fs::write(&path, "edited in place\n").unwrap();
    let err = write_atomic_checked(&path, "irlume's\n", Some("decided on this\n"))
        .map_err(String::from)
        .expect_err("the bytes changed");
    assert!(err.contains("left alone"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "edited in place\n");
    write_atomic_checked(&path, "irlume's\n", Some("edited in place\n")).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "irlume's\n");
}

#[test]
fn a_checked_removal_keeps_a_file_edited_meanwhile() {
    let dir = TestDir::new("ovr-checked-remove");
    let path = dir.0.join("plasmalogin");
    std::fs::write(&path, "saved by an editor\n").unwrap();
    let err = remove_checked(&path, Some("decided on this\n"))
        .map_err(String::from)
        .expect_err("the bytes changed");
    assert!(err.contains("not touched"), "{err}");
    assert!(path.exists());
    remove_checked(&path, Some("saved by an editor\n")).unwrap();
    assert!(!path.exists());
    assert!(leftovers(&dir.0).is_empty(), "{:?}", leftovers(&dir.0));
}

/// Names irlume made in `dir` for its own use and should not have left.
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".irlume-") || n.contains("irlume-swap-source"))
        .collect()
}

/// A package manager or an editor that replaces the file (a rename over its
/// name) after irlume checked it keeps its file: the removal acts on the
/// file irlume checked, never on whatever holds the name when it unlinks.
/// Reachable only from inside the removal, hence the test hook.
#[test]
fn a_checked_removal_keeps_a_file_that_replaced_it_after_the_check() {
    let dir = TestDir::new("ovr-remove-swapped");
    let path = dir.0.join("plasmalogin");
    std::fs::write(&path, "decided on this\n").unwrap();
    arm(&SWAP_DURING_WRITE, &path);
    let err = remove_checked(&path, Some("decided on this\n"));
    disarm(&SWAP_DURING_WRITE, &path);
    let err = err
        .map_err(String::from)
        .expect_err("the file was replaced after the check");
    assert!(err.contains("not touched"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "SOMEONE ELSE'S FILE\n",
        "the replacement survives"
    );
    assert!(leftovers(&dir.0).is_empty(), "{:?}", leftovers(&dir.0));
}

/// The same for an editor that saves in place after the check: the bytes
/// are compared again once the file is out of the way, and it goes back.
#[test]
fn a_checked_removal_keeps_a_file_edited_in_place_after_the_check() {
    let dir = TestDir::new("ovr-remove-edited");
    let path = dir.0.join("plasmalogin");
    std::fs::write(&path, "decided on this\n").unwrap();
    arm(&EDIT_DURING_REMOVE, &path);
    let err = remove_checked(&path, Some("decided on this\n"));
    disarm(&EDIT_DURING_REMOVE, &path);
    let err = err
        .map_err(String::from)
        .expect_err("the file was edited after the check");
    assert!(err.contains("not touched"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "EDITED IN PLACE\n");
    assert!(leftovers(&dir.0).is_empty(), "{:?}", leftovers(&dir.0));
}

/// A file that replaced the checked one is put back without replacing a
/// newer file that took the name meanwhile; when it cannot be, it stays at
/// its private name and the error says where.
#[test]
fn a_file_that_cannot_be_put_back_is_named_and_nothing_is_replaced() {
    let dir = TestDir::new("ovr-remove-occupied");
    let path = dir.0.join("plasmalogin");
    std::fs::write(&path, "decided on this\n").unwrap();
    arm(&SWAP_DURING_WRITE, &path);
    arm(&OCCUPY_AFTER_ASIDE, &path);
    let err = remove_checked(&path, Some("decided on this\n"));
    disarm(&SWAP_DURING_WRITE, &path);
    disarm(&OCCUPY_AFTER_ASIDE, &path);
    let err = err
        .map_err(String::from)
        .expect_err("the file was replaced after the check");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "A NEWER FILE\n");
    let left = leftovers(&dir.0);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].contains(".irlume-removing."), "{left:?}");
    assert!(
        err.contains("could not be put back") && err.contains(&left[0]),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.0.join(&left[0])).unwrap(),
        "SOMEONE ELSE'S FILE\n",
        "the replacement is kept under its private name"
    );
    assert!(
        !is_abandoned_scratch(&left[0]),
        "the scratch sweep never deletes it"
    );
}

/// A symlink, a file with a second name, other bytes, and a file where none
/// was expected are refused as before, each leaving everything in place.
#[test]
fn a_checked_removal_refuses_links_and_other_files() {
    let dir = TestDir::new("ovr-remove-refusals");
    let target = dir.0.join("real");
    std::fs::write(&target, "decided on this\n").unwrap();

    let link = dir.0.join("sddm");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = remove_checked(&link, Some("decided on this\n"))
        .map_err(String::from)
        .expect_err("a symlink");
    assert!(err.contains("symlink"), "{err}");
    assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());

    let second = dir.0.join("lightdm");
    std::fs::hard_link(&target, &second).unwrap();
    let err = remove_checked(&second, Some("decided on this\n"))
        .map_err(String::from)
        .expect_err("two names");
    assert!(err.contains("hard links"), "{err}");
    assert!(second.exists() && target.exists());
    std::fs::remove_file(&second).unwrap();

    let err = remove_checked(&target, Some("other bytes\n"))
        .map_err(String::from)
        .expect_err("other bytes");
    assert!(err.contains("not touched"), "{err}");
    let err = remove_checked(&target, None)
        .map_err(String::from)
        .expect_err("expected absent");
    assert!(err.contains("not touched"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "decided on this\n"
    );

    let absent = dir.0.join("gdm-password");
    let err = remove_checked(&absent, Some("decided on this\n"))
        .map_err(String::from)
        .expect_err("gone");
    assert!(err.contains("not touched"), "{err}");
    assert!(leftovers(&dir.0).is_empty(), "{:?}", leftovers(&dir.0));
}

/// A removal decided on an absent file finds nothing to remove.
#[test]
fn a_checked_removal_of_a_file_expected_absent_does_nothing() {
    let dir = TestDir::new("ovr-remove-absent");
    remove_checked(&dir.0.join("gdm-password"), None).expect("nothing to remove");
    assert!(leftovers(&dir.0).is_empty(), "{:?}", leftovers(&dir.0));
}

/// Reconcile leaves an override it may not write (made immutable, or on a
/// read-only mount) and says so, instead of failing at every timer run.
#[test]
fn an_immutable_or_read_only_override_is_left_without_failing_reconcile() {
    for code in [1, 30] {
        let e = format!(
            "rename into /etc/pam.d/sddm: {}",
            std::io::Error::from_raw_os_error(code)
        );
        assert!(write_refused_by_admin(&e), "{e}");
    }
    for code in [2, 13, 28] {
        let e = format!(
            "rename into /etc/pam.d/sddm: {}",
            std::io::Error::from_raw_os_error(code)
        );
        assert!(!write_refused_by_admin(&e), "{e}");
    }
}

/// The TUI runs as the person, who cannot look inside the root-only state
/// directory. A marker that cannot be seen is judged by the wiring; one that
/// is plainly absent means reconcile maintains nothing.
#[test]
fn the_refresh_offer_needs_the_marker_or_the_wiring() {
    use std::io::ErrorKind::{NotFound, PermissionDenied};
    let never = || -> bool { panic!("not asked") };
    assert!(marked_for_maintenance(Ok(()), || true, never));
    assert!(!marked_for_maintenance(Ok(()), || false, never));
    assert!(!marked_for_maintenance(Err(NotFound), never, never));
    assert!(marked_for_maintenance(Err(PermissionDenied), never, || {
        true
    }));
    assert!(!marked_for_maintenance(
        Err(PermissionDenied),
        never,
        || false
    ));
}

/// Recording the tracking line changes no PAM line, so a re-apply skips it
/// on a file it may not write, as reconcile's maintenance step does, rather
/// than failing where an older release reported the file as correct. Any
/// other write that fails is still an error.
#[test]
fn a_header_only_write_that_cannot_be_made_is_skipped() {
    let error = |code: i32| {
        WriteError::from(format!(
            "create /etc/pam.d/.polkit-1.irlume-new.2.3.tmp: {}",
            std::io::Error::from_raw_os_error(code)
        ))
    };
    for code in [1, 30] {
        let out = header_write_refused("/etc/pam.d/polkit-1", true, error(code)).expect("skipped");
        assert_eq!(change_id(&out), "already-correct", "{out}");
        assert!(out.message.starts_with('⚠'), "{out}");
        assert!(
            header_write_refused("/etc/pam.d/polkit-1", false, error(code)).is_err(),
            "a write that changes a PAM line"
        );
    }
    assert!(header_write_refused("/etc/pam.d/polkit-1", true, error(13)).is_err());
}

#[test]
fn keeping_a_copy_accepts_only_an_identical_existing_one() {
    let dir = TestDir::new("ovr-keep-copy");
    let path = dir.0.join("plasmalogin");
    let copy = dir.0.join(format!("plasmalogin{BACKUP}"));
    std::fs::write(&path, "the file\n").unwrap();
    keep_copy(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "the file\n");
    keep_copy(&path).expect("the same bytes are already kept");
    std::fs::write(&copy, "something else\n").unwrap();
    assert!(keep_copy(&path).is_err());
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "something else\n");
}
