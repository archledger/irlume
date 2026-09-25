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
    let err = remove_checked(&path, Some("decided on this\n")).expect_err("the bytes changed");
    assert!(err.contains("not touched"), "{err}");
    assert!(path.exists());
    remove_checked(&path, Some("saved by an editor\n")).unwrap();
    assert!(!path.exists());
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
        format!(
            "create /etc/pam.d/.polkit-1.irlume-new.2.3.tmp: {}",
            std::io::Error::from_raw_os_error(code)
        )
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
