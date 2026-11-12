// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Where to report a problem (#1329): the lines that end the output of
//! `irlume support-report`, of the TUI's support report and of human
//! `irlume doctor` output that has a warning or failure. A security
//! problem, or one the reader is not sure about, goes to private reporting;
//! anything else goes to the issue chooser.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The block. It names the cases the issue forms in `.github/ISSUE_TEMPLATE/`
/// name, and each address ends its line. At most 71 columns per line, so a
/// 9-column prefix keeps it within 80.
const WHERE_TO_REPORT: &str = "\
Security problem (a photo, video, mask or another person got in,
face sign-in worked without your face, or face data was exposed),
or not sure? Never post it publicly. Report it privately:
https://github.com/archledger/irlume/security/advisories/new
or the e-mail address in SECURITY.md.
Anything else: https://github.com/archledger/irlume/issues/new/choose";

/// After a report the reader may attach as it is.
const ATTACH_THIS_REPORT: &str = "Your own words are fine; attach this report file.";
/// After a root report made without `--probe`.
const ATTACH_OWN_USER_REPORT: &str =
    "Your own words are fine; attach a report made as your own user.";
/// After a root probe report that lists other accounts' events.
const ATTACH_PROBE_OR_OWN_USER_REPORT: &str =
    "Your own words are fine; attach this report file, or one made as your own user.";
/// After a user report from an irlumed that does not keep other accounts'
/// events out of it.
const ATTACH_REPORT_AFTER_RESTART: &str =
    "Your own words are fine; attach the new report, not this one.";
/// After doctor output, which is not the report.
const ATTACH_A_REPORT: &str =
    "Your own words are fine; attach the file `irlume support-report` writes.";
/// Doctor output names the account it checks, as in `templates (<user>)`,
/// and its `camera group` lines can show the serial number of a camera
/// added to the pair, as the hardware issue form says.
const DOCTOR_SHOWS_ACCOUNT: &str = "\
Doctor output shows your account name and an added camera's serial
number; you may replace both before posting.";
/// About irlume's PAM module only, not pam_faillock: a face attempt that
/// does not grant leaves the sign-in to the password (root AGENTS.md,
/// "Password fallback").
const PASSWORD_LINE: &str =
    "irlume never blocks your password; a failed face sign-in falls back to it.";

/// Which other accounts' events a report lists or can list. The
/// authentications and status events follow its privacy checklist
/// (`authentication_checklist_line` in `support_report.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OtherAccounts {
    /// No other account's events: no daemon section, or an ordinary user's
    /// report from a current irlumed.
    Nothing,
    /// Every account's recent authentications.
    Authentications,
    /// Every account's recent status events, which an older irlumed also
    /// uses for keyring arms and token releases.
    StatusEvents,
    /// A report whose events are not withheld, root's or an ordinary user's
    /// from an older irlumed, that holds no authentication or status event:
    /// it can still hold other accounts' enrollment, identification or
    /// camera-diagnostics events.
    OtherEvents,
}

/// Who made a report and which other accounts' events it lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReportRun {
    /// An ordinary user. A current irlumed keeps other accounts' events out
    /// of such a report, so `other_accounts` is `Nothing`, as it is without
    /// a daemon section; from an older one it is never `Nothing`.
    User { other_accounts: OtherAccounts },
    /// Root, which reads every account's events; `probe` with `--probe`.
    /// `other_accounts` is `Nothing` only without a daemon section.
    Root {
        other_accounts: OtherAccounts,
        probe: bool,
    },
}

/// The lines that say which other accounts' events the report lists.
fn other_accounts_lines(other_accounts: OtherAccounts) -> &'static str {
    match other_accounts {
        OtherAccounts::Nothing => "",
        OtherAccounts::Authentications => {
            "It lists every account's recent authentications: when each happened\n\
             and its outcome.\n"
        }
        OtherAccounts::StatusEvents => {
            "It lists every account's recent status events: when each happened\n\
             and its outcome.\n"
        }
        OtherAccounts::OtherEvents => {
            "It can list other accounts' recent events: when each happened and\n\
             its outcome.\n"
        }
    }
}

/// The note for a report made as root: who can read the file, which other
/// accounts' events it lists, and how to make one with only your account.
fn root_note(other_accounts: OtherAccounts, probe: bool) -> String {
    let last = if probe {
        "A probe needs root. To include only your account, run it as your own\n\
         user without --probe, not as root or with sudo.\n"
    } else {
        "Run it as your own user, not as root or with sudo, to include only\n\
         your account.\n"
    };
    format!(
        "This report was made as root, so only root can read the file.\n{}{last}",
        other_accounts_lines(other_accounts)
    )
}

/// The note for a user report from an irlumed that does not keep other
/// accounts' events out of it: one older than this irlume, still running
/// after an upgrade or not yet upgraded.
fn older_irlumed_note(other_accounts: OtherAccounts) -> String {
    format!(
        "This report was made with a running irlumed that is older than this\n\
         irlume and does not keep other accounts' events out of a report.\n\
         {}Restart irlumed (`sudo systemctl restart irlumed`), or finish the upgrade,\n\
         and make the report again.\n",
        other_accounts_lines(other_accounts)
    )
}

/// What `irlume support-report` and the TUI's support report print after
/// "Inspect it before sharing": a blank line, the run's note and a blank
/// line where it has one, the block, the attach line for this run and the
/// password line. Each line ends in a newline, for `print!`.
pub(crate) fn after_support_report(run: ReportRun) -> String {
    let (note, attach) = match run {
        ReportRun::User {
            other_accounts: OtherAccounts::Nothing,
        } => (None, ATTACH_THIS_REPORT),
        ReportRun::User { other_accounts } => (
            Some(older_irlumed_note(other_accounts)),
            ATTACH_REPORT_AFTER_RESTART,
        ),
        ReportRun::Root {
            other_accounts,
            probe,
        } => (
            Some(root_note(other_accounts, probe)),
            match (probe, other_accounts) {
                (true, OtherAccounts::Nothing) => ATTACH_THIS_REPORT,
                (true, _) => ATTACH_PROBE_OR_OWN_USER_REPORT,
                (false, _) => ATTACH_OWN_USER_REPORT,
            },
        ),
    };
    let mut text = String::from("\n");
    if let Some(note) = note {
        text.push_str(&note);
        text.push('\n');
    }
    text.push_str(WHERE_TO_REPORT);
    text.push('\n');
    text.push_str(attach);
    text.push('\n');
    text.push_str(PASSWORD_LINE);
    text.push('\n');
    text
}

/// What human `irlume doctor` prints after its summary line when a check
/// warned or failed: a blank line, the block, where the report to attach
/// comes from, that doctor output shows the account name, and the
/// password line. No newline at the end, for `dout!`.
pub(crate) fn after_doctor() -> String {
    format!("\n{WHERE_TO_REPORT}\n{ATTACH_A_REPORT}\n{DOCTOR_SHOWS_ACCOUNT}\n{PASSWORD_LINE}")
}

/// The homes `display_path` shortens to `~` for this process, from `$HOME`
/// and the effective uid (`homes_from`).
pub(crate) fn display_homes() -> Vec<PathBuf> {
    homes_from(std::env::var_os("HOME").as_deref(), crate::is_root())
}

/// The homes `display_path` shortens to `~`: none for root, whose report
/// path is shown in full; else `home` when it is absolute and not `/`,
/// then its canonical form when that differs and is not `/` (a symlinked
/// home), so both a typed path and a canonical one match.
fn homes_from(home: Option<&OsStr>, root: bool) -> Vec<PathBuf> {
    if root {
        return Vec::new();
    }
    let Some(home) = home.map(PathBuf::from) else {
        return Vec::new();
    };
    let usable = |path: &Path| path.is_absolute() && path != Path::new("/");
    if !usable(&home) {
        return Vec::new();
    }
    let canonical = std::fs::canonicalize(&home).ok();
    let mut homes = vec![home];
    if let Some(canonical) = canonical {
        if usable(&canonical) && !homes.contains(&canonical) {
            homes.push(canonical);
        }
    }
    homes
}

/// `path` with the first of `homes` it lies inside shown as `~`, compared
/// component by component (`/home/alicex` is not inside `/home/alice`); any
/// other path, and a home itself, as given.
pub(crate) fn display_path(path: &Path, homes: &[PathBuf]) -> String {
    for home in homes {
        if let Ok(rest) = path.strip_prefix(home) {
            if !rest.as_os_str().is_empty() {
                return format!("~/{}", rest.display());
            }
        }
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURITY_URL: &str = "https://github.com/archledger/irlume/security/advisories/new";
    const ISSUES_URL: &str = "https://github.com/archledger/irlume/issues/new/choose";

    /// Every value a report run can take.
    const RUNS: [ReportRun; 12] = [
        ReportRun::User {
            other_accounts: OtherAccounts::Nothing,
        },
        ReportRun::User {
            other_accounts: OtherAccounts::Authentications,
        },
        ReportRun::User {
            other_accounts: OtherAccounts::StatusEvents,
        },
        ReportRun::User {
            other_accounts: OtherAccounts::OtherEvents,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::Nothing,
            probe: false,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::Authentications,
            probe: false,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::StatusEvents,
            probe: false,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::OtherEvents,
            probe: false,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::Nothing,
            probe: true,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::Authentications,
            probe: true,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::StatusEvents,
            probe: true,
        },
        ReportRun::Root {
            other_accounts: OtherAccounts::OtherEvents,
            probe: true,
        },
    ];

    /// The shell copies hold the same lines: each package script once, in
    /// a heredoc after a blank line and followed by its attach line, and
    /// the installer once, behind `warn`. This compares text only; that
    /// the scripts print it is checked by `scripts/test-install-script.sh`
    /// and the package-hook tests.
    #[test]
    fn shell_copies_print_the_same_report_lines() {
        let heredoc = format!("\n{WHERE_TO_REPORT}\n{ATTACH_A_REPORT}\n");
        for (name, script) in [
            (
                "packaging/arch/irlume.install",
                include_str!("../../../packaging/arch/irlume.install"),
            ),
            (
                "packaging/arch-git/irlume.install",
                include_str!("../../../packaging/arch-git/irlume.install"),
            ),
            (
                "packaging/debian/postinstall.sh",
                include_str!("../../../packaging/debian/postinstall.sh"),
            ),
            (
                "packaging/ppa/debian/postinst",
                include_str!("../../../packaging/ppa/debian/postinst"),
            ),
        ] {
            assert_eq!(script.matches(&heredoc).count(), 1, "{name}");
        }
        let installer: String = WHERE_TO_REPORT
            .lines()
            .map(|line| format!("  warn \"{line}\"\n"))
            .collect();
        assert_eq!(
            include_str!("../../../scripts/install.sh")
                .matches(&installer)
                .count(),
            1,
            "scripts/install.sh"
        );
    }

    /// The security line comes first and says not to post publicly before
    /// it names the private route; the issue chooser comes last. Each
    /// address ends its line, so a terminal's link detection takes all of
    /// it.
    #[test]
    fn the_private_route_comes_before_the_public_one() {
        let block = WHERE_TO_REPORT;
        assert!(block.starts_with("Security problem ("), "{block}");
        assert!(block.contains(&format!("{SECURITY_URL}\n")), "{block}");
        assert!(block.contains("SECURITY.md"), "{block}");
        let never = block.find("Never post it publicly.").expect("never post");
        let security = block.find(SECURITY_URL).expect("security URL");
        let issues = block.find(ISSUES_URL).expect("issue chooser URL");
        assert!(never < security && security < issues, "{block}");
        assert!(block.ends_with(ISSUES_URL), "{block}");
        assert_eq!(block.matches("https://").count(), 2, "{block}");
        for case in [
            "a photo, video, mask or another person got in",
            "face sign-in worked without your face",
            "face data was exposed",
            "or not sure?",
        ] {
            assert!(block.contains(case), "{case}: {block}");
        }
        for run in RUNS {
            let text = after_support_report(run);
            assert_eq!(text.matches(block).count(), 1, "{run:?}: {text}");
        }
    }

    /// Plain ASCII without an em dash; block lines fit behind a 9-column
    /// prefix within 80 columns, every other line within 80.
    #[test]
    fn printed_lines_are_plain_ascii_within_their_width() {
        for line in WHERE_TO_REPORT.lines() {
            assert!(line.len() <= 71, "{} columns: {line}", line.len());
        }
        for run in RUNS {
            let text = after_support_report(run);
            assert!(text.is_ascii(), "{run:?}: {text}");
            assert!(!text.contains('\u{2014}'), "{run:?}: {text}");
            assert!(text.ends_with('\n'), "{run:?}: {text}");
            for line in text.lines() {
                assert!(line.len() <= 80, "{run:?}: {} columns: {line}", line.len());
                assert_eq!(line, line.trim_end(), "{run:?}: trailing space: {line:?}");
            }
        }
        let doctor = after_doctor();
        assert!(doctor.is_ascii(), "{doctor}");
        assert!(!doctor.contains('\u{2014}'), "{doctor}");
        assert!(
            !doctor.ends_with('\n'),
            "dout! adds the newline: {doctor:?}"
        );
        for line in doctor.lines() {
            assert!(line.len() <= 80, "{} columns: {line}", line.len());
            assert_eq!(line, line.trim_end(), "trailing space: {line:?}");
        }
    }

    /// Doctor's closing lines: a blank line, the block, the report to
    /// attach, that doctor output shows the account name and an added
    /// camera's serial number (two lines), and the password line.
    #[test]
    fn doctor_output_ends_with_the_block_and_points_to_the_report() {
        assert_eq!(
            after_doctor(),
            format!(
                "\n{WHERE_TO_REPORT}\n\
                 Your own words are fine; attach the file `irlume support-report` writes.\n\
                 Doctor output shows your account name and an added camera's serial\n\
                 number; you may replace both before posting.\n\
                 irlume never blocks your password; a failed face sign-in falls back to it."
            )
        );
        assert!(
            !after_doctor().contains("account name; you may replace it"),
            "{}",
            after_doctor()
        );
        assert_eq!(after_doctor().matches(SECURITY_URL).count(), 1);
        assert_eq!(after_doctor().matches(ISSUES_URL).count(), 1);
    }

    /// A root report says that only root can read the file, names the other
    /// accounts' events only when its checklist does, and says how to make
    /// one with only your account; a user report from a current irlumed
    /// has no note. A probe report asks for that file, and also offers one
    /// made as your own user when it lists other accounts' events.
    #[test]
    fn a_root_note_says_only_what_the_file_holds() {
        let user = after_support_report(ReportRun::User {
            other_accounts: OtherAccounts::Nothing,
        });
        assert!(!user.contains("made as root"), "{user}");
        assert!(!user.contains("every account"), "{user}");
        assert!(!user.contains("older than this"), "{user}");

        let root = after_support_report(ReportRun::Root {
            other_accounts: OtherAccounts::Nothing,
            probe: false,
        });
        assert!(root.contains("only root can read the file"), "{root}");
        assert!(
            root.contains(
                "Run it as your own user, not as root or with sudo, to include only\n\
                 your account.\n"
            ),
            "{root}"
        );
        assert!(!root.contains("every account"), "{root}");
        assert!(!root.contains("--probe"), "{root}");

        let root = after_support_report(ReportRun::Root {
            other_accounts: OtherAccounts::Authentications,
            probe: false,
        });
        assert!(
            root.contains("every account's recent authentications"),
            "{root}"
        );
        assert!(!root.contains("status events"), "{root}");

        let root = after_support_report(ReportRun::Root {
            other_accounts: OtherAccounts::StatusEvents,
            probe: false,
        });
        assert!(
            root.contains("every account's recent status events"),
            "{root}"
        );
        assert!(!root.contains("authentications"), "{root}");

        let probe = after_support_report(ReportRun::Root {
            other_accounts: OtherAccounts::Nothing,
            probe: true,
        });
        assert!(probe.contains("only root can read the file"), "{probe}");
        assert!(
            probe.contains("run it as your own\nuser without --probe, not as root or with sudo."),
            "{probe}"
        );
        assert!(!probe.contains("every account"), "{probe}");
        assert!(
            probe.contains("\nYour own words are fine; attach this report file.\n"),
            "{probe}"
        );
        for other_accounts in [OtherAccounts::Authentications, OtherAccounts::StatusEvents] {
            let probe = after_support_report(ReportRun::Root {
                other_accounts,
                probe: true,
            });
            assert!(
                probe.contains(
                    "\nYour own words are fine; attach this report file, or one made as \
                     your own user.\n"
                ),
                "{probe}"
            );
        }
    }

    /// A user report from an irlumed that does not keep other accounts'
    /// events out of it (an older one still running after an upgrade) says
    /// so, names what it lists or can list, says how to restart irlumed and
    /// asks for the new report, not for this file.
    #[test]
    fn a_user_report_from_an_older_irlumed_asks_for_a_new_one() {
        for (other_accounts, lists) in [
            (
                OtherAccounts::Authentications,
                "\nIt lists every account's recent authentications: when each happened\n\
                 and its outcome.\n",
            ),
            (
                OtherAccounts::StatusEvents,
                "\nIt lists every account's recent status events: when each happened\n\
                 and its outcome.\n",
            ),
            (
                OtherAccounts::OtherEvents,
                "\nIt can list other accounts' recent events: when each happened and\n\
                 its outcome.\n",
            ),
        ] {
            let text = after_support_report(ReportRun::User { other_accounts });
            assert!(
                text.contains(
                    "irlumed that is older than this\n\
                     irlume and does not keep other accounts' events out of a report.\n"
                ),
                "{text}"
            );
            assert!(text.contains(lists), "{text}");
            assert_eq!(text.matches("\nIt ").count(), 1, "{text}");
            assert!(
                text.contains(
                    "\nRestart irlumed (`sudo systemctl restart irlumed`), or finish the \
                     upgrade,\nand make the report again.\n"
                ),
                "{text}"
            );
            assert!(
                text.contains("\nYour own words are fine; attach the new report, not this one.\n"),
                "{text}"
            );
            assert!(!text.contains("attach this report file"), "{text}");
            assert!(!text.contains("made after that"), "{text}");
            assert!(!text.contains("made as root"), "{text}");
        }
        // The note for other events claims no authentication or status
        // event and no event of every account.
        let other = after_support_report(ReportRun::User {
            other_accounts: OtherAccounts::OtherEvents,
        });
        for absent in ["every account", "authentications", "status events"] {
            assert!(!other.contains(absent), "{absent}: {other}");
        }
        let text = after_support_report(ReportRun::User {
            other_accounts: OtherAccounts::Nothing,
        });
        assert!(
            text.contains("\nYour own words are fine; attach this report file.\n"),
            "{text}"
        );
        assert!(!text.contains("not this one"), "{text}");
        assert!(!text.contains("older than this"), "{text}");
    }

    /// The full tail for a user report, an older irlumed's user reports
    /// with authentications and with other events only, a root report and
    /// a root probe report.
    #[test]
    fn the_report_tail_is_the_block_then_the_attach_and_password_lines() {
        const BLOCK: &str = "\
Security problem (a photo, video, mask or another person got in,
face sign-in worked without your face, or face data was exposed),
or not sure? Never post it publicly. Report it privately:
https://github.com/archledger/irlume/security/advisories/new
or the e-mail address in SECURITY.md.
Anything else: https://github.com/archledger/irlume/issues/new/choose
";
        const PASSWORD: &str =
            "irlume never blocks your password; a failed face sign-in falls back to it.\n";
        assert_eq!(
            after_support_report(ReportRun::User {
                other_accounts: OtherAccounts::Nothing,
            }),
            format!("\n{BLOCK}Your own words are fine; attach this report file.\n{PASSWORD}")
        );
        assert_eq!(
            after_support_report(ReportRun::User {
                other_accounts: OtherAccounts::Authentications,
            }),
            format!(
                "\n\
                 This report was made with a running irlumed that is older than this\n\
                 irlume and does not keep other accounts' events out of a report.\n\
                 It lists every account's recent authentications: when each happened\n\
                 and its outcome.\n\
                 Restart irlumed (`sudo systemctl restart irlumed`), or finish the upgrade,\n\
                 and make the report again.\n\
                 \n\
                 {BLOCK}Your own words are fine; attach the new report, not this one.\n\
                 {PASSWORD}"
            )
        );
        assert_eq!(
            after_support_report(ReportRun::User {
                other_accounts: OtherAccounts::OtherEvents,
            }),
            format!(
                "\n\
                 This report was made with a running irlumed that is older than this\n\
                 irlume and does not keep other accounts' events out of a report.\n\
                 It can list other accounts' recent events: when each happened and\n\
                 its outcome.\n\
                 Restart irlumed (`sudo systemctl restart irlumed`), or finish the upgrade,\n\
                 and make the report again.\n\
                 \n\
                 {BLOCK}Your own words are fine; attach the new report, not this one.\n\
                 {PASSWORD}"
            )
        );
        assert_eq!(
            after_support_report(ReportRun::Root {
                other_accounts: OtherAccounts::Nothing,
                probe: false,
            }),
            format!(
                "\n\
                 This report was made as root, so only root can read the file.\n\
                 Run it as your own user, not as root or with sudo, to include only\n\
                 your account.\n\
                 \n\
                 {BLOCK}Your own words are fine; attach a report made as your own user.\n\
                 {PASSWORD}"
            )
        );
        assert_eq!(
            after_support_report(ReportRun::Root {
                other_accounts: OtherAccounts::Authentications,
                probe: true,
            }),
            format!(
                "\n\
                 This report was made as root, so only root can read the file.\n\
                 It lists every account's recent authentications: when each happened\n\
                 and its outcome.\n\
                 A probe needs root. To include only your account, run it as your own\n\
                 user without --probe, not as root or with sudo.\n\
                 \n\
                 {BLOCK}Your own words are fine; attach this report file, or one made \
                 as your own user.\n{PASSWORD}"
            )
        );
    }

    /// Only a path below the running home is shortened, matched component
    /// by component against the raw home first, then its canonical form.
    #[test]
    fn only_paths_inside_the_running_home_are_abbreviated() {
        let homes = [PathBuf::from("/home/alice"), PathBuf::from("/real/alice")];
        let shown = |path: &str| display_path(Path::new(path), &homes);
        assert_eq!(shown("/home/alice/x"), "~/x");
        assert_eq!(shown("/home/alice/work/r.txt"), "~/work/r.txt");
        assert_eq!(shown("/real/alice/x"), "~/x");
        assert_eq!(shown("/home/alice"), "/home/alice");
        assert_eq!(shown("/home/alicex/y"), "/home/alicex/y");
        assert_eq!(
            display_path(Path::new("/home/alice/x"), &[PathBuf::from("/home/al")]),
            "/home/alice/x"
        );
        assert_eq!(shown("irlume-support-1.txt"), "irlume-support-1.txt");
        assert_eq!(shown("/tmp/x"), "/tmp/x");
        assert_eq!(
            display_path(Path::new("/home/alice/x"), &[]),
            "/home/alice/x"
        );
    }

    /// The homes come from `$HOME` and the effective uid: none for root,
    /// for a relative home, for `/` or without a home; else the home as
    /// given, then its canonical form when that differs and is not `/`.
    #[test]
    fn display_homes_follow_home_and_its_canonical_form() {
        let dir = std::env::temp_dir().join(format!(
            "irlume-where-to-report-{:08x}",
            rand::random::<u32>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let to_root = dir.join("to-root");
        std::os::unix::fs::symlink("/", &to_root).unwrap();
        let canonical_real = std::fs::canonicalize(&real).unwrap();
        let user = |home: &Path| homes_from(Some(home.as_os_str()), false);
        let through_link = user(&link);
        let direct = user(&canonical_real);
        let resolves_to_root = user(&to_root);
        let as_root = homes_from(Some(link.as_os_str()), true);
        std::fs::remove_file(&to_root).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(through_link, [link.clone(), canonical_real.clone()]);
        assert_eq!(direct, [canonical_real.clone()]);
        // A home that resolves to `/` matches only as given.
        assert_eq!(resolves_to_root, [to_root.clone()]);
        assert!(as_root.is_empty(), "root sees full paths: {as_root:?}");
        assert_eq!(
            display_path(&canonical_real.join("r.txt"), &through_link),
            "~/r.txt"
        );
        assert_eq!(display_path(&link.join("r.txt"), &through_link), "~/r.txt");
        for home in ["relative/home", "/"] {
            let homes = user(Path::new(home));
            assert!(homes.is_empty(), "{home}: {homes:?}");
        }
        assert!(homes_from(None, false).is_empty());
    }
}
