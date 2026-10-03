// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! `irlume split`: thin split-pair management over the daemon's opt-in
//! requests (ADR-0032 §4, §6). Machine-oriented argument shapes; the TUI
//! comes with the later interaction work. A new client meeting an older
//! daemon reports unsupported split management and never falls back to
//! `set-cameras` or any less specific operation (ADR-0029 §6 as amended).

use super::flag;
use irlume_common::split_wire::{SplitMutationGuard, SplitSideFacts};
use irlume_common::Request;

/// Parse the guard copied from one root listing, without refreshing it after
/// confirmation. JSON preserves every field boundary.
fn parse_guard(text: &str) -> Result<SplitMutationGuard, &'static str> {
    let guard: SplitMutationGuard =
        serde_json::from_str(text).map_err(|_| "--guard needs a JSON guard object")?;
    guard.validate()?;
    Ok(guard)
}

/// JSON preserves serials containing commas, quotes, equals signs and Unicode.
fn parse_side(text: &str) -> Result<SplitSideFacts, &'static str> {
    serde_json::from_str(text).map_err(|_| "--rgb and --ir need JSON side-facts objects")
}

/// What the daemon's answer means in words and exit code. Pure, so the
/// no-fallback rule is testable: an older daemon's answer is reported as
/// unsupported split management, never as a reason to try another request.
pub(crate) fn explain_split_reply(
    reply: Result<&irlume_common::Response, String>,
) -> (String, bool) {
    match reply {
        Ok(irlume_common::Response::Ok(msg)) => (msg.clone(), true),
        Ok(irlume_common::Response::SplitInventory(view)) => {
            (serde_json::to_string(view).unwrap_or_default(), true)
        }
        Ok(irlume_common::Response::SplitStatusView {
            state,
            record_count,
            generation,
            selection_resolves,
        }) => (
            format!(
                "split store: {state:?}, {record_count} record(s), generation {generation:?}, selection resolves: {selection_resolves}",
            ),
            true,
        ),
        Ok(irlume_common::Response::Error(e)) => (
            format!(
                "split management refused: {e}\n(a daemon that predates split management \
                 reports it as unsupported; no fallback to any other operation is attempted)"
            ),
            false,
        ),
        Ok(other) => (format!("unexpected reply from the daemon: {other:?}"), false),
        Err(e) => (format!("could not reach irlumed: {e}"), false),
    }
}

pub(crate) const HELP: &str = "usage:
  irlume split list
  irlume split status                                             (root)
  irlume split add --guard JSON --rgb JSON --ir JSON                (root)
  irlume split remove PAIRKEY                                      (root)
  irlume split select PAIRKEY|--clear --guard JSON                  (root)

Flags accept --name VALUE or --name=VALUE. Copy exact facts from sudo irlume split list.
Guard JSON: {\"supervisor_id\":\"...\",\"revision\":1,\"rgb\":{\"instance_id\":\"...\",\"generation\":1,\"endpoint\":\"/dev/video0\"},\"ir\":{\"instance_id\":\"...\",\"generation\":1,\"endpoint\":\"/dev/video1\"}}
Side JSON: {\"identity\":\"vid:pid:serial\",\"path\":\"/dev/video0\",\"controller\":\"0000:00:14.0\",\"domain\":\"usb2\",\"ports\":[8]}
Quote JSON and PAIRKEY in the shell. Commas in serials need no extra escaping inside JSON.
These commands manage authorization only; split enrollment/authentication remain disabled.
The machine --json/--contract interface is not supported by split commands.";

pub(crate) fn help() -> std::process::ExitCode {
    println!("{HELP}");
    std::process::ExitCode::SUCCESS
}

/// Build the request for one `split` invocation. Pure.
///
/// # Errors
/// A static reason when the arguments do not describe one operation.
pub(crate) fn split_request(args: &[String]) -> Result<Request, &'static str> {
    let Some(sub) = args.get(1).map(String::as_str) else {
        return Err("a split subcommand is required");
    };
    let (flags, mut index): (&[&str], usize) = match sub {
        "status" | "list" => (&[], 2),
        "add" => (&["--guard", "--rgb", "--ir"], 2),
        "remove" => (&[], 3),
        "select" => (&["--guard"], 3),
        _ => return Err("unknown split subcommand"),
    };
    let mut seen = std::collections::BTreeSet::new();
    while index < args.len() {
        let token = &args[index];
        let (name, inline) = token
            .split_once('=')
            .map_or((token.as_str(), None), |(k, v)| (k, Some(v)));
        if !flags.contains(&name) || !seen.insert(name) {
            return Err("unknown or repeated split flag");
        }
        let value = if let Some(value) = inline {
            value
        } else {
            index += 1;
            args.get(index)
                .map(String::as_str)
                .ok_or("split flag needs a value")?
        };
        if value.is_empty() || value.starts_with("--") {
            return Err("split flag needs a value");
        }
        index += 1;
    }
    match sub {
        "status" => Ok(Request::SplitStatus),
        "list" => Ok(Request::ListSplitAuthorizations),
        "add" => {
            let guard = parse_guard(flag(args, "--guard").ok_or("add needs --guard")?)?;
            let rgb = parse_side(flag(args, "--rgb").ok_or("add needs --rgb")?)?;
            let ir = parse_side(flag(args, "--ir").ok_or("add needs --ir")?)?;
            Ok(Request::AddSplitAuthorization {
                guard: Box::new(guard),
                rgb: Box::new(rgb),
                ir: Box::new(ir),
            })
        }
        "remove" => {
            let key = args
                .get(2)
                .map(String::as_str)
                .ok_or("remove needs a pair key")?;
            if key.starts_with("--") {
                return Err("remove needs a pair key");
            }
            Ok(Request::RemoveSplitAuthorization {
                pair: key.to_owned(),
            })
        }
        "select" => {
            let guard = parse_guard(flag(args, "--guard").ok_or("select needs --guard")?)?;
            let key = args
                .get(2)
                .map(String::as_str)
                .ok_or("select needs a pair key or --clear")?;
            // `--clear` selects nothing; the empty pair text clears.
            let pair = if key == "--clear" {
                String::new()
            } else if key.starts_with('-') {
                return Err("select needs a pair key or --clear");
            } else {
                key.to_owned()
            };
            Ok(Request::SelectSplitPair {
                guard: Box::new(guard),
                pair,
            })
        }
        _ => Err("unknown split subcommand"),
    }
}

/// `irlume split <status|list|add|remove|select> ...`
pub(crate) fn run(args: &[String]) -> std::process::ExitCode {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return help();
    }
    let request = match split_request(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{reason}");
            eprintln!("{HELP}");
            return std::process::ExitCode::from(2);
        }
    };
    let (words, ok) = match super::daemon_request(&request) {
        Ok(response) => explain_split_reply(Ok(&response)),
        Err(e) => explain_split_reply(Err(e.to_string())),
    };
    if ok {
        println!("{words}");
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("{words}");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(list: &[&str]) -> Vec<String> {
        // The dispatch hands over argv without the program name.
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_requests_build_from_thin_arguments() {
        let args = argv(&["split", "status"]);
        assert!(matches!(split_request(&args), Ok(Request::SplitStatus)));
        let args = argv(&["split", "list"]);
        assert!(matches!(
            split_request(&args),
            Ok(Request::ListSplitAuthorizations)
        ));
        let args = argv(&[
            "split",
            "add",
            "--guard",
            r#"{"supervisor_id":"0123456789abcdef0123456789abcdef","revision":7,"rgb":{"instance_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":1,"endpoint":"/dev/video0"},"ir":{"instance_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generation":2,"endpoint":"/dev/video1"}}"#,
            "--rgb",
            r#"{"identity":"5986:2113:s1","path":"/dev/video0","controller":"0000:00:14.0","domain":"usb2","ports":[8]}"#,
            "--ir",
            r#"{"identity":"5986:1141:s2","path":"/dev/video1","controller":"0000:00:14.0","domain":"usb2","ports":[5]}"#,
        ]);
        let Ok(Request::AddSplitAuthorization { guard, rgb, ir }) = split_request(&args) else {
            panic!("add must build");
        };
        assert_eq!(guard.revision, 7);
        assert_eq!(guard.rgb.generation, 1);
        assert_eq!(rgb.ports, vec![8]);
        assert_eq!(ir.domain, "usb2");
        let args = argv(&["split", "remove", "split1;a|c|usb2|1;b|c|usb2|2"]);
        let Ok(Request::RemoveSplitAuthorization { pair }) = split_request(&args) else {
            panic!("remove must build");
        };
        assert!(pair.starts_with("split1;"));
    }

    #[test]
    fn an_older_daemon_reads_as_unsupported_and_never_falls_back() {
        let (words, ok) = explain_split_reply(Ok(&irlume_common::Response::Error(
            "unknown request variant".into(),
        )));
        assert!(!ok);
        assert!(words.contains("unsupported"), "{words}");
        // The no-fallback rule of ADR-0029 §6: no other operation is named.
        for forbidden in ["set-cameras", "SetCameras", "retr"] {
            assert!(!words.contains(forbidden), "{words}");
        }
    }

    #[test]
    fn successful_replies_carry_the_answer() {
        let (words, ok) = explain_split_reply(Ok(&irlume_common::Response::Ok(
            "split authorization published as generation 2".into(),
        )));
        assert!(ok);
        assert!(words.contains("generation 2"));
    }

    #[test]
    fn review_side_json_preserves_comma_and_quote_in_serial() {
        let expected = SplitSideFacts {
            identity: "5986:2113:serial,\"quoted\"".into(),
            path: "/dev/video0".into(),
            controller: "0000:00:14.0".into(),
            domain: "usb2".into(),
            ports: vec![8],
        };
        let text = serde_json::to_string(&expected).unwrap();
        assert_eq!(parse_side(&text).unwrap(), expected);
    }

    #[test]
    fn review_flag_equals_form_preserves_json_value() {
        let args = argv(&["split", "add", "--rgb={\"identity\":\"a,b=c\"}"]);
        assert_eq!(flag(&args, "--rgb"), Some("{\"identity\":\"a,b=c\"}"));
    }

    #[test]
    fn review_split_rejects_unnegotiated_or_duplicate_flags_before_dispatch() {
        for args in [
            argv(&["split", "status", "--json"]),
            argv(&["split", "remove", "key", "--contract=1"]),
            argv(&["split", "add", "--guard", "{}", "--guard={}"]),
            argv(&["split", "add", "--rgb"]),
        ] {
            assert!(split_request(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn review_select_rejects_option_like_keys_before_dispatch() {
        let guard = r#"{"supervisor_id":"0123456789abcdef0123456789abcdef","revision":7,"rgb":{"instance_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":1,"endpoint":"/dev/video0"},"ir":{"instance_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generation":2,"endpoint":"/dev/video1"}}"#;
        for key in ["--json", "--contract=1", "--unknown"] {
            assert!(split_request(&argv(&["split", "select", key, "--guard", guard])).is_err());
        }
        assert!(matches!(
            split_request(&argv(&["split", "select", "--clear", "--guard", guard])),
            Ok(Request::SelectSplitPair { pair, .. }) if pair.is_empty()
        ));
    }
}
