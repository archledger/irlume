// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! `irlume split`: thin split-pair management over the daemon's opt-in
//! requests (ADR-0032 §4, §6). Machine-oriented argument shapes; the TUI
//! comes with the later interaction work. A new client meeting an older
//! daemon reports unsupported split management and never falls back to
//! `set-cameras` or any less specific operation (ADR-0029 §6 as amended).

use irlume_common::split_wire::{SplitMutationGuard, SplitSideFacts, SplitSideGuard};
use irlume_common::Request;

/// The guard every mutation except removal carries: displayed supervisor,
/// revision and both sides in role order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuardArgs {
    pub(crate) supervisor_id: String,
    pub(crate) revision: u64,
    pub(crate) rgb: SplitSideGuard,
    pub(crate) ir: SplitSideGuard,
}

/// Parse `SUPERV,REV,RGBINST,RGBGEN,RGBEND,IRINST,IRGEN,IREND`.
fn parse_guard(text: &str) -> Result<GuardArgs, &'static str> {
    let fields: Vec<&str> = text.split(',').collect();
    if fields.len() != 8 {
        return Err("the guard needs 8 comma-separated fields");
    }
    let revision: u64 = fields[1]
        .parse()
        .map_err(|_| "the revision is not a number")?;
    let rgb_generation: u64 = fields[3]
        .parse()
        .map_err(|_| "the RGB generation is not a number")?;
    let ir_generation: u64 = fields[6]
        .parse()
        .map_err(|_| "the IR generation is not a number")?;
    Ok(GuardArgs {
        supervisor_id: fields[0].to_owned(),
        revision,
        rgb: SplitSideGuard {
            instance_id: fields[2].to_owned(),
            generation: rgb_generation,
            endpoint: fields[4].to_owned(),
        },
        ir: SplitSideGuard {
            instance_id: fields[5].to_owned(),
            generation: ir_generation,
            endpoint: fields[7].to_owned(),
        },
    })
}

impl GuardArgs {
    fn into_guard(self) -> SplitMutationGuard {
        SplitMutationGuard {
            supervisor_id: self.supervisor_id,
            revision: self.revision,
            rgb: self.rgb,
            ir: self.ir,
        }
    }
}

/// Parse `IDENTITY,PATH,CONTROLLER,DOMAIN,PORTS` with dotted ports.
fn parse_side(text: &str) -> Result<SplitSideFacts, &'static str> {
    let fields: Vec<&str> = text.split(',').collect();
    if fields.len() != 5 {
        return Err("a side needs 5 comma-separated fields");
    }
    let ports = fields[4]
        .split('.')
        .map(|p| p.parse::<u8>().map_err(|_| "a port is not a number"))
        .collect::<Result<Vec<u8>, _>>()?;
    if ports.is_empty() {
        return Err("a side needs at least one port");
    }
    Ok(SplitSideFacts {
        identity: fields[0].to_owned(),
        path: fields[1].to_owned(),
        controller: fields[2].to_owned(),
        domain: fields[3].to_owned(),
        ports,
    })
}

/// Flag value lookup: `--name VALUE`.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
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
                "split store: {state:?}, {record_count} record(s), generation                  {generation:?}, selection resolves: {selection_resolves}",
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

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         irlume split status                                      (root)\n  \
         irlume split list\n  \
         irlume split add --guard SUPER,REV,RGBINST,RGBGEN,RGBEND,IRINST,IRGEN,IREND \\\n    \
         --rgb IDENTITY,PATH,CONTROLLER,DOMAIN,PORTS --ir IDENTITY,PATH,CONTROLLER,DOMAIN,PORTS   (root)\n  \
         irlume split remove PAIRKEY                             (root)\n  \
         irlume split select PAIRKEY|--clear --guard SUPER,REV,RGBINST,RGBGEN,RGBEND,IRINST,IRGEN,IREND   (root)"
    );
    std::process::exit(2);
}

/// Build the request for one `split` invocation. Pure.
///
/// # Errors
/// A static reason when the arguments do not describe one operation.
pub(crate) fn split_request(args: &[String]) -> Result<Request, &'static str> {
    let Some(sub) = args.get(1).map(String::as_str) else {
        return Err("a split subcommand is required");
    };
    match sub {
        "status" => Ok(Request::SplitStatus),
        "list" => Ok(Request::ListSplitAuthorizations),
        "add" => {
            let guard = parse_guard(flag(args, "--guard").ok_or("add needs --guard")?)?;
            let rgb = parse_side(flag(args, "--rgb").ok_or("add needs --rgb")?)?;
            let ir = parse_side(flag(args, "--ir").ok_or("add needs --ir")?)?;
            Ok(Request::AddSplitAuthorization {
                guard: Box::new(guard.into_guard()),
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
            } else {
                key.to_owned()
            };
            Ok(Request::SelectSplitPair {
                guard: Box::new(guard.into_guard()),
                pair,
            })
        }
        _ => Err("unknown split subcommand"),
    }
}

/// `irlume split <status|list|add|remove|select> ...`
pub(crate) fn run(args: &[String]) -> std::process::ExitCode {
    let request = match split_request(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{reason}");
            usage();
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
            "0123456789abcdef0123456789abcdef,7,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,1,/dev/video0,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,2,/dev/video1",
            "--rgb",
            "5986:2113:s1,/dev/video0,0000:00:14.0,usb2,8",
            "--ir",
            "5986:1141:s2,/dev/video1,0000:00:14.0,usb2,5",
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
}
