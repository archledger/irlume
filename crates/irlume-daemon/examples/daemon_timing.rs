// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! One live daemon authentication trial set, with boundary attribution.
//!
//! This connects to the RUNNING daemon over its socket and sends real
//! `Authenticate` requests; with a diagnostic trace subscription it also
//! prints the daemon-side stage boundaries for those requests. It performs
//! no inference itself. See --help and docs/research/benchmark-harness.md.
//! Engine stages can overlap or nest; this tool never sums them.

use irlume_common::diagnostics::{
    TraceEventKind, TraceRecord, TraceStage, TraceValidator, CURRENT_TRACE_SCHEMA_VERSION,
    MAX_TRACE_LINE_BYTES,
};
use irlume_common::{Request, Response};
use std::io::{BufReader, Read, Write as _};
use std::time::{Duration, Instant};

const HELP: &str = "Usage: daemon_timing <user> [--service NAME|none] [--trials N] [--cancel-after MS] [--no-trace]
Sends real Authenticate requests to the running daemon and measures request-to-reply.
With a trace subscription (root; default on unless --no-trace) it also prints the
daemon-side stage boundaries (schema 3). Refused and cancelled trials are labeled,
never pooled with grants. Stage intervals may overlap or nest and are never summed.
Unmeasured boundaries (worker reply to socket write, PAM stack, desktop unlock) are
printed explicitly. Attended, authorized use only: cameras may open.";
const TRACE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

struct Options {
    user: String,
    service: Option<String>,
    trials: u32,
    cancel_after_ms: Option<u64>,
    trace: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut service = Some("kde-fingerprint".to_owned());
        let mut trials = 1_u32;
        let mut cancel_after_ms = None;
        let mut trace = true;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--service" => {
                    let value = args.next().ok_or("--service requires a value")?;
                    service = (value != "none").then(|| value.clone());
                }
                "--trials" => {
                    let value = args.next().ok_or("--trials requires a value")?;
                    trials = value
                        .parse()
                        .map_err(|_| format!("invalid trials: {value}"))?;
                    if trials == 0 || trials > 100 {
                        return Err("trials must be 1..=100".into());
                    }
                }
                "--cancel-after" => {
                    let value = args.next().ok_or("--cancel-after requires a value")?;
                    cancel_after_ms = Some(
                        value
                            .parse()
                            .map_err(|_| format!("invalid cancel-after: {value}"))?,
                    );
                }
                "--no-trace" => trace = false,
                value if value.starts_with('-') => return Err(format!("unknown option: {value}")),
                _ => positional.push(arg.clone()),
            }
        }
        if positional.len() != 1 {
            return Err(HELP.into());
        }
        Ok(Self {
            user: positional.remove(0),
            service,
            trials,
            cancel_after_ms,
            trace,
        })
    }
}

/// One client-measured trial. `wall_us` is the harness's own clock around
/// request-to-reply; it shares no origin with daemon monotonic timestamps.
struct TrialTiming {
    wall_us: Option<u64>,
    cancelled: bool,
    outcome: String,
}

fn outcome_label(response: &Response) -> &'static str {
    match response {
        Response::AuthResult { granted: true, .. } => "granted",
        Response::AuthResult { granted: false, .. } => "refused",
        Response::Error(_) => "error",
        _ => "unexpected",
    }
}

/// Nearest-rank median (ceil(n/2), ranks from one), the same convention the
/// benchmark examples use, so an even sample count reports an observed value
/// rather than an average of two.
fn median(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().div_ceil(2);
    Some(sorted[rank - 1])
}

/// The report separates the two clock domains and always names the
/// unmeasured boundaries. Stage intervals are listed, never summed.
fn render_report(trials: &[TrialTiming], stages: &[(TraceStage, u64)]) -> String {
    let mut out = String::new();
    out.push_str(
        "== request-to-reply (client clock; includes daemon ingress, queue, engine, reply) ==\n",
    );
    for (index, trial) in trials.iter().enumerate() {
        match trial.wall_us {
            Some(wall) => out.push_str(&format!(
                "trial {}: {} {:.3} ms\n",
                index + 1,
                trial.outcome,
                wall as f64 / 1000.0
            )),
            None => out.push_str(&format!(
                "trial {}: {} (no reply interval: {})\n",
                index + 1,
                trial.outcome,
                if trial.cancelled {
                    "cancelled by this harness"
                } else {
                    "connection ended without a reply"
                }
            )),
        }
    }
    let granted: Vec<u64> = trials
        .iter()
        .filter(|t| t.outcome == "granted")
        .filter_map(|t| t.wall_us)
        .collect();
    let refused: Vec<u64> = trials
        .iter()
        .filter(|t| t.outcome == "refused")
        .filter_map(|t| t.wall_us)
        .collect();
    if let Some(m) = median(&granted) {
        out.push_str(&format!(
            "granted median: {:.3} ms ({} samples)\n",
            m as f64 / 1000.0,
            granted.len()
        ));
    }
    if let Some(m) = median(&refused) {
        out.push_str(&format!(
            "refused median: {:.3} ms ({} samples; never pooled with grants)\n",
            m as f64 / 1000.0,
            refused.len()
        ));
    }
    out.push_str("== daemon stage boundaries (daemon monotonic clock; may overlap or nest) ==\n");
    if stages.is_empty() {
        out.push_str("  (no stage records; subscribe without --no-trace and run as root)\n");
    }
    for (stage, elapsed_us) in stages {
        out.push_str(&format!(
            "  {stage:?}: {:.3} ms\n",
            *elapsed_us as f64 / 1000.0
        ));
    }
    out.push_str("stages are attribution labels, not addends; do not sum them\n");
    out.push_str("== unmeasured boundaries ==\n");
    out.push_str("  worker reply to socket write: unmeasured\n");
    out.push_str("  PAM stack around the daemon calls: unmeasured\n");
    out.push_str(
        "  desktop/greeter unlock completion: unmeasured (no trustworthy signal established)\n",
    );
    out
}

fn read_bounded_line<R: Read>(reader: &mut R, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Err(std::io::Error::other("truncated line"))
                };
            }
            Ok(_) if byte[0] == b'\n' => {
                if line.len() > limit {
                    return Err(std::io::Error::other("line too long"));
                }
                return Ok(Some(line));
            }
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > limit {
                    return Err(std::io::Error::other("line too long"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

struct TraceConnection {
    reader: BufReader<std::os::unix::net::UnixStream>,
    validator: TraceValidator,
}

impl TraceConnection {
    fn subscribe(duration_ms: u64) -> Result<Self, String> {
        let timeout = Duration::from_secs(15);
        let mut stream = irlume_common::client::connect_stream(timeout)
            .map_err(|error| format!("connect: {error}"))?;
        let mut request = serde_json::to_vec(&Request::TraceSubscribe {
            duration_ms,
            trace_schema: Some(CURRENT_TRACE_SCHEMA_VERSION),
        })
        .map_err(|error| format!("encode request: {error}"))?;
        request.push(b'\n');
        stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("send request: {error}"))?;
        let mut reader = BufReader::new(stream);
        let header = read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES)
            .map_err(|error| format!("read header: {error}"))?
            .ok_or_else(|| "daemon closed before accepting the trace".to_owned())?;
        let limits = match serde_json::from_slice::<Response>(&header)
            .map_err(|error| format!("invalid daemon response: {error}"))?
        {
            Response::TraceAccepted { limits } => limits,
            Response::Error(message) => return Err(format!("trace refused: {message}")),
            other => return Err(format!("unexpected daemon response: {other:?}")),
        };
        let validator = TraceValidator::new(limits)
            .map_err(|error| format!("invalid daemon limits: {error}"))?;
        Ok(Self { reader, validator })
    }

    /// Drain until the terminal record (or a timeout), returning the stage
    /// boundaries of every operation observed.
    fn drain(mut self) -> Result<Vec<(TraceStage, u64)>, String> {
        let mut stages = Vec::new();
        let deadline = Instant::now() + TRACE_DRAIN_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("trace did not finish within the drain timeout".into());
            }
            self.reader
                .get_ref()
                .set_read_timeout(Some(remaining))
                .map_err(|error| format!("set timeout: {error}"))?;
            let line = match read_bounded_line(&mut self.reader, MAX_TRACE_LINE_BYTES) {
                Ok(Some(line)) => line,
                Ok(None) => {
                    return Err("trace ended without a terminal record".into());
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err("trace did not finish within the drain timeout".into());
                }
                Err(e) => return Err(format!("read trace: {e}")),
            };
            let record: TraceRecord = self
                .validator
                .push_line(&line)
                .map_err(|error| format!("invalid trace record: {error}"))?;
            if let TraceEventKind::StageTiming { stage, elapsed_us } = record.event {
                stages.push((stage, elapsed_us));
            }
            if record.terminal {
                return Ok(stages);
            }
        }
    }
}

fn one_trial(options: &Options) -> Result<TrialTiming, String> {
    let mut stream = irlume_common::client::connect_stream(Duration::from_secs(15))
        .map_err(|error| format!("connect: {error}"))?;
    let request = serde_json::to_vec(&Request::Authenticate {
        user: options.user.clone(),
        service: options.service.clone(),
        structured_errors: true,
        intent_confirmation: None,
    })
    .map_err(|error| format!("encode request: {error}"))?;
    let cancel = options.cancel_after_ms.map(Duration::from_millis);
    let started = Instant::now();
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("send request: {error}"))?;
    // A cancelled trial closes its own socket mid-request: the daemon learns
    // the client left and stops the capture (ClientLink), which is the
    // production cancellation path this harness observes.
    if let Some(delay) = cancel {
        std::thread::sleep(delay);
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    let mut reader = BufReader::new(stream);
    let line = read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES);
    let elapsed = started.elapsed();
    match line {
        Ok(Some(line)) => {
            let response = serde_json::from_slice::<Response>(&line)
                .map_err(|error| format!("invalid response: {error}"))?;
            Ok(TrialTiming {
                wall_us: Some(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)),
                cancelled: false,
                outcome: outcome_label(&response).to_owned(),
            })
        }
        Err(e) => Err(format!("read reply: {e}")),
        Ok(None) => Ok(TrialTiming {
            wall_us: None,
            cancelled: cancel.is_some(),
            outcome: if cancel.is_some() {
                "cancelled"
            } else {
                "no-reply"
            }
            .to_owned(),
        }),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let options = Options::parse(&args)?;
    eprintln!(
        "daemon_timing: user={} service={:?} trials={} cancel_after={:?} trace={}",
        options.user, options.service, options.trials, options.cancel_after_ms, options.trace
    );
    eprintln!(
        "attended, authorized measurement only; cameras may open; refused outcomes are labeled"
    );
    let trace = match if options.trace {
        Some(TraceConnection::subscribe(60_000))
    } else {
        None
    } {
        Some(Ok(connection)) => Some(connection),
        Some(Err(message)) => {
            eprintln!("daemon_timing: continuing without a trace ({message})");
            None
        }
        None => None,
    };
    let mut trials = Vec::new();
    for _ in 0..options.trials {
        trials.push(one_trial(&options)?);
    }
    let stages = match trace {
        Some(connection) => connection.drain()?,
        None => Vec::new(),
    };
    print!("{}", render_report(&trials, &stages));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trial(wall_us: Option<u64>, outcome: &str) -> TrialTiming {
        TrialTiming {
            wall_us,
            cancelled: outcome == "cancelled",
            outcome: outcome.to_owned(),
        }
    }

    #[test]
    fn options_reject_unknown_flags_and_bad_counts() {
        assert!(Options::parse(&["user".into()]).is_ok());
        assert!(Options::parse(&["--surprise".into(), "user".into()]).is_err());
        assert!(Options::parse(&[]).is_err());
        assert!(Options::parse(&["user".into(), "--trials".into(), "0".into()]).is_err());
        assert!(Options::parse(&["user".into(), "--trials".into(), "101".into()]).is_err());
        assert!(Options::parse(&["user".into(), "--cancel-after".into(), "x".into()]).is_err());
        let options = Options::parse(&["u".into(), "--service".into(), "none".into()]).unwrap();
        assert_eq!(options.service, None);
        assert_eq!(options.trials, 1);
    }

    #[test]
    fn the_report_always_names_the_unmeasured_boundaries() {
        let report = render_report(&[trial(Some(1_000), "granted")], &[]);
        assert!(report.contains("worker reply to socket write: unmeasured"));
        assert!(report.contains("PAM stack around the daemon calls: unmeasured"));
        assert!(report.contains("desktop/greeter unlock completion: unmeasured"));
    }

    #[test]
    fn stages_are_listed_but_never_summed() {
        let stages = vec![
            (TraceStage::QueueWait, 1_500),
            (TraceStage::EngineAuthenticate, 3_000_000),
        ];
        let report = render_report(&[trial(Some(3_100_000), "granted")], &stages);
        assert!(report.contains("QueueWait: 1.500 ms"));
        assert!(report.contains("EngineAuthenticate: 3000.000 ms"));
        assert!(report.contains("do not sum them"));
        assert!(!report.contains("total"));
    }

    #[test]
    fn cancelled_and_refused_trials_are_labeled_not_pooled() {
        let trials = vec![
            trial(Some(2_000_000), "granted"),
            trial(Some(4_000_000), "granted"),
            trial(Some(9_000_000), "refused"),
            trial(None, "cancelled"),
        ];
        let report = render_report(&trials, &[]);
        assert!(report.contains("trial 4: cancelled (no reply interval"));
        assert!(
            report.contains("refused median: 9000.000 ms (1 samples; never pooled with grants)")
        );
        assert!(report.contains("granted median: 2000.000 ms (2 samples)"));
    }

    #[test]
    fn median_handles_odd_even_and_empty_inputs() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[7]), Some(7));
        assert_eq!(median(&[3, 1, 2]), Some(2));
        // Nearest rank: an observed value, never an average of two.
        assert_eq!(median(&[4, 1, 3, 2]), Some(2));
    }
}
