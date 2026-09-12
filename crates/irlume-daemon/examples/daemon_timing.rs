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
    MAX_TRACE_DURATION_MS, MAX_TRACE_LINE_BYTES,
};
use irlume_common::{Request, Response};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const HELP: &str = "Usage: daemon_timing <user> [--service NAME|none] [--trials N] [--cancel-after MS] [--no-trace]
Sends real Authenticate requests to the running daemon and measures request-to-reply.
With a trace subscription (root; default on unless --no-trace) it also prints the
daemon-side stage boundaries (schema 3). Refused and cancelled trials are labeled,
never pooled with grants. Stage intervals may overlap or nest and are never summed.
Unmeasured boundaries (worker reply to socket write, PAM stack, desktop unlock) are
printed explicitly. Replies have a 30s deadline; cancellation must be 0..=30000ms.
Trace collection reserves a bounded window for the whole trial plan (at most 5min)
and waits for its terminal record. Use --no-trace for longer trial plans or old daemons.
Attended, authorized use only: cameras may open.";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
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
        if cancel_after_ms.is_some_and(|ms| ms > 30_000) {
            return Err("cancel-after must be 0..=30000 ms".into());
        }
        let options = Self {
            user: positional.remove(0),
            service,
            trials,
            cancel_after_ms,
            trace,
        };
        if options.trace {
            options.trace_duration_ms()?;
        }
        Ok(options)
    }

    fn trace_duration_ms(&self) -> Result<u64, String> {
        let reply = self
            .cancel_after_ms
            .map(Duration::from_millis)
            .unwrap_or(REPLY_TIMEOUT);
        // Include each connection budget and leave cancellation cleanup time.
        // Reject rather than silently letting the server clamp away coverage.
        let duration = (CONNECT_TIMEOUT + reply + TRACE_DRAIN_TIMEOUT) * self.trials;
        let ms = u64::try_from(duration.as_millis()).map_err(|_| "trace plan overflow")?;
        if ms > MAX_TRACE_DURATION_MS {
            return Err(
                "trial plan exceeds the 5min trace limit; use fewer trials or --no-trace".into(),
            );
        }
        Ok(ms)
    }
}

/// One client-measured trial. `wall_us` is the harness's own clock around
/// request-to-reply; it shares no origin with daemon monotonic timestamps.
#[derive(Debug)]
struct TrialTiming {
    wall_us: Option<u64>,
    cancelled: bool,
    outcome: String,
    reason: Option<String>,
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
        if let Some(reason) = &trial.reason {
            // Debug formatting escapes terminal controls and line breaks.
            out.push_str(&format!("  reason: {reason:?}\n"));
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

fn read_bounded_line(
    reader: &mut BufReader<UnixStream>,
    limit: usize,
    deadline: Instant,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "line deadline",
            ));
        }
        reader.get_ref().set_read_timeout(Some(remaining))?;
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::other("truncated line"))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(available.len());
        if count > limit.saturating_sub(line.len()) {
            return Err(std::io::Error::other("line too long"));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

fn encode_request(request: &Request) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec(request).map_err(|error| format!("encode request: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

struct TraceConnection {
    reader: BufReader<std::os::unix::net::UnixStream>,
    validator: TraceValidator,
    deadline: Instant,
    coverage_deadline: Instant,
}

impl TraceConnection {
    fn subscribe(duration_ms: u64) -> Result<Self, String> {
        let stream = irlume_common::client::connect_stream(CONNECT_TIMEOUT)
            .map_err(|error| format!("connect: {error}"))?;
        Self::on_stream(stream, duration_ms)
    }

    fn on_stream(mut stream: UnixStream, duration_ms: u64) -> Result<Self, String> {
        let request = encode_request(&Request::TraceSubscribe {
            duration_ms,
            trace_schema: Some(CURRENT_TRACE_SCHEMA_VERSION),
        })?;
        stream
            .set_write_timeout(Some(CONNECT_TIMEOUT))
            .map_err(|e| e.to_string())?;
        let subscription_sent = Instant::now();
        stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("send request: {error}"))?;
        let mut reader = BufReader::new(stream);
        let header_deadline = Instant::now() + CONNECT_TIMEOUT;
        let header = read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES, header_deadline)
            .map_err(|error| format!("read header: {error}"))?
            .ok_or_else(|| "daemon closed before accepting the trace".to_owned())?;
        let limits = match serde_json::from_slice::<Response>(&header)
            .map_err(|error| format!("invalid daemon response: {error}"))?
        {
            Response::TraceAccepted { limits } => limits,
            Response::Error(message) => return Err(format!("trace refused: {message}")),
            other => return Err(format!("unexpected daemon response: {other:?}")),
        };
        let mut validator = TraceValidator::new(limits)
            .map_err(|error| format!("invalid daemon limits: {error}"))?;
        if limits.duration_ms < duration_ms {
            return Err("accepted trace window is shorter than the trial plan".into());
        }
        // Subscription processing can only start after this instant. Using it
        // is conservative even when delivery of the start record is delayed.
        let coverage_deadline = subscription_sent + Duration::from_millis(limits.duration_ms);
        let deadline = coverage_deadline + TRACE_DRAIN_TIMEOUT;
        // Older daemons may ignore the requested schema. Verify it before any
        // authentication request, rather than losing timing attribution later.
        let first = read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES, header_deadline)
            .map_err(|error| format!("read trace start: {error}"))?
            .ok_or("trace closed before its start record")?;
        let first = validator
            .push_line(&first)
            .map_err(|e| format!("invalid trace start: {e}"))?;
        if first.trace_schema != CURRENT_TRACE_SCHEMA_VERSION
            || !matches!(first.event, TraceEventKind::TraceStarted { .. })
            || first.terminal
        {
            return Err("daemon did not start the requested schema 3 trace; use --no-trace for an older daemon".into());
        }
        Ok(Self {
            reader,
            validator,
            deadline,
            coverage_deadline,
        })
    }

    /// Drain until the terminal record (or a timeout), returning the stage
    /// boundaries of every operation observed.
    fn drain(mut self) -> Result<Vec<(TraceStage, u64)>, String> {
        let mut stages = Vec::new();
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("trace did not finish within the drain timeout".into());
            }
            self.reader
                .get_ref()
                .set_read_timeout(Some(remaining))
                .map_err(|error| format!("set timeout: {error}"))?;
            let line =
                match read_bounded_line(&mut self.reader, MAX_TRACE_LINE_BYTES, self.deadline) {
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
            if matches!(record.event, TraceEventKind::EventsDropped { count } if count != 0) {
                return Err("trace dropped events; timing attribution is incomplete".into());
            }
            if let TraceEventKind::StageTiming { stage, elapsed_us } = record.event {
                stages.push((stage, elapsed_us));
            }
            if record.terminal {
                self.validator
                    .finish()
                    .map_err(|e| format!("invalid trace end: {e}"))?;
                return Ok(stages);
            }
        }
    }
}

fn one_trial(options: &Options) -> Result<TrialTiming, String> {
    let stream = irlume_common::client::connect_stream(CONNECT_TIMEOUT)
        .map_err(|error| format!("connect: {error}"))?;
    trial_on_stream(stream, options, REPLY_TIMEOUT)
}

fn trial_on_stream(
    mut stream: UnixStream,
    options: &Options,
    reply_timeout: Duration,
) -> Result<TrialTiming, String> {
    let request = encode_request(&Request::Authenticate {
        user: options.user.clone(),
        service: options.service.clone(),
        structured_errors: true,
        intent_confirmation: None,
    })?;
    let cancel = options.cancel_after_ms.map(Duration::from_millis);
    let started = Instant::now();
    stream
        .set_write_timeout(Some(reply_timeout))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("send request: {error}"))?;
    // Read immediately so a reply that beats cancellation keeps its actual
    // reply interval. A deadline-triggered disconnect has no reply interval.
    let mut reader = BufReader::new(stream);
    let deadline = started + cancel.unwrap_or(reply_timeout).min(reply_timeout);
    let line = read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES, deadline);
    let elapsed = started.elapsed();
    match line {
        Ok(Some(line)) => {
            let response = serde_json::from_slice::<Response>(&line)
                .map_err(|error| format!("invalid response: {error}"))?;
            Ok(TrialTiming {
                wall_us: Some(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)),
                cancelled: false,
                outcome: outcome_label(&response).to_owned(),
                reason: match response {
                    Response::AuthResult {
                        granted: false,
                        reason,
                        ..
                    } => Some(reason),
                    Response::Error(reason) => Some(reason),
                    _ => None,
                },
            })
        }
        Err(e)
            if cancel.is_some()
                && matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
        {
            reader
                .get_ref()
                .shutdown(std::net::Shutdown::Both)
                .map_err(|e| format!("cancel request: {e}"))?;
            Ok(TrialTiming {
                wall_us: None,
                cancelled: true,
                outcome: "cancelled".into(),
                reason: None,
            })
        }
        Err(e) => Err(format!("read reply: {e}")),
        Ok(None) => Ok(TrialTiming {
            wall_us: None,
            cancelled: false,
            outcome: "no-reply".into(),
            reason: None,
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
    let (trace, coverage_deadline) = if options.trace {
        let connection = TraceConnection::subscribe(options.trace_duration_ms()?)?;
        let coverage_deadline = connection.coverage_deadline;
        // Drain while trials run: an undrained subscriber can overflow its
        // bounded queue and lose exactly the events this tool is measuring.
        (
            Some(std::thread::spawn(move || connection.drain())),
            Some(coverage_deadline),
        )
    } else {
        (None, None)
    };
    let trials: Result<Vec<_>, _> = (0..options.trials).map(|_| one_trial(&options)).collect();
    let coverage_overrun = coverage_deadline.is_some_and(|deadline| Instant::now() > deadline);
    let stages = match trace {
        Some(worker) => worker.join().map_err(|_| "trace reader panicked")?,
        None => Ok(Vec::new()),
    };
    let trials = trials?;
    let stages = stages?;
    if coverage_overrun {
        return Err(
            "trials outlasted the reserved trace window; timing attribution is incomplete".into(),
        );
    }
    print!("{}", render_report(&trials, &stages));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::diagnostics::{
        CategoricalOutcome, OperationClass, OperationId, TraceLimits, TraceWarning,
    };

    const REFUSAL: &[u8] = b"{\"AuthResult\":{\"granted\":false,\"score\":0.0,\"live\":false,\"reason\":\"no face in IR\"}}\n";

    fn options(cancel: Option<u64>) -> Options {
        Options {
            user: "synthetic-user".into(),
            service: Some("kde-fingerprint".into()),
            trials: 1,
            cancel_after_ms: cancel,
            trace: false,
        }
    }

    fn fake_auth(reply: Option<&'static [u8]>) -> (UnixStream, std::thread::JoinHandle<()>) {
        let (client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut reader = BufReader::new(server);
            let request = read_bounded_line(
                &mut reader,
                MAX_TRACE_LINE_BYTES,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap()
            .unwrap();
            assert!(matches!(
                serde_json::from_slice::<Request>(&request).unwrap(),
                Request::Authenticate { .. }
            ));
            if let Some(reply) = reply {
                reader.get_mut().write_all(reply).unwrap();
            }
        });
        (client, worker)
    }

    #[test]
    fn socket_trial_sends_a_complete_request_and_preserves_refusal_reason() {
        let (client, worker) = fake_auth(Some(REFUSAL));
        let result = trial_on_stream(client, &options(None), REPLY_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert_eq!(result.outcome, "refused");
        assert_eq!(result.reason.as_deref(), Some("no face in IR"));
        assert!(result.wall_us.is_some());
    }

    #[test]
    fn reply_winning_cancellation_keeps_its_reply_time() {
        let (client, worker) = fake_auth(Some(REFUSAL));
        let result = trial_on_stream(client, &options(Some(2_000)), REPLY_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert_eq!(result.outcome, "refused");
        assert!(!result.cancelled);
        assert!(
            result.wall_us.unwrap() < 1_500_000,
            "must not sleep to the cancellation instant after a reply"
        );
    }

    #[test]
    fn cancellation_disconnects_without_inventing_a_reply_interval() {
        let (client, server) = UnixStream::pair().unwrap();
        let result = trial_on_stream(client, &options(Some(30)), REPLY_TIMEOUT).unwrap();
        assert!(result.cancelled);
        assert_eq!(result.wall_us, None);
        let mut reader = BufReader::new(server);
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(
            read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES, deadline)
                .unwrap()
                .is_some()
        );
        assert!(
            read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES, deadline)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn peer_eof_before_cancel_is_not_a_harness_cancellation() {
        let (client, worker) = fake_auth(None);
        let result = trial_on_stream(client, &options(Some(2_000)), REPLY_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert_eq!(result.outcome, "no-reply");
        assert!(!result.cancelled);
    }

    #[test]
    fn reply_wait_uses_its_own_budget_and_a_partial_line_cannot_extend_it() {
        let (client, mut server) = UnixStream::pair().unwrap();
        // An inherited connect timeout must not become the reply timeout.
        client
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            server.write_all(REFUSAL).unwrap();
        });
        let result = trial_on_stream(client, &options(None), Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert_eq!(result.outcome, "refused");

        let (client, mut server) = UnixStream::pair().unwrap();
        server.write_all(b"{\"AuthResult\":").unwrap();
        let result = trial_on_stream(client, &options(None), Duration::from_millis(30));
        assert!(result.unwrap_err().contains("read reply"));
    }

    #[test]
    fn socket_lines_reject_oversize_and_truncation() {
        for (bytes, limit, expected) in [
            (b"abc\n".as_slice(), 3, true),
            (b"abcd\n", 3, false),
            (b"abc", 3, false),
        ] {
            let (client, mut server) = UnixStream::pair().unwrap();
            server.write_all(bytes).unwrap();
            server.shutdown(std::net::Shutdown::Write).unwrap();
            let result = read_bounded_line(
                &mut BufReader::new(client),
                limit,
                Instant::now() + Duration::from_secs(1),
            );
            assert_eq!(result.is_ok(), expected);
        }
    }

    fn trace_record(
        schema: u32,
        sequence: u64,
        event: TraceEventKind,
        terminal: bool,
    ) -> TraceRecord {
        TraceRecord {
            trace_schema: schema,
            sequence,
            monotonic_us: sequence,
            utc_unix_ms: 0,
            operation_id: OperationId::from_bytes([0; 16]),
            operation: OperationClass::Authentication,
            event,
            terminal,
        }
    }

    fn send_record(stream: &mut UnixStream, record: &TraceRecord) {
        let mut bytes = serde_json::to_vec(record).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).unwrap();
    }

    fn trace_pair(schema: u32, duration: u64) -> (UnixStream, UnixStream) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let limits = TraceLimits::bounded(duration);
        let mut header = serde_json::to_vec(&Response::TraceAccepted { limits }).unwrap();
        header.push(b'\n');
        server.write_all(&header).unwrap();
        send_record(
            &mut server,
            &trace_record(
                schema,
                0,
                TraceEventKind::TraceStarted {
                    limits,
                    warning: TraceWarning::PrivilegedDiagnosticOracle,
                },
                false,
            ),
        );
        (client, server)
    }

    #[test]
    fn trace_rejects_ignored_schema_and_clipped_coverage_before_trials() {
        let (client, _server) = trace_pair(1, 100);
        assert!(TraceConnection::on_stream(client, 100)
            .err()
            .unwrap()
            .contains("schema 3"));
        let (client, _server) = trace_pair(3, 50);
        assert!(TraceConnection::on_stream(client, 100)
            .err()
            .unwrap()
            .contains("shorter"));
    }

    #[test]
    fn trace_requires_a_terminal_record_and_rejects_dropped_events() {
        let (client, server) = trace_pair(3, 100);
        let connection = TraceConnection::on_stream(client, 100).unwrap();
        server.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(connection.drain().unwrap_err().contains("terminal"));
        let (client, mut server) = trace_pair(3, 100);
        let connection = TraceConnection::on_stream(client, 100).unwrap();
        send_record(
            &mut server,
            &trace_record(3, 1, TraceEventKind::EventsDropped { count: 1 }, false),
        );
        assert!(connection.drain().unwrap_err().contains("dropped"));
    }

    #[test]
    fn trace_waits_for_the_promised_window_instead_of_a_fixed_five_second_drain() {
        let (client, mut server) = trace_pair(3, 6_000);
        let connection = TraceConnection::on_stream(client, 6_000).unwrap();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(6));
            send_record(
                &mut server,
                &trace_record(
                    3,
                    1,
                    TraceEventKind::StageTiming {
                        stage: TraceStage::QueueWait,
                        elapsed_us: 12,
                    },
                    false,
                ),
            );
            send_record(
                &mut server,
                &trace_record(
                    3,
                    2,
                    TraceEventKind::Finished {
                        outcome: CategoricalOutcome::Completed,
                    },
                    true,
                ),
            );
        });
        let stages = connection.drain().unwrap();
        worker.join().unwrap();
        assert_eq!(stages, vec![(TraceStage::QueueWait, 12)]);
    }

    #[test]
    fn trace_plan_and_cancellation_are_bounded_before_connecting() {
        let parse =
            |args: &[&str]| Options::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            parse(&["user"]).unwrap().trace_duration_ms().unwrap(),
            50_000
        );
        assert_eq!(
            parse(&["user", "--trials", "6"])
                .unwrap()
                .trace_duration_ms()
                .unwrap(),
            300_000
        );
        assert!(parse(&["user", "--trials", "7"]).is_err());
        assert!(parse(&["user", "--trials", "100", "--no-trace"]).is_ok());
        assert!(parse(&["user", "--cancel-after", "30001"]).is_err());
    }

    #[test]
    fn refusal_reason_is_visible_but_terminal_controls_are_escaped() {
        let mut refused = trial(Some(1_000), "refused");
        refused.reason = Some("no face\n\x1b[2J".into());
        let report = render_report(&[refused], &[]);
        assert!(report.contains("no face\\n\\u{1b}[2J"));
        assert!(!report.contains('\x1b'));
    }

    fn trial(wall_us: Option<u64>, outcome: &str) -> TrialTiming {
        TrialTiming {
            wall_us,
            cancelled: outcome == "cancelled",
            outcome: outcome.to_owned(),
            reason: None,
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
