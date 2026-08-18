// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded privileged trace recording and offline typed explanation.

use irlume_common::artifact::SecureArtifact;
use irlume_common::diagnostics::{
    parse_trace, TraceEventKind, TraceLimits, TraceRecord, TraceValidator,
    DEFAULT_TRACE_DURATION_MS, MAX_TRACE_BYTES, MAX_TRACE_DURATION_MS, MAX_TRACE_LINE_BYTES,
};
use irlume_common::{Request, Response};
use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

pub(crate) fn run(args: &[String]) -> ExitCode {
    match args.get(1).map(String::as_str) {
        Some("explain") => run_explain(args),
        Some("record") | None | Some("--duration" | "--output") => run_record(args),
        Some(value) if value.starts_with("--duration=") || value.starts_with("--output=") => {
            run_record(args)
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: irlume trace [record] [--duration 60s] [--output FILE.jsonl]\n       irlume trace explain FILE.jsonl [--output FILE.txt]"
    );
    ExitCode::from(2)
}

fn run_record(args: &[String]) -> ExitCode {
    let options = match parse_record_args(args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("irlume trace: {message}");
            return ExitCode::from(2);
        }
    };
    if effective_uid() != 0 {
        eprintln!("irlume trace: recording requires root; use `sudo irlume trace`");
        return ExitCode::from(2);
    }
    eprintln!(
        "irlume trace: privileged diagnostic oracle; exact liveness and match values may be sensitive. No frames, embeddings, credentials, account/profile names, or raw emitter payloads are recorded."
    );
    let output = options.output.unwrap_or_else(default_output_path);
    match record(&output, options.duration) {
        Ok(path) => {
            println!("Diagnostic trace created: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("irlume trace: {message}");
            ExitCode::FAILURE
        }
    }
}

fn record(output: &Path, duration: Duration) -> Result<PathBuf, String> {
    let requested_ms = u64::try_from(duration.as_millis()).unwrap_or(MAX_TRACE_DURATION_MS);
    let timeout = duration.saturating_add(Duration::from_secs(30));
    let mut stream = irlume_common::client::connect_stream(timeout)
        .map_err(|error| format!("connect: {error}"))?;
    let mut request = serde_json::to_vec(&Request::TraceSubscribe {
        duration_ms: requested_ms,
    })
    .map_err(|error| format!("encode request: {error}"))?;
    request.push(b'\n');
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("send request: {error}"))?;

    let mut reader = BufReader::new(stream);
    let header = read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES)?
        .ok_or_else(|| "daemon closed before accepting the trace".to_owned())?;
    let limits = match serde_json::from_slice::<Response>(&header)
        .map_err(|error| format!("invalid daemon response: {error}"))?
    {
        Response::TraceAccepted { limits } => limits,
        Response::Error(message) => return Err(message),
        other => return Err(format!("unexpected daemon response: {other:?}")),
    };
    let mut validator =
        TraceValidator::new(limits).map_err(|error| format!("invalid daemon limits: {error}"))?;
    let mut artifact = SecureArtifact::create(output, limits.max_bytes)
        .map_err(|error| format!("{}: {error}", output.display()))?;

    loop {
        let line = match read_bounded_line(&mut reader, MAX_TRACE_LINE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => {
                return Err(format!(
                    "trace ended without a terminal record; recoverable partial kept at {}",
                    artifact.partial_path().display()
                ));
            }
            Err(message) => {
                return Err(format!(
                    "{message}; recoverable partial kept at {}",
                    artifact.partial_path().display()
                ));
            }
        };
        let record = validator.push_line(&line).map_err(|error| {
            format!(
                "invalid trace: {error}; recoverable partial kept at {}",
                artifact.partial_path().display()
            )
        })?;
        artifact.write_chunk(&line).map_err(|error| {
            format!(
                "write failed: {error}; recoverable partial kept at {}",
                artifact.partial_path().display()
            )
        })?;
        if record.terminal {
            validator.finish().map_err(|error| {
                format!(
                    "invalid terminal: {error}; recoverable partial kept at {}",
                    artifact.partial_path().display()
                )
            })?;
            let published = artifact
                .commit()
                .map_err(|error| format!("{}: {error}", output.display()))?;
            if let Some(warning) = published.durability_warning {
                eprintln!("irlume trace: durability warning: {warning}");
            }
            return Ok(published.final_path);
        }
    }
}

fn read_bounded_line<R: std::io::BufRead>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    let read = std::io::Read::take(
        &mut *reader,
        u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1),
    )
    .read_until(b'\n', &mut line)
    .map_err(|error| format!("read failed: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() > limit || !line.ends_with(b"\n") {
        return Err("trace line exceeded its bound or was truncated".into());
    }
    Ok(Some(line))
}

struct RecordOptions {
    output: Option<PathBuf>,
    duration: Duration,
}

fn parse_record_args(args: &[String]) -> Result<RecordOptions, &'static str> {
    if args.first().map(String::as_str) != Some("trace") {
        return Err("invalid command");
    }
    let mut index = usize::from(args.get(1).map(String::as_str) == Some("record")) + 1;
    let mut output = None;
    let mut duration = None;
    while index < args.len() {
        match args[index].as_str() {
            "--duration" if duration.is_none() => {
                duration = Some(parse_duration(
                    args.get(index + 1).ok_or("--duration requires a value")?,
                )?);
                index += 2;
            }
            value if value.starts_with("--duration=") && duration.is_none() => {
                duration = Some(parse_duration(value.trim_start_matches("--duration="))?);
                index += 1;
            }
            "--output" if output.is_none() => {
                output = Some(PathBuf::from(
                    args.get(index + 1).ok_or("--output requires a path")?,
                ));
                index += 2;
            }
            value if value.starts_with("--output=") && output.is_none() => {
                output = Some(PathBuf::from(value.trim_start_matches("--output=")));
                index += 1;
            }
            _ => return Err("usage: irlume trace [record] [--duration 60s] [--output FILE.jsonl]"),
        }
    }
    if output.as_deref().is_some_and(|path| {
        path.extension().and_then(|extension| extension.to_str()) != Some("jsonl")
    }) {
        return Err("--output must end in .jsonl");
    }
    Ok(RecordOptions {
        output,
        duration: duration.unwrap_or(Duration::from_millis(DEFAULT_TRACE_DURATION_MS)),
    })
}

fn parse_duration(raw: &str) -> Result<Duration, &'static str> {
    let (number, multiplier) = if let Some(number) = raw.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = raw.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = raw.strip_suffix('m') {
        (number, 60_000)
    } else {
        return Err("duration must end in ms, s, or m");
    };
    let value = number
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("duration must be a positive integer")?;
    Ok(Duration::from_millis(
        value.saturating_mul(multiplier).min(MAX_TRACE_DURATION_MS),
    ))
}

fn default_output_path() -> PathBuf {
    PathBuf::from(format!(
        "irlume-trace-{}.jsonl",
        crate::support_report::utc_filename_timestamp()
    ))
}

fn effective_uid() -> u32 {
    #[expect(
        clippy::undocumented_unsafe_blocks,
        reason = "libc has no safe uid wrapper"
    )]
    unsafe {
        libc::geteuid()
    }
}

fn run_explain(args: &[String]) -> ExitCode {
    let (input, output) = match parse_explain_args(args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("irlume trace explain: {message}");
            return ExitCode::from(2);
        }
    };
    let rendered = match explain(&input) {
        Ok(rendered) => rendered,
        Err(message) => {
            eprintln!("irlume trace explain: {message}");
            return ExitCode::FAILURE;
        }
    };
    let Some(output) = output else {
        print!("{rendered}");
        return ExitCode::SUCCESS;
    };
    let result = (|| {
        let mut artifact = SecureArtifact::create(&output, MAX_TRACE_BYTES)?;
        artifact.write_chunk(rendered.as_bytes())?;
        artifact.commit()
    })();
    match result {
        Ok(published) => {
            println!(
                "Trace explanation created: {}",
                published.final_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("irlume trace explain: {}: {error}", output.display());
            ExitCode::FAILURE
        }
    }
}

fn parse_explain_args(args: &[String]) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    if args.get(1).map(String::as_str) != Some("explain") {
        return Err("invalid command");
    }
    let input = args.get(2).ok_or("a .jsonl trace path is required")?;
    if input.starts_with('-') {
        return Err("a .jsonl trace path is required");
    }
    let mut output = None;
    let mut index = 3;
    while index < args.len() {
        match args[index].as_str() {
            "--output" if output.is_none() => {
                output = Some(PathBuf::from(
                    args.get(index + 1).ok_or("--output requires a path")?,
                ));
                index += 2;
            }
            value if value.starts_with("--output=") && output.is_none() => {
                output = Some(PathBuf::from(value.trim_start_matches("--output=")));
                index += 1;
            }
            _ => return Err("usage: irlume trace explain FILE.jsonl [--output FILE.txt]"),
        }
    }
    if output.as_deref().is_some_and(|path| {
        path.extension().and_then(|extension| extension.to_str()) != Some("txt")
    }) {
        return Err("--output must end in .txt");
    }
    Ok((PathBuf::from(input), output))
}

fn explain(input: &Path) -> Result<String, String> {
    let file =
        std::fs::File::open(input).map_err(|error| format!("{}: {error}", input.display()))?;
    let limits = TraceLimits::bounded(MAX_TRACE_DURATION_MS);
    let parsed = parse_trace(BufReader::new(file), limits).map_err(|error| error.to_string())?;
    Ok(render_timeline(parsed.records()))
}

fn render_timeline(records: &[TraceRecord]) -> String {
    use std::fmt::Write as _;
    let mut by_operation: BTreeMap<String, Vec<&TraceRecord>> = BTreeMap::new();
    let mut dropped = 0_u64;
    for record in records {
        let operation_id = serde_json::to_string(&record.operation_id)
            .unwrap_or_else(|_| "\"invalid\"".into())
            .trim_matches('"')
            .to_owned();
        by_operation.entry(operation_id).or_default().push(record);
        if let TraceEventKind::EventsDropped { count } = record.event {
            dropped = dropped.saturating_add(count);
        }
    }

    let mut output = String::new();
    writeln!(output, "Irlume diagnostic trace schema 1").unwrap();
    writeln!(output, "Records: {}", records.len()).unwrap();
    writeln!(output, "Events dropped before recording: {dropped}").unwrap();
    for (operation_id, operation_records) in by_operation {
        writeln!(output).unwrap();
        writeln!(
            output,
            "Operation {operation_id} ({:?})",
            operation_records[0].operation
        )
        .unwrap();
        for record in operation_records {
            writeln!(
                output,
                "  +{:>10} us  #{}  {}{}",
                record.monotonic_us,
                record.sequence,
                render_event(&record.event),
                if record.terminal { " [terminal]" } else { "" }
            )
            .unwrap();
        }
    }
    output
}

fn render_event(event: &TraceEventKind) -> String {
    // Every value is a closed enum, finite number, validated SafeLabel, or
    // exact contract. No daemon/user prose is accepted into this renderer.
    format!("{event:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::diagnostics::{
        CategoricalOutcome, OperationClass, OperationId, TraceWarning, TRACE_SCHEMA_VERSION,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixture_record(sequence: u64, event: TraceEventKind, terminal: bool) -> TraceRecord {
        TraceRecord {
            trace_schema: TRACE_SCHEMA_VERSION,
            sequence,
            monotonic_us: sequence * 1_000,
            utc_unix_ms: 1,
            operation_id: OperationId::from_bytes([7; 16]),
            operation: OperationClass::Authentication,
            event,
            terminal,
        }
    }

    fn sandbox(label: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "irlume-trace-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn serve_fixture(listener: UnixListener, limits: TraceLimits, records: Vec<TraceRecord>) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request_line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request_line)
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&request_line).unwrap(),
            Request::TraceSubscribe { .. }
        ));
        serde_json::to_writer(&mut stream, &Response::TraceAccepted { limits }).unwrap();
        stream.write_all(b"\n").unwrap();
        for record in records {
            serde_json::to_writer(&mut stream, &record).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    }

    #[test]
    fn record_arguments_are_bounded_and_require_jsonl() {
        let parsed = parse_record_args(&[
            "trace".into(),
            "--duration".into(),
            "10m".into(),
            "--output=x.jsonl".into(),
        ])
        .unwrap();
        assert_eq!(
            parsed.duration,
            Duration::from_millis(MAX_TRACE_DURATION_MS)
        );
        assert!(parse_record_args(&["trace".into(), "--output=x.txt".into()]).is_err());
        assert!(parse_duration("NaNs").is_err());
        assert!(parse_duration("0s").is_err());
    }

    #[test]
    fn explanation_groups_typed_events_and_reports_drops_without_prose() {
        let limits = TraceLimits::bounded(1_000);
        let records = vec![
            fixture_record(
                0,
                TraceEventKind::TraceStarted {
                    limits,
                    warning: TraceWarning::PrivilegedDiagnosticOracle,
                },
                false,
            ),
            fixture_record(1, TraceEventKind::EventsDropped { count: 4 }, false),
            fixture_record(
                2,
                TraceEventKind::Finished {
                    outcome: CategoricalOutcome::Denied,
                },
                true,
            ),
        ];
        let rendered = render_timeline(&records);
        assert!(rendered.contains("Operation 07070707070707070707070707070707"));
        assert!(rendered.contains("Events dropped before recording: 4"));
        assert!(rendered.contains("[terminal]"));
    }

    #[test]
    fn bounded_reader_rejects_truncation_and_oversize() {
        let mut truncated = BufReader::new(&b"{}"[..]);
        assert!(read_bounded_line(&mut truncated, 8).is_err());
        let mut oversized = BufReader::new(&b"123456789\n"[..]);
        assert!(read_bounded_line(&mut oversized, 8).is_err());
    }

    #[test]
    fn complete_trace_is_published_mode_0600_and_parseable() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = sandbox("publish");
        let socket = dir.join("daemon.sock");
        let target = dir.join("capture.jsonl");
        let limits = TraceLimits::bounded(10);
        let records = vec![
            fixture_record(
                0,
                TraceEventKind::TraceStarted {
                    limits,
                    warning: TraceWarning::PrivilegedDiagnosticOracle,
                },
                false,
            ),
            fixture_record(
                1,
                TraceEventKind::Finished {
                    outcome: CategoricalOutcome::Completed,
                },
                true,
            ),
        ];
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || serve_fixture(listener, limits, records));
        let previous = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("IRLUME_SOCKET", &socket);
        let published = record(&target, Duration::from_millis(10)).unwrap();
        match previous {
            Some(value) => std::env::set_var("IRLUME_SOCKET", value),
            None => std::env::remove_var("IRLUME_SOCKET"),
        }
        server.join().unwrap();

        assert_eq!(published, target);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let parsed =
            parse_trace(BufReader::new(std::fs::File::open(target).unwrap()), limits).unwrap();
        assert_eq!(parsed.records().len(), 2);
    }

    #[test]
    fn disconnect_without_terminal_keeps_partial_and_never_publishes_final() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = sandbox("partial");
        let socket = dir.join("daemon.sock");
        let target = dir.join("capture.jsonl");
        let limits = TraceLimits::bounded(10);
        let records = vec![fixture_record(
            0,
            TraceEventKind::TraceStarted {
                limits,
                warning: TraceWarning::PrivilegedDiagnosticOracle,
            },
            false,
        )];
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || serve_fixture(listener, limits, records));
        let previous = std::env::var_os("IRLUME_SOCKET");
        std::env::set_var("IRLUME_SOCKET", &socket);
        let error = record(&target, Duration::from_millis(10)).unwrap_err();
        match previous {
            Some(value) => std::env::set_var("IRLUME_SOCKET", value),
            None => std::env::remove_var("IRLUME_SOCKET"),
        }
        server.join().unwrap();

        assert!(error.contains("without a terminal record"));
        assert!(!target.exists());
        let partials = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".partial."))
            .count();
        assert_eq!(partials, 1);
    }
}
