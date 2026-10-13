// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Explicit retained-process reliability control, outside the ordinary GPU sweep.

#![cfg(test)]

use super::gpu_reliability_clock_tests::{proves_system_sleep, SleepOffsetBounds};
use super::gpu_reliability_protocol_tests::{Boundary, Protocol, Reference, Report, Step};
use super::gpu_reliability_reader_tests::{sleep_bounds, Observation, Reader};
use super::gpu_reliability_witness_tests::{validate_runtime_witness, CounterGrowth, WitnessError};
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

pub(super) struct Config {
    pub(super) identity: String,
    pub(super) cpu_reference: String,
    pub(super) gpu_bits: [String; 4],
    runtime_wait: Duration,
    system_wait: Duration,
}

impl Config {
    fn parse(text: &str, attended: Option<&str>) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let object = value.as_object().ok_or("reference must be an object")?;
        if object.len() != 5 || !matches!(attended, None | Some("0") | Some("1")) {
            return Err("invalid reference fields or attended intent".into());
        }
        let hash = |value: Option<&serde_json::Value>| -> Result<String, String> {
            let hash = value.and_then(|v| v.as_str()).ok_or("missing SHA-256")?;
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
            {
                return Err("expected lowercase SHA-256".into());
            }
            Ok(hash.to_owned())
        };
        let wait = |name: &str| -> Result<Duration, String> {
            value
                .get(name)
                .and_then(|v| v.as_u64())
                .filter(|v| *v <= 600)
                .map(Duration::from_secs)
                .ok_or_else(|| format!("{name} must be an integer in 0..600"))
        };
        let runtime_wait = wait("runtime_wait_secs")?;
        let system_wait = wait("system_wait_secs")?;
        if !system_wait.is_zero() && attended != Some("1") {
            return Err(
                "system wait needs fresh operator Ready and IRLUME_GPU_RELIABILITY_ATTENDED=1"
                    .into(),
            );
        }
        let gpu = value
            .get("gpu_bits")
            .and_then(|v| v.as_array())
            .filter(|v| v.len() == 4)
            .ok_or("four prior GPU digests required")?;
        Ok(Self {
            identity: hash(value.get("identity"))?,
            cpu_reference: hash(value.get("cpu_reference"))?,
            gpu_bits: [
                hash(gpu.first())?,
                hash(gpu.get(1))?,
                hash(gpu.get(2))?,
                hash(gpu.get(3))?,
            ],
            runtime_wait,
            system_wait,
        })
    }
}

/// Read a bounded, explicit reference for an opt-in diagnostic.
///
/// # Errors
/// Refuses non-regular, unreadable, oversized or invalid reference input.
pub(super) fn read_reference(path: &Path, attended: Option<&str>) -> Result<Config, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    // Validate the opened descriptor without waiting for a FIFO peer first.
    // Nonblocking mode does not alter ordinary regular-file reads on Linux.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("reference is not a regular file".into());
    }
    let mut text = String::new();
    file.take(8193)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 8192 {
        return Err("reference exceeds 8192 bytes".into());
    }
    Config::parse(&text, attended)
}

pub(super) trait Observations {
    fn boundary(&mut self, boundary: Boundary) -> Result<(), String>;
    fn runtime_start(&mut self) -> Result<(), String>;
    fn runtime_end(&mut self) -> Result<bool, String>;
    fn system(&mut self) -> Result<bool, String>;
}

/// Drive one retained protocol, stopping on the first observation or call error.
///
/// # Errors
/// Propagates failed observations/boundaries and protocol refusals without retry.
pub(super) fn drive(
    protocol: &mut Protocol<'_>,
    observations: &mut impl Observations,
) -> Result<Report, String> {
    loop {
        let result = match protocol.next() {
            Step::Boundary(boundary) => {
                if let Err(error) = observations.boundary(boundary) {
                    let _ = protocol.boundary(boundary, false, false);
                    return Err(error);
                }
                protocol.boundary(boundary, true, true)
            }
            Step::Infer { .. } => protocol.infer(),
            Step::RuntimeWait => {
                observations.runtime_start()?;
                protocol.runtime_wait_finished()
            }
            Step::RuntimeProof => protocol.runtime_proof(observations.runtime_end()?),
            Step::SystemWait => protocol.system_proof(observations.system()?),
            Step::Complete => return Ok(protocol.report()),
            Step::Stopped => return Err("protocol stopped".into()),
        };
        result.map_err(|e| format!("protocol refused: {e:?}"))?;
    }
}

struct HardwareObservations<'a> {
    cpu: &'a mut crate::Embedder,
    platform: &'a crate::npu::gpu::GpuPlatform,
    reader: Reader,
    config: &'a Config,
    samples: [Option<Observation>; 4],
    runtime_clock: Option<SleepOffsetBounds>,
    cpu_checks: u64,
}

fn runtime_verdict(result: Result<CounterGrowth, WitnessError>) -> Result<bool, String> {
    match result {
        Ok(_) => Ok(true),
        Err(error @ (WitnessError::Counter | WitnessError::Binding | WitnessError::ReadOrder)) => {
            Err(format!("invalid runtime observation: {error:?}"))
        }
        Err(
            WitnessError::Posture
            | WitnessError::NoSuspendedGrowth
            | WitnessError::SystemSleepNotExcluded,
        ) => Ok(false),
    }
}

impl Observations for HardwareObservations<'_> {
    fn boundary(&mut self, boundary: Boundary) -> Result<(), String> {
        self.cpu_checks += 1;
        let cpu = self.cpu.cpu_reference_digest().map_err(|e| e.to_string())?;
        if cpu != self.config.cpu_reference {
            return Err(format!("CPU canary changed at {boundary:?}"));
        }
        self.platform.still_loaded_as_hashed()?;
        self.reader.verify_binding()?;
        println!("RELIABILITY_BOUNDARY {boundary:?} cpu_canary=unchanged inventory=unchanged binding=unchanged cpu_fingerprint_calls={}", self.cpu_checks);
        Ok(())
    }

    fn runtime_start(&mut self) -> Result<(), String> {
        self.runtime_clock = sleep_bounds();
        self.samples[0] = Some(self.reader.sample()?);
        let before = self.samples[0].as_ref().unwrap().view();
        if before.status != [Some("active"); 2] || before.control != [Some("auto"); 2] {
            println!("RELIABILITY_RUNTIME no active/AUTO start: INCONCLUSIVE");
            return Ok(());
        }
        let deadline = Instant::now() + self.config.runtime_wait;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            let observation = self.reader.sample()?;
            let sample = observation.view();
            if sample.control != [Some("auto"); 2] {
                println!("RELIABILITY_RUNTIME control changed: INCONCLUSIVE");
                break;
            }
            if sample.status == [Some("suspended"); 2] {
                self.samples[1] = Some(observation);
                // One second observation, not a retry until an attractive delta.
                std::thread::sleep(Duration::from_millis(10));
                self.samples[2] = Some(self.reader.sample()?);
                break;
            }
        }
        self.reader.verify_binding()
    }

    fn runtime_end(&mut self) -> Result<bool, String> {
        self.samples[3] = Some(self.reader.sample()?);
        let end = sleep_bounds();
        println!(
            "RELIABILITY_RUNTIME observations={:?} sleep_start={:?} sleep_end={end:?}",
            self.samples, self.runtime_clock
        );
        let [Some(a), Some(b), Some(c), Some(d)] = &self.samples else {
            println!("RELIABILITY_RUNTIME missing event: INCONCLUSIVE");
            return Ok(false);
        };
        let result = validate_runtime_witness(
            self.reader.expected(),
            &[a.view(), b.view(), c.view(), d.view()],
            self.runtime_clock,
            end,
        );
        println!("RELIABILITY_RUNTIME witness={result:?}; occurrence only, not continuous residency or D3cold");
        runtime_verdict(result)
    }

    fn system(&mut self) -> Result<bool, String> {
        self.reader.verify_binding()?;
        let start = sleep_bounds();
        if self.config.system_wait.is_zero() {
            println!("RELIABILITY_SYSTEM wait disabled: INCONCLUSIVE");
            return Ok(false);
        }
        println!("RELIABILITY_READY pid={} identity={} counted_calls=700 sleep_start={start:?}; operator initiates suspend; wait={:?}",
            std::process::id(), self.config.identity, self.config.system_wait);
        let deadline = Instant::now() + self.config.system_wait;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            let end = sleep_bounds();
            if proves_system_sleep(start, end) {
                self.reader.verify_binding()?;
                println!("RELIABILITY_SYSTEM sleep_start={start:?} sleep_end={end:?} proven=true");
                return Ok(true);
            }
        }
        self.reader.verify_binding()?;
        println!("RELIABILITY_SYSTEM no new event proven: INCONCLUSIVE");
        Ok(false)
    }
}

/// Explicit invocation only. Prior matching synthetic digests are inputs, never
/// recreated as an accepted baseline here. Only the operator initiates sleep.
#[test]
#[ignore = "hardware: explicit prior reference and bounded waits; nonzero system wait requires a freshly ready operator"]
fn gpu_retained_hw_reliability_control() {
    use super::gpu_groundwork_tests::{
        hw_cpu_cascade, hw_selection, recognizer_bytes, report_hw_identity,
    };
    use crate::npu::gpu;
    let reference_path = std::env::var_os("IRLUME_GPU_RELIABILITY_REFERENCE")
        .expect("explicit reference file required");
    let attended = match std::env::var("IRLUME_GPU_RELIABILITY_ATTENDED") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("invalid attended intent: {error}"),
    };
    let config = read_reference(Path::new(&reference_path), attended.as_deref()).unwrap();
    let report = {
        let bytes = recognizer_bytes();
        let (mut cpu, _cascade) = hw_cpu_cascade();
        let mut platform =
            gpu::GpuPlatform::open_admitted(&hw_selection(), &gpu::Sources::default()).unwrap();
        report_hw_identity("retained reliability", platform.identity());
        assert_eq!(
            platform.identity().digest(),
            config.identity,
            "prior identity changed"
        );
        let reader = Reader::new(
            Path::new("/sys/class/drm"),
            Path::new("/proc/sys/kernel/random/boot_id"),
            &platform.identity().render_node,
        )
        .unwrap();
        let (mut model, assignment, _cache) = platform
            .compile_with_cache_observation(
                gpu::CacheMode::Disabled,
                gpu::CacheProvenance::Bypass,
                &bytes,
            )
            .unwrap();
        assert_eq!(assignment, "GPU.0");
        assert_eq!(
            cpu.cpu_reference_digest().unwrap(),
            config.cpu_reference,
            "prior CPU canary changed"
        );
        let references: [Reference; 4] = std::array::from_fn(|k| {
            let input = super::super::npu_reference::chip(k);
            let output = model.infer(&input).unwrap();
            assert_eq!(output.len(), crate::EMBED_DIM);
            assert!(output.iter().all(|v| v.is_finite()));
            let raw: Vec<_> = output.iter().flat_map(|v| v.to_le_bytes()).collect();
            assert_eq!(
                irlume_common::sha256_hex(&raw),
                config.gpu_bits[k],
                "prior input {k} changed"
            );
            Reference {
                input,
                bits: output.iter().map(|v| v.to_bits()).collect(),
            }
        });
        println!("RELIABILITY_SETUP recognizer_compiles=1 gpu_baseline_calls=4 counted_calls=0 cpu_fingerprint_calls=1 platform_identity_warmup=SEPARATE assignment={assignment} model_sha256={}", irlume_common::sha256_hex(&bytes));
        let mut observations = HardwareObservations {
            cpu: &mut cpu,
            platform: &platform,
            reader,
            config: &config,
            samples: std::array::from_fn(|_| None),
            runtime_clock: None,
            cpu_checks: 1,
        };
        let mut protocol = Protocol::new(model.as_mut(), &references, crate::EMBED_DIM).unwrap();
        match drive(&mut protocol, &mut observations) {
            Ok(report) => report,
            Err(error) => panic!(
                "RELIABILITY_REFUSED {error}; actual_counts={:?}; no qualification",
                protocol.report()
            ),
        }
    }; // Drop the original request, platform, CPU and cascade normally first.
    println!(
        "RELIABILITY_RESOURCES_DROPPED report={report:?} total={:?}",
        report.total()
    );
    // Hypothetical external teardown is used ONLY to inspect all other criteria.
    // The collector must still verify this exact process exits normally.
    println!(
        "RELIABILITY_COVERAGE_READY={} NORMAL_PROCESS_EXIT=PENDING certification=NOT_EVALUATED",
        report.accepted(true)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Infer,
        Boundary(Boundary),
        RuntimeStart,
        RuntimeEnd,
        System,
    }

    type Trace = Arc<Mutex<Vec<(Event, u64)>>>;

    struct TraceModel {
        trace: Trace,
        calls: u64,
    }

    impl crate::npu::Infer for TraceModel {
        fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String> {
            self.calls += 1;
            self.trace.lock().unwrap().push((Event::Infer, self.calls));
            Ok(input.to_vec())
        }
    }

    struct TraceObservations {
        trace: Trace,
        runtime: bool,
        system: bool,
        fail: Option<Event>,
    }

    impl TraceObservations {
        fn observe(&self, event: Event) -> Result<(), String> {
            let calls = self
                .trace
                .lock()
                .unwrap()
                .last()
                .map(|(_, n)| *n)
                .unwrap_or(0);
            self.trace.lock().unwrap().push((event, calls));
            if self.fail == Some(event) {
                Err("unavailable observation".into())
            } else {
                Ok(())
            }
        }
    }

    impl Observations for TraceObservations {
        fn boundary(&mut self, boundary: Boundary) -> Result<(), String> {
            self.observe(Event::Boundary(boundary))
        }
        fn runtime_start(&mut self) -> Result<(), String> {
            self.observe(Event::RuntimeStart)
        }
        fn runtime_end(&mut self) -> Result<bool, String> {
            self.observe(Event::RuntimeEnd)?;
            Ok(self.runtime)
        }
        fn system(&mut self) -> Result<bool, String> {
            self.observe(Event::System)?;
            Ok(self.system)
        }
    }

    fn simulate(
        runtime: bool,
        system: bool,
        fail: Option<Event>,
    ) -> (bool, Report, Vec<(Event, u64)>) {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut model = TraceModel {
            trace: Arc::clone(&trace),
            calls: 0,
        };
        let mut observations = TraceObservations {
            trace: Arc::clone(&trace),
            runtime,
            system,
            fail,
        };
        let references = [1.0_f32, 2.0, 3.0, 4.0].map(|value| Reference {
            input: vec![value],
            bits: vec![value.to_bits()],
        });
        let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
        let success = drive(&mut protocol, &mut observations).is_ok();
        let report = protocol.report();
        let events = trace.lock().unwrap().clone();
        (success, report, events)
    }

    #[test]
    fn driver_brackets_first_runtime_cycle_and_starts_system_evidence_after_700() {
        for (runtime, system) in [(true, true), (true, false), (false, true), (false, false)] {
            let (success, report, trace) = simulate(runtime, system, None);
            assert!(success);
            assert_eq!(report.total().gpu_fully_bit_checked_ok, 1000);
            assert_eq!(report.accepted(true), runtime && system);
            assert!(!report.accepted(false));
            let position = |event, count| trace.iter().position(|v| *v == (event, count)).unwrap();
            assert!(position(Event::Infer, 400) < position(Event::RuntimeStart, 400));
            assert!(position(Event::RuntimeStart, 400) < position(Event::Infer, 401));
            assert!(position(Event::Infer, 404) < position(Event::RuntimeEnd, 404));
            assert!(position(Event::RuntimeEnd, 404) < position(Event::Infer, 405));
            assert!(position(Event::Infer, 700) < position(Event::System, 700));
            assert!(position(Event::System, 700) < position(Event::Infer, 701));
            assert_eq!(
                trace
                    .iter()
                    .filter(|(event, _)| *event == Event::Infer)
                    .count(),
                1000
            );
        }
    }

    #[test]
    fn driver_does_not_resume_after_missing_observations_or_failed_boundaries() {
        for (failure, calls) in [
            (Event::RuntimeStart, 400),
            (Event::RuntimeEnd, 404),
            (Event::System, 700),
            (Event::Boundary(Boundary::Setup), 0),
            (Event::Boundary(Boundary::BeforeRuntime), 400),
            (Event::Boundary(Boundary::AfterRuntime), 404),
            (Event::Boundary(Boundary::BeforeSystem), 700),
            (Event::Boundary(Boundary::AfterSystem), 700),
            (Event::Boundary(Boundary::Final), 1000),
        ] {
            let (success, report, trace) = simulate(true, true, Some(failure));
            assert!(!success);
            assert_eq!(report.total().gpu_wrapper_attempted, calls);
            assert_eq!(report.total().gpu_fully_bit_checked_ok, calls);
            assert!(!report.accepted(true));
            assert_eq!(trace.last(), Some(&(failure, calls)));
        }
    }

    fn config(system_wait: u64) -> serde_json::Value {
        serde_json::json!({
            "identity": "a".repeat(64), "cpu_reference": "b".repeat(64),
            "gpu_bits": ["c".repeat(64), "d".repeat(64), "e".repeat(64), "f".repeat(64)],
            "runtime_wait_secs": 30, "system_wait_secs": system_wait,
        })
    }

    #[test]
    fn config_requires_prior_digests_bounded_waits_and_explicit_attended_intent() {
        let parsed = Config::parse(&config(0).to_string(), None).unwrap();
        assert_eq!(parsed.runtime_wait, Duration::from_secs(30));
        assert_eq!(parsed.system_wait, Duration::ZERO);
        assert!(Config::parse(&config(60).to_string(), None).is_err());
        assert!(Config::parse(&config(60).to_string(), Some("0")).is_err());
        assert!(Config::parse(&config(60).to_string(), Some("1")).is_ok());
        for field in [
            "identity",
            "cpu_reference",
            "gpu_bits",
            "runtime_wait_secs",
            "system_wait_secs",
        ] {
            let mut missing = config(0);
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                Config::parse(&missing.to_string(), Some("1")).is_err(),
                "{field}"
            );
        }
        for field in ["runtime_wait_secs", "system_wait_secs"] {
            for invalid in [
                serde_json::json!(-1),
                serde_json::json!(601),
                serde_json::json!(1.5),
                serde_json::json!("30"),
            ] {
                let mut input = config(0);
                input[field] = invalid;
                assert!(Config::parse(&input.to_string(), Some("1")).is_err());
            }
        }
        for hash in ["", "abc", &"G".repeat(64), &"A".repeat(64)] {
            let mut input = config(0);
            input["gpu_bits"][3] = serde_json::json!(hash);
            assert!(Config::parse(&input.to_string(), None).is_err());
        }
    }

    #[test]
    fn reference_read_bounds_actual_bytes_and_refuses_non_regular_or_malformed_input() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reference.json");
        assert!(read_reference(root.path(), None).is_err());
        assert!(read_reference(&path, None).is_err());
        let valid = config(0).to_string();
        std::fs::write(&path, &valid).unwrap();
        assert!(read_reference(&path, None).is_ok());
        std::fs::write(&path, format!("{valid}{}", " ".repeat(8193))).unwrap();
        assert!(read_reference(&path, None).is_err());
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_reference(&path, None).is_err());
        for invalid in ["[]", "{}", "null", "not JSON"] {
            std::fs::write(&path, invalid).unwrap();
            assert!(read_reference(&path, None).is_err());
        }
    }

    #[test]
    fn invalid_runtime_counters_are_errors_not_missing_coverage() {
        for error in [
            WitnessError::Counter,
            WitnessError::Binding,
            WitnessError::ReadOrder,
        ] {
            assert!(runtime_verdict(Err(error)).is_err());
        }
        for error in [
            WitnessError::Posture,
            WitnessError::NoSuspendedGrowth,
            WitnessError::SystemSleepNotExcluded,
        ] {
            assert_eq!(runtime_verdict(Err(error)), Ok(false));
        }
        assert_eq!(
            runtime_verdict(Ok(CounterGrowth {
                lower_ms: 1,
                upper_ms: 3
            })),
            Ok(true)
        );
    }

    #[test]
    fn fifo_reference_open_does_not_wait_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::process::{Command, Stdio};
        const CHILD: &str = "IRLUME_TEST_RETAINED_FIFO_CHILD";
        const TEST: &str = "onnx::gpu_tests::gpu_reliability_hardware_tests::tests::fifo_reference_open_does_not_wait_for_a_writer";
        if let Some(path) = std::env::var_os(CHILD) {
            let error = read_reference(Path::new(&path), None)
                .err()
                .expect("FIFO refused");
            assert_eq!(error, "reference is not a regular file");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reference.fifo");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a live NUL-terminated path in this test's private
        // directory; mkfifo reads it and creates only that fixture node.
        let created = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(created, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let timed_out = loop {
            match child.try_wait() {
                Ok(Some(_)) => break false,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(None) => {
                    let _ = child.kill();
                    break true;
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("fixture wait failed: {error}");
                }
            }
        };
        let output = child.wait_with_output().unwrap();
        assert!(
            !timed_out,
            "reference open blocked on a FIFO without a writer"
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("running 1 test") && stdout.contains("1 passed; 0 failed"),
            "{stdout}"
        );
    }

    #[test]
    fn retained_control_is_one_explicit_ignored_test_outside_the_ordinary_sweep() {
        let executable = std::env::current_exe().unwrap();
        let control =
            "onnx::gpu_tests::gpu_reliability_hardware_tests::gpu_retained_hw_reliability_control";
        assert!(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/NPU.md"))
                .contains(control)
        );
        let list = |args: &[&str]| {
            let output = std::process::Command::new(&executable)
                .args(args)
                .env_remove("IRLUME_GPU_RELIABILITY_REFERENCE")
                .env_remove("IRLUME_GPU_RELIABILITY_ATTENDED")
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            list(&["--list", "--ignored", "--exact", control]),
            [control]
        );
        let ordinary = list(&["--list", "--ignored", "gpu_hw_"]);
        assert_eq!(ordinary.len(), 5);
        assert!(!ordinary.iter().any(|v| v == control));
    }
}
