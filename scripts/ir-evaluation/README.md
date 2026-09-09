# Attended IR-only evaluation harness

Developer tooling for the [qualification protocol](../../docs/IR_ONLY_QUALIFICATION.md).
It runs the existing **non-granting diagnostic**, never PAM or a login command.
Dual-camera authentication remains the default; optional IR-only login is not
implemented by this tool. A successful harness result means the recorded attempt
passed instrumentation and preservation checks, not that a sensor or policy is
qualified.

## Diagnostic report records

New diagnostic builds emit report schema 4. `identity_acceptance` is
`best_template`, `centroid`, or `both` when the final category is
`candidate_match`; every other category requires null. The label records which
existing finite-score identity predicates passed without exposing a score,
template, or identity. A final cancellation or expiry clears the label.
Instrumenting this decision makes empirical acceptance-arm coverage measurable;
it does not supply that coverage or qualify a device or policy.

`capture_stages_ms` contains the nine
schema-2 nullable millisecond fields (`open`, `session_setup`, `buffers`, `metadata`,
`emitter`, `warmup`, `rate_fill`, `frames`, `session_release`) plus six teardown
fields described below. The wrapper also accepts exact older schemas 1, 2 and 3;
unknown fields, labels and versions are refused.
The host configuration and wrapper ledger schemas remain 1.

Timing storage is fixed-size, request-local and enabled by the nondefault
`irlume-camera/capture-timing` feature, selected by `ir-only-evaluation`. Scope
timers record on ordinary errors and cancellation as well as success. Null means
the stage was not entered; zero can mean it completed within one millisecond.
There are no images, names, error messages, scores or device paths in these fields.

`session_setup` overlaps buffer allocation, metadata setup, emitter control,
warm-up and rate fill, and includes resource cleanup if setup fails. Do not add
overlapping times. `rate_fill` includes the subsequent metadata drain.
`session_release` measures explicit session destruction after a session was
successfully constructed, even if frame capture failed. On setup failure it
stays null because cleanup belongs to `session_setup`; it is not evidence that
cleanup was skipped. The outer `capture_ms` also includes the operation lease,
camera destruction and other work outside these spans. No individual driver-call
or optical emitter-off timing is claimed. A killed process may produce no report;
the external watchdog and trace checks remain necessary.

| Teardown field | Measured operation |
|---|---|
| `image_stop` | Release image buffers/stream, then stop the stream's lease state |
| `metadata_streamoff` | Metadata STREAMOFF call, when streaming |
| `metadata_buffers` | Unmap metadata buffers and request buffer release |
| `metadata_format` | Restore metadata format, when a different format was displaced |
| `metadata_close` | Close the metadata descriptor |
| `emitter_restore` | Explicit or destructor-triggered emitter backend restore call |

Timing handles attach to successfully constructed owners in the selected IR
session setup as each becomes available, before frame warm-up. Failed construction
cleanup before attachment remains inside the existing open/setup spans. Owner
teardown spans can also occur during privacy refusal or recovery, so they are
accumulated for the request and need not be contained solely in `session_release`.
Replacement owners created by an explicit session recovery do not receive these
handles; the one-shot IR evaluation does not invoke that recovery path.
Null means no instrumented call was entered, not that a resource was left open.
Timing a restore call does not establish that restoration succeeded. The emitter
span excludes subsequent backend destruction, including any backend-specific
fallback restore; unexplained session-release remainder needs investigation.

The new spans observe existing cleanup in place: they neither reorder owners nor
skip cleanup on cancellation, expiry or driver failure. They do not issue extra
camera calls. A timing-only handle does not carry cancellation into teardown.

Freeze the new executable and wrapper hashes in a separate plan and ledger before
using these records. Keep earlier attempts and their original budget. Investigate
an unexpected lifecycle category even when the wrapper reports `complete`.

## Supported scope

Linux with systemd, `/proc`, sysfs, Python 3.10+, `strace`, `fuser`, and a running
`irlumed.service`. The explicit IR image node must have index 0 and exactly one
index-1 metadata sibling on the same non-virtual interface; RGB must be a distinct
index-0 interface. Device names must be literal `/dev/videoN` paths. These checks
verify topology, not infrared spectral response or sensor authenticity: review
camera models, drivers and the binding before use. Other layouts are refused.

The reviewed diagnostic must use a single process with shared thread descriptor
tables. Successful process forks, descriptor-table unsharing, bulk closes or
video descriptor duplication invalidate the trace proof. This is deliberately
conservative. Do not remove checks to make an unfamiliar host pass; investigate
and review any extension. No Windows/ThinkPad, non-systemd or new sensor validation
is implied by offline tests or by this laptop's camera-free preflight.

## Prepare a private host configuration

Follow the protocol to freeze source/patch identity, models, thresholds, sampling,
normal-light schedule, strata and numerical acceptance targets **before** trials.
No numerical release targets have been adopted by this harness. Schema 4 records
which identity acceptance predicates passed for each admitted candidate, but the
instrumentation does not compute certification or population confidence claims.
Use a separate ledger per frozen host/configuration
and stratum, with anonymous attempt IDs mapped to the predeclared schedule. A
`qualification` label is descriptive and cannot turn pilot results into evidence.

Build the reviewed diagnostic without changing default features:

```sh
cargo build --release --locked -p irlume-auth \
  --features ir-only-evaluation --example ir_only_evaluation
python3 -m unittest discover -s scripts/ir-evaluation -p 'test_*.py'
```

Review the three Python modules and exact executable/model/runtime hashes before
root execution. This tool is **not a sandbox for an untrusted executable or model**.
It pins the selected files; the OS, Python, tracer and transitive shared libraries
remain trusted dependencies whose versions belong in the campaign record.

Copy the three modules (`runner.py`, `host.py`, `harness.py`) and reviewed diagnostic
to an administrator-owned directory such as `/opt/irlume-ir-evaluation`, using
root ownership and modes 0644 for modules / 0500 for the executable. Every component
and symlink hop in tool, asset, configuration and output paths must be root-owned
and not group/world-writable. Do not execute a user-writable checkout as root.
Create a **new** root-owned mode-0700 output directory for this campaign and a
root-owned mode-0600 JSON configuration. Keep configuration out of shared reports.

Example **shape only**; replace every placeholder and confirm the camera mapping.
The tool rejects incomplete hashes. Paths and the subject UID are private inputs
and are not copied into results.

```json
{
  "schema": 1,
  "subject_uid": 1000,
  "budget_ms": 5000,
  "watchdog_seconds": 15,
  "assets": {
    "binary": {"path": "/opt/irlume-ir-evaluation/diagnostic", "sha256": "REVIEWED_SHA256"},
    "detector": {"path": "/usr/share/irlume/models/face_detection_yunet_2023mar.onnx", "sha256": "REVIEWED_SHA256"},
    "recognizer": {"path": "/usr/share/irlume/models/glintr100.onnx", "sha256": "REVIEWED_SHA256"},
    "flir": {"path": "/usr/share/irlume/models/flir.onnx", "sha256": "REVIEWED_SHA256"},
    "ort": {"path": "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so", "sha256": "REVIEWED_SHA256"}
  },
  "cameras": {"rgb": "/dev/video0", "ir": "/dev/video2", "metadata": "/dev/video3"},
  "protected_files": ["/usr/bin/irlumed", "/usr/bin/irlume", "/etc/pam.d/irlume-retry-reset"],
  "service": "irlumed.service"
}
```

Add an `adapter` asset with `path` and `sha256` only when the reviewed enrollment
requires it. Choose the local enrolled account's UID explicitly; 1000 is not a
discovery rule. Choose the diagnostic budget (100–30000 ms) and a longer startup
watchdog (at most 120 seconds) during campaign planning, not after a result.

`protected_files` must be the reviewed set of **public installed binaries and
configuration** whose preservation the campaign claims. The example is not a
complete system manifest. Include the actual PAM module, service configuration,
policy and camera configuration where applicable; only existing regular files
or trusted links to them are supported. Never list enrollment/template stores,
password files, credentials or recovery data. The tool hashes only this declared
scope and public assets. Read-only enrollment behavior is a separate audited
contract of the diagnostic. Service PID/state/restart count, process credentials,
capabilities, NoNewPrivs, seccomp, LSM context, SELinux enforcement state where
available, and camera topology are compared in memory before/after. Preservation
does not prove the initial security configuration is appropriate; review it first.

The host snapshot also compares the active LSM list. A kernel with only
`capability`, `landlock`, `lockdown`, `yama` and/or `bpf` may report `EINVAL`
for the process-context read without supplying a process label, as observed on
the reviewed Minihost configuration. The wrapper records a distinct absent-context
state in memory only for that restricted module set and exact error. Unknown modules, label providers such as SELinux or
AppArmor, other read errors, and changes to the list/context still fail the
preservation check. This is not a claim of SELinux/AppArmor enforcement on a host
where they are inactive. See the [Linux LSM hook defaults](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h)
and [LSM framework](https://github.com/torvalds/linux/blob/master/security/security.c).

## Run one scheduled attempt

From a local terminal, using the reviewed root-owned files:

```sh
sudo /usr/bin/python3 -E -s /opt/irlume-ir-evaluation/runner.py \
  --config /opt/irlume-ir-evaluation/host.json \
  --output /var/lib/irlume-ir-evaluation/pilot-01 \
  --attempt control-01 --campaign pilot --mode preflight
```

Preflight loads models and reads enrollment but opens no camera. Every subsequent
invocation also repeats this camera-free check and checks host preservation.
For a scheduled live attempt, choose `genuine`, `impostor`, `attack`, `empty` or
`cancel`, and a new anonymous attempt ID. `empty` and `cancel` are lifecycle controls.
For example, the operator can replace the final line with:

```sh
  --attempt genuine-01 --campaign pilot --mode genuine
```

The participant must be ready **now**, other camera apps closed, and only the
scheduled presentation in view. The tool requires an interactive terminal and
an explicit `READY` response, then prints `START`. It runs one scan and prints
`FINISHED`; positioning is no longer required. There is no unattended readiness
flag and no automatic retry loop. `cancel` sends a cancellation byte after the
first successful IR image open. Ctrl-C requests supervisor cleanup and records
an interrupted attempt. No frames or scores are saved.

Exit 0 means instrumentation/preservation completed; the category can still be a
refusal or an infrastructure error. Exit 1 means stop and review the result.
Exit 2 means setup or ledger could not complete; inspect for a started record
before doing anything else. An attack, impostor or empty-view `candidate_match`,
invalid/granting output, unexpected video access, missing close, watchdog cleanup,
or changed/unverifiable protected state stops the campaign ledger. There is no
force-continue option. Preserve the stopped ledger, investigate, and document
review before starting a separate follow-up ledger. Never delete failed attempts
to obtain a passing campaign.

## Read the ledger correctly

Each attempt directory is reserved exclusively, then `started.json` is flushed
before the first diagnostic invocation. `final.json` is written exclusively and
flushed after cleanup and preservation checks. Incomplete directories, malformed
final records and stopped outcomes block subsequent invocations in that ledger.
A host-wide `/run/irlume-ir-evaluation.lock` prevents simultaneous harness runs.
Root-owned mode-0700 temporary executable stages under `/run` are removed on normal
completion. The small lock file remains for reuse until reboot.

The ledger retains only fixed categories/flags, public asset hashes, bounded
stage timings and video open/close metadata. It never retains diagnostic stderr,
non-video trace paths, account names or raw exceptions. `preflight` and `evaluation`
are separate fields, **not two accuracy trials**. Count each started accuracy
invocation once; a preflight error, declined readiness or missing final record
still needs explicit accounting as a failed/incomplete attempt. Planned attempts
never invoked are separately not started. A completed `no_face` is not a PAD
refusal. Follow the protocol's all-started and assessment-only denominators;
`evaluation: null` means no report was retained and does not prove that capture
never started; preserve it as failed/unknown. Controls are separate. Stage timings exclude startup; wall time includes tracing
and model loading but not all host verification/readiness time.

Video opens are paired once with a successful close of the same descriptor and
device, with no outstanding descriptors, then `fuser` must show all video nodes
idle. Tracing failures and ambiguous process/descriptor behavior fail the proof.
Trace timestamps describe syscall entries; descriptor closure is not a measurement
of the physical emitter switching off. The watchdog performs process-group TERM
then KILL cleanup. SIGKILL, power loss, an uninterruptible kernel operation or a
process escaping its group cannot be turned into guaranteed cleanup by Python;
a missing final record requires review and the idle check must independently pass.
Only the reviewed diagnostic is supported, not arbitrary programs.

Relevant primary references: [strace descriptor decoding](https://strace.io/),
[Python subprocess lifecycle and timeout limits](https://docs.python.org/3/library/subprocess.html),
and [Linux V4L2 device opening/closing](https://docs.kernel.org/userspace-api/media/v4l/open.html).

### Optional syscall timing

Add `--trace-ioctl` to a separately frozen diagnostic campaign to record numeric
video ioctl request numbers, results, and microsecond durations. This uses
`strace -T -e raw=ioctl`: argument structures are never decoded, and raw lines,
pointers, errors, and non-video operations are discarded. Only descriptors
observed opening a `/dev/videoN` node are associated with these records; closed
descriptors are removed. Existing trace ambiguity and overflow gates still apply.
The default trace remains unchanged. No authentication or capture behavior changes.

Interpret request numbers against the measured host's ABI and headers. These
wall-clock syscall durations include tracing and scheduling effects; they cannot
prove physical emitter-off timing or distinguish kernel internals. An image-stop
span also includes unmapping and local bookkeeping, which ioctl tracing does not
measure. A successful instrumented run is evidence preservation, not an accuracy
qualification or a guaranteed hard deadline.
