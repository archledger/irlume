# Head-Gesture-Only Software Verification

Date: 2026-08-19

## Result

The frozen head-gesture-only candidate passed the software, packaging, PAM,
and mixed-version gates in this report. No product defect was found and no
implementation fix was made.

The strict machine API run reported 36 passes, zero failures, and two skips.
The skipped `camera-diagnostics` and `support-report-json` capabilities are
newer than the conformance script and were not counted as passes.

## Frozen Candidate and Environment

All candidate verification preceded creation of this report. The worktree was
clean when frozen.

- Candidate commit: `948324169b64237f11fc1b0ec8e1aa8b5aef8b81`
- Candidate tree: `ee40ee3b446ed37567791a7da92eebd3ff5243af`
- Branch: `refactor/head-gesture-only`
- Comparison build: detached `origin/main` commit
  `f94ca363d3638712ad9d707a273f6236415e2a62`
- Host: Fedora Linux, kernel `7.1.8-200.fc44.x86_64`, x86-64
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Python: `3.14.6`
- Bash: `5.3.9(1)-release`
- Git: `2.55.0`
- PAM host dependencies: `/usr/bin/pamtester`,
  `/usr/lib64/libpam_wrapper.so`, and
  `/usr/lib64/pam_wrapper/pam_set_items.so`

The freeze commands and results were:

```text
git status --short --branch
```

Result: exit 0; only
`## refactor/head-gesture-only...origin/main [ahead 23]` was printed.

```text
git rev-parse HEAD
git rev-parse HEAD^{tree}
```

Result: exit 0; the commit and tree were the values above.

## Workspace Gates

```text
cargo fmt --all -- --check
```

Result: exit 0, no output.

```text
cargo clippy --workspace --all-targets -- -D warnings
```

Result: exit 0; the strict all-target workspace lint finished without a
warning.

```text
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Result: exit 0; rustdoc generated all workspace documentation with warnings
denied.

```text
cargo build --release --locked
```

Result: exit 0; the release profile finished in 1 minute 8 seconds.

```text
./scripts/run-tests-guarded.sh --min 650 -- cargo test --workspace --locked
```

Result: exit 0; 1,741 tests passed, zero selected tests failed, and the guard
confirmed the 650-test floor.

```text
git diff --check
```

Result: exit 0, no output.

### Ordinary-Lane Ignores

The exact inventory command was:

```text
cargo test --workspace --locked -- --ignored --list
```

Result: exit 0; it listed 88 ignored tests. They are intentionally outside the
ordinary workspace lane for these stated reasons:

- `irlume-auth`: 3 tests need configured v4l2loopback RGB and IR feeder nodes.
- `irlume-camera`: 26 tests need some combination of v4l2loopback feeder or
  spare nodes, real physical RGB/IR/UVC hardware, an operator-controlled UVC
  unbind/rebind, the Shinetech four-node camera, a drivable real IR emitter, or
  pre-created root-owned lock files.
- `irlume-cli`: 5 benchmark tests need ONNX models plus ONNX Runtime; 6 capture
  tests need configured v4l2loopback feeder nodes.
- `irlume-core`: 26 tests need a real TPM or `swtpm`, fresh signed-PCR or
  provisioned pcrlock artifacts, root-only durability/upgrade inputs, or
  deliberate envelope fault injection.
- `irlume-daemon`: 3 tests need configured v4l2loopback feeder nodes and 1
  needs `swtpm`; the shutdown integration test needs ONNX models plus ONNX
  Runtime to boot the daemon.
- `irlume-pam`: 16 tests need `pam_wrapper` plus `pamtester`. They were run
  explicitly below.
- `irlume-vision`: 1 test needs the packaged TFLite runtime and pinned mesh.

The ordinary lane did not count any ignored test toward its 1,741 passes.

## Machine API, Packaging, and Pure Hardware Harnesses

```text
python3 scripts/machine-api-conformance.py --irlume target/release/irlume --strict
```

Result: exit 0; 36 passed, 0 failed, 2 skipped. The script explicitly reported
that it does not know the newer `camera-diagnostics` and
`support-report-json` capabilities. Fixtures, the event-stream fixture,
contract negotiation, typed refusal cases, and every capability understood by
the script passed. There was no machine-contract stderr or host escalation.

```text
./scripts/check-packaging-parity.sh
```

Result: exit 0, `packaging parity: OK`. Helper programs, systemd units, model
installation, version `0.10.0`, ONNX Runtime `1.24.4`, and both AppArmor
executable-path variants agreed across their applicable packaging lanes.

```text
python3 scripts/hardware/test-run-slice4-hardware.py
```

Result: exit 0; 10 tests passed.

```text
python3 scripts/hardware/test-validate-slice4-hardware.py
```

Result: exit 0; 16 tests passed.

```text
bash -n scripts/hardware/run-slice4-hardware.sh
```

Result: exit 0, no output.

## PAM Wrapper Integration

The required command was first run inside the managed sandbox:

```text
./scripts/run-tests-guarded.sh --min 16 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
```

Result: exit 101. The 9 library tests passed, but all 16 `pamwrap` tests failed
before their PAM assertions because the sandbox denied temporary Unix socket
binding with `EPERM` at `pamwrap.rs:293` or `pamwrap.rs:318`. This was an
environment result, not a product-test result.

The identical command was rerun with host permission to bind its temporary
Unix sockets and execute `pamtester`:

```text
./scripts/run-tests-guarded.sh --min 16 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1
```

Result: exit 0; all 16 `pamwrap` tests passed serially, all 9 library tests
passed, and the guard counted 25 total passes. This includes
`pamwrap_polkit_shake_aborts_only_the_polkit_stack`, the non-polkit fallback
cases, migration prompting, typed-password behavior, and credential release.

## Mixed-Version Wire and Socket Evidence

The planned `/tmp/irlume-head-only-origin-main` and
`/tmp/irlume-old-target` paths were checked and did not exist. The comparison
revision and detached worktree were created with:

```text
git rev-parse origin/main
git worktree add --detach /tmp/irlume-head-only-origin-main origin/main
```

Result: exit 0; both resolved to detached commit
`f94ca363d3638712ad9d707a273f6236415e2a62`.

```text
CARGO_TARGET_DIR=/tmp/irlume-old-target cargo build --manifest-path /tmp/irlume-head-only-origin-main/Cargo.toml --release --locked -p irlume-cli -p irlume-daemon
```

Result: exit 0; the detached CLI and daemon release build finished in 1 minute
20 seconds.

The four release binaries were distinct and had these SHA-256 digests:

```text
d54e1909623aaad68e62e7773e10bb0c7b012a24c2e820face160a05207a6b46  target/release/irlume
37d37c043e5d9203c4334e015660ce9edbc26f783a4ec640bf19c3296fa44ec4  target/release/irlumed
fa11dd4f98af646acb474b7c0446cb3d20d33f09e12d4222b236610f0e016ce9  /tmp/irlume-old-target/release/irlume
7bf52f0cee6e6e1a9f261be9505f8eca1a5bddac0413f6a1ace1e66a76341b99  /tmp/irlume-old-target/release/irlumed
```

### Detached Client to Candidate Daemon

The candidate daemon was launched without system installation or binary swap:

```text
env IRLUME_SOCKET=/tmp/irlume-mixed-new-daemon/irlumed.sock IRLUME_STATE_DIR=/tmp/irlume-mixed-new-daemon/state IRLUME_CONFIG_DIR=/tmp/irlume-mixed-new-daemon/config IRLUME_DET_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/face_detection_yunet_2023mar.onnx IRLUME_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/glintr100.onnx IRLUME_IR_ADAPTER=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/does-not-exist.onnx IRLUME_MESH_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/face_landmarks_detector.tflite IRLUME_BLAZE_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/blaze_face_short_range.onnx target/release/irlumed
```

Result: the daemon bound the isolated socket, loaded the supplied shipped
models, and reported that it was serving. The missing adapter path deliberately
selected the supported raw-IR path. The host did not allow this unprivileged
process to inspect every camera consumer or open the system emitter lock, so it
reported those hardware-only limitations and made no emitter write through
that locked path. They did not affect the profile wire request.

The detached `origin/main` client was then run against that daemon:

```text
env IRLUME_SOCKET=/tmp/irlume-mixed-new-daemon/irlumed.sock IRLUME_STATE_DIR=/tmp/irlume-mixed-new-daemon/state IRLUME_CONFIG_DIR=/tmp/irlume-mixed-new-daemon/config /tmp/irlume-old-target/release/irlume profiles list --user wisbfime
```

Result: exit 0, `[profiles] none enrolled`. The daemon was then stopped with
Ctrl-C; exit 130 was the intentional teardown result after the successful
client exchange.

### Candidate Client to Detached Daemon

The detached `origin/main` daemon was launched against a second isolated root:

```text
env IRLUME_SOCKET=/tmp/irlume-mixed-old-daemon/irlumed.sock IRLUME_STATE_DIR=/tmp/irlume-mixed-old-daemon/state IRLUME_CONFIG_DIR=/tmp/irlume-mixed-old-daemon/config IRLUME_DET_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/face_detection_yunet_2023mar.onnx IRLUME_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/glintr100.onnx IRLUME_IR_ADAPTER=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/does-not-exist.onnx IRLUME_MESH_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/face_landmarks_detector.tflite IRLUME_BLAZE_MODEL=/home/wisbfime/irlume/.worktrees/head-gesture-only/models/blaze_face_short_range.onnx /tmp/irlume-old-target/release/irlumed
```

Result: the daemon bound the second isolated socket, loaded the supplied
models, and reported that it was serving. It reported the same unprivileged
hardware-only emitter limitations; they did not affect the wire request.

The candidate client was then run against that daemon:

```text
env IRLUME_SOCKET=/tmp/irlume-mixed-old-daemon/irlumed.sock IRLUME_STATE_DIR=/tmp/irlume-mixed-old-daemon/state IRLUME_CONFIG_DIR=/tmp/irlume-mixed-old-daemon/config target/release/irlume profiles list --user wisbfime
```

Result: exit 0, `[profiles] none enrolled`. The daemon was then stopped with
Ctrl-C; exit 130 was the intentional teardown result after the successful
client exchange.

No command installed, replaced, or invoked an Irlume binary under `/usr/bin`.

### Guarded Literal Compatibility Tests and Filter Substitution

The planned common filter existed and was guarded:

```text
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-common old_client --locked
```

Result: exit 0; 1 test passed:
`tests::an_old_client_request_defaults_to_prose_errors`.

The planned daemon filter did not exist. It was run under the guard so a zero
selection could not pass silently:

```text
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-daemon mixed_version --locked
```

Result: exit 1; zero tests passed and the guard rejected the selection. Current
test discovery found the literal compatibility tests below, so the absent
filter was not counted as a pass.

Each additional common compatibility test was run with an independent nonzero
guard:

```text
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-common an_old_daemon_ignores_the_new_request_field --locked
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-common enrollment_response_is_compatible_in_both_reader_directions --locked
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-common request_wire_compat_defaults_for_older_callers --locked
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-common retired_eye_requests_still_parse_as_tombstones --locked
```

Result: exit 0 for every command; each selected and passed exactly 1 test.

The first attempt to require all five common tests while running the whole
common package was:

```text
./scripts/run-tests-guarded.sh --require tests::an_old_client_request_defaults_to_prose_errors,tests::an_old_daemon_ignores_the_new_request_field,tests::enrollment_response_is_compatible_in_both_reader_directions,tests::request_wire_compat_defaults_for_older_callers,tests::retired_eye_requests_still_parse_as_tombstones --min 5 -- cargo test -p irlume-common --locked
```

Result: exit 101 in the managed sandbox. All five required compatibility tests
passed, along with 107 other tests, but 7 unrelated client socket tests failed
because the sandbox denied Unix socket operations with `EPERM`. The four
focused commands above plus the separately guarded `old_client` command avoid
that unrelated environment failure and prove all five required selections.

The current daemon substitutions were:

```text
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-daemon retired_eye_calibration_requests_keep_privilege_and_have_no_side_effects --locked
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-daemon retired_eye_tombstones_are_diagnostic_completed_not_failures --locked
```

Result: exit 0 for both commands; each selected and passed exactly 1 test.

The socket-serving substitution was first run in the managed sandbox:

```text
./scripts/run-tests-guarded.sh --min 1 -- cargo test -p irlume-daemon serve_records_eye_privilege_failures_and_tombstone_completion --locked
```

Result: exit 101 because its Unix socket setup received `EPERM` before the
assertion. The identical guarded command was rerun with host socket permission.
Result: exit 0; exactly 1 test passed and the guard confirmed it.

## Cleanup and Final State Before the Report

The detached worktree was clean and was removed through Git:

```text
git -C /tmp/irlume-head-only-origin-main status --short --branch
git -C /tmp/irlume-head-only-origin-main rev-parse HEAD
git worktree remove /tmp/irlume-head-only-origin-main
```

Result: exit 0; the detached worktree was clean at
`f94ca363d3638712ad9d707a273f6236415e2a62` and was removed.

The isolated build and runtime roots were removed with:

```text
cargo clean --target-dir /tmp/irlume-old-target
rm -r /tmp/irlume-mixed-new-daemon /tmp/irlume-mixed-old-daemon
```

Result: exit 0; Cargo removed 2,411 files and 656.5 MiB. A final existence
check found the detached worktree, isolated target, and both runtime roots
absent. The candidate worktree was still clean at the frozen commit and tree.

## Concerns

- The strict conformance program skips two advertised capabilities because its
  checker has no implementation for them. Those are explicit coverage gaps,
  not contract failures and not passes.
- Managed sandbox Unix socket policy caused the PAM and focused socket-test
  failures described above. Identical host-permission reruns passed. The full
  workspace gate had already passed before those focused sandbox reruns.
- Real camera, v4l2loopback, TPM, fault-injection, and packaged-runtime lanes
  remain outside this software-only task. Their exact ignore reasons are listed
  above; the hardware matrix is a separate verification task.
