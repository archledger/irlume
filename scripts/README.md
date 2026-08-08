# scripts/

Grouped by **who runs them**, because that is what decides whether a path can
move. Anything CI, a packaging lane, or a user calls stays at the top level:
`run-tests-guarded.sh` has about 40 references and `fetch-models.sh` about 30,
and **`install.sh`'s URL is published** in the README and on the Copr and PPA
pages, so it must never move.

## Release and packaging

| Script | What it does |
|---|---|
| `install.sh` | The one-step installer users run via a published `curl` URL. Detects the distro, installs from Copr, the PPA, the AUR or a checksum-verified `.deb`, and wires nothing into PAM. |
| `install-host.sh` | Installs a locally built checkout onto this host: binaries and the systemd unit only. For developers, not users. |
| `fetch-models.sh` | Fetches the ONNX weights from the `models-v1` release and verifies each sha256. Replaces `git lfs pull`; every packaging lane calls it before building. |
| `build-ppa-source.sh` | Builds the Ubuntu PPA **source** package. Launchpad's builders have no network, so the orig tarball carries vendored crates and the bundled runtime. |
| `verify-ppa-publish.py` | Waits until a PPA upload is actually installable. `dput` saying "Successfully uploaded" only means Launchpad accepted it; build and publication happen after, and fail silently. |
| `build-tflite-runtime.sh` | Builds the bundled TFLite C runtime from a pinned TensorFlow tag. Google publishes no stable Linux C-API artifact. |
| `build-tflite-runtime-container.sh` | Runs the above inside `ubuntu:22.04`, the oldest system the universal `.deb` advertises, so the glibc and libstdc++ floors hold. |

## Checks that CI runs

| Script | What it does |
|---|---|
| `run-tests-guarded.sh` | Runs a test command and fails if it selected no tests. `cargo test <name>` exits 0 when the filter matches nothing, which reads as a pass. |
| `check-packaging-parity.sh` | Every systemd unit and AppArmor rule must ship in every lane, and every lane must agree on the version. |
| `check-action-pins.sh` | Enforces SHA-pinning on every GitHub Action, with one documented exception for the SLSA provenance generator. |
| `ir-node-from-doctor.sh` | Names the IR capture node from `irlume doctor` output, so the nightly hardware suite can point `burst_dump` at it. Separates "no camera" from "no IR camera" from "this no longer parses", which the inline version it replaces could not. `--self-test` runs on every PR. |
| `machine-api-conformance.py` | Checks a build answers contract 1 the way `docs/MACHINE-API.md` says. Written for consumers, so it needs only Python 3 and an irlume binary. |
| `capture-machine-fixtures.py` | Regenerates `schemas/fixtures/` from a real engine, so consumers develop against documents irlume actually emitted. |

## Diagnosing one machine

Run by a maintainer against a specific box, usually while chasing a report.

| Script | What it does |
|---|---|
| `diagnose-missing-camera.sh` | Read-only evidence collection for a camera that stopped appearing after irlume wrote to its UVC extension units (#159). Changes nothing. |
| `gkr-token-check.sh` | Proves the GNOME keyring token handoff against a real `gnome-keyring-daemon` without touching the caller's own login keyring. |
| `kwallet-handoff-check.sh` | Proves a key irlume derives opens a wallet a real `ksecretd` guards, handed over by the helper irlume ships. |
| `login-transaction-container-test.sh` | Exercises `login apply` / `verify` / `rollback` against a throwaway PAM tree in a container. |
| `tpm-pcr-race-swtpm.sh` | Reproduces `TPM2_RC_PCR_CHANGED` in a software TPM and proves the retry rescues it. |
| `timing-report.py` | Summarises camera capture timings from daemon debug logs. |
| `deploy-keyring-unlock.sh` | Stages a rebuilt daemon, PAM module and CLI onto a test box, with the SELinux policy the greeter needs. |
| `deploy-passive-ear.sh` | Stages the passive-EAR liveness build and wires the FaceMesh model into the daemon unit. |

## `hardware/`: manual procedures that need a real camera

Run by hand on a machine with the hardware. Nothing automated calls them.

| Script | What it does |
|---|---|
| `emitter-journal-hardware-test.sh` | Hardware validation for the IR emitter undo record (#181). |
| `emitter-journal-container-test.sh` | The same undo record against a throwaway state directory, no camera needed. |
| `emitter-journal-strace-test.sh` | Proves from syscalls that the undo record is durable **before** the camera is written to. |
| `emitter-journal-powerloss-test.sh` | Does the record survive a real power loss? Uses `sysrq-trigger` for an immediate reboot: no sync, no unmount. |
| `emitter-journal-portmove-1-leave-record.sh` | Stage 1: leave an unresolved undo record at one USB port. |
| `emitter-journal-portmove-2-at-other-port.sh` | Stage 2: same camera at a different path. Byte-for-byte what a *second unit* of the same model looks like, which is the case that must be refused. |
| `emitter-journal-portmove-3-back-home.sh` | Stage 3: back at the original address, where the promise made in stage 2 must be honoured. |
| `emitter-journal-two-cameras-test.sh` | Two IR cameras on one machine: does either one's setup destroy the other's undo data? |
| `emitter-override-per-stream-test.sh` | Does an `IRLUME_IR_EMITTER` override reach the camera on every stream, or only the first after a daemon start? (#168) |
| `emitter-selfclear-test.sh` | Does a control set once before streaming stay set for a whole capture window? (#168) |
| `emitter-stream-record-hardware-test.sh` | The per-stream emitter record, on real hardware. |

## `research/`: the instruments behind the published numbers

Each is referenced from the write-up whose figures it produced, so start from the
document in `docs/pad-results/` or `docs/recognition-results/`, not from here.

| Script | What it does |
|---|---|
| `analyze-landmark-relief.py` | Recomputes every number in the landmark-relief report from the corpus, so an edited figure fails. |
| `check-occluder-report.py` | The same idea for the occluder report, whose corpora the script above cannot consume. |
| `landmark-relief-corpus.py` | Derives the committed corpus from landmark CSVs. The raw frames are infrared images of the operator's face and are deliberately not committed. |
| `compare-blaze-parity.py` | The fail-closed parity gate for the full-range BlazeFace decoder against Google's own runtime. |
| `mp-face-detector-bench.py` | Runs Google's MediaPipe FaceDetector over the stage-3 corpus, so no hand-rolled decode can flatter itself. |
| `capture-stage3-segment.sh` | Captures one stage-3 corpus segment: positioning lead-in, then paired RGB and IR frames. |
| `blinkcap-campaign.sh` | Records one labelled IR `EarSample` sequence per invocation, for the consent-gesture dataset. |
