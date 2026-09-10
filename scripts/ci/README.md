# Restricted nightly IR capture

`irlume-ci-capture.py` is an administrator-installed helper for a self-hosted
runner without general sudo. The workflow uses it when
`/usr/local/libexec/irlume-ci-capture` exists. Otherwise it uses the existing
noninteractive-sudo capture route. Both paths require exactly one positive emitter proof, the minimum frame
count and brightness-spread gates.

The helper accepts exactly the checked-out Git source-tree ID and IR device. It
runs a separately approved, root-owned capture ELF for six frames, with a clean
environment and a 45-second timeout. It executes the same inode whose SHA256 it
verified. Capture files stay in a root-private temporary directory, are streamed
as a bounded archive into the workflow's temporary directory, and are removed
by both sides' cleanup. It accepts no command, executable path, output path,
frame count or environment overrides. The helper does not grant authentication
or return enrolled biometric data.

## Two positive outcomes

The trace-enabled capture emits one of two exact diagnostic lines:

- `irlume: capture emitter write completed`: this capture actually changed the
  emitter control. Existing configured and known-device write paths keep this
  requirement; a failed write or `AlreadyHeld` cannot use the default proof.
- `irlume: capture emitter device default verified`: no write action was planned,
  recovery was checked without a restore write, and the open camera advertised
  a Microsoft Face Authentication control whose current value equals its own
  validated D1 default. The capability/default validator is shared with setup;
  a second current-value read rejects a change during validation. The capture
  retains its stream lock but owns no control change to restore.

The default path makes only control reads and exists only with emitter tracing
requested. It does not alter normal authentication behavior, save a config,
replay a payload, or manufacture a write. Missing, partial, repeated or mixed
positive markers fail. Both outcomes still require frame delivery and brightness
spread. These checks establish reported control state, frame delivery, and a non-flat
brightness range;
they do not establish that a host write caused an optical change. In particular,
BRIO may operate in D1 by default while NexiGo requires an actual transition.

The control contract is [Microsoft UVC Face Authentication](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5#2226-face-authentication-control).
Do not infer default readiness from VID:PID, successful face unlock, absence of
errors, an already-held non-default value, or brightness alone.

## Installation and approval

Installation is an administrator operation, separate from a runner job. Do not
promote an existing runner-owned executable by merely copying and hashing it.
Build `cargo build --locked -p irlume-camera --example burst_dump` from the exact
reviewed source tree in a trusted build environment, record the toolchain and
build result, and verify that tree against the approved signed commit. Verify
the ELF interpreter, DT_NEEDED, RPATH/RUNPATH and the target host's resolved
libraries; no loader/search path or dependency may be runner-writable. The
source tree must match the checkout that the hardware workflow will test. A
merge with the identical tree can reuse approval; a changed tree cannot.

Install the following paths with root ownership and no group/other write access:

| Path | Mode | Content |
|---|---|---|
| `/usr/local/libexec/irlume-ci-capture` | `0755` | Exact reviewed helper; preserve its `python3 -I` shebang |
| `/usr/local/lib/irlume-ci` | `0755` | Approved-artifact directory |
| `/usr/local/lib/irlume-ci/burst_dump` | `0755` | Trusted capture ELF |
| `/usr/local/lib/irlume-ci/capture.json` | `0644` | Manifest below |
| `/var/lib/irlume-ci` | `0700` | Private temporary capture storage |

Every ancestor must be a real root-owned directory without group/other write
access. The helper refuses symlinks, unsafe ownership/modes, mismatched tree,
wrong device or changed executable digest before capture.

Manifest (replace placeholders with verified values):

```json
{"schema": 1, "source_tree": "<40-character Git tree ID>", "sha256": "<64-character ELF SHA256>", "device": "/dev/video2"}
```

For the verified Archhost runner account `ghrunner`, the only required sudoers
command rule is:

```sudoers
ghrunner ALL=(root) NOPASSWD: /usr/local/libexec/irlume-ci-capture
```

The helper itself validates its two arguments. Do not grant `env`, a shell,
`SETENV`, a runner-writable binary, or `ALL`. Keep `env_reset` enabled. Stage the
rule privately, validate it with `visudo -cf`, install it root-owned `0440`, and
validate the complete sudo policy. Confirm ordinary `sudo -n true` and an
unapproved helper source tree remain denied. Do not change runner labels to
conceal a missing privilege prerequisite.

## Qualification and maintenance

Run `test-irlume-ci-capture.py` and `../test-nightly-ir-capture.py` without root;
they do not operate hardware. Before deployment, also exercise actual root
execution with a synthetic ELF in an isolated root-owned staging directory:
valid capture/archive, environment isolation, rejected tree/device, writable or
changed ELF, missing marker, symlink output, insufficient frames, timeout and
cleanup. These integration fixtures must never use a physical camera.

After installing an approved artifact, perform a separately authorized bounded
hardware check and verify camera release and product-daemon health. Fixture
success is not physical-camera acceptance. The normal nightly remains restricted
to main and covers the complete build, tests, real TPM, camera and coverage flow.
The helper's executable is an independently built artifact of that exact source
tree; it is not claimed to be byte-identical to the runner's local build.

A new source tree intentionally requires a new trusted build and administrator
promotion. Prepare the new ELF and manifest together, keep the previous pair,
and verify the new pair before enabling it. A mismatched pair fails closed.
Do not silently approve whatever the runner has built to make CI green.

Before initial installation, retain a root-private manifest of created paths and
any pre-existing files. Rollback removes only the newly introduced sudoers rule
and helper/artifact paths after identity checks, or restores the previous
approved pair. It does not change product packages, enrollment, PAM, runner
services or runner labels. Keep failed qualification evidence and report the
remaining hardware gate accurately.


## Nightly coverage prerequisites

The coverage job prepares its own `cargo-llvm-cov` **0.9.1** using
`setup-coverage-tools.sh` before model fetch or loopback-camera producers start.
It builds with `cargo install --locked` into a unique directory under
`RUNNER_TEMP`, verifies the installed version, and exports its absolute path as
`IRLUME_COVERAGE_BIN`. Every coverage lane invokes that program directly so a
missing or older runner-user installation cannot change the tool used. The
runner cleans the temporary directory after the job; setup requires no sudo and
does not replace tools in the runner's Cargo home.

Both eligible runners use distribution Rust. Setup locates system `llvm-cov`
and `llvm-profdata`, checks that their LLVM major versions match `rustc -vV`,
and exports `LLVM_COV` and `LLVM_PROFDATA`. Missing tools, an incompatible LLVM,
a failed install, or an unexpected coverage-tool version fails setup before
any test capture. The version check is a prerequisite check; actual profile
compatibility and the existing 75% line floor are still verified by coverage.
See the [pinned tool's upstream environment contract](https://github.com/taiki-e/cargo-llvm-cov/tree/v0.9.1#environment-variables).

`python3 scripts/ci/test-setup-coverage-tools.py` exercises fresh and previously
provisioned runners, incompatible/missing LLVM, failed installation and wrong
tool versions using executable fixtures. It neither installs real tools nor
opens hardware. For a version update, also run a real tiny instrumented Rust
test and `report --summary-only --fail-under-lines 75` as each runner account
with the exact new setup, before qualifying the full nightly again. Keep the
shared capability selectors, named-test guards and coverage threshold intact.
