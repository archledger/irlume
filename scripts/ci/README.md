# Restricted nightly IR capture

`irlume-ci-capture.py` is an administrator-installed helper for a self-hosted
runner without general sudo. The workflow uses it when
`/usr/local/libexec/irlume-ci-capture` exists. Otherwise it uses the existing
noninteractive-sudo capture route. Both paths retain the emitter-write marker,
minimum frame count and brightness-spread gates.

The helper accepts exactly the checked-out Git source-tree ID and IR device. It
runs a separately approved, root-owned capture ELF for six frames, with a clean
environment and a 45-second timeout. It executes the same inode whose SHA256 it
verified. Capture files stay in a root-private temporary directory, are streamed
as a bounded archive into the workflow's temporary directory, and are removed
by both sides' cleanup. It accepts no command, executable path, output path,
frame count or environment overrides. The helper does not grant authentication
or return enrolled biometric data.

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
