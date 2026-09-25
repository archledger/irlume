# AGENTS.md

irlume is face and fingerprint authentication for Linux, in Rust: a privileged
daemon (`irlumed`), a CLI and TUI (`irlume`), a PAM module (`pam_irlume.so`), a
KDE System Settings module and TPM-sealed keyring unlock. It is pre-1.0 and
GPL-3.0-or-later, with one maintainer who decides what merges and ships
([GOVERNANCE.md](GOVERNANCE.md)). Three things must never break: authentication
correctness (no grant without a genuine live match), the password fallback (it
always works) and the privacy of biometric data. If a task seems to need any of
them weakened, stop and ask.

This file guides coding agents and the people who run them. It condenses
[CONTRIBUTING.md](CONTRIBUTING.md) and the docs it links; each rule names its
source. Where prose and code disagree, trust `Cargo.toml`, `ci.yml` and the
code, and say so in the PR. `ADR-NNNN` means `docs/adr/NNNN-*.md`. Nested
`AGENTS.md` files (crates `irlume-common`, `-daemon`, `-cli`, `-pam`, and
`docs/adr`) add rules for their area and never relax these.

## Repository map

| Path | What it is | Start at |
|---|---|---|
| `crates/irlume-common` | Wire types (`Request`, `Response`), socket client, config. Depends on no other irlume crate. | [its AGENTS.md](crates/irlume-common/AGENTS.md), [docs/SETUP.md](docs/SETUP.md) |
| `crates/irlume-camera` | V4L2/UVC capture, IR emitter, device pinning, inventory. | `src/lib.rs`; ADR-0007, 0023, 0024, 0028, 0029 |
| `crates/irlume-vision`, `-liveness` | Detection, alignment, embedding; liveness cues and PAD. | ADR-0013, ADR-0019, [docs/PAD_SELFTEST.md](docs/PAD_SELFTEST.md) |
| `crates/irlume-core` | Encrypted templates, TPM sealing, keyring and recovery envelopes. | ADR-0025, [docs/SECURITY_AT_REST.md](docs/SECURITY_AT_REST.md) |
| `crates/irlume-auth` | The `Engine`: the only place a grant is decided. | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) "Authentication flow" |
| `crates/irlume-daemon` | `irlumed`: socket, per-request authorization, the single worker. | [its AGENTS.md](crates/irlume-daemon/AGENTS.md) |
| `crates/irlume-pam` | `pam_irlume.so`, a thin socket client. | [its AGENTS.md](crates/irlume-pam/AGENTS.md) |
| `crates/irlume-cli` | `irlume`: CLI, TUI, `--json` API, PAM wiring (`src/pamwire.rs`). | [its AGENTS.md](crates/irlume-cli/AGENTS.md), [docs/TUI.md](docs/TUI.md), [docs/MACHINE-API.md](docs/MACHINE-API.md) |
| other `crates/` | libexec helpers (`gkr-unlock`, `kwallet-init`, `password-verify`) and the fprintd wrapper. | [crates/README.md](crates/README.md) |
| `docs/adr/` | Architecture decision records. | [its AGENTS.md](docs/adr/AGENTS.md) |
| `kcm/` | KDE module (C++/QML, CMake): read-only, launches the TUI. | [docs/KCM.md](docs/KCM.md) |
| `fuzz/` | Separate nightly cargo-fuzz workspace with its own `Cargo.lock`. | `fuzz_targets/`, `seeds/` |
| `packaging/`, `nix/` | Distro and Nix lanes, systemd units, AppArmor, SELinux, polkit. | [packaging/README.md](packaging/README.md) |
| `schemas/`, `models/` | Machine API schema and fixtures; model hashes and BOM. | [models/README.md](models/README.md) |

Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); terms: [CONTEXT.md](CONTEXT.md).
The main TUI, camera, daemon and auth files run 16k to 24k lines: search, do not read them whole.

## Setup

- `nix develop` pins Rust 1.88.0, libclang, tpm2-tss, linux-pam and ONNX Runtime
  1.28.1 (sets `ORT_DYLIB_PATH`), but has no pamtester, pam_wrapper, swtpm or
  bubblewrap. Distro packages: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md); the
  full Ubuntu list is `ci.yml` "Install system build dependencies".
- The CLI's fixed-path root-probe tests exec `/usr/bin/bwrap` (Ubuntu 24.04:
  `bash scripts/ci-bubblewrap.sh --check`); its other black-box tests do not.
  Without pamtester and pam_wrapper most PAM end-to-end tests pass vacuously
  and the COSMIC ones fail ([the PAM AGENTS.md](crates/irlume-pam/AGENTS.md)).
- There is no `rust-toolchain` file. Outside Nix, run fmt, clippy and doc as
  `cargo +1.88.0 ...`; a newer clippy reports lints CI does not.
- `bash scripts/fetch-models.sh` fetches and verifies the weights (about 614 MB)
  into `models/`; without them the engine-backed tests fail with `engine load`.
- Point `ORT_DYLIB_PATH` at a `libonnxruntime.so` (1.24 or newer) unpacked
  outside the repo (its tarball is not git-ignored). Without it tests fail with
  a load error, but the `irlume-auth` examples hang.

## Gate commands

The required "fmt · clippy · build · test" job (`.github/workflows/ci.yml`) runs
these in order among other steps, then the swtpm, v4l2loopback, pam_wrapper and
shared-greeter lanes. Run all of these plus the matching rows below.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked -p irlume-auth -p irlume-camera --features irlume-auth/ir-only-evaluation --all-targets -- -D warnings
cargo test --locked -p irlume-auth --features ir-only-evaluation --lib --examples
cargo test --locked -p irlume-camera --features capture-timing --lib
RUSTDOCFLAGS="-D warnings" cargo doc --locked -p irlume-auth -p irlume-camera --features irlume-auth/ir-only-evaluation --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo build --release --locked
./scripts/run-tests-guarded.sh --min 650 -- cargo test --workspace --locked
```

| When you touch | Also run |
|---|---|
| `irlume-vision` features | `for f in cuda openvino coreml tensorrt; do cargo check -p irlume-vision --features "$f" --locked; done; cargo check -p irlume-vision --all-features --locked` |
| `--json` output, `schemas/` | `python3 scripts/test-machine-api-conformance.py && python3 scripts/machine-api-conformance.py --irlume target/release/irlume --strict` (needs python3 `jsonschema`) |
| `scripts/ir-evaluation/` | `python3 -m unittest discover -s scripts/ir-evaluation -p 'test_*.py'` |
| `packaging/`, versions, `docs/hardware/` | `bash scripts/check-packaging-parity.sh` |
| systemd units | `systemd-analyze verify packaging/systemd/<unit>` for each changed unit (CI first stubs `/usr/bin/irlumed` and `/usr/bin/irlume` with `/bin/true` when absent), then `systemd-analyze security --offline=true --threshold=37 packaging/systemd/irlumed.service` (94 for `irlume-reconcile.service`) |
| dependencies | `cargo deny check advisories bans licenses sources`, `cargo deny --manifest-path fuzz/Cargo.toml check advisories` (`audit.yml` scans the fuzz lockfile) and `(cd fuzz && cargo fetch --locked)` |
| fuzzed parsers | in `fuzz/`: `mkdir -p corpus/<t> && cp -n seeds/<t>/* corpus/<t>/`, then `cargo +nightly-2026-07-15 fuzz run <t> -- -max_total_time=45 -rss_limit_mb=4096` (targets in `fuzz/fuzz_targets/`) |
| `.github/workflows/` | `bash scripts/check-action-pins.sh`; also use `persist-credentials: false`, least-privilege `permissions`, and pass untrusted values through `env:`; never interpolate an untrusted `${{ }}` expression inside `run:` (`workflow-audit.yml`) |
| `flake.nix`, `nix/` | `nix flake check --no-build --show-trace` and `nix build .#default --no-link --print-out-paths --show-trace`; after a dependency or fork bump also `nix build --no-link .#default.cargoDeps .#onnxruntime-bin` |
| `kcm/` | `cmake -S kcm -B target/kcm-build -DBUILD_TESTING=ON && cmake --build target/kcm-build` |
| `crates/irlume-pam` | the commands in [its AGENTS.md](crates/irlume-pam/AGENTS.md) |

## Testing

- Test the changed crate first (`cargo test --locked -p <crate>`), then run the
  gate. Judge a run by its `test result:` and `run-tests-guarded:` lines;
  passing negative-path tests print `FAILED` text on stderr.
- New behavior gets tests in the same PR, a defect fix a regression test, a
  fuzzed parser a seed in `fuzz/seeds/<target>/`, hardware-only code an
  `#[ignore = "..."]` test plus a validation note ([CONTRIBUTING.md](CONTRIBUTING.md)
  "Ground rules for a security project", [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md)).
- Tests never touch real system paths: use DEVELOPMENT.md "Sandbox environment
  overrides" under the crate's env lock (common `testenv::lock()`; core, camera,
  cli `crate::testenv::ENV_LOCK`; auth `tests::ENV_LOCK`; daemon `env_lock()`).
- TPM tests (`#[ignore]`) need swtpm and `IRLUME_TCTI=swtpm:host=127.0.0.1,port=2321`
  (DEVELOPMENT.md); without it they use the host TPM (`/dev/tpm0`, `/dev/tpmrm0`),
  where `evict_persistent_srk_*` evicts persistent SRKs. `loopback_*` tests need
  ffmpeg-fed v4l2loopback nodes (root to load the module) and the `IRLUME_TEST_*`
  variables in `ci.yml`. CI runs both lanes for every PR; `hardware-checks.yml`
  and `hardware-suite.yml` run only on maintainer machines. Say in the PR what
  you could not run.
- CI selects ignored tests by prefix (`loopback_`, `bench_`, `tpm_`, `pinned_`,
  `shared_greeter_real_daemon`), exact `--require` name or whole target
  (`irlume-pam`, `irlume-daemon --test shutdown`) in `ci.yml` and the hardware
  workflows. Any other ignored test never runs; renaming a selected one breaks
  its lane, so update every workflow naming it (`grep -rn <name> .github/workflows`).
- A test that passes alone but fails in the full run shares process state (an
  unlocked env variable, a thread that outlived its guard, a process-wide
  cache). Compare `-- <name> --exact` with the full run and `--test-threads=1`,
  then fix the isolation; never serialize a workflow or `#[ignore]` the test.
- Source-shape tests read source text, so renames can fail them:
  `crates/irlume-auth/tests/no_probe_on_the_auth_path.rs`, `crates/irlume-cli/tests/camera_authority.rs`,
  the daemon's `include_str!` scan, text pins in `crates/irlume-pam/src/lib.rs`.

## Conventions

- Every `.rs` file opens with `// SPDX-License-Identifier: GPL-3.0-or-later`
  then `// Copyright the irlume contributors.` Edition 2021, MSRV 1.88
  (`Cargo.toml`): no let-chains; code builds on 1.88.0 and stable. rustfmt
  default style; rustdoc runs with `-D warnings`, so broken doc links fail.
- Workspace lints (`Cargo.toml` `[workspace.lints.clippy]`; new crates set
  `[lints] workspace = true`) fail CI: public fallible or panicking functions
  document `# Errors` and `# Panics`; every `unsafe` block has a `// SAFETY:`
  comment. Old debt carries `#[expect(clippy::<lint>, reason = "doc backlog")]`,
  on the function for `missing_errors_doc` and `missing_panics_doc`, on the
  single unsafe expression (never its function) for `undocumented_unsafe_blocks`
  (`Cargo.toml` comment). New code documents instead; delete an expectation when
  you document its site (an unfulfilled one fails). Prefer `#[expect]` to `#[allow]`.
- Use [CONTEXT.md](CONTEXT.md) terms ("capture schedule", not "camera mode").
  Head gestures are removed ([docs/HEAD-GESTURE-REMOVAL.md](docs/HEAD-GESTURE-REMOVAL.md));
  IR-only login is experimental opt-in ([docs/IR_ONLY_QUALIFICATION.md](docs/IR_ONLY_QUALIFICATION.md)).
- Writing (comments, docs, commits, PRs): plain punctuation, no em dashes
  (U+2014), concrete and terse, numbers over adjectives
  ([CONTRIBUTING.md](CONTRIBUTING.md) "Writing style"). Check with
  `grep -nP '\x{2014}' <files>`; older files still have some.

## Invariants that are easy to break

1. **Password fallback.** Any error, timeout, no-match, panic or unavailable
   daemon makes the PAM module return `PAM_IGNORE`, never `PAM_SUCCESS` or
   `PAM_AUTH_ERR`. Its two deliberate `PAM_ABORT` paths are listed in
   [the PAM AGENTS.md](crates/irlume-pam/AGENTS.md); keep them and add no other
   ([SECURITY.md](SECURITY.md) "Threat model (summary)", `crates/irlume-pam/src/lib.rs`).
2. **One decider.** Only `irlume-auth` decides a grant; shims stay thin; no
   binary links another binary's crate ([crates/README.md](crates/README.md)).
3. **Privilege split.** `irlumed` alone owns camera, IR emitter, models,
   templates and TPM, through one serialized worker. Clients hold no secrets and
   never open a camera. `SO_PEERCRED` is checked per connection. Only two
   root-only requests release a sealed secret, never `Authenticate`:
   `UnsealPassword` after a live face match, and `UnsealKeyring` (login
   password, KDE wallet key or GNOME keyring token) without one, for the
   fingerprint path, gated on a login or unlock service (ADR-0003,
   `crates/irlume-common/src/lib.rs`; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
   "Privilege separation", "Authentication flow").
4. **Posture and wire.** Every `Request` variant has an explicit arm, with no
   wildcard, in the daemon's posture tables. Socket changes stay additive, as
   old and new binaries meet during upgrades (daemon AGENTS.md). `--json` is a
   public contract ([docs/MACHINE-API.md](docs/MACHINE-API.md)).
5. **Fail closed.** A missing or failed required PAD model is a
   password-fallback denial, never a spoof (ADR-0019). An unreadable or
   malformed security setting reads as the safe default (ADR-0018). PAD cues are
   deny-only: Live to Spoof, nothing else (ADR-0013).
6. **Privileged intent.** At privileged prompts (sudo, su, doas, polkit) only a
   hidden `yes` authorizes one face attempt (ASCII, at most 16 bytes, compared
   after trimming whitespace and ignoring case, so ` YES ` counts), other
   non-empty input stays the password, and empty Enter never starts the camera
   (ADR-0010, ADR-0011),
   unless the owner set `privileged_face_consent=0`, which the daemon re-checks
   (ADR-0018). Greeter and lock stacks arm on an empty Enter. Mixed versions
   fail closed (ADR-0010).
7. **Enrollment.** Templates change only by explicit enrollment (ADR-0017); one
   face is one profile (ADR-0005); the third-party model lane stays removed
   (ADR-0015). One template-key unseal per request, borrowed as `&[u8]`, never
   an owned copy (ADR-0025).
8. **Cameras.** `verify_pinned` runs first in every capture; the virtual-camera
   escape is exact-path and test-only (THREAT_MODEL.md "Camera trust: device
   pinning"). The capture-mode probe never runs during authentication
   (ADR-0007). The decision is delivered before the stream is released (ADR-0027).
9. **Retry ceiling.** 50 per account; errors and cancellations keep their
   charge; mode switches never clear it (THREAT_MODEL.md "Intent, throttling,
   and privilege elevation").
10. **Pinned forks.** `pamsm` and `tss-esapi` are pinned by commit (`rev`) in
    the root `Cargo.toml` `[patch.crates-io]`, never by branch or tag (ADR-0012).
    `fuzz/Cargo.toml` repeats the tss-esapi patch by branch, frozen by
    `fuzz/Cargo.lock`; a fork bump updates both lockfiles and `nix/package.nix` `outputHashes`.

## Security and privacy

- Never commit biometric data (frames, embeddings, templates), even as fixtures,
  or attach it to issues. Never add model weights to git: they come from the
  `models-v1` release, pinned in `models/SHA256SUMS` (the tracked
  `face_landmarks_detector.tflite` is the one exception). A new model is
  permissive in code, weights and training data ([CONTRIBUTING.md](CONTRIBUTING.md)
  "Ground rules for a security project", [models/README.md](models/README.md)).
- No score, threshold value or similarity in UI text, unprivileged replies or
  the attempt record; nothing biometric in logs. Journal deny lines go through
  `deny_score` (one decimal) and `deny_reason` (numbers stripped), exact only
  under `IRLUME_LOG=debug`; grant lines log the score to the root-only journal.
  Matching never exits early (ADR-0030 section 5, THREAT_MODEL.md "Side channels").
- Secrets stay in `SecretBytes` or `Zeroizing`, never logged. State files are
  0600 root in 0700 directories (`packaging/tmpfiles.d/irlume.conf`); no face
  image is stored ([docs/SECURITY_AT_REST.md](docs/SECURITY_AT_REST.md)). Device
  text goes through `journal_safe`, `printable` or `camera_display_name`;
  support reports stay share-safe (ADR-0008).
- New dependencies: crates.io only, a `deny.toml`-allowed license, an audit
  note in the PR ([docs/CODE_REVIEW.md](docs/CODE_REVIEW.md));
  `advisories.ignore` stays empty. Commit `Cargo.lock`, and `fuzz/Cargo.lock`
  when common, core or camera change.
- Vulnerabilities go only to GitHub Private Vulnerability Reporting or the
  address in [SECURITY.md](SECURITY.md). If you find one, stop and tell the human,
  who files it; describe it nowhere public (issue, PR, commit, branch name,
  CHANGELOG, public fork).

## Commits and pull requests

- One change per PR; self-review against [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md).
  Weakening a guarantee (votes, budgets, modes, authorization posture) needs an
  ADR (CODE_REVIEW.md); other security-posture changes (grant arms, consent, rate
  limits, fallbacks) usually do, so sketch one in the PR early
  ([CONTRIBUTING.md](CONTRIBUTING.md) "Changes that touch cameras, PAM, or the daemon").
- Subject `type(scope): summary`, e.g. `fix(config): safe writes (ADR-0029 B1)`;
  types `fix feat docs perf ci test deps chore refactor bench build` (`git log`).
  The PR title, or a lone commit's subject, becomes the squash subject; GitHub
  appends `(#N)`. Body: a short paragraph, then `- ` bullets wrapped near 72
  columns; every commit message lands in the squash.
- **AI attribution (maintainer decision).** Commits carry no AI co-author
  trailers and no "Generated with" lines; the commit message ends with exactly
  one human `Signed-off-by` (the DCO check wants exactly one). The PR
  description says briefly whether and how an AI tool helped, so reviewers know
  where to look harder. The human contributor is responsible for every line
  under their sign-off.
  - Never add `Co-authored-by`, `Assisted-by`, `Generated with` or a second
    `Signed-off-by`, even if your tool does by default; the sign-off names the
    human, never an agent or bot. Commit with `git commit -s`
    (`git commit --amend -s --no-edit` adds a missing one).
  - `<upstream>` is the archledger/irlume remote (`origin` in a clone; in a fork
    `git remote add upstream https://github.com/archledger/irlume.git`). Before
    pushing, `git fetch <upstream>`; then `git log --format='%h %s%n%(trailers:only=true)' <upstream>/main..`
    shows exactly one `Signed-off-by: Name <email>` per commit (what `dco.yml`
    counts), and `git log --format=%B <upstream>/main.. | grep -inE 'co-authored-by|assisted-by|generated with'` prints nothing.
- PR description: fill in [the template](.github/pull_request_template.md).
  Under Testing list the commands run with results, new test names and what you
  could not run; never tick an unverified box ("Hardware-validated" only for
  hardware you name). PAM, daemon or capture changes add camera model, RGB-only
  or RGB+IR, distro, package and `journalctl -u irlumed` lines. Add the AI line,
  e.g. "AI assistance: a coding agent drafted the parser and tests; I reviewed
  every line and ran the gate." Describe the final change, not the session. A
  fork's first PR waits for workflow approval (CONTRIBUTING.md "Pull request process").
- User-facing changes add a CHANGELOG entry under `## [Unreleased]`, in the
  existing `### Added` or `### Fixed`, newest first: one `- ` bullet, a blank line
  between bullets, two-space continuation indent, present tense, ADR section and
  issue cited (`(ADR-0029 B1)`, `#797`).
- Update by rebasing (`git fetch <upstream> && git rebase <upstream>/main`,
  rerun the gate, `git push --force-with-lease`), not merging: it keeps every
  commit signed off and the squash free of merge commits. A rebase or
  cherry-pick can duplicate `Signed-off-by`; recheck. Merging needs the seven
  required checks at the top of `ci.yml` on the final head ([docs/CODE_REVIEW.md](docs/CODE_REVIEW.md))
  and every review conversation resolved (branch protection on `main`). Answer
  automated review comments like a person's: fix, or say why not.

## Agents must not

- Bump versions, create tags, or sign or publish releases
  ([GOVERNANCE.md](GOVERNANCE.md), [docs/RELEASING.md](docs/RELEASING.md));
  the `git commit -s` sign-off is still required.
- Push, open or merge PRs, or post comments, unless the human asked.
- Weaken, skip or delete a test to get green, `#[ignore]` a failing test, lower
  a `--min` floor or raise an exposure threshold.
- Hand-edit `docs/HARDWARE.md` (generated from `docs/hardware/fleet-evidence.json`
  by `scripts/generate-hardware-matrix.py`) or `schemas/fixtures/` (re-captured
  from an installed daemon before a release by `scripts/capture-machine-fixtures.py`).
- Move a top-level `scripts/` file (`install.sh`'s URL is published;
  [scripts/README.md](scripts/README.md)), or rename a required CI job or a
  `tui --page` slug the KCM uses.
- Change the host: `/etc/pam.d`, `/etc/irlume`, `/var/lib/irlume`, installed
  units, the real TPM. A broken PAM stack locks its owner out.
- Commit secrets, biometric data, weights, build output, tool state, or
  rustflags such as `target-cpu=native` in `.cargo/config.toml`.
- Add tool-specific agent instruction files (shared guidance goes in an
  `AGENTS.md`), or edit `AGENTS.md` files unless that is the task.
