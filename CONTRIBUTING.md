# Contributing to irlume

Thanks for your interest. irlume is **GPL-3.0-or-later** and intends to stay
fully open source forever. There is **no CLA** and no commercial relicensing;
your contributions remain under the same copyleft terms everyone else enjoys.

Ways to help, in rough order of usefulness right now:

- **Hardware reports** from laptops and webcams with IR sensors, working or
  not. These feed [`docs/HARDWARE.md`](docs/HARDWARE.md), which is generated
  from measured evidence, and they shape which capture paths get fixed next.
  Use the *Hardware report* issue template.
- **Bug reports** with daemon journal excerpts (`journalctl -u irlumed`,
  timestamps, camera model, distro and package). Use the *Bug report* issue
  template; the more of its fields you fill, the faster the triage.
- **Code and docs**: fixes, tests, and documentation improvements, following
  the ground rules below.
- **Packaging**: the Fedora, Arch, Debian/PPA, and Nix lanes live under
  `packaging/` and `nix/`; distro-specific fixes are welcome there.
- **Questions and triage**: the
  [discussions](https://github.com/archledger/irlume/discussions) area is the
  place for setup questions and design talk; answering other people's
  questions there is a real contribution.

How the project is run (who merges, how releases are signed and published) is
documented in [`GOVERNANCE.md`](GOVERNANCE.md).

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/) instead of a CLA. It's a
lightweight statement that you wrote (or have the right to submit) the code you
contribute. Just sign off your commits:

```sh
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line. By signing off
you certify the DCO. That's it: no forms, no rights assignment.

The check wants **exactly one** `Signed-off-by` trailer per commit. If you
rebase or cherry-pick and the trailer gets duplicated, the build fails until it
is back to one; `git commit --amend -s --no-edit` fixes a missing one.

## Pull request process

- PRs merge as a **single squash commit** back to `main`, with a
  `type: description (#number)` subject (`feat:`, `fix:`, `docs:`, and so on).
  You do not need to squash your branch yourself; review happens on your
  commits, the squash happens at merge.
- **First PR from a fork**: GitHub holds a fork's workflows (CI, CodeQL, DCO)
  in *action required* until a maintainer approves them to run. If the checks
  panel looks empty a few minutes after opening, that is why; it is not a
  problem with your PR, and no action is needed from you.
- CI runs on every push and PR: `cargo fmt --check`, `cargo clippy -D
  warnings`, build, workspace tests on Rust 1.88, `test (stable)`, cargo-deny
  (advisories, licenses, duplicate versions), the fuzz corpus, systemd unit
  verification, and the DCO check, plus CodeQL and the nix flake check. A green
  local `cargo fmt` / `cargo clippy` / `cargo test` means a green CI.
- Fill in the PR template. The checkboxes are the same gates CI and review
  will apply, including hardware validation for anything touching PAM, the
  daemon, or capture.

## Ground rules for a security project

- **Never commit biometric data**: no captured frames, embeddings, or
  templates, even as test fixtures. Use synthetic or your own clearly-consented
  data, kept out of the repo. This applies to issue attachments too: excerpt
  the journal line you need, never a raw capture or a template file.
- **Keep the model BOM permissive.** Any new model must be clean at all three
  layers (code, weights, training data). No InsightFace buffalo_l/antelopev2 or
  other non-commercial weights; they conflict with GPL.
- **Tests are required for new functionality.** Major new functionality must
  land with automated tests for it in the same PR, added to the `cargo test`
  suite (or, for parser-facing code, the fuzz corpus). A PR that adds
  behavior without tests for that behavior will not be merged; the exception
  is code that only runs against physical hardware, which gets an `#[ignore]`
  test plus a written validation note instead.
- **Liveness/PAD changes** should come with a self-test against the relevant
  ISO/IEC 30107-3 attack class: run `IRLUME_DEV=1 irlume padcapture` /
  `padreport` and
  include the per-species APCER/BPCER numbers. See
  [`docs/PAD_SELFTEST.md`](docs/PAD_SELFTEST.md) for the methodology and protocol.
- **A pull request from a fork is not CodeQL-scanned before merge.** GitHub's
  default setup for code scanning does not analyse fork pull requests, so an
  external contribution reaches review with the ordinary CI behind it (clippy as
  `-D warnings`, cargo-deny, the fuzz corpus, zizmor and actionlint over
  workflows) but without CodeQL. Measured on this repo: of the last 30 merged
  pull requests, the 29 from repo branches each ran CodeQL and the one from a
  fork ran none. main is analysed straight after the merge, so the code is
  scanned, later than a maintainer would want. A maintainer who wants CodeQL on
  a fork contribution first can push the branch into this repository and open
  the pull request from there, which is the same shape as every scanned PR.
- Run `cargo fmt`, `cargo clippy`, and `cargo test` before opening a PR; CI
  runs the same checks (`cargo fmt --check`, `cargo clippy -D warnings`, build,
  test on Rust 1.88) on every push and PR, so a green local run means a green CI.
  The codebase is rustfmt-formatted (default style); the bulk-format commit is
  in `.git-blame-ignore-revs`, so run `git config blame.ignoreRevsFile
  .git-blame-ignore-revs` once to keep `git blame` meaningful.

## Changes that touch cameras, PAM, or the daemon

Authentication behavior cannot be judged from code alone, so changes to
capture, PAM integration, or the daemon's auth path get validated on real
hardware before merging, on the maintainer's test machines. You cannot run
that gate yourself and are not expected to. What helps review move fast:

- Say what you tested, on what hardware (camera model, RGB-only or rgb+ir,
  distro and package version), and what happened, including relevant
  `journalctl -u irlumed` lines.
- A change that adds or reclassifies a PAM service should name where the
  service ships (the distro, greeter, or lock screen that creates the
  `/etc/pam.d/` file); classifications are sourced, not guessed.
- Design-level changes to security posture (grant arms, consent flow, rate
  limiting, fallbacks) usually need an ADR; sketching one in the PR description
  early saves a round trip. Existing examples live in
  [`docs/adr/`](docs/adr/).

## Writing style

Plain punctuation only: no em dashes anywhere in docs, commits, issues, or PR
text. Use commas, periods, or parentheses instead. Match the tone of the
existing documentation pages: concrete, terse, numbers over adjectives.

## Reporting security issues

Do not open a public issue for anything security-sensitive. Follow
[`SECURITY.md`](SECURITY.md); private reporting is enabled on the repository.

## Conduct

By participating you agree to the [code of conduct](CODE_OF_CONDUCT.md). Be
aware that this is a biometrics project: treat other people's face data with
the same rules as your own (see the ground rules above).

## Setting up a dev environment

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full walkthrough. The
quickest path is Nix: `nix develop` gives you the whole pinned toolchain
(Rust, libclang, TPM/PAM libs, the ONNX runtime) on any distro with one
command; the guide also lists the per-distro `dnf`/`apt`/`pacman` dependencies
if you'd rather install them by hand. Note the models are fetched from a
release (`bash scripts/fetch-models.sh`), and real face/camera/TPM/PAM testing
needs a physical machine.

## Where to start

Look for `todo!()` / `TODO` markers in the code. A good first smoke test of a
working dev setup is the alignment self-test:
`IRLUME_DEV=1 irlume selftest align --model models/glintr100.onnx`
(dev/benchmark subcommands are gated behind `IRLUME_DEV=1`). Issues labeled
*good first issue* are picked to be self-contained.
