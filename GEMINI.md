# Working agreement for AI agents in the irlume repo

irlume is a from-scratch Rust IR face-authentication system for Linux (a PAM
module `pam_irlume`, a daemon `irlumed`, a CLI `irlume`, and a TUI). GPL-3.0.
It secures login, sudo, screen unlock, and polkit app prompts, so correctness
and honesty about limits matter more than speed.

## Scope and limits (non-negotiable)

- **Never push to the remote, create tags, or publish releases.** `main` is a
  protected branch (pull request required, status checks required, linear
  history). Work only on a local feature branch. Signing and publishing are done
  by a human and the primary agent, not here.
- **Default to read-only.** For research and code review, read and report; do
  not edit. Only write code when explicitly asked, and then on a branch.
- **Treat your output as a pull request from a new contributor**, not as ground
  truth: it gets reviewed and must pass the gates below before it can merge.

## Before any change is considered done

- `cargo fmt --check` clean.
- `cargo clippy --all-targets -- -D warnings` clean (CI runs exactly this).
- `cargo test --workspace` passing.
- The coverage ratchet floor holds (CI: `cargo llvm-cov ... --fail-under-lines`,
  currently 76). Do not lower it without a written reason in the CI comment.
- Container-first testing: validate in a disposable container (podman, swtpm for
  TPM paths) before any hardware test. Watch the actual actions, not just exit
  codes.

## Commits

- End every commit message with a `Signed-off-by: archledger
  <archledger236@gmail.com>` trailer.
- Keep messages concrete: what changed, why, and how it was verified.

## Coding standards

- Deep modules over line-count dogma: a simple interface over real work beats
  many thin pass-through layers.
- Every non-obvious block carries a why-comment (the reason, not a restatement
  of the code).
- Parse, don't validate: turn untrusted input into a typed value at the boundary
  and pass the typed value inward.
- Typed errors, not stringly-typed control flow. Fail closed on the auth paths:
  any error, timeout, or malformed response must fall back to the password,
  never grant.
- No cleverness for its own sake. Match the surrounding code's idioms, naming,
  and comment density.

## Writing (prose, comments, docs, commit messages)

- No em dashes anywhere, including code comments. Use a semicolon, comma,
  parentheses, or restructure.
- No unsourced statistics, no intensifiers ("significantly", "dramatically"),
  no filler ("it's important to note", "when it comes to"), no AI-tell verbs
  ("leverage", "utilize", "delve", "streamline", "underscore").
- Every claim ends on a concrete, checkable detail or gets cut. Do not oversell
  what the code does; state the limit plainly (this is a security tool).

## Good uses here

Research across the codebase, a second-opinion review of a diff or a subsystem,
adversarial checks on security and liveness paths, and ongoing coding assistance
on a branch. When in doubt about a security or PAM change, prefer to flag it for
human review rather than apply it.
