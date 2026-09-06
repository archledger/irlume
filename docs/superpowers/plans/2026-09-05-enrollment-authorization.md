# Enrollment Authorization Implementation Plan

> For agentic workers: use superpowers:executing-plans inline. No subagents.

**Goal:** Authorize every non-root Enroll and AddScan before enrollment mutation.
**Architecture:** One private polkit adapter on connection threads, a single-use worker grant, and the existing exhaustive request posture table. Preserve transactional replacement.
**Tech stack:** Rust 2021, MSRV 1.88, polkit D-Bus; dbus 0.9.12 with system libdbus. Inspection rejected the bundled libdbus 1.14.4; distro-managed libraries receive normal system security updates.
**Spec:** ../specs/2026-09-05-enrollment-authorization.md

## Global constraints

- Root retains administrative authority; owner check remains mandatory.
- OS authorization may use configured factors. No password-only claim.
- Approval 60 seconds; queue freshness 15 seconds; worker budget 300 seconds.
- No subagents, em dashes, installed policy changes or biometric artifacts.
- Inference and benchmarks only on archhost.

## Task 1: Compose and establish baseline

- [x] Create feat/enrollment-authorization at 8bf99653 and apply exact saved replacement.patch, preserving original worktree.
- [x] Run `cargo test --locked -p irlume-daemon pregate_` and retain receipt.
- [x] Add connection regression: an owner Enroll/AddScan with an exited peer must receive Error before arbiter submission. Execute against baseline and observe a behavioral failure.

## Task 2: Authorize before queue and consume before mutation

Files: crates/irlume-daemon/src/enrollment_authorization.rs, main.rs, Cargo.toml, Cargo.lock.

- [x] Add `EnrollmentEffect::AddsTrust` in exhaustive posture table, retaining invalidation for both mutation variants.
- [x] Private interface: `authorize(req: &Request, peer: &Peer, stream: &UnixStream) -> Result<Option<Grant>, String>`; root and other requests return None. `Grant::consume(self, req: &Request, peer: &Peer) -> Result<(), String>` validates binding, live process, mapping and age.
- [x] Pin /proc peer directory; read stat/start-time and all UID fields through openat; reject gone, zombie, changed or mismatched subjects.
- [x] Send CheckAuthorization over a dedicated system-bus connection; poll reply and client lifetime with a bounded deadline; send CancelCheckAuthorization on cancellation and disconnect the connection.
- [x] RAII pending slots enforce one approval per UID and eight globally. No camera/key locks or detached threads while authenticating.
- [x] Add grant to Queued. Actual worker dispatch consumes it before cache invalidation. Missing grant denies trust-adding non-root requests, including direct dispatch tests.
- [x] Run regression green; add positive/negative grant, expiry, identity, capacity, D-Bus wire/reply and real socket/arbiter tests with fake authority only at external D-Bus boundary. Source review confirms approval precedes arbiter admission and key/camera locks; actual polkit-to-Irlume PAM reentry remains a deployment validation item.

## Task 3: Clients, packaging and confinement

Files: crates/irlume-cli/src/main.rs, tui.rs; packaging/polkit/org.irlume.enroll.policy; Arch/Fedora/Debian/ppa/Nix/source install/uninstall manifests; both AppArmor profiles; docs/SETUP.md and COMMANDS.md.

- [x] Set enrollment-specific client wait to 380 seconds and explain OS approval before capture; retain all other request budgets.
- [x] Install non-retained auth_self action for all session classes. Add polkit runtime dependencies and source-install guidance.
- [x] Permit scoped process stat/status and system-bus authority access in both AppArmor profiles. Keep systemd sandbox unchanged; inspect SELinux integration.
- [x] Run real disposable Debian policy installation/pkaction/no-agent challenge and AppArmor parser, existing packaging parity and CLI/common suites. Full package builds, runtime confinement and old/new installed-client matrix remain unperformed.

## Task 4: Verify and hand off

- [x] Run formatter, workspace all-target Clippy and warnings-denied rustdoc, focused software tests, and actual applicable packaging checks. Keep failures and corrections in receipts.
- [x] Review final diff against every spec invariant, including cancellation, worker authorization, transactional replacement and no secret logging. Correct defects with regression evidence.
- [x] Save exact patch/hash, source state, results and limitations. Refresh shared memory after material changes. No publication, deployment or live camera trial is part of this implementation turn.

## Validation outcome

Local common 125 passed; CLI/TUI 595 passed with 11 existing ignored; focused authorization 5 and posture 2 passed. Archhost daemon suite 158 passed, 0 failed, 4 existing ignored. Workspace all-target Clippy, warnings-denied rustdoc, Rust 1.88 all-target check, formatter, offline dependency bans/licenses, packaging parity and x86_64 Nix evaluation passed. The installed archhost daemon remained active with PID 1778 and zero restarts throughout the successful run. Exact remote scratch was removed.

This is an uncommitted implementation candidate. A real desktop/terminal approval and cancellation trial, polkit PAM reentry, runtime confinement and full distribution package builds remain unverified. The adapter measures a 60-second deadline and bounds D-Bus reply waits; the trusted system-bus connection setup uses the binding's blocking connect API. No hard timeout on that syscall was demonstrated. These limits must accompany review and deployment decisions.
