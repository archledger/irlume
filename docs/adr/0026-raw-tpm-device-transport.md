# ADR-0026: Talk to the TPM through the raw device, with the resource manager as fallback

## Status

Accepted 2026-09-22 (proposed and implemented the same day). Motivated by
the `enrollment_load` measurements in issue #797 after ADR-0025 removed the
redundant unseals: one unseal per request remained, and it cost 1.5 s on
the archhost reference machine.

Changes no sealing policy, no PCR binding and no key handling; ADR-0025's
one-unseal-per-request invariant and the Tier 1/2/3 policies are untouched.

## Context

irlume opens a fresh ESAPI context for every TPM conversation (`tpm.rs`
`open_context`), runs the commands of one seal or unseal, flushes what it
loaded, and drops the context. The transport was `device:/dev/tpmrm0`, the
kernel's TPM resource manager, overridable with `IRLUME_TCTI`.

A Tier 1 (`PolicyAuthorize` over systemd-signed PCR 11) unseal is fourteen
TPM commands: SRK probe, `Load` of the sealed object, `StartAuthSession`
(salted against the SRK), `PolicyPCR`, `PolicyGetDigest`, `LoadExternal` of
the signing key, `VerifySignature`, `PolicyAuthorize`, `Unseal`, and flushes.
Profiled command by command on archhost (AMD firmware TPM, `0x414D4400`,
firmware `0x3005E`) with a throwaway object sealed under the real systemd key
and the real signature file (evidence: `artifacts/irlume/2026-09-22-tpm-unseal-profile/`
on the shared ledger):

| transport | Tier 1 unseal | Tier 3 literal-PCR unseal |
|---|---|---|
| `/dev/tpmrm0` (kernel resource manager) | **1470 ms** | 644 ms |
| `/dev/tpm0` (raw device) | **82 ms** | 72 ms |

The 1470 ms matches the traced `enrollment_load` stage (1484–1519 ms across
every attended attempt of #797) to within the disk read of the envelope.

The chip is not slow. The resource manager is doing what it must to let
several spaces share a chip with a handful of slots: after every command it
`ContextSave`s and flushes every session and transient object the command
touched, and `ContextLoad`s them again before the next one. On this firmware
TPM each of those round trips costs 40–90 ms, and a fourteen-command
conversation with one session and one or two objects in flight makes about
twenty of them. The laptop's Intel PTT shows the same shape at a smaller
scale (142 ms via the manager, 65 ms raw, literal tier).

Keeping objects resident across requests makes it worse under the manager,
not better: with more handles in flight every command pays more save/load
pairs (measured 910 ms per unseal with the sealed object, the signing key and
the verification ticket resident, against 1470 ms cold). Caching the
verification ticket alone (bytes the TPM issued, no secret) saves ~450 ms and
would still leave ~800 ms. Neither reaches the raw figure.

`/dev/tpm0` is exclusive-open: one process at a time, EBUSY for the rest. The
kernel serializes every command on the chip mutex, and a resource-manager
command is prepared, transmitted and committed under that same lock, so a raw
user's commands interleave only between whole manager commands, never inside
one. Because the manager leaves nothing loaded between its commands, a raw
user that keeps its own loaded handles to a minimum (irlume: at most two
objects and one session, for tens of milliseconds) cannot starve it on a chip
with the TPM-mandated minimum of three transient and three session slots;
archhost's firmware TPM reports six and three. The one hazard is the reverse:
handles loaded through the raw device belong to the chip, not to a space, so
a process that dies mid-conversation leaves them loaded until something
flushes them, and a chip whose slots are full refuses every `Load`.

The daemon's AppArmor profile already allows `/dev/tpm[0-9] rw` alongside
`/dev/tpmrm[0-9]`, and the unit sets neither `PrivateDevices` nor a
`DeviceAllow` list, so no confinement change is needed.

## Decision

1. `open_context` tries `device:/dev/tpm0` first and falls back to
   `device:/dev/tpmrm0` when the raw open fails for any reason (EBUSY from a
   concurrent opener or a userspace resource manager, a denied device, a
   missing node). The fallback is per call: the next conversation tries the
   raw device again. The first fallback in a process is noted once at debug
   level, with the error.

2. An explicit `IRLUME_TCTI` is obeyed alone, with no fallback: it is the
   test and swtpm hook and the way to pin the manager
   (`IRLUME_TCTI=device:/dev/tpmrm0` restores the previous behaviour exactly).

3. Every raw-device context is swept before use: `GetCapability` over the
   transient, HMAC-session and policy-session handle ranges (the chip answers
   the HMAC range with every loaded session, policy ones included), and
   `FlushContext` of everything listed. Any loaded handle visible through the
   raw device is a leak by construction (no other raw user exists while we hold
   the exclusive open; the manager leaves nothing loaded between commands), so
   the sweep is safe and makes the crash hazard self-healing at the next open.
   Individual flush results are not trusted: ESYS reports an invalid handle
   state for a reconstructed policy session after the chip has already flushed
   it. The chip is re-queried afterwards, and only a handle still loaded fails
   the sweep; then that context is dropped and the next transport is tried.

4. The command sequences themselves do not change. Every load stays paired
   with a flush on success and error paths (the module's existing rule), which
   on the raw device is what frees the chip's slots rather than a formality.

## Consequences

- `enrollment_load` on archhost is expected to fall from ~1.5 s to under
  0.1 s, on every attempt, for every account and tier. The keyring
  login-password unseal at PAM time takes the same path and gains the same.
  Machines whose resource manager is cheap (the laptop) gain less and lose
  nothing.
- No change to what is unsealed, when, under which policy, or for how long
  the key lives. PCRs are still read live by the chip on every unseal.
- A second irlume process (the CLI, the PAM module) that opens the TPM during
  the daemon's tens-of-milliseconds conversation gets EBUSY on the raw device
  and uses the manager for that call. Correct, just slower for that one call.
- A userspace resource manager (`tpm2-abrmd`) holding `/dev/tpm0` makes every
  irlume call fall back; the once-per-process debug line says so.
- Who gets the raw path: udev gives `/dev/tpm0` to the `tss` user with group
  `root` (mode 0660), so the daemon and the PAM module (root) use it; a
  non-root CLI invocation and the non-root CI runner fall back to the manager
  on every call. The fallback note is a debug-level line, silent unless
  `IRLUME_LOG=debug` (or `trace`) is set; the schema 4 `enrollment_load`
  stage is the plain indicator of which transport a daemon is getting.
- CI: the swtpm jobs set `IRLUME_TCTI` and are unaffected. The hardware job
  keeps its pinned-manager round trip and adds one with `IRLUME_TCTI` unset;
  because the runner is not root that step proves the fallback branch on the
  real chip, not the raw one. The raw branch and the sweep are exercised as
  root on the reference machines (below).

## Acceptance tests

- `an_explicit_tcti_is_the_only_candidate`,
  `the_default_tries_the_raw_device_then_the_resource_manager`,
  `a_failed_raw_open_falls_back_and_a_failed_fallback_reports_its_own_error`,
  `an_explicit_tcti_that_fails_is_not_retried_elsewhere` (pure).
- `a_raw_open_sweeps_handles_a_dead_process_left_loaded` (real TPM, root): a
  child process leaks a policy session, an HMAC session and a transient object
  through the raw device and exits without flushing; the next production open
  must report the slots occupied, sweep them to zero, and a full unseal must
  follow. Passed on all three fleet machines.
- `seal_unseal_roundtrip_default_transport_order` (real TPM, `IRLUME_TCTI`
  unset): as root on the laptop's Intel PTT it passed with `strace` showing
  only `/dev/tpm0` opened (raw branch and sweep); in the hardware-checks
  workflow it runs unprivileged and proves the fallback branch.
- Field confirmation: one attended archhost trial after the candidate
  install, expecting `enrollment_load` below 100 ms in the schema 4 trace.
