# Roadmap

What irlume intends to do, and not do, through mid-2027. Items come from the
2026-07-20 security, standards, and performance audits; they are intentions,
not promises, and the order can change when hardware reports or security
findings say it should. Dated snapshots of what shipped live in
[CHANGELOG.md](../CHANGELOG.md).

## Done from the original audit backlog

Shipped since this list was written: the consecutive-failure throttle (0.4.0;
the NIST SP 800-63B-4 3.2.3 hard requirement), panic containment at the PAM
entry points, the hardening passes (constant-time checks, zeroization), the
sandboxed systemd unit (validated on real logins), and the anti-spoof
decision: both PAD models ship default-on and bundled, verified at startup
([ADR-0013](adr/0013-ship-pad-models-default-on.md)); the third-party model
lane was later removed outright
([ADR-0015](adr/0015-remove-thirdparty-model-lane.md)).

The shipped recognizer now loads from the same bytes checked at startup;
ONNX Runtime workers no longer spin while idle. Multi-camera enrollment,
grouped capture and latency improvements shipped in v0.13.0. v0.14.0 adds
secondary-store encryption and the KDE System Settings dashboard with TUI
launch buttons. Native privileged KCM controls remain optional future work.

## Still open: footprint

- Convert the recognizer model to external-data ONNX so onnxruntime maps it
  from disk instead of copying it, subject to measured benefit and model-load
  compatibility. The original audit's about 617 MB resident for 260 MB of
  weights is a historical observation, not a current memory budget.
- Measure current cold/warm latency, idle and peak RSS, idle CPU and energy
  per attempt on named hardware. Preserve the full PAD admission protocol.

## Recommended next work

The September 2026 review puts protocol correctness and support accuracy first,
followed by a provider-neutral frontend lifecycle contract, current-release
upgrade/rollback qualification, and explicit docking/camera-choice behavior.
Frontend work needs selected-user binding, an independently usable password
path, explicit start/cancel and no grant after cancellation; it is a design
candidate, not a shipped integration. Targeted model-interface tests, MIPI/IPU
diagnostics, accessibility and localization follow their own evidence and user
needs. Compile-only NPU experiments do not establish inference parity or a
shipped acceleration guarantee.

## Ongoing

- Test discipline toward the OpenSSF silver criteria: measure statement
  coverage (cargo-llvm-cov), and add a regression test with every bug fix
  that can be tested without hardware. The Tier-1 signed-PCR unseal works
  (see below), and the `seal_unseal_signed_pcr_roundtrip_real_hardware`
  test on a systemd-boot/UKI host covers `seal_authorized` / `unseal_authorized`
  (new seals no longer use Tier 1; the test proves older envelopes unseal)
  and an earlier full suite reached ~80.1% line coverage. The v0.14.0
  [September 19 nightly run](https://github.com/archledger/irlume/actions/runs/35447111819)
  recorded 83.03% line coverage; neither figure is a timeless coverage claim.
  Remaining gaps include attended live-face and TTY interaction paths beyond
  the unattended camera/TPM lanes. swtpm still cannot run the signed-PCR test: it
  rejects the `TPM2_PolicyAuthorize` ticket from `TPM2_VerifySignature`
  (`TPM_RC_VALUE`), so that test stays `#[ignore]` and runs on real signed-UKI
  hardware; do not re-attempt a swtpm signed-PCR test.
  Earlier this was misread as a swtpm-only quirk with correct production code.
  It was not: `load_external_pubkey` loaded systemd's public key under the
  **Null** hierarchy, so `VerifySignature` yielded a null ticket that
  `PolicyAuthorize` rejects with `TPM_RC_VALUE` on real TPMs too (confirmed on
  systemd-boot hardware). Tier-1 therefore never engaged and every UKI host
  silently fell back to Tier-2. Loading the key under the **Owner** hierarchy
  (the key Name, which the sealed policy commits to, is hierarchy-independent)
  fixes it; verified by a real-TPM seal→unseal round-trip landing on
  `PolicyKind::Authorized`.
- cargo-vet with the Mozilla and Google shared audit sets for the
  dependency tree (359 lockfile packages at 0.13.0).
- Hardware reports: more IR camera modules, NixOS on bare metal, and live-face
  qualification beyond the recorded Silverblue/Pop!_OS installation and password
  tests. [docs/PLATFORMS.md](PLATFORMS.md) tracks the matrix and its dates.
- IR exposure control where cameras support it, to attack the documented
  outdoor/backlit failure mode.

## Not planned

- No cloud components, telemetry, or account systems; authentication stays
  local.
- No non-Linux ports.
- No paid certification lab engagements (iBeta, FIDO) at hobby scale; the
  published self-tests against the same protocols stay the substitute.
- No WebAuthn/passkey platform-authenticator role for now; the scope is
  login, unlock, `sudo`, keyring, and app prompts via polkit (Bitwarden,
  `pkexec`).
