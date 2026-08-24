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

## Still open: footprint

- Convert the recognizer model to external-data ONNX so onnxruntime maps it
  from disk instead of copying it; the daemon currently holds about 617 MB
  resident for 260 MB of weights.
- Read each model once at startup (checksum and load from the same buffer)
  and stop onnxruntime worker threads from spin-waiting.

## Ongoing

- Test discipline toward the OpenSSF silver criteria: measure statement
  coverage (cargo-llvm-cov), and add a regression test with every bug fix
  that can be tested without hardware. With the Tier-1 signed-PCR unseal now
  working (see below), the `seal_unseal_signed_pcr_roundtrip_real_hardware`
  test on a systemd-boot/UKI host covers `seal_authorized` / `unseal_authorized`
  and the full suite reaches ~80.1% line coverage. The remaining points are
  hardware-only paths (live-face match, camera streaming, the TTY main loops)
  that CI cannot exercise. swtpm still cannot run the signed-PCR test: it
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
  174-crate dependency tree.
- Hardware reports: more IR camera modules, NixOS on bare metal, Fedora
  Atomic, Ubuntu derivatives. [docs/PLATFORMS.md](PLATFORMS.md) tracks the
  matrix.
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
