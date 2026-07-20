# Roadmap

What irlume intends to do, and not do, through mid-2027. Items come from the
2026-07-20 security, standards, and performance audits; they are intentions,
not promises, and the order can change when hardware reports or security
findings say it should. Dated snapshots of what shipped live in
[CHANGELOG.md](../CHANGELOG.md).

## Next: a security-focused 0.3.x

The audit backlog, in rough order:

- Consecutive-failure lockout in the daemon: disable face auth for a user
  after repeated failed verifications and fall back to password. This is the
  one hard requirement from NIST SP 800-63B-4 section 3.2.3 that irlume
  lacks, and it bounds spoof-retry attacks.
- `catch_unwind` at the PAM entry points plus `forbid(unsafe_code)` and
  panic-lint denies on the crates that already have no unsafe, so a panic
  can never take down the host greeter.
- Constant-time comparison (`subtle`) for the sealed-password check, a
  manual `Clone` for `SecretBytes` that keeps the mlock guarantee, and
  zeroization of the remaining error-path copies.
- systemd unit sandboxing (NoNewPrivileges, ProtectSystem, SystemCallFilter,
  device allow-listing) layered under the existing SELinux/AppArmor
  policies, validated on real logins before shipping.
- `PR_SET_DUMPABLE` and core-dump limits for the daemon.

## Then: anti-spoof and footprint (0.4 direction)

- Decide whether the qualified third-party IR PAD model becomes a default
  deny-only cue instead of an opt-in. It closes the one demonstrated
  presentation-attack breach (life-size glossy print); the open question is
  UX for offline installs, since the model is fetched, not bundled.
- Convert the recognizer model to external-data ONNX so onnxruntime maps it
  from disk instead of copying it; the daemon currently holds about 617 MB
  resident for 260 MB of weights.
- Read each model once at startup (checksum and load from the same buffer)
  and stop onnxruntime worker threads from spin-waiting.

## Ongoing

- Test discipline toward the OpenSSF silver criteria: measure statement
  coverage (cargo-llvm-cov), and add a regression test with every bug fix
  that can be tested without hardware. Coverage sits at ~80%; the last few
  points are hardware-only paths (live-face match, camera streaming, the
  TTY main loops) plus the Tier-1 signed-PCR unseal. The signed-PCR path
  cannot be covered against swtpm: swtpm rejects the `TPM2_PolicyAuthorize`
  ticket that `TPM2_VerifySignature` produces for a null-hierarchy external
  public key (checkTicket TPM_RC_VALUE), the exact key kind the signed-PCR
  flow requires. A TPM-generated key authorizes fine on swtpm, so the
  production code is correct; the simulator just cannot exercise this path.
  It stays covered by the real-hardware `#[ignore]` test. Do not re-attempt
  a swtpm signed-PCR test.
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
  login, unlock, sudo, and keyring.
