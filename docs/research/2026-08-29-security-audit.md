# Security audit, 2026-08-29

A full code-grounded security audit of the irlume workspace at `65460762`,
covering all twelve crates, the packaging units, and the PAM wiring surfaces.
Method: context-building dossiers (per-function assumptions with citations),
structural review of the authorization matrix, adversarial verification of
every candidate finding to a TRUE/FALSE verdict, scanner passes, and fuzz
campaigns over the untrusted-input parsers.

## Scope and attacker classes

In scope, in decreasing order of attention:

1. Unprivileged local process (any uid): the Unix socket peer, the PAM
   conversation input, sysfs/proc readers, `/tmp` and `/run` tenants.
2. Physical / presentation attacker: prints, screens, masks, IR reflectors.
3. Malicious camera device or hostile kernel-supplied descriptors.
4. Crash / power-loss windows in privileged writers (integrity class).
5. Supply chain (model files, packaging scriptlets).

Out of scope, per the standing threat model
([THREAT_MODEL.md](../THREAT_MODEL.md)): a root attacker, and cryptographic
camera attestation against malicious hardware.

## What held (verified controls)

Every control below was traced source-to-sink with file:line evidence and
survived adversarial reading:

- **Socket authorization matrix.** `SO_PEERCRED` is captured before any
  parse; every `Request` arm carries an explicit `RequestPosture`
  (`main.rs` L2364-2615), `SetCameras`/`UnsealPassword`/`UnsealKeyring` are
  `RootOnly` with tests pinning refusal (`main.rs` L9986, L10000), and the
  unseal paths add envelope-existence, biopolicy class, and intent gates.
- **Request framing.** `take(64 KiB)` precedes any allocation or parse
  (`main.rs` L1313, L2335); the wire type is a closed Rust enum with no
  untyped `Value`; `serde_json` never disables the recursion limit anywhere
  in the workspace.
- **PAM module env trust.** `secure_getenv` suppresses every
  secret-relevant `IRLUME_*` override in all setuid contexts
  (`client.rs` L47-65); remote-session markers only ever force deny; the
  helper binaries that receive the TPM-released secret on stdin are
  reachable only from root-daemon greeter lanes (wiring is verify-only for
  sudo/polkit), and their argv/envp are constants plus NSS values. No
  unprivileged env reaches a privileged sink.
- **Username path safety.** `valid_username` (`main.rs` L2356-2362) rejects
  empty, over-64, leading `-`/`.`, and every byte outside
  `[A-Za-z0-9_.$-]`: no `/`, no NUL, no traversal into the
  `format!("{user}.json")` joins.
- **Matching math.** Every shipped embedding is L2-normalized in Rust
  (`vision.rs` L612, L662) before the fixed 0.55 cosine comparison
  (`auth.rs` L5263-5276); enroll and auth share one path; a swapped
  recognizer changes the `embed:<sha256>` space tag and fails closed for
  every stored scan (`main.rs` L163-166).
- **Liveness fallbacks.** The saturation-frame fallback reads the raw (not
  differenced) frame (`camera` L391, L5358); the only unmeasurable corner
  is refused before any grant (`liveness.rs` L807-816). Degenerate
  landmarks that default FRONTAL only skip a permissive gate and destroy
  the identity chip simultaneously (`align.rs` L298-325).
- **Helpers.** `drop_privileges` does initgroups-setgid-setuid with a
  four-ID verify and refuses uid 0; wallet keys ride a private pipe, never
  argv/env/socket; `/run/user/<uid>` is 0700 and the GKR socket checks
  `SO_PASSCRED` peer uid.
- **At-rest storage.** Secret-bearing files are 0600 from creation
  (create_new + explicit mode, no chmod window); daemon dirs 0750 via
  `UMask=0027`; template spaces are digest-pinned (`storage.rs` L206-223).
- **Panic firewall.** All four PAM entry points wrap their bodies; no
  reachable panic on untrusted input in the module's production spans.

Scanner and dynamic evidence: semgrep (default ruleset) over all crates:
0 findings. CodeQL default suite via CI: clean (the two
`cfg(test)`-blind queries excluded 2026-08-29, PR #595, after 139/139
verified false positives). `cargo test --workspace`: green. Fuzz campaigns
over the four untrusted-input parsers (`ipc_request`, `sealed_envelope`,
`pcr_signature`, `uvc_illumination`): 101,286,310 executions, zero crashes,
zero OOMs, zero timeouts.

## Findings fixed by this audit batch

1. **`write_pam_edit` was a truncate-in-place write of a PAM file**
   (`fingerprint.rs` L409): a crash, full disk, or power loss mid-write
   could leave a truncated `/etc/pam.d` file, and the forced 0644 clobbered
   any tighter existing mode. Now: one-shot backup, atomic temp-rename with
   directory fsync via the shared helper, and the existing file mode is
   preserved.
2. **`policy::set_method` was a non-atomic truncate write** (`policy.rs`
   L70): same crash-window class for `/etc/irlume/method`; a truncated file
   parses to `Auto` (face on). Now atomic via the same helper. The
   fail-open parse itself stays: it is the documented anti-lockout default
   and the atomic write removes the crash path that could silently flip it.
3. **Peer-supplied service strings reached the journal unsanitized**
   (`main.rs` L2046, L3629, L3654, L4077, L4109): a local peer could forge
   `irlumed:` journal lines via embedded newlines. Now sanitized (control
   characters replaced, length clamped) before any journal write.
4. **`set_mode` ignored chmod errors** (`main.rs` L4774): a silent failure
   would leave the socket mode unset with no trace. Now checked, with a
   loud journal warning on failure.

## Hardening backlog (verified, not fixed here)

Ordered by value; each was confirmed real in code but sits inside the root
trust boundary, hardens a fail-closed path, or is cosmetic:

1. **Pin absolute paths for binaries spawned as root.** `loginctl`
   (`platform.rs` L115), `systemctl`/`restorecon`/`semodule`
   (`pamwire.rs` L1841-1888), `authselect`/`pam-auth-update`
   (`fingerprint.rs` L1143), `gnome-shell` (`pamwire.rs` L612), `busctl`
   (`secrets.rs` L33), package-manager detection (`uninstall.rs`). All are
   root-invoked with root-controlled env today; pinning removes the class.
2. **`IRLUME_MODELS_STRICT` defaults off, and the post-panic engine rebuild
   reopens model paths without re-verifying digests** (`main.rs` L150-172,
   in-code comment is honest about it). Ship `=1` in the daemon unit and
   re-verify on rebuild when strict is on.
3. **Envelope/version fields are never checked on load**
   (`envelope.rs` L128, `storage.rs` L566, `recovery.rs` L46); unknown
   versions should be rejected rather than best-effort parsed (root-only
   files, so integrity-of-format hardening).
4. **Rate-limit strikes are keyed by username, not uid** (`main.rs`
   L1004-1080): NSS aliases multiply the 5-strike budget; keying by uid
   closes it. The throttle is documented as a throttle with password
   fallback, so impact is bounded.
5. **`/var/lib/irlume` is 0755 from packaging scriptlets** (umask 022):
   enrolled usernames are listable. One mechanism creating it 0750 (tmpfiles
   or scriptlet with explicit mode) closes the listing.
6. **Secret hygiene gaps:** `SecretBytes` clones are not memlocked
   (`common/lib.rs` L35); mlock failure is warn-and-continue and nothing
   ever munlocks (`memlock.rs` L14-46); the kwallet PBKDF2 output is not
   memlocked (`kwallet.rs` L154). Swap/dump exposure only, root process.
7. **`kwallet read_salt` walks user-controlled intermediate symlinks**
   (`kwallet.rs` L75; leaf is the fixed `kdewallet.salt`): an openat2
   `RESOLVE_BENEATH`/`NO_SYMLINKS` walk removes the residual
   existence/size oracle from error text.
8. **`Adapter::apply` returns un-normalized output and its doc comment
   claims otherwise** (`vision.rs` L692-700): opt-in, root-only path;
   normalize and fix the doc.
9. **`IRLUME_GRACE_MS` parses unvalidated and
   `IRLUME_SHAKE_MIN_CROSSINGS` bypasses the `env_override` range/report
   chain** (`auth.rs` L541-546, `liveness.rs` L1258-1263): route both
   through the existing override discipline (operator-controlled env only,
   but the validation asymmetry invites mistakes).
10. **Per-recognizer threshold remains the shipped constant 0.55**
    (`auth.rs` L2635, `core` L91): safe today because non-default weights
    change the space tag and fail closed; #276 tracks the ROC-derived
    threshold.
11. **Omarchy fingerprint unwire uses raw substring matching**
    (`fingerprint.rs` L601-643): drift in upstream lines could delete
    foreign content; match on the pinned byte-constants instead.
12. **Uninstall wildcard deletion** (`uninstall.rs` L340-352): `*irlume*`
    glob in five root dirs; narrow to the exact packaged file list.
13. **Daemon `set_devices`/cameras.conf values are format-unvalidated**
    (`main.rs` L3751-3777, root-only writers): a `/dev/videoN`-shape check
    would make misconfiguration loud instead of weird.
14. **Stale unit comment**: `irlumed.service` L26-27 describes per-user
    `$HOME` state that the daemon (no HOME, writes `/var/lib/irlume`) does
    not have.

## Threat model delta

The standing [THREAT_MODEL.md](../THREAT_MODEL.md) validated against the
code: the camera-pinning conditions, the posture table, the sealing-tier
ladder, the fingerprint-tier residual (ADR-0003), and the score-exposure
rules all match their implementations. Two additions from this audit:

- **Journal forging** (fixed in this batch): a local peer could forge
  journal lines via newlines in service strings; treat daemon journal lines
  as attacker-influensible input in investigations no longer needed.
- **Model tamper gate is opt-in and one-shot**: the strict manifest check
  is honest about its own limits; until it defaults on and re-verifies on
  rebuild, treat verified-model status as a startup-time property only.

Assumptions that materially shaped the verdicts: single-user workstations
and laptops (no multi-tenant hosts where uid boundaries matter differently);
packaged deployment (systemd unit env is root-owned; LSM profiles active
where the distro enforces them); the maintainer fleet tests on enforcing
hosts. If any deployment shares a host between mutually distrusting users,
revisit backlog items 4 and 5 first.
