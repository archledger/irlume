# ADR-0033: Split-Camera Authentication

**Status:** Draft (RFC, not accepted)
**Date:** 2026-10-13
**Scope:** `irlume-common` (wire), `irlume-daemon` (posture, routing),
`irlume-auth` (execution), `irlume-pam` (selection)

## Context

`EnrollSplitOn` (`crates/irlume-common/src/lib.rs:598`) admits enrollment
against an explicitly chosen split camera pair: a supervisor identity,
per-side guards, and an account authorization, carried as
`SplitEnrollmentCameraChoice`. The daemon captures RGB and IR on that pair,
binds the resulting profile to it, and seals the template key under the
account's TPM policy. Enrollment works; it has been demonstrated end to end,
including on hardware whose IR path needs the `t480-experimental`
accommodations.

Nothing can authenticate against such an enrollment.

`Request::Authenticate` (`lib.rs:559`) carries no camera selection. It resolves
cameras through the ordinary path, and the ordinary path never opens a split
pair. `crates/irlume-auth/src/request_preparation.rs:769-779` states this as a
standing refusal:

```rust
pub(crate) const ORDINARY_PATH_SPLIT_REFUSAL: &str =
    "this request uses the ordinary camera path, which never opens a split camera pair; \
     explicit split enrollment uses `irlume enroll --split-camera-choice`";
```

The comment documents the blast radius explicitly: *"`identify`, `profiles
add-scan` and positioning have no split counterpart."* `Authenticate` from a
standard PAM client belongs in that list but is not named there, because no
split authenticate request exists to contrast it with.

Observed consequence: a host with exactly one profile, one scan, encrypted
templates, and a valid sealed key (`irlume status` confirms all four) still
falls straight to password on every PAM service. The daemon journals nothing,
because the refusal happens at request preparation, before any capture starts.
The enrollment is stranded: writable, readable by `status`, unusable for
authentication.

## Problem statement

Split-camera enrollments need a split-camera authentication path, or they are
dead state. The missing piece is not a flag or a policy value; the refusal is
unconditional by design ("stays true once split activation is admitted"), so no
configuration can route around it.

## Proposal

### 1. Wire: `AuthenticateSplitOn`

A new `Request` variant mirroring `EnrollSplitOn`:

```rust
AuthenticateSplitOn {
    user: String,
    service: Option<String>,
    intent_confirmation: Option<IntentAttestation>,
    pair: Box<SplitEnrollmentCameraChoice>,  // same shape as EnrollSplitOn
}
```

Compatibility rules, per the daemon's socket contract:

- **Additive only.** Old and new binaries meet during upgrades, so the variant
  is a new arm, never a reshaped `Authenticate`. `#[serde(deny_unknown_fields)]`
  on the choice type stays as is; any new field it needs is `#[serde(default)]`.
- **Same authorization shape as enrollment.** The account authorization token
  (`generation` + `token`) is replayed, so a caller that could enroll can
  authenticate and nothing else can. Root callers follow the existing
  `SO_PEERCRED` rules; no new privilege is introduced.
- **`--json` stability.** If the CLI gains a split authenticate verb, its
  output follows `docs/MACHINE-API.md` like any other.

### 2. Daemon posture and routing

`fn posture(req: &Request) -> RequestPosture` (`crates/irlume-daemon/src/main.rs:4339`)
requires an explicit arm per variant, with no wildcard. The new arm mirrors
`Authenticate`'s posture (caller must be root or the account's owner;
`intent_confirmation` honoured under the same waiver rules the daemon
re-checks itself at `main.rs:5568-5600`, where "root said so" is explicitly not
the guarantee).

Request preparation needs a split-aware resolution parallel to the ordinary
one: given the account's published secondary store and the choice's guards,
resolve the pair, verify the guards against the current publication (the same
`verify_split_guard` check enrollment uses at `main.rs:5084`), and open the
pair for the single attempt. The ordinary path is untouched; its refusal stays
byte-identical for every request that uses it.

Execution reuses `authenticate_for_in_window_with_policy` with the resolved
split pair, so PAD, liveness, thresholds, budgets, and the grant/deny contract
are the same code, not a parallel implementation.

### 3. PAM selection: standard vs split

`pam_irlume.so` must decide per attempt, without prompting and without weakening
the password floor:

1. If the account has an ordinary enrollment, send `Authenticate` (current
   behaviour, unchanged).
2. Else, if the account has a split-bound enrollment and a published,
   selected pair, send `AuthenticateSplitOn` with the account's choice.
3. Else, return `PAM_IGNORE` immediately (current fallback behaviour).

The decision is read-only (status + split list) and happens before any camera
opens. Every non-success path keeps returning `PAM_IGNORE`, per the module's
standing invariant. No new PAM conversation is introduced; intent confirmation
for privileged services follows the existing `confirm_face_intent` path
unchanged.

Open question: whether the choice should be re-derived per attempt or cached at
module init. Re-deriving costs two daemon round trips per attempt; caching risks
using a stale generation after re-registration. The enrollment helper
(`scripts/t480-enroll.sh`) re-derives every time; PAM should probably do the
same until measured otherwise.

### 4. Security and threat model

**PAD applies identically.** ADR-0013 calibrates the ViT cue as "0.55 with a
5-frame-median vote per authentication" and requires re-qualification if either
threshold moves, gated by four-host fleet validation. Split authentication
executes the same `authenticate_for` path, so it inherits the same vote, the
same threshold, and the same deny-only wiring. No PAD parameter changes with
this ADR.

**The `t480-experimental` mitigations do not transfer as a bundle.** They were
scoped to make *enrollment* possible on thermally and firmware-constrained
hardware, and each needs a separate decision for authentication:

| Mitigation | Enrollment role | Authentication verdict |
|---|---|---|
| PAD vote retention across `Uncertain` (`PadWindowScope::Enrollment`) | Cuts emitter re-arms during capture loops | **Must not transfer.** Authentication's window crosses attempts; the anti-replay property asserted by `grouped_interrupted_evidence_does_not_reuse_prior_votes` must hold. |
| Capture budget 30s → 90s | Covers a 5-vote window at ~4s/round | Needs its own measurement; authentication rounds are shorter (no enrollment overhead) and the anti-stall rationale differs. |
| Chroma span tolerance 2 → 8 | Accommodates sensor read noise in the content latch | Transfers only with a calibration record for the authenticating sensor; the §4 verdict stays strict either way. |
| Software-composite `authPolicy` | Works around trial-session divergence on Kaby Lake-R fTPM | Transfers only if the same divergence is demonstrated on the authenticating host; it changes what new envelopes commit to. |

**Thermal constraints need a hardware profile, not a feature flag.** The T480
emitter reaches thermal cutoff over roughly ten seconds of continuous use, and
the mitigations above exist because of it. If split authentication is to work on
such hardware, the retry and vote-window policy should be driven by a measured
device profile (emitter duty cycle, per-round cost), not by a build flag that
also weakens authentication. That profile does not exist yet; this ADR does not
create it, but no split-authentication implementation on constrained hardware
can ship without one.

**No new spoof surface in principle.** The proposal adds no new grant path that
the ordinary path does not already have: same engine, same PAD, same policy,
same TPM-bound key. The new surface is the *selection* (which pair opens), and
it is constrained by the same guards and authorizations as enrollment.

## Alternatives considered

- **Status quo (stranded enrollments).** Split enrollment remains a write-only
  operation for PAM purposes. Rejected: it makes `EnrollSplitOn` a trap.
- **Teach the ordinary path to open split pairs.** Rejected: the ordinary-path
  refusal is a deliberate isolation boundary (camera trust, device pinning per
  THREAT_MODEL.md). Dissolving it would put every ordinary caller in scope of
  split authorization semantics.
- **CLI-only split authentication (`identify --split-camera-choice`).**
  Possible as a companion, but it does not unblock PAM, which is the stated
  problem. Left as follow-up work, not part of this ADR.

## Acceptance

- [ ] Wire variant merged with additive-compatibility tests and `--json`
  conformance where applicable.
- [ ] Posture arm merged; `scripts/check-agents-md.py` and the `dco` check green.
- [ ] `authenticate_for` executes split requests with zero changes to PAD
  parameters; the two anti-replay tests pass unmodified.
- [ ] PAM selection merged with fallback-to-password tests on a host with no
  enrollment, an ordinary enrollment, and a split enrollment.
- [ ] Fleet validation per the camera-change rule, including at least one
  split-pair host.
- [ ] This ADR's status flipped to Accepted with the merge commit cited.

## References

- `crates/irlume-common/src/lib.rs:559` (`Authenticate`), `:598`
  (`EnrollSplitOn`)
- `crates/irlume-auth/src/request_preparation.rs:769-779`
  (`ORDINARY_PATH_SPLIT_REFUSAL`)
- `crates/irlume-daemon/src/main.rs:4339` (`posture`), `:5568-5600`
  (confirmation re-check)
- ADR-0013 (PAD calibration: 0.55, 5-frame median, re-qualification rule)
- ADR-0031 §4 (YUYV content prerequisites), ADR-0032 (split authorization)
- THREAT_MODEL.md ("Camera trust: device pinning")
