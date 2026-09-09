# IR-only campaign record

Copy this form for one frozen campaign. Follow the
[qualification protocol](../IR_ONLY_QUALIFICATION.md). This unfilled form is not
an accepted plan or evidence of qualification. Do not put personal identifiers,
biometric payloads or raw errors in any field. A missing required entry makes a
qualification campaign incomplete.

## Plan, frozen before evaluation

| Required field | Campaign entry |
|---|---|
| Campaign ID, date and phase: development / pilot / qualification | |
| Plan revision and review reference; freeze date | |
| Code commit, local patch hash and executable hash | |
| Model/adapter identities and hashes; recognizer space | |
| Matching, PAD and liveness thresholds; profile/template-count strata | |
| Hardware model, kernel/driver, backend and vetted image/metadata topology | |
| Scope: population, sensor configurations, ordinary lighting/pose/distance | |
| Enrollment procedure and separation from evaluation sessions | |
| Development/evaluation separation by people, instruments and sessions | |
| Dataset origin, terms, preprocessing, splits and known training overlap | |
| Participant consent process and private retention/deletion procedure | |
| Sampling unit, cluster structure, order, counts and missing-data rules | |
| Planned genuine and zero-effort impostor attempts by stratum | |
| Planned attack attempts by species/device; target-identity validity checks | |
| Untested attack/device/population scope and effect on intended claims | |
| Independent empirical identity-arm coverage method, or unavailable | |
| Evaluation budget, startup watchdog, cancellation and release checks | |
| Reviewed harness revision; exact output/category allowlist | |
| Protected-state verification and restoration procedure | |
| Accuracy trials versus separate lifecycle/fault controls | |

## Acceptance targets, reviewed before evaluation

Record project decisions here; do not silently copy standards with different
metrics. For each row specify numerator/denominator, numerical target, uncertainty
method/confidence, independent sampling unit and per-stratum sample plan. Explain
how the sample plan can support the target. Blank or retrospectively chosen
entries cannot qualify a deployment.

| Required measure | Target, uncertainty and sampling plan |
|---|---|
| Attack candidate fraction, each claimed species/configuration | |
| Zero-effort impostor candidate fraction, each claimed configuration | |
| Genuine failed-attempt fraction, each claimed configuration | |
| Capture/infrastructure failure fraction and stage/data adequacy | |
| Multiple-stratum/cluster treatment and fixed stopping rule | |

Any attack/impostor candidate, grant indication, unexpected device access,
cleanup/preservation failure is a stop for investigation regardless of these
numbers. Record the disposition before resuming; never delete the stopped trial.

## Results, append after the frozen plan

| Stratum | Planned | Started | Candidate | No face | Liveness refused | PAD refused | Identity mismatch | Other diagnostic categories | Harness failures |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| One row per ground-truth class/species and sensor configuration | | | | | | | | | |

Enumerate every “other” category separately, with counts. Candidate + all refusal
and error categories + harness failures must equal started. Explain planned but
not started attempts without claiming outcomes for them. Give aggregate unique
participant, instrument, session and device counts and cluster sizes without
identity linkage. Record separate stage-reach counts; these overlap outcomes and
must not be added to the outcome denominator.

Report both all-started and explicitly defined assessment-only fractions, their
counts and valid uncertainty bounds. Report non-response/availability details,
weakest strata, all stop conditions and their disposition. Keep lifecycle controls
separate. Never provide just a combined headline or treat zero samples as zero risk.

## Lifecycle and integration evidence

| Check | Evidence/reference or not tested |
|---|---|
| Camera-free preflight, exact binary/schema identity | |
| Only vetted IR image/metadata nodes opened; no RGB opens | |
| All successful opens closed; camera idle afterward | |
| Cancellation and expiry override late candidates | |
| Fault/lease/permission/incompatible-enrollment cases, no grant | |
| Protected state preserved; watchdog or restoration failures | |
| Empirical coverage of both identity acceptance arms | |
| Final installed state and operator release from positioning | |
| Actual login integration review/testing | Not implemented by this diagnostic |

If reporting physical optical shutdown, include its distinct measurement method;
descriptor timestamps alone do not support that claim.

## Decision

- Outcome: not qualified / inconclusive / evidence meets predeclared targets for stated scope.
- Supported scope and unresolved exclusions:
- Comparison against every frozen target and uncertainty requirement:
- Failed attempts and unresolved findings retained:
- Independent reviewer disposition and reviewed artifact identities:
- Configuration/model/code changes that invalidate this result:
- Next action (no automatic login enablement):

Publish only reviewed aggregate evidence and public code/model identities. Local
trial-category/timing and video-open metadata may be retained under the protocol;
remove private host/account paths and participant linkage before sharing.
