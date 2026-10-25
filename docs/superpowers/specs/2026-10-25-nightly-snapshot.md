# Daily nightly snapshot foundation

Status: approved and implemented as a local read-only foundation. No publisher,
installer or schedule is enabled. Research baseline: main
`339cb8b75a3adb4807031ef4eb25dc70ad0770b4`.

## Objective

Give the nightly package lanes one daily source decision. Each consumer must
use the same full main-branch commit, rather than resolve moving `main` for
itself. This first slice produces a locally inspectable candidate record;
it does not produce an installable release or change a running machine.

The audience is opt-in nightly testers. Stable releases keep their existing
identity, installation paths and release gates. Existing nightly lanes stay
unchanged until their replacements are separately verified and approved.

This extends the direction in [ADR-0037](../../adr/0037-nightly-channel.md).
It does not yet replace that ADR's per-lane implementation or its stated
qualification limits. [RELEASING.md](../../RELEASING.md) continues to govern
release publication and complete-package qualification.

## Scope and assumptions

- One UTC selection slot per day; 03:00 UTC is approved for the later scheduler.
  This slice creates no timer or workflow trigger and does not enforce a
  time-of-day window on manual invocations.
- Use the head of `archledger/irlume`'s `main` observed for that slot. If its
  evidence is incomplete or failing, hold the previous selection. Do not
  search arbitrary branches for a green commit.
- Freeze the selected commit before subsequent work. A later merge cannot
  silently change an existing candidate.
- Preserve native package ownership. Source-to-native-package experiments,
  package version adapters, downloads and installers are later work.
- A successful source decision means only that the specified source checks
  passed. It does not mean packages exist, installation is safe, hardware was
  qualified, or the candidate was signed or published.

## Candidate contract

Use a versioned JSON document with `kind: nightly-candidate` and
`schema_version: 1`. Required information:

| Field group | Required meaning |
|---|---|
| Slot | Explicit UTC date and actual observation time |
| Source | Expected repository, `refs/heads/main`, full commit and tree IDs |
| Identity | Readable date/hash label; full commit remains authoritative |
| Inputs | Digests for the committed lockfiles and model/runtime pin declarations used by the candidate |
| Policy | Version and digest of the exact source-check policy |
| Evidence | Matching workflow/run/job identities, commit, attempt, conclusion and completion time for every required check |

The 17-file inventory below identifies committed source declarations. Its
`input_scope` is `source-declarations-not-build-closure`. It is not a resolved
dependency graph or a claim that downstream binaries are reproducible. The
complete Git tree identifies source outside this inventory. Later build records
must identify their target, toolchain, features, inputs and output digests.

| Group | Source declarations |
|---|---|
| Source checks | `.github/workflows/ci.yml`, `.github/workflows/dco.yml`, `.github/workflows/workflow-audit.yml` |
| Rust inputs | `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.toml`, `fuzz/Cargo.lock` |
| Nix inputs | `flake.lock`, `nix/package.nix` |
| Models/runtime | `models/SHA256SUMS`, `scripts/build-tflite-runtime.sh`, `scripts/fetch-models.sh`, `scripts/fetch-ort.sh` |
| Native packaging | `packaging/arch/PKGBUILD`, `packaging/debian/nfpm.yaml`, `packaging/fedora/irlume.spec`, `packaging/ppa/container-build.sh` |

Every entry contains its Git blob ID and SHA-256. The collector requests the
file at the full selected commit, verifies the Git blob hash against the
returned bytes, then computes SHA-256. `policy_version: 1` and `policy_sha256`
bind the reviewed check mapping and ordered inventory. The schema validates
structure; the Python validator also checks policy, inventory and cross-field
identity. Neither authenticates an arbitrary caller-supplied file.

Illustrative display label only: `nightly-20261025-g339cb8b75a3a`.
It is not a Cargo, Debian, RPM or Arch package version. Do not sort commits
or display labels to decide which build is newer. A publisher will own
monotonic channel ordering in a later slice; this selector cannot advance it.

Reject unknown schema versions, duplicate JSON keys, missing required
fields, wrong types, invalid dates/identifiers and inconsistent evidence.
Bound input size, pagination and request duration. Errors must not produce
a partial candidate that another process could mistake for success.

## Qualification policy

Require successful evidence for the exact selected commit, not a PR head,
synthetic PR merge commit, older main commit or matching job name elsewhere.
Verify repository, GitHub application and workflow identity as well as names.
Use the relevant current run attempt; an old success cannot hide a later
failed or incomplete attempt.

The initial policy includes the seven repository-required checks:

- `fmt · clippy · build · test`
- `test (stable)`
- `fuzz (untrusted-input parsers)`
- `cargo-deny (advisories · licenses · duplicate versions)`
- `systemd units (verify + exposure ratchet)`
- `nix flake check`
- `DCO (exactly one trailer)`

Also require the workflow audit's `actionlint (workflow correctness)` and
`zizmor (workflow security)` checks. Capture the policy explicitly and compare
it with the repository's effective required-check configuration. Unexplained
policy drift holds selection; do not silently drop or accept new requirements.

Missing, pending, failed, cancelled, skipped, ambiguous or incomplete required
evidence holds selection. An unavailable API or incomplete page sequence is
unknown, not success. Never treat a successful workflow's aggregate status as
proof that every required job ran.

Hardware evidence is not collected by this source-check selector. No candidate
is hardware-qualified. Do not dispatch a hardware job or modify the existing
hardware gates. A later publication contract must record its package and
hardware evidence separately and decide those gates explicitly.

The CI-readiness follow-up removes path filters from the hosted workflow
audit's push trigger. Once integrated, every branch push is eligible for the
same two audit jobs, including source-only main commits. Existing weekly and
manual triggers are unchanged. A commit with no successful exact-SHA audit
run is still held; this selector cannot waive it.

## Decision outcomes and side effects

Return a structured decision with one of three outcomes:

- `selected`: a complete candidate and matching source-check evidence.
- `unchanged`: the previous accepted source/input/policy identity still
  applies; no replacement is needed.
- `hold`: no replacement; include a bounded, machine-readable reason.

Malformed input or an operational error exits nonzero. An expected pending
candidate may be reported as `hold`, but must never share a success flag with
`selected`. Consumers must inspect the outcome, not only the process exit code.

Retries for the same slot and frozen inputs are idempotent. A conflicting
candidate for an already occupied slot is refused rather than overwritten.
Any local output is written as a complete new file; interrupted writes leave
the prior complete output unchanged. Collection does not advance a public
channel or mutate a previous published record.

The caller supplies `--previous` and the output pathname; this slice has no
global channel registry. Use one pathname per slot and always supply the last
accepted record on later invocations. Different paths without a previous
record do not coordinate with each other. If source, inputs and policy are
unchanged on a later day, keep the previous candidate rather than create a
duplicate daily record.

Local JSON fixtures validate decision logic and data consistency only. They
do not authenticate GitHub observations. The live read-only collector must
retrieve evidence from the expected repository; an arbitrary caller-supplied
file cannot authorize publication or installation.

## Implementation and verification conventions

Use Python 3 and the existing `scripts/ci` conventions. Keep the decision
logic testable without a network connection; mock the API boundary, not the
qualification rules. Do not add a package dependency without review.

Files:

- `scripts/ci/nightly-snapshot.py`: validation, decision, CLI and local output.
- `scripts/ci/nightly_snapshot_github.py`: bounded GET-only collection.
- `scripts/ci/test-nightly-snapshot.py`: standard-library unittest suite.
- `schemas/nightly-candidate-v1.schema.json`: candidate contract.

### Local use

Run with Python 3 and the existing `jsonschema` package. Authentication is
optional for public source reads but required to read protected-branch metadata.
Use `GH_TOKEN` or `GITHUB_TOKEN` with read access to the repository's source,
Actions and branch-protection metadata. The tool does not retrieve credentials,
print token values, invoke GitHub CLI or send non-GET requests.

```sh
# Observe only; no candidate file is written.
python3 -B scripts/ci/nightly-snapshot.py --collect

# Supply the current UTC date and a trusted local destination directory.
# The directory must already exist, belong to the caller and not be writable
# by group/other. Use a distinct filename for each date.
python3 -B scripts/ci/nightly-snapshot.py --collect --slot 2026-10-25 \
  --previous /trusted/local/previous-candidate.json \
  --output /trusted/local/nightly-20261025.json

# Offline observation fixtures have the shape used by observation() in the
# test file. Their evidence_origin is always fixture.
python3 -B scripts/ci/nightly-snapshot.py --fixture observation.json
```

`--collect` accepts only today's UTC date; `--fixture` takes its slot from the
fixture and cannot combine with `--slot`. A record's `evidence_origin` must
match its invocation mode, including `--previous`. `selected`, `unchanged` and
expected `hold` decisions exit 0; malformed input or operational failure exits
2 with a generic diagnostic. Inspect `outcome`, never just the exit code.
Only `selected` writes `--output`.

The required `fmt · clippy · build · test` CI job runs the offline contract
suite before downloading models. The suite also uses the job's existing
PyYAML dependency to verify its CI placement and the audit trigger/runners.
This adds no automatic selector invocation and no new nightly schedule.

The collector caps each response at 1 MiB and each invocation at 80 requests,
uses socket timeouts up to 20 seconds and checks a 180-second collection
budget between reads/requests. This is not a hard process deadline: DNS and
operating-system stalls can exceed socket timeouts. A future scheduler must
also impose its own process timeout. Pagination must match reported totals;
duplicates, changing totals or the API's 1,000-result boundary are refused.
Redirects and off-repository paths are refused. The collector rechecks runs,
protection policy and main before returning, but GitHub does not provide an
atomic snapshot across these endpoints. Evidence can change after the final
read and must be requalified before future publication.

Local output uses a 0600 temporary file, file `fsync`, a no-clobber hard link
and directory `fsync`. It requires a local filesystem supporting those
operations. Existing equivalent candidates retain their original bytes;
conflicting files and symlinks are refused. Abrupt process death may leave
a private `.nightly-*` temporary file, never a partly written candidate at
the final pathname. A directory-sync failure can leave a complete final
file even though the command exits 2; retry validates that file. Protect the
directory and its ancestors from untrusted writers. These files are unsigned
observations, not release authorization.

### Verification

```sh
python3 -B scripts/ci/test-nightly-snapshot.py
python3 -m py_compile scripts/ci/nightly-snapshot.py scripts/ci/nightly_snapshot_github.py scripts/ci/test-nightly-snapshot.py
ruff check scripts/ci/nightly-snapshot.py scripts/ci/nightly_snapshot_github.py scripts/ci/test-nightly-snapshot.py
ruff format --check scripts/ci/nightly-snapshot.py scripts/ci/nightly_snapshot_github.py scripts/ci/test-nightly-snapshot.py
git diff --check
```

Before integrating any workflow, also run the repository's action-pin check,
actionlint, zizmor and affected workflow contracts. No live workflow or host
is needed to prove this first slice.

Acceptance tests must cover all outcomes, a wrong SHA/repository/workflow,
duplicate or substituted checks, pagination failure, cancelled/skipped jobs,
reruns, policy drift, a merge during collection, duplicate JSON keys,
same-slot retries, conflicting replacement and interrupted local output.

## Boundaries and next decision

Always retain failed/unknown evidence as such and preserve the previous
selection. Keep tokens out of records, logs and subprocess arguments.

This slice never signs or publishes a release, changes package versions,
uploads an artifact, installs software, changes PAM or services, opens a
camera/TPM, or retires a distro lane. It introduces no automatic upgrade or
new release authority. No benchmark, compatibility or rollback claim follows
from passing its unit tests.

The owner approved the 03:00 UTC selection slot, source-check policy and
read-only first-slice boundary. Package build comparison, release promotion
and installer/update integration remain separately reviewable work.

## Sources

- [GitHub scheduled event behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [GitHub workflow runs API](https://docs.github.com/en/rest/actions/workflow-runs)
- [GitHub workflow jobs API](https://docs.github.com/en/rest/actions/workflow-jobs)
- [GitHub branch protection API](https://docs.github.com/en/rest/branches/branch-protection)
- [GitHub branch rules API](https://docs.github.com/en/rest/repos/rules)
- [Python file operations](https://docs.python.org/3.14/library/os.html)
- [Python URL request timeouts](https://docs.python.org/3.14/library/urllib.request.html)
- [GitHub releases API](https://docs.github.com/en/rest/releases/releases)
- [SemVer precedence](https://semver.org/)
