# Release readiness and finalization

A passing pull request is one prerequisite. Release a reviewed, uniquely versioned
candidate only after its packages and upgrade behavior have been checked. Do not
replace v0.11.3 assets with unreleased source still labeled 0.11.3.

## Candidate checks

1. Select the candidate commit and a new version. Update Cargo/workspace lock and
   package version fields together; run `bash scripts/check-packaging-parity.sh`.
   Record the commit, toolchains and package SHA256 digests used in validation.
2. Require the normal CI, workflow audit, full install matrix, and nightly suites
   to pass on that candidate. A targeted regression or an older green run does
   not close a full-suite failure. Audit failed, cancelled and skipped jobs;
   resolve actual failures without lowering floors or removing tests.
3. Check the permanent runner-health monitor, GitHub runner status and the handoff
   for both minihost and archhost. Trusted hardware jobs use shared capability labels so either
   available eligible runner can accept them. GitHub does not promise equal job
   counts; do not pin a machine merely to balance totals. Fork PR jobs stay hosted.
4. Build the actual Debian, Arch, Fedora and Nix outputs for the channels being
   released. Inspect package contents, ownership, runtime dependencies and version
   metadata. The recipe parity script checks declarations; it does not replace
   inspecting built artifacts or running installation transactions.

On disposable systems for each supported channel, keep an independent working
password/admin session and record these outcomes. Do not record passwords,
recovery phrases, templates or camera frames in release evidence.

| Transaction | Required evidence |
|---|---|
| Clean install | Daemon starts; CLI, PAM module, models, runtime, wallet helpers, password verifier, dedicated PAM service and polkit policies are installed at the expected paths. |
| Upgrade from v0.11.3 | Matching components installed together, daemon restarted into the candidate, existing configuration and enrollment retained, password login available. |
| Authorization/recovery | Enrollment and recovery management require their configured OS approval; denial/cancellation changes no managed state. Qualify retry reset with synthetic local accounts on supported systems. |
| Retry persistence | Existing counters survive upgrade and restart; password login alone does not reset them. Successful explicit recovery follows the documented budgets. |
| Rollback | Restore the previous complete package set and restart the daemon; keep enrollment, recovery envelopes and retry records intact. Check password login and document which newer authorization checks the older daemon lacks. |

Restore disposable VM snapshots between destructive fixture scenarios. Do not
clear production retry records to make an upgrade test pass. Actual attended
camera/PAM qualification remains a separate test from package structure checks.

## Changes users need to understand after v0.11.3

- Upgrade the daemon, CLI, PAM module and helpers together, then restart the
  daemon. Wallet-salt lookup moved into the account-scoped helper; partial
  upgrades cannot provide the complete correction. Enrollment and recovery
  management also need the packaged polkit actions and an authorization agent.
- The cumulative face budget is 50 unsuccessful requests. Cancellation and
  interrupted reservations remain charged. Cooldown expiry and ordinary password
  login do not clear the cumulative history. Self-service `irlume retry reset`
  requires the matching password verifier and dedicated `pam_unix` service.
  This initially supports local passwords; LDAP, SSSD and systemd-homed are not
  qualified, and enforcing AppArmor makes self-service reset unavailable.
  Password login and explicit administrator recovery remain available.
- Head nod/shake gestures are removed. Follow [gesture migration](HEAD-GESTURE-REMOVAL.md).
  Typed confirmation remains the default for privileged prompts; the machine
  owner can explicitly waive it with the documented [consent control](SETUP.md).
  This does not install automatic KDE face startup/cancellation integration.
- Dual RGB+IR remains the default. Experimental IR-only is an explicit opt-in
  with stricter capture evidence and PAD requirements, not a hardware or security
  qualification. Keep its experimental limitations in the release notes.
- Encrypted v3 template storage was already shipped in v0.11.3; do not describe
  it as a new migration. Existing sealed wallet envelopes need no conversion for
  the helper change. See [recovery and rollback details](SETUP.md) before downgrading:
  an older daemon does not enforce all newer management authorization gates.

## Signed assets and publication

Only after candidate approval, create the signed release tag and a **draft**
release. Upload all Debian and Arch packages, any intended SELinux RPM,
`SHA256SUMS`, and its detached `SHA256SUMS.asc` signature. Use plain package
filenames and two spaces between each SHA256 digest and filename. Sign every
package; provenance files are separate attestations and are not in that manifest.

Download the draft's complete asset set and run the reviewed checkout's strict
verifier locally:

```sh
python3 scripts/verify-release-assets.py /path/to/downloaded-assets
```

Publish only the approved complete draft. Then require successful **Verify release
assets** and **SLSA release provenance** runs for the actual tag. To request a fresh
check after a corrected upload, set the real tag and dispatch both workflows:

```sh
TAG=vX.Y.Z  # replace with the actual approved release tag
gh workflow run verify-release.yml -f "tag=$TAG"
gh workflow run slsa-provenance.yml -f "tag=$TAG"
```

Wait for completion and verify the uploaded `multiple.intoto.jsonl` against every
package as described in [VERIFY.md](VERIFY.md). The provenance workflow checks the
returned release ID and downloads the expected nonempty attachment. A green job
that did not upload provenance is not completion. Partial or empty releases fail
verification; asset upload itself is not a reliable workflow trigger, so request
an explicit final run when needed. These attestations cover off-CI package bytes,
not a claim that the package build ran in the generator's isolated environment.

Record final run URLs, candidate OID, package digests, provenance coverage,
channel publication results, runner health, remaining limitations, and rollback
instructions in the project handoff. Do not claim release readiness while required
candidate install/upgrade, nightly, or hardware qualification remains unverified.
