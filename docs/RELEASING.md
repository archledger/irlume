# Release readiness and finalization

A passing pull request is one prerequisite. Release a reviewed, uniquely versioned
candidate only after its packages and upgrade behavior have been checked. Do not
replace an already-published release's assets with unreleased source that still
carries that release's version label.

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
5. Reread the `AGENTS.md` files against the changes since the previous release.
   CI checks their paths, links and gate commands, not their rules, test lanes
   or versions (MSRV, ONNX Runtime, the fuzz nightly, the models release).

On disposable systems for each supported channel, keep an independent working
password/admin session and record these outcomes. Do not record passwords,
recovery phrases, templates or camera frames in release evidence.

| Transaction | Required evidence |
|---|---|
| Clean install | Daemon starts; CLI, PAM module, models, runtime, wallet helpers, password verifier, dedicated PAM service and polkit policies are installed at the expected paths. On the channels that ship the AppArmor profile (Debian/PPA, Arch; not Fedora, which ships an SELinux module, nor Nix), on a host with AppArmor enforcing and a TPM: the profile is loaded in enforce (`aa-status`), and two authentications log no `apparmor="DENIED"` line for `/dev/tpm0`, `/dev/tpmrm0` or `/run/lock/irlume/tpm-raw-conversation`: one over the default transport (raw device, which also writes the marker), and one with the daemon pinned to the manager (a temporary drop-in with `Environment=IRLUME_TCTI=device:/dev/tpmrm0`, restart, authenticate, remove the drop-in, restart). A single authentication only exercises whichever transport wins, so it cannot vouch for the other rule. ADR-0026: a denied device rule is a silent cost (~1.4 s per unseal on AMD firmware TPMs, or a failed unseal when both are denied); a denied marker rule silently turns crash recovery off. |
| Upgrade from the previous release | Matching components installed together, daemon restarted into the candidate, on the profile-shipping channels (Debian/PPA, Arch) the AppArmor profile reloaded by the post-install hook so its new rules are live without a reboot, existing configuration and enrollment retained, password login available. (The upgrade harness currently pins v0.11.3 -> v0.12.0; bump its assertions per [UPGRADE-VALIDATION.md](UPGRADE-VALIDATION.md) when the pair moves.) |
| Authorization/recovery | Enrollment and recovery management require their configured OS approval; denial/cancellation changes no managed state. Qualify retry reset with synthetic local accounts on supported systems. |
| Retry persistence | Existing counters survive upgrade and restart; password login alone does not reset them. Successful explicit recovery follows the documented budgets. |
| Rollback | Restore the previous complete package set and restart the daemon; keep enrollment, recovery envelopes and retry records intact. Check password login and document which newer authorization checks the older daemon lacks. |

Restore disposable VM snapshots between destructive fixture scenarios. Do not
clear production retry records to make an upgrade test pass. Actual attended
camera/PAM qualification remains a separate test from package structure checks.

## Changes users need to understand after the previous release

The list below is the v0.11.3 -> v0.12.0 example set; re-derive it from the
CHANGELOG for each release.

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

### SBOM and VEX per release

Every release ships machine-readable composition data alongside the packages:

1. **SBOM set** (CycloneDX 1.3, JSON): from the release tag checkout run
   `bash scripts/generate-release-sbom.sh <version> <asset-dir>` (requires
   `cargo install cargo-cyclonedx --version 0.5.9 --locked`). One SBOM per crate that builds
   a shipped binary; files are named `irlume-<version>-sbom-<crate>.cdx.json`.
   The generator exports the committed revision to a temporary directory and
   invokes cargo-cyclonedx once for the whole workspace. It checks the release
   version and locked dependency graph, rejects lockfile drift, and validates
   unique component identifiers, resolvable dependency edges, and absence of
   local filesystem references. Outputs are resolved relative to the caller.
   Use `--revision <tag>` to regenerate a historical release with the current
   tooling. See [SBOM-INTEGRITY.md](SBOM-INTEGRITY.md) for the contract and audit.
2. **VEX document** (OpenVEX): `python3 scripts/generate-vex.py --version
   <version>` emits `irlume-<version>-vex.json` with one `not_affected`
   statement per advisory suppressed in `deny.toml`, carrying the documented
   rationale; a clean ignore list yields an empty-statement record of the
   clean scan.
3. Add both to `SHA256SUMS`, re-sign, upload with the packages;
   `scripts/verify-release-assets.py` validates coverage and JSON structure
   (CycloneDX `bomFormat`, OpenVEX `@context`) like any other asset.


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
