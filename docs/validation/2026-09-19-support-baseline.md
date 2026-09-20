# Support evidence snapshot, September 19, 2026

The first two sections reconcile the v0.14.0 support summary with earlier
maintainer validation records. The source review used
`bcbabafdc2e3eadd4306326e2a09ea5a38e1c959`; that post-tag commit changes release
metadata tooling, not v0.14.0 application runtime code. The final section records
the subsequent attended Face Authentication parser-candidate checks.

## Attended camera evidence

September 17 tests used evolving pre-v0.13 candidates. They must not be
reported as a fresh v0.14.0 camera campaign or a single immutable-build benchmark.
The older generated [hardware matrix](../HARDWARE.md) remains a dated record.

| Configuration | Recorded result | Boundary |
|---|---|---|
| Archhost, BRIO and NexiGo N930W, default dual policy and shipped PAD configuration | At least 25 consecutive grants in the recorded stress battery; BRIO warm approximately 7.6–7.8 seconds, N930W 10.1–11.8 seconds | Candidate workstream through the PR745 enrollment fix; no universal latency or population false-rejection claim |
| Same camera-group campaign | Mid-attempt unplug returned a typed hardware failure in 3.4 seconds; replug recovered with a grant. Secondary removal/re-addition and a subsequent grant succeeded | These cases do not establish preferred-camera or docking failover policy |
| BRIO and N930W attack spot checks | BRIO vinyl banner and phone refused; N930W phone refused | Cross-spectrum refusal can precede neural PAD. N930W banner was not tested in this batch |
| ASUS built-in camera | Seven-attempt session: initial looking-away refusal, two centered dual grants, one experimental IR-only grant, two banner refusals, then a genuine control grant | Exact source OID was not established; installed binary carried unreleased content. One print/geometry in a dim room; no ASUS phone or soak test |
| ASUS, forced RGB-only KDE lock-screen candidate later shipped through PR746 | Four grants at approximately 5.315–5.465 seconds, with the complete five-sample PAD vote in one session | A forced-no-IR built-in-camera test, not qualification of every RGB-only camera |

The ASUS banner passed the algorithmic cross-spectrum gate but FLIR refused
both presentations; the genuine control at the same position granted. Earlier
genuine refusals were associated with weak IR/glint presentation conditions.
The records support a real limitation, not a deterministic ASUS-camera failure.

These are maintainer-recorded results. The private session receipts are retained
in shared project memory under the September 17 checkpoints and laptop-PAD
report; no frames or enrollment material accompany this public summary.

## v0.14.0 release and deployment evidence

The release tag identifies commit `b1aa213b3d1f933506102d3fd2c23919c0808012`.
Its reviewed candidate was `5a5404770dffb8a9130c3d64845341bdb7ff36e4`; both
have tree `d02c02baec8ce040f175b57bef1bd9db1b953777`.

- [Release CI](https://github.com/archledger/irlume/actions/runs/35446309068)
  and the [seven-job installation matrix](https://github.com/archledger/irlume/actions/runs/35446319368)
  passed in the release record.
- [September 19 nightly attempt 2](https://github.com/archledger/irlume/actions/runs/35447111819)
  passed hardware and coverage jobs, reporting 83.03% line coverage. This is a
  dated result, not current branch coverage or all-path qualification.
- Archhost upgraded 0.13.0-1 to 0.14.0-1. The running daemon matched the installed
  candidate; existing managed files retained contents, modes and ownership.
  Installed KCM passed 12 loadtest assertions against the real CLI and daemon.
- Ubuntu 26.04 native packages passed clean installation, CLI smoke and
  offscreen KCM loading. NixOS KCM loading remains unverified.
- Release assets passed [verification](https://github.com/archledger/irlume/actions/runs/35449182428)
  and [provenance generation](https://github.com/archledger/irlume/actions/runs/35449184370).

Package/state preservation does not prove authorized-write migration of every
legacy secondary store. These checks also do not establish all-distro rollback,
new attended face grants, or Atomic/Nix bare-metal qualification. The
[upgrade harness](../UPGRADE-VALIDATION.md) still describes an older version
pair; its existence is not a receipt for v0.14.0.

## Next qualification

Re-run capture and authentication on existing cameras after the Face
Authentication parser correction, retaining emitter-restoration and password
fallback checks. Then qualify current-version upgrade/rollback and desktop
password/cancel lifecycles separately. Report exact builds and environments
for each; do not expand these results into a cross-project speed or security
comparison.

## September 19–20 follow-up: Face Authentication parser candidate

The scoped camera checks planned above were subsequently run with the
eight-byte-entry parser correction on top of `bcbabafd`. The tested daemon
SHA-256 was `88a9a962603dba3cd11282695dd671b5a0dacde37dc433d051dd5fc8538a9595`;
the tested `ir_emitter.rs` source SHA-256 was
`87b84fe2bccaacbe01e749fa4c330a0d33278350d75c9d609f3b3c0e5484ecc6`.

| Camera / environment | Candidate result | Limits |
|---|---|---|
| ASUS built-in `3277:0059`, Fedora KDE, SELinux enforcing | Seven genuine grants across experimental IR-only and dual RGB+IR; covered-camera refusal; attended KDE password fallback | Includes both known-payload and device-derived control routes; one person, not population or PAD certification |
| BRIO `046d:085e`, Arch KDE, AppArmor enforcing | Four genuine dual-policy grants; covered-camera refusal; attended KDE password fallback | Device-derived control route; original D1 default retained without requiring a redundant write |
| NexiGo `3443:c803`, same Arch host | Two warm candidate grants at 13.53/13.24 seconds; installed baseline grants at 13.72/13.90 seconds; covered-camera refusal | Initial stale enrollment refused on both builds. After owner-approved secondary refresh, cold requests still reached the unchanged 15-second deadline on both builds; one candidate request refused a looking-away presentation |

The NexiGo refresh replaced ten secondary scans while preserving the primary
enrollment byte-for-byte. The group then reported connected and no longer stale.
Its initial binding refusals and later cold-start failures are part of the
record; this was not an all-attempts-passed campaign. The small timing sample
does not establish a performance improvement or regression.

Device-derived captures selected only the cameras' advertised Microsoft Face
Authentication controls and called the corrected parser on GET_DEF/GET_MAX.
Readback confirmed the original nine-byte control state after testing: ASUS
and NexiGo D0, BRIO D1. Original daemons and configuration were restored, with
no camera holders or pending emitter/stream records at the final checks.
These readbacks establish control-state restoration, not independently measured
optical darkness. Physical multi-entry hardware remains untested; multi-entry,
truncation, reserved-field and padding coverage uses specification-derived
software fixtures. Current-release upgrade/rollback and broader desktop
lifecycle qualification remain separate work.
