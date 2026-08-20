# Maintained pamsm fork: migration verification

Date: 2026-08-20
Candidate under verification: irlume `main` at
`aef04e6653cd91c5af843bf6c155a38e0729b629` (tree
`c8d39511fee27957fb02cf6a9708853363123044`), the squash merge of PR #505.

This report records the software-side verification of plan Tasks 10-12
(`docs/superpowers/plans/2026-08-20-github-maintained-pamsm-fork.md`).
Installed-system and KDE acceptance evidence (Task 13) is recorded separately
when that task runs.

## Exact identities

| Object | Identity |
| --- | --- |
| Fork repository | `https://github.com/archledger/pam_sm_rust` (public, parent `rcatolino/pam_sm_rust`) |
| Fork checkpoint commit | `ac9f644240e95c49246cb6b55adce2f2aea12a77` |
| Signed annotated tag | `irlume-0.5.5-patch.1` → `ac9f644240e95c49246cb6b55adce2f2aea12a77` |
| Tag signature | good, EDDSA key `F35053398E3C80FE20891B82C10B8492BD7F30C6` (`git verify-tag`) |
| Upstream base | tag `0.5.5` = `a51131ebaa252a9c77727f65d962d33d8a632e87` (unchanged, dormant) |
| Fork history | 12 signed commits past upstream (11 hardening + governance squash), each with exactly one `Signed-off-by` trailer; range rebuilt and force-pushed before any consumer pinned it, tree verified byte-identical |
| Fork PR | [pam_sm_rust#1](https://github.com/archledger/pam_sm_rust/pull/1), squash-merged as `ac9f6442` (GitHub-signed, DCO in message) |
| irlume dependency selector | `[patch.crates-io] pamsm = { git = ".../pam_sm_rust", rev = "ac9f644240e95c49246cb6b55adce2f2aea12a77" }` |
| Cargo.lock source | `git+https://github.com/archledger/pam_sm_rust?rev=ac9f644240e95c49246cb6b55adce2f2aea12a77#ac9f644240e95c49246cb6b55adce2f2aea12a77` |
| irlume merge commit | `aef04e6653cd91c5af843bf6c155a38e0729b629` (PR #505, GitHub `verified: true`, one DCO trailer) |
| Preceding irlume commit | `191700104331cd0dc3337293023c3d70f4a0c497` (PR #504 DCO workflow, GitHub `verified: true`, one DCO trailer) |
| In-tree vendored copy | `third_party/pamsm-0.5.5/` deleted; `.gitattributes` exception removed |
| Release artifacts (this tree) | `libpam_irlume.so` SHA-256 `21c8235030c6b4eafc03d4d9fe3aedc14de7df5beca9372486f6a23cdf0c877d`; `irlumed` `3d35183b2fb989e0f4b3cd3dd05e8d8e4a4187241d2bb86b99329c1aff1cdf3b`; `irlume` `dd0fc98b1aaf86208f6c72b17f31d481a1f59f9deb03626420a83097423a9118` |

## API and wire scope is unchanged

- `git diff 308f26fe..aef04e66 -- crates/irlume-common` is empty.
- `git diff 308f26fe..aef04e66 -- crates/irlume-daemon` is empty.
  (`308f26fe` is the PR #502 merge this design descends from.) The daemon
  request/attestation protocol, `irlume-common` DTOs, and camera code are
  untouched by the migration; the change surface is
  `crates/irlume-pam` plus packaging/CI metadata.
- `cargo tree -i pamsm --locked` resolves pamsm solely from the fork rev, with
  no other source.

## Migration correctness (Task 10)

- The reseal password stash and the GNOME keyring token stash now use the
  fork's zeroizing module-data API: `send_secret(.., PamSecretBytes::new(..))`
  for storage and `unsafe { get_secret(..) }` borrows confined to the smallest
  match arms, each copy landing in `irlume-common`'s zeroizing `SecretBytes`.
  Both unsafe blocks carry SAFETY comments stating the fork's contract (key
  registered in the same PAM transaction; no replacement during the borrow).
- Compile contract
  `pamsm_exposes_safe_auth_token_clearing_and_zeroizing_secrets` pins the
  presence of `clear_authtok`, `info`, `send_secret`, `get_secret` through
  `Pam` without raw-handle exposure. It is compile-only by design (fn-pointer
  coercion); runtime behavior is pinned by the integration case below.
- New integration case
  `pamwrap_secret_stash_replaces_and_completes_without_printing`: two
  `authenticate` ops in one pam transaction force a stash→replace cycle
  (exercising `PAM_DATA_REPLACE` cleanup of the superseded secret), then
  `open_session` reads back exactly the replaced value; the fixed dummy secret
  never appears in transaction output. A double-free or a lost cleanup in the
  fork's replacement path aborts or leaks under the ASan/LSan lane.
- RED evidence for the port: `E0433 PamSecretBytes`, `E0599 send_secret`,
  `E0599 get_secret` against the old path dependency, captured before the pin.

## Packaging and offline proof (Task 11)

- `scripts/check-packaging-parity.sh` now requires the exact fork URL plus
  40-character rev in `Cargo.toml`, the matching `git+...#rev` source in
  `Cargo.lock`, no `branch =` selector, absence of `third_party/pamsm-0.5.5`,
  and no pamsm `.gitattributes` exception. Verified in both directions: the
  current tree passes; a mutated copy using `branch = "irlume-patches"` fails
  exactly on the moving-selector assertions.
- Clean-archive offline build: `git archive HEAD` → extract →
  `cargo vendor --locked vendor` → `cargo check -p irlume-pam --offline
  --locked` succeeds from the vendor directory alone (the fork source is
  vendored like any git dependency). Temporary trees removed after evidence.
- `cargo deny` policy updated for the new dependency reality: license allow
  `GPL-3.0-only` (the fork's canonical SPDX declaration; the deprecated
  `GPL-3.0` form is gone), and `sources.allow-git` gains the pamsm fork as the
  second reviewed git dependency.
- `nix/package.nix` gains `outputHashes."pamsm-0.5.5"` =
  `sha256-00+xvNseESHveWKYJjSieqVPdD9G320ApSXxYH14dtg=`; a full local
  `nix build .#irlume` succeeds at the pinned rev.
- Absence scan over `Cargo.toml Cargo.lock .gitattributes crates scripts docs`
  (excluding the plan document, which records history) finds no live
  `third_party/pamsm`, `pamsm = { path`, `PamSendRef`, `send_bytes`,
  `retrieve_bytes`, or `fn conv` reference.

## Software gates at the frozen candidate

All commands run at `aef04e66` with the working tree clean (model weights
fetched by `scripts/fetch-models.sh`, which verifies SHA-256 against
`models/SHA256SUMS`):

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | pass |
| `cargo check --workspace --all-targets --locked` | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | pass |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked` | pass |
| `run-tests-guarded --min 650 -- cargo test -q --workspace --locked` | 1765 passed / 0 failed |
| `run-tests-guarded --min 25 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1` | 39 passed / 0 failed |
| ASan/LSan full workspace (exact `asan.yml` command, nightly, explicit target, host outside any sandbox) | 1765 passed / 0 failed, suppressions matched |
| `cargo deny check advisories bans licenses sources` | all ok |
| `./scripts/check-packaging-parity.sh` | OK |
| `cargo build --workspace --release --locked` | pass |
| `git diff --check` | clean |

GitHub checks at the merged head (PR #505, `32be7f72` head pre-squash): all 15
green, including stable CI, aggregate, all CodeQL languages, ASan lane,
cargo-deny, fuzz, Nix flake, systemd ratchet, actionlint, zizmor, DCO,
self-hosted hardware, and both Packit Fedora 43/44 RPM builds.

## Fork-side evidence (cross-reference)

The fork's own required checks (fmt·clippy·build·test at MSRV 1.88.0 and
stable, hard-gated serial pam_wrapper, ASan/LSan with runtime preload,
CodeQL rust, cargo-deny, actionlint, zizmor, DCO) all passed at
`ac9f6442` before the tag; branch protection enforces them on
`irlume-patches` with required signatures, linear history, and no
force-push/deletion. Independent GLM review of the fork delta
(approve-with-findings, no memory-safety or fail-open defect) and of this
migration PR (approve-with-findings, both actionable findings fixed pre-merge)
are on record in the session logs.

## Known limitations and rollback

- The installed laptop PAM module remains the PR #502-era candidate
  (runtime OID `efddb9fe…`, module hash `4a1833c1…`) until Task 13 installs
  the artifact from this tree; rollback snapshots from 2026-08-19 remain in
  `/home/wisbfime/irlume-system-backups/`.
- Task 13 (fresh rollback snapshot, transactional install of
  `libpam_irlume.so` from this tree, and the five KDE acceptance cases with
  the user) is the remaining acceptance step before release.
- Fork bump policy: a new fork checkpoint requires a new signed tag, delta
  review, and a PR that updates the rev in lockstep with the nix outputHash;
  `check-packaging-parity.sh` fails any selector that moves.

## Task 13: installed artifact and live KDE acceptance

Performed 2026-08-20 18:40-18:57 EDT on the ASUS KDE host
(Fedora 44, Plasma 6.7.4, Wayland, `polkit-kde-authentication-agent-1`).

### Install inventory and transaction

- Installed-before PAM module: `4a1833c19c3d222a903b3dda68b14be104c7b3ba9642167965a6a31c063bc805`
  (`lib_t`, 0644→installed 0755, root) — the PR #502-era module, matching the
  recorded state with no drift.
- `polkit-1` stack unchanged throughout: `976de9516df78e2d6d578e3b40d0e1e0e4c56ba88049fc31089990f08a7ae0d3`.
- Running daemon: the established `/usr/local/bin/irlumed-mesh-test` override
  (`3cf00098…`), active with 1 profile / 11 scans, keyring armed
  (pcrlock Tier 2), templates encrypted. Task 13 installs only the PAM
  artifact; the daemon is untouched.
- Candidate rebuilt from merged `main` `c9e66b51` (tree `4fb4ba5e`) with
  `cargo build --workspace --release --locked`: workspace artifact
  `21c8235030c6b4eafc03d4d9fe3aedc14de7df5beca9372486f6a23cdf0c877d`,
  byte-identical to the Task 12 report hash across worktrees (a
  `-p irlume-pam`-only build differs by feature unification and is NOT the
  shipped artifact; packaging lanes build the workspace).
- Rollback snapshot (0700, root): `/home/wisbfime/irlume-system-backups/2026-08-20-fork-pamsm-c9e66b51/`
  with byte-for-byte copies of the old module plus `polkit-1`, `sudo`,
  `plasmalogin` stacks, `SHA256SUMS`, and the shellchecked rollback-on-error
  installer.
- Transactional install verified: staged beside target, hash-pinned
  (`21c82350…` expected before and after), atomic rename, `restorecon` →
  `system_u:object_r:lib_t:s0`, stack hash re-verified unchanged, services
  active, enrollment intact.

### Five fresh-grant KDE cases

Temporary polkit authorizations cleared (polkitd restart) before each case;
each case ran `pkexec /usr/bin/true`. No credentials were observed or
recorded; human-visible observations were collected from the user separately
from backend evidence.

| # | Case | Backend evidence | User-visible (reported) |
| --- | --- | --- | --- |
| 1 | `yes` face | one `pam_irlume` grant via `polkit-agent-helper-1` (18:50:54); one daemon request, IR-only match 0.782 vs 0.602, granted; exit 0 | info line + exactly one hidden field; granted on face alone |
| 2 | one-entry password | exactly one `PAM:authentication`, grantors `pam_usertype,pam_localuser,pam_unix`; zero daemon entries; exit 0 | one field, real password once, granted, no camera |
| 3 | wrong then correct | 18:53:05 `pam_unix` failure (`res=failed`), 18:53:19 success through `pam_unix`; zero daemon entries; exit 0 | same single field re-prompted; granted; no camera |
| 4 | empty then cancel | exit 127 "Not authorized"; one failed helper attempt; zero daemon entries | no camera at any point; first two Enter presses produced no visible change, third showed the re-prompt (Plasma dialog quirk, recorded verbatim); Cancel dismissed |
| 5 | camera-busy fallback | 18:56:51 daemon logged `/dev/video0: camera busy`; 18:56:57 the `yes` submit failed through `pam_unix` (`yes` is not a password — correct fallthrough); 18:57:06 one real password granted via `pam_unix`; exit 0 | typed `yes`+Enter twice, then real password once in the re-prompted field |

All five cases match the PR #502 contract under the fork-migrated module.

### Post-case state

- Installed module remains `21c8235030c6b4eafc03d4d9fe3aedc14de7df5beca9372486f6a23cdf0c877d`, `lib_t`.
- Daemon/socket active; enrollment, keyring arm state, and templates unchanged.
- Rollback path: restore `pam_irlume.so` from the snapshot above and
  `restorecon`; no stack or daemon changes to undo.
