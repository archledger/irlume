# scripts/

Three groups. The split is by who runs them, not by language.

## Top level: wired into something

These are called by CI, a packaging lane, or a user, so their paths are
load-bearing and moving one breaks a caller. `run-tests-guarded.sh` has about 40
references and `fetch-models.sh` about 30; **`install.sh`'s URL is published** in
the README and on the Copr and PPA pages, so it must never move.

| Script | Run by |
|---|---|
| `install.sh` | users, via a published `curl` URL |
| `install-host.sh` | a developer, installing a local build onto this host |
| `fetch-models.sh` | every packaging lane, before a build |
| `run-tests-guarded.sh` | CI, and it refuses a test filter that matches nothing |
| `check-packaging-parity.sh` | CI, so a unit or rule cannot exist in one lane only |
| `check-action-pins.sh` | CI, so every GitHub Action stays SHA-pinned |
| `machine-api-conformance.py` | CI, against the versioned machine API |
| `capture-machine-fixtures.py` | a maintainer, refreshing those fixtures |
| `build-ppa-source.sh` | the PPA lane |
| `build-tflite-runtime.sh`, `build-tflite-runtime-container.sh` | rebuilding the bundled TFLite C runtime |
| `verify-ppa-publish.py` | after a `dput`, because an accepted upload is not a published package |
| `diagnose-missing-camera.sh`, `gkr-token-check.sh`, `kwallet-handoff-check.sh` | a maintainer, diagnosing one machine |
| `deploy-keyring-unlock.sh`, `deploy-passive-ear.sh` | a maintainer, staging a build onto a test box |
| `login-transaction-container-test.sh`, `tpm-pcr-race-swtpm.sh` | a maintainer, reproducing a condition in a container or software TPM |
| `timing-report.py` | a maintainer, summarising timings |

## `hardware/`: manual procedures that need a real camera

Run by hand, on a machine with the hardware, usually to reproduce or re-verify
an emitter behaviour. Nothing automated calls them, which is why they can live
here. Several are multi-step: the `emitter-journal-portmove-*` trio runs in
order, on two USB ports.

## `research/`: measurement and analysis

One-off instruments behind the numbers in `docs/pad-results/` and
`docs/recognition-results/`. Each is referenced from the write-up whose figures
it produced, so start from the document rather than from the script.
