# irlume documentation

The [README](../README.md) is the front page. Everything below is the detail it
points at.

## Using irlume

| | |
|:--|:--|
| [SETUP.md](SETUP.md) | Install and configure, guided or by hand |
| [COMMANDS.md](COMMANDS.md) | Every command and flag |
| [FAQ.md](FAQ.md) | Common questions |
| [LIMITATIONS.md](LIMITATIONS.md) | What irlume does not do, with the measurements |
| [DEBUGGING.md](DEBUGGING.md) | Trace a failing login, stage by stage |
| [PLATFORMS.md](PLATFORMS.md) | Distro and desktop coverage |
| [NIXOS.md](NIXOS.md) | The NixOS module |
| [APP-INTEGRATION.md](APP-INTEGRATION.md) | Face-approving app prompts (Bitwarden, pkexec) |

## Security

| | |
|:--|:--|
| [THREAT_MODEL.md](THREAT_MODEL.md) | Who this defends against, and who it does not |
| [SECURITY_AT_REST.md](SECURITY_AT_REST.md) | What is stored, how it is encrypted, and the disk-theft test |
| [VERIFY.md](VERIFY.md) | Reproduce every claim on your own machine |
| [STANDARDS.md](STANDARDS.md) | Mapping to ISO/IEC 30107-3 and FIDO |
| [PAD_SELFTEST.md](PAD_SELFTEST.md) | The presentation-attack self-test protocol |
| [FAIRNESS.md](FAIRNESS.md) | Demographic error-rate work |

## Building on irlume

| | |
|:--|:--|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the daemon, CLI and PAM module fit together |
| [INTEGRATION.md](INTEGRATION.md) | Driving irlume from your own software |
| [MACHINE-API.md](MACHINE-API.md) | The versioned machine API, field by field |
| [THIRD-PARTY-MODELS.md](THIRD-PARTY-MODELS.md) | Models irlume has measured, and at what threshold |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Dev shell, tests, and the local loop |
| [CREDITS.md](CREDITS.md) | The projects irlume builds on |
| [ROADMAP.md](ROADMAP.md) | What is planned |

## Evidence

Measurements are committed, not summarised. Each write-up names the instrument
that produced it and the dataset it ran on.

| | |
|:--|:--|
| [`adr/`](adr/) | Architecture decision records, numbered |
| [`pad-results/`](pad-results/) | Presentation-attack measurements |
| [`recognition-results/`](recognition-results/) | Recognizer accuracy and demographic spread |
| [`validation/`](validation/) | End-to-end grant-path validation runs |
| [`cross-distro/`](cross-distro/) | Distro-family surveys |
| [`research/`](research/) | Source audits against kernel and library references |

Where each evaluation dataset was actually obtained, which is not always the
canonical academic page, is in [`../benchmarks/README.md`](../benchmarks/README.md).
The scripts behind these numbers are in [`../scripts/`](../scripts/), grouped by
who runs them.
