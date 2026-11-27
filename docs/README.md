# irlume documentation

Use this index to find guides, contracts, security evidence, and maintainer notes.

## User guides

| | |
|:--|:--|
| [Setup](user/SETUP.md) | Install, enroll, and configure irlume |
| [Disable or uninstall](user/DISABLE.md) | Stop face authentication on selected surfaces or remove irlume |
| [Platform support](user/PLATFORMS.md) | Distro, package, and login manager coverage |
| [NixOS](user/NIXOS.md) | Configure the NixOS module |
| [KDE System Settings](user/KCM.md) | Install and use the Plasma module |
| [Desktop authentication](user/DESKTOP-AUTH.md) | What login, unlock, and privileged prompts do |
| [Application prompts](user/APP-INTEGRATION.md) | Set up Bitwarden and other polkit prompts |
| [FAQ](user/FAQ.md) | Common questions |
| [Debugging](user/DEBUGGING.md) | Trace a failing login and collect a report |

## Reference

| | |
|:--|:--|
| [Commands](reference/COMMANDS.md) | Command syntax, flags, and authorization notes |
| [TUI](reference/TUI.md) | The interactive interface, screen by screen |
| [Machine API](reference/MACHINE-API.md) | Versioned machine output, field by field |
| [Integration](reference/INTEGRATION.md) | Use irlume from other software |
| [Limits](reference/LIMITATIONS.md) | Unsupported configurations and measured limits |
| [Hardware compatibility](reference/HARDWARE.md) | Generated matrix of recorded results |
| [Credits](reference/CREDITS.md) | The projects irlume builds on |

## Security

| | |
|:--|:--|
| [Threat model](security/THREAT_MODEL.md) | Attacker assumptions and security boundaries |
| [Security at rest](security/SECURITY_AT_REST.md) | Stored data, encryption, and the disk-theft test |
| [Verification](security/VERIFY.md) | Verify release artifacts and reproduce checks |
| [SBOM integrity](security/SBOM-INTEGRITY.md) | Checks on the released CycloneDX component graph |
| [Reproducibility](security/REPRODUCIBILITY.md) | Build inputs, rebuild commands, and limits |
| [Standards](security/STANDARDS.md) | Mapping to ISO/IEC 30107-3 and FIDO |
| [PAD self-test](security/PAD_SELFTEST.md) | Presentation-attack testing protocol |
| [IR-only qualification](security/IR_ONLY_QUALIFICATION.md) | Evidence required to qualify experimental IR-only installations |
| [IR request evaluation](security/IR_REQUEST_EVALUATION.md) | Maintainer workflow for non-granting comparisons |
| [Fairness](security/FAIRNESS.md) | Demographic error-rate work |

## Architecture and maintenance

| | |
|:--|:--|
| [System overview](architecture/ARCHITECTURE.md) | Daemon, CLI, and PAM relationships |
| [Decision records](architecture/adr/) | Numbered architecture decisions |
| [Crate map](../crates/README.md) | Workspace responsibilities and dependency direction |
| [Development](architecture/DEVELOPMENT.md) | Dev setup and test commands |
| [Code review](architecture/CODE_REVIEW.md) | Review criteria and change gates |
| [Releasing](architecture/RELEASING.md) | Release checklist and upgrade requirements |
| [Upgrade validation](architecture/UPGRADE-VALIDATION.md) | Package, service, and authentication upgrade checks |
| [Runner maintenance](architecture/RUNNER-MAINTENANCE.md) | Maintain self-hosted CI runners |
| [Head-gesture removal](architecture/HEAD-GESTURE-REMOVAL.md) | Migration notes for retired settings |
| [Roadmap](architecture/ROADMAP.md) | Planned work |

For project policies, see [Contributing](../.github/CONTRIBUTING.md),
[Support](../.github/SUPPORT.md), or [Private security reporting](../.github/SECURITY.md).
For release history, see the [changelog](../CHANGELOG.md).

## Evidence

Measurements are committed, not summarised. Each write-up names the instrument
that produced it and the dataset it ran on.

| | |
|:--|:--|
| [`pad-results/`](pad-results/) | Presentation-attack measurements |
| [`recognition-results/`](recognition-results/) | Recognizer accuracy and demographic spread |
| [`validation/`](validation/) | End-to-end grant-path validation runs |
| [`cross-distro/`](cross-distro/) | Distro-family surveys |
| [`research/`](research/) | Source audits against kernel and library references |

Where each evaluation dataset was actually obtained, which is not always the
canonical academic page, is in [`../benchmarks/README.md`](../benchmarks/README.md).
The scripts behind these numbers are in [`../scripts/`](../scripts/), grouped by
who runs them.
