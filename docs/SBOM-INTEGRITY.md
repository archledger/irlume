# Release SBOM integrity

## Research and decisions (2026-09-19)

Issue [#772](https://github.com/archledger/irlume/issues/772) was reproduced
during v0.14.0 release preparation. A valid checksum authenticated the metadata
file, but did not establish that its component identifiers or dependency graph
were usable.

Primary sources checked before implementation:

- [cargo-cyclonedx 0.5.9](https://docs.rs/crate/cargo-cyclonedx/0.5.9): one
  invocation writes a BOM beside every workspace manifest. `--manifest-path`
  does not isolate output to that member. The default description is a crate
  with Cargo targets as subcomponents; the default schema is CycloneDX 1.3.
- [CycloneDX dependency relationships](https://cyclonedx.org/use-cases/software-dependencies/):
  every `bom-ref` is unique within a BOM, and `ref` and `dependsOn` identify
  defined components or services. A component without a dependency record is
  opaque, not necessarily dependency-free.
- [CycloneDX 1.3 schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3.schema.json):
  component references are document-local identifiers. Graph checks supplement
  structural checks; they do not replace full JSON Schema validation.

The release tooling should therefore:

1. Generate the whole workspace once in a temporary source tree taken from the
   requested Git revision. Check the version and locked dependency graph before
   generation, and reject lockfile drift afterward. Keep intermediate workspace
   BOMs out of the checkout; write release files to the caller's output directory.
2. Derive stable local component identifiers from each component's package URL,
   preserving versions and target distinctions. Remove only local download URL
   qualifiers; retain meaningful remote qualifiers and subpaths. Rewrite graph
   references with an exact old-to-new identifier map, not a lossy fallback.
3. Validate unique definitions and resolvable dependency edges before emitting
   files and when verifying signed release assets. Reject local filesystem URLs.
   Do not invent empty dependency records for opaque native dependencies.
4. Audit every published SBOM, preserving evidence of historical defects.
   Regenerate damaged historical metadata from its original release revision;
   document corrections, re-sign the manifest, and refresh provenance. Application
   packages and release tags retain their original bytes and identities.

The Rust SBOMs describe Cargo dependencies, not every system library, model, or
native plugin. The separate Arch KCM SBOM describes its native package inventory.
That distinction remains explicit in release notes.

## Historical audit

The GitHub release inventory on 2026-09-19 contained SBOMs in two releases:
six in v0.13.0 and seven in v0.14.0. Earlier application releases and the model
and runtime releases had no SBOM assets. Signatures and manifest checksums were
verified before examining the downloaded documents.

| Release | Documents | Duplicate definitions | Dangling dependency references | Local filesystem references |
| --- | ---: | ---: | ---: | ---: |
| v0.13.0, original metadata | 6 | 22 | 37 | 65 |
| v0.14.0, published metadata | 7 | 0 | 0 | 0 |

The original v0.13.0 metadata was authentic but had invalid graph identities.
Its original SHA256 values are retained here for identifying cached copies:

| Crate | Original SBOM SHA256 |
| --- | --- |
| cli | `409bda5dde0b64d59e0f21b55b80cfaef5569d1c6c43f9ecf7d32712df893329` |
| daemon | `7fab248823ff1ba989005f6dc108be3b99f4ee3421d3b9ba9fac9ea17b679dab` |
| gkr-unlock | `c3b9439ba2a0a784a965aa92f32a74260a8827ba2ac00caa99c841f0c651749c` |
| kwallet-init | `af80199dd2947f3c608e4683a45a2bdec6bdb9187bf53cee49a4e85e4178e724` |
| pam | `92d842b6b6f16648acbcbe4039b8a565ce755c3ccae4b6f40c196a59166f4ff5` |
| password-verify | `19515e5d75b335d978300866dfc682509ccd1410e68feb51553c83c339aaa6d7` |

Regeneration uses the verified original v0.13.0 tag at
`fcf03dcaa748e6384c129959097e1a190e34a45d`. It preserves the component inventories
(314 CLI, 199 daemon, 33 PAM, 31 for each wallet helper, and 7 password-verifier
dependencies) and produces valid graphs. Corrections to published historical
metadata are recorded in that release's notes and covered by a fresh signed
manifest and provenance.
