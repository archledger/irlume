# EdgeFirst TFLite 0.11.1 registry update

Date: 2026-11-07. Tracking issue: #1103.

## Source identity and scope

The published `edgefirst-tflite` and `edgefirst-tflite-sys` 0.11.1 packages
replace the temporary Git revision
`43c7a741818866bd7e4dc209f504430540c8711f`. The reason for that pin and its
original qualification remain in [tflite-zip9-pin.md](tflite-zip9-pin.md).
The old pin already uses ZIP 9; this update does not claim to fix a current
ZIP-8 dependency graph.

Both archives were checked against crates.io's checksums and identify
upstream commit `57120e3afd3908abf19539da76f5edf973206d8e`, matching the
dereferenced `v0.11.1` tag:

| Package | SHA-256 |
|---|---|
| `edgefirst-tflite` 0.11.1 | `78b51ae77d80311356e835829fe72d324f7033d8b7f06f8d82d6c7c06ca434e2` |
| `edgefirst-tflite-sys` 0.11.1 | `3e992e8d4f4b0f7ae18b6aacef45b412fed1a451943b1a30f1c0215bbfdbf1e5` |

Sources:
- [Wrapper package](https://crates.io/crates/edgefirst-tflite/0.11.1)
- [Sys package](https://crates.io/crates/edgefirst-tflite-sys/0.11.1)
- [Reviewed upstream tree](https://github.com/EdgeFirstAI/tflite-rs/tree/57120e3afd3908abf19539da76f5edf973206d8e)
- [Upstream changelog](https://github.com/EdgeFirstAI/tflite-rs/blob/57120e3afd3908abf19539da76f5edf973206d8e/CHANGELOG.md)

## Delta from the Git pin

The model, interpreter, library loader, generated C API loader, XNNPACK
function table, sys build script and vendored downloader are byte-identical.
Existing delegate constructors add an optional custom-state field, set to
`None` for XNNPACK and external delegates. The tensor element-check helper
becomes crate-visible, and the unused HAL error helper becomes feature-gated.

New custom-delegate code and kernel-FFI mirrors compile unconditionally, but
Irlume does not call `Delegate::from_custom`. They add no required symbols to
Irlume's current loading path. Their presence is not qualification for using
custom delegates or for changing the runtime or backend.

The Rust 1.88 minimum, edition 2021, dependency requirements and empty default
features are unchanged apart from the wrapper/sys version selection. LICENSE
is unchanged (Apache-2.0); upstream NOTICE has expanded component information.
That upstream workspace list is not Irlume's resolved dependency graph.

## Irlume integration and graph guards

- Select `edgefirst-tflite = "=0.11.1"` with `default-features = false`.
- Remove only the two EdgeFirst Git patches from the root and fuzz manifests,
  their obsolete Nix Git output hashes and the unused `deny.toml` Git-source
  allowance. Retain the other fork pins and source allowances.
- Pin both registry packages in both lockfiles. Graph tests require exactly
  one entry per package, the reviewed version, the crates.io source and the
  corresponding archive checksum. Keep ZIP >= 9.0.5 and current cargo-deny
  checks rather than adding advisory exceptions.
- Preserve the absolute runtime path, model hash and inline-buffer checks,
  explicit XNNPACK construction, typed Float32 checks, and interpreter-before-
  model destruction order in `TfliteSession`.
- Do not enable vendoring, archive, DMA-BUF, camera-adaptor or custom-delegate
  paths. The packaged TFLite runtime and model files are not updated here.

Cargo changed no other package versions. In the root lockfile it normalized
three Windows-only edges (`errno`, `rustix`, `tempfile`) from `windows-sys`
0.59.0 to the already-locked 0.61.2; each published manifest allows
`>=0.52, <0.62`. The fuzz graph has no other entry changes. This is a
Cargo-generated lockfile change, not a manual lockfile edit.

## Qualification

Before the dependency change, all four existing graph tests passed. The two
updated registry-identity tests then failed against the old Git graph. After
resolution, all seven graph tests passed, including new invalid-identity,
missing/duplicate-entry and ZIP-floor fixtures, on Rust 1.88.0.
Five deliberate regressions of the source, version, checksum, unique-entry
and ZIP-floor guards were caught; the original source was restored exactly.
The vision suite passed 118 tests with four runtime tests deferred to their
explicit lane. All four then passed with the packaged runtime and pinned
public models, including C-API buffer identity and destruction order.
No runtime test was skipped in that explicit lane. All-feature/all-target
vision Clippy and formatting also passed.

Final acceptance also requires the dependency rows in `AGENTS.md`, the full
software gates and the four named pinned-runtime tests from
`hardware-checks.yml`. Run those with explicit runtime/model paths and the
existing `run-tests-guarded.sh --require` names; a skipped model test is not
runtime evidence. Do not substitute real camera or host-TPM activity for the
isolated software checks, and do not infer a performance improvement from
this dependency update.
