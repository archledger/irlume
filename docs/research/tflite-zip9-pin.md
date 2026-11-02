# TFLite zip-9 upstream pin (EdgeFirstAI/tflite-rs @ 43c7a741)

Date: 2026-11-02. Tracking issue: #1103. Companion audit for the
`[patch.crates-io]` entries in `Cargo.toml` and `fuzz/Cargo.toml`, in the
tradition of [tflite-0.10.1-audit.md](tflite-0.10.1-audit.md).

## Why the pin exists

Published `edgefirst-tflite`/`-sys` 0.10.3 (crates.io, 2026-10-01) still
require `zip = "8"` in the sys crate's build dependencies. zip 8.6.0 carries
four advisories patched only in zip >= 9.0.0
(RUSTSEC-2026-0367/0368/0369, and RUSTSEC-2026-0429 which broke the
required cargo-deny check on PR #1258), and the GitHub-only advisory
GHSA-m665-v7pm-7grj (Zip Cloaking, no RustSec id) raises the floor to
9.0.5. Upstream `EdgeFirstAI/tflite-rs` merged the move to zip 9 in PR #20
(feature commit `bc7aed2b`, merged main `43c7a741`, 2026-10-28) but has
published no release accepting zip 9 (issue #21 asks for one). The pin
holds irlume on that merged, immutable upstream revision until a release
ships, instead of carrying advisory exceptions for code irlume never
executes.

## Upstream delta review (v0.10.3 tag .. 43c7a741)

Everything that reaches irlume's graph was reviewed before any of it was
executed. The delta touching compiled crate sources is exactly three files:

| File | Change |
|---|---|
| `crates/tflite-sys/Cargo.toml` | build-dep `zip` "8" -> "9" (one line) |
| `crates/tflite/Cargo.toml` | optional runtime `zip` "8" -> "9" (one line) |
| `crates/tflite/src/archive.rs` | +16/-5: zip 9's `file_names()` yields per-name `Result`s (names are now validated), so `ModelArchive::new` collects them eagerly into a `Vec<String>` and maps an undecodable name to `invalid_argument` |

Everything else in the delta is examples, documentation, workflow files,
`.gitignore`, and a `profiling` profile in the root manifest: none of it is
in the dependency graph. `crates/tflite-sys/build.rs` and
`crates/tflite-sys/src/vendored.rs` (the only zip call sites in the sys
crate) are byte-identical to the published 0.10.3 sources, as is the
wrapper's `lib.rs` (so `archive` stays behind
`#[cfg(feature = "archive")]`). `LICENSE`/`NOTICE` are unchanged; both
crates remain Apache-2.0 (Au-Zone), already allowed in `deny.toml`. The
workspace keeps `version = "0.10.3"` and `rust-version = "1.88"`, so
irlume-vision's exact `=0.10.3` constraint still matches and the MSRV is
unchanged.

## Posture after the pin (unchanged from the triage)

irlume-vision selects `edgefirst-tflite = "=0.10.3", default-features =
false` with no features forwarded: the wrapper's `archive` feature (the
only consumer of the wrapper's zip dependency) stays off, and the sys
crate's `vendored` feature (the only consumer of the sys crate's zip build
dependency) stays off everywhere in the workspace. zip 9.2.2 is therefore
compiled as a build dependency, exactly as zip 8.6.0 was, and no zip call
site is compiled into anything irlume ships; the LiteRT library still comes
from `IRLUME_TFLITE_LIB`, never from a download. The `webpki-roots` license
exception's wording ("Cargo compiles it into that crate's build script ...
its code path runs solely under the `vendored` feature irlume keeps off")
remains accurate.

## Resolved graphs, guard and gates

- Root `Cargo.lock` and `fuzz/Cargo.lock`: both tflite crates resolve to
  `git+https://github.com/EdgeFirstAI/tflite-rs?rev=43c7a741...#43c7a741...`,
  still version 0.10.3; zip 8.6.0 is gone and zip 9.2.2 is the only zip in
  either graph (>= the 9.0.5 floor above).
- `crates/irlume-vision/src/lib.rs` carries `tflite_dependency_graph_tests`:
  four tests asserting, per lockfile, that every zip is >= 9.0.5 and that
  both tflite crates resolve from the pinned rev. They failed 4/4 against
  the pre-pin graph (the honest RED), fail again under a raised-floor or
  rev-drift mutation, and pass after the pin. A future `cargo update` that
  regresses zip or drops the patch off the pinned rev fails the test suite
  the same day instead of waiting for a red advisory gate.
- The three zip 8.6.0 advisory exceptions
  (RUSTSEC-2026-0367/0368/0369) were removed from `deny.toml`; no new
  exception was added (RUSTSEC-2026-0429 is gone because zip 8.6.0 is
  gone). The rsa exception (RUSTSEC-2023-0071, #1112) is untouched.
- `nix/package.nix` `cargoLock.outputHashes` gains both tflite keys with
  the single fixed-output hash of the shared repo/rev
  (`sha256-94Ib/o9JeaTwcSfttiv5cupl29y/NnSfifYovZ9Fook=`, taken from
  nix's own mismatch output, not guessed).

Tooling note: `cargo +1.88.0 check -p zip --locked` panics inside cargo's
own feature-resolution code when asked to select a package that exists only
as a build dependency; no irlume gate does that. zip 9.2.2's compilation
under Rust 1.88 is proven by the rlib/rmeta artifacts from the successful
`cargo check -p irlume-vision --all-features --locked` (which runs the sys
crate's build script and therefore builds its build dependencies).

## Restore / update plan

This pin is temporary scaffolding until upstream releases. When
EdgeFirstAI/tflite-rs publishes a release whose sys crate accepts zip >= 9
(watch issue #21 and the crates.io versions feed):

1. Drop both `[patch.crates-io]` tflite entries from `Cargo.toml` and
   `fuzz/Cargo.toml`, and the two `outputHashes` keys in
   `nix/package.nix`.
2. Bump irlume-vision's `edgefirst-tflite` version pin if the release is
   not 0.10.3, and audit the published sources against the pinned rev the
   way tflite-0.10.1-audit.md did for 0.10.1 (the registry package
   identifies its upstream commit).
3. Update both lockfiles and rerun the dependency rows of AGENTS.md
   (cargo-deny root + fuzz, fuzz fetch, the vision all-features check and
   the Nix cargoDeps/onnxruntime builds).
4. Keep the graph-guard tests: they are version-agnostic about how the fix
   arrives and continue to fail on any zip below the advisory floor or any
   tflite resolution that is not the reviewed source.

Until then, a bump of this pin means: pick a new immutable merged upstream
rev, diff its compiled-crate sources against 43c7a741 the way this document
did, and update both `[patch]` revs, both lockfiles and both
`outputHashes` keys together. Never point the entries at a floating branch.
