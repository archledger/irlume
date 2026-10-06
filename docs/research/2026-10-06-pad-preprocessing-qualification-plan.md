# PAD preprocessing qualification plan (issue #795)

This plan gates release of the recorded-scorer preprocessing correction for
the ViT RGB PAD input. It is deliberately specific about what evidence must
exist before a release carries the change, because the correction moves every
genuine and attack tensor while the operating point (0.55 deny threshold, the
five-frame median, mandatory PAD) stays fixed. Issue #795 stays open until
the reporter-side causal and acceptance evidence exists.

## What changed and what did not

The change is confined to `crates/irlume-vision/src/lib.rs`: `pad_vit_input`
now performs the recorded m96 scorer's integer ROI crop (float32 box
width/height reconstruction, 96/112 expansion, truncation toward zero,
half-open clip to the frame) and OpenCV's RGB8 fixed-point `INTER_LINEAR`
resize (exact 2x downsample uses the matching area average), quantized to
bytes before `(px/255 - 0.5)/0.5`. The previous fractional crop clamped the
extent one pixel short and a float bilinear sampler fed unquantized samples.

Unchanged: the 0.55 threshold, `VIT_PAD_VOTE_N` (five-score median), the
deny-only role of the RGB PAD cue on the cross-spectrum path (ADR-0013), the
IR PAD cue, all liveness rules, identity matching, password fallback and
privacy behavior. No colorimetry conversion was introduced.

## Contract authority

The target is the local measured comparator (the m96 crop and RGB8
`INTER_LINEAR` resize of `benchmarks/pad-candidates/vit_liveness_score.py`
and `vit_live_session.py`, the scorers behind the 2026-08-21/-22
qualification). This is a selected comparator, not the publisher's training
preprocessing: the model publisher's Python and C++ examples differ from each
other and document no crop rule. Adopting the scorer contract makes the
daemon reproduce the pipeline that generated the shipped operating-point
measurements.

## Evidence already in hand (software)

- Independent fixtures generated from the scorer crop plus the installed
  OpenCV RGB8 `INTER_LINEAR` oracle (Python 3.14.7, NumPy 2.5.2,
  `opencv-python` 5.0.0.93, threads=1, optimized dispatch/OpenCL/IPP
  disabled), pinned in
  `benchmarks/preprocessing-conformance/pad-vit-fixtures-receipt.json` with
  the generator hash and oracle environment. Fourteen frame cases: the
  wave-3 list (full-frame last row/column, black-ROI-on-white isolation,
  fractional, negative and clipped bounds, a one-pixel strip, 224 identity,
  448-to-224 exact 2x downsample, constant channels and the rounding
  counterexample), a 336-to-224 exact 1.5x downscale (only 0.25/0.75
  coefficients), and three crops of a 640x480 frame at the sizes face ROIs
  reach on 640x480 cameras: a 300x260 interior ROI, a 521x463
  right/bottom-clipped ROI and the full 640x480 frame. Two crop-only cases
  pin the float32 m96 arithmetic where float64 truncates to the neighbor,
  and two scorer-wrap cases pin the deliberate zero tensor where the
  scorer's NumPy slice wraps a negative x2 stop into a 526x271 or 586x271
  chip.
- `cargo test` pins, per case, the crop bounds, the RGB8 resize bytes
  (FNV-1a-64 plus probes) and every element of the float32 tensor
  `pad_vit_input` returns (FNV-1a-64 of its little-endian bytes), so CI
  enforces end-to-end bit-exactness on every head. Crop extent and ROI
  isolation fail on the original helper; the 448 case holds 50,176 exact-2x
  rounding-tie blocks that a round-half-even implementation would answer
  differently.
- Mutations run against these tests on 2026-10-06 (archhost copy, never
  committed): f32 coordinate math in the resize passes the original 11
  cases and fails `full_frame_640x480` and `clipped_roi_521x463`
  (`face_roi_300x260` is below 449 px, the smallest ROI side where that
  variant changes any coefficient or offset); f64 margin math passes all
  14 frame cases and the hand-written truncation cases and fails both
  crop-only cases; copying the wrong frame row into one ROI row when the
  ROI does not start at row 0 passes every check that existed before the
  full-tensor hash and fails that hash on 4 cases.
- The current-candidate comparison
  (`benchmarks/preprocessing-conformance/compare_current.py`) compiled the
  working-tree helper and matched the live oracle bit-exactly across all
  fourteen cases (2,107,392 tensor elements, worst absolute delta 0.0). Its
  receipt records the checkout's HEAD, any measured file that differs from
  it and the rustc version. Before merge,
  `compare_current.py --require-clean` runs on a clean checkout of the PR
  head; it refuses to run while any measured file differs from HEAD, so
  its receipt names exactly the commit it measured. That receipt, archived
  with its SHA-256, is the comparison evidence for the head; a
  working-tree run is not.
- The real shipped `liveness_vit.onnx` (SHA-256 pinned in
  `models/SHA256SUMS`) scores the `face_roi_300x260` and
  `clipped_roi_521x463` fixture frames at their recorded p_spoof (0.496063
  and 0.466778, equal to 9 digits under ONNX Runtime 1.28.1 and 1.29.0)
  within 1e-4, and a one-pixel crop shift moves each score by 3.2e-3 to
  3.5e-3. Widening the crop by one column (1.0e-3), dropping the resize
  rounding term (1.4e-4) or copying the wrong frame row (2.5e-4) each
  fails that test; f32 coordinate math (4.4e-6) does not and is caught by
  the fixtures. The uniform-frame test shows determinism and a low score
  only; a uniform frame cannot show a crop or resize change. The vision
  unit suite passes with the real models (99 passed, 0 failed, 4 ignored).

None of this measures genuine or attack scores. Synthetic conformance cannot
establish the deployed operating point on any camera.

## Release gates

A release carrying this change requires, on attended hardware:

1. **Old/new paired genuine series.** For each fleet camera class that
   authenticates today (Zenbook UX5406S `3277:0059`, NexiGo N930W, Logitech
   BRIO), run the real `Engine::assess` with both PAD cues on the old and the
   new preprocessing at close, login and far distance, six genuine
   assessments per cell. Record `face_frac`, `pad-vit: p_spoof` per frame,
   the five-frame median and the verdict. Gate: every genuine presentation
   that lived on the old preprocessing also lives on the new one, and the
   genuine median stays below 0.55 with margin comparable to the old runs
   (fleet historical genuine band 0.27-0.465).
2. **Attack set unchanged or stricter.** Printed photo, phone replay and
   banner presentations at login distance on the same cameras, same protocol
   as the ADR-0013 qualification. Gate: every attack presentation rejected
   on the old preprocessing is still rejected (or the median p_spoof rises);
   no attack presentation crosses from reject to accept.
3. **Reporter unit `3277:0055` acceptance.** The complete five-score
   authentication series on the reporter's Shinetech pair (three attempts
   each at close, login and far distance, with the print presentation
   offered in #795). Gate: genuine lock-screen attempts unlock reliably
   while print/screen/covered-camera attempts keep failing closed. This is
   also the causal evidence #795 needs: if p_spoof drops below 0.55 at the
   measured distances, the preprocessing was a contributing cause; if the
   scores stay near 0.60, the camera's sensor/ISP path is the cause and this
   change alone does not close #795.
4. **Fleet soak.** After installing on both fleet hosts, one attended
   session of lock-screen and `irlume identify` use per host with
   `IRLUME_LOG=debug`, keeping the `pad-vit:`, `attempt:` and
   `liveness(cross-spectrum)` lines. Gate: no genuine denial appears that
   the old preprocessing did not produce.

Failure handling: if any gate fails, revert `pad_vit_input` to the previous
arithmetic (the patch is a single helper region in
`crates/irlume-vision/src/lib.rs`; the fixtures and generator stay as
evidence). The threshold must not be moved to compensate, and PAD must not be
made optional: both would change the security policy that ADR-0013 approved.

## Rollout order

Implement the gates on the branch that carries the patch, in the order
above. Gate 3 needs the reporter's availability; until it runs, #795 stays
open and the change may merge as a gated slice but must not ship in a
release. A camera-qualified PAD calibration record (per-camera deny
thresholds derived from the owner's own genuine and banner runs) remains the
fallback plan if gate 3 shows the two distributions still overlap on
`3277:0055`.
