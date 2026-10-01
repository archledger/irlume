# Issue #795: synthetic preprocessing conformance

The synthetic probe reproduces both source discrepancies: RGB decoding ignores
the range/matrix contract, and PAD preprocessing differs from the recorded m96
scorers. Neither result establishes the cause of the reporter's rejection.

## Reproduce

Run from the repository root. The tools can be committed or run from a newer
checkout; all production/scorer inputs always come from Git objects at
`6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820`:

```sh
python3 benchmarks/preprocessing-conformance/verify.py
```

`run.py` runs the differential experiment alone. `verify.py` runs it twice,
compares stdout byte-for-byte, runs ten unittest controls, Rust formatting and
Clippy, and verifies the six baseline-source hashes. Git whitespace/status checks
are scoped to the experiment directory; unrelated checkout changes are allowed.
The baseline Git objects must be available locally, including in shallow clones;
missing objects or wrong source hashes fail without a checkout-source fallback.
Exact command output
and exit codes are in `checks.json`; numerical output is in `results.json`.

Installed dependencies used: Python 3.14.7, NumPy 2.5.2,
`opencv-python` 5.0.0.93 (`cv2` 5.0.0), Rust 1.88.0, edition 2021. OpenCV uses one
thread with IPP, OpenCL and optimized dispatch disabled; numerical-library thread
counts are one. Rust compiles one dependency-free probe with one codegen unit.
There is no Cargo build or shared target. The historical qualification's exact
OpenCV/NumPy versions remain unrecorded in the inspected scorer material. Today's
run is a version-recorded execution of its source, not an exact historical replay.

The probe compiles the unchanged `yuyv_to_rgb`, `nv12_to_rgb`, `RgbView` and
`pad_vit_input` source fragments. It obtains every input with `git show BASE:path`
and checks its SHA256 against the recorded baseline hash before extraction.
Python AST extraction selects only each baseline scorer's
crop function and five preprocessing assignments, ending before `sess.run`.
The scorer modules are never imported. All frames and bboxes are generated.

`baseline` and `source_sha256` identify the measured source. The separate
`experiment_checkout_revision` and `experiment_tool_sha256` identify the tools'
checkout and exact code bytes, including uncommitted tool edits. A later tools
commit or checkout revision does not change which production code is measured.
These receipts establish baseline-specific quantitative differences only;
they do not certify parity or correctness of current production code.

## Oracle and reproduction controls

The tests cover source replay across checkout revisions and source changes.
They mock only Git transport; Rust compilation and both scorer preprocessing
functions execute. Failure-path tests preseed successful receipts and verify
that repeat mismatches, command failures and executable-launch errors replace
them with current failure records.

Independent non-neutral 709/full and 601/full expected values use the luma
coefficients in Linux 6.10 V4L2 sections 2.17.1-2 and full-range chroma scaling
in 2.17.10. [U3]

For 709/full, separate chroma impulses give the following float64 RGB anchors:

| Y,Cb,Cr | Expected R,G,B |
|---|---|
| 128,192,128 | 128,116.05807760067114,246.2945 |
| 128,128,192 | 228.3935,98.15707760067114,128 |
| 128,64,192 | 228.3935,110.099,9.7055 |
| 128,192,64 | 27.6065,145.901,246.2945 |

These literals were evaluated independently with decimal arithmetic, not by the
oracle under test. For example, Cb=192 gives normalized Cb=64/256=0.25;
709 has Kr=0.2126, Kb=0.0722 and Kg=0.7152, so B is
`128 + 255 * 2 * (1 - 0.0722) * 0.25 = 246.2945`, and G is
`128 - 255 * 2 * 0.0722 * (1 - 0.0722) * 0.25 / 0.7152`.
For the mixed `(128,64,192)` anchor, 601/full instead gives
`[217.3775,104.4125,15.035]`. The tests distinguish matrix, range and chroma order.

## Provenance

- The measured baseline is
  `6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820`, verified on 2026-10-01.
- The recorded scorers are `vit_liveness_score.py` and `vit_live_session.py`,
  introduced by `1354b723883024fac57487fe9afdc56c38326c3b` (#515). Both use the
  m96 margin, integer half-open clipped ROI, RGB8 OpenCV `INTER_LINEAR`, then
  float32 normalization and CHW layout. Their crops and tensors agree exactly
  on all eight cases in this run. [S1]
- `models/SHA256SUMS:6` and both scorers pin
  `c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c`.
  A read-only SHA256 of the existing `models/liveness_vit.onnx` matched that digest.
  It was not loaded into a model parser/runtime or executed. This says nothing
  about the reporter's installed weights.
- The publisher is Adedev-W/LivenessModels-ONNX, inspected at
  `b5930eb8cf9480ef47f9ed5fca3ca62dc587fe55`. Its README and examples specify RGB,
  224x224, rescale 1/255, mean/std 0.5, CHW, real=0/spoof=1. They provide no m96
  crop contract or pinned Python/OpenCV/Pillow versions. The Python example
  leaves Pillow's filter implicit; the C++ example uses OpenCV resize. The local
  scorer is the comparator here, not an inferred training-time resize rule. [U1]
- OpenCV 5.0.0's tag resolves to
  `40738fb16ceddb5fb3fea747585f7ce6abb0605b`; its source verifies half-pixel
  coordinates, source-border clamping and separate fixed-point RGB8 resizing.
  The installed wheel reports `5.0.0-dirty`; tag-source inspection does not prove
  the wheel is bit-identical to that commit. Executed results are tied to the
  installed wheel and settings above. [U2]

## PAD results

Every tensor has 150,528 float32 elements (3x224x224). Pixel-equivalent errors
undo normalization by multiplying tensor error by 127.5; they are not PAD scores.

| Generated case | Max tensor error | Max pixel-equivalent error |
|---|---:|---:|
| Uniform RGB control | 0 | 0 |
| Full 32x32 ramp | 0.0642858744 | 8.1964416504 |
| Fractional interior ramp | 0.0188806057 | 2.4072875977 |
| Integer ROI, black inside/white outside | 1.4115830660 | 179.9768371582 |
| Left/top clipped ramp | 0.0156706572 | 1.9980087280 |
| Right/bottom clipped ramp | 0.0181972384 | 2.3201446533 |
| 512x384 color-step downsampling | 1.9396610260 | 247.3067808151 |
| One-pixel RGB control | 0 | 0 |

For the full 32x32 ramp, the final red value is `243.44644165039062` in Rust
versus `248` in the scorer. Rust clips its upper bound to 31 and resizes an
extent of 31; the reference crops all 32 columns. [S2]

The border-isolation case uses bbox `[24,24,31,31]`, expanded integer ROI
`[18:37,18:37]`. Its entire reference crop is black. Rust's first RGB value is
`[179.97683715820312; 3]`, because bilinear sampling reaches outside the ROI
into the surrounding white pixels. Bounds are integer in this case, so bbox
truncation cannot explain this difference. [S2, S3]

The separate `rgb8_vs_float_resize_only` measurement uses identical reference
crop geometry and changes only the OpenCV input dtype. On the full ramp it
differs by up to `0.005602359771728516` in normalized tensor units. This captures
the RGB8 fixed-point/quantized resize path versus the floating-point path;
fixing crop geometry alone cannot claim exact scorer parity. Large color-step
errors characterize a deliberately discontinuous synthetic image, not a typical
face or model-response bound.

## YUYV/NV12 results

The probe packs 456 YUV triples as tightly packed even-sized YUYV and NV12.
Both extracted Rust converters produce identical RGB bytes. All 256 neutral
full-range ramp points reproduce their input luma. Eight synthetic metadata
tuples cover explicit 601/709 and full/limited ranges, sRGB/JPEG/Rec.709 defaults,
and an explicit 601 override of Rec.709. These tuples label the independent
oracle: no real driver negotiation runs, and production converters cannot accept
these fields. The production burst call site passes only bytes/width/height. [S4]

| Explicit reference matrix/range | Max absolute RGB-channel error |
|---|---:|
| 601 full | 1.5893750000 |
| 601 limited | 21.2148846668 |
| 709 full | 45.8765216023 |
| 709 limited | 58.7179816356 |

These compare integer production output with a clipped float64 reference, before
choosing any output-rounding policy. Samples include luma excursions beyond the
limited nominal range. Full-range chroma uses V4L2's scale of 256, limited range
uses luma 219/chroma 224. The small full-601 discrepancy includes truncated output,
approximate coefficients and full-range chroma scaling; full-601 byte-exact parity
is not claimed. [U3]

Legal limited-range neutral anchors `(16,128,128)` and `(235,128,128)` return
`[16,16,16]` and `[235,235,235]`, instead of black `[0,0,0]` and white
`[255,255,255]`. A chromatic anchor `(128,64,192)` returns `[217,104,14]`;
the full-range 709 reference is `[228.3935,110.099,9.7055]`.
The limited-601 oracle cross-check against OpenCV on legal-luma samples has a
maximum error of `0.5616438356164224` byte units. OpenCV's YUYV conversion is not
used as an oracle for 709 or full range. [U2, U3]

V4L2 defaults resolve YUV sRGB to 601/limited, JPEG to 601/full and Rec.709 to
709/limited. Explicit encoding/range must override those defaults. The installed
`v4l 0.14.0` `Format` exposes colorspace, quantization and transfer but drops
`ycbcr_enc`; preserving that field is required to distinguish a Rec.709 colorspace
with explicit 601 from default 709. No matrix should be guessed from resolution
or camera name. Unknown/unsupported tuples are refused by this probe's bounded
reference resolver; that is not a new production refusal policy. [S5, U3]

## Recommended next correction and gates

The smallest independent next patch is the pure PAD crop/resize helper in vision,
after the maintainer confirms the documented recorded-scorer contract. Adopt
integer half-open ROI bounds, clamp interpolation to that ROI, and reproduce the
RGB8 resize stage before normalization. Use version-recorded OpenCV outputs as
the independent oracle; resolve output rounding explicitly rather than assuming
`round()` reproduces `INTER_LINEAR`. Avoid a new production OpenCV dependency.

Tests should cover the black-ROI isolation, full-frame final row/column,
fractional/negative/edge bboxes, up/downsampling, RGB/CHW constants, RGB8 rounding
and invalid/empty inputs. Replace the existing extent-31 expectation only in the
same corrective patch, with a reference-backed test that fails before the fix
and passes afterward. Do not promote observed wrong values into golden targets.

Handle decoder colorimetry separately from the PAD crop correction:
retain the raw negotiated encoding and validated defaults, carry the resolved
range/matrix to both converters, and test metadata changes and explicit overrides.
Keep full-range support. Add padded-stride/layout and truncated-buffer tests at
the real capture boundary; this packed-buffer probe does not cover them. Bound
unsupported encodings/transfer functions explicitly rather than silently decoding
everything as 601. The wrapper's missing field makes a coefficient-only change
incomplete.

Before deployment or closing #795, separately authorize attended validation on
the reporter's `3277:0055` and affected fleet cameras. Verify exact RGB negotiated
format/colorimetry/stride, firmware metadata credibility, software/model digest,
RGB bbox/crop provenance, and preprocessing revision. Use the complete five-score
authentication path for representative genuine plus print/banner/screen cases;
confirm password fallback. Compare old/new preprocessing under controlled
conditions and the unchanged decision policy. Prior production-path qualification
used current preprocessing, so scorer fidelity alone cannot qualify deployment.
No inference results, threshold evidence or hardware resolution were obtained here.

## Validation receipts

The recorded run passed eight verification commands and ten unittest controls;
repeated JSON stdout was byte-identical. Rust formatting and standalone Clippy
passed. This synthetic verification does not run inference or hardware gates.

Each run writes its commands and results to `checks.json`. `results.json` records
the source hashes, installed versions, tool hashes and checkout revision, so its
whole-file digest changes when the experiment revision changes even if numerical
measurements remain identical. Compare the measurement fields separately when
comparing runs across revisions.

Generated files stay in the ignored `build/`, `__pycache__/`, `results.json` and
`checks.json` paths. The experiment does not change production preprocessing,
thresholds, qualification records or authentication policy.

Prevention lesson: the old extent-31 assertion agreed with its implementation,
so it could not detect reference drift. Keep independent scorer/oracle fixtures,
exact source hashes and execution-version receipts. Uniform colors alone miss
crop-edge defects; include nonuniform and outside-ROI patterns.
Separate measured-source identity from the tools' revision so publishing the
tools cannot invalidate reproduction. Invalidate prior success before starting
a new verification run, and retain failure receipts for post-command checks too.

## Exact source references

All S1-S4 paths refer to Irlume commit
`6ee8ef5ca48f9f1ec7f9ee9b2eac876915a92820`.

- **S1:** `benchmarks/pad-candidates/vit_liveness_score.py:7-22,59-77,80`;
  `benchmarks/pad-candidates/vit_live_session.py:10-12,45-68`.
- **S2:** `crates/irlume-vision/src/lib.rs:1385-1394,1434-1470,1540-1573`.
- **S3:** `crates/irlume-vision/src/align.rs:147-191`.
- **S4:** `crates/irlume-camera/src/lib.rs:5283-5307,10756-10804`.
- **S5:** `Cargo.lock:2895-2908`; `v4l 0.14.0`,
  `src/format/mod.rs:49-75,123-155`.
- **U1:** [Publisher README](https://github.com/Adedev-W/LivenessModels-ONNX/blob/b5930eb8cf9480ef47f9ed5fca3ca62dc587fe55/README.md),
  [Python example](https://github.com/Adedev-W/LivenessModels-ONNX/blob/b5930eb8cf9480ef47f9ed5fca3ca62dc587fe55/Example/ONNX-python.py),
  [C++ example](https://github.com/Adedev-W/LivenessModels-ONNX/blob/b5930eb8cf9480ef47f9ed5fca3ca62dc587fe55/Example/ONNX-cpp.cpp).
- **U2:** [OpenCV resize](https://github.com/opencv/opencv/blob/40738fb16ceddb5fb3fea747585f7ce6abb0605b/modules/imgproc/src/resize.cpp#L4107-L4159),
  also lines 962-963 and 1972-1998;
  [YUV conversion](https://github.com/opencv/opencv/blob/40738fb16ceddb5fb3fea747585f7ce6abb0605b/modules/imgproc/src/color_yuv.simd.hpp#L1018-L1023),
  also lines 1092-1097.
- **U3:** [Linux 6.10 V4L2 colorimetry](https://www.kernel.org/doc/html/v6.10/userspace-api/media/v4l/colorspaces-details.html),
  sections 2.17.1-3 and 2.17.10;
  [quantization overview](https://www.kernel.org/doc/html/v6.10/userspace-api/media/v4l/colorspaces.html).
  Installed `/usr/include/linux/videodev2.h:307-328,366-396` confirms default maps.
