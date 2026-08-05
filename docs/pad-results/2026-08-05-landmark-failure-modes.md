# Landmark failure modes: what bad geometry does to the cues that consume it, 2026-08-05

The measurement #276 requires before the detection/landmarks stage can open to
third-party models. A broken or mis-converted detector/landmarker does not
raise an error; it emits coordinates, and the question is what every consumer
answers when those coordinates are garbage. The worked example that motivated
this (2026-08-04, #25 relief work): chin landmarks fell outside a 400-row
frame, the sampler clamped at the border, and two strobe phases "disagreed"
for a purely geometric reason.

- **Instrument:** `crates/irlume-auth/examples/landmark_failure_probe.rs`.
  Synthetic frames, hand-built pathologies, no camera, deterministic; anyone
  can regenerate both tables below with
  `cargo run -p irlume-auth --example landmark_failure_probe`.
- **Pathologies model third-party failure classes, not fuzz:** a different
  left/right labeling convention (`swapped`), landmarks locked onto background
  (`shifted`), coordinates outside or far beyond the frame, a saturated output
  head (`collapsed`), non-finite output from a broken converted op (`nan`), a
  bad detector scale (`tiny`), and a 468-point set whose topology is rotated
  by one index (`mis-indexed`; relevant because the MediaPipe Face Landmarker
  generation has a different point count, 478, and index-contract mismatch is
  exactly what a swap-in risks).
- **Code before:** `86bf9ca`. **Code after:** the guards this document
  shipped with.

## Before: measured on 86bf9ca

Five-point (detector landmark) consumers, IR frame 400x300 with eye disks at
(120,120)/(200,120) and a bright corner hotspot:

| pathology | eye_glint | glint_contrast | both_eyes_open | yaw_asym | pitch_frac | align_to_arcface |
|---|---|---|---|---|---|---|
| nominal | 255.000 | 192.031 | true | 0.000 | 0.500 | Ok (chip bytes 90..180) |
| swapped | 255.000 | 192.031 | true | 0.000 | 0.500 | Ok (chip bytes 90..180) |
| shifted | 27.000 | 3.394 | false | 0.000 | 0.500 | Ok (chip bytes 90..180) |
| offframe | 0.000 | 0.000 | false | 0.000 | 0.500 | Ok (chip bytes 90..90) |
| far | 0.000 | 0.000 | false | 0.000 | 0.500 | Ok (chip bytes 90..90) |
| collapsed | 51.000 | 0.400 | false | 0.000 | 0.500 | Err (degenerate landmark geometry) |
| **nan** | **255.000** | 0.000 | **true** | 0.000 | 0.500 | **Ok (chip bytes 0..0)** |
| tiny | 51.000 | 0.400 | false | 0.000 | 0.500 | Ok (chip bytes 150..180) |

`FaceMesh::landmarks()` against pathological detector boxes (the shipped mesh,
478-point generation):

| bbox | result | finite | inside expanded crop | extent px |
|---|---|---|---|---|
| nominal face | Ok (478 pts) | 478/478 | 478/478 | 122 x 152 |
| zero-area | Ok (478 pts) | 478/478 | 478/478 | 0.000 x 0.000 |
| inverted | Ok (478 pts) | 478/478 | 0/478 | 121 x 126 |
| offframe | Ok (478 pts) | 478/478 | 478/478 | 191 x 198 |
| nan | Ok (478 pts) | 0/478 | 0/478 | -inf x -inf |
| huge | Ok (478 pts) | 478/478 | 478/478 | 1905380 x 1978312 |

## Findings

1. **A NaN landmark reads the frame corner as an eye, in the permissive
   direction.** Rust's saturating float→int cast turns NaN into 0, so every
   pixel-sampling cue centered on a NaN coordinate samples (0,0). With a
   bright corner (emitter bloom is a realistic stand-in), `eye_glint`
   answered its maximum and `both_eyes_open`, the gate behind
   require-eyes-open, answered **true** from landmarks that do not exist.
2. **Alignment accepted geometry that does not exist.** NaN landmarks slid
   through the least-squares similarity fit into a NaN transform, and the
   edge-clamped sampler returned an all-black 112x112 chip as `Ok`; the
   embedder then embeds a chip that came from no face.
3. **The mesh ran on any box and vouched for the result.** Zero-area,
   inverted, off-frame, NaN, and million-pixel boxes all returned a full
   point set as `Ok`, including 478 NaN points and 478 copies of one point.
   Every downstream consumer of those points (EAR, the passive blink gate,
   the alignment refine) received confident numbers.
4. **`head_pose` answers a confident frontal (0.0 / 0.5) for every
   pathology**, including NaN: its degenerate-geometry branches default to
   the frontal answer, which is the permissive one for framing gates. The
   nod gesture is unaffected (it needs motion, and a constant reads as no
   gesture), which the probe confirms.
5. **Measured fail-closed already, no change needed:** off-frame and far
   coordinates sample nothing (0.0 / false); a mis-indexed 468-point
   topology reads EAR 0.0, and the stream consumers (`detect_blink`,
   `detect_deliberate_closure` with a valid calibration, `detect_nod`,
   `calibrate_open_ear`) refuse NaN windows and stuck-constant windows at
   0.0 and 0.05 alike; `swapped` left/right labeling changes nothing (the
   cues are symmetric in the two eyes).

## Guards shipped with this document

- `detection_is_finite`: YuNet detections and the Blaze rescue box are
  dropped at the source when any coordinate is non-finite. A NaN score
  already failed the threshold comparison, but a NaN coordinate with a
  finite score survived decode and NMS.
- `mesh_box_valid`: the mesh refuses non-finite, non-positive-area,
  no-frame-overlap, and larger-than-4x-frame boxes, by named reason.
- `mesh_output_plausible`, applied inside `map_checked_mesh_output`, the
  same call that maps raw output into frame coordinates, so the check
  cannot be skipped without losing the coordinates: non-finite output, a
  point set mostly outside the sampled crop, and a collapsed extent are
  refused.
- The glint cues and `both_eyes_open` fail closed on non-finite eye
  coordinates; `align_to_arcface` refuses non-finite landmarks with its
  existing degenerate-geometry error.

Every caller of `FaceMesh::landmarks()` already treats an error as "no
landmarks", the fail-closed answer for the cues these feed. All guards are
validity bounds (is the input geometrically meaningful at all), not tuned
thresholds; none has a false-reject cost on genuine input, and the
border-overshoot slop (25% of the crop side) keeps a tilted chin from being
refused.

## After: same probe, with the guards

| pathology | eye_glint | glint_contrast | both_eyes_open | align_to_arcface |
|---|---|---|---|---|
| nan | 0.000 | 0.000 | false | Err (degenerate landmark geometry) |

| bbox | result |
|---|---|
| zero-area | Err (mesh refused detector box: not a positive-area region) |
| inverted | Err (mesh refused detector box: not a positive-area region) |
| offframe | Err (mesh refused detector box: no overlap with the frame) |
| nan | Err (mesh refused detector box: non-finite coordinates) |
| huge | Err (mesh refused detector box: area exceeds 4x the frame) |

All other rows are unchanged from the before tables.

## What this does not establish

- Nothing here measures a real third-party detector or landmarker; it
  measures what irlume's consumers do with bad geometry however it arises.
  Opening the stage still needs a measured candidate entry: detection rate
  and landmark accuracy on this project's cameras, live, per the catalog
  rule.
- `head_pose`'s frontal default on degenerate-but-finite geometry remains:
  with the detector-output filter, non-finite input can no longer reach it,
  but a detector emitting collapsed finite landmarks would still read as
  frontal to the framing gates. Recorded rather than changed, because the
  consumers that release credentials (nod gesture) are motion-based and
  unaffected.
- The `tiny` and `shifted` rows produce plausible-looking chips from wrong
  crops; recognition then scores them against enrolled templates, which is
  the deny-direction for an attacker but a false-reject cost for a broken
  detector. That is a quality question for the candidate measurement, not a
  validity gate.
- Single synthetic frame per case; the pixel values are constructed, not
  captured. The confident-wrong findings are about arithmetic (casts, fits,
  mapping), which synthetic frames exercise fully; no claim here depends on
  sensor behavior.
