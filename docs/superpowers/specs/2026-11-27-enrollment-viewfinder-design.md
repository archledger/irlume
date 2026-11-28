# TUI enrollment viewfinder

## Intent

Help people line up with the camera without having to infer their position
from text alone. Keep the existing cues for direction, pose, distance and
lighting. The viewfinder is not a camera preview or a readiness indicator.

```text
Center your face in the frame    Framing guide
                                 ┌─────────────────────┐
                                 │                     │
                                 │  o      [   ]       │
                                 │                     │
                                 └─────────────────────┘
```

The target stays fixed. The same generic marker moves right when the person
moves right, and gets larger at closer distances. A centered marker does
not imply that pose or lighting has passed. The current cue and countdown
remain more prominent than the marker.

## Approaches

- **Chosen:** Reuse the existing RGB framing sample and send coarse
  position and size to the TUI. The user gets a visual reference without
  video, another camera session, or more capture work.
- **Cue-only:** Keeps the wire unchanged, but the TUI does not know where
  in the frame the face is and cannot move a meaningful marker.
- **Inline webcam video:** Shows exact appearance, but requires a new
  image boundary the owner does not want to change.

## Boundary and behavior

- Existing non-root, active-seat, account-owner framing session only. The
  client asks for the optional guide; the daemon checks eligibility before
  producing it. Root, unnamed and other-account requests receive no new
  data. Legacy single samples do not carry the guide.
- Send only horizontal and vertical buckets `0..=10` and a three-level
  size `0..=2`. No camera pixels, landmarks, identity, additional pose or
  IR data. Nothing new goes to disk, logs, diagnostics, support reports or
  the machine CLI API.
- Show the latest sample through the existing countdown, without advancing
  or resetting it. Clear the marker on no detection, invalid optional
  coordinates, stale data or a failed sample. Clear the panel when
  framing ends, before authorization or scan capture starts.
- Use the existing terminal palette and keyboard flow. Position and size
  must be readable without color. Keep the current text-only flow for
  older daemons, compact layouts and `IRLUME_REDUCE_MOTION`.
- Rust 1.88.0; existing Ratatui 0.30.2; no new dependencies. Do not change
  framing decisions, scan acceptance, capture pacing, camera ownership,
  authorization, enrollment storage, PAM or login/unlock behavior.
- Use synthetic samples for implementation and tests. An attended camera
  trial is separate and requires approval.
