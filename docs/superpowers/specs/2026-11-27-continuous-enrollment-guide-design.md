# Continuous enrollment guide

Keep the existing centered, pixel-free guide in one place from the beginning
of enrollment through its result. The user should not have to guess whether
the guide disappeared because a scan started or because something failed.

| Stage | What the panel shows |
|---|---|
| Starting or framing | The existing cue and a marker when the first fresh position arrives |
| Countdown | The countdown above the same guide and progress area |
| OS approval | “Waiting for approval,” without a marker |
| Capture and merge confirmation | “Capturing scans” or the existing merge prompt; show a marker only for fresh RGB observations from this capture |
| Result | Success, refusal, cancellation, or unknown outcome, with no marker. Keep the existing result actions and last captured count. |

Only real enrollment progress advances the count. A missing, stale, unsupported,
or failed observation clears the marker; it never implies a rejected scan or
successful enrollment. Compact and reduced-motion terminals remain text-only.
Maintain the existing one-blank-row separation where the frame fits.

## Approaches

- **Chosen:** keep one view in the TUI and get optional position feedback from
  frames the authorized enrollment already assesses. No second detector call.
- A persistent box with only status text is sufficient during approval and on
  older daemons, but would not show position during capture on a current daemon.
- A second active framing session would compete for camera ownership and is
  not part of this design.

## Boundaries

The capture worker sends coarse `FramingPosition` buckets (`x/y 0..=10`,
`size 0..=2`) plus freshness, only to the explicitly opted-in, non-root,
same-account enrollment connection after its existing active-seat and OS
approval gates. No images, landmarks, identification, liveness data, logging,
or new persistence. No geometry on ordinary enrollment requests, PAM or
login/unlock. Keep the old wire forms and outcomes for both mixed versions.

Geometry is disposable and can be dropped without changing enrollment.
Never open another camera, introduce a new inference, change how captures
are scheduled or accepted, modify current pose/liveness checks, or request
head turns. The guide expires on observations at least 2 seconds old, and
must never show a marker while waiting for approval or showing a result.
Use Rust 1.88.0 and existing Ratatui 0.30.2, with no new dependencies.
Verify on synthetic inputs and in a camera-free VM first; native installation
and live testing are not part of this design.
