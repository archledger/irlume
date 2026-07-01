# Passive EAR liveness — real-world non-response (daemon e2e), 2026-07-01

Follow-up to [2026-07-01-passive-ear-liveness.md](2026-07-01-passive-ear-liveness.md).
That validation (night, indoor lighting, subject at arm's length facing the camera)
measured 10% non-response. This session wired the same detector through the real
daemon path and measured it in *realistic* conditions. Result: the wiring is
correct, but the blink-catch rate collapses to ~19% — unusable — and the cause is
now precisely characterized.

## Setup

- Daemon at HEAD with `IRLUME_MESH_MODEL` wired into the systemd unit
  (`scripts/deploy-passive-ear.sh`); `require_challenge` ON for the test.
- End-to-end trigger: real `sudo` via pam_irlume (interactive TTY), subject
  genuine, no glasses.

## Results

**E2E wiring: correct.** Every attempt logged
`granted=false live=true score=0.69–0.83 (passive liveness: no natural blink...)`
— face match excellent, IR gate Live, the challenge alone withheld the grant, and
PAM cascaded to password. No lockout, no false accept. The mechanism works.

**Non-response: 11/11 sudo attempts** (kitchen, daylight through window), including
5 attempts looking straight at the camera with a deliberate natural blink.

**meshprobe sweep, same day (12 runs × 3 reps, subject blinking naturally each rep):**

| Condition | mesh tracking | EAR open (median-ish) | EAR min per rep | Blinked reps |
|---|---|---|---|---|
| Kitchen, sun on face | n=40/40 | 0.24–0.28 | 0.156–0.206 | 1/12 |
| Living room, dark (no other camera user) | n=0–6/40 | — | — | 0/12 (NoEyes/Uncertain — fail-safe correct) |
| Living room, lamp | n=40/40 | 0.21–0.22 | 0.123–0.161 | 6/24 |

## Root cause

The dip threshold is `0.72 × median` ≈ 0.17 for these baselines. Natural-blink
minima land at **0.12–0.21** — straddling the cutoff by ±0.03. At 15 fps IR,
further halved by `capture_ir_sequence`'s 2-frame de-strobe burst (~7.5 samples/s
effective), a ~150 ms blink contributes ~1 sample, usually mid-closure rather than
at full closure. The depth threshold can't be loosened (banner jitter occupies
0.75–0.90 × median; loosening re-admits the attack — established in the two-cue
analysis). So the detector is *seeing* the blinks but scoring them too shallow.

The dark-room n≈0 runs are a **separate, real gap** (kamoso was closed before each
run — no device contention). In a dark room the only face-lighting is the pulsed
IR emitter; a bystander view of the raw feed (kamoso, which does not drive the
emitter) is black there, while sunlight/bulb ambient IR fills frames in lit rooms.
`capture_ir_sequence`'s de-strobe assumes the emitter lights ~1 of every 2 frames,
but only 0–6 of 40 samples had a detectable face → the effective lit-frame duty
cycle in darkness is far lower (or the emitter control isn't holding across the
stream). Regular auth survives darkness because `capture_ir` takes the brightest
of a ~10-frame burst; the passive window's burst=2 does not. Fail-safe behavior
(no face → never a grant) held throughout.

## Conclusions

1. `require_challenge` stays **opt-in/OFF**. Current depth-dip detector:
   validated-safe (0 false accepts across all sessions) but ~80% non-response in
   realistic daytime conditions.
2. Next detector iteration = **temporal-velocity ("V-shape") detection**: a real
   blink is a sharp consecutive-sample drop-then-recover transient even when its
   *depth* misses the threshold (today's misses at 0.174–0.206 all had the V);
   banner jitter is not a coherent V. Also try `burst=1` (full 15 samples/s) —
   detection-gated per-frame face filtering already rejects the dark strobe frames.
3. The passive window also needs a **dark-room capture strategy**: investigate the
   emitter's real strobe duty cycle / whether it can be held continuously, or
   select frames by brightness within larger bursts (as `capture_ir` does) while
   keeping enough temporal resolution to catch a blink.
4. Any new detector must re-run the banner attack before shipping (the 0.72 depth
   floor is what currently rejects it).
