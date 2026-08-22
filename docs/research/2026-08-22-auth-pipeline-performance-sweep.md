# Auth-pipeline performance sweep — fleet stage costs

Date: 2026-08-22
Tool: `crates/irlume-auth/examples/stage_bench.rs` (synthetic frames, full
stage calls incl. preprocessing; warmed sessions except the explicitly-noted
first-inference spike). Caveat: sessions built WITHOUT the production
intra-op cap of 2 (thread effects noted below); numbers are self-consistent
across hosts, absolute values may shift slightly under the daemon's thread
config.

## Fleet stage costs (ms, mean)

| stage | ASUS Zen ultrabook | archhost 5700G | minihost N100 |
|---|---|---|---|
| detect grey 640x480 (YuNet) | 9.26 | 7.46 | 15.81 |
| detect rgb 640x480 (YuNet) | 11.70 | 9.45 | 18.95 |
| landmarks (face_landmark) | 6.82 | 6.53 | 12.70 |
| **embed 112x112 (glintr100)** | **149.9** | **106.7** | **255.7** |
| **PAD ViT 224 (liveness_vit)** | **229.8** | **169.2** | **454.3** |
| PAD FLIR 112 (flir) | 3.06 | 2.09 | 5.37 |

## Where one auth actually spends CPU (post-#518, sequential)

Measured e2e (auth_timing): ASUS 7.04s, minihost 8.95s (no-face path).
Adding the inference stages a Live attempt pays (minihost N100 numbers):

- Camera machinery dominates: RGB open+fill+burst 2.2s, IR 5.9s — the
  Windows-Hello dossier directions (pre-arm, persistent sessions, MSXU
  firmware strobe) are the only levers of this size.
- **Consent watch: YuNet runs EVERY frame** (`frame_to_head_pose` →
  `detect_any` per frame; only the gesture classifier is every-6th): on N100
  ~120 frames x 15.8 ms ≈ 1.9 s per watch. This is E1 (detect-track hybrid)
  — the single biggest CPU-side win, and pose comes from YuNet's 5-point
  landmarks, so a tracker only needs to maintain the bbox between
  re-detects.
- **ViT PAD: one inference per Live attempt, sequential post-verdict**
  (the "consent-watch-pipelined" plan note was not how it landed): 454 ms on
  N100 on the critical path. E2 (FLIR-uncertainty cascade) or E6 (INT8;
  N100 has AVX-VNNI) directly attacks this.
- **Embedder x2 (RGB + IR chips): 512 ms on N100.** Follow-up recorded:
  the FRIR evaluation measured AuraFace at 37.98 ms on archhost vs 106.7 ms
  here (different ORT build/venv and thread config) — understanding that
  2.8x gap may be a free win on the second-biggest CPU stage; reconcile
  the measurement conditions before acting.
- FLIR PAD is negligible (2-5 ms). FaceMesh ~7-13 ms.

## Ranked roadmap (measured-leverage order, from this sweep + dossiers)

1. E1 consent-watch detect-track (saves ~1.5-1.9 s N100 / ~1.0-1.2 s others
   per watch; detector frames remain the only gate-state advancers).
2. Camera machinery (pre-arm IR during RGB phase; then persistent
   sequential sessions — design work, slice 4-8 contracts; MSXU
   firmware-strobe investigation enabled by the probe findings).
3. E2 ViT cascade behind FLIR (saves up to 454 ms N100 on confident
   presentations; offline score-pair analysis first) and/or E6 INT8 ViT
   (N100/1335U VNNI hosts; also 343→~90 MB memory).
4. Embedder measurement reconciliation (possible free 2.8x); otherwise
   leave glintr100 fp32 (dossier verdict).
5. E3 session warm-up at daemon start (first-boot spike removal, zero
   risk); E5 spinning/power config on battery hosts.

## MSXU fleet probe findings (msxu_probe, read-only)

- ASUS IR (3277:0059): MS XU unit 14, face-auth sel 06 (info 0x03 GET+SET,
  len 9, def/cur mode 01) + metadata sel 09. Our emitter already writes this
  control (mode 02).
- NexiGo IR (3443:c803): MS XU unit 4 on the IR interface, same contract.
  The RGB interface's MS XU advertises NOTHING — matching the MSXU spec
  (face-auth addresses IR streaming interfaces only).
- **Logitech Brio (046d:085e, archhost): MS XU unit 12 with face-auth 06 +
  metadata 09 advertised, default mode byte 02 (an auth streaming mode) —
  and its /dev/video2 is a GREY 340x340 stream, the Hello-spec IR format.
  archhost is potentially the THIRD dual-capable host, not RGB-only.**
  Activating it needs: discovery/pairing investigation (why it was
  classified RGB-only), emitter validation for the Brio, capture
  qualification. Follow-up, not attempted tonight.

All three cameras also advertise the metadata selector (09) — the
deterministic per-frame lit-bit path (replacing brightest-of-burst
heuristics) is potentially available fleet-wide pending metadata-node
verification.
