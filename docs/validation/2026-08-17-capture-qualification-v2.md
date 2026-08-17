# Capture qualification v2 hardware validation, 2026-08-17

This is the physical counterpart to ADR 0007. All final qualification and
stress results below ran from commit
`994cb997fdecab696851525c9b43771ab6969f3a`. GitHub was unavailable, so that
commit was transferred to the three remote hosts as a verified Git bundle and
checked out in dedicated detached worktrees. The installed daemon was stopped
only for each guarded run and restored on every exit.

The qualification daemon used an isolated `IRLUME_STATE_DIR`, config directory,
keyring directory, and control socket. It could therefore exercise the exact
production request/status/store path as root without reading or replacing an
enrolled profile or an installed capture qualification.

## Matrix

| Host | Camera and connection | Exact production tuples | Controlled qualification | Selected-schedule stress |
|---|---|---|---|---|
| `UX5406S-Fedora`, kernel 7.1.8-200.fc44.x86_64 | ASUS FHD/IR `3277:0059`, serial `200901010001`; descriptor `e742d2c24ab42fa8ca13330ea94b2715b9b6745dcab9425042b00fc1c37396d7`; UVC interfaces 0/2; `/usb3/3-5`; xHCI controller `/0000:00:14.0`; 480 Mb/s | RGB requested/accepted YUYV 640x480 at 1/30, stride 1280, image 614400. IR requested/accepted GREY 640x400 at 1/15, stride 640, image 256000 | Safe inconclusive: sequential 6/6 with exact contract, rate, continuity, and ActiveIr evidence; concurrent 1/6, with five typed delivered-rate shortfalls. No authority was published, so resolution stayed sequential | PASS, two 60 s sequential phases with recovery; RGB 13.72 Hz, IR 13.95 Hz, zero cumulative drops |
| `HP-ArchLinuxGaming`, kernel 7.1.5-zen1-2-zen | Logitech BRIO `046d:085e`, serial `E179CB54`; descriptor `409892b9451b9f18db9fcccdbd98e3be13846c34e96f9a88dfbfb79648322b2c`; both selected nodes are genuinely under UVC interface 0; `/usb4/4-2`; controller `/0000:0d:00.3`; 5 Gb/s | RGB requested/accepted YUYV 640x480 at 1/30, stride 1280, image 614400. IR requested GREY 640x400 at 1/30; accepted GREY 340x340 at 1/30, stride 340, image 115600 | Measured sequential: sequential 6/6 healthy; bounded concurrent warm-up returned `VIDIOC_DQBUF`, all six concurrent rounds were accounted as capture failures, and a fresh sequential control succeeded. Stored reason `concurrent_unavailable` | PASS, two 60 s sequential phases with recovery; RGB 13.91 Hz with one cumulative drop, IR 28.53 Hz with zero drops |
| `fimerlwi-ThinkPad-X13-Yoga-Gen-4`, kernel 7.0.0-29-generic | Integrated Chicony RGB `04f2:b7bf`, serial `01.00.00`; descriptor `bc9a400100e873b71e6569b84c8979135b1c38837d9db836de422358ad935851`; UVC interface 0; `/usb3/3-4`; 480 Mb/s; no IR endpoint | RGB accepted YUYV 640x480 at 1/30, stride 1280, image 614400 | `no_ir_pair`; daemon selected the RGB-only path and did not invoke camera tuning or an emitter write | PASS, 60 s RGB stress with recovery; 8.90 Hz, zero cumulative drops |
| `minihost`, kernel 7.1.6-1-cachyos | NexiGo HelloCam N930W `3443:c803`, no serial; descriptor `150ea66489d7e6ae04d1dc7c7f65aefd1a10cb8af627c6d668acd0b1b01fd834`; UVC interfaces 0/2; behind `/usb1/1-3/1-3.1`; xHCI controller `/0000:00:14.0`; 480 Mb/s | RGB requested/accepted YUYV 640x480 at 1/30, stride 1280, image 614400. IR requested GREY 640x400 at 1/30; accepted GREY 640x360 at 1/30, stride 640, image 230400 | Measured sequential: sequential 6/6 healthy; bounded concurrent warm-up returned a short YUYV payload, all six concurrent rounds were accounted as capture failures, and a fresh sequential control succeeded. Stored reason `concurrent_unavailable` | PASS, two 60 s sequential phases with recovery; RGB 27.93 Hz, IR 28.56 Hz, zero cumulative drops |

“Healthy” in the qualification column means every completed sequential round
matched the recorded accepted format and interval, cleared its delivered-rate
floor, preserved cross-round continuity, and carried ActiveIr provenance. A
stream merely returning frames was not treated as concurrent authority. That
distinction is why the ASUS result is sequential even though an exploratory
dual-stream stress could keep dequeuing frames: its concurrent IR delivery did
not remain above the licensed floor.

## Commands and evidence

The controlled six-round request was driven through the exact daemon and CLI:

```text
irlume camera-mode
irlume camera-tune --rounds 6
irlume camera-mode
```

The guarded physical runner used the exact commit on every host:

```text
./scripts/hardware/run-slice4-hardware.sh WORKTREE HOST \
  994cb997fdecab696851525c9b43771ab6969f3a RGB IR sequential
./scripts/hardware/run-slice4-hardware.sh WORKTREE HOST \
  994cb997fdecab696851525c9b43771ab6969f3a RGB - rgb-only
```

Raw logs and generated JSON remain on the test hosts under their worktree
`target/capture-v2-qualification-*994cb997*` and
`target/slice4-*994cb997*` directories. They are not committed because they are
machine artifacts rather than product fixtures.

## Hardware findings that changed the code

The first physical qualification run on parent commit `02371ef` exposed two
bugs that software fixtures had hidden:

1. Runtime provenance stores requested and accepted *frame intervals* such as
   1/30. The matcher inverted them as though they were rates, falsely rejecting
   every real frame's exact contract.
2. A failure while concurrently filling the bounded delivered-rate windows
   escaped the probe. On both BRIO and NexiGo that prevented the healthy
   trailing sequential control from turning an unavailable concurrent arm into
   a durable sequential qualification.

Commit `994cb997` corrected both and added executable regressions for exact
interval matching/drift and the failed-warm-up-to-sequential-control transition.
It also repaired the `MACHINE-API.md` check registry table discovered by the
full workspace conformance test.

## Deliberately not claimed

- Same-port unplug/replug and moving an external camera to another physical USB
  path require a person at the remote host. No such action was performed, so
  the runtime-key unit tests—not this matrix—cover generation and context
  invalidation.
- Suspend/resume was not issued remotely because none of these hosts has a
  verified out-of-band wake path.
- No synthetic competing USB load was invented. The real constrained hub/link
  and concurrent warm-up failures above are recorded, but there was no existing
  safe load injector that could guarantee it would touch only test hardware.
- A live concurrent authentication failure followed by successful facial
  recognition on the bounded sequential retry needs an enrolled person in
  frame. The executable auth transition tests cover the state machine; this
  unattended matrix does not claim the genuine-face branch.
- The unprivileged stress helper could not read root-owned legacy emitter
  journals on BRIO and NexiGo and therefore logged the fail-closed warning. The
  exact root daemon qualification used only its normal known-safe path; no
  speculative emitter payload or discovery search was sent. Minihost also
  reported low optical IR brightness despite ActiveIr metadata, so dark-room
  authentication remains a separate emitter/scene validation item.
