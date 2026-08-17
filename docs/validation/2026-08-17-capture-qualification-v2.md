# Capture qualification v2 hardware validation, 2026-08-17

This is the physical counterpart to ADR 0007. The four-host qualification and
stress matrix ran from commit
`994cb997fdecab696851525c9b43771ab6969f3a`. The later interactive Minihost
hotplug and enrollment regressions ran from that commit and were repeated from
fix commit `5bdff0ed5df054bb65b83f7990b89f3350785b8b`. GitHub was unavailable, so
the commits were transferred to the remote hosts as verified Git bundles and
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

### Minihost hotplug and USB-path checks

Interactive unplug/replug testing then exposed a lifecycle failure on
`994cb997`. After a same-port replug, the lifecycle worker reported `camera
snapshot never became quiet`, stopped permanently, and left the daemon's
inventory fail-closed even though the kernel had rediscovered the camera. A
daemon restart recovered it.

Commit `5bdff0ed` makes bounded unstable-snapshot and event-storm outcomes
retryable while keeping monitor/socket and inventory failures terminal. On the
same NexiGo and physical path, the exact daemon then survived the unplug,
reported the camera absent while disconnected, and rediscovered both endpoints
after replug without a daemon restart. The runtime generation changed from
context `6d7c62...` to `6f183d...`, while the matching measured-sequential
authority remained applicable.

Moving the NexiGo from `/usb1/1-3/1-3.1` to `/usb1/1-1/1-1.1` correctly changed
the runtime context and resolved to `unqualified_no_authority` with the safe
sequential default. A new six-round qualification on that path produced
sequential 6/6 healthy, concurrent 0/6 capture failures, and a healthy trailing
control before publishing measured-sequential authority. This demonstrates
that link speed alone is not treated as sufficient evidence: both paths were
480 Mb/s, but the physical USB path remained part of the qualification key.

The raw hotplug evidence is retained on Minihost at:

```text
/home/test/irlume/.worktrees/hw-capture-v2-02371ef/target/
  capture-v2-physical-minihost-hotplug-fix-5bdff0ed5df054bb65b83f7990b89f3350785b8b.y4OqbT
```

### Minihost dark-IR enrollment check

The interactive TUI enrollment on `994cb997` also appeared to freeze at the
last countdown second. The daemon repeatedly performed the bounded IR
assessment, found the stream dark, restored the emitter, and restarted the
entire assessment. The preflight result was logged but not carried into the
auth capture policy.

Commit `5bdff0ed` adds a request-scoped RGB-only enrollment policy. It never
changes process-wide IR availability, selects RGB-only only after the known IR
preflight returns a definite dark result, and keeps preflight failures on the
full-assurance IR path. On the same Minihost camera, exact-build TUI enrollment
then completed scan 1 and an AddScan scan 2, each with one bounded dark-IR
preflight followed by RGB capture.

That retest exposed a separate presentation bug: after a successful AddScan,
the TUI displayed the identity-merge confirmation because it interpreted every
`created: false` response as a merge. Commit `cc55d43` limits that confirmation
to the first new-profile request. Its full CLI test suite, strict clippy, and
format checks pass; the presentation-only fix has not yet had a physical TUI
retest.

## Deliberately not claimed

- Suspend/resume was not issued remotely because none of these hosts has a
  verified out-of-band wake path.
- No synthetic competing USB load was invented. The real constrained hub/link
  and concurrent warm-up failures above are recorded, but there was no existing
  safe load injector that could guarantee it would touch only test hardware.
- A live forced-concurrent authentication attempt on Archhost failed over to
  sequential and granted the enrolled person. The matrix does not claim a
  naturally qualified concurrent camera because all three tested RGB+IR pairs
  selected sequential.
- The unprivileged stress helper could not read root-owned legacy emitter
  journals on BRIO and NexiGo and therefore logged the fail-closed warning. The
  exact root daemon qualification used only its normal known-safe path; no
  speculative emitter payload or discovery search was sent. Minihost also
  reported low optical IR brightness despite ActiveIr metadata, so dark-room
  authentication remains a separate emitter/scene validation item.
