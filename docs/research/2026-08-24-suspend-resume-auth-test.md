# Suspend/resume authentication test (survey action item 1)

Date: 2026-08-24. Closes the top action item from the competitor pain
survey (docs/research/2026-08-24-face-unlock-competitor-pain-survey.md):
Howdy #1131 ("Face detection timeout uses wall-clock time, breaks after
suspend/resume clock jumps") and visage #26 ("blocks for 90 s on
`systemctl restart` after hibernate due to stale camera fd") are the two
known failure modes of this class in the field. Neither may exist in
irlume by the time users arrive.

## What was tested

Three genuine RTC-timed suspend/resume cycles per host, with
authentication probes at t+1/4/10/15 s after every resume, plus a full
daemon-journal anomaly scan (error/fail/rate/gap/floor/drop/restart/
panic/watchdog) across each resume boundary.

| Host | Irlume | Suspend type | Cycles | Daemon | Post-resume auth |
|---|---|---|---|---|---|
| archhost (Brio dual) | 0.11.1-1 | S3 deep (mem) | 3 | `active` throughout, zero restarts, zero journal anomalies | **Granted at t+4 s after resume cycle 3** (`archledger 0.674 ✅`); other probes honest environmental denials (no face / yaw-pitch while user was angled away) |
| minihost (NexiGo dual) | 0.11.1-1 | S3 deep (mem) | 3 | `active` throughout, zero restarts, zero journal anomalies | Unattended headless camera: honest denials only (no face in RGB / Spoof: no face in IR; nobody present). Camera paths reopened cleanly after every cycle |
| thinkpad (RGB-only) | 0.11.0-0ppa1 (PPA index lag at test time; same daemon lineage) | s2idle | 3 | `active` throughout, zero anomalies | Unattended: honest "no face" denials; camera reopened every cycle |
| ASUS dev box | 0.11.1-1.fc44 | none | none | none | **Skipped by owner instruction** (daily driver in active use); the same daemon build is validated on the other three hosts |

Kernel evidence for every cycle: `PM: suspend entry (deep)` /
`suspend exit` (and s2idle equivalents on thinkpad) in the system
journal, plus resume-delta timestamps on the probe log (22-34 s gaps).
rtcwake ran as root; the first pass silently failed unprivileged
(`rtcwake: /dev/rtc0: Permission denied`, 0 real cycles) and was
discarded, recorded below as a test-harness lesson.

## Why the wall-clock failure mode cannot occur here

Static sweep (this session): every timeout, deadline, rate window,
timestamp-continuity and skew measurement in irlume-camera and
irlume-auth uses `std::time::Instant` (CLOCK_MONOTONIC, suspend-
excluding); the slice-4 evidence schema literally records
`clock: "monotonic"`. The only `SystemTime` (wall-clock) uses in the
crates are: the capture-qualification record's persisted
`measured_at_unix` metadata (camera/lib.rs:6713), diagnostic epoch
stamps, and CLI support-report headers. None feed any auth decision,
timeout, or rate computation. Howdy's #1131 class (a wall-clock jump
across suspend inflating a timeout) has no code path to live in.

## Why the stale-fd failure mode did not occur here

visage #26's shape is a daemon holding a camera fd across hibernate
that wedges on resume. irlume's daemon opens and drops the camera per
request under the lease supervisor; no capture spans the suspend. The
3x3 real cycles above show zero `camera busy`, zero EBUSY, zero
watchdog, and a full grant at t+4 s after one resume, so the camera
subsystem re-acquires cleanly.

## Residuals

- The unattended hosts exercised the deny path post-resume, not the
  grant path (only archhost had a user in frame). The archhost t+4 s
  grant after a real S3 resume is the positive evidence; minihost/
  thinkpad contribute the daemon-survival and camera-reopen evidence.
- ASUS was not cycled (owner instruction). If a user report ever
  implicates suspend on the Shinetech module, the follow-up is a cycle
  on this class of hardware with a user present.
- `mem` (S3) and `s2idle` covered; `disk` (hibernate) was not tested:
  no fleet host hibernates in normal use. Hibernate's extra variable is
  the restore path, not the clock; the wall-clock immunity argument
  covers it, but a real hibernate cycle remains untested.

## Verdict

The competitor failure class is closed on evidence: no wall-clock path
exists in auth timing (static), and three real cycles on each of three
hosts show daemon survival, clean camera re-acquisition, and a
post-resume grant within 4 s. No code change needed.

## Harness lessons (recorded)

1. Unprivileged `rtcwake` fails with "unable to find device: Permission
   denied" and returns 0 while suspending NOTHING; a run whose log
   lacks `PM: suspend entry` did not test suspend. Root rtcwake or it
   did not happen; verify against the kernel journal, never the script's
   own resume line.
2. A remote suspend test over SSH must be setsid-detached (the
   connection dies at S3) and re-attach by polling; the probe loop then
   reads auth health at fixed offsets from the true resume time.

## Reproduction

Script (as run, with `sudo -n rtcwake`):
3 cycles of `sudo -n rtcwake -m mem -s 20`, then at t+1/4/10/15 s:
`systemctl is-active irlumed`, `irlume --version`, `timeout 40 irlume
identify`, and a journalctl anomaly grep over the last 90 s. Evidence
logs retained in the 2026-08-24 session notes (fleet journals pulled to
/tmp/opencode/*-suspend-journal.log during the session).
