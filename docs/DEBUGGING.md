# Debugging & scrutiny guide

Everything here is for reading irlume's decisions: diagnosing
"face login didn't work", timing a slow verify, or auditing that the system
does what the docs claim. Nothing in this guide can weaken auth: traces log
**numbers only** (scores, thresholds, cue values, timings), never camera
frames, embeddings, passwords, or anything reusable.

## Reading the journal with `irlume logs`

All auth decisions land in the system journal. `irlume logs` shows the whole
story in one stream: daemon lines, the PAM audit records that say what the
greeter actually granted, and the keyring modules a face login feeds:

```sh
irlume logs                     # this boot (sudo if the system journal is hidden)
irlume logs -f                  # live: watch while you test a login
irlume logs --since "20 min ago"
```

How to read the key lines:

| Line | Meaning |
|---|---|
| `irlumed: UnsealPassword: attempt for 'x'` | a greeter/lock asked for a face login (camera fires now) |
| `irlumed: UnsealPassword: OK for 'x' (score 0.8800), password unsealed` | face matched AND the TPM released the sealed password |
| `…face matched … but TPM unseal FAILED` | face was fine; PCR drift kept the keyring locked → `irlume diag`, then `sudo irlume reseal` |
| `audit … grantors=pam_irlume` | PAM's own record that the grant came from face, not password fallthrough |
| `pam_unix(<svc>:auth): authentication failure` with **no** irlumed line before it | a typed (wrong) password; correct on-demand behavior: typing never fires the camera |
| `plasma-kwallet-pam` / `pam_gnome_keyring` lines | the unsealed password reaching your wallet/keyring |

## Per-stage pipeline tracing

The outcome line tells you *what* was decided; tracing tells you *why* and *how
long each stage took*:

```sh
sudo irlume logs debug on       # systemd drop-in + daemon restart
irlume logs -f                  # then test a login / run: irlume verify (IRLUME_DEV=1)
sudo irlume logs debug off
```

A granted IR-path attempt looks like:

```
irlume[debug]: assess: rgb 1280x720 in 412ms, faces=1 top-det=0.93
irlume[debug]: assess: ir 640x360 in 388ms, faces=1 top-det=0.91
irlume[debug]: liveness(cross-spectrum): Live (…); ir_bright=142 ir_depth=1.31 glint=0.42 ambient=41 yaw_asym=0.08 pitch=0.51
irlume[debug]: gate(per-user depth floor): live 1.31 vs floor 1.12
irlume[debug]: match(rgb): best 0.912 vs thr 0.574 (3 scans, best profile 'Face Profile 1')
irlume[debug]: verify 'x' total 1843ms
```

Every gate that can reject prints its measured value next to the threshold it
was compared against, **on pass as well as fail**. A genuine user skating
just above a floor is visible here long before it becomes a false reject. The
dim/dark paths add `match(fusion)`, `match(ir-fallback)`,
`liveness(ir-only/dark)`, and `match(ir/dark)` lines with the same shape. Most
wall-clock time goes to camera I/O; the `assess:` lines show it, which helps
when chasing a slow login. The RGB and IR captures run overlapped on the IR
path, so those two times overlap rather than sum; setting
`IRLUME_SEQUENTIAL_CAPTURE=1` on the daemon forces the old back-to-back order
when isolating a camera problem.

The same switch works per-run for CLI dev tools: `IRLUME_LOG=debug IRLUME_DEV=1
irlume verify`.

Authentication also has a presence grace window: after the consent gesture,
capture attempts repeat while no usable face is in frame, so walking up or
settling into position still works (`grace:` debug lines show the attempts).
The window is per-service: ~15 seconds for login and lock screens (you may be
walking up), ~5 seconds for `sudo`/`su` (you're already at the terminal, so it
drops to the password prompt quickly). Only presence-class failures retry (no
face, off-angle, or the transient "RGB face / no IR face" a user makes while
settling); a below-threshold match or a real spoof verdict settles immediately.
`IRLUME_GRACE_MS` on the daemon overrides both windows; `0` restores the old
one-shot behavior.

**Security note: treat tracing as a diagnostic session, not a resident
setting.** While tracing is on, *denied* attempts log their exact match score
next to the threshold. To anyone who can read the system journal (root or the
`systemd-journal` group) that is an oracle: present a spoof, read how close it
got, adjust, repeat. This is most relevant if you enabled face-`sudo`, where a
compromised user session would be the one reading the journal. Both halves are
privileged (enabling tracing needs root; reading the system journal needs
root/`systemd-journal`), so this does not weaken a default setup, but the
habit that keeps it irrelevant is: turn tracing on, reproduce your problem,
turn it off. With tracing **off** (the default), the journal's denied-attempt
lines are deliberately coarsened: scores quantize to one decimal
(`score ~0.4`) and measured cue values are redacted (`IR too flat
(center/edge …)`). The categorical reason (which gate fired) stays; the
per-attempt gradient goes. The **exact** numbers still reach the one place a
genuine user is being coached through a false reject: the TUI/CLI in their
own session (the IPC reply), which a greeter-side attacker never sees; the
PAM module ignores the reason text entirely. Nothing else changes while
tracing is on: gates, thresholds, and what the daemon will or will not
release are identical.

## Health & config at a glance

```sh
irlume doctor          # platform, TPM, Secure Boot, cameras, models, install origin
irlume login status    # per-service wiring + face trigger mode (on-demand / face-first)
irlume diag            # TPM seal + PCR drift (sudo for detail)
irlume status          # daemon + enrollment state
```

## Exercising PAM without logging out

`pamtester` drives the exact PAM stack a greeter uses:

```sh
sudo pamtester <service> $USER authenticate
```

`<service>` is your greeter's PAM service: `plasmalogin`, `sddm`, `lightdm`,
`greetd`, `gdm-password`, `cosmic-greeter`, or `polkit-1` for app prompts.
`irlume login status` prints the active ones. On an on-demand wiring, press **Enter on the empty password
prompt** to trigger face; type the password to confirm the no-camera path.
Watch `irlume logs -f` in a second terminal.

Expected on-demand matrix (all live-validated):

| You do | Expect |
|---|---|
| wait, touch nothing | **no** camera fire, ever (no ambient scanning) |
| empty password + Enter | camera fires → `UnsealPassword OK` → grant |
| type correct password | no camera; password grants |
| type wrong password | no camera; normal failure prompt |

## Platform checks

- **SELinux (Fedora):** `sudo ausearch -m avc -ts recent | grep irlume` must
  come back empty; the shipped policy covers the confined greeter → daemon socket.
- **KWallet false alarm:** `busctl call org.kde.kwalletd6 … isOpen` can report
  `false` even when your wallet is open; it activates an empty legacy
  `kwalletd6`, the wrong daemon. Query the real one instead:
  `busctl --user get-property org.freedesktop.secrets
  /org/freedesktop/secrets/collection/kdewallet org.freedesktop.Secret.Collection Locked`
  (`b false` = unlocked).

## Fingerprint reader stopped responding

The most common cause is a stale fprintd device claim, and the most common
trigger is suspend/resume: fprintd can hold the reader claimed across a sleep
cycle, after which `pam_fprintd` fails silently and the finger prompt never
appears again (upstream fprintd issues #192 and #216 track this). Symptoms and
checks:

- `irlume doctor` prints a stale-claim warning when it detects the wedge.
- `irlume fingerprint status` reports the listing failure instead of
  pretending no finger is enrolled.
- The fix is always the same: `sudo systemctl restart fprintd`, which releases
  the claim. Enrollment and verification work again immediately.

Two related traps doctor also checks for:

- **pam_faillock in the same stack as pam_fprintd** (Fedora default layout): a
  touch-sensor misread can burn all fingerprint retries in under two seconds
  and every one counts toward the account lockout. Recover with
  `faillock --user <you> --reset`.
- **pam_fprintd reachable from `sudo` plus a running SSH server:** `sudo` typed
  inside an SSH session stalls for the full fingerprint timeout (up to 30
  seconds) waiting on a reader the remote user cannot touch.

`irlume fingerprint reset` deletes every print fprintd holds for the user and
re-enrolls. Use it when fingers list fine but never verify: that is template
desync between the sensor's on-chip storage and the host database, typical
after enrolling in Windows on a dual-boot machine, reinstalling the OS, or a
BIOS "clear fingerprints".

## Per-camera cue tuning

The liveness cues carry per-camera-calibrated thresholds (set on the ASUS and
NexiGo reference hardware). A camera with a different frame rate, noise floor,
or bbox jitter can override them on the daemon unit without a rebuild:

| Variable | Cue | Default |
|---|---|---|
| `IRLUME_RGB_MOIRE_MAX` | screen-replay moiré ceiling (also listed in [SETUP.md](SETUP.md)) | 28 |
| `IRLUME_BLINK_MOTION_MAX` | median head-motion ceiling above which no EAR dip is trusted as a blink | 0.02 |
| `IRLUME_BLINK_CONTRAST_DROP` | minimum eye-region contrast drop for a dip to count | 1.15 |
| `IRLUME_BLINK_CONTRAST_MOTION_FLOOR` | motion level above which the contrast check engages | 0.015 |

`IRLUME_DEBUG_IR` (any value) additionally logs the IR burst's
ambient-subtraction decisions frame by frame.

## Developer / benchmark tools

Gated behind `IRLUME_DEV=1` because they open the camera directly (bypassing
the daemon); they measure, and hold no privileged path:

| Tool | What it does |
|---|---|
| `verify` | one full auth pipeline run in the foreground (pairs well with `IRLUME_LOG=debug`) |
| `liveness` | live liveness-gate probe with cue readout |
| `selftest` | liveness self-test; `selftest align` for the aligner |
| `capture` / `calcapture` | save frames / run a calibrated capture campaign |
| `eval` / `irbench` / `genuine` | accuracy benchmarks over captured sets (see [VERIFY.md](VERIFY.md)) |
| `normprobe` / `meshprobe` | embedding-norm and FaceMesh probes |
| `padcapture` / `padreport` | presentation-attack (spoof) capture + report (see [PAD_SELFTEST.md](PAD_SELFTEST.md)) |

### Measuring capture overlap

The daemon logs per-side capture timings when tracing is on. To measure what
the concurrent RGB+IR capture saves on your hardware:

```bash
sudo irlume logs debug on
# run a few verifies (lock and unlock, or: irlume identify)
journalctl -u irlumed --since -10min > /tmp/irlume.log
scripts/timing-report.py /tmp/irlume.log
sudo irlume logs debug off
```

The report prints per-side capture times and the average overlapped cost (max
of each rgb+ir pair) against the sequential cost (sum). On the ASUS Zenbook
reference hardware the overlap cuts the capture stage from about 1.46s to
about 1.0s per verify.

Reproducing the published accuracy/anti-spoof claims end-to-end is covered in
[VERIFY.md](VERIFY.md).
