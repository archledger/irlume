# Face-unlock competitor pain survey (Howdy and the field)

Date: 2026-08-24. Method: GitHub Search + REST API pulls against the issue
and PR trackers of every active project in the domain, plus their READMEs.
Reaction counts (`+N`) are the community vote on each item and were read
the same day. Keyword totals are `search/issues` totals over each repo's
OPEN issues unless stated. No claim below comes from memory or secondary
write-ups; every number names its source.

Purpose (per the project owner): find the problems users of existing face
unlock software actually hit, and the features they ask for, so irlume has
them solved before users arrive.

## The field

| Project | Stars | State (2026-08-24) | Shape |
|---|---|---|---|
| boltgolt/howdy | 7,731 | 326 open / 615 closed issues, 189 PRs; last push 2025-07-29 (13 months stale) | Python 2/3, dlib + face_recognition, PAM-invoked subprocess per auth |
| EmixamPP/linux-enable-ir-emitter | 361 | active (pushed 2026-07-26) | Companion tool Howdy users depend on for IR emitters |
| sovren-software/visage | 75 | young (created 2026-02-22), active | Rust PAM + persistent daemon + IR + ONNX; ADRs; benchmarks Howdy's per-auth subprocess at 2-3 s |
| Slimbook-Team/slimbookface | 69 | active, vendor-backed | Graphical face manager on PPA, Ubuntu-centric |
| rushabh-v/linux_face_unlock | 68 | active | Ubuntu scripts, no PAM depth |
| nullpo-head/WSL-Hello-sudo | 1,315 | stable niche | Bridges Windows Hello into WSL sudo (demand signal, not a competitor) |
| Vladush/LinuxCamPAM (27), sett4/chissu-pam (12), philippmeisberger/pam-face (dead 2019), Churro/pam-face-authentication (dead 2015) | | | Smaller or historical |

Howdy is the only one with mass real-world deployment, so its tracker is
the primary pain corpus. visage is the closest architectural sibling to
irlume and is young enough that its tracker is a preview of OUR future
tickets.

## 1. Howdy pain taxonomy, quantified

Of 326 open issues (keyword totals, GitHub search, 2026-08-24):
`install`=176, `camera`=160, `python`=129, `IR`=103, `dlib`=91,
`emitter`=31, `recognize`=36, `dark`=35, `timeout`=35, `lock`=51,
`gdm`=31, `polkit`=16, `slow`=14, `snap`=12.

### A. Installation and dependency churn, the dominant class (54% of open issues)

Every big thread is this class: #960 pip upgrade, #985 pip on 24.04, #954
PEP 668 `externally-managed-environment`, #1038 Python 3.14, #945 Mint 22
Python errors, #923/#781/#787 install failures, #786 `No module named
dlib`, #1084 pybind, #1136 NumPy 2.x crashes, #1082 missing dlib on Arch,
#1090 "Make new release" (+8, releases lag distros), #966/#715 package-me
requests per Ubuntu release, #593/#594 repository-per-distro churn,
README's own note that Fedora stable still needs Python 2 (line 66).
#644 names the worst outcome: "dependency updates break howdy, leaves you
unable to login."

Root cause: a Python program with C extensions (dlib, OpenCV) invoked from
PAM, installed by distro scripts, refreshed by system package updates.

### B. Security posture

- README, "A note on security" (line 158): "in no way as secure as a
  password and will never be... a well-printed photo of you could be
  enough... a more quick and convenient way of logging in, not a more
  secure one." No liveness/PAD ships.
- #1098: face model files world-readable 644 in /etc/howdy/models.
- #397: "Should snapshots be readable for everyone?"
- #957: privilege-escalation question.
- Users asking for a consent gate for years: #218 "Require confirmation
  of recognition" (+13, enhancement/help-wanted) and #1079 "Optional
  confirmation step for sudo (prevent silent camera-based approval)" (+8).

### C. IR, emitters, darkness

`IR`=103 open issues. #312 Lenovo X1 Carbon gen 7 IR emitter (+4);
#1109 documents that ASUS Sonix 3277:0018 emitters are motion-reactive
and linux-enable-ir-emitter may hang the system (our Shinetech 3277:0059
is the same family; our ADR-0016 dark-shutter disclosure covers exactly
this class); #567 asks to integrate linux-enable-ir-emitter (+4 closed);
linux-enable-ir-emitter's own tracker is boot-order races (#48 "Not
working at boot", #1 fd too early), per-device quirks (#269 ThinkBook),
strobe expectations (#11 "it should blink" like Windows Hello), symlink
and multi-device handling (#46, #42).

### D. PAM / desktop integration

#1077 cannot run in polkit (+7); #1013 howdy doesn't work on the lock
screen (+3); #1134 Pop!_OS COSMIC login broken and cannot disable;
#1138 Kubuntu 26.04 Discover store auth error; #1099 KDE neon; #199 login
loops with encrypted /home (+4); #1117 GDM on SELinux-enforcing can't open
the camera (xdm_t denied map on /dev/video*); #1104 GNOME 50 churn;
#1101/#1102 hard-to-install stuck loops; #1085 Dolphin admin auth fails;
#385 journald broadcast spam (fixed in #380, LOG_EMERG misuse).

### E. UX gaps users keep voting for

- #9 (+21, the most-reacted closed issue ever): "Allow normal password
  entry at the same time as face recognition" (asynchronous PAM).
- #456 (+12 open): "Skip facial detection after password entered."
- #389 (+5): a visible "scanning" prompt like Windows Hello.
- #739 (+6): Ctrl+C to cancel recognition.
- #1131: timeout uses wall-clock time, breaks after suspend/resume.
- #692 (PR): retry more when no frame is readable.
- #141: disable only for initial sign-in.

### F. Performance and architecture

visage's README measures Howdy's shape: "Python subprocess per auth
attempt, 2-3 s". Howdy users asked: #99 "Any plans to speed up
recognition?" (+4), #1132 "Persistent secure daemon to reduce per-auth
startup latency", #1073 CUDA shouldn't be required, #887 GPU-when-CNN-false,
#249 GPU enablement.

### G. Reliability, the brick class

#644 dependency update bricks login; #1112 pam_howdy.so segfaults on Mint
(users fall back to pam_exec); #968 BrokenPipeError on unlock (+15, top
closed); #1121 ffmpeg backend crash; #1136 NumPy 2.x crash; #1127
IndexError. Pattern: a memory-unsafe/interpreted stack running in the PAM
critical path.

### H. Feature requests, ranked by reactions

1. Consent/confirmation gate (#218 +13, #1079 +8, #1076 active-liveness
   component).
2. Packaging: Flatpak/Snap (#356 +8), per-distro (#966, #1097 ETA PPA for
   26.04, #1034 Void, #151 Gentoo).
3. Keyring unlock after login (#1092 +5).
4. TPM integration (#1115 +6).
5. Hello-style scan prompt (#389 +5); cancel (#739 +6).
6. Continuous retraining (#342 +5); newer models (#937 deepface, #1060).
7. Translations (#486 +10, help wanted).
8. WebAuthn/passkey platform authenticator via face (#1125, PR).
9. Multi-camera auto-switch (visage #77), dual-IR centering (#1096).
10. Snapshot visibility (#226 "record faces that fail?"), guides (users
    shipping their own install guides for Fedora 43/44: #1066 +10, #1135).

## 2. What the sister projects prove

visage (our closest sibling, same design goals) is already collecting:
stale camera fd blocking 90 s after hibernate (#26), missing .deb in the
release (#75), NixOS build breaks (#69, #38), empty AUR repo (#24),
verification failing on long sessions until daemon restart (#48),
a threat-model claim ("no network access") no unit directive enforced
(#78, closed), and hardware-compat docs rotting (#84, #85). Every one of
these is a lane irlume already runs or has already hit and fixed.

slimbookface: all frames too dark on IR (Executive model, #15); IR enroll
only works after RGB enroll (#14); distro template exceptions (#11);
encrypted-/home breaks it (#8, same class as Howdy #199); per-release
compat churn (#16, #13, #9); Fedora/universal packaging request (#7);
Arch request (#2).

## 3. Mapping to irlume: solved by design, or gap

| Their pain | irlume today | Verdict |
|---|---|---|
| Install/dependency churn (54%) | Rust binaries, pinned ORT + bundled models, 5 packaging lanes, signed release fallback in install.sh, no interpreter in the auth path | Solved; keep the "no system Python ever" line |
| Photo spoofing (README admits) | PAD default-on: ViT RGB print-species + FLIR IR (ADR-0013), fail-closed every path | Solved and shipped |
| Consent gate (#218/#1079) | Typed-`yes` intent gate for privileged auth (ADR-0010/0011), root/daemon gate before camera | Solved |
| Model files world-readable (#1098) | Templates encrypted at rest, TPM-sealed, 0600 root | Solved |
| Per-auth subprocess latency (#99/#1132) | Persistent daemon, socket-activated, models loaded once; ~7.6 s cold but ~2-3 s of that is capture; overlapped TPM unseal (#517) | Mostly solved; latency work continues |
| Password+face simultaneously (#9 +21) | Single-field `yes`-or-password handoff (ADR-0011) | Solved |
| Camera running after password (#456) | Intent gate + plaintext deny-before-camera precedence | Solved |
| IR emitter boot races (LEIE #48/#1) | Emitter journal + undo records + restore-on-open, MSXU/D1 handling, qualification | Solved |
| Dark IR / dark rooms | SecureDark (ADR-0016), emitter proven in true dark (stage 3) | Solved |
| PAM/DE churn (gdm/lock/polkit/COSMIC) | login enable + reconcile path/timer self-heal units; KDE/GNOME tested; SELinux package shipped | Solved for shipped lanes; COSMIC untested |
| Encrypted /home loops (#199) | State under /var/lib/irlume, TPM-sealed, not $HOME-dependent | Solved by design |
| SELinux camera denial (#1117) | irlume-selinux package, enforcing-host validation | Solved |
| Dependency update bricks login (#644) | Password fallback always; deny = fallback, never lockout; fail-closed direction audited | Solved |
| pam segfaults (#1112) | Rust PAM wrapper via the maintained pam_sm_rust fork; panic containment on every C boundary | Solved |
| journald broadcast (#374/#380) | Never used; per-request SO_PEERCRED socket | Solved |
| Wall-clock timeout after suspend (#1131) | CLOCK_MONOTONIC everywhere (slice-4 evidence records `clock: monotonic`) | Solved; add an explicit suspend/resume auth test (below) |
| No release / per-distro lag (#1090) | Four lanes cut the same sitting, storefront text updated per release skill | Solved |
| Multi-user/profiles | profiles (multi-profile, per-user floors) | Solved |
| Headless/remote | Remote-session guard fails closed (SSH markers) | Solved |
| Stale fd after hibernate (visage #26) | Not verified for us | GAP: suspend/resume fleet test |
| Continuous retraining (#342) | None; enrollment is explicit, per-user floors recalibrated by re-enroll | GAP (deliberate? security tradeoff to write down) |
| Visible scan prompt (#389) | TUI shows capture state; PAM prompt is echo-off `yes` field | PARTIAL: greeter-side scan feedback not designed |
| Cancel recognition (#739) | Not mapped to a key | GAP (small) |
| Keyring unlock (#1092) | Armed keyring + kwallet/gkr helpers | Solved (under-marketed) |
| TPM (#1115) | pcrlock Tier 2, template keys | Solved (under-marketed) |
| Translations (#486) | English only | GAP (low priority until users arrive) |
| Flatpak/Snap (#356) | Not applicable to a PAM daemon; document why | DOCS |
| Immutable distros (Silverblue #594) | RPM lanes untested on layering | GAP: test once |
| WebAuthn/passkey via face (#1125) | Not built | Frontier: fits the TPM keyring direction |
| Hardware compat table | README asks for reports; no published matrix | GAP: publish one (learn from visage #84's rot: generate it from telemetry we already log, not by hand) |
| Model modernization (#937/#1060) | Single-model policy (ADR-0015); evaluation lane exists (FRIR/FLXC/ViT all evaluated 2026-08-21/22) | Solved as policy; keep publishing evaluations |

## 4. Action items, ranked

1. Suspend/resume fleet test (their #1131, visage #26): authenticate
   immediately after resume on all four hosts; verify no wall-clock or
   stale-fd behavior. Cheap, closes a class before any user hits it.
2. Publish a hardware compatibility matrix generated from evidence we
   already capture (camera identity, capture mode, emitter control,
   works/fails), not hand-maintained. Howdy's and visage's compat docs
   both rotted; ours must be generated or it will too.
3. Market what we already solved that users are literally voting for:
   consent gate, keyring unlock, TPM sealing, password fallback, no
   interpreter in the auth path. These are README/storefront headlines in
   every competitor's tracker (Howdy #218 +13, #1092, #1115), and ours
   are shipped defaults, not roadmap items.
4. Write down the continuous-retraining decision as an ADR position
   (explicit enrollment only, why: adaptive enrollment is a known PAD
   weakening vector; offer guided re-enroll instead). Users will ask
   because Howdy users asked.
5. COSMIC greeter + immutable-distro one-shot tests (Pop!_OS #1134 class,
   Silverblue #594 class) before anyone files them.
6. Small UX items with big vote counts in their trackers: a cancel affordance
   during scanning, and a documented "how do I turn it off per-surface"
   page (Howdy #141 class: our `login disable` + per-surface tiers exist;
   document them together).
7. Track visage. It is the only architecturally comparable project, it is
   moving fast, and its tracker is a free preview of our next bugs
   (hibernate, long-session verification, packaging edges).

## 5. Sources

- boltgolt/howdy: repo meta, README (security note line 158, Fedora
  Python 2 note line 66), 326 open / 615 closed issues, 189 PRs; top
  issues by reactions (open and closed), 60 most recent issues, keyword
  totals; issues #9, #218, #342, #356, #389, #456, #567, #644, #692,
  #739, #786, #887, #927, #954, #960, #968, #985, #99, #1038, #1066,
  #1073, #1076, #1077, #1079, #1085, #1090, #1092, #1094, #1096, #1098,
  #1104, #1109, #1112, #1115, #1117, #1121, #1125, #1127, #1131, #1132,
  #1134, #1136, #1138; PRs #380, #528, #692, #709, #719.
- EmixamPP/linux-enable-ir-emitter: meta + top issues #1, #10, #11, #18,
  #42, #46, #48, #269.
- sovren-software/visage: meta, README (Howdy benchmark quote, ADRs,
  security policy), issues #24, #26, #33, #38, #48, #49, #69, #75, #77,
  #78, #84, #85.
- Slimbook-Team/slimbookface: meta + issues #2, #4, #5, #7, #8, #9, #10,
  #11, #12, #13, #14, #15, #16, #17.
- GitHub repository search for the field enumeration (queries:
  "face authentication pam", "face unlock linux", "pam face recognition",
  "windows hello linux face"), 2026-08-24.
