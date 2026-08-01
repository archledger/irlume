# Changelog

All notable changes to irlume are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`fingerprint enable` says which prompts a finger actually answers, instead
  of implying all of them.** The gate before recording the method asked only
  "does an active `pam_fprintd.so` line exist in some live stack" — the right
  gate (face must not stand down while nothing drives a prompt) but the wrong
  report: on the issue-#155 Ubuntu box the only carrier was `gdm-fingerprint`,
  so the success message promised finger unlock on a machine whose sudo and
  console login had no fingerprint path at all. `enable` (and
  `fingerprint status`) now print per-surface coverage — login screens, lock
  screens, console login, sudo — resolved the way libpam actually evaluates a
  stack: `auth include`/`substack` chains followed transitively, the Debian
  `@include` form included, non-auth includes contributing nothing, and
  include targets opened by name even when dotted (each behaviour pinned by
  experiment against `pam_exec.so`; the authselect templates confirm Fedora's
  `with-fingerprint` lands in `system-auth`, which is why one line covers
  nearly everything there and one line covers almost nothing on the Ubuntu
  layout). The gate itself is unchanged, so the documented Arch flow — add the
  line to `system-local-login`, re-run — still enables, and now states that it
  covered console login and not sudo. When the line reaches none of the
  tracked surfaces, the report says that too. A file using backslash line
  continuations contributes nothing to coverage — libpam joins those lines
  before tokenizing, so a physical line that looks like an auth fingerprint
  line can be the tail of another directive's arguments (verified: the spliced
  line never ran), and under-reporting is the safe direction where
  over-reporting is the defect this exists to fix. Closes #155.
- **The wallet hand-off check was blind to the fingerprint path.** It anchored
  on the face `unseal` line, but the post-auth `keyring` line releases the same
  sealed password — and on a fingerprint-only box the greeter carries ONLY that
  line, so a missing or mis-ordered wallet module after a fingerprint login was
  never reported: the wallet stayed locked with nothing naming why. The check
  now anchors on the first credential-releasing line of either mode, and its
  warning names both methods. Verified against the KDE sources while at it:
  Plasma's login greeter authenticates through the single `plasmalogin` stack
  (its PAM backend has no fingerprint service; kscreenlocker's `kde-fingerprint`
  triple is the lock screen only), so the greeter `keyring` line is exactly
  where the KDE cold-boot fingerprint→KWallet chain runs — new tests pin that
  the line lands above `pam_kwallet5.so` on every upstream plasmalogin layout.

- **A stack using backslash line continuations is refused, not corrupted.**
  libpam's line assembler joins a directive ending in `\` with the next
  physical line before tokenizing (whitespace after the backslash does not
  defuse it; a backslash ending a comment does not continue — all three pinned
  by experiment against `pam_exec.so`). irlume edits stacks line-by-line, so
  on such a file every matcher reads a different unit than PAM evaluates, and
  inserting a stanza directly after a continued anchor would splice irlume's
  text into the middle of the neighbouring logical line — corrupting the auth
  stack on write. Continuations are now detected up front: the wiring
  transforms decline the whole file (staged, never written — the same contract
  as a missing anchor) and the keyring hand-off advisory stays silent rather
  than judging lines PAM does not see as written. No upstream `plasmalogin` or
  `gdm-password` stack uses continuations, so behaviour on real systems is
  unchanged; a test now pins that assumption too.

- **A module named only in a comment counted as configured.** libpam strips a
  trailing `#` comment before tokenizing a stack line, so `auth required
  pam_unix.so  # was pam_irlume.so` loads no irlume module at all. Every
  matcher compared against the raw line instead, and disagreed with the thing
  it configures. The consequences ran from cosmetic to silent: an invented
  anchor, a keyring consumer that does not exist, and — because
  `content_has_module` gates the whole wiring path — a stack whose comment
  merely mentioned `pam_irlume.so` reported as already wired, so `login
  enable` wrote nothing and said it succeeded. All ten matchers now compare
  against the directive, exactly what PAM tokenizes. The `# irlume-landing`
  and `# irlume-keyring` tags are still matched on the raw line, since being
  comments is the whole point of them.

- **A keyring module that stands down for the service was counted as if it
  worked.** `pam_gnome_keyring.so` takes `only_if=<comma,separated,services>`,
  and for any service outside that list every one of its entry points returns
  `PAM_SUCCESS` immediately: it reads no token, stashes nothing, unlocks
  nothing. The hand-off check matched the module name alone, so such a line
  counted as a working consumer — reporting a wallet that would open when
  nothing would, which is the one thing this check exists to prevent. It also
  suppressed the consumer irlume adds to a fingerprint stack, silently undoing
  that unlock. The list is now evaluated per service, matching whole
  comma-separated items the way gkr-pam's own `evaluate_inlist` does, so
  `only_if=gdm` no longer satisfies `gdm-fingerprint`. `pam_kwallet5.so` has no
  equivalent option, so only the GNOME case narrows.

- **Fingerprint keyring unlock never wired on GNOME, and could not have worked
  if it had.** Two defects in one stack. The wiring anchored on a literal
  `pam_fprintd.so` auth line, but GDM's `gdm-fingerprint.pam` never names the
  module — it delegates to `auth substack fingerprint-auth` — so the anchor
  search found nothing and the whole step became a silent no-op: `login enable`
  reported success and wrote nothing. And had it wired, the stack carries no
  keyring module at all, so the released password would have gone to a stack
  with no consumer. The anchor now recognizes a fingerprint substack or include
  as well as the literal module, and when the stack has no keyring consumer of
  its own the two `pam_gnome_keyring.so` halves it needs are added alongside.
  Those added lines are tagged so unwiring removes exactly ours and never a
  distro-shipped keyring line, and carry PAM's leading `-` so a machine without
  gnome-keyring installed is unaffected. Face login was never involved.

- **A renamed shared PAM stack no longer drops the face block onto the wrong
  line.** The greeter block anchored on a fixed list of stack names
  (`password-auth`, `system-auth`, …) and, failing that, on the first `auth`
  line — a guess that puts the `success=1` jump above whatever module happens to
  come first. GDM's development branch renames its shared stack to
  `gdm-password-auth-substack`, which no name matches; the guess would then have
  anchored above `pam_selinux_permit.so` and landed the jump *before* the
  password substack, which still runs. No released GDM ships that rename, so
  this was latent rather than live, but it would have arrived silently with an
  upgrade. Any `auth … substack …` line is now preferred over the guess,
  whatever the stack is called — a substack is atomic for jump counting, so the
  jump form stays correct — and the first-auth-line guess is kept strictly last.

- **openSUSE greeters anchored face auth on the wrong line, skipping the
  nologin gate.** openSUSE's `plasmalogin` routes the password through
  `auth substack common-auth`, a stack name the wiring did not recognize, so it
  fell back to the first `auth` line and inserted the `success=1` jump above
  `pam_nologin.so`. A face match then jumped over the nologin gate and landed
  *before* `substack common-auth`, which ran anyway: face auth that neither
  honoured nologin nor spared the user the password. The auth and session stack
  names are now kind-aware and include openSUSE's `common-auth` and
  `common-session`, so the jump anchors on the password substack (atomic for
  jump counting, so the jump form stays correct) and `pam_nologin.so` keeps
  running first. A bare `auth include common-auth` is treated as an include
  instead, taking the `sufficient` form a jump cannot skip.

### Added

- **`login status` says when face login releases a password nothing will use.**
  Wiring the greeter and arming the keyring is only half the KWallet path: the
  released password still has to be read by `pam_kwallet5.so` (KDE) or
  `pam_gnome_keyring.so` (GNOME), from an auth line BELOW irlume's, with a
  matching session line to start the wallet daemon. When that module is absent,
  or sits above ours where it runs before the token exists, the face login
  succeeds and the wallet prompts anyway — and every command still reported the
  greeter as `● wired`, so the one symptom the user could see pointed away from
  the cause. `login status` and `login enable --apply` now inspect each wired
  greeter and name which half is missing. Advisory only: it changes no stack and
  fails no command, because an absent wallet module is a packaging choice rather
  than a broken wiring.

- **A dark or blinded IR capture reports what its evidence supports.** A dark
  burst used to get one hint ("no active emitter; run `sudo irlume ir-setup`")
  even though shutters, covers, range, exposure and emitter failures all
  produce similar frames. The capture path now reports from the camera's
  per-frame illumination metadata, the privacy control, the emitter-control
  state and the frame's mean and spread (its pixel standard deviation): it
  names an engaged shutter,
  separates frames the camera marked illuminated from a requested mode it
  never reported as illuminated, and reserves `ir-setup` advice for the one
  case with no active emitter. Illumination metadata is never treated as
  proof of optical output: a failed LED and a subject out of range read the
  same, and the diagnosis says so. The most common measured cover case was
  not dark at all: an opaque cover under an active emitter produced a
  saturated, nearly constant frame (measured 252.8 to 255.0 on the two test
  cameras, against a standard deviation of 35 and up for every recorded real
  scene), so that
  signature is named too. And `IRLUME_IR_EMITTER=off` now silences this
  output, which the old hint's own text promised while printing anyway.
  Closes [#185] and [#197].

- **Emitter-mode crash recovery for recorded capture writes.** Before
  changing the camera's control, the capture path writes a per-camera stream
  record and confirms it once the camera accepts the write; a later daemon
  claims a confirmed leftover and finishes the interrupted restore, with
  claims counted and capped. The guard arms with the value the write actually
  displaced (one read, no window for another client's value to be lost in),
  and it holds the camera handle itself, so a restore cannot land on a
  descriptor number the kernel has recycled. The bookkeeping is deliberately
  best-effort: when its lock, record write or confirmation is unavailable,
  irlume warns and drives the emitter without crash recovery rather than
  turning a full disk into a failed login, so a kill in that degraded path
  can still strand the mode. Closes [#188], [#189] and [#190].

- **`doctor` names each camera node's backend.** `(uvcvideo, USB)` for the
  case irlume is built and tested for; the driver, the bus and a warning for
  anything else; and a visible "backend unknown" when the observation fails.
  Read from `VIDIOC_QUERYCAP`, the interface's own answer. This is the first
  question of every camera bug report ([#187] had to collect it by shell
  script), answered by the tool that should have known.

### Fixed

- **`ir-setup` refuses to write camera firmware while the privacy shutter is
  engaged.** With the shutter shut the sensor substitutes a blank frame, so
  discovery measured a constant, learned nothing from every exploratory write,
  and told the user their camera "advertises no usable emitter control". Setup
  now refuses up front when the shutter is engaged, and also when the privacy
  control cannot be read at all ("could not read the switch" is not "the
  switch is released"); it re-checks immediately before each exploratory
  write, because the operator can engage the shutter mid-run; and restores are
  never blocked. Closes [#186].

[#185]: https://github.com/archledger/irlume/issues/185
[#186]: https://github.com/archledger/irlume/issues/186
[#187]: https://github.com/archledger/irlume/issues/187
[#188]: https://github.com/archledger/irlume/issues/188
[#189]: https://github.com/archledger/irlume/issues/189
[#190]: https://github.com/archledger/irlume/issues/190
[#197]: https://github.com/archledger/irlume/issues/197

## [0.7.2] - 2026-07-30

Fixes a camera-firmware hazard present in 0.7.1. Please upgrade.

### Added

- **A login transaction the desktop can carry out, confirm and undo.**
  `irlume login plan|apply|verify|rollback --json` lets an integration make one
  specific PAM change, check it landed, and put back exactly what was there
  before. A record is written before the first PAM write and confirmed after, so
  a crash mid-apply leaves something that says how to get back; rollback restores
  only while every file is still exactly as apply left it, and refuses rather
  than reverting an edit the transaction never made. Every irlume path that
  changes PAM now holds one lock for the whole operation, writes durably, and
  refuses a PAM path that is a symlink or has more than one hard link. Closes
  [#108].

- **`auth-test-events`**: `irlume auth test --events=jsonl` streams whether the
  claimed account's live face matches its own enrolment, as newline-delimited
  JSON. Verification against one account, never identification, and it releases
  nothing.

- **`login-plan-json`**: what `login enable` or `login disable` would change,
  without changing anything.

### Fixed

- **`IRLUME_IR_EMITTER` wrote to the camera with none of the checks 0.7.1 added.**
  0.7.1 stopped irlume guessing its way around a camera's extension units, but
  left one path exempt: the override applied its bytes before irlume had read the
  camera's descriptor at all, so an arbitrary payload went to an arbitrary unit
  and selector on whichever device was open. No GUID, no check that the unit
  exists, no check that the selector is advertised, no `GET_INFO`, no length
  bound, no read-back. This is the same kind of unchecked write that preceded the
  camera in [#159] no longer enumerating on the USB bus, and it remained reachable
  in 0.7.1. Which payload or sequence caused that camera's permanent failure was
  never established, and nobody should establish it experimentally.

  Two things made it worse than a documented escape hatch. irlume advertised it:
  the hint that printed when infrared looked dark told the user to set it, which
  is precisely when someone is guessing. And it was not one write. `enable` runs
  every eighth frame of every capture, so an override in `irlumed`'s environment
  re-sent the payload for the life of the daemon; in #159 the writes continued
  after the device had stopped answering.

  The override still exists and may still name a vendor's unit rather than
  Microsoft's, because cameras with no Microsoft unit are the case it exists for.
  It is no longer exempt. The camera's descriptor must publish that unit and
  advertise that selector, `GET_INFO` must say the control accepts a write,
  `GET_LEN` must agree with the payload's length, and `GET_CUR` must answer;
  irlume refuses and says which check failed otherwise. It is applied at most once
  per camera per process, and not at all if the control already holds the value.
  Reported as [#179].

  A value that is set but unusable no longer reads as no value. Both a parse
  failure and a non-text value became "no override", which meant carrying on to
  the built-in table, so one mistyped byte in an override written to *replace*
  that payload made irlume write the payload instead, every eighth frame, and
  say nothing. A malformed value now drives nothing and prints what it could not
  read.

  The dark-infrared hint told users to run `linux-enable-ir-emitter configure`.
  That tool finds a control by writing invented payloads until the picture
  brightens, which is the search irlume removed from its own code after [#159].
  It now points at `sudo irlume ir-setup`, which works from what the camera
  publishes.

[#179]: https://github.com/archledger/irlume/issues/179

- **Infrared frames were called lit by guessing from brightness.** irlume averaged
  pixels against a fixed threshold of 40 out of 255. Measured on an ASUS Hello
  module across 2160 stationary frames, exactly one configuration makes that
  threshold correct: sitting close to the camera without glasses. At arm's length,
  or simply wearing glasses without moving, every emitter-off frame was
  misclassified. irlume now reads the camera's own illumination flag, the one
  Microsoft's UVC extension publishes per frame, instead of inferring it. Closes
  [#167].

- **Six checks reported success having checked nothing.** One theme in six places:
  a zero-match, zero-iteration or zero-sample case indistinguishable from a clean
  pass — a conformance run that attempted nothing and exited 0, a set comparison
  where no line carried the field, a `zip()` over an empty side. Each was proved
  by reproducing the failure first. Closes [#161], [#162], [#163], [#164], [#165]
  and [#166].

- **A CI lane could select tests by name and run none of them.** `cargo test
  <names>` exits 0 when the filter matches nothing, so a renamed test turned a
  lane into a green no-op, and the coverage jobs were vulnerable the same way.
  Closes [#158].

[#108]: https://github.com/archledger/irlume/issues/108
[#158]: https://github.com/archledger/irlume/issues/158
[#161]: https://github.com/archledger/irlume/issues/161
[#162]: https://github.com/archledger/irlume/issues/162
[#163]: https://github.com/archledger/irlume/issues/163
[#164]: https://github.com/archledger/irlume/issues/164
[#165]: https://github.com/archledger/irlume/issues/165
[#166]: https://github.com/archledger/irlume/issues/166
[#167]: https://github.com/archledger/irlume/issues/167

## [0.7.1] - 2026-07-29

Security release. Please upgrade.

### Fixed

- **irlume could permanently destroy a camera, and did.** Looking for the control
  that lights a Windows-Hello illuminator, irlume wrote guessed payloads to every
  UVC extension unit from 0 to 31 and every selector from 0 to 15 until the
  infrared image got brighter. On a Lenovo ThinkPad camera (USB `174f:11b4`)
  those writes reached an undocumented vendor unit, the camera stopped answering,
  and by the next boot it no longer enumerated on the USB bus at all. A full
  shutdown and the laptop's emergency reset hole did not bring it back. Reported
  as [#159].

  It ran without anyone asking for it. From 0.1.0, enrolling a face could start
  the search. From 0.3.0, so could every daemon start, meaning every boot. What
  triggered it was a dark infrared frame, which is also what an unlit room or an
  empty chair looks like, so the search could run on hardware that never needed
  it. Setting the documented `IRLUME_IR_EMITTER=off` did not prevent it, and on a
  camera irlume already knew how to drive it made the search more likely by
  leaving the picture dark.

  Nothing guesses any more. Discovery reads the camera's USB descriptor, which
  states which extension units exist, identifies each one by GUID, and lists
  exactly which selectors each implements. Only Microsoft's documented
  camera-control unit is addressed, only selectors that unit advertises are
  touched, `GET_INFO` must say the control accepts a write, and the value written comes
  from the camera's own answers. For IR Torch, which Microsoft specifies
  completely, that value is checked against the specification before it is
  written. Anything that cannot be put back afterwards is not written at all, and
  a change is only believed if it follows the control in both directions, and the
  first failed request ends the whole operation.

  Where a value has to be chosen rather than read, it is derived from what the
  camera advertises. Microsoft's Face Authentication control cannot use the
  device's default: the specification says an interface that is also usable for
  ordinary capture defaults to general-purpose mode, and both cameras this was
  validated against do exactly that. The mode is therefore taken from the
  camera's own `GET_MAX`, which states which face-authentication mode each of its
  interfaces supports, and every structural contradiction is a refusal. On both
  cameras that derivation produces the payload separately validated on each of
  them, byte for byte.

  Discovery now only happens when someone runs `irlume ir-setup`. It is not a
  side effect of starting the daemon or enrolling a face.

  `IRLUME_LOG_EMITTER_WRITES=1` prints every emitter write irlume makes, byte for
  byte. Every one goes through a single function, so none can escape it.

- **Upgrading stops the writes.** A control found by the old search was persisted
  and re-applied on every capture. Those files are refused: the persisted control
  now records which camera it was found on, files written before 0.7.1 carry no
  such record, and a control found by writing invented payloads cannot be assumed
  harmless because the current camera has something at the same numbers. Machines
  that relied on one either fall back to the built-in table or re-run
  `irlume ir-setup`. The second line of that file, a "brightness boost" found by
  writing `0xFF` across a control of unknown meaning, is no longer written or read.

- **A camera is identified by what the USB bus says it is.** The built-in table
  matched a substring of the V4L card name, so any camera whose name contained
  "ASUS" received nine bytes at unit 14, selector 6. It is keyed on
  `idVendor:idProduct`, and the descriptor is checked before the write either
  way. Identity is resolved from the file descriptor that will receive the write,
  so the descriptor that authorises a write always describes the device that
  gets it.

### Added

- **`scripts/diagnose-missing-camera.sh`** collects evidence from an affected
  machine and sends the camera nothing. There is no software recovery once a
  camera stops enumerating: every firmware path runs over USB control transfers,
  which need a device that answers. The script says so rather than offering false
  hope, and it lists what not to try.

[#159]: https://github.com/archledger/irlume/issues/159

## [0.7.0] - 2026-07-28

### Added

- **Camera arbitration.** An authentication is no longer queued behind preview
  or enrolment work. Connections are read on their own threads, authentication
  is taken first, and a running enrolment yields between whole captures rather
  than holding the camera to the end. Measured on the Zenbook's real IR pair:
  authentication under an eight-client flood 5.25s to 0.16s, and a lock-screen
  unlock under the same flood 14.39s to 4.27s. An enrolment displaced this way
  returns `preempted` and persists nothing.

- **`ly` display manager.** Detected even though `ly` registers no
  `display-manager.service` (its unit is templated and carries no alias), and
  wired through `/etc/pam.d/ly`. Validated on a real `ly` install.

- **Wedged-capture watchdog.** `WatchdogSec` in the unit, answered only while
  the camera worker reports progress, so a capture stuck inside a driver call
  ends as a bounded restart instead of an indefinite hang.

- **Per-uid refusal throttle.** A local process spinning on refused camera work
  no longer costs the daemon 161 points of CPU: measured 11,327 refusals/s down
  to 72/s, with unrelated requests answered throughout.

- **AddressSanitizer over the test suite, weekly and on pull requests that touch
  the code.** irlume is mostly safe Rust, so this is aimed at the places where it
  is not: NSS `getpwnam_r` buffer handling, the mlock and madvise page arithmetic
  that protects a decrypted secret, `secure_getenv`, a UVC control ioctl, and the
  daemon's `SO_PEERCRED` path. Clippy cannot see into any of them.

  Not a required check, on purpose: `-Zsanitizer` is unstable, and an unrelated
  nightly regression must not be able to block a pull request.

  Verified by planting a deliberate out-of-bounds read and confirming the job
  reported it with the right file and line, then removing it. A gate nobody has
  seen fire is a gate nobody should trust.

- **`docs/INTEGRATION.md`, a guide for people writing software that drives
  irlume.** How to call the machine API, the startup handshake, what contract 1
  offers, what it deliberately does not (no mutation, no event stream, no D-Bus
  service, no client library) and what to do instead, the authorization model,
  and how to develop against a sandbox daemon on your own socket rather than
  pointing test knobs at the one that authenticates real logins.

  It also names the version-gating mistake directly: matching `engine_version`
  against a version range turns an unrelated release into "unsupported" for the
  user. Gate on `contract_versions` and `capabilities`, which are promises about
  behaviour.

- **A JSON Schema for contract 1, with captured fixtures and a conformance
  script.** `schemas/machine-api-v1.schema.json` (JSON Schema 2020-12) describes
  every document the machine commands write, and packaged builds install it at
  `/usr/share/irlume/schemas/` so the schema and the engine implementing it are
  never a version apart on a user's machine.

  The schema does not close its objects, and consumers are told not to either:
  fields may be added within a contract version, so a validator that rejects
  unknown properties turns a permitted engine update into a broken panel.

  `schemas/fixtures/v1/` holds documents captured from a real engine, including
  the daemon-unreachable and the three refusal cases, so a consumer can build
  against what irlume actually writes rather than against invented examples.
  Profile and scan display names are replaced with placeholders, since they are
  user text.

  `scripts/machine-api-conformance.py` checks a build the way a consumer would:
  envelope rules, every advertised capability actually answering, the refusals
  refusing, and no device or PAM paths in the output. It runs in CI against the
  release binary, and a downstream can run it against whichever irlume versions
  it supports. The doctor check-id registry is now documented in
  MACHINE-API.md, and a test fails if an id ships undocumented or a documented
  id stops shipping.

- **`irlume login status --json`.** Which PAM surfaces carry face auth, as values
  instead of the report's glyphs and column spacing. Each surface reports its PAM
  service name, its role (`login-screen`, `login-screen-fingerprint`,
  `lock-screen`, `sudo`, `polkit`), whether the service exists here, whether it is
  wired, and how face fires on it (`face-first`, `on-demand`, `keyring`,
  `verify`). The active login manager is named alongside the PAM services it
  consults, so an integration can find the entry describing its own login screen
  without guessing from service names.

  The surface list is complete: a service absent from the machine still appears,
  with `present: false`. Service names are published rather than `/etc/pam.d`
  paths, on the same terms as the camera capability in `status --json`.

  The human `login status` is unchanged, byte for byte. Both outputs are built
  from one pass over the PAM files, so they can differ in wording but not in what
  they claim is wired.

  This completes the read-only machine API: `version`, `status`, `doctor`,
  `profiles list` and `login status` all answer in JSON, and none of the five
  commands a desktop integration needs requires parsing English.

- **`irlume doctor --json`.** Every readiness check as an identified result with
  a state of `pass`, `warn`, `fail`, `unknown` or `info`, so an integration can
  show a diagnostic list without matching English.

  The array is complete: every check reports on every run, including ones that do
  not apply to this machine. A consumer may therefore read an id it knows about
  and cannot find as "this engine version does not run that check" rather than as
  "it passed". One check previously went silent when `doctor` ran without a
  session bus, which under this rule would have read as a pass; it now reports
  `unknown`.

  Check ids are public API. The list may grow, but an id is never renamed or
  reused for a different meaning.

  The human `doctor` is unchanged, byte for byte. It is instrumented rather than
  rewritten: each check records its result beside the line that reports it, so
  one pass over the machine produces both outputs and they cannot drift.

- **`irlume status --json`.** The readiness summary a desktop integration needs,
  as values instead of prose. It reports the daemon state, auth method,
  enrollment counts, template protection, keyring arming, recovery passphrase,
  camera capability and fingerprint presence.

  Two deliberate narrowings against the human command: it reports whether an RGB
  and an IR camera resolved, never which device nodes, and it does not name the
  account, since the caller already knows which one it asked about.

  Anything that depends on the daemon carries a `known` flag, and when that is
  false the counts are absent rather than zero. A consumer must not be able to
  mistake "we could not find out" for "this account has nothing enrolled".

  This exists because the alternative is what a real consumer is doing today:
  matching English phrases and column spacing out of the human output, where a
  reworded line silently degrades its interface.

- **A consumer can state which contract it implements.** `--contract N` on any
  machine command makes the engine agree only to a version it actually speaks,
  and refuse anything else before the daemon is contacted or any side effect
  begins. `irlume version --json` advertises the supported range as
  `contract_versions`, and every response echoes the version in force.

  Omitting the flag always means contract 1 and always will. It deliberately
  does not mean "newest": a program written against contract 1 must keep getting
  contract 1 from an engine that has since learned contract 2, rather than
  having a response change meaning underneath it.

  This exists now, while the surface is read-only, because a capability string
  alone is a poor gate. A consumer that enables behaviour on seeing a capability
  name has no way to say which semantics it was built for, and the engine has no
  way to refuse. Contract negotiation is the part that has to be in place before
  any privileged or mutating command is added.

- **The machine API can tell a consumer why a request failed.** `profiles list
  --json` previously reported one opaque `operation-failed` whether the caller
  was not permitted to read that account or the engine genuinely broke, because
  the daemon reports both to the CLI as prose. It now reports `not-authorized`
  and `operation-failed` separately, so a desktop integration can show a
  permission message instead of a generic failure, or retry instead of giving up.

  `not-authorized` still says nothing about whether the named account exists. An
  ordinary caller is refused before the enrollment store is consulted, so a real
  account and an invented one give the identical answer, and the command cannot
  be used to enumerate accounts.

  The socket carries this without breaking an upgrade in either direction. A
  request opts in with a defaulted `structured_errors` field, and the daemon
  sends the typed response only to a request that asked for one, because a
  client that predates the new response variant cannot decode it. An older
  client omits the field and keeps receiving the prose it understands; a newer
  client meeting an older daemon has its unknown field ignored and falls back to
  the same prose. The human CLI and TUI keep the prose deliberately, since it is
  written to be read.

- **Desktop integrations now have a small, versioned JSON foundation.**
  `irlume version --json` advertises only implemented public capabilities, and
  `irlume profiles list --json` exposes the existing read-only enrollment
  summary without daemon prose or private socket access. The documented
  contract keeps stdout machine-only, uses stable error codes, and deliberately
  withholds mutation capabilities until the enrollment store owns opaque IDs.

- **`sudo irlume camera-tune` measures whether your camera can read both sensors
  at once.** Some Hello modules stop exposing their colour stream properly while
  their infrared sibling is streaming. On a NexiGo HelloCam N930W the colour
  frame parks near a brightness of 60 no matter the room: with the light behind
  the camera it measured 142.9 captured alone against 59.8 captured alongside
  infrared, 42% of the signal, while the infrared stream was untouched. The same
  colour sensor paired with a *different* camera's infrared node kept 99%, so it
  is the two interfaces of one module competing, not concurrency itself. An ASUS
  FHD built-in measured in the same light kept 102%.

  The command runs both capture orders a few times, compares them, and stores the
  answer per camera in `cameras.conf`; authentication then captures one sensor at
  a time on cameras that need it and keeps the faster overlapped path on cameras
  that do not. Overlapping saves 716ms per capture on the ASUS and 1410ms on the
  NexiGo, which is what it costs those cameras to switch.

  A dim room hides the fault, since a scene that genuinely reads ~60 looks the
  same either way. The command says so instead of reporting a clean result: below
  a sequential brightness of 100 it reports the measurement as inconclusive and
  asks for a re-run in normal light. A detected loss needs no such caveat.

- **Enrolling no longer re-opens the camera for every attempt.** The capture
  loop holds both streams open for its duration instead of paying the open,
  format negotiation, buffer mapping, stream start and auto-exposure warm-up per
  attempt. Measured on an ASUS FHD built-in, a colour+infrared capture pair costs
  1912ms through the per-call path and 797ms on a held stream, so 58% of every
  attempt was setup rather than frames. It also stops the capture light blinking
  once per attempt, which is what the old lifecycle looked like from the outside.

  Holding the stream is safe because the emitter does not go dark: after a single
  control write it stayed lit through 30 seconds of continuous streaming on both
  modules tested, and the control survives even closing the stream. Streams are
  still never held between requests, so an idle daemon keeps reserving nothing.

### Changed

- **Releasing your keyring password now asks for a gesture, by default.** On a
  face login that unlocks the login keyring, irlume waits for a deliberate nod
  (or a calibrated eye closure, if you set that up) after the face match before
  the TPM releases your stored password. The watch ends the instant the nod is
  seen; only a login where you never nod pays the whole watch window (120 frames,
  roughly 8 seconds) before the password prompt. Nothing else changes: login, the
  lock screen, `sudo` and app prompts behave exactly as before.

  Why only this operation: a session grant ends with the session, but a released
  keyring password is a reusable secret that also unlocks your password manager.
  irlume's own PAD self-test recorded the default single-frame IR gate accepting a
  life-size glossy vinyl print 69 times out of 70, an APCER of 98.6%
  ([2026-06-30](docs/pad-results/2026-06-30-ir-liveness-selftest.md)), against the
  15% ceiling FIDO's Level 1 biometric certification allows. A nod is something
  that print cannot produce, which is why the credential path no longer rests on
  the single-frame cues alone.

  Nothing here can lock you out. A missed gesture, a camera that is busy, no IR
  camera, or a FaceMesh model that is not deployed all fall back to typing your
  password, and your keyring then unlocks from what you typed exactly as it would
  have from a released password. A nod needs no calibration, so an existing
  enrollment keeps working with no re-enroll.

  Prefer the old behavior? `sudo irlume credential-release-challenge off` (it
  warns and asks first), the `[g]` key on the TUI's Settings page, or
  `credential_release_challenge=0` in `/etc/irlume/settings.conf`. `irlume
  doctor` reports the state, and flags the case where the gate is on but cannot
  run on this machine.

  What it was measured to do, on one camera with a seated user, 17 attempts
  against the real login stack: nodding continuously released the password 4
  times out of 4, and holding still with consent withheld released it once in 10.
  A single nod released it 0 times out of 3, which is why the prompt asks you to
  keep nodding rather than to nod. It has not been measured against a photo held
  in the hand, and the same detections show the detector responding to incidental
  movement, so treat this as raising the cost of a print attack rather than
  closing it. See docs/THREAT_MODEL.md and issue #101.

- **The IR "depth" cue is now called what it is: a center/edge brightness
  ratio.** Nothing in irlume measures range. The cue compares the middle of the
  IR face region to its rim, which a lit 3D face brightens and a flat matte print
  does not, and a glossy print defeats. Calling it depth oversold it. Renamed
  throughout: the `depth_ok` cue is `center_edge_ratio_ok`, `DEPTH_MIN_RATIO` is
  `MIN_CENTER_EDGE_RATIO`, the per-user floor accessor is
  `ir_center_edge_ratio_floor`, and the debug and doctor lines, the PAD self-test
  cue attribution (`depth` → `center_edge`), and the capture-dump JSON key follow.
  Stored enrollments are untouched: the on-disk key stays `ir_depth` so a
  downgrade still reads your fitted floor. The denial text now says the face
  region is flatter than your enrolled face instead of asserting you are a photo.

### Fixed

- The consent gesture's pitch threshold was raised from 0.070 to 0.075, the
  midpoint of the measured gap between deliberate nods (0.082-0.108) and
  sitting still or holding a print (0.021-0.069). The crossings count was
  deliberately left alone: measured, it does not separate the two.

- **A display manager irlume could name but not wire was reported as supported.**
  `doctor` recorded `display-manager: pass` whenever the active login manager had
  an entry in the PAM service mapping, without checking that anything wires the
  service that entry names. `ly` maps to a `ly` PAM service that no wiring recipe
  covers, so on an `ly` host `login enable` silently wired nothing while doctor
  said the machine was fine, and `login status --json` reported
  `recognized: true`.

  Being named and being wirable are now the same test, which is what
  `login status --json` already documented `recognized` to mean. An `ly` host now
  gets the warning that points at the issue tracker.

  The mapping became a table rather than a `match` so a test can walk every entry:
  adding a login manager without adding its wiring recipe now fails the suite.
  Wiring `ly` itself is now supported and was validated on a real `ly` host
  (#128, #144).

- **`mlock_refusal_warns_and_continues` failed under a sanitizer instead of
  saying why.** The sanitizer runtime defines its own `mlock`, so the call never
  reaches the kernel, `RLIMIT_MEMLOCK` refuses nothing, and the warning the test
  looks for is never printed. The test now detects that the lock was not enforced
  and reports which assertion it skipped, rather than reporting a bug that is not
  there or passing quietly as though it had checked.

- **Two `doctor` checks vanished from the machine document instead of reporting
  that they did not apply.** `polkit-helper-sandbox` was recorded only when
  polkit prompts were already wired, and `pam-regeneration-guard` only when the
  login stack was wired. On any machine where neither is true, both ids were
  simply absent, which under the completeness rule reads as "this engine version
  does not run that check" rather than "it did not apply here". Both now report
  `info`, so the array is 23 entries on a wired desktop and in a bare container
  alike. Found by running `doctor --json` in a container rather than by reading
  the code. The human report is unchanged, byte for byte.

- **Face unlock on the KDE lock screen works again, and `irlume detect` stops
  lying to unprivileged callers.** An earlier change in this development cycle
  had packaging create an `irlume` system group, which made the daemon restrict
  its control socket to `0660 root:irlume`. Nothing ever added a member to that
  group. `kscreenlocker_greet` is not setuid, so the lock screen's PAM
  conversation runs as you, its `connect()` to the socket returned EACCES, and
  face unlock silently fell through to the password along with the keyring
  unseal that rides on it. `irlume detect` exited 10 (partial) as a user and 0
  (ready) as root on the same healthy, enrolled machine, and `irlume status`
  reported "daemon NOT reachable" while the daemon was serving requests
  normally. `sudo`, the login greeter and polkit prompts were unaffected because
  all three run as root.

  The socket is now mode 0666 and the group is gone. Reachability was never the
  authorization boundary: `SO_PEERCRED` is, it is supplied by the kernel at
  connect time, and every request still requires either root or a target that
  matches the calling uid. This is the ordinary arrangement for a local system
  daemon. It is systemd's own documented default for filesystem sockets
  (`SocketMode=` in `systemd.socket(5)`), pcscd ships the same, and fprintd
  keeps its endpoint reachable and authorizes per operation. Group membership
  could not have fixed it either: supplementary groups are process credentials
  fixed at login, so adding your uid does not reach the desktop you are already
  in, and greeter account names differ across display managers.

  Requests remain bounded (64 KiB, read and write deadlines), each connection
  stays isolated behind `catch_unwind`, and the unauthenticated dry-run emitter
  probe now shares the per-uid camera interval that already covered `Identify`.
  On Fedora the SELinux module is still the mandatory-access layer.

- Connect failures now distinguish "nothing is listening" from "this uid may not
  connect". EACCES no longer prints "irlumed is not running" or points you at
  `systemctl status` for a healthy service, and it deliberately does not tell
  you to run `sudo` or change the socket mode, because both hide whatever set it.

- `irlume-reconcile.timer` is packaged on Fedora. It was installed into the
  buildroot but never listed in `%files`, which fails the rpm build on an
  unpackaged file, and it was missing from `%preun`/`%postun`, so an uninstall
  left it enabled.

- **The RGB and IR frames of one decision had no bound on how far apart they were
  taken.** The liveness gate treats them as one scene: the face must appear in
  the same place in both, and the colour frame's head pose judges a decision made
  largely on the infrared frame. Nothing enforced that they showed the same
  moment. The two captures race on separate threads, either one can retry alone,
  and the dimming self-heal recaptures colour after infrared has finished. Frames
  now carry the span of time their pixels came from, and a pair more than 3
  seconds apart is refused as an uncertain capture rather than judged. That is a
  retryable outcome, not a spoof accusation, so the grace window simply captures
  again; the normal paths sit far below the limit, since overlapped captures
  overlap and sequential ones run back to back.

- **A camera that failed to stop streaming could take the daemon down.** The v4l
  binding panics from its stream destructor on any STREAMOFF failure except a
  disconnected device, and a destructor panic during an existing panic aborts the
  process, which for the root daemon means every session's face auth, not one
  request. Teardown failures are now contained and logged; the frames are already
  captured by then and nothing depends on the stop succeeding.

- **16-bit infrared frames were rescaled one frame at a time.** The scale was
  derived from each frame's own brightest pixel, so a single hot pixel appearing
  or leaving changed the whole frame's values. The capture path then compares
  frame brightness to pick the emitter's lit phase and the ambient floor, which
  that rescaling makes meaningless. The scale is now fixed once per capture
  session. Cameras with 8-bit infrared, which is all of the ones tested, were
  never affected.

- **A short infrared sequence read as "you did not blink".** When frozen frames
  exhausted the capture's attempt budget, the blink check silently judged whatever
  short window arrived. The shortfall is now reported, so a camera fault is
  distinguishable from a still face in the logs.

- **Face `sudo` never worked on Debian and Ubuntu.** The wiring looked for a line
  starting with `auth` to place the stanza above, and Ubuntu's `/etc/pam.d/sudo`
  has none: it carries `session` lines and `@include common-auth`. The stanza was
  appended at the end of the file instead, after the password modules, where it
  can never grant. `sudo` now uses the same include-aware anchor as the polkit
  wiring. Run `sudo irlume login enable --with-sudo --apply` (or `irlume login
  reconcile`) to move an existing misplaced stanza; a file with no auth phase at
  all is now skipped and reported instead of appended to.

- **Fedora-layout greeters we have not validated for the on-demand probe lost the
  face entirely.** The `substack` wiring path emitted `pam_irlume.so unseal`
  without the `facefirst` argument that the `@include` path emits, so on those
  greeters the module waited on a password probe the greeter answers only after
  the user types, and the camera never ran. Affects GDM below the GNOME version
  gate and any unrecognized display manager; GNOME 46 and later, SDDM,
  plasmalogin, LightDM, greetd and COSMIC were unaffected.

## [0.6.1] - 2026-07-24

### Added

- **TUI feature parity: every CLI action is now reachable by keypress.** A
  parity audit found nine CLI features the TUI only mentioned as
  commands-to-type; since the TUI captures the mouse, those commands could
  not even be copied out. All are now actions: face-sudo and app-prompt
  wiring plus un-wire (Login wiring tab, un-wire behind a y/n confirm),
  eye-closure calibration, fingerprint verify/enable/disable/reset (reset
  confirmed), third-party model enable/disable (the license/provenance
  confirm still runs, hosted in the terminal), daemon debug-log toggle
  (Repair), the origin-aware updater (Done), and a Repair check + one-key
  fix for PAM wiring stripped by a distro regeneration. `[M]` releases
  mouse capture so terminal text selection works when copying is still
  wanted. Consecutive privileged actions share sudo's tty timestamp
  (5-minute default), so one authentication covers a TUI session's worth
  of changes; container-verified.

- **`irlume doctor` warns when the active display manager is not
  recognized.** biopolicy classifies an unmapped login or lock service as
  deny, and `login enable` cannot wire a display manager irlume has no PAM
  mapping for, so a display manager that is new or was renamed by an update
  drops face login back to the password with no signal. doctor now resolves
  the active `display-manager.service`; when there is no mapping for it, it
  names the DM and links the issue tracker. Silent on recognized DMs and on
  headless hosts. Validated on plasmalogin, sddm, and lightdm (no warning)
  and against an unmapped name (warning fires) on hardware and in a
  container.

### Fixed

- **Ctrl-C during any suspended TUI action no longer kills the TUI.** In the
  cooked terminal, SIGINT reaches the whole foreground group and the TUI had
  the default (fatal) disposition. A no-op SIGINT handler now shields the TUI
  around every suspended flow, including the in-place fingerprint, update, and
  doctor actions, not only the sudo ones; a caught signal resets to the default
  across exec, so a child (sudo, dnf, a prompt) still gets Ctrl-C. Found when
  Ctrl-C in the third-party-model license prompt took the whole TUI down.
- **Ctrl-modified letters no longer alias to plain-letter TUI actions.**
  Ctrl-C arrives as Char('c')+CONTROL and fired the calibrate binding;
  modifier-carrying letters are now ignored by the key dispatcher.
- **The TUI runs its own binary for privileged steps, even shell-wrapped
  ones.** The self-exe substitution only rewrote a bare `irlume` argument, so
  the `sh -c "irlume selinux load && ..."` action resolved `irlume` from root's
  PATH, a possibly older installed build. It now splices the running binary into
  the command, and falls back to the PATH name only when an in-session update has
  replaced the on-disk binary.
- **Packaged installs can re-load the SELinux module after `login
  disable`.** The pp lookup never searched
  `/usr/share/selinux/packages/irlume.pp`, the irlume-selinux rpm's
  install path, so a disable → enable cycle on a Copr install lost the
  module ("irlume.pp not found") until a package reinstall. The rpm's
  install-time module load had masked the gap. Found by hardware
  validation of the TUI un-wire/re-wire round trip.
  `IRLUME_SELINUX_PP` now also overrides the `selinux load` lookup.

- **`irlume bitwarden setup`: one command replaces the copy-paste Bitwarden
  polkit setup.** Detects how Bitwarden was installed and acts per flavor:
  flatpak and native installs get the action file written host-side (content
  ships inside irlume, byte-identical to bitwarden/clients' resource file, so
  nothing is downloaded at install time); snap is left to snapd, which
  installs the action itself on plug connect; ostree/immutable hosts get the
  rpm-layering steps instead of a doomed write to read-only /usr. Dry-run by
  default, `--apply` to act. An existing action file with different content
  is never overwritten (Bitwarden's own setup may have written a newer one),
  and after installing, the command confirms registration with polkit itself
  (`pkaction`), catching the mislabeled-file failures a file check misses.
  `irlume doctor` now points at the command when Bitwarden is installed with
  polkit wired but no action registered. docs/APP-INTEGRATION.md rewritten
  around it; the old manual wget flow also mislabeled snap as needing manual
  setup, which snapd has handled since Bitwarden 2025.3. Hardened for machines
  with more than one Bitwarden: when snapd already owns the polkit action,
  `setup` no longer writes a second file for the same action id (a snap next to
  a flatpak or native package), and doctor no longer tells that working snap
  install to run a command that would refuse. Per-user flatpak detection under
  `sudo` resolves the real home from `getent passwd` instead of assuming
  `/home/<name>`; the polkit confirmation polls up to a second so a correct
  install is not misreported as unregistered; and the file is written via a
  temp-then-rename so polkit never sees a half-written policy.

- **`irlume doctor` reports install-hygiene drift.** Two related checks, both
  report-only: stray irlume-named files next to the managed binaries and the
  PAM module that no package owns (the backups a manual branch install leaves
  behind: they outlive every later package update and a stale
  `pam_irlume.so.*` in the module directory muddies auth debugging), and a
  managed binary whose content no longer matches the installed package (a
  hand-installed build overlaying it, which the next package update will
  silently replace; doctor names the file and the reinstall command). Both
  checks stay silent when the install is clean. Content drift is detected via
  the package manager's own verify (`rpm -V` / `dpkg --verify` /
  `pacman -Qkk`), run in the C locale so a non-English `pacman` does not slip a
  drift past the English-token parser; mtime-only drift is ignored. A hand-built
  `/usr/local/bin/irlume` shadowing the packaged binary on `PATH` is also
  flagged, since the package verify only checks its own path.

- **Face-login self-heal survives an inactive watcher and an upgrade from a
  pre-marker install.** The 0.6.0 PAM-strip self-heal (`irlume-reconcile.path`)
  was edge-triggered inotify and gated on the `login.wired` marker that only
  `login enable` writes, so a strip during an offline `dnf`/`apt` run, or an
  upgrade from a version that predates the marker (0.5.0 and earlier), never
  re-applied the wiring. Two changes close that: `login reconcile` with no
  marker but login already wired now adopts the existing wiring into a marker
  (inferring the sudo and polkit flags from the live PAM files), and
  `irlume-reconcile.service` also runs at boot (`WantedBy=multi-user.target`,
  self-gating) to catch a strip that landed while the watcher was down.
  Packaging enables and starts it on install and upgrade across Fedora, Arch,
  and Debian/Ubuntu. Validated end to end on sddm (Arch) and lightdm (Debian):
  adopt, strip, re-apply byte-identical, and a clean boot run.

- **A pinned camera pair survives a `/dev/videoN` renumber.** A pair chosen in
  the TUI Cameras tab was stored in `cameras.conf` as bare `/dev/videoN` paths
  and only checked for existence, so a kernel or udev update that renumbered
  the video nodes could open a different sensor. `set-cameras` now records each
  node's stable device identity (`vid:pid:serial`), and `select_pair` keeps the
  saved path only while it still resolves to that identity, otherwise re-finds
  the node that now carries it. A pin with no recorded identity keeps the
  earlier path-exists behavior. Validated on a real NexiGo N930W: a stale path
  re-anchored to the right node by identity and role.

### Changed

- NixOS now appears in the packaged badge and the comparison table's "Runs on"
  row (the `nixosModules.irlume` flake target already shipped).
- The `irlume biopolicy <on|off|status>` operation-class toggle is now in
  docs/COMMANDS.md (it was reachable in the CLI and TUI but undocumented).

### Security

- The recovery passphrase now has a 12-character minimum at setup. It is the
  only barrier on the template-key envelope against an offline attacker with the
  disk, so a trivial passphrase is refused; the confirmation copy is zeroized
  rather than left in the heap as plaintext.
- `irlumed` warns loudly when no `irlume` group exists and it leaves the socket
  world-connectable, instead of falling back to 0666 silently. Privileged
  operations stay gated by the peer-credential check regardless.
- `cameras.conf` / `settings.conf` are created mode 0600 instead of
  written-then-chmod, closing the brief window where a new file was
  world-readable.
- A profile that opted into the passive-blink liveness challenge now fails
  closed to the password when the challenge cannot run (no IR camera, or the
  FaceMesh model is not deployed), instead of granting without it. The password
  always works, so this is a fallback, not a lockout; it was previously a silent
  skip-and-grant.
- The per-user IR depth floor (an anti-print 3D-structure check, fitted
  automatically at every IR enrollment and enforced on both IR paths) is now
  surfaced by doctor: on IR hardware, an enrollment made before the feature
  existed carries no recorded depth, so doctor nudges a re-enroll to activate it.

## [0.6.0] - 2026-07-23

### Added

- **Deliberate consent gesture for polkit prompts: head NOD or eye closure.**
  polkit agents start the PAM conversation with no user action, so a bare face
  match would approve a prompt the user never acknowledged; the daemon now
  requires a deliberate gesture for the polkit class (verify-only, never a
  credential release, IR tier only, fails closed to the password). Approve with
  a head NOD (the default: pose-defined, so it works at any head angle or
  lighting, including reclined/in bed, and needs no calibration) or, after a
  one-time `sudo irlume calibrate-closure`, by closing your eyes ~1s and
  reopening. One capture feeds both detectors and accepts EITHER, so the user
  does whichever suits their position; `consent_gesture=nod|closure` in
  settings.conf restricts to one. Both were tuned and validated offline against
  hardware capture campaigns (nod: zero false accepts across still / look-around,
  accepts reclined nods; closure: zero across squint / natural-blink / look-down
  / spoof, via a per-user absolute EAR threshold after the campaign showed a
  held squint is indistinguishable from a held closure). `pam_irlume` shows the
  gesture hint on the polkit dialog; `irlume doctor` reports the wiring and
  gesture state. New camera streaming core (`capture_ir_streaming`), pose/EAR
  capture, and a dev tool (`irlume blinkcap`, `IRLUME_DEV`) underpin the tuning.
  See docs/APP-INTEGRATION.md.

- **polkit app prompts can be face-approved (opt-in): `sudo irlume login
  enable --with-polkit --apply`.** Desktop apps ask polkit to verify the user
  (Bitwarden's "unlock with biometrics" is a polkit prompt, as are `pkexec`
  and GNOME Software); wiring `pam_irlume` into the `polkit-1` stack lets a
  face match answer them, password fallback unchanged. The polkit class is
  verify-only at the daemon (an always-on refusal guards the TPM-sealed
  credential, independent of tier or biopolicy config), requires the deliberate
  consent gesture above even without the per-enrollment opt-in (polkit agents
  start the PAM conversation with no user action, so the gesture is the intent
  signal), fails closed when the gesture cannot run, and is denied outright on
  RGB-only hardware. `irlume login status` gains a polkit row, `irlume doctor`
  flags a Bitwarden polkit action with no wiring, and the SELinux policy (1.1.0)
  grants the polkit helper domain socket access. See docs/APP-INTEGRATION.md.

- **Fingerprint coexistence: unlock with face OR fingerprint (`Method::Both`).**
  `sudo irlume fingerprint enable` now defaults to Both when a camera is present,
  keeping face on instead of standing it down; `--fingerprint-only` restores the
  old replace-face behavior. `irlume doctor` and the TUI report the coexistence
  as healthy rather than as a competing-modules warning.

- **Distro-update self-heal for PAM wiring.** A new `irlume login reconcile`
  subcommand plus `irlume-reconcile.path`/`.service` systemd units re-apply the
  greeter PAM wiring if `authselect apply` / `pam-auth-update` / a package
  upgrade strips it. `login enable` records the wiring scope in a marker; the
  watcher is a no-op until then and loop-safe once wired. `irlume doctor` gains a
  regeneration-guard advisory confirming the watcher is armed on managed hosts.

- **`irlume doctor` login-keyring probe.** Reports whether the login keyring is
  unlocked (what Bitwarden and other Secret Service apps read from) and names the
  provider (ksecretd on Plasma 6, kwalletd, gnome-keyring), pointing a locked
  keyring at the exact PAM module that unlocks it.

### Fixed

- **`irlume keyring arm` rejects a non-login password.** It now verifies the
  entered password is your actual login password before sealing, so a mistyped
  or wrong password can no longer be sealed and leave the wallet failing to
  unlock (the ksecretd `-9` failure class).

- **Bitwarden flatpak/snap setup documented.** The sandbox cannot register
  Bitwarden's polkit action and gives no in-product prompt; docs/APP-INTEGRATION.md
  now has the exact host commands (install the policy, Fedora SELinux label) plus
  the Settings toggle. Verified live: the polkit dialog appears and a head nod
  unlocks the vault on the 2026.6.1 flatpak.

- **The "test (stable)" CI job now actually tests on stable.** Its
  `dtolnay/rust-toolchain` step was pinned to the action's `1.88.0` version
  branch, which has no `toolchain` input, so `with: toolchain: stable` was
  silently ignored and the job installed 1.88.0 (a duplicate of the MSRV job).
  The stable, coverage, and fuzz jobs now pin `@master`, which declares the
  input and honors the requested toolchain. Found by a workflow audit.
- **The `install.sh` installer refuses to run without a verified signature.**
  It previously fell back to unsigned checksums with a warning when
  `SHA256SUMS.asc` or `gpg` was absent, so an attacker serving a modified
  release could strip the signature to disable enforcement. Signature
  verification is now mandatory (fail-closed); `IRLUME_INSECURE_NO_SIG=1` is
  the explicit, documented opt-out for installing without gpg.

### Security

- **`pam_irlume` no longer trusts `IRLUME_SOCKET` in a setuid context (local
  root fix).** The module is linked into setuid-root PAM stacks (`/etc/pam.d/sudo`
  under `--with-sudo`), which inherit the caller's environment. It resolved the
  daemon socket from `IRLUME_SOCKET` via `getenv`, so a local user could run
  `IRLUME_SOCKET=/tmp/evil.sock sudo …`, point the module at a fake daemon that
  always replies "granted", and gain root with no password or face. The override
  is now read through `secure_getenv`, which returns NULL under AT_SECURE, so the
  compiled socket path always wins in a setuid stack while the daemon and dev/test
  keep the override. Found by a pre-release security audit.
- **Self-heal marker hardened.** The `login.wired` reconcile marker is written
  0600 root-owned and trusted only when root-owned in production, so it cannot be
  planted by a non-root user to force `--with-sudo` wiring. reconcile also now
  checks the active display manager's own greeter (not any greeter), so a distro
  update that strips only the active greeter is actually repaired.

- **The self-hosted preflight runner no longer has any path to running fork
  code.** It triggered on `pull_request` behind a same-repo `if:` guard, but a
  `pull_request` run executes the fork's own copy of the workflow, so the guard
  text was attacker-editable and the real control was the fork-approval wall.
  Preflight now triggers on `push` instead, which a fork cannot fire against
  this repo at all, removing the untrusted-code path structurally. The
  self-hosted checkouts also set `persist-credentials: false`.

## [0.5.0] - 2026-07-21

Driven by a field-research campaign across 25+ sibling projects' issue
trackers (Howdy alone contributed 1,124 mined issues): the release fixes the
failure classes their users hit before irlume users can, hardens the
fingerprint path against everything the libfprint/fprintd corpus documents,
and stands up hardware-in-the-loop CI: a self-hosted runner with a real TPM
and IR camera that validates every change on silicon. That runner found and
fixed its first kernel-drift bug before this release shipped.

### Fixed

- **`fingerprint enable` no longer disables face auth with nothing wired on
  Arch-family distros.** On distros without authselect/pam-auth-update the
  command printed manual wiring instructions and then recorded
  `method=fingerprint` anyway, so the daemon stood face down while no module
  drove the fingerprint prompt: the box silently became password-only. The
  method now changes only after an active `pam_fprintd.so` line actually exists
  in `/etc/pam.d`; the same check guards the authselect/pam-auth-update paths,
  which can exit 0 without producing the line (e.g. a custom authselect profile
  lacking the feature).

- **Tier-1 signed-PCR sealing works.** irlume's strongest TPM tier (a
  `PolicyAuthorize` over systemd's PCR-signing key, the one that survives kernel
  updates without a reseal) never actually engaged. It loaded systemd's public
  key under the Null hierarchy, so the TPM rejected the resulting
  `PolicyAuthorize` ticket with `TPM_RC_VALUE`, and every UKI / systemd-boot
  host silently fell back to Tier-2 (pcrlock). Loading the key under the Owner
  hierarchy fixes it (the key's Name, which the sealed policy commits to, is
  hierarchy-independent, so the policy is unchanged). Verified on a real
  systemd-boot host, including a Tier-1 seal that unseals after a reboot.

- **The "irlumed is not running" guidance survives newer kernels.** Connecting
  to a stale daemon socket (daemon gone, file left behind) returns
  `ECONNRESET` instead of `ECONNREFUSED` on newer kernels (observed on
  7.1.4-zen by the self-hosted hardware runner); the client now maps both to
  the actionable start-the-daemon message instead of a raw errno.

### Added

- **Panic firewall in `pam_irlume.so`.** Every PAM entry point now runs behind
  `catch_unwind`; a panic anywhere in the module or a dependency maps to
  `PAM_IGNORE`, so the stack falls through to the password. Without it, a panic
  reaching the `extern "C"` boundary aborts the calling process (sudo or the
  greeter, since Rust 1.81), and the module's own dependency stack contains
  reachable panics. Crashing auth modules were the dominant lockout/fail-open
  class in the pre-2020 generation of face-PAM projects.
- **NIST known-answer test for the template envelope.** A CAVP AES-256-GCM
  vector (`gcmEncryptExtIV256.rsp`) is decrypted through the on-disk
  `nonce ‖ ciphertext ‖ tag` layout in the test suite, and the 28-byte framing
  overhead is pinned. An `aes-gcm` upgrade that changes the algorithm or the
  blob layout now fails CI instead of silently orphaning every encrypted
  enrollment (a sibling project nearly merged exactly that dependency bump).
- **Hardware-report issue template.** New GitHub issue form that asks for the
  machine/camera model, distro, and `irlume doctor` / `irlume detect` output up
  front, so camera and emitter quirks arrive with the data a fix needs.
- **`irlume fingerprint verify` and `irlume fingerprint reset`.** `verify` runs
  one interactive round against the enrolled prints and is offered
  automatically after every enrollment, catching the "enroll succeeds, verify
  never matches" sensor failure before the user relies on it at the greeter.
  `reset` deletes every print fprintd holds for the user (confirm-gated;
  `--yes` for scripts; refuses to delete without a terminal) and offers a fresh
  enrollment: the remedy for chip/host template desync after a Windows
  dual-boot enrollment, an OS reinstall, or a BIOS fingerprint wipe.
- **Fingerprint doctor checks.** `irlume doctor` now warns on: a stale fprintd
  device claim (the dominant post-suspend failure; finger prompts silently stop
  until `systemctl restart fprintd`), a vendor driver stack
  (open-fprintd/python-validity) owning the fprint bus name instead of stock
  fprintd, pam_faillock sharing a stack with pam_fprintd (a touch-sensor
  misread can burn every retry in seconds and lock the account), and
  pam_fprintd reachable from `sudo` while an SSH server runs (every remote
  `sudo` stalls up to 30s waiting on the local reader).

- **Real-hardware validation joins CI.** A self-hosted runner with a real TPM
  and a real IR camera now runs the TPM seal/unseal tests against silicon
  rather than a software TPM, and captures a live emitter strobe burst,
  nightly and on every maintainer pull request. The distinction matters: the
  Tier-1 sealing fix above is a bug class that passed software-TPM CI
  completely and only ever failed on real hardware. The universal `.deb` is
  also now installed and smoke-tested weekly on bare Debian 12/13 and
  Ubuntu 22.04/24.04/26.04 images, guarding the glibc floor the package
  promises.
- **IR capture negotiates beyond native GREY.** IR nodes that expose only the
  16-bit grey family (Y16/Y10/Y12) or only a packed colour container
  (NV12/YUYV) now work: 16-bit frames are converted with an effective-depth
  estimate (the V4L2 spec keeps sample data LSB-aligned and allows Y16 to
  carry as few as 10 real bits, so a fixed top-byte take reads such sensors as
  near-black), and NV12/YUYV nodes contribute their 8-bit luma plane. Y16-class
  nodes also classify as IR now instead of falling to Other, which silently
  demoted those machines to the RGB convenience tier. MJPEG-only IR nodes get
  an error naming what the camera offers. Validated against the reference IR
  camera (native GREY path unchanged, strobe capture intact).

### Changed (fingerprint plumbing)

- Every fprintd/busctl helper now runs under `LC_ALL=C`; the fprintd CLI tools
  are gettext-localized, so on a non-English locale the status parsing silently
  stopped working.
- Enrollment has a 120-second completion deadline (a wedged driver otherwise
  hangs the enroll forever), captures stderr, and maps each failure class to
  its own actionable message: reader claimed by another session, on-sensor
  storage full, reader disconnected mid-enroll, polkit refusal, no device.
- Listing enrolled fingers now distinguishes "no fingers enrolled" from "the
  listing failed" (stale claim, polkit refusal, readerless box;
  `fprintd-list` exits 0 in all of them). Found live: over SSH, polkit refuses
  the listing, and status/verify used to answer "no finger enrolled; run
  irlume fingerprint add", pointing exactly the wrong way.
- Stale-claim detection matches the D-Bus error names (never translated) in
  addition to the C-locale phrases, and multi-reader machines now report every
  reader's name instead of only the first.

### Changed

- **Existing seals climb to the strongest available tier automatically, with no
  re-arm.** After the fix above a machine that was sealed under a weaker tier
  upgrades on its own: the keyring seal on the next login, and the template key
  on the next face match. The upgrade fires only when a strictly stronger tier
  is available and the ladder round-trip-verifies it, so a machine already at
  its best tier does nothing. New enrollments seal at Tier-1 directly.

## [0.4.0] - 2026-07-21

Two batches: preempting camera and UX failure classes mined from other Linux
face-auth projects' issue trackers with research-grounded auth-policy hardening,
and a whole-codebase, CLI/TUI, and auth-pipeline audit. The matching and
liveness changes were confirmed on the KDE lock screen (face grants in a bright
room and in the dark) before release.

### Added

- **RGB pixel-format negotiation.** Capture now negotiates `NV12` in addition to
  `YUYV`, so cameras that expose only `NV12` work instead of failing at capture.
  A camera that offers neither (MJPEG-only) gets a clear up-front error and an
  `irlume doctor` diagnosis, in place of a cryptic "expected YUYV". `doctor`
  reports RGB decodability using the same format list capture actually decodes.
- **`irlume doctor` recognizes Intel IPU6/IPU7 cameras.** These expose no direct
  V4L2 node, so a bare "no camera" was misleading; doctor now names the sensor
  and points at the libcamera software relay, covering both IPU6 and IPU7 across
  the dkms and in-kernel drivers with a PCI-ID fallback. It also states the
  accurate limitation that the IR sensor is not exposed on Linux at all.
- **`irlume doctor` warns when a user is enrolled but no greeter is wired.**
  `authselect` / `pam-auth-update` can regenerate the PAM stacks and drop
  irlume; doctor now surfaces that state instead of leaving a silently
  face-less login.
- **Consecutive-failure throttle.** After a run of failed face attempts (5 by
  default, `IRLUME_RATE_LIMIT`) the daemon stops firing the camera on the
  gesture for a cooldown (30s, `IRLUME_RATE_COOLDOWN_SECS`) and PAM falls
  straight to the password; a grant resets it, and an empty frame (nobody
  present) never counts. A rejected real presentation counts, including a caught
  spoof, so an attacker cannot cheaply grind presentation attacks against the
  gate. This is a throttle, not the NIST SP 800-63B-4 §3.2.3 hard
  biometric-disable tier: the password is always the fallback and there is no
  account lockout. Applied on both the login/sudo and keyring-unseal paths.
- **Informed opt-in for the anti-spoof blink challenge at enrollment.** Every
  mainstream authenticator (Face ID, Android, Windows Hello) ships passive
  presentation-attack detection rather than an active challenge, so the blink
  challenge stays off by default; the enroll flow now surfaces the choice
  instead of leaving it a hidden flag. The TUI Settings screen toggles it in
  place with `[c]`, alongside the existing `[enter]` eyes-open toggle.

### Changed

- **First capture warms up and retries.** A suspend/resume can leave `uvcvideo`
  re-initializing when the first frame is requested; capture now warms the
  stream and retries so a resume does not fail the login outright.
- **`irlumed.service` stops promptly and runs sandboxed.** `TimeoutStopSec=10s`
  caps the stop wait so a package-upgrade restart cannot stall (the 90s-hang
  class seen elsewhere), guarded by a SIGTERM regression test. The unit also
  gains `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`,
  `ProtectSystem=full`, the `ProtectKernel*`/`ProtectControlGroups` set, and a
  `CapabilityBoundingSet` scoped to `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER`
  (the caps it needs to own enrolled files to the user). `ProtectHome`,
  `PrivateDevices`, and `MemoryDenyWriteExecute` are deliberately left off
  (per-user `$HOME` state, camera and TPM access, the ONNX runtime's JIT).
  Validated live: the daemon starts, loads models, binds the socket, and raises
  no SELinux denials under the restrictions.
- **`docs/THREAT_MODEL.md`** documents that the on-demand empty-Enter gesture
  already supplies the deliberate intent (FIDO User Presence) a passive
  face-auth tool otherwise lacks for `sudo`, so privilege elevation needs no
  extra challenge beyond the gesture and the default liveness gate.

### Security

- **A remote (SSH) session no longer fires the local camera.** The camera is
  physically at the machine, so on an SSH login or an `sudo` inside an SSH
  shell, whoever is in front of the camera (not the remote user) would satisfy
  the face factor. The PAM module now checks `PAM_RHOST` (and the `SSH_*`
  environment markers) up front and returns `PAM_IGNORE` for a remote
  transaction, so the password or another factor authenticates instead. Always
  on, independent of how the stack is wired.
- **Stage-2 fusion weighs the RGB modality by its real brightness.** The
  cross-spectrum path passed a hardcoded RGB face brightness of 0 into fusion's
  quality weight, so fusion always treated RGB as if the room were pitch-dark
  and collapsed the fused score toward IR regardless of actual light. That
  weakened the "an impostor must fool both modalities at once" bound in bright
  rooms. `assess_full` now measures the real RGB face luma (as the RGB-only
  path already did); the liveness gate is unchanged.
- **The dark (IR-only) path enforces the per-user calibrated depth floor.** The
  RGB path already required the live frame to clear the user's enrolled
  3D-structure floor; the dark path used only the lenient global ratio, so a
  curved warm spoof sitting between the two could be rejected in lit conditions
  yet granted in the dark. The same floor now applies on both paths.
- **The daemon self-test is gated to root.** `SelfTest` fires the camera and
  returns raw liveness measurements (IR brightness, depth, glint), a
  spoof-tuning oracle; it now refuses a non-root peer like the other
  camera-bearing requests, which matters on the permissive-socket fallback.
- **Sealed key and recovery files are created at mode 0600 atomically.** They
  were written and then `chmod`-ed, leaving a brief window where the file
  existed under the default umask. The payload is TPM-sealed or
  passphrase-wrapped, so the window was low-value, but the file is now opened
  with the mode set so it is never momentarily wider.

### Fixed

- **The pcrlock PCR parser rejects malformed hex instead of panicking.** The
  same class already fixed in the PCR-signature parser existed in `tpm::hex32`,
  which sliced two bytes at a time with no guard: an odd-length or non-ASCII
  (multi-byte) value in `pcrlock.json` panicked the root daemon. It now rejects
  odd-length and non-ASCII input up front, mirroring `pcrsig::from_hex`.
- **A non-finite detector score can no longer hide the real face.** A NaN
  detection score passed the `< threshold` test (false for NaN) and then ranked
  highest under `total_cmp`, so a single NaN cell would win the top-face pick
  and shadow the genuine face, forcing a false reject. Non-finite scores are
  now dropped at decode.
- **A truncated IR frame degrades to a safe deny instead of panicking.**
  `mean_in_bbox` indexed the frame assuming `len == width * height`; a short or
  mismatched buffer from the camera would panic. It now length-checks once and
  returns 0 (read as "too dark") on a short frame.
- **A wrong-dimension stored template can no longer crash the daemon.** The
  cosine matcher assumed both embeddings were the same length (only a
  debug-time assertion), so a template whose dimension differs from the live
  probe (a swapped recognizer model, which the daemon allows with a warning, or
  a truncated file) indexed out of bounds and panicked the root daemon into a
  restart loop. Mismatched lengths now score a definitive non-match, so the
  account falls back to re-enrollment instead. The IR path already filtered by
  dimension; this covers the RGB and identify paths.

## [0.3.0] - 2026-07-19

### Added

- **`irlume uninstall` (CLI and TUI).** Removes irlume the way it was
  installed, in a lockout-safe order: it un-wires PAM and stops the daemon
  first so a box is never stranded mid-auth, disarms the keyring, wipes
  `/var/lib/irlume` and `/etc/irlume`, then removes the package through
  whatever installed it (`dnf remove`, `apt-get purge`, `pacman -R`, or
  deleting the source-installed files) and clears the residual repo files and
  systemd drop-in that a plain package remove leaves behind. The TUI requires
  a typed-word confirmation before it proceeds.
- **NixOS module.** `nixosModules.irlume` (in the flake, backed by
  `nix/module.nix`) wires the daemon, PAM, and per-greeter login and lock
  configuration declaratively; `docs/NIXOS.md` documents it.
- **Merge-aware enrollment in the TUI.** Enrolling a face the system already
  knows now adds the new scans to that profile instead of creating a second
  one; a face maps to exactly one profile. This brings the 0.2.1 CLI behavior
  to the TUI (issue #15), with a confirmation prompt before the merge.
- **`irlume models`: opt-in third-party liveness models** (the runtime shape
  of the issue #4 `nonfree-pad` idea). The catalog lists externally-trained
  models with real weight licenses that fail the shipped-stack provenance bar;
  irlume never ships or mirrors them. `sudo irlume models enable flir` shows
  the license, the provenance status, and the measured numbers, requires the
  model name typed back plus a y/N, downloads once from the publisher's
  origin, verifies the pinned sha256, and restarts the daemon; `disable`
  deletes the weights and reverts to the shipped stack. The daemon wires an
  enabled model as a deny-only cue on the lit IR frame: it can turn a Live
  verdict into Spoof, never anything else (unit-tested invariant), and it
  refuses weights whose checksum stops matching. First entry: the MIT-licensed
  DAMO FLIR IR model, which closes the vinyl-print gap above. `irlume doctor`
  reports the enabled model.
- Third-party PAD candidate evaluation (issue #4 follow-through):
  `docs/pad-results/2026-07-17-third-party-pad-candidates.md` measures the two
  externally-trained liveness models that carry real weight licenses on real
  deployment hardware. The MIT-licensed DAMO FLIR IR model catches the
  vinyl-print species that defeats the algorithmic gate (122/123 frames across
  two cameras vs the gate's 98.6% APCER) with a clean genuine side; Intel's
  CelebA-Spoof-trained `anti-spoof-mn3` saturates at "spoof" for genuine users
  under indoor lighting and is not listed. Eval scripts and score summaries in
  `benchmarks/pad-candidates/`.
- `docs/STANDARDS.md`: maps the biometric standards that apply to a device
  login system (ISO/IEC 30107-3, 19795-1, 24745, the Windows Hello bar,
  Android's biometric classes) onto irlume's committed evidence, states what
  is not claimed under each (no certification, no Hello-bar FAR, no 3D-mask
  resistance), and points every number at the artifact and reproduction path
  behind it.
- `landmark_dump` example (issue #4): captures a raw IR strobe burst and
  writes, per frame, the PGM plus a CSV of all 478 FaceMesh landmark
  coordinates and the IR brightness (3x3 patch mean) at each; the input a
  landmark-anchored relief prototype needs without writing capture/detect/mesh
  glue. Coordinates print at full f32 precision so offline re-sampling from
  the CSV reproduces the tool's own brightness values exactly (verified: 8604
  landmarks across 18 live frames, worst delta 0.0044 from decimal printing).

### Changed

- **Ambient-flooded IR scenes get an actionable rejection.** When the scene's
  own infrared is strong enough to starve the anti-spoof depth and reflectance
  cues (measured threshold: ambient 170 on the 0-255 scale; above it, 0/129
  genuine samples passed in the 2026-07-16 field session), the denial now says
  "too much IR light behind you (open sky, sun, or bright lamps); turn away
  from the light or use your password" instead of "looks 2D, not a 3D face".
  Same fail-closed verdict, honest reason. The sensor cannot tell what the
  source is, so the message names examples rather than guessing. The measured
  ambient level also joins the liveness debug traces.
- The daemon startup notice about stale IR templates fires only when dark/dim
  login is actually broken (no usable current-space templates), not forever
  after a completed re-enroll.
- README documents the measured outdoor operating envelope; packaging comments
  record the verified distro onnxruntime versions (Fedora and Ubuntu are all
  below irlume's 1.24 floor, so the bundle stays).
- ARCHITECTURE.md documents the IR strobe capture and the opt-in ambient
  subtraction path with its gates (previously only in this changelog);
  ADR-0001 gains the acceptance bar for a future learned PAD model, including
  the model-inversion criterion raised in issue #4.
- Every operator-facing knob is now documented: SETUP.md gains a configuration
  reference (the four `/etc/irlume` + `/var/lib/irlume` config files, camera
  selection precedence, and the daemon environment variables from
  `IRLUME_MODELS_STRICT` through the TPM overrides), DEVELOPMENT.md lists the
  sandbox path overrides and the nine cargo example harnesses, and
  DEBUGGING.md covers the per-camera liveness tuning thresholds. `irlume
  set-cameras` appears in `irlume help` (it was the TUI picker's hidden
  backing command, but it is also the only scriptable way to persist a camera
  pair).

### Fixed

- **On Arch, the IR emitter self-heals at daemon startup, and the PAM
  include-layout wiring is corrected.** The daemon re-applies the IR emitter
  enable on startup so a suspend/resume or a fresh boot does not leave the
  emitter dark, and the PAM include layout is wired the way Arch's stack
  expects.
- **The PCR-signature parser rejects non-ASCII hex instead of panicking.** A
  multi-byte UTF-8 character in a hex field split a byte boundary and panicked
  the root daemon's parser; it now rejects non-ASCII input up front. Found by
  fuzzing the signature parser.
- **TUI micro-audit fixes.** A full pass over the TUI produced deliberate
  `[y]`/`[n]` confirmations (a stray key no longer counts as "yes"), correct
  rendering of the merge and delete prompts, a static two-row footer with all
  live messages moved to a scrollable Activity panel, and scroll-handling
  fixes for the enroll and operation views.
- **The universal `.deb` works on Debian 12 (and now Ubuntu 22.04).** It was
  built on Ubuntu 24.04 (glibc 2.39), so on Debian 12 (glibc 2.36) dpkg
  installed it and then every binary failed to start with "GLIBC_2.39 not
  found"; the package declared no libc floor, so nothing refused. The build
  now runs on a debian:12 base (binaries reference GLIBC_2.35 symbols at
  most), the package declares `libc6 (>= 2.35)` so older systems get a clean
  dpkg refusal instead of a broken install, and `build-deb.sh` asserts the
  declared floor covers what the binaries actually reference so a future base
  bump cannot reintroduce this silently. Found by container-testing the
  install matrix on Debian proper. The v0.2.1 release asset was rebuilt and
  replaced in place (same source, same tag; only the build base changed).
- **`install.sh` GPG verification can actually fire.** The script verified
  `SHA256SUMS.asc` against a keyserver fetch of the pinned key, but no `.asc`
  was published with releases and the key was not on keys.openpgp.org, so
  every install silently fell back to HTTPS + SHA256. Releases now ship
  `SHA256SUMS.asc`, and the installer carries the pinned public key inline
  (same trust anchor as the already-pinned fingerprint), importing it into a
  throwaway GNUPGHOME, with no keyserver dependency, and the user's keyring is
  never touched.
- **The Arch PKGBUILD builds on a clean system.** `clang` joins
  `makedepends`: the V4L2 bindings are generated by bindgen, which needs
  libclang at build time, so `makepkg` on a machine without clang failed in
  `v4l2-sys-mit`. Found by a container dry run of the AUR install; dev boxes
  had clang installed and never hit it. (AUR updated as pkgrel 2.)
- **Arch update and install paths point at the AUR.** `irlume update` on a
  pacman install and the one-step `install.sh` both still referenced a
  `.pkg.tar.zst` release asset that stopped shipping after 0.1.x, so each
  ended at a missing download. Both now use the AUR package (live since
  0.2.0): the installer runs `yay`/`paru` when present and prints the
  `makepkg` steps otherwise, and `irlume update` shows the helper and
  helper-less routes.

## [0.2.1] - 2026-07-16

### Fixed

- **`irlume enroll` merges into the matching profile instead of refusing.** A
  face can never own two profiles, so when a capture matches an existing
  profile the only thing the old refusal ("this face is already enrolled
  as ...") accomplished was forcing the same scans through `add-scan` by hand.
  Now the captured scans are added to the matching profile (up to the 30-scan
  cap; a full profile still refuses), the per-enrollment IR calibration is
  refitted, and the reply says what happened. A novel face still creates a new
  profile, and a capture that matches two different profiles is still refused.
  This also makes `irlume enroll` work as the documented 0.2.0 upgrade remedy:
  the anti-mixing guard used to refuse upgraders, whose faces still match
  their old profile through the unchanged RGB path, exactly when they needed
  fresh current-space scans to revive dark/dim login. On 0.2.0 itself, the
  working paths are `irlume tui` (Profiles, improve) or `irlume enroll --reset`.
- **Enroll captures only what fits.** A one-scan probe decides whether the
  face merges into an existing profile and sizes the session from the free
  slots: a profile with 5 slots left gets a 5-scan top-up instead of a 10-scan
  session that discards half, and a full profile (30 scans) is refused after
  one scan instead of ten. A new face still gets the normal 10.

## [0.2.0] - 2026-07-15

> **⚠ Breaking: re-enroll needed for dark/dim login.** This release removes the
> IR adapter (see Removed). Face profiles enrolled under 0.1.x have IR templates
> in the old adapter's embedding space, which no longer matches. **Bright-light
> (RGB) face login keeps working**, and any mismatch falls back to your password
> as usual, but **dark/dim (IR) login stops until you re-enroll**: run
> `irlume enroll`. Nothing else is required and no data is lost.

### Added

- **Detection cascade: BlazeFace short-range rescue.** YuNet stays the primary
  detector; when it finds no face (measured on saturated outdoor-walking frames:
  76.9% detected), a BlazeFace short-range pass runs and FaceMesh refines its
  box into the 5 alignment points. The cascade detects 98.5% of those frames
  while never firing when YuNet succeeds, so easy detection is unchanged (LFW:
  0 rescues, identical accuracy). Both models are Apache-2.0.
- **FaceMesh upgraded to the 478-point FaceLandmarker mesh** (256px), converted
  from Google's Apache-2.0 `face_landmarker.task`. Measured 28% better eye
  accuracy on CBSR ground truth (NME 0.0378 → 0.0273). The loader auto-detects
  the input size and accepts either the 468 or 478 generation.
- **Per-enrollment IR calibration (ADR-0004).** A ridge-regularized linear map
  fitted on-device from each user's own consented scans, pulling IR embeddings
  toward their RGB space; it activates whenever no global adapter is loaded and
  ships no weights (no license surface). Replaces the research-only-trained
  `ir_adapter.onnx` (now removed, see below).
- **Presence grace window after the consent gesture.** After the blank-Enter
  gesture, capture retries while no usable face is in frame so walking up or
  settling still authenticates: ~15s for login/lock, ~5s for `sudo`/`su`
  (`IRLUME_GRACE_MS` overrides). Only presence-class failures retry, never a
  below-threshold match (FAR-neutral by construction).
- **IR-template embedding-space tagging** so a future adapter swap/removal fails
  loud ("re-enroll") instead of scoring across embedding spaces.

### Removed

- **`ir_adapter.onnx` dropped from the repo and every package (ADR-0004).** Both
  versions that ever shipped were trained on the CBSR NIR (OTCBVS dataset 07) and
  Oulu-CASIA NIR academic datasets, whose licenses cover research/education only;
  bundling them conflicted with the commercial freedom GPLv3 grants downstream, so
  the shipped stack is now MIT/Apache-2.0 only. The default IR path is raw AuraFace
  plus the per-enrollment calibration above, which the ADR's own measurements show
  is also the better default (the global adapter slightly *worsened* every unseen
  identity). The optional `--adapter` / `IRLUME_IR_ADAPTER` hook remains for a
  user-supplied clean-licensed adapter. **Upgrade note:** an enrollment made
  against the old adapter is tagged with its embedding space and must be
  re-enrolled after updating; the daemon refuses to match across spaces.

### Changed

- Enabled the cargo-deny license gate (`check licenses` in CI) with a curated
  permissive + GPL-compatible allowlist; no non-commercial or AGPL/SSPL license
  is permitted in the dependency tree.
- Dropped the unused `ndarray` dependency (the `ort` bridge only used the tuple
  tensor API), trimming the build; reduced per-match string allocation in the
  argmax path. No auth-decision, threshold, or model change.
- Added a Microsoft trademark disclaimer for the descriptive "Windows Hello"
  references.

## [0.1.5] - 2026-07-12

### Added

- **Tier 2 TPM sealing via systemd-pcrlock.** On a machine where the admin has
  run `systemd-pcrlock make-policy`, new seals bind to the pcrlock NV index
  (`TPM2_PolicyAuthorizeNV`). A firmware or Secure Boot update then needs one
  `make-policy` re-run instead of a re-arm, and the sealed password keeps
  releasing. Sealing tries Tier 1 (signed PCR policy), then Tier 2, then the
  literal PCR-7 seal, and round-trip-verifies each candidate before trusting
  it, so a policy that cannot unseal on the current boot never holds the
  secret. Existing envelopes are untouched until the next arm or reseal.
- `irlume status` and the TUI keyring panel now name the seal tier and warn
  when the bound PCRs have drifted since sealing. This uses a new daemon
  `KeyringInfo` request; against an older daemon both surfaces fall back to
  the previous armed yes/no display.
- `irlume diag` reports whether a pcrlock policy is provisioned and which NV
  index new seals would bind to.
- The daemon log names the exact remedy when a PCR drift locks face
  authentication (re-arm for a literal seal, `make-policy` for pcrlock).
- TPM fault-injection test hooks and ignored real-hardware tests covering
  pcrlock seal/unseal, drift, and the seal-tier ladder.

### Changed

- The `tss-esapi` dependency builds from the `irlume-patches` branch of our
  fork: tss-esapi 7.7.0 plus the `PolicyAuthorizeNV` wrapper (upstream merged
  it in 2024 but never shipped it in a 7.x release) and upstream PR #530's
  session-handle leak fix. `Cargo.lock` pins the exact commit.
- IR ambient subtraction (opt-in via `IRLUME_IR_AMBIENT_SUBTRACT=1`) reworked
  its gate against a real sunlight dataset. Under strong ambient IR the sensor
  saturates and a genuine strobe compresses to a gap of ~8-10, so the old
  fixed gap of 20 blocked subtraction in exactly the sunlit captures that
  needed it; the strobe threshold is now the sensor-noise floor (8). After
  subtracting, the result must retain enough mean signal (12) or the raw lit
  frame is kept, so a bright pedestal that collapses the subtracted frame can
  no longer hand a blank image downstream. On 33 genuine bursts this lifts the
  IR depth cue over its floor in 7 more cases with no regression to any that
  already passed. Still opt-in: enabling it by default needs flat-spoof
  captures under the same light and a re-enroll so the per-user floor matches.
  A new `IRLUME_DEV=1 irlume suncal <det> <dir>` tool scores such a dataset.

### Fixed

- TUI: the Activity-history scroll (PgUp/PgDn) now works during a running
  operation and mid-enrollment, and the Welcome screen's `[i]` identify key
  works in the default view; both were previously swallowed by the panel's
  key handling.
- A pcrlock policy that covers zero PCRs is refused at seal and unseal time;
  binding a secret to it would give no measured-boot protection.

## [0.1.4] - 2026-07-07

A distribution and self-update release: face authentication itself is
unchanged; this makes installing and updating irlume smooth on every distro.

### Changed

- **`irlume update` is fully adaptive.** It reports the version your package
  manager has installed, detects the exact channel it came from (Copr,
  PPA, the GitHub `.deb`, the pacman package, or a source build), matches the
  release asset for your CPU architecture, and only offers a download that
  exists: no more dead links or steering an Ubuntu derivative to a PPA
  that can't serve it.
- **Two Ubuntu lanes.** The PPA carries the current Ubuntu LTS (native,
  auto-updating); every derivative (Mint, Pop!_OS, Zorin, elementary) uses the
  universal `.deb` below: one binary that installs on Ubuntu 24.04 and newer.
- Declared minimum Rust is now 1.88 (the real floor, via the ONNX Runtime binding).

### Fixed

- Arch: `git lfs pull` fetches the model weights correctly under `makepkg`.
- PPA source builds pack a deterministic orig tarball.

### Downloads: which asset do I need?

Prefer your distro's repo (`dnf` / the PPA / the AUR-style package) so updates
arrive automatically; these assets are direct downloads for everyone else.

- **`irlume_0.1.4_amd64.deb`**: Debian and Ubuntu derivatives. Built on the
  oldest supported Ubuntu base, so this single file installs on Mint, Pop!_OS,
  Zorin, elementary, and any newer Ubuntu (`sudo apt install ./…`).
- **`irlume-0.1.4-1-x86_64.pkg.tar.zst`**: Arch Linux (`sudo pacman -U ./…`).
- **`irlume-0.1.4-1.fc44.x86_64.rpm`**: Fedora, the main package
  (`sudo dnf install ./…`). The [Copr](https://copr.fedorainfracloud.org/coprs/archledger/irlume)
  is the auto-updating Fedora channel and pulls the SELinux policy in for you.
- **`irlume-selinux-0.1.4-1.fc44.noarch.rpm`**: the SELinux policy companion for
  the Fedora RPM. Fedora enforces SELinux by default and the login greeter can't
  reach the daemon without this module. It's a *weak* dependency, so a local
  `dnf install ./main.rpm` won't pull it automatically; install it alongside the
  main RPM on an enforcing system. It's `noarch` because the policy is
  architecture-independent (that's also why it's a separate package, not baked
  into the `x86_64` RPM).

## [0.1.3] - 2026-07-07

Display-manager coverage, new diagnostics, security hardening, and a much
friendlier guided enrollment.

### Added

- **Every major login manager is now profiled** for consent-driven face auth:
  GDM (on-demand on GNOME ≥ 46, face-first below), SDDM, LightDM (gtk + slick),
  greetd, COSMIC's greeter, and KDE's Plasma Login Manager, each wired to the
  behaviour its greeter supports. Face is **on-demand** by default:
  leave the password empty and press Enter; typing a password never starts the
  camera.
- **`irlume logs`**: every face-auth journal line (daemon, PAM grantors, keyring
  modules) in one view, with `-f` / `--since`. **`irlume logs debug
  on|off`** toggles per-stage pipeline tracing (`IRLUME_LOG=debug`) for
  diagnosing a failed or slow login: capture timings, liveness cues vs
  thresholds, match scores. Numbers only; never frames, embeddings, or secrets.
- **Directional enrollment guidance**: the framing guide now tells you which way
  to turn ("Turn your head left") and tilt ("Lift your chin"), and **auto-
  calibrates the frontal pitch neutral per user/camera** so the coaching centres
  on wherever a level face reads on your hardware. Fresh enrollment now captures
  **5 scans** (was 3).
- A per-tab **hint bar** in the TUI so a first-time user always knows what a
  screen is for and which key to press. `docs/DEBUGGING.md` scrutineer's guide.

### Security

- **1:N `identify` and identity verification are peer-authenticated**: a
  non-root caller is scoped to its own account (root keeps the cross-user
  search), closing a similarity-score oracle on a world-connectable socket.
- **Journal deny lines are redacted** with tracing off: denied-attempt scores
  quantize to one decimal and cue measurements are stripped, so the system
  journal can't be used as a spoof-tuning oracle. Exact values still reach the
  session's own TUI/CLI for false-reject coaching.

### Fixed

- **Enrollment enforces frontal framing at capture, not just before the
  countdown**: drifting off-angle during the 3-2-1 re-frames instead of saving
  a bad-angle template.

## [0.1.2] - 2026-07-05

First-run smoothness release, driven by a screen-recorded fresh-install test
on Fedora: install → `irlume tui` → press `[e]` → enrolled → `[w]` → wired,
with no terminal detours.

### Fixed

- **Fresh installs work immediately**: the Fedora package now enables and
  starts `irlumed` at install (systemd preset + scriptlet), matching what the
  Arch and Debian packages already did. Previously the daemon shipped disabled
  and the first enrollment failed with a cryptic `os error 2`.
- **SELinux**: `dnf install irlume` now pulls the policy subpackage in by
  default (weak dependency), and both the subpackage scriptlet and
  `irlume login enable` restart the daemon after loading the module; the
  already-bound socket kept its pre-policy label, which silently blocked the
  confined greeter until the next reboot.
- `sudo irlume login disable --apply` now always unwires `/etc/pam.d/sudo`
  (the "undoes everything" promise was false unless `--with-sudo` was passed).
- Daemon-unreachable errors name the exact fix
  (`sudo systemctl enable --now irlumed`) instead of `os error 2`; the
  dry-run `login disable` no longer claims it removed the SELinux module.
- Security-audit hardening: enrollment saves are atomic (0600 temp + rename,
  no truncation on crash, no permissions window); the daemon zeroizes response
  buffers that may carry an unsealed credential; a cancelled sudo during the
  enroll fix no longer freezes the TUI; PAM-file restores keep admin edits
  made after wiring (strip-in-place unless the file is otherwise unchanged).

### Changed

- **TUI essential view**: the wizard shows only the setup path: Welcome →
  Enroll → Keyring → Recovery → Login wiring → Done. `[v]` reveals all tabs;
  Repair appears automatically when something fails.
- **Press `[e]` and it works**: enrolling with a stopped daemon now runs the
  sudo enable+start fix and resumes enrollment automatically.
- **`[w]` wires login from the TUI** (Done tab and Login-wiring tab); the Done
  dashboard gained a "login wiring" row and says "one step left" instead of a
  premature "All set".
- Enrollment guidance (glasses profile, appearance changes, sunlight) on the
  Profiles tab and in the README FAQ; THREAT_MODEL now states that the
  fingerprint companion has no presentation-attack detection of its own.
- New `irlume version` subcommand, and `irlume update` now detects how irlume
  was installed (Copr, PPA, release asset, source) and updates through that
  same channel.

## [0.1.1] - 2026-07-04

Packaging-only patch release: makes the Fedora Copr pipeline work end-to-end.
No functional changes to the daemon, CLI, or PAM module.

### Fixed

- **Fedora/Copr builds now succeed** (validated live in Copr): Packit jobs
  request build-time networking (`enable_net`) so cargo can reach crates.io;
  `Cargo.lock` is now committed so `cargo build --locked` works from release
  tarballs; the spec gained the missing `clang-devel`, `kernel-headers`, and
  `pkgconf-pkg-config` BuildRequires (bindgen for V4L2, pkg-config for
  tss-esapi); and the SELinux policy module is compiled from its committed
  `.te` source during the build instead of expecting a pregenerated `.pp`.
- Fedora users can install from Copr: `dnf copr enable archledger/irlume &&
  dnf install irlume`.

### Notes

- Arch (`.pkg.tar.zst`) and Debian/Ubuntu (`.deb`) packages are functionally
  unchanged from v0.1.0; the v0.1.1 release ships freshly built assets.

## [0.1.0] - 2026-07-03

First public release. Local infrared face authentication for Linux:
clean-BOM, TPM-sealed, engineered to meet or beat Windows Hello. The password
is always the fallback: no lockout, ever.

### Added

- **Privilege-separated architecture**: a thin `pam_irlume.so` module and
  `irlume` CLI are untrusted clients of a privileged `irlumed` daemon (the only
  component that touches the camera, IR emitter, models, templates, or TPM),
  over a `SO_PEERCRED`-authenticated Unix socket.
- **Clean model bill-of-materials**, all permissive & GPLv3-compatible, bundled:
  YuNet (MIT) detection, AuraFace 512-D ArcFace (Apache-2.0) recognition,
  self-built algorithmic IR liveness, and opt-in passive blink liveness via
  MediaPipe FaceMesh (Apache-2.0) eye-aspect-ratio.
- **Encrypted at rest**: templates are 512-D embeddings only (never images),
  AES-256-GCM encrypted under a key the TPM seals to boot state. Disk-theft
  tested: sealed data is undecryptable on another machine.
- **Hardware tiers**: IR camera → Secure (login, `sudo`, lock screen, keyring
  unlock); RGB-only → Convenience (screen unlock only); optional fingerprint
  companion factor.
- **TPM-sealed keyring unlock**: a face login unseals the login password and
  hands it to gnome-keyring / KWallet, so the wallet opens with no prompt.
- **Method/tier/login-manager-aware PAM wiring** (`irlume login enable`) for
  GDM, SDDM, and Plasma `plasmalogin`; opt-in, never auto-wired on install.
- **Guided TUI** (`irlume tui`) for enrollment, configuration, live status, and
  a Repair tab that detects and fixes common issues.
- **Packaging for all three families**: Fedora RPM (Copr/Packit), Arch
  PKGBUILD, Debian/Ubuntu `.deb` (nfpm). onnxruntime is bundled on Fedora and
  Debian/Ubuntu; Arch uses the system package.

### Security

- ISO/IEC 30107-3 PAD self-test tooling (`padcapture` / `padreport`) with
  per-species APCER / BPCER / ACER and exact-binomial confidence intervals.
- SO_PEERCRED + operation-class biopolicy gate on credential release (opt-in, off by default);
  bounded request size and read/write timeouts on the daemon socket.

### Known limitations

- Passive blink liveness is a deterrent, not a guarantee: a determined
  life-size glossy print can still slip through occasionally, and it does not
  cover glasses-wearers; every miss falls safely to the password.
- RGB-only laptops get the Convenience tier by design (face never releases
  credentials).
- Not lab-certified: self-tested against ISO/IEC 30107-3, no paid iBeta pass.

[Unreleased]: https://github.com/archledger/irlume/compare/v0.7.2...HEAD
[0.7.2]: https://github.com/archledger/irlume/releases/tag/v0.7.2
[0.7.1]: https://github.com/archledger/irlume/releases/tag/v0.7.1
[0.7.0]: https://github.com/archledger/irlume/releases/tag/v0.7.0
[0.6.1]: https://github.com/archledger/irlume/releases/tag/v0.6.1
[0.6.0]: https://github.com/archledger/irlume/releases/tag/v0.6.0
[0.5.0]: https://github.com/archledger/irlume/releases/tag/v0.5.0
[0.4.0]: https://github.com/archledger/irlume/releases/tag/v0.4.0
[0.3.0]: https://github.com/archledger/irlume/releases/tag/v0.3.0
[0.2.1]: https://github.com/archledger/irlume/releases/tag/v0.2.1
[0.2.0]: https://github.com/archledger/irlume/releases/tag/v0.2.0
[0.1.5]: https://github.com/archledger/irlume/releases/tag/v0.1.5
[0.1.4]: https://github.com/archledger/irlume/releases/tag/v0.1.4
[0.1.3]: https://github.com/archledger/irlume/releases/tag/v0.1.3
[0.1.2]: https://github.com/archledger/irlume/releases/tag/v0.1.2
[0.1.1]: https://github.com/archledger/irlume/releases/tag/v0.1.1
[0.1.0]: https://github.com/archledger/irlume/releases/tag/v0.1.0
