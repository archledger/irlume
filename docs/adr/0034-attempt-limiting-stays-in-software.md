# ADR-0034: Keep attempt limiting in software and irlume out of the TPM lockout

## Status

Proposed 2026-10-15.

Records why irlume does not move its attempt limits into the TPM, and what
it changes instead. The consecutive unsuccessful request ceiling (#683,
THREAT_MODEL.md "Intent, throttling, and privilege elevation") and the
reset-password budget (DISABLE.md "Password-verified retry reset") are
unchanged and stay the only attempt limits. Changes no sealing policy and
no PCR binding: the Tier 2 and Tier 3 policies, ADR-0025's one unseal per
request and ADR-0026's transport are untouched. Section 3 changes the
attributes of irlume's storage key and so needs a migration of every sealed
envelope; section 3.4 leaves evicting the old key to the daemon-performed
eviction tracked in #1073.

Amended 2026-10-15 by the [new key's template
record](#amendment-2026-10-15-the-new-storage-keys-template-carries-an-irlume-label)
below: the new storage key's template also carries an irlume label in
`unique`, so that no other stack's storage key is irlume's by derivation.

Amended 2026-10-16 by the [Phase 3
record](#amendment-2026-10-16-phase-3-retires-a-storage-key-at-irlumeds-start)
below: irlumed's start retires an unused storage key itself, a root-only
request retires one that only its recorded name identifies, and a weak
(ROCA) storage key is replaced by moving its envelopes first (#1073).

## Context

### What irlume limits today

Each account has a durable budget of 50 consecutive unsuccessful requests,
shared by face verification and credential release
(`crates/irlume-daemon/src/retry_throttle.rs`, `FACE_LIMIT`). Inside it,
short strikes add rests: by default every 5 striking outcomes (a spoof, a
below-threshold match, an expired deadline, an unavailable runtime or
another denial; no face, an uncertain result and the setup outcomes charge
the budget without striking) start a 30-second cooldown, after which the
strikes start again from zero
(`IRLUME_RATE_LIMIT` 1 to 5, `IRLUME_RATE_COOLDOWN_SECS` 30 to 86400). The
charge is written before any engine work, so a crash, an error, a
cancellation or a reboot keeps it. Cooldowns use `CLOCK_MONOTONIC` and the
boot ID, so a civil-clock change does not shorten them, and a reboot
restarts a recorded cooldown for its full length. Only a written face
grant, a verified password reset or an administrator reset clears the
count. Records are 0600 root files under the 0700 root-owned
`/var/lib/irlume/retry`. The password-verified reset has a budget of its
own (`<uid>.reset.json`, `retry_throttle/recovery.rs`): after 5 failed
checks each further check waits 30 seconds, and at 50 an administrator
must reset it.

DISABLE.md ("Persistent retry records") states the limit: "Write-ahead
charges survive crashes and reboot, but cannot resist root deletion or disk
rollback." THREAT_MODEL.md puts "Root deletion, disk rollback and the
ambiguity between socket delivery and durable reset" outside "an
exactly-once guarantee".

### The question

Microsoft gives its reason for counting failed guesses of a PIN in the TPM
rather than in software: "Software solutions might provide similar
features, but they can't provide the same level of protection, especially
if the system restarts, the system clock changes, or files on the hard
disk that count failed guesses are rolled back" (Microsoft Learn, "How
Windows uses the Trusted Platform Module", Platform Crypto Provider). A
TPM 2.0 offers two mechanisms irlume could use (TPM 2.0 Library Part 1,
version 185, clause numbers below):

- **Dictionary-attack (DA) protection on an authorization value.** The
  authValue of every object without `noDA` and every NV index without
  `TPMA_NV_NO_DA` "receives DA protection" (16.8.1). One set of counters
  serves the whole chip (16.8.2), and it counts failed authValue checks:
  `failedTries` "is incremented when the TPM returns TPM_RC_AUTH_FAIL"
  (16.8.2), while a failed policy returns `TPM_RC_POLICY` "to indicate that
  dictionary attack protection was not involved" (16.8.3). While
  `failedTries` equals `maxTries`, "any use of a DA-protected authValue
  will return TPM_RC_LOCKOUT" (16.8.3). `failedTries` falls by one after
  each `recoveryTime` without a failure or a power interruption (16.8.2),
  and a TPM that starts after a non-orderly shutdown counts one more
  failure (16.8.6; a note there allows counting it only when a DA-protected
  object was used in that boot). `TPM2_DictionaryAttackLockReset` (16.8.4)
  and `TPM2_DictionaryAttackParameters` (16.8.2) need Lockout
  Authorization, `lockoutAuth` or `lockoutPolicy`, and a wrong
  `lockoutAuth` blocks further attempts until `lockoutRecovery` has passed
  or `lockoutPolicy` succeeds (16.8.5).
- **An NV counter in the release policy.** A `TPM_NT_COUNTER` index changes
  only through `TPM2_NV_Increment` and starts above any value a counter of
  the same name ever had (34.2.6.3); `TPM2_PolicyNV` can make an unseal
  conditional on its value (34.2.7). A PIN Fail index gives one "authValue
  (PIN)" a failure count of its own, outside the global one (34.2.8.2), but
  it too counts failures of a secret the user enters.

### Measured on the maintainer's machines

Read-only `GetCapability`, 2026-10-15 (evidence:
`artifacts/irlume/2026-10-14-windows-tpm-research/` on the shared ledger,
NOTES.md section 7):

| | Zenbook (Intel PTT) | ThinkPad T480 (STMicroelectronics) |
|---|---|---|
| `lockoutAuthSet` | 1 | 1 |
| `MAX_AUTH_FAIL` / `LOCKOUT_INTERVAL` / `LOCKOUT_RECOVERY` | 32 / 7200 s / 86400 s | 32 / 7200 s / 86400 s |
| NV counters defined / `NV_COUNTERS_AVAIL` / `NV_COUNTERS_MAX` | 5 / 0 / 128 | 4 / 12 / 0 (no limit) |

Both TPMs carry a lockout authorization this Linux install does not know.
Who set it is not established. Windows is a candidate: since 1703 its
default keeps the lockout authorization ("For TPM 2.0, a value of 5 means
keep the lockout authorization", Microsoft Learn, "TPM Group Policy
settings"). The parameters are the Windows 8 certification values "32,
7200, and 86400" (TCG TPM v2.0 Provisioning Guidance 1.0 r1.0, 7.7), the
profile of Windows 10 1607 and earlier ("32 PIN guesses immediately, and
then only one more guess every two hours", "TPM fundamentals"); current
Windows instead configures the TPM "to lock after 32 authorization failures
and to forget one authorization failure every 10 minutes" (same page). A
lockout on these machines cannot be reset from Linux without clearing the
TPM. Where Linux provisioned the TPM itself, `lockoutAuth` is usually
empty (a cleared TPM's is EmptyAuth, Part 1 10.8.1), and then any process
that can open the TPM can reset the lockout or change its parameters, as
the swtpm test below did. The Zenbook reports no room for another orderly
NV counter (`NV_COUNTERS_AVAIL` counts indexes "with their TPM_NT of
TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET" and "is an
estimate", Part 2 version 185, table 28). A counter without
`TPMA_NV_ORDERLY` writes NV on every increment (Part 1 34.2.4.3); after a
non-orderly shutdown an orderly one is set to its stored value ORed with
`MAX_ORDERLY_COUNT`, a jump of up to that many counts (34.2.6.3); the TPM
may refuse a write with `TPM_RC_NV_RATE`, and the specification gives no
endurance figure (34.6).

### Who else uses the DA counter and NV space

- systemd-cryptenroll: a wrong TPM2 PIN "increments the TPM dictionary
  attack lockout mechanism, and may lock out users for a prolonged time ...
  The lockout mechanism is a global property of the TPM, systemd-cryptenroll
  does not control or configure the lockout mechanism"
  (`man/systemd-cryptenroll.xml`, systemd main at b44cca76b958). In
  `src/shared/tpm2-util.c`, `tpm2_seal` sets `TPMA_OBJECT_NODA` on its
  sealed object unless a PIN is used (`hmac_attributes |= pin ? 0 :
  TPMA_OBJECT_NODA;`), and its storage key template sets it.
- Windows Hello on a dual-boot machine: the PIN protector is "a TPM seal
  operation using the PIN as entropy", so each wrong PIN is a DA failure
  against the same counter (Microsoft Learn, "How Windows Hello for
  Business works"). Hello also limits failed face and fingerprint attempts:
  "after multiple unsuccessful attempts, a specific biometric method ...
  may become temporarily unavailable", and "Restarting the device does not
  restore biometric availability" (Hello for Business FAQ). Microsoft
  gives no number for it and, unlike the PIN's, does not attribute it to
  the TPM.
- Windows keeps a software budget in front of the TPM too: by default a
  standard user may cause 4 TPM authorization failures, and all standard
  users together 9, in 480 minutes, because "When the TPM enters a lockout
  mode, it's global for all users" ("TPM Group Policy settings"). TCG
  expects this: "the operating system will layer additional anti-hammering
  protection atop that provided by the TPM" (Part 1 16.8.8.1).
- systemd allocates NV indexes for pcrlock and for its NvPCRs, and flags NV
  index space found exhausted in a boot, separately for orderly and
  non-orderly NvPCRs
  (`/run/systemd/tpm2-nv-space-exhausted-{orderly,non-orderly}`).

### What the TPM can and cannot check

The TPM verifies secrets (an authValue, through an HMAC or password
session) and policies. It cannot judge a face. irlume's face decision is
made in software by irlumed, and the credential it then releases is sealed
in an object authorized only by its PCR policy (`tpm.rs` `sealed_template`
leaves `userWithAuth` clear, so its empty authValue cannot be used). So:

- A DA-protected authValue limits guesses of a secret. The face path has no
  such secret. Adding one would mean a PIN for every face login, a different
  product. The recovery passphrase is a secret, but it is the backstop for
  exactly the cases the TPM cannot serve (the TPM cleared, Secure Boot off,
  the disk in another machine; `crates/irlume-core/src/recovery.rs`), so it
  stays an offline Argon2id envelope with a 12-character floor and cannot
  depend on the TPM.
- An NV counter in the policy limits unseals, not face attempts. To count
  face attempts, irlumed would have to increment it before each attempt, so
  it binds only an irlumed that follows the rules, which is the same daemon
  that already enforces the software budget.

The counter would only add something against an attacker who can restore
an older retry record but cannot otherwise control the running system:

| Attacker | Software budget | NV counter adds |
|---|---|---|
| Local account without root | Enforced: records are root-only. | Nothing. |
| Root on the running system | Can delete records, read daemon memory, or unseal directly (PCR policy, no authValue). | Nothing: root needs no face attempts. |
| Physical access, state on full-disk encryption unlocked by a passphrase or PIN | Cannot read or rewrite the record offline; restoring an older image of the whole volume is the last row. | Nothing beyond the last row. |
| Physical access, no such encryption | Can rewrite the record offline, and the rest of the installed system with it, for example `/etc/shadow`, the PAM stack or irlumed ("the installed system can be changed offline", SECURITY_AT_REST.md "Disk-theft test"). | Nothing that matters: the machine is already open. |
| Physical access, a verified root (dm-verity) covering the system and `/etc`, the state directory writable and not encrypted | Can rewrite the record offline, but not the verified system. | Nothing that matters: on that configuration the whole state directory is untrusted input that the offline writer controls (below). |
| Physical access that can boot an older or writes-discarded copy of the state directory on a boot chain the seal accepts, and nothing more (for example a boot menu that offers file-system snapshots but locks command-line editing) | Each such boot starts from the older record. | Closes this case. |

The last row is narrow: on most installs the same position, an editable
boot menu or no disk-encryption PIN, already gives root. No configuration
irlume can check closes it. Full-disk encryption unlocked by a passphrase
or PIN under `/var/lib/irlume` (a volume the TPM or a key file unlocks
alone does not count, SECURITY_AT_REST.md layer 3) narrows it: an older
copy, even a block-level image restored without the key, then boots only
when someone who knows the secret unlocks it, and the owner loses every
change made since that copy. It does not make the record fresh: dm-crypt
"provides transparent encryption of block devices" (kernel dm-crypt
documentation), with no counter, so a restored valid older volume unlocks
as usual. A verified root does not cover the writable state directory,
and a pcrlock policy over the boot loader cannot tell an older copy of
that directory from the current one, since the same boot loader boots
both (a policy that covers PCR 4 "never closes" offline change, layer 3).
Only a monotonic counter outside the disk, such as the TPM's, would close
it.

The verified-root row: what irlume reads from `/var/lib/irlume`, the
enrollments and sealed keys as well as the retry records, is state an
offline writer of that directory controls, so on that configuration the
state directory is untrusted input and the rollback of one record is not
the weakest point. SECURITY_AT_REST.md layer 3 offers a verified root as a
remedy for the offline change of the installed system; it does not
protect the writable state directory, which needs full-disk encryption
unlocked by a passphrase or PIN for any at-rest guarantee about its
contents. Section 5 says so.

Against that, a counter costs: an NV index that can fail to allocate (the
Zenbook has no orderly one left) and that competes with systemd; one NV
write per attempt; a reset that needs either a reseal of every envelope or
a second NV index composed with the Tier 2 `PolicyAuthorizeNV` policy;
loss of the counter on a TPM clear; and a new failure mode on every
authentication.

### A gap found while checking

irlume's sealed objects set `noDA`, but its storage key does not:
`srk_template` in `crates/irlume-core/src/tpm.rs` sets `fixedTPM`,
`fixedParent`, `sensitiveDataOrigin`, `userWithAuth`, `restricted` and
`decrypt`. Every seal (`TPM2_Create`) and every unseal (`TPM2_Load`)
authorizes that key with its empty authValue. The TCG storage-key template,
which systemd uses, sets `noDA` "because of the convention of assigning a
well-known Authorization Value of all zeroes to shared SRKs" (Provisioning
Guidance 7.5.1; `tpm2_get_srk_template` in `tpm2-util.c`: "TPMA_OBJECT_NODA
is added"). irlume's key has the same empty authValue, so its DA
protection guards no secret.

Tested on a throwaway swtpm 0.10.2 (libtpms 0.10.2, tpm2-tools 5.8) with no
host TPM visible, 2026-10-15 (evidence: `research-item5-2026-10-15/` in the
same directory, `swtpm-da-lockout/` and `swtpm-audit-2026-10-15/`, scripts,
logs and checksums). After two wrong PINs on a DA-protected test object put
the TPM in lockout:

- `TPM2_Load` and `TPM2_Create` under a key made from irlume's
  `srk_template` failed with `TPM_RC_LOCKOUT` (0x921), for a Tier 3
  (PolicyPCR) and a Tier 2 (owner-authorized `PolicyAuthorizeNV` over an
  owner-read NV index) object alike.
- Objects with the same templates and policies under a key with `noDA` set
  loaded and unsealed, with the policy session unsalted, salted with that
  key (as irlume's `with_session` salts with the storage key, unbound), or
  salted and bound to it. Starting a session salted with the `srk_template`
  key also succeeded; only the `Load` under it failed.
- `TPM2_CreatePrimary` under the owner hierarchy, and
  `TPM2_DictionaryAttackLockReset` with an empty `lockoutAuth`, worked.
- The lockout ended one `recoveryTime` after the last failure, the counter
  then one below the maximum.

This matches the specification. Lockout makes no exception for an empty
authValue (16.8.3; the TCG reference code's `CheckAuthSession` marks a
password session's authValue used and calls `CheckLockedOut` for any handle
`IsDAExempted` rejects), a `noDA` object is "not subject to lockout"
(22.2.6), a permanent hierarchy other than lockout gets no DA protection
(16.8.1), and the reference code notes that "a policy is still usable even
if the object is DA protected and the TPM is in lockout" when the policy
uses neither `PolicyAuthValue` nor `PolicyPassword`. So a lockout caused by
anything else on the machine, such as wrong LUKS TPM2 PINs typed at boot or
a Windows Hello PIN on dual boot, stops irlume's face login and fingerprint
keyring unlock until it ends: one `recoveryTime` of powered-on time after
the last failure, 2 hours on the machines above, which a power interruption
can restart (16.8.2). The failure is closed, to the password, so it is an
availability defect, not a bypass.

## Decision

### 1. The attempt limits stay in software

The consecutive unsuccessful request ceiling and the reset-password budget
stay irlume's only attempt limits, as shipped in #683 to the design in
`docs/superpowers/specs/2026-09-08-cumulative-retry-recovery-design.md`.
irlume does not add a DA-protected authValue or an NV counter to any
release path, by default or as an option. Against Microsoft's three
failure modes:

- **Restart:** the charge is written before engine work and survives
  crashes and reboots (unchanged).
- **Clock change:** cooldowns use the monotonic clock and the boot ID, and a
  reboot restarts a recorded cooldown (unchanged).
- **Rollback:** not covered, and accepted as a residual. The record resists
  neither root nor offline change, as documented; the Context table shows
  that only the narrow older-copy boot is an attacker a TPM counter would
  stop. Full-disk encryption unlocked by a passphrase or PIN under the
  state directory narrows that case to boots someone who knows the secret
  unlocks, but does not close it. Section 5 makes the documentation say so.

### 2. irlume stays out of the DA counter

Every TPM object irlume creates for its own seals is DA-exempt: the sealed
objects (already `noDA`) and, from section 3, its storage key. No object
irlume creates has a secret authValue (the storage key's is empty). irlume
sends no `TPM2_DictionaryAttackLockReset` or
`TPM2_DictionaryAttackParameters` (the pinned tss-esapi has no wrapper for
either, so a call would go through raw `Esys_` bindings), defines no NV
counter, and never asks for, stores or derives `lockoutAuth`. irlume
never causes an authorization failure in the budget that disk unlock PINs
and Windows Hello depend on: none of its authorizations checks a secret
that can be wrong. Under the new key it also uses no DA-protected object.
While envelopes or seals still use the old key it does, so on a TPM that
implements the 16.8.6 note's alternative a non-orderly shutdown after that
use counts one failure; under the clause's base rule a non-orderly startup
counts one whatever irlume did. A DA failure elsewhere on the machine
stops touching irlume once its
envelopes are on the new key. While the section 3.2 fallback keeps an
envelope, or new seals, on the old key, a lockout still blocks them, as
today, and doctor says so (section 4).

### 3. The storage key moves to `noDA`

1. **Template.** The storage key template becomes today's `srk_template`
   plus `noDA`: still RSA-2048, AES-128-CFB, SHA-256 name, empty authValue
   and empty authPolicy. These are the TCG storage-key attributes for RSA.
   Amended 2026-10-15 (below): the template also sets `unique` to an
   irlume label. The algorithm does not change here; an ECC storage key is
   a separate decision and would reuse this migration.
2. **Handle.** The new key is persisted at a handle of its own, so both
   keys can exist during the migration. The preferred handle is the one
   next to the old key's: 0x81010003 by default; with an
   `IRLUME_SRK_HANDLE` override, which keeps naming the old key's handle,
   the handle after it, or the one before it for an override at the top of
   the owner persistent range (0x817FFFFF). Today the override accepts any
   persistent handle, platform range included, and an unparsable value
   silently becomes 0x81010002 (`persistent_srk_raw`); with this change an
   override outside 0x81000000 to 0x817FFFFF, the range Owner
   Authorization may assign (Part 1 34.3; 0x81800000 to 0x81FFFFFF needs
   Platform Authorization), or one that does not parse, is refused and
   logged, and new seals stay on the old key. When another stack's key
   holds the preferred handle, irlumed takes the first free handle above
   it, wrapping within 0x81000000 to 0x817FFFFF, so the new key's handle
   never leaves the owner range. It records the chosen handle in a
   root-only state file under `/var/lib/irlume`, which later starts read
   first. Before it persists the new key it looks for a copy already
   persisted: it enumerates the owner persistent handles and adopts one
   whose public area equals its derivation of the new template (exact
   identity, as `evict_persistent_srk` compares), so a power loss between
   `TPM2_EvictControl` and the state file never leaves a second copy taking
   persistent capacity. A free handle number does not mean the TPM has
   room, and `TPM_PT_HR_PERSISTENT_AVAIL` does not settle it either: it is
   "the number of additional persistent objects that could be loaded into
   NV memory", which "is an estimate", and "If this value is at least 1,
   then at least one object of any type may be made persistent" (Part 2
   version 185, table 28), so a 0 promises nothing. irlumed therefore tries
   `TPM2_EvictControl` whenever a free owner handle exists. Only when that
   refuses (for example `TPM_RC_NV_SPACE`, seen on swtpm once the property
   reached 0) or no owner handle is free do new seals stay on the persisted
   old key, with nothing moving, and doctor reports it. Each attempt
   derives the new key first, so after a refusal irlumed records it with
   the boot ID in its state file and tries again only at its first start
   in a later boot, or sooner when `TPM_PT_HR_PERSISTENT_AVAIL` reads at
   least 1, which guarantees room; a daemon restart within the same boot
   pays no derivation. Deriving an RSA-2048 primary takes more than 10
   seconds on slow firmware TPMs (`load_or_create_srk`), which would
   consume most of the authentication window (about 15 seconds at login, 10
   at `sudo` and polkit prompts, `irlume-auth`) on every authentication. So
   no new envelope is written under a transiently derived key while a
   persisted irlume key exists. Today irlume does derive the old key per
   call when another stack's key holds its handle (`load_or_create_srk`:
   "correct, just slower"). That fallback stays, for the old key only: when
   neither key is persisted (another stack's key on the old key's handle
   and no room for the new one), seals and loads keep today's per-call
   derivation of the old key, nothing moves, and doctor reports it. The new
   key is never derived per call. irlume keeps its own handles rather than the
   shared 0x81000001 (`TPM2_SRK_HANDLE` in systemd's `tpm2-util.h`;
   Provisioning Guidance table 2): systemd creates an ECC key there when
   the handle is empty and the TPM supports one
   (`tpm2_get_best_srk_template`), and it is another stack's to manage.
   irlumed derives and persists the new key when it starts and finds an
   envelope under the old key, so no login pays for the derivation.
   Recognizing a key as irlume's (`is_irlume_srk`,
   `derives_from_srk_template`, and the #1079 storage-key comparison
   `storage_key_check`, which doctor reports under `tpm-firmware`) knows
   both templates. The old one seals only while the new key cannot be
   persisted (the fallback above); once the new key is persisted, the old
   one only loads.
3. **Envelopes.** New seals use the new key once it is persisted. A sealed
   envelope records the handle and TPM name of the key it was sealed under,
   in a new optional field that older releases ignore (`SealedEnvelope` has
   no `deny_unknown_fields`), so a load goes straight to the right parent
   and checks that the key there is the one it was sealed under; an
   envelope without the field is under the old key. The recorded name
   decides and the handle is a hint: another stack may take a handle an
   eviction freed. When the key at the recorded handle is absent or has
   another name, irlumed's start looks for a persisted key with the
   recorded name, else derives the template whose key has that name (old
   or new) and checks the name. An envelope under the old key then moves
   straight to the new key through that transient old key when the new key
   is persisted, and nothing is persisted for the old one; otherwise the
   derived key is persisted by the rule of section 3.2 and an old-key
   envelope moves once the new key can be. An authentication uses only a
   key whose name
   matches. It never derives the new key and never recovers a parent by
   name, which happens only at irlumed's start; it derives the old key per
   call only where the section 3.2 fallback applies (no persisted irlume
   key), as `load_or_create_srk` does today when another stack's key holds
   the handle ("a read-only unseal takes this path too"). This extends the
   record #1073 proposes, the persisted key's TPM name kept once per host,
   to every envelope. An envelope under the old key moves at the points
   where envelopes already move to a stronger policy: the template key at
   irlumed's start (`move_to_stronger_policy`, through `move_with`) and best
   effort on the other non-authentication loads and writes that already
   call `move_best_effort`, never inside an authentication request
   (ADR-0025: at most one unseal); a keyring secret at `irlume keyring arm`
   or at the next login whose PAM session runs pam_irlume's `reseal` line
   (`ResealPassword`, root-only, `keyring::reseal_password`). Being under
   the old key counts as a reason to move, like a weaker tier. A move
   happens only when the new key is persisted, so a move never pays for a
   derivation. Today only a Tier 2 seal is round-trip verified (`tpm::seal`
   unseals a pcrlock candidate; the literal PCR seal is not unsealed before
   use), so the move to the new key adds its own round trip: the candidate
   is unsealed and compared before it replaces the envelope. Every move
   writes with `save_reporting`, which tells a visible but not durable
   write (`AtomicWrite::VisibleNotDurable`) from a failed one, where
   `save` reports both as an error. A failed move leaves the old envelope
   in use.
4. **The old key.** It stays persisted while any envelope on the host names
   it, including envelopes that no longer unseal because their PCRs moved.
   A move is not durable just because the new envelope is visible: when
   syncing the directory fails (`AtomicWrite::VisibleNotDurable`), a power
   loss can bring back the envelope under the old key (`move_with` in
   `template_key.rs`). So the old key counts as unused only when every move
   off it reported a durable write and a scan in a later boot (another boot
   ID) still finds no envelope naming it; a restored envelope is found first
   and keeps the key. Evicting it then uses the daemon request #1073
   proposes for a key with the ROCA fingerprint (item 2: a root-only
   request on the worker that checks the key is still irlume's, as
   `evict_persistent_srk` does), extended to the old key, with exact
   identity, never a shape match. Only a fresh derivation proves it on its
   own: Phase 3 and uninstall evict the old key automatically only when
   today's derivation of the old template gives the same modulus (the
   uninstall path's rule), and uninstall evicts the new key by the same
   rule against the new template. Phase 2 also records the old key's TPM name at
   the first start that verifies it by derivation, the record #1073
   proposes, but that record lives in the state directory, which section 5
   treats as untrusted on hosts where it is writable offline, so it is
   advisory and never by itself authorizes destroying a key. When only the
   recorded name matches, as after a firmware update that changed
   derivation between Phase 2 and Phase 3, doctor and uninstall report the
   handle and the key's name, and the key is evicted only after an
   administrator confirms it explicitly with a root-only request that
   names that handle and name. An old key that no longer matches when
   Phase 2 first runs is not recorded and keeps the #1079 manual path.

   Eviction frees a persistent handle; it does not destroy the key. The old
   template derives the same key bit for bit on the same TPM (`tpm.rs`:
   deriving it "also opens one sealed under a persistent SRK that has since
   been evicted"), so an envelope under the old key that comes back after
   the eviction, from an older copy of the state directory (Context) or a
   restored backup, still opens. irlumed's start, finding such an envelope
   and no persisted old key, derives the old key once and moves the
   envelope through it to the persisted new key, persisting nothing for
   the old key (section 3.3); no recovery passphrase or re-enrollment is
   needed. Only when the new key is not persisted either does it persist
   the old key again by the rule of section 3.2, or, without room, leave
   the envelope to today's per-call derivation (no persisted irlume key)
   until a key can be persisted.

   Eviction adds exposures that a persisted key does not have, because a
   returning old-key envelope then depends on re-deriving the old key:
   - a firmware update that changes how the TPM derives keys (the ROCA case
     of #1079): today it leaves the persisted key, and so its envelopes,
     usable; after the eviction the old key no longer re-derives;
   - an owner authorization set after the eviction, by another operating
     system or a provisioning tool: irlume derives and persists its keys
     with an empty owner authorization (`create_srk` and both
     `evict_control` calls use a null-auth session on the owner
     hierarchy), so it can then neither re-derive the old key nor persist a
     new one.

   In either case an old-key envelope that comes back afterwards needs
   `irlume recovery restore` or a re-enrollment, as after a cleared TPM.
   Phase 3 states both in the eviction's log line and in doctor.

### 4. doctor reports the TPM lockout

A new doctor check, `tpm-lockout`, reports the DA state from what irlumed
reads with `GetCapability`, in an additive field of the `TpmReadiness`
reply (an older daemon's reply reads as unknown):

- `lockoutAuthSet` and `inLockout` from `TPM_PT_PERMANENT`, and
  `TPM_PT_LOCKOUT_COUNTER`, `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL`
  and `TPM_PT_LOCKOUT_RECOVERY`;
- whether the storage key irlume seals under is DA-exempt, and, when the
  new key could not be persisted (section 3.2), why.

Readings, the first that applies. A Pass or Info reading counts in neither
doctor's closing summary nor the `doctor --check` exit code (0 clean, 1
warnings only, 2 any failure; `doctor_report.rs` `Summary`), so every
reading that needs action is a warning:

- **Unknown:** no TPM, the daemon could not read it, or an older daemon.
- **Warn:** in lockout while some irlume envelopes are still under the old
  key. The detail names each account and envelope kind still under the old
  key and what the lockout blocks for it until it ends, one lockout
  interval of powered-on time after the last failure: a template key,
  that account's face login; a keyring secret, that account's credential
  release after a face or fingerprint login. Envelopes already on the new
  key are not named, since the lockout does not block them.
- **Warn:** in lockout with every envelope on the new key: irlume is not
  affected, but disk unlock PINs and other TPM PIN users on this machine are.
- **Warn:** not in lockout, but the new key could not be persisted
  (section 3.2), so the envelopes named stay on the old key and the next
  lockout would block them; the detail gives the refusal (for example
  `TPM_RC_NV_SPACE`, or no free owner handle).
- **Info:** a lockout authorization is not set, so any process that can open
  the TPM can reset the lockout or change its parameters. This describes the
  machine, not irlume, which does not rely on it.
- **Pass:** otherwise. The detail gives failures over maximum, the interval,
  and whether a lockout authorization is set.

The check sends no authorized command. Its remedy text names waiting, an
administrator's `tpm2_dictionarylockout --clear-lockout` where the lockout
authorization is known, and otherwise the operating system that holds it.

### 5. The documentation names the rollback limit precisely

THREAT_MODEL.md (the "Consecutive unsuccessful request ceiling" bullet of
"Intent, throttling, and privilege elevation") and DISABLE.md ("Persistent
retry records") say that, by this ADR, the TPM does not count
face attempts; that the record does not resist root, offline change, or a
boot of an older or writes-discarded copy of the state directory on a boot
chain the seal accepts. They say that the last case stays open: full-disk
encryption unlocked by a passphrase or PIN under `/var/lib/irlume` narrows
it to boots someone who knows the secret unlocks, but gives the record no
freshness, and a verified root or a pcrlock policy does not narrow it.
SECURITY_AT_REST.md layer 3 and its "Disk-theft test" row say that a
verified root protects the installed system, not the writable state
directory: on a host whose `/var/lib/irlume` is not on full-disk
encryption unlocked by a passphrase or PIN, an offline writer controls the
state irlume reads there, so a verified root alone gives no at-rest
guarantee about irlume's enrollments, sealed keys or retry records.

### 6. When to revisit

Revisit section 1 if irlume gains a TPM-checked user secret on a release
path (that secret would go under DA, with section 2's sharing cost stated),
if a supported install documents snapshot boot as an unauthenticated
recovery path, or if Linux distributions start provisioning `lockoutAuth`
so that only an administrator can reset a lockout.

## Consequences

- No change to how many face attempts an account gets, or when they reset.
- irlume keeps working through a TPM lockout once its envelopes are on the
  new key. Until an envelope moves, a lockout still stops it, as today.
- The migration costs one storage key derivation per host when the new
  key persists (more than 10 seconds on slow firmware TPMs, at irlumed's
  first start after the upgrade), and while the TPM refuses to persist it,
  one derivation at most per boot (section 3.2); one more persistent
  handle while both keys exist; one root-only state file naming the new
  key's handle and any refusal; and one rewrite of each envelope.
- A downgrade to a release before section 3 cannot open an envelope already
  moved: the keyring secret reseals under the old key at the next login
  that runs pam_irlume's `reseal` line, and the template key needs
  `irlume recovery restore` or a re-enrollment. Section 3's CHANGELOG entry
  says so.
- After Phase 3 evicts the old key, a firmware update that changes key
  derivation makes a returning old-key envelope need recovery
  (section 3.4); until then the persisted old key protects against it.
- doctor gains one read-only check and the `TpmReadiness` reply one field.
- The rollback residual stays, and is now described precisely: what
  narrows it, and that nothing irlume can check closes it.

## Phasing

- **Phase 1:** the `tpm-lockout` doctor check (section 4), the tests that pin
  section 2, and the documentation of section 5.
- **Phase 2:** the storage key move (section 3.1 to 3.3), with the swtpm
  lockout test below.
- **Phase 3:** evicting the old key (section 3.4) with the daemon request
  #1073 proposes, extended to the old key.

## Acceptance tests

- `sealed_template` and the new storage key template both set `noDA` (unit
  tests on the built attributes). The old template seals only while the
  new key cannot be persisted; once the new key is persisted, a seal never
  uses the old one.
- In a dedicated swtpm, with the DA parameters lowered and a throwaway
  DA-protected object failed until `inLockout` is set: a seal and an unseal
  of each envelope kind under the new key succeed for Tier 3, and for Tier 2
  where the swtpm lane provisions a pcrlock index; an envelope sealed under
  the old key fails to load while locked out, then moves to the new key at
  its move point once the lockout is cleared and unseals in a later lockout.
  The test restores the parameters, or runs in its own swtpm instance, so
  no other test sees the lockout. It is added by name to the irlume-core
  list of the "test (TPM-gated, against swtpm)" step in `ci.yml` (that
  lane runs listed names; only the irlume-daemon lane selects by the
  `tpm_` substring).
- The move to the new key unseals and compares its candidate before
  replacing the envelope, for Tier 3 as for Tier 2; a candidate that does
  not unseal to the same secret leaves the old envelope in place and
  loadable. Every move writes with `save_reporting`, and a
  `VisibleNotDurable` result is reported as visible, not as a failure. An
  envelope that no longer unseals keeps the old key reported as needed.
  With an envelope under the old key, irlumed's start persists the new
  key. No login or authentication derives the new key or recovers a parent
  by name; with no persisted irlume key (the section 3.2 fallback), an
  authentication of an envelope under the old key still succeeds through
  today's per-call derivation of the old key.
- With the preferred handle held by another stack's key, the new key is
  persisted at the next free owner handle and found there again after a
  restart through the recorded handle. A power loss after
  `TPM2_EvictControl` and before the state file is written (simulated by
  stopping between the two steps) leaves the next start adopting the
  persisted key, with no second copy persisted.
- `TPM_PT_HR_PERSISTENT_AVAIL` reading 0 does not stop the attempt: with a
  free owner handle, `TPM2_EvictControl` is tried (a fake that reports 0
  and accepts ends with the key persisted). When `TPM2_EvictControl`
  refuses (`TPM_RC_NV_SPACE` on swtpm once its capacity is used) or no
  owner handle is free, new seals and moves stay on the persisted old key,
  no envelope is written under a transiently derived key while a persisted
  irlume key exists, and the first start in a later boot, or a start that
  reads `TPM_PT_HR_PERSISTENT_AVAIL` of at least 1, tries again. With
  neither key
  persisted (another stack's key on the old key's handle and the new key
  refused), enrollment and keyring seals still succeed through today's
  per-call derivation of the old key, nothing moves, doctor reports it,
  and the new key is never derived per call.
- An envelope records its parent's handle and TPM name; a load that finds
  no key, or a key with another name, at that handle does not use it. At
  irlumed's start, an envelope whose recorded handle now holds another
  stack's key is recovered by its recorded name: the matching template is
  derived, its name checked, the key persisted by the section 3.2 rule and
  the envelope moved (swtpm).
- `is_irlume_srk`, `derives_from_srk_template`, `evict_persistent_srk` and
  `storage_key_check` (#1079) recognize both templates; a key matching
  neither stays foreign.
- The new key's handle is 0x81010003 by default, the override's next
  handle for an `IRLUME_SRK_HANDLE` override, and 0x817FFFFE for an
  override of 0x817FFFFF: never outside the owner persistent range. An
  override in the platform range (0x81800000 to 0x81FFFFFF), outside the
  persistent range, or that does not parse as hex is refused and logged,
  and new seals stay on the old key.
- Phase 2 records the old key's TPM name at the first start whose
  derivation matches it. Phase 3 and uninstall evict a key at the old
  handle on their own only when today's derivation matches it. A key that
  matches only the recorded name (the test stands in for a derivation
  change with a key at the old handle that today's derivation does not
  reproduce but whose name was recorded) is reported with its handle and
  name and evicted only after the administrator's explicit root-only
  confirmation naming both; a record edited to name another stack's key
  at that handle evicts nothing without that confirmation.
- Phase 3, under #1073: a move whose write reports
  `AtomicWrite::VisibleNotDurable` keeps the old key needed; with every move
  durable, the old key is not evicted in the boot that made the last move,
  only after a scan in a later boot finds no envelope naming it; an envelope
  under the old key restored by a simulated power loss keeps the old key.
  After the eviction, an envelope under the old key restored from an older
  copy of the state directory, with another stack's key on the old handle
  and no room to persist anything, is moved at irlumed's next start
  through a transient old key to the persisted new key, persisting nothing
  for the old key, with no recovery step (swtpm); an authentication before
  that start does not derive it. With an owner authorization set after
  the eviction (`tpm2_changeauth -c o` on swtpm), the same restored
  envelope is reported by doctor and the start log as needing `irlume
  recovery restore` or a re-enrollment.
- A refused persist of the new key is recorded with the boot ID: a daemon
  restart in the same boot derives nothing; the first start in a later
  boot, or a start that reads `TPM_PT_HR_PERSISTENT_AVAIL` of at least 1,
  derives and tries again.
- `tpm-lockout` readings for pass, the three warnings, info and unknown come
  from synthetic capability values. The lockout warning names only the
  accounts and envelope kinds still under the old key (a template key
  alone names face login, a keyring secret alone names credential
  release); a refused persist without a lockout is a warning, so `doctor
  --check` exits 1. A `TpmReadiness` reply without the new field parses
  and reads unknown; the CLI never opens the TPM for it.
- No non-test code calls `Esys_DictionaryAttackLockReset` or
  `Esys_DictionaryAttackParameters` (the pinned tss-esapi has no safe
  wrapper for either), `nv_increment`, or `nv_define_space` with
  `NvIndexType::Counter` (source-shape test, as the repository's other
  source scans).
- THREAT_MODEL.md and DISABLE.md carry the section 5 wording.

## Amendment 2026-10-15: the new storage key's template carries an irlume label

Found while starting Phase 2. Section 3.1's template, today's `srk_template`
plus `noDA` with an empty `unique`, is field for field the RSA storage key
template systemd derives (`tpm2_get_srk_template` in
`src/shared/tpm2-util.c`), which follows the TCG shared SRK template
(Provisioning Guidance 7.5.1, Table 1). systemd persists that key at
0x81000001 when that handle is empty and the TPM does not support its ECC
template (`tpm2_get_or_create_srk`, `tpm2_get_best_srk_template`).
TPM2_CreatePrimary seeds the derivation with
the hierarchy's seed and a hash of the whole template, `unique` included
(Part 1 24.6.3; the reference code's `CreatePrimary.c` uses the template's
Name), so the same template on the same TPM gives the same key. With the
template as written, exact identity would not tell irlume's new key from that
systemd key, or from another stack's TCG storage key with an empty `unique`:
the adoption of section 3.2 could take another stack's key for irlume's, and
an eviction against the new template (section 3.4, and uninstall) could remove
it.

The new template therefore sets `unique` to the ASCII text
`irlume ADR-0034 storage key` followed by zero bytes to 256 bytes, the size of
an RSA-2048 modulus, as the EK Credential Profile pads its nonce for template
L-1. Part 1 24.2.7 lets the caller place any value in `unique` that is
structured as the TPM's own; the TPM replaces it with the modulus. The label
is fixed, since changing it changes the key. The attributes, algorithm and
authorization of section 3.1 are unchanged, and so is the old template.

The shape check that picks candidates (attributes, name hash, authPolicy and
key size) cannot see the label, because a key's public area holds the
modulus in `unique`, so it still matches another stack's TCG storage key. As
sections 3.2 and 3.4 already require, only a comparison with a fresh
derivation of the template decides that a key is irlume's.

Uninstall finds the new key by scanning the owner persistent handles, since
its handle is recorded in the state directory, which the wipe has removed by
then, and evicts only a key whose modulus equals a fresh derivation. A handle
scan reads every page the TPM reports through moreData; tpm2-tools'
vacant-handle search reads only the first.

Acceptance tests (added):

- The new template is the old one with `noDA` and the label, and nothing
  else, and the old template is unchanged (unit tests on the built
  templates).
- On swtpm, with the TCG RSA template's key persisted at 0x81000001, irlume's
  new key at another owner handle and a key with the new template but a
  random modulus at a third: the TCG key's modulus differs from irlume's, the
  eviction removes irlume's key only, and a second eviction finds nothing.

## Amendment 2026-10-16: Phase 3 retires a storage key at irlumed's start

Phase 2 is in place (#1085, #1087, #1090 to #1094): irlumed's start persists
the DA-exempt key, new seals go under it, envelopes on the original key move
onto it at their move points, an envelope whose parent left its handle is
recovered by the recorded name, and the record keeps the original key's
handle and TPM name with whether today's derivation matched it (section 3.4).
Section 3.4 leaves open who evicts the original key and when, and #1073 item 2
asks what replacing a weak storage key does to the secrets sealed under it.
This records both. "Retire" below means: evict a storage key from its owner
persistent handle once no envelope needs it.

### Who retires, and when

irlumed's start retires the original key itself, in the start-up step and
under its record lock, after the persist and recovery steps, and never in an
authentication. It needs no client: the start already holds the record, opens
the TPM, and runs before any request. The daemon request #1073 proposes is
kept only for the case a start may not decide alone (below). The original key
is retired when all of these hold:

1. **Unused across boots.** A start's census finds no envelope under the
   original key (none without a recorded parent, and none it cannot read,
   which counts as under it), and records that boot ID as the start of the
   key's unused time. A start in another boot that finds none again may
   retire it; a start that finds one clears the mark. A boot ID that cannot be
   read is no other boot, so no start retires then. A move whose
   write reports `AtomicWrite::VisibleNotDurable` records its boot ID too, and
   no start in that boot may mark the key unused: after a power loss the
   envelope under the original key can come back, and the first start in the
   next boot finds it. So the earliest retirement is in the boot after the
   last move, or two boots after a move that was not durable.
2. **Exact identity.** The key at the original handle has the TPM name the
   record kept (section 3.4), and a fresh derivation of the original template
   at this start gives the same modulus, as uninstall compares it. The
   derivation runs only at a start that derives nothing else, as the record's
   own check does, so no start pays for two derivations of an RSA-2048 key.
3. **The DA-exempt key is present** at its recorded handle with its recorded
   name, so an envelope that comes back has a key to move to.

A key at the original handle that only the recorded name identifies (today's
derivation differs, as after a firmware update that changed key generation)
is never retired by a start. doctor names its handle and name, and a root-only
request retires it after an administrator names both: `irlume tpm retire-key
--handle <handle> --name <name>`, served on the worker. irlumed checks that the
key at that handle has that name, that the record kept that name for it, and
that condition 1 holds, and then evicts it; any mismatch refuses with nothing
evicted. A record edited to name another stack's key therefore evicts nothing
without that confirmation, and the confirmation itself names the key.

### An envelope that comes back

After the original key is retired, an envelope under it can return from an
older copy of the state directory or a restored backup (section 3.4).
irlumed's start finds it in the census, derives the original template as a
transient key, which it never persists while the DA-exempt key is persisted,
and moves the envelope through it onto the DA-exempt key at its move point
(the template key at the start, a keyring secret at the next login's reseal).
An authentication never derives the original key once a DA-exempt key is
persisted: an envelope still under the retired key falls back to the password
until the start or the reseal has moved it. Only with no persisted irlume key
at all does the section 3.2 fallback, today's per-call derivation, apply.
Today an unseal finding the original handle free derives the original key and
persists it there (`load_or_create_srk` in `SrkMode::Initialize`); Phase 3
changes that path, since otherwise the first authentication after a
retirement would persist the key again.

### A weak storage key (#1073 item 2)

doctor's `tpm-firmware` check also reads the DA-exempt key for the ROCA
fingerprint, since new seals go under it. A weak key is replaced by moving its
envelopes first, never by evicting a key an envelope names:

- **The original key is weak.** Its envelopes move onto the DA-exempt key as
  for any original key. When today's derivation of the DA-exempt template
  gives a key without the fingerprint, nothing more is needed; the original
  key is then retired as above, through the confirmed request when only its
  name identifies it.
- **The DA-exempt key is weak** (persisted before a firmware update fixed key
  generation) **and today's derivation of its template is not.** irlumed's
  start persists the new derivation at the next free owner handle and records
  it as the DA-exempt key, keeping the weak key's handle and name in the
  record as a key to retire. An envelope whose parent is the weak key counts
  as having a reason to move, like one on the original key, and moves at its
  move point. The weak key is retired when no envelope names it, across boots
  as in condition 1, and only through the confirmed request, since a fresh
  derivation no longer reproduces it.
- **Today's derivation of the DA-exempt template is weak too** (the firmware
  is not updated). The DA-exempt key is not replaced, since a new one would
  be as weak; doctor says to update the TPM firmware first.

So the request never touches the secrets sealed under a key: they have moved
before it can run. Face login needs no `irlume recovery restore` and no
re-enrollment, unlike the manual eviction doctor advises today (#1079), and a
keyring secret needs no reseal at a password login. The confirmation step is
the administrator naming the handle and the name; resealing under the new key
is the move, which is round-trip checked as section 3.3 requires.

### What doctor reports

The `tpm-lockout` reading is unchanged. A storage key waiting to be retired is
reported with its handle, its name and the condition it waits for: a later
boot, an envelope that still names it (by account and kind), a derivation
that no longer matches (with the `irlume tpm retire-key` command), or the
DA-exempt key it needs. Uninstall, which evicts only what a fresh derivation
gives, reports a key that only its recorded name identifies with its handle
and name and leaves it, as section 3.4 says.

Acceptance tests (added, Phase 3):

- With every envelope moved by durable writes, the original key is not
  retired at a start in the boot of the last move and is retired at the first
  start in a later boot whose census still finds none; a move that reported
  `VisibleNotDurable` delays it by one more boot; an envelope under the
  original key restored by a simulated power loss keeps it; an envelope that
  cannot be parsed keeps it; an unreadable boot ID retires nothing (fake TPM
  and boot IDs, and swtpm).
- A start that derived the DA-exempt key does not retire in the same start.
- A key at the original handle whose name the record kept but that today's
  derivation does not reproduce (a key the test persists from another
  template, its name written into the record as matched) is not retired by
  any start; the confirmed request with its handle and name retires it; the
  request with another handle or another name, or while an envelope is under
  it, refuses and evicts nothing; a record edited to name another stack's key
  evicts nothing (swtpm).
- After the original key is retired, an envelope under it restored from an
  older copy of the state directory is moved at the next start through a
  transient original key onto the DA-exempt key, with nothing persisted at the
  original handle; an authentication before that start does not derive it
  and falls back to the password (swtpm).
- A recorded DA-exempt key with the ROCA fingerprint, with today's derivation
  clean, is replaced at the next start by a new key at the next free handle;
  its envelopes move at their move points and the weak key is kept until the
  confirmed request retires it; with today's derivation weak too, nothing
  moves and doctor names the firmware update (synthetic moduli for the
  fingerprint, as `roca_verdict`'s tests use, and swtpm for the moves).
