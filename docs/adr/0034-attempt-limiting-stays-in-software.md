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
| Physical access, a verified root (dm-verity) covering the system and `/etc`, the state directory writable and not encrypted | Can rewrite the record offline, but not the verified system. | Nothing that matters: the same writer can replace the other state irlume reads there, the enrollment and the sealed template key, which carry no authenticity check an offline writer cannot meet (below). |
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

The verified-root row needs its reason spelled out. The template key is
loaded from its envelope after a check of the envelope's `uid` field and an
unseal (`template_key.rs` `load_key_with`); the enrollment is decrypted with
that key and its own `uid` field checked (`storage.rs`
`load_path_with_source`). Both fields are in files under
`/var/lib/irlume`. Creating a sealed object under irlume's storage key
needs no secret, since its authValue is empty, and accepts any policy,
including one copied from an existing envelope's public area; such an
object unseals under the same PCR state (swtpm, 2026-10-15). So on that
configuration the state directory is trusted input that an offline writer
controls, and the rollback of one record is not the weakest point.
SECURITY_AT_REST.md layer 3 offers a verified root as a remedy for the
offline change of the installed system; it does not protect the writable
state directory, which needs full-disk encryption unlocked by a passphrase
or PIN for any at-rest guarantee about its contents. Section 5 says so.

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
counter, and never asks for, stores or derives `lockoutAuth`. A DA failure
anywhere else on the machine therefore never touches irlume, and irlume
never spends the budget that disk unlock PINs and Windows Hello depend on.

### 3. The storage key moves to `noDA`

1. **Template.** The storage key template becomes today's `srk_template`
   plus `noDA`: still RSA-2048, AES-128-CFB, SHA-256 name, empty authValue
   and empty authPolicy. These are the TCG storage-key attributes for RSA.
   The algorithm does not change here; an ECC storage key is a separate
   decision and would reuse this migration.
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
   old key, with nothing moving; irlumed retries at its next start, and
   doctor reports it. Deriving an RSA-2048 primary takes
   more than 10 seconds on slow firmware TPMs (`load_or_create_srk`), which
   would consume most of the authentication window (about 15 seconds at
   login, 10 at `sudo` and polkit prompts, `irlume-auth`) on every
   authentication. So no new envelope is written under a transiently
   derived key while a persisted key exists. Today irlume does derive one
   per call when another stack's key holds its handle (`load_or_create_srk`:
   "correct, just slower"); that fallback stays for the old key and is not
   extended to the new one. irlume keeps its own handles rather than the
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
   or new), checks the name, persists it by the rule of section 3.2, and
   moves the envelope. An authentication uses only a key whose name
   matches and never derives one. This extends the
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
   `evict_persistent_srk` does), extended to the old key, with the
   uninstall path's rule: exact identity by derived modulus, never a shape
   match. Uninstall evicts both keys under that rule.

   Eviction frees a persistent handle; it does not destroy the key. The old
   template derives the same key bit for bit on the same TPM (`tpm.rs`:
   deriving it "also opens one sealed under a persistent SRK that has since
   been evicted"), so an envelope under the old key that comes back after
   the eviction, from an older copy of the state directory (Context) or a
   restored backup, still opens. irlumed's start, finding such an envelope
   and no persisted old key, derives the old key once, persists it again by
   the rule of section 3.2, and moves the envelope; no recovery passphrase
   or re-enrollment is needed. Eviction adds one exposure that a persisted
   key does not have: today a firmware update that changes how the TPM
   derives keys (the ROCA case of #1079) leaves the persisted key, and so
   its envelopes, usable; once the old key is evicted, such an update makes
   it impossible to re-derive, and an envelope under it that comes back
   afterwards needs `irlume recovery restore` or a re-enrollment, as after
   a cleared TPM. Phase 3 therefore states it in the eviction's log line
   and in doctor.

### 4. doctor reports the TPM lockout

A new doctor check, `tpm-lockout`, reports the DA state from what irlumed
reads with `GetCapability`, in an additive field of the `TpmReadiness`
reply (an older daemon's reply reads as unknown):

- `lockoutAuthSet` and `inLockout` from `TPM_PT_PERMANENT`, and
  `TPM_PT_LOCKOUT_COUNTER`, `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL`
  and `TPM_PT_LOCKOUT_RECOVERY`;
- whether the storage key irlume seals under is DA-exempt, and, when the
  new key could not be persisted (section 3.2), why.

Readings, the first that applies:

- **Unknown:** no TPM, the daemon could not read it, or an older daemon.
- **Warn:** in lockout while any irlume envelope is still under the old key:
  face login and fingerprint keyring unlock use the password until the
  lockout ends, one lockout interval of powered-on time after the last
  failure.
- **Warn:** in lockout with every envelope on the new key: irlume is not
  affected, but disk unlock PINs and other TPM PIN users on this machine are.
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
- The migration costs one storage key derivation per host (more than 10
  seconds on slow firmware TPMs, paid once at irlumed's first start after
  the upgrade), one more persistent handle while both keys exist, one
  root-only state file naming the new key's handle, and one rewrite of
  each envelope.
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
  key, and no login derives a key.
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
  no envelope is ever written under a transiently derived key, and the
  next start tries again.
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
- Phase 3, under #1073: a move whose write reports
  `AtomicWrite::VisibleNotDurable` keeps the old key needed; with every move
  durable, the old key is not evicted in the boot that made the last move,
  only after a scan in a later boot finds no envelope naming it; an envelope
  under the old key restored by a simulated power loss keeps the old key.
  After the eviction, an envelope under the old key restored from an older
  copy of the state directory opens at irlumed's next start, which derives
  and persists the old key again and moves the envelope, with no recovery
  step (swtpm).
- `tpm-lockout` readings for pass, both warnings, info and unknown come from
  synthetic capability values; a `TpmReadiness` reply without the new field
  parses and reads unknown; the CLI never opens the TPM for it.
- No non-test code calls `Esys_DictionaryAttackLockReset` or
  `Esys_DictionaryAttackParameters` (the pinned tss-esapi has no safe
  wrapper for either), `nv_increment`, or `nv_define_space` with
  `NvIndexType::Counter` (source-shape test, as the repository's other
  source scans).
- THREAT_MODEL.md and DISABLE.md carry the section 5 wording.
