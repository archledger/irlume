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
shared by face verification and credential release, with short strikes of
5 failures and then a 30-second wait before each further attempt
(`crates/irlume-daemon/src/retry_throttle.rs`). The charge is written before
any engine work, so a crash, an error, a cancellation or a reboot keeps it.
Cooldowns use `CLOCK_MONOTONIC` and the boot ID, so a civil-clock change
does not shorten them, and a reboot restarts a recorded cooldown for its
full length. Only a written face grant, a verified password reset or an
administrator reset clears the count. Records are 0600 root files under the
0700 root-owned `/var/lib/irlume/retry`. The password-verified reset has its
own budget with the same shape (`<uid>.reset.json`: 5, 30 s, ceiling 50).

THREAT_MODEL.md and DISABLE.md state the limit: "Write-ahead charges survive
crashes and reboot, but cannot resist root deletion or disk rollback."

### The question

Microsoft gives its reason for counting failed guesses of a PIN in the TPM
rather than in software: "Software solutions might provide similar
features, but they can't provide the same level of protection, especially
if the system restarts, the system clock changes, or files on the hard
disk that count failed guesses are rolled back" (Microsoft Learn, "How
Windows uses the Trusted Platform Module", Platform Crypto Provider). A
TPM 2.0 offers two mechanisms irlume could use (TPM 2.0 Library Part 1,
version 185, clause numbers below):

- **Dictionary-attack (DA) protection on an authorization value.** The TPM
  counts failed authorizations of every object without `noDA` and every NV
  index without `TPMA_NV_NO_DA` (16.8.1), in one set of counters for the
  whole chip (16.8.2). While `failedTries` equals `maxTries`, "any use of a
  DA-protected authValue will return TPM_RC_LOCKOUT" (16.8.3).
  `failedTries` falls by one after each `recoveryTime` of powered-on time
  without a failure (16.8.2), and a non-orderly shutdown after DA use adds
  one (16.8.6). Resetting the counter, or changing the parameters, needs
  `lockoutAuth`, and a wrong `lockoutAuth` blocks further attempts for
  `lockoutRecovery` (16.8.4, 16.8.5).
- **An NV counter in the release policy.** A `TPM_NT_COUNTER` index changes
  only through `TPM2_NV_Increment` and starts above any value a counter of
  the same name ever had (34.2.6.3); `TPM2_PolicyNV` can make an unseal
  conditional on its value (34.2.7). A PIN Fail index gives one secret a
  failure count of its own, outside the global one (34.2.8.2), but it too
  counts failures of a secret the user enters.

### Measured on the maintainer's machines

Read-only `GetCapability`, 2026-10-15 (evidence:
`artifacts/irlume/2026-10-14-windows-tpm-research/` on the shared ledger,
NOTES.md section 7):

| | Zenbook (Intel PTT) | ThinkPad T480 (STMicroelectronics) |
|---|---|---|
| `lockoutAuthSet` | 1 | 1 |
| `MAX_AUTH_FAIL` / `LOCKOUT_INTERVAL` / `LOCKOUT_RECOVERY` | 32 / 7200 s / 86400 s | 32 / 7200 s / 86400 s |
| NV counters defined / `NV_COUNTERS_AVAIL` / `NV_COUNTERS_MAX` | 5 / 0 / 128 | 4 / 12 / 0 (no limit) |

Both TPMs carry a lockout authorization this Linux install does not know,
most likely set by the Windows install each machine shipped with: since
1703 Windows keeps the lockout authorization in its own registry
(Microsoft Learn, "TPM Group Policy settings", level 5). Their parameters
are the Windows 8 certification values "32, 7200, and 86400" (TCG TPM v2.0
Provisioning Guidance 1.0 r1.0, 7.7), Windows' legacy profile: 32 failures,
then one attempt every 2 hours. A lockout on these machines cannot be reset
from Linux without clearing the TPM. Where Linux provisioned the TPM itself,
`lockoutAuth` is usually empty (a cleared TPM's is EmptyAuth, Part 1
10.8.1), and then any process that can open the TPM can reset the lockout
or change its parameters. The Zenbook has no room for another orderly NV
counter (`NV_COUNTERS_AVAIL` counts indexes "with ... the TPMA_NV_ORDERLY
attribute SET", Part 2 version 185, table 28). A counter without
`TPMA_NV_ORDERLY` writes NV on every increment (Part 1 34.2.4.3), an
orderly one jumps forward to its next stored boundary after a power loss
(34.2.6.3), the TPM may refuse a write with `TPM_RC_NV_RATE`, and the
specification gives no endurance figure (34.6).

### Who else uses the DA counter and NV space

- systemd-cryptenroll: a wrong TPM2 PIN "increments the TPM dictionary
  attack lockout mechanism, and may lock out users for a prolonged time ...
  The lockout mechanism is a global property of the TPM, systemd-cryptenroll
  does not control or configure the lockout mechanism"
  (`man/systemd-cryptenroll.xml`, systemd main at b44cca76b958).
  `src/shared/tpm2-util.c` sets `TPMA_OBJECT_NODA` on every object except
  one protected by a PIN.
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
- systemd allocates NV indexes for pcrlock and its NvPCRs, and records NV
  exhaustion separately for orderly and non-orderly indexes
  (`/run/systemd/tpm2-nv-space-exhausted-{orderly,non-orderly}`).

### What the TPM can and cannot check

The TPM verifies secrets (an authValue, through an HMAC or password
session) and policies. It cannot judge a face. irlume's face decision is
made in software by irlumed, and the credential it then releases is sealed
under a PCR policy with no authValue (`tpm.rs` `sealed_template`). So:

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
| Physical access, state on full-disk encryption unlocked by a passphrase or PIN | Cannot rewrite the record offline. | Nothing. |
| Physical access, no such encryption | Can rewrite the record offline, and also `/etc/shadow`, the PAM stack and irlumed itself (SECURITY_AT_REST.md "Disk-theft test"). | Nothing that matters: the machine is already open. |
| Physical access that can boot an older or writes-discarded copy of the state directory on a boot chain the seal accepts, and nothing more (for example a boot menu that offers file-system snapshots but locks command-line editing) | Each such boot starts from the older record. | Closes this case. |

The last row is narrow: on most installs the same position, an editable
boot menu or no disk-encryption PIN, already gives root. Its remedies are
the ones SECURITY_AT_REST.md layer 3 names for offline change: full-disk
encryption unlocked by a passphrase or PIN, or a pcrlock policy that covers
the boot loader.

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

Tested on a throwaway swtpm 0.10.2 (libtpms 0.10.2) with no host TPM
visible, 2026-10-15 (evidence: `research-item5-2026-10-15/swtpm-da-lockout/`
in the same directory, script, log and checksums):
after two wrong PINs on a DA-protected test object put the TPM in lockout,
`TPM2_Load` and `TPM2_Create` under a key made from irlume's `srk_template`
both failed with `TPM_RC_LOCKOUT` (0x921). The same `noDA` PolicyPCR object
under a key with `noDA` set loaded and unsealed. `TPM2_CreatePrimary` under
the owner hierarchy still worked. This is the specified behavior: lockout
makes no exception for an empty authValue (16.8.3; the TCG reference code's
`CheckAuthSession`: "The authValue is going to be "used" even if it is an
EmptyAuth"), while a `noDA` object is "not subject to lockout" (22.2.6), a
permanent hierarchy other than lockout gets no DA protection (16.8.1), and
an unbound policy session that does not use `PolicyAuthValue` or
`PolicyPassword` is not checked (reference code). The Tier 2 policy's
owner-authorized `PolicyAuthorizeNV` is therefore not blocked; the storage
key is. So a lockout caused by anything else on the machine, such as wrong
LUKS TPM2 PINs typed at boot or a Windows Hello PIN on dual boot, stops
irlume's face login and fingerprint keyring unlock until it ends: one
`recoveryTime` of powered-on time after the last failure, 2 hours on the
machines above, which a power cycle can restart. The failure is closed, to
the password, so it is an availability defect, not a bypass.

## Decision

### 1. The attempt limits stay in software

The consecutive unsuccessful request ceiling and the reset-password budget
stay irlume's only attempt limits, as shipped in #683 to the design in
`docs/superpowers/specs/2026-09-08-cumulative-retry-recovery-design.md`.
irlume does not
add a DA-protected authValue or an NV counter to any release path, by
default or as an option. Against Microsoft's three failure modes:

- **Restart:** the charge is written before engine work and survives
  crashes and reboots (unchanged).
- **Clock change:** cooldowns use the monotonic clock and the boot ID, and a
  reboot restarts a recorded cooldown (unchanged).
- **Rollback:** not covered. The record resists neither root nor offline
  change, as documented; the Context table shows that only the narrow
  older-copy boot is an attacker a TPM counter would stop, and its remedies
  are disk encryption with a PIN or a pcrlock policy over the boot loader.
  Section 5 makes the documentation say so.

### 2. irlume stays out of the DA counter

Every TPM object irlume creates for its own seals is DA-exempt: the sealed
objects (already `noDA`) and, from section 3, its storage key. No object
irlume creates has a secret authValue (the storage key's is empty). irlume
sends no `TPM2_DictionaryAttackLockReset` or
`TPM2_DictionaryAttackParameters`, and never asks for, stores or derives
`lockoutAuth`. A DA failure anywhere else
on the machine therefore never touches irlume, and irlume never spends the
budget that disk unlock PINs and Windows Hello depend on.

### 3. The storage key moves to `noDA`

1. **Template.** The storage key template becomes today's `srk_template`
   plus `noDA`: still RSA-2048, AES-128-CFB, SHA-256 name, empty authValue
   and empty authPolicy. These are the TCG storage-key attributes for RSA.
   The algorithm does not change here; an ECC storage key is a separate
   decision and would reuse this migration.
2. **Handle.** The new key is persisted at the handle after the old key's,
   so both can exist during the migration: 0x81010003 by default, or the one
   after an `IRLUME_SRK_HANDLE` override, which keeps naming the old key's
   handle. If that handle holds another stack's key, the new key is derived
   transiently for each call, as the old one is today when its handle is
   taken. irlume keeps its own handles rather than the shared 0x81000001:
   systemd puts an ECC key there when the TPM supports one
   (`tpm2_get_best_srk_template`), and it is another stack's to manage.
   Deriving an RSA-2048 primary takes more than 10 seconds on slow firmware
   TPMs (`load_or_create_srk`), so irlumed derives and persists the new key
   when it starts and finds an envelope under the old key, and no login pays
   for it. Recognizing a key as irlume's (`is_irlume_srk`,
   `derives_from_srk_template`, the doctor's storage-key check of #1079)
   knows both templates; the old one is accepted for loading only.
3. **Envelopes.** New seals use the new key. A sealed envelope records which
   key it was sealed under, in a new optional field that older releases
   ignore, so a load goes straight to the right parent; an envelope without
   the field is under the old key. An envelope under the old key moves at the
   points where envelopes already move to a stronger policy: the template
   key when irlumed starts (`move_best_effort` in `template_key.rs`, never
   inside an authentication request, ADR-0025), and a keyring secret at the
   next verified password login (`keyring::reseal_password`). Being under the
   old key counts as a reason to move, like a weaker tier. A move happens
   only when the new key is persisted, so a move never pays for a
   derivation. A move is round-trip verified before it replaces the
   envelope, and a failed move leaves the old envelope in use.
4. **The old key.** It stays persisted while any envelope on the host names
   it, including envelopes that no longer unseal because their PCRs moved.
   Evicting it once none does is the daemon-performed eviction tracked in
   #1073, with the uninstall path's rule: exact identity by derived modulus,
   never a shape match. Uninstall evicts both keys under that rule.

### 4. doctor reports the TPM lockout

A new doctor check, `tpm-lockout`, reports the DA state from what irlumed
reads with `GetCapability`, in an additive field of the `TpmReadiness`
reply (an older daemon's reply reads as unknown):

- `lockoutAuthSet` and `inLockout` from `TPM_PT_PERMANENT`, and
  `TPM_PT_LOCKOUT_COUNTER`, `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL`
  and `TPM_PT_LOCKOUT_RECOVERY`;
- whether the storage key irlume seals under is DA-exempt.

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

THREAT_MODEL.md ("Consecutive unsuccessful request ceiling") and DISABLE.md
("Persistent retry records") say that, by this ADR, the TPM does not count
face attempts; that the record does not resist root, offline change, or a
boot of an older or writes-discarded copy of the state directory on a boot
chain the seal accepts; and which configurations close the last case
(full-disk encryption unlocked by a passphrase or PIN, or a pcrlock policy
that covers the boot loader).

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
  the upgrade), one more persistent handle while both keys exist, and one
  rewrite of each envelope.
- A downgrade to a release before section 3 cannot open an envelope already
  moved: the keyring secret reseals under the old key at the next password
  login, and the template key needs `irlume recovery restore` or a
  re-enrollment. Section 3's CHANGELOG entry says so.
- doctor gains one read-only check and the `TpmReadiness` reply one field.
- The rollback residual stays, and is now described in terms of the
  configurations that close it.

## Phasing

- **Phase 1:** the `tpm-lockout` doctor check (section 4), the tests that pin
  section 2, and the documentation of section 5.
- **Phase 2:** the storage key move (section 3.1 to 3.3), with the swtpm
  lockout test below.
- **Phase 3:** evicting the old key (section 3.4), decided and implemented
  under #1073.

## Acceptance tests

- `sealed_template` and the new storage key template both set `noDA`; the
  old template is accepted only to load, never to seal (unit tests on the
  built attributes).
- In a dedicated swtpm, with the DA parameters lowered and a throwaway
  DA-protected object failed until `inLockout` is set: a seal and an unseal
  of each envelope kind under the new key succeed for Tier 3, and for Tier 2
  where the swtpm lane provisions a pcrlock index; an envelope sealed under
  the old key fails to load while locked out, then moves to the new key at
  its move point once the lockout is cleared and unseals in a later lockout.
  The test restores the parameters, or runs in its own swtpm instance, so
  no other test sees the lockout. It runs in the CI swtpm lane by its
  `tpm_` name.
- A move that fails its round trip leaves the old envelope in place and
  loadable; an envelope that no longer unseals keeps the old key reported
  as needed. With an envelope under the old key, irlumed's start persists
  the new key; with the new key's handle taken by another stack's key, a
  password login leaves the keyring envelope under the old key and derives
  nothing.
- `is_irlume_srk`, `derives_from_srk_template`, `evict_persistent_srk` and
  the doctor storage-key check (#1079) recognize both templates; a key
  matching neither stays foreign.
- `tpm-lockout` readings for pass, both warnings, info and unknown come from
  synthetic capability values; a `TpmReadiness` reply without the new field
  parses and reads unknown; the CLI never opens the TPM for it.
- No non-test code calls `dictionary_attack_lock_reset`,
  `dictionary_attack_parameters`, `nv_increment` or `nv_define_space` with
  a counter type (source-shape test, as the repository's other source
  scans).
- THREAT_MODEL.md and DISABLE.md carry the section 5 wording.
