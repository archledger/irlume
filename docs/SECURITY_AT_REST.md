# Biometric data at rest: security model + audit (2026-07-02)

How irlume stores your face and how hard it is for an attacker to get it.
Live-tested on real hardware (Fedora TPM box + Arch TPM box); results below.

> **Update 2026-09-18/19 (multi-camera stores):** since 0.13.0 a secondary
> enrolled camera lives in its own group with a separate store file,
> `/var/lib/irlume/cameras/<user>.json`. 0.13.0 wrote that store as
> root-only plaintext JSON - a gap against this page's own bar, recorded in
> ADR-0024 and since closed: secondary stores are now AES-256-GCM encrypted
> under the same account template key as the primary (owner-only files,
> upgrade-on-write from 0.13.0-era plaintext). Encryption claims below cover
> secondary stores only after that migration. Installing v0.14.0 or reading an
> existing store does not encrypt it; the next authorized write does. Older
> plaintext files and backups retain their earlier exposure.

## What is stored and what is NOT

**Never an image.** irlume stores only **L2-normalized 512-D face embeddings**
(AuraFace output): a list of floats, one vector per enrolled scan, plus IR
embeddings and a few liveness calibration scalars. No JPEG/PNG/raw frame ever
touches disk (`storage.rs`: "We store L2-normalized embeddings, never raw
images"; verified by grep, there is no image-write path). This is true of both
stores: the primary `/var/lib/irlume/<user>.json` and the secondary
`/var/lib/irlume/cameras/<user>.json` hold embeddings and calibration scalars
only, never images. irlumed does not write core dumps (`LimitCORE=0` in its
unit, and a zero core limit and a cleared dumpable flag set at startup), so a
crash or watchdog abort writes no core file holding a frame, embedding or
decrypted template. Swap is separate: while irlumed runs, the kernel may page
ordinary memory out to a swap device, and only secret buffers are locked in
memory, so on a host with unencrypted swap those can reach disk; encrypted
swap (or none) keeps them off it. Each scan captured since ADR-0030 C2 also records when it
was captured (a unix timestamp, so the TUI can show a capture date range). It
is not biometric. It sits inside the same payload as the embeddings, so it is
encrypted where they are and in a 0600 plaintext file on a host without a TPM
key.

Why this matters: an embedding is a one-way projection. You cannot re-render the
enrollment photo from it, and it is not a fingerprint/photo an attacker can
reuse elsewhere. (Academic "template inversion" can produce a *blurry
look-alike* from some embeddings, but not the original image, and irlume's
matching also requires passing IR liveness; an inverted RGB image can't.)

## How it is protected: four layers

1. **Filesystem: root-only.** Enrollment `…/irlume/<user>.json` and the sealed
   key `/var/lib/irlume/template-keys/<user>.json` are `0600 root:root`.
   *Tested:* a normal user `cat` → **Permission denied** (both files).
2. **Encryption at rest: AES-256-GCM.** On a TPM host the embeddings are
   encrypted (random 96-bit nonce per write, GCM auth tag) - in the primary
   store and in new or migrated secondary multi-camera stores (same account
   template key, separate envelope). *Original primary-store test:* the
   on-disk file's `enc` field is opaque base64; grepping it for `rgb`, `embedding`, `scans`, or any
   `NN.NNNN` float → **nothing** (no plaintext leak).
3. **Key custody: TPM-sealed, never on disk in the clear.** The AES key is a
   random 32 bytes sealed by the TPM. The stored key envelope holds only the
   TPM `public`/`private` blobs; the `private` is wrapped under the TPM's
   Storage Root Key with a **PCR policy**: a provisioned systemd-pcrlock NV
   policy (Tier 2) where one exists and covers a firmware-measured PCR (0 to
   7), else the literal **PCR-7** policy (Tier 3,
   the default on most machines). Note Tier 3 binds to the Secure Boot
   **state** (PCR 7), not the loaded kernel/initrd, so a validly-signed but
   modified kernel does not move it; Tier 2 is the one that can bind
   boot-component measurements (PCR 4, once they are locked; see below). A
   signed PCR-11 policy (Tier 1), which earlier
   releases preferred on UKI machines, binds only what the operating system
   measures itself, so new seals no longer use it and an existing Tier 1
   envelope moves on its next reseal.
   The plaintext key exists only transiently in the daemon's memory (zeroized
   on drop).

   What the seal does not cover: a TPM seal binds the boot chain it measures,
   not the root filesystem. Where irlume's state directory (`/var/lib/irlume`)
   is not on encrypted storage, someone with the machine can change the
   installed system offline (for example, add a service that runs as root) and
   boot the unchanged boot chain. The PCRs then match the policy, whichever it
   is, and the template key and any armed keyring secret (for the login
   password kind, the login password itself) unseal on that machine. A policy
   that does not cover the boot loader code (PCR 4) leaves a second path:
   another operating system signed with the same keys reproduces what it binds
   and can unseal them directly, without changing the installed system. That
   holds for the literal PCR 7 policy (Tier 3), a literal `IRLUME_PCRS` set
   without PCR 4 (PCRs 0 to 3 measure this machine's firmware, its
   configuration and option ROMs, which are the same whatever it boots), a
   signed PCR 11 policy (Tier 1), and a pcrlock policy (Tier 2) without PCR 4.
   systemd-pcrlock leaves out of its policy every PCR whose measurements it
   cannot match to locked components, so PCR 4 is covered only once the
   binaries measured there are locked before `make-policy`: `lock-pe` for a
   boot loader, `lock-uki` for a unified kernel image (the tool is
   `/usr/lib/systemd/systemd-pcrlock`, outside `PATH`). A policy that covers
   PCR 4 closes the second path only where the boot loader also measures what
   it loads next, as a unified kernel image does; a GRUB boot leaves the
   initrd and the kernel command line to PCRs 9 and 8, which a pcrlock policy
   leaves out by default. It never closes the first.

   What protects the sealed secrets at rest is full-disk encryption unlocked
   by a passphrase or PIN (a volume the TPM or a key file unlocks alone does
   not count), or an integrity-verified root filesystem (dm-verity) that
   covers everything the boot runs and reads configuration from, `/etc`
   included, with its root hash bound by a pcrlock policy or a signature,
   together with a pcrlock policy that covers PCR 4: a verified root stops the
   offline change but not the second path. A root hash on a unified kernel
   image's command line is covered with that image; a GRUB command line is
   measured into PCR 8, which a pcrlock policy leaves out by default. A
   pcrlock policy is worth having in addition to encryption, not instead of
   it. Once one is provisioned, existing seals move to it: the keyring secret
   at `irlume keyring arm` or its next re-seal at a password login, the
   template key at irlumed's next start.

   `irlume keyring arm` (after an arm) and `irlume doctor` (check
   `sealed-storage`) report this for the account. The storage probe looks for
   a dm-crypt layer under the directories that hold what is sealed (the
   keyring and template-key directories, as irlumed resolves them) and
   under the installed system (`/`, `/usr` and `/etc`, which an offline
   change would alter); the least protected one decides. It does not detect a drive's
   hardware encryption, a filesystem's own encryption or a verified root, and
   it cannot show whether a dm-crypt volume asks for a passphrase or PIN or
   unlocks from the TPM or a key file alone. The report is a warning when a
   keyring secret or a template key is sealed and no dm-crypt layer is found,
   or the storage cannot be established, so it stays a warning on a verified
   root. It is information whenever those directories are on dm-crypt,
   since the storage does not show how that volume unlocks, and it names each
   sealed secret's policy another operating system may reproduce: the keyring
   secret's (one without PCR 4, one with PCR 4 on a boot loader that does not
   measure what it loads next, or one irlume cannot read) and the template
   key's, which the daemon does not report (where no pcrlock policy is used
   for sealing it is the literal one). With an `IRLUME_PCRS` override the
   guidance names the PCRs the keyring seal binds. The directories probed
   are irlumed's, as systemd gives them to it (a source install's unit
   included). On dm-crypt the information also says that what the boot
   reads before the volume is unlocked (the EFI system partition, an
   unencrypted /boot) is not encrypted and can be changed offline to
   capture the passphrase or PIN, whatever the TPM policy measures; Secure
   Boot verifying all of it (a signed unified kernel image) narrows this,
   and a GRUB configuration and initrd are not verified. `irlume
   setup`, `irlume keyring reseal` and the TUI's Password Wallet show the same
   guidance after a seal.

### Compared with Windows Enhanced Sign-in Security

Windows describes its Enhanced Sign-in Security (ESS) trust architecture with
vocabulary that maps onto what irlume already does, and vocabulary that does
not. ESS isolates the biometric path using Virtualization Based Security
(VBS) and TPM 2.0
([Microsoft's ESS overview](https://support.microsoft.com/en-us/windows/security/identity-signin/enhanced-sign-in-security-in-windows)),
plus an OEM-configured SDEV ACPI table describing the biometric hardware
chain and, for fingerprint sensors, Microsoft-issued factory certificates
(preserved in
[the camera-landscape research](research/2026-08-27-camera-landscape-research.md)
after Microsoft retired the hardware page that documented them).

What corresponds: both seal biometric-derived secrets to a TPM 2.0, and both
gate their release on firmware-measured state. irlume's pcrlock policy
(Tier 2) is the closest analog to SDEV-style firmware attestation of the
sensor chain: a statement, checked before the credential moves, that the
machine below the credential is the one that was measured. The literal PCR-7
policy (Tier 3) is the weaker corner: boot-chain *state*, not component
measurements.

What does not correspond, stated plainly: ESS isolates the matching engine
in a hypervisor; Linux has no equivalent here, and irlume runs in the normal
kernel/user boundary, compensating with fail-closed design (capture errors
and PAD misses deny to password, never grant), TPM gating of credential
release, and camera pinning. And where ESS is an OEM firmware program,
irlume consumes the camera through the ordinary kernel driver and records
what that hardware says (the census, the illumination metadata) rather than
attesting it. One deliberate difference: irlume's recovery passphrase is a
user-controlled escape hatch that can re-arm a lost seal, which a
pure-attestation model would not offer. This is a mapping of vocabulary, not
a claim of equivalence.

4. **IPC: SO_PEERCRED.** The daemon releases profile data only to the target
   user or root; the sealed *login password* (keyring) only to a root peer.
   *Tested:* a CLI peer asking for another user's profiles → **"not
   authorized"**.

## Records belong to an account uid

irlume stores each account's records under the account name. The
enrollment (`<user>.json`), the sealed template key
(`template-keys/<user>.json`), the keyring envelope (`keyring/<user>.json`)
and the recovery envelope (`recovery/<user>.json`) also record the numeric
uid of the account they were written for, as a `uid` field. On an encrypted
store the enrollment's uid is inside the ciphertext; the sealed key and the
envelopes carry it in their JSON beside the sealed blob. The code is
`crates/irlume-core/src/account.rs`.

Each load compares that uid with the account's current uid, resolved through
NSS (so LDAP, SSSD and systemd-homed accounts resolve too). A request from
the account itself (not root) passes irlumed's authorization check only when
the name resolves to the caller's uid, so every record that request loads or
writes is checked against, and records, the caller's uid. On an
authentication request irlumed reuses the lookup it already makes for the
retry record, so the check adds no second lookup there. A cached profile
listing is served only while the name resolves to the uid its load used.

| Record | Recorded uid differs from the current one | Current uid cannot be resolved |
|---|---|---|
| Enrollment and template key | The account reads as not enrolled; the key is not unsealed. `irlume enroll` enrolls again: it writes a new enrollment under a new key, and once that enrollment is saved it removes the recovery envelope of the replaced key (an enrollment that fails to save puts the replaced key back) | Error; face falls back to the password |
| Keyring envelope | Not released (face or fingerprint path), not re-sealed, and not returned for a re-arm or a disarm. `irlume keyring arm` arms again; a GNOME keyring token has to be removed first with `irlume keyring forget --force` | Not released |
| Recovery envelope | `irlume recovery restore` refuses it; `irlume recovery setup` after enrolling again writes a new one | Refused |

A name that no account has any more counts as a different uid. irlumed logs
each record it does not use, with the uids and the next step.

- A record written before the uid was recorded (0.14.0 and earlier) is
  accepted, and its next write records the uid: an enrollment write (enroll,
  add scans, rename or delete a profile), a template key or keyring re-seal,
  a keyring arm, or `irlume recovery setup`. Such a write for a name that has
  no account records no uid. Moving a template key to a stronger policy
  (at irlumed's start, or on a load) keeps the uid it records, or none: the
  name may by then resolve to another account than the one whose enrollment
  the key opens. An enrollment write for the account does not reuse such a
  key when the enrollment under it records another uid (the write reads the
  stored enrollment with the key to find out): as for a key sealed for
  another uid, the account gets a new key, and the old key's recovery
  envelope is removed once the new enrollment is saved.
- A write never changes the uid a record carries. An operation that loads a
  record and writes it back (add scans, rename a profile, delete one that is
  not the last, turn require-eyes-open off, a template key or keyring re-seal,
  a restore from the recovery passphrase) writes it for the uid its load
  checked, and is refused before anything is written when the name resolves
  to another uid, or to no account, by then. Deleting the last profile
  removes the account's records rather than writing them. An enrollment an
  earlier release wrote counts as its template key's uid when the key records
  one, so its save neither records the new uid nor replaces the key. A new
  enrollment, key, arm or recovery envelope records the current uid.
- When the current uid cannot be resolved, a write keeps the uid its record
  carries, and a write that would leave a record without one (a new
  enrollment, key, arm or recovery envelope, or the rewrite of an earlier
  release's record) is refused before anything is written.
- A record that is not used is never removed automatically: an account whose
  uid changed and is changed back finds its records usable again. To remove
  them by hand, stop irlumed and delete the account's files under
  `/var/lib/irlume` (`<user>.json`, `cameras/<user>.json`,
  `template-keys/<user>.json`, `recovery/<user>.json`, `keyring/<user>.json`).
- Added-camera stores (`cameras/<user>.json`) record no uid. They are
  encrypted under the template key and used only together with the primary
  enrollment, whose check covers them; on a host without a TPM they are
  plaintext, but still unusable without a primary enrollment for the uid.
- Retry records (`retry/<uid>.json`) and the attempt record are kept by uid
  already.
- The field is additive: an older irlumed ignores it and keeps using records
  by name.

## Disk-theft test

Simulated a full exfiltration: copied **both** the encrypted enrollment and the
sealed key envelope off the Fedora box and planted them on the Arch box (a
*different* machine with its *own* TPM), then forced the daemon to load them.

**Result: `tpm: integrity check failed`.** Arch's TPM refuses to unseal a key
sealed by Fedora's TPM. The stolen ciphertext is undecryptable off the original
machine, even on hardware that also has a TPM, even with the key envelope in
hand. Cleaned up all artifacts afterward.

So the realistic attacks and their outcomes:

| Attacker capability | Outcome |
|---|---|
| Normal user account on the box | Can't read either file (0600 root) |
| Steals the disk / backup image (**TPM host**) | Encrypted primary and migrated secondary ciphertext will not unseal on another TPM; unmigrated v0.13.0 secondary files and old plaintext backups remain exposed |
| Steals the disk / backup image (**no-TPM host**) | Templates are root-only but **plaintext** (see "Degraded hosts" below): recoverable 512-D embeddings, not an image |
| Steals disk AND has the physical machine, no root | The seal binds the boot chain, not the root filesystem. Where the state directory is not on full-disk encryption unlocked by a passphrase or PIN, the installed system can be changed offline and booted on the unchanged boot chain, which unseals the template key and any armed keyring secret under any policy. A policy that does not cover the boot loader (PCR 4), such as the literal PCR 7 policy (Tier 3), adds a second path: another operating system signed with the same keys reproduces it and unseals them directly; a pcrlock policy (Tier 2) that covers PCR 4 closes that one. Remedies: full-disk encryption unlocked by a passphrase or PIN, or a verified root (dm-verity) whose root hash a pcrlock policy or a signature binds (layer 3 above) |
| Root on the live original machine | Game over: root can ask the daemon to unseal (true of any at-rest scheme; root is the trust boundary) |
| Recovers only the embedding plaintext (somehow) | Gets a 512-float vector, not a photo; can't replay it past IR liveness |

## Degraded hosts: no TPM / no Secure Boot

- **No TPM:** no hardware to seal a key, so templates are stored **root-only
  plaintext** (still 0600 root: invisible to the user, but not encrypted at
  rest) and keyring auto-unlock can't be armed. Face login + sudo still work.
  The Repair tab now flags this with a "TPM" row.
- **Secure Boot off (present):** TPM sealing still works but binds to a PCR-7
  value that isn't anchored to a trusted boot chain, which weakens tamper
  resistance (an attacker who alters the boot path doesn't invalidate the
  seal). Repair flags this with a "Secure Boot" row.

## How this compares to Windows Hello

Hello keeps biometric templates in a **VBS/TPM-backed enclave** and gates them
behind a hardware-isolated process; the OS never sees raw template material.
irlume is not enclave-isolated: the daemon is a normal (root) process that
holds the decrypted embeddings in memory while matching, so **root on the live
machine is the trust boundary** (as it is for most Linux secrets). What irlume
matches Hello on: no raw images stored, strong at-rest encryption, hardware key
custody bound to boot state, and disk theft yields nothing. Where Hello is
stronger: runtime isolation of the template from a compromised OS kernel.
Closing that gap would need a TEE/enclave path (out of scope today; noted).

## Residual gaps / follow-ups

- Embeddings live in daemon RAM during matching (unavoidable without a TEE);
  they are `zeroize`d where feasible but a root-level live-memory attacker on
  the original machine can reach them. This is the Hello-vs-irlume delta above.
- No-TPM hosts store plaintext-at-rest embeddings (root-only). A software
  passphrase-encrypted mode (Argon2id, like the recovery envelope) could
  encrypt at rest even without a TPM; candidate hardening.
