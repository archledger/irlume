# Biometric data at rest — security model + audit (2026-07-02)

How irlume stores your face and how hard it is for an attacker to get it.
Live-tested on real hardware (Fedora TPM box + Arch TPM box); results below.

## What is stored (and what is NOT)

**Never an image.** irlume stores only **L2-normalized 512-D face embeddings**
(AuraFace output) — a list of floats, one vector per enrolled scan, plus IR
embeddings and a few liveness calibration scalars. No JPEG/PNG/raw frame ever
touches disk (`storage.rs`: "We store L2-normalized embeddings, never raw
images"; verified by grep — there is no image-write path).

Why this matters: an embedding is a one-way projection. You cannot re-render the
enrollment photo from it, and it is not a fingerprint/photo an attacker can
reuse elsewhere. (Academic "template inversion" can produce a *blurry
look-alike* from some embeddings, but not the original image, and irlume's
matching also requires passing IR liveness — an inverted RGB image can't.)

## How it is protected — layered

1. **Filesystem: root-only.** Enrollment `…/irlume/<user>.json` and the sealed
   key `/var/lib/irlume/template-keys/<user>.json` are `0600 root:root`.
   *Tested:* a normal user `cat` → **Permission denied** (both files).
2. **Encryption at rest: AES-256-GCM.** On a TPM host the embeddings are
   encrypted (random 96-bit nonce per write, GCM auth tag). *Tested:* the
   on-disk file's `enc` field is opaque base64; grepping it for `rgb`,
   `embedding`, `scans`, or any `NN.NNNN` float → **nothing** (no plaintext
   leak).
3. **Key custody: TPM-sealed, never on disk in the clear.** The AES key is a
   random 32 bytes sealed by the TPM. The stored key envelope holds only the
   TPM `public`/`private` blobs — the `private` is wrapped under the TPM's
   Storage Root Key with a **PCR-7 (Secure Boot state) policy**. The plaintext
   key exists only transiently in the daemon's memory (zeroized on drop).
4. **IPC: SO_PEERCRED.** The daemon releases profile data only to the target
   user or root; the sealed *login password* (keyring) only to a root peer.
   *Tested:* a CLI peer asking for another user's profiles → **"not
   authorized"**.

## Disk-theft test (the important one)

Simulated a full exfiltration: copied **both** the encrypted enrollment and the
sealed key envelope off the Fedora box and planted them on the Arch box (a
*different* machine with its *own* TPM), then forced the daemon to load them.

**Result: `tpm: integrity check failed`.** Arch's TPM refuses to unseal a key
sealed by Fedora's TPM. The stolen ciphertext is undecryptable off the original
machine — even on hardware that also has a TPM, even with the key envelope in
hand. Cleaned up all artifacts afterward.

So the realistic attacks and their outcomes:

| Attacker capability | Outcome |
|---|---|
| Normal user account on the box | Can't read either file (0600 root) |
| Steals the disk / backup image | Ciphertext only; key won't unseal on any other TPM → **no data** |
| Steals disk AND has the physical machine, no root | Must defeat TPM PCR-7 policy + get root to run the daemon path |
| Root on the live original machine | Game over — root can ask the daemon to unseal (true of any at-rest scheme; root is the trust boundary) |
| Recovers only the embedding plaintext (somehow) | Gets a 512-float vector, not a photo; can't replay it past IR liveness |

## Degraded hosts (no TPM / no Secure Boot)

- **No TPM:** no hardware to seal a key, so templates are stored **root-only
  plaintext** (still 0600 root — invisible to the user, but not encrypted at
  rest) and keyring auto-unlock can't be armed. Face login + sudo still work.
  The Repair tab now flags this with a "TPM" row.
- **Secure Boot off (present):** TPM sealing still works but binds to a PCR-7
  value that isn't anchored to a trusted boot chain — weaker tamper resistance
  (an attacker who alters the boot path doesn't invalidate the seal). Repair
  flags this with a "Secure Boot" row.

## How this compares to Windows Hello (honest)

Hello keeps biometric templates in a **VBS/TPM-backed enclave** and gates them
behind a hardware-isolated process; the OS never sees raw template material.
irlume is not enclave-isolated — the daemon is a normal (root) process that
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
  encrypt at rest even without a TPM — candidate hardening.
