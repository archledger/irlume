# ADR-0035: No phase-locked daemon key

## Status

Proposed 2026-10-17. Records a design irlume considered and does not adopt:
releasing a TPM-sealed key to irlumed only during an early part of the boot,
then closing that window, so that a root process later in the same boot
could not unseal irlume's envelopes through the TPM. The maintainer chose on
2026-10-17 to record it as declined. Depends on ADR-0025 (one template-key
unseal per authentication request) and ADR-0034 (irlume's storage key);
changes neither. Changes no code.

## Context

### The proposal

Three systems release a key only early in the boot and then make the TPM
refuse it for the rest of that boot:

- BitLocker seals its key with PCR 11 at 0, and the boot manager extends
  PCR 11 before it hands control to any boot loader: "Since the PCR 11 value
  is guaranteed to be different after exiting the boot manager, the attacker
  can't unlock the BitLocker key" (Microsoft Learn, "BitLocker
  countermeasures").
- Android's KeyMint marks keys `EARLY_BOOT_ONLY`: they "may only be used
  during early boot, until IKeyMintDevice::earlyBootEnded() is called", which
  `init.rc` calls once `/data` is mounted (AOSP `Tag.aidl`,
  `IKeyMintDevice.aidl`).
- systemd measures boot phase words into PCR 11 (`systemd-pcrphase`, since
  v252) so that, for example, a LUKS key is "only accessible in the initrd,
  but not later" (systemd NEWS 252). Since v259 its NvPCRs, NV indexes used
  as PCRs, may be written for the first time only from the initrd (NEWS 259
  and 262).

For irlume the design would be: irlumed unseals one daemon key while the
window is open, then closes it, by extending a PCR the key's policy reads or
by read-locking an NV index the policy gates on (`TPMA_NV_READ_STCLEAR` and
`TPM2_NV_ReadLock`; `TPM2_PolicyNV` then fails with `TPM_RC_NV_LOCKED`, TPM
2.0 Library Part 3, 23.9 and 31.14). Envelopes would be opened with that key
for the rest of the boot. A root process that ran after the window closed
could no longer unseal them through the TPM.

### What it would protect against, as irlume runs today

irlume already states that root on the running machine is its trust
boundary. docs/SECURITY_AT_REST.md's attacker table, row "Root on the live
original machine": "Game over: root can ask the daemon to unseal". Two paths
stay open to such a root process whatever the TPM refuses:

- **Asking irlumed, for the keyring secret.** `UnsealKeyring` releases the
  sealed login password, KDE wallet key or GNOME keyring token to a root peer
  on a login or unlock service with no face match, for the fingerprint path;
  its wire documentation says "a live root attacker in a login context can
  obtain it" (`Request::UnsealKeyring`, ADR-0003). A phase lock would not
  change that.
- **Reading irlumed's memory, for everything.** irlume is not
  enclave-isolated, and root can read the daemon's memory
  (SECURITY_AT_REST.md, "Residual gaps"). Under the proposal that memory
  would hold the daemon key for the whole uptime.

The template key and the templates are different: irlumed never sends them
to a peer, so asking irlumed does not reach them. A phase lock would keep the
template envelopes from a root process that also cannot read irlumed's
memory. That needs a host that blocks both ways root reads another process:
Yama's ptrace scope 3, where "no processes may use ptrace with PTRACE_ATTACH
nor via PTRACE_TRACEME" (kernel `Documentation/admin-guide/LSM/Yama.rst`;
modes 0 to 2 leave root able to attach), and kernel lockdown, which
restricts direct access to the running kernel image (`/dev/mem`, `/dev/kmem`,
`/dev/kcore`, BPF and kprobes among others, `kernel_lockdown(7)`). That is the benefit this ADR weighs: the privacy of
the templates against a live root process, on hosts hardened that far.

### What the mechanisms give on the machines irlume runs on

Researched from the systemd source and documentation (main at `bdea819a`,
tag v262), the TPM 2.0 Library v185 Parts 1 to 3, the PC Client Platform
Firmware Profile 1.06 r52, the TCG reference implementation, the kernel, and
the UAPI group's registries:

1. **systemd's phase words exist only on measured boots.** The
   `systemd-pcrphase` units are conditioned on `ConditionSecurity=measured-uki`
   (v255 to v260) or `measured-os` (v261 on), which is set only when
   systemd-stub measured the booted UKI (`StubPcrKernelImage`) or
   `systemd.tpm2_measured_os=` says so. On a GRUB boot of a plain kernel the
   units do not run, PCR 11 stays zero for the whole boot, and any process
   that can extend PCRs can give it any "phase" value.
2. **Policies limited to the initrd need a measured UKI.** In v262,
   `systemd-measure --policyref`, `systemd-cryptenroll
   --tpm2-public-key-policyref=initrd` and `ukify --sign-initrd-pcrs` sign
   with the key whoever builds the UKI holds: a distribution or the machine's
   owner, not irlume. systemd main (commit `46bdee6`, 2026-10-14, after v262)
   falls back, for NvPCRs, to a write policy bound to the current value of
   PCR 11 when the UKI carries no signed initrd policy. Its NEWS notes that
   such a policy changes "whenever the UKI changes, so this is mostly useful
   where the value of PCR 11 in the initrd is predictable". A gate built that
   way needs no builder key, but still a measured UKI, and its policy must be
   remade at each UKI update.
3. **irlumed starts late.** Its unit is ordered `After=multi-user.target`
   (`packaging/systemd/irlumed.service`). A window that irlumed itself closes
   is open to every root service that starts before it. Closing it before
   host userspace means an initrd or early unit that unseals the key and hands
   it over: systemd credentials are decrypted again at each service start
   (`docs/CREDENTIALS.md`), so the hand-over would go through PID 1's file
   descriptor store instead.
4. **An NV gate must be anchored.** NV indexes "can be deleted by anyone
   with access to the TPM, and then be recreated" (systemd
   `docs/TPM2_PCR_MEASUREMENTS.md`), so systemd measures each NvPCR's name
   into PCR 9 and allows the first write only from the initrd. An irlume gate
   index would need the same anchoring, a subrange of the UAPI.19 Linux NV
   index range, and `TPMA_NV_POLICY_DELETE` to resist recreation. Anyone who
   can read the index can also read-lock it first, a denial of service.
5. **No PCR is free.** PCR 16 and 23 can be reset from any locality (PC
   Client Firmware Profile 3.3.4.9 and 3.3.4.10), and S3 does not preserve
   them (3.3.4.10 for PCR 23; the TCG reference implementation saves neither),
   so they cannot hold a lock. UAPI.7 lists a Linux user for every one of
   PCR 8 to 15; an extra extend of PCR 11, for example, breaks systemd
   secrets bound to its phase paths.
6. **Hibernation reopens every lock, and writes the key to disk.** A resume
   from S4 is a TPM Restart (`Startup(CLEAR)` after `Shutdown(STATE)`): every
   PCR returns to its initial value and every STCLEAR lock clears (Part 1,
   9.2.3.2; Part 3, 9.3.1), while the restored userspace, including any root
   process that was running, comes back with the window open. systemd has the
   same open problem for its own phases (systemd issue #34488). S3 and s2idle
   keep the locks. Before that, hibernation "creates a snapshot image of
   memory to be written into persistent storage" (kernel
   `Documentation/admin-guide/pm/sleep-states.rst`), and a key held for the
   whole uptime is in it. On a host whose image or swap is not encrypted, a
   thief who takes the disk afterwards reads the key and opens every
   envelope, which the seal alone protects today: the template key exists in
   memory only during a request (ADR-0025 section 3).
7. **A restart cannot reopen the window.** Without a key kept outside the
   process, every restart of irlumed would end face login until the next
   boot. systemd's file descriptor store can keep the key in a memfd: "a
   restart job for a service will leave the fdstore intact, but a separate
   stop and start job for it ... will likely not" (`docs/FILE_DESCRIPTOR_STORE.md`).
   An automatic restart after a crash (irlumed's unit sets
   `Restart=on-failure`) and RPM's `%systemd_postun_with_restart` are restart
   jobs, so the key would survive them. It would not survive a `systemctl stop`
   followed by a `start`, or a crash loop that exhausts the restart attempts
   and leaves the unit failed, unless `FileDescriptorStorePreserve=` keeps the
   store. The key would then live in PID 1 as well as in irlumed.

### What it would cost

- It reverses ADR-0025 section 4, which keeps no key across requests and
  leaves "a short-lived, PCR- and file-digest-keyed in-process cache" to its
  own decision with "PCR drift, suspend and lock-screen questions" (#797,
  step 3). Each request now unseals under the PCR policy, so a PCR change
  between requests refuses at the next load; a key unsealed once at start
  would not.
- Face login would depend on how irlumed stops: a stop and start, or a crash
  loop that leaves the unit failed, would end it until the next boot (points
  3 and 7 above).
- Hibernation would need its own handling (point 6): the key would have to
  be dropped before the snapshot, with a reboot to get it back, or the
  hibernation image encrypted independently, and the window re-closed from
  the resume path, which no supported init system does today. Without that,
  a host that hibernates to an unencrypted image would lose today's
  protection against disk theft.
- It would take a TPM resource irlume does not hold today: an anchored NV
  index with its own registry range, or a PCR another component uses.

## Decision

### 1. irlume does not phase-lock a daemon key

irlumed holds no key across authentication requests. Each request keeps
unsealing the template key under the envelope's PCR policy once, as ADR-0025
decides. irlume extends no PCR and defines no NV index to open or close a
boot-phase window.

### 2. Why

1. The lock would not protect the keyring secret, which root can ask irlumed
   for (`UnsealKeyring`). It would protect the template envelopes only from a
   root process that cannot read irlumed's memory, on hosts with Yama's
   ptrace scope 3 and kernel lockdown, and on every other host it would make
   reading memory more rewarding, since the key would sit there for the
   whole uptime.
2. On most installs the window cannot close before host userspace: PCR 11
   phases need a measured UKI, initrd-only policies need the UKI builder's
   signing key, and irlumed starts after `multi-user.target`.
3. Every resume from hibernation reopens the window for the userspace it
   restores, and every hibernation image holds the key, so a host without an
   encrypted image would trade protection against disk theft for it.
4. A stop and start, an upgrade outside a restart job, or a crash loop that
   leaves the unit failed would turn face login off until the next boot.
   Surviving the other restarts means keeping the key in PID 1's file
   descriptor store as well.

### 3. What stays as it is

The protections docs/SECURITY_AT_REST.md describes are unchanged: envelopes
are sealed to the boot state their policy binds, a stolen disk unseals
nothing, and root on the running machine is the trust boundary. Nothing in
irlume's documentation claims protection from a live root process, and this
ADR adds none.

### 4. When to revisit

Revisit when all of these hold:

- irlume no longer releases a sealed secret to root without a check that
  root alone cannot satisfy, so a TPM lock would close the last path;
- the supported distributions boot measured UKIs by default, with signed
  initrd-phase policies or a predictable PCR 11 for systemd's fallback, so a
  key can be unsealed in the initrd and the window closed before host
  userspace;
- a resume from hibernation re-closes such windows before the restored
  userspace runs (systemd issue #34488, or an equivalent), and the key can be
  kept out of the hibernation image.

The template-envelope benefit (Context, "What it would protect against, as
irlume runs today") can also be raised on its own, for hosts hardened with
Yama's ptrace scope 3 and kernel lockdown, if the maintainer judges it worth
the costs above for them.

## Consequences

- No behaviour, wire or file format changes.
- docs/SECURITY_AT_REST.md's residual gaps name this ADR, so the reason
  irlume does not do what BitLocker does with PCR 11 is recorded where the
  root trust boundary is.
- The queue's item 6 from the 2026-10-14 TPM survey is closed. The research
  behind this record is kept with that survey.

## Acceptance tests

None execute code: this ADR changes no behaviour. The tests that pin ADR-0025
(one unseal per request, the key dropped on every return path, no copy of it)
stay as they are and keep pinning section 1.
