# Package upgrade and rollback validation

[`scripts/test-package-upgrade.py`](../scripts/test-package-upgrade.py) exercises
four real package transactions in one disposable systemd guest:

1. Install the old package (`old-install`).
2. Upgrade to the candidate (`candidate-upgrade`).
3. Restore the complete old package (`old-rollback`).
4. Upgrade to the candidate again (`candidate-reupgrade`).

The current harness requires upstream versions **0.11.3 → 0.12.0 → 0.11.3 →
0.12.0**. It checks package metadata and installed CLI versions; renaming an
artifact does not change its version. For a later release pair, review and
update the harness's version and state-format assertions before running it.
This document describes a procedure, not a completed qualification result.

## Prepare an isolated guest

Use a fresh x86_64 QEMU/KVM VM for each package lane. Give it task-owned disks,
systemd as the running service manager, and no pre-existing Irlume installation.
Do not attach host cameras, physical TPMs, USB devices, shared folders, host
credential directories, or an SSH agent. Use an emulated TPM only if needed.
Transfer public packages and reviewed scripts over the guest's dedicated access
channel; keep host private keys outside the guest.

The guard requires effective UID 0, `systemd-detect-virt --vm` reporting `qemu`
or `kvm`, and an exact root-controlled marker. **The marker is the operator's
attestation; it cannot prove isolation or detect device passthrough.** Inspect
the VM configuration before creating it. Containers and ordinary host execution
are refused.

Prepare these prerequisites inside the guest before taking a clean snapshot:

- Python 3.9 or newer; systemd tools, working distribution repositories, and the
  runtime dependencies of both package versions. The harness does not bootstrap
  its tools or repair a broken package database.
- Debian/Ubuntu: `apt-get`, `dpkg-deb`, and `dpkg-query`. Arch: `pacman`, `tar`,
  and zstd support. Fedora: DNF5, RPM, `getenforce`, and `semodule`, with SELinux
  **Enforcing** throughout the run.
- For authentication checks: `pamtester` with the 0.1.2 exit-status contract,
  `useradd`, `chpasswd`, `sudo`, NSS account/group lookup, and an active
  `ssh.service` or `sshd.service`. If a distribution does not package pamtester,
  build an authenticated source archive inside the guest and record its digest.
  `/usr/local/bin` must exist, be root-owned, and not be group/other-writable;
  the checker validates its ancestors as well.
- An independent non-root account named `qualifier`, with its own working SSH
  login, nonempty `~/.ssh/authorized_keys`, and `sudo -n true` access. Keep that
  administrative connection available. Do not pre-create the checker's separate
  `irlume-upgrade-fixture` account or its private files.

Preserve the distribution's service security settings. Do not disable
AppArmor/SELinux, loosen systemd confinement, or add privileged device access to
make a failing transaction appear qualified.

## Stage verified inputs

Verify package provenance and digests before staging them. For published Debian
and Arch release assets, use the repository's
[`verify-release-assets.py`](../scripts/verify-release-assets.py) with the trusted
release signing key. Record the candidate source revision, build provenance,
package metadata, and digests separately from this generic procedure.

For Fedora, obtain **both** `irlume` and `irlume-selinux` RPMs for each version
and the target Fedora release. The main package must be x86_64 and the policy
package noarch; each pair must have exactly matching version-release metadata.
Import the applicable public Copr signing key into the guest only after checking
its fingerprint against a trusted source; keep that verification receipt.
Every DNF5 transaction enables `localpkg_gpgcheck=True`. An unsigned RPM or an
unknown signing key is a failure, not a reason to disable the check.

Run the following **only in a root shell inside the inspected disposable VM**:

```sh
install -d -m 0755 /var/tmp/irlume-upgrade-input
install -d -m 0700 /var/tmp/irlume-upgrade-output
umask 077
(set -C; printf '%s' 'irlume-upgrade-20260910' > /run/irlume-upgrade-disposable)
```

The marker has no trailing newline. Copy the reviewed harness and
[`check-upgrade-auth.py`](../scripts/check-upgrade-auth.py), plus the verified
packages, into `/var/tmp/irlume-upgrade-input`. Use real files and absolute paths;
the harness refuses symlink inputs or ancestors. The filenames below are staging
names: preserve the package extension and use the correct verified contents.

Take a snapshot before the first transaction, while no Irlume or authentication
fixtures are installed. Include the guest's emulated TPM state in the recovery
plan if present. `/run` is volatile, so re-create the exact marker after a reboot
only after rechecking that this is still the intended isolated guest.

## Run one lane

Each command below runs all four stages. Choose one command for the guest's
distribution; every output filename and its `.log` sibling must be new. The
output directory must already exist and have no symlink ancestors.

Debian/Ubuntu:

```sh
python3 /var/tmp/irlume-upgrade-input/test-package-upgrade.py \
  --old /var/tmp/irlume-upgrade-input/old.deb \
  --candidate /var/tmp/irlume-upgrade-input/candidate.deb \
  --stage-check /var/tmp/irlume-upgrade-input/check-upgrade-auth.py \
  --output /var/tmp/irlume-upgrade-output/debian.json
```

Arch:

```sh
python3 /var/tmp/irlume-upgrade-input/test-package-upgrade.py \
  --old /var/tmp/irlume-upgrade-input/old.pkg.tar.zst \
  --candidate /var/tmp/irlume-upgrade-input/candidate.pkg.tar.zst \
  --stage-check /var/tmp/irlume-upgrade-input/check-upgrade-auth.py \
  --output /var/tmp/irlume-upgrade-output/arch.json
```

Fedora:

```sh
python3 /var/tmp/irlume-upgrade-input/test-package-upgrade.py \
  --old /var/tmp/irlume-upgrade-input/old.rpm \
  --candidate /var/tmp/irlume-upgrade-input/candidate.rpm \
  --old-selinux /var/tmp/irlume-upgrade-input/old-selinux.rpm \
  --candidate-selinux /var/tmp/irlume-upgrade-input/candidate-selinux.rpm \
  --stage-check /var/tmp/irlume-upgrade-input/check-upgrade-auth.py \
  --output /var/tmp/irlume-upgrade-output/fedora.json
```

The harness uses apt with downgrade and conffile-preservation options, pacman
`-U`, or DNF5 `install`/`upgrade`/`downgrade`/`upgrade` with both RPMs together.
Package transactions have a 900-second timeout, daemon readiness a 120-second
budget, and each optional stage checker a 180-second timeout. Omitting
`--stage-check` omits authentication qualification and is recorded in the JSON.

## Interpret results and recover

Require a zero exit status, top-level `passed: true`, and four passing stage
receipts. Inspect each stage's authentication result and limitations as well.
Package-manager success alone is insufficient: the harness checks installed
versions, a ready daemon Ping response, PID replacement, the running executable's
digest, required payload modes, and preservation of configuration and synthetic
state. Old-package files must return byte-for-byte with their original modes and
owners. Debian's explicitly declared obsolete candidate conffiles may remain;
they are checked and reported separately. Fedora checks both installed RPMs,
enforcing mode, and presence of the enabled Irlume policy module.
Reviewed tmpfiles tightening of the state root's group/other permissions is
allowed; synthetic descendant metadata must remain unchanged.

The authentication checker creates a throwaway account, a private PAM service,
and a randomly generated guest-only password. It tests correct and incorrect
password fallback at every stage, plus candidate retry status and reset behavior
when available. Passwords travel over stdin and stay inside
`/var/tmp/irlume-upgrade-private`; never print, copy, or publish that directory.

Export **only the sanitized JSON receipt** for shared evidence. Raw package
output and service diagnostics remain in the guest's `.log` file. Do not export
guest journals, account databases, private fixture manifests, or disk snapshots
as ordinary report attachments. Retain the exact artifact digests and build
provenance alongside the receipt.

On failure, stop and inspect the guest locally. The harness leaves the failed
stage's state intact; terminating a timed-out process group cannot undo writes
already applied by a package transaction. It performs no automatic repair,
removal, or purge. Recover by restoring the known clean VM snapshot or creating
a new disposable guest, then run the full sequence with a fresh output path.
Do not delete individual fixture files or restart the sequence on a partially
tested installation. Discard only the task-owned guest after preserving the
sanitized evidence.

## Qualification limits

- Synthetic configuration, state bytes, and retry records establish preservation
  of those fixtures. They do not establish cryptographic enrollment usability,
  TPM-sealed credential recovery, camera behavior, liveness, or biometric login.
- Version 0.11.3 has no retry enforcement. Retaining candidate retry files during
  rollback does not mean that the old daemon enforces their limits.
- An enforcing AppArmor installation can intentionally report password-verified
  retry reset unavailable. Record that limitation; password fallback is tested
  separately. Do not turn off confinement to change the outcome.
- The transaction sequence covers the package's enabled, running service path
  and checks that its enabled state remains unchanged. It does not qualify an
  administrator-disabled or stopped-service upgrade, a wired graphical greeter,
  or every login manager. An enabled SELinux module listing does not prove its
  live byte equivalence or confined greeter access.
- A separate Nix profile generation rollback is not a NixOS system-generation,
  module, service, PAM, or hardware qualification. This package harness does not
  implement a NixOS transaction. See [NIXOS.md](NIXOS.md) for that integration.

Run the local harness regressions without installing any packages:

```sh
python3 scripts/test-package-upgrade-harness.py
python3 scripts/test-check-upgrade-auth.py
```
