# Native NPU/AppArmor experiment checkpoint

Work in progress for #1046. This directory preserves the lab sources after
the temporary workspace was cleared. It is not a supported deployment tool
or a completed NPU qualification.

## Current result

- The Rust change adds test-only synthetic-input checks. It does not open
  production native-loading or certification gates.
- The latest disposable guest passed the known-denial control and reached
  the native test. It failed before NPU compilation because the guest had
  no accelerator node under `/sys/class/accel`.
- Its native audit window also contained a denied read of
  `/proc/sys/vm/nr_hugepages`. The missing-device cause remains unresolved;
  these two observations must not be conflated.
- No successful NPU model inference has been recorded. Neither profile's
  combined native-inference acceptance is complete.
- Host recovery was verified after the attempts. Hardware testing is paused.

Earlier attempts found an undersized guest filesystem and a checker that
compared the kernel's process ID with a worker thread ID. The preserved guest
runner requires 2 GiB free before installation and checks the correct process
ID. Native windows still reject every AppArmor denial.

## Preserved source

`SNAPSHOTS.json` identifies the original source archives and hashes. The
latest host controller, attempt wrapper, guest runner, ELF closure checks,
audit checks, result checks, input builders and device-free lifetime proof
are retained here. Some test filenames retain their earlier version labels;
their imports now target the preserved controller and wrapper.
The superseded first host controller is not republished; its historical tests
remain in the private archive. Restored regressions cover the final controller's
typed scope binding, canonical device paths, power policy and test summaries.

The XML and JSON under `fixtures/` describe the failed fourth attempt. They
are historical inputs, not instructions to rerun it.

These scripts contain fixed lab paths, hashes, machine identities and consumed
attempt IDs. Do not run the host controllers, input builders or lifetime proof
directly from this checkpoint. Reconstruct and verify all inputs, create a new
attempt identity and obtain approval plus an exclusive hardware reservation
before a future run. Never retry a consumed attempt or overwrite its receipts.

The retained controls include a paused guest, a connection held for libvirt
AUTODESTROY, an independently bound QEMU-scope timer, resource limits and a
recovery sleep inhibitor that stays active if restoration is uncertain.
None of those controls grants permission to launch hardware tests.

## Offline checks

The Python tests require Python 3.11 or later, `pyelftools` 0.32 and a C
compiler. Use an environment where those dependencies are already installed:

```sh
python3 -B -m unittest discover \
  -s scripts/experiments/npu-apparmor -p 'test_*.py'
```

This command runs parser and mocked lifecycle tests, not the guest controllers
or the ignored Rust hardware tests. Do not sweep ignored tests with `--ignored`.
The restored checkpoint passes 59 offline tests and Ruff. The count excludes
three tests for the superseded first host controller.

Before this checkpoint, the exact Rust source diff passed 394 vision tests
with 22 intentionally ignored hardware tests, plus Clippy. That is retained
software evidence, not a fresh full-workspace run or an NPU success claim.

## Resume

1. Keep hardware testing paused while examining the guest's driver and
   firmware logs. The last full offline export was interrupted and its
   output has not been validated.
2. Establish why the guest had no accelerator node. Separately evaluate the
   observed hugepage read against the actual profiles; do not suppress audit
   failures or substitute firmware identity.
3. Rebuild a fresh, hash-verified payload from the corrected source. The
   builders also require the pinned model, native libraries, firmware package,
   authenticated Ubuntu image and external staging manifests. Those inputs
   are deliberately not included in Git.
4. Complete both executable-path cases, both denial controls, repeated native
   output checks, CPU comparisons and host restoration before claiming success.

VM images, model weights, compiled binaries, credentials, raw guest journals
and private recovery material remain outside Git. Preserve their private
backup and shared handoff records independently; this draft checkpoint does
not replace them.
