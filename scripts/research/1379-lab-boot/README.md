# Book 2 dummy boot proof

The guest owns no physical device and has neither a disk nor a network.
QEMU runs with `-nodefaults` and `-no-user-config`, so a host `qemu.conf`
cannot add a device. Only the guest's synthetic PID 1 fixture is privileged. The host does not
load a kernel, change cgroups or install anything for this proof.

Use a clean checkout of Linux
[`988117cc1bb17338c586a4e21ade88b5397eac33`](https://github.com/gregkh/linux/tree/988117cc1bb17338c586a4e21ade88b5397eac33)
and QEMU x86-64 11.1.3 with TCG. The build needs GCC, static libc, standard
Linux build tools and `bc`; if using a private copy, verify its source or
package signature and put it on `PATH` for this build only. The verifier
and its tests need Python 3.11 or newer. Choose a fresh
absolute scratch path underneath `/tmp/opencode` and run without privilege:

```sh
lab=scripts/research/1379-lab-boot
bash "$lab/build_guest.sh" "$linux" "$scratch/build"
python3 -B -m unittest discover -s "$lab" -p test_run_guest.py
python3 -B "$lab/run_guest.py" "$scratch/build" "$scratch/smoke-receipt" smoke
```

Every run uses a new receipt directory and a per-boot nonce. The verifier
reads the serial log without newline translation, splits it on `\n` only
and refuses a receipt line with a control character. Only PID 1 can write
receipt lines: every forked child first points its standard descriptors at
an `O_PATH` handle of `/`, which refuses reads and writes and is not a
device. The boundary worker checks this before it reports
`INHERITED_HANDLE_CLOSED`. A smoke pass
proves that this exact kernel and initramfs booted and powered off without
passthrough. It does not prove device policy, capture, teardown or Book 2
qualification.

Run `missing-deny` and `policy` with separate receipt directories. The
negative image path verifies a dummy read actually works without the device
filter but must stop before inventory. The positive path installs a real
guest device filter before inventory and checks equal-mode aliases, a different
minor, write and node-creation denial. The target is the built-in `mem` class
entry `1:5`, with matching sysfs identity and a guest compiled without modules.
A refused module operation is a control for this fixed built-in endpoint,
not a lifetime guarantee for a detachable camera or a reused media device.

The `boundary` case additionally seeds a real dummy descriptor before worker
startup, requires it to be closed before any approved open, and verifies that
the quarantined peer cannot read the owner's still-live proc descriptor link
or open the dummy alias. A guest-only Unix-socket control transfers a real
dummy descriptor without the fixture filter. It then checks that the same
filter as the worker refuses sending and receiving on a viable socket with
a descriptor queued; only this control keeps the socket, not the worker.
The `kept-fd` negative reaches the same retained-handle refusal guard
instead of any successful boundary receipt. This is a fixed dummy fixture
with audited workers; it does not validate libcamera, IPA or a production
supervisor.

Run the complete set in fresh emulator instances:

```sh
for case in smoke missing-deny policy kept-fd boundary; do
    python3 -B "$lab/run_guest.py" "$scratch/build" "$scratch/check-$case" "$case" || exit 1
done
```

The two negative cases are successful only when they report refusal and never
emit a later-stage success record. Keep `build.sha256`, `guest.config` and the
case serial logs with the signed source revision and tool versions. Do not
attach the guest image to a support issue or infer device replacement safety
outside this built-in guest node. The first lab requirements still not covered
are B03 through B11; B12 remains a separate attended-device decision.
