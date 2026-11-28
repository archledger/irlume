# Book 2 dummy boot proof

The guest owns no physical device and has neither a disk nor a network.
Only the guest's synthetic PID 1 fixture is privileged. The host does not
load a kernel, change cgroups or install anything for this proof.

Use a clean checkout of Linux
[`988117cc1bb17338c586a4e21ade88b5397eac33`](https://github.com/gregkh/linux/tree/988117cc1bb17338c586a4e21ade88b5397eac33)
and QEMU x86-64 11.1.3 with TCG. The build needs GCC, static libc, standard
Linux build tools and `bc`; if using a private copy, verify its source or
package signature and put it on `PATH` for this build only. Choose a fresh
absolute scratch path underneath `/tmp/opencode` and run without privilege:

```sh
lab=scripts/research/1379-lab-boot
bash "$lab/build_guest.sh" "$linux" "$scratch/build"
python3 -B -m unittest discover -s "$lab" -p test_run_guest.py
python3 -B "$lab/run_guest.py" "$scratch/build" "$scratch/smoke-receipt" smoke
```

Every run uses a new receipt directory and a per-boot nonce. A smoke pass
proves that this exact kernel and initramfs booted and powered off without
passthrough. It does not prove device policy, capture, teardown or Book 2
qualification.
