# Issue #492: four-device IR setup evidence

Date: 2026-08-18  
Tested commit: `5f38c745a390452e389dbb922dc8c61e8b631c4b`  
Harness: `scripts/hardware/ir-setup-evidence-hardware-test.sh`

## Purpose

This is the physical acceptance record for the evidence semantics introduced
for issue #492. It tests three distinct claims:

1. Microsoft Face Authentication D1 may be accepted only when its alternating
   frame behavior is tied to the control transition.
2. Weak or absent optical evidence is `Inconclusive`, not proof that a control
   is unsupported or unusable.
3. Every exploratory write is exactly recoverable, and a failed recovery must
   preserve its durable record and keep normal service stopped.

The transition harness atomically snapshots the camera identity and current
control bytes from one open descriptor. Its identity token binds the descriptor
hash, interface, serial when present, USB device path, and live sysfs inode.
Every direct test write revalidates that token on the same descriptor that will
receive the ioctl. The exact initial bytes are fsynced under `/var/lib` before
the first write. Cleanup deletes that record and restarts the packaged daemon
only after exact read-back succeeds.

## Artifact identity

The Fedora-built artifacts used on the local ASUS, Arch BRIO, and CachyOS
NexiGo hosts had these SHA-256 values on every machine:

| Artifact | SHA-256 |
|---|---|
| `irlume` | `cc876d2835673e2ee342126e38c456c398c1e474aaf06fffff5f1cad3b6a9b90` |
| `irlumed` | `c7484f3597ba432c59faca8cb9d2bdb7055712099ab547b3d20becc51946374c` |
| `xu_set` | `5ee76866d4bbed1e98bcb25dfdbf1daf21d87182fcf4bd5053e3c36835c63b34` |
| hardware harness | `c0209fb8c430d07978723d9ce0199eaecb8e00bdaa53f4cb0328a4e8a7e89152` |

The Ubuntu ThinkPad could not load the Fedora binary because Ubuntu lacked
`libcrypt.so.2`. It therefore built the same complete-history bundle and exact
commit natively, with `TMPDIR` and `CARGO_TARGET_DIR` on its home filesystem.

## Results

| Host / camera | Hardware class | Result | Final control / state |
|---|---|---|---|
| UX5406S Fedora, Shinetech ASUS `3277:0059` | transition, unit 14 selector 6 | 8 passed, 0 failed | exact pre-test `010301000000000000`; daemon active |
| Arch host, Logitech BRIO `046d:085e` | device default, unit 12 selector 6 | 8 passed, 0 failed | unchanged D1 `010202000000000000`; daemon active |
| CachyOS mini host, NexiGo N930W `3443:c803` | transition, unit 4 selector 6 | 8 passed, 0 failed | exact pre-test `010301000000000000`; daemon active |
| Ubuntu ThinkPad, Integrated Camera | no usable emitter XU | 3 passed, 0 failed | no XU write and no persisted state; daemon active |

No host retained a `/var/lib/irlume-492.*` recovery directory after its
successful exact-restoration audit.

### ASUS transition camera

With UVCM metadata available, setup proved D1, persisted `3277:0059 14:6`,
left exactly `010302000000000000` applied until harness cleanup, and left no
undo record. With metadata forcibly disabled, the optical observation was too
weak (`before 91`, `after 89`, threshold `+20`), so setup returned typed
`Inconclusive`, saved no config, and restored the parked value exactly.

Transcript directory: `/tmp/irlume-492-evidence.lDz7sA`

### BRIO device-default camera

Both metadata modes recognized the validated Face Authentication D1 default
`010202000000000000`. Neither mode emitted `SET_CUR`, neither persisted a
configuration or undo record, and both left the exact control unchanged.

Transcript directory: `/tmp/irlume-492-evidence.Van31D`

### NexiGo transition camera

With UVCM metadata available, setup proved D1, persisted `3443:c803 4:6`, left
exactly `010302000000000000` applied until cleanup, and left no undo record.
With metadata disabled, the weak optical observation (`before 0`, `after 7`,
threshold `+20`) returned typed `Inconclusive`, saved no config, and restored
the parked value exactly.

Transcript directory: `/tmp/irlume-492-evidence.ljXEb3`

### ThinkPad RGB-only camera

The camera's Microsoft unit advertised selectors `0x02`, `0x03`, and `0x09`,
but neither Face Authentication `0x06` nor IR Torch `0x0a`. Setup therefore
reported no usable emitter control, emitted no XU write, and persisted neither
configuration nor undo state.

Transcript directory: `/tmp/irlume-492-evidence.LR7r6h`

## Conclusion

The physical matrix supports the typed three-state design. Contract-level
metadata established D1 on both transition cameras. Removing that observation
did not produce strong control-correlated optical evidence on either device,
so both correctly became `Inconclusive` rather than false success or a claim of
incompatibility. The BRIO remained a read-only device-default success, and the
RGB-only ThinkPad remained a definitive no-control result without writes.

Most importantly, all exploratory paths ended with exact control read-back,
no recovery residue, and the packaged daemon active.
