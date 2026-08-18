# Privacy-bounded support report hardware validation, 2026-08-17

The final four-host matrix ran from signed commit
`ccecf8636ffaccb34ff157d7d9160ae88206ff42`. Each host checked out that exact
object in an isolated worktree. The guarded runner stopped the installed daemon,
started the exact build with an isolated socket and state directory, copied only
capture-qualification records, and restored the installed daemon on every exit.
No enrollment data was copied or read.

## Matrix

| Host | Sanitized camera context | Resolved probe | Report artifact |
|---|---|---|---|
| `UX5406S-Fedora`, kernel 7.1.8-200.fc44.x86_64 | ASUS RGB+IR `3277:0059`, interfaces 0/2, 480 Mb/s, controller `0000:00:14.0`, USB `3-5`; RGB YUYV 640x480 at 1/30; IR GREY 640x400 at 1/15 | sequential default; RGB and IR captured; unqualified/no stored authority | 2,501 bytes; SHA-256 `26c6432595bc969ca2ecbaf8935ea07691a76cee41149a8c273f0704ac20ab19` |
| `HP-ArchLinuxGaming`, kernel 7.1.5-zen1-2-zen | Logitech BRIO `046d:085e`, interface 0, 5 Gb/s, controller `0000:0d:00.3`, USB `4-2`; RGB YUYV 640x480 at 1/30; IR requested GREY 640x400 and accepted 340x340 at 1/30 | stored measured-sequential qualification (`concurrent_unavailable`); RGB and IR captured | 2,496 bytes; SHA-256 `27b9824cf52998ab18270e95aa40c8f7e6386cc11973e4ef89352f577307a587` |
| `minihost`, kernel 7.1.6-1-cachyos | NexiGo N930W `3443:c803`, interfaces 0/2, 480 Mb/s, controller `0000:00:14.0`, USB `1-1.1`; RGB YUYV 640x480 at 1/30; IR requested GREY 640x400 and accepted 640x360 at 1/30 | sequential default; RGB and IR captured; unqualified/no stored authority on this isolated context | 2,500 bytes; SHA-256 `811e2ba01b4a77f4ef041083e3baa1c55753eb6423a279aa82dd3a924d6882d4` |
| `fimerlwi-ThinkPad-X13-Yoga-Gen-4`, kernel 7.0.0-29-generic | Chicony RGB `04f2:b7bf`, interface 0, 480 Mb/s, controller `0000:00:14.0`, USB `3-4`; YUYV 640x480 at 1/30; no IR endpoint | `no_ir_pair`; RGB-only captured, IR correctly reported missing | 1,803 bytes; SHA-256 `59a3205b37e2aada3cb6629391a86535e73fbb27a2659aa9378afef4f2055119` |

Every report rendered the driver/backend, controller and USB topology,
serial-presence boolean, truncated descriptor/qualification/runtime tokens,
requested and accepted exact stream contracts, lifecycle generation, capture
schedule/source, qualification reason, and process-local degradation field.
The human report contains no raw serial or device/sysfs path.

## Read-only and publication checks

The unprivileged default report changed the exact-build daemon log by zero lines
on every host: 14→14 on this host, 13→13 on Archhost, 14→14 on Minihost, and
11→11 on ThinkPad. This is the physical evidence that the default path did not
open a camera or activate an emitter. The runner also rejected `/dev/video` in
the report body.

On all four hosts:

- the report footer SHA-256 matched the body;
- final reports were mode 0600 and below the 1 MiB limit;
- a second publication to the same path returned nonzero and left the original
  hash unchanged;
- interrupted trace publication left only a mode-0600 named partial, never a
  truncated final artifact;
- the installed daemon was active again after the isolated run.

## Explicit probe and fallback

The normal probe captured both roles on all RGB+IR hosts and returned the
categorical RGB-only result on ThinkPad. A second Archhost run set the existing
operator override to request concurrent capture. The BRIO reported:

```text
concurrent via environment_override
PairRateEstablishmentFailure
fallback_captured (RGB=captured, IR=captured)
```

The copied qualification JSON remained exactly
`bf8f000f5a071c9203bfb5a3bb803a57f838208017b7175a6e12a99343e2af3d`
before and after, and its empty lock remained the SHA-256 empty-file digest.
The explicit support probe therefore exercised bounded safety fallback without
publishing or changing durable qualification authority.

## Hardware findings that changed the implementation

Physical validation found three gaps that software fixtures had not exposed:

1. `SupportProbeSink` forwarded share-safe events but dropped trace-only events.
2. The dual-camera probe held a diagnostics operation and then reacquired its
   own lease from a worker, timing out against itself.
3. The daemon snapshot initially retained no camera context, and the RGB-only
   probe used a bare capture that omitted detector/liveness trace evidence. The
   first complete renderer then exposed that the primary text artifact still
   omitted topology and exact contracts even though JSON carried them.

The branch now has executable regressions for each seam. The final physical
matrix above is after all four corrections.

## Evidence location

The raw machine artifacts remain private on the four hosts under:

```text
/var/tmp/irlume-diag-evidence-ccecf86-this
/var/tmp/irlume-diag-evidence-ccecf86-archhost
/var/tmp/irlume-diag-evidence-ccecf86-minihost
/var/tmp/irlume-diag-evidence-ccecf86-thinkpad
/var/tmp/irlume-diag-evidence-ccecf86-archhost-forced
```

They are not committed because the report is the intentionally share-safe
projection; raw daemon logs and local filenames are not product fixtures.
