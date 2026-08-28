# MS-XU metadata illumination as a pipeline capability (issue #568): source research

Date: 2026-08-27. Agent: opencode. Status: research complete, design pending approval.
Question: what exactly does issue #568 ask for, what already exists in the tree,
and which facts constrain the design? Everything below is verified against the
named source; nothing is inferred where a source could be read.

## 1. What the Microsoft spec says (primary source)

Source: Microsoft UVC 1.5 extensions specification, sections 2.2.2.9, 2.2.3.1,
2.2.3.4, 2.2.3.4.4.
https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5
(local copy: .firecrawl/msxu-spec.md, scraped this session)

- The Metadata Control (2.2.2.9, selector 0x09) is a Windows host-side control
  for enabling metadata production. On Linux it has no direct analog; the
  userspace surface is the uvcvideo metadata capture node (section 3 below).
- Metadata items use one common header, `KSCAMERA_METADATA_ITEMHEADER`:
  `{ ULONG MetadataId; ULONG Size; }` where Size covers header plus payload
  (2.2.3.1).
- The standard identifier enum (2.2.3.1) assigns:
  PhotoConfirmation=1, UsbVideoHeader=2, CaptureStats=3, CameraExtrinsics=4,
  CameraIntrinsics=5, FrameIllumination=6, Custom_Start=0x80000000.
  irlume's `METADATA_ID_FRAME_ILLUMINATION: u32 = 6`
  (crates/irlume-camera/src/ir_metadata.rs:71) matches the spec value.
- The FrameIllumination item (2.2.3.4.4) is exactly 16 bytes:
  `{ MetadataId, Size=16, ULONG Flags, ULONG Reserved }` with the single
  defined flag `KSCAMERA_METADATA_FRAMEILLUMINATION_FLAG_ON = 0x00000001`.
  irlume's parser (ir_metadata.rs:285-292, `size >= 12`, bit 0 of the first
  payload ULONG) reads exactly this shape.
- 2.2.3.4 also says: if firmware produces an identifier's metadata, it "shall
  be present on all frames". irlume measured otherwise (first frame after
  STREAMON carries no record, ir_metadata.rs:31-33). Both facts are recorded
  because the difference is the kernel's, not the camera's, and the parser
  must tolerate absence per frame.
- There is NO ambient-light-level item in the standard set. The only
  illumination signal is the per-frame ON/OFF flag. So the issue's "ambient
  reading" means, in irlume's vocabulary, the Dark-flagged frames (the
  emitter-off ambient exposure), which is what `Illumination::Dark`,
  `ambient_partner`, and `IrCaptureStats::ambient_observed` already model.
  A lux-like number does not exist in this spec and must not be invented.

## 2. What the kernel delivers (primary sources)

Source: kernel docs for V4L2_META_FMT_UVC ("UVCH") and
V4L2_META_FMT_UVC_MSXU_1_5 ("UVCM").
https://www.kernel.org/doc/html/v6.3/userspace-api/media/v4l/pixfmt-meta-uvc.html
https://docs.kernel.org/userspace-api/media/v4l/metafmt-uvc-msxu-1-5.html
(local copies: .firecrawl/kernel-meta-uvc.md, .firecrawl/kernel-msxu.md)

- Each UVCH block is `struct uvc_meta_buf` packed: `__u64 ns; __u16 sof;
  __u8 length; __u8 flags; __u8 buf[];` (the 12-byte prefix irlume's
  `UVC_META_BUF_HEADER` skips). UVCM is the same layout but `buf[]` carries
  all appended UVC payload-header bytes, which is where the Microsoft records
  live.
- The kernel doc states the driver MAY drop headers: when the buffer is full,
  when they carry no new information, or for rate limiting. Consumers must
  treat absence of a record as "not said", which is the fallback irlume
  already implements.
- uvcvideo registers the metadata node against the same USB interface as its
  image node; irlume's sibling-scan pairing rule and its "lowest-numbered
  node above the image node" refinement are documented in ir_metadata.rs:802-917
  with the Brio measurement (#310) and are not re-litigated here.

### The partial-metadata-buffer fix (the issue's "upstream context")

Source: Ricardo Ribalda, "[PATCH v2 0/2] media: uvcvideo: Avoid partial
metadata buffers", 2026-04-17.
https://lore.kernel.org/linux-media/20260417-uvc-meta-partial-v2-0-31d274af7d2d@chromium.org/T/
(v1 2026-04-15 via patchew; local copy: .firecrawl/lore-v2-thread.md)

- Bug: "If the metadata queue that is empty receives a new buffer while we are
  in the middle of processing a frame, the first metadata buffer will contain
  partial information." Fix lineage: `Fixes: 088ead255245 ("media: uvcvideo:
  Add a metadata device node")`; the fix tracks the metadata buffer state and
  only copies once a block is complete (`length <= 2` or a non-ACTIVE buffer
  is dropped wholesale).
- The fix is in stable: it appears in the Linux 6.12.97 stable release
  announcement (https://lwn.net/Articles/1084924/, local copy:
  .firecrawl/lwn-partial-meta.md) and correspondingly in newer series.
- Consequence for irlume: on kernels predating the fix (a live fraction of
  any fleet), userspace can receive a FIRST metadata buffer that begins
  mid-header. irlume's parser already handles arbitrary leading bytes
  defensively (`length < 2` refused, `checked_add` bounds, overrun refused:
  ir_metadata.rs:238-296, with unit tests including every-prefix truncation
  at :1109-1117). Issue #568's acceptance criterion "malformed metadata never
  panics or stalls capture (fuzz corpus case)" is the machine-checked version
  of this property.

## 3. What the tree already has (verified line references)

- Node discovery and probing: `metadata_node_for` (ir_metadata.rs:814-833)
  scans same-interface siblings above the image node and probes each with
  `offers_uvcm` (:925-948), which opens O_RDWR and issues VIDIOC_TRY_FMT.
  TRY_FMT allocates no queue and changes no state, so calling it during
  qualification context collection is observationally safe.
- Per-frame ingestion: `IlluminationLog` is opened inside `IrCamera::session`
  BEFORE image STREAMON (lib.rs:4944-5004), drained between image dequeues,
  and closed on Drop with format restore. The gate-frame and ambient-partner
  selection consume the camera's flags (`best_gate_frame`,
  `ambient_partner`, ir_metadata.rs:309-414).
- Dark-path correlation ALREADY EXISTS: `DarkEvidence` carries
  `frames_lit`, `frames_classified`, and `lit_max_mean`
  (crates/irlume-camera/src/ir_dark.rs:42-67), `ir_dark::diagnose` consumes
  them, and the auth path counts `illumination_failures` when the camera
  contradicts the emitter control (lib.rs:6361-6400, 7065-7139, 7717-7720).
  The IR-dark optical measurement remains authoritative; metadata is
  corroboration. The issue's "consider it as an input to dark-path decisions"
  bullet is therefore DONE by prior work (#167, #264, #221, #312) and needs
  no new dark-path logic.
- Burst statistics: `IrCaptureStats` already reports
  `camera_classified_frames` and `ambient_observed` (lib.rs:313-328), filled
  at lib.rs:5439-5446.
- The diagnostics surface exists: `irlume camera diagnostics --json`
  (issue #462) routes Request::CameraDiagnostics through the daemon
  (daemon main.rs:3983-3992) to `irlume_camera::camera_rate_diagnostics`
  (lib.rs:3492-3517), which runs one bounded gated capture per role and
  returns `CameraDiagnosticsReport { rgb, ir, skew_us, capture_strategy }`
  (irlume-common lib.rs:1101-1109). The IR diagnostic capture currently
  DISCARDS its stats (`let (frame, _stats)` at lib.rs:3452): the evidence
  the issue wants surfaced is already being produced and thrown away.
- The qualification machinery: `QualificationContext` (endpoints + stream
  contracts) is collected non-streaming per capture
  (lib.rs:6923-6944), `QualificationAttempt` carries the measurement
  evidence, and `CaptureQualificationRecord` persists under
  state_dir()/capture-qualifications (capture_qualification.rs:1286-1296)
  with SCHEMA_VERSION=2, POLICY_VERSION=1, PRODUCER_ENGINE_VERSION=1
  (:11-15).
- Fuzz territory: fuzz/ is a separate nightly workspace
  (fuzz/Cargo.toml) whose targets are the daemon's attacker-reachable
  parsers (ipc_request, pcr_signature, sealed_envelope); CI runs each for
  45s from checked-in seeds (.github/workflows/ci.yml:590-664).
  `parse_illumination` is pub(crate) in a private module, so it is currently
  OUTSIDE the fuzz workspace's reach.

## 4. Design constraints the research uncovered

1. DO NOT add the field to `QualificationContext` itself. Two independent
   mechanisms make that hazardous:
   - `runtime_key()` is sha256 over the serialized context
     (capture_qualification.rs:736-740); any new field changes every key.
   - `CaptureQualificationRecord::resolve` compares the stored authoritative
     context to the live one with full-struct equality (:1196-1212), so any
   new field invalidates every stored qualification whose record lacks it
   (`ContextChanged`), on every host, camera and no-metadata alike (old
   records deserialize to None, live collection yields Some). The daemon
   only auto-reprobes on ENROLLMENT (daemon main.rs:3053-3103, #340), so
   existing users would silently lose concurrent authority until a manual
   camera-mode run or re-enroll. That is precisely the "behavior regression
   on cameras without metadata nodes" the acceptance criteria forbid.
   Recording presence in `QualificationAttempt` (the evidence half, not the
   authorization half) satisfies "recorded during qualification" with zero
   effect on stored authority.
2. Record presence, not the node path. /dev/videoN numbering is not stable
   across reboots or replugs; a path in an equality-adjacent record invites
   spurious mismatches. The context's own endpoints are topology identities,
   not node numbers, for the same reason.
3. Serde compatibility is verified both ways: no `deny_unknown_fields`
   anywhere in capture_qualification.rs or irlume-common (checked by grep),
   so an added optional field with `#[serde(default)]` on the attempt reads
   old records as None, and old binaries reading new records ignore the
   unknown field. No schema_version or engine-version bump needed, and
   bumping PRODUCER_ENGINE_VERSION would actually HARM old binaries
   (they would reject new records as invalid evidence).
4. The diagnostics addition can reuse the existing bounded IR capture; it
   only needs to stop discarding `_stats` and to surface node presence
   (a TRY_FMT probe, no streaming). Additive fields on the emitted JSON have
   precedent under contract 1; the report is emitted verbatim by the CLI
   (machine.rs:644-649), which passes unknown content through.
5. The fuzz target needs: irlume-camera added to fuzz/Cargo.toml (it is a
   path dependency; the workspace already depends on two crates), a public
   export of the pure parser (the module is private today), a [[bin]] entry,
   a seeds/ directory, and the target added to the CI loop's explicit list.
6. Fleet gate: this touches the camera qualification and diagnostics path,
   so the camera-change fleet rule applies before merge. Current fleet hosts
   with UVC pairs: archhost (BRIO + NexiGo N930W), ASUS (internal Shinetech
   pair, 0.572 RPM); thinkpad is RGB-only internal Chicony (the
   no-IR-pair case); minihost is camera-less (the no-camera case).

## 5. Gap analysis against the acceptance criteria

- "qualification context records the metadata node presence per camera pair":
  GAP. Nothing in the qualification record mentions the metadata node today.
- "irlume camera diagnostics --json reports the illumination stream state":
  GAP. The report carries rate evidence only; the IR capture's illumination
  stats are computed and discarded.
- "malformed metadata never panics or stalls capture (fuzz corpus case)":
  PARTIAL. Unit tests cover truncation/overrun/zero-size; no fuzz target
  exists, and the parser is not reachable from the fuzz workspace.
- "no behavior regression on cameras without metadata nodes": CONSTRAINT,
  satisfied by design choice 1 above; the no-metadata fallback paths already
  have tests (ir_metadata.rs:1148-1167, 1240-1249).
- Dark-path correlation (task bullet, not an acceptance line): already
  implemented, see section 3.

## 6. Sources

- MS-XU 1.5 spec (sections 2.2.2.9, 2.2.2.10, 2.2.3.1, 2.2.3.4.x):
  https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5
- V4L2_META_FMT_UVC doc: kernel.org doc html v6.3 userspace-api media v4l
  pixfmt-meta-uvc
- V4L2_META_FMT_UVC_MSXU_1_5 doc: docs.kernel.org userspace-api media v4l
  metafmt-uvc-msxu-1-5
- Partial-metadata-buffer series: lore.kernel.org/linux-media
  20260417-uvc-meta-partial-v2-0-31d274af7d2d@chromium.org (and v1 via
  patchew); present in Linux 6.12.97 per lwn.net/Articles/1084924/
- Tree evidence: crates/irlume-camera/src/{ir_metadata.rs, lib.rs,
  capture_qualification.rs, ir_dark.rs}, crates/irlume-common/src/lib.rs,
  crates/irlume-cli/src/{machine.rs, main.rs},
  crates/irlume-daemon/src/main.rs, fuzz/, .github/workflows/ci.yml, all at
  main 613da5f9.
- Prior irlume research this builds on:
  docs/research/2026-08-27-camera-landscape-research.md (uncommitted), whose
  engineering implication 3 recommended exactly this standardization.
