# ADR-0032: Cross-device RGB+IR pairing by administrator pin

## Status

Proposed 2026-09-28. Based on the proposal in #938 by @maurerr, with
maintainer refinements to identity, selection, compatibility and activation.

Amends ADR-0029 sections 1 and 6 to add a separate pairing class and coherent
publication of its authorization and selection. `ConnectedPair` retains its
one-physical-camera invariant. Existing account selection, including the
implemented incomplete-legacy-binding `NotApplicable` behavior, remains in
force for ordinary pairs.

Depends on ADR-0007 (identity and capture qualification), ADR-0024 (complete
role-labelled credential bindings), ADR-0029 (selection), ADR-0030 (display
and redaction), and ADR-0031 (descriptor-based YUYV IR classification).
ADR-0031 section 4's YUYV exposure refusal remains in force.

This ADR defines the contract for later implementation PRs. Its acceptance
tests and activation gate must be satisfied before split-pair enrollment or
authentication becomes available.

## Context

The ThinkPad T480 in #887 has a Bison IR module, `5986:1141`, and a colour
module, `5986:2113`, on two USB devices. Its descriptor-attested IR role does
not make those devices an ordinary connected pair. ADR-0029 section 1 and
`connected::pair_camera` construct a `ConnectedPair` from one physical
camera with exactly one RGB and one IR capture node, classified at the
current generation. The lease currently refuses a request spanning physical
cameras with `SpansPhysicalCameras`.

An administrator needs a way to authorize that cross-device relationship
without changing the meaning of every existing pair. Such authorization is
distinct from enrolling a pair for an account, selecting it for a request,
or qualifying a capture schedule.

The pin must also distinguish locations. Binding identities can lack a
serial, and reported serials are not guaranteed unique. Node names and USB
bus numbers can change on re-enumeration. A PCI controller plus relative
ports is still incomplete: Linux xHCI creates USB2 and USB3 root hubs under
one PCI device and numbers each hub's ports independently.

## Decision

### 1. A separate class, built only from an administrator authorization

`SplitPair` represents two distinct physical USB cameras with one selected
capture endpoint per role. Each side retains its own binding identity,
qualified USB location, selected node path, built-in/external evidence,
instance ID and generation. Discovery alone never creates a split pair.
`ConnectedPair` and its ordinary construction rule are unchanged.

The daemon constructs split candidates from one complete, current passive
inventory publication. Descriptor, topology and role facts used for that
construction belong to the publication; the pairing operation does not open
cameras or infer new roles. A publication from another supervisor incarnation
or revision cannot be mixed into the candidate pool. Each side has its own
instance and generation; those values need not equal the other side's.

The internal pairing view may carry a separate split-pair collection. It is
empty without explicit authorization. Ordinary pairs retain their existing
construction and claim their physical devices first. Ordered split records
are then resolved without allowing a physical device to participate in two
published pairs. A record that overlaps an ordinary pair or an earlier
resolved split record is refused. Other independent valid records remain
usable.

An authorization selects endpoints already classified by the existing
rules. It cannot turn RGB into IR, classify an unknown endpoint, or make a
metadata node a capture endpoint. Missing USB evidence, missing roles or
multiple capture nodes of the requested role leave that side unresolved.
Existing descriptor requirements, including ADR-0031's YUYV attestation,
still apply.

### 2. Persistent location includes the root-hub domain

A split authorization records, for each side:

- the non-empty binding identity, in the existing `vid:pid[:serial]` form;
- the selected node path;
- a qualified USB location:
  `(controller identity, root-hub protocol domain, relative port chain)`.

The controller identity comes from the raw USB connection facts described
in ADR-0007, not a sanitized display label. The root domain distinguishes
independently numbered root hubs under that controller. For xHCI it must
distinguish the USB2 and SuperSpeed root-hub domains. The relative port chain
is interpreted within that domain. The implementation must derive these
facts from the controller/root-hub topology, not infer the domain from an
endpoint's negotiated speed alone.

If the available topology cannot identify the controller and root domain
unambiguously, the side is unresolved. The dynamically allocated USB bus
number, device address and `/dev/videoN` number are not part of the durable
location. The existing `<bus>-<port>` display string and the diagnostic
`SafeLabel` projection are not authorization keys.

Resolution requires the recorded identity and complete location to match,
and the recorded path to name the currently classified endpoint of the
requested role. A missing location component never acts as a wildcard.

| Change | Persistent location and credential key | Live resolution |
|---|---|---|
| USB bus number changes, controller/domain/ports unchanged | Unchanged | Revalidate current facts |
| Selected node is renumbered | Unchanged | Refuse until the administrator updates the recorded path |
| Controller, root domain or relative ports change | Different | Require a new pin; existing credential binding does not move |
| Either side reconnects with all recorded facts unchanged | Unchanged | Re-prove its new incarnation before capture |
| Controller or root domain is missing or ambiguous | No usable key | Refuse the split pair |

These rules match reported hardware facts. They do not prove that the same
physical unit returned. Replacement hardware presenting the same binding
identity, qualified location and selected path is indistinguishable with
these facts. Detecting that replacement needs a per-unit fact this design
does not provide.

### 3. Pairing authorization, selection and enrollment stay separate

The administrator's ordered collection authorizes which devices may form a
split pair. Collection order resolves overlapping authorizations; it is not
authentication preference order. Creating an authorization neither enrolls
the pair for an account nor silently changes the selected default.

For authentication, the split pair must additionally match the requesting
account's complete split-aware primary binding or an active secondary group.
In automatic mode, keep eligible primary first, then eligible secondary
pairs in canonical role-labelled pair-key order. Step 5 specifies the
extended key ordering while preserving the relative order of existing
ordinary-pair keys. Reordering non-overlapping authorization records does
not change this account-scoped ranking.

Pinned mode still selects one pair and does not fall back to another when
it is unavailable. A selected split pair refers to its complete pair key,
not its position in the authorization list. Environment overrides retain
their selection precedence, but do not themselves authorize a cross-device
relationship. Enrollment uses the operation's explicit choice and existing
approval path; choosing a split pair also requires a matching administrator
authorization. Apply `forbid_external_cameras` to both sides: either side
failing that policy makes the split pair ineligible.

The existing ordinary-pair and incomplete-legacy-binding behavior remains
unchanged. In particular, `NotApplicable` can retain the standing ordinary
pair as implemented today; that fallback never authorizes a split pair.
There is no movement to another pair after a biometric or PAD refusal and
no pooling of evidence between pairs (ADR-0024 section 5).

### 4. Whole-pair credential bindings and coherent configuration

The durable unit key combines binding identity with the complete qualified
location. A split credential binds the RGB unit key and then the IR unit key
in role order. Swapping roles changes the pair key; discovery order does not.
The encoding must distinguish the split class from legacy ordinary bindings
and represent both sides without ambiguity. Matching compares the whole
pair, never independently authorized halves from two enrollments.

A legacy identity-only `camera_binding` or secondary-group entry is not
silently interpreted as a split binding. A legacy four-key pin keeps its
existing meaning and does not create a split authorization by inferring
missing locations from whatever hardware is connected. Explicit enrollment
or adding a camera establishes a new split-aware account binding. Removing
or reordering machine authorization records does not rewrite enrollments or
reactivate an inactive secondary store.

The administrator changes the root-owned authorization records through a
daemon-validated privileged configuration operation. An update that both
authorizes and selects a split pair publishes one coherent old or new state
under the configuration lock, extending ADR-0029 section 6. A malformed or
unreadable authorization state, or an unresolved selected-pair reference,
refuses the split operation; it is not read as a fresh automatic setup.

Step 3 must specify the bounded, versioned collection encoding, selected-pair
reference, atomic publication and upgrade behavior. The ordinary four-key
pin remains compatible when split configuration is absent. New split
management requests fail visibly against an older daemon; the client never
downgrades them to the ordinary setter and reports success.

### 5. Sequential capture and two-incarnation revalidation

Initial split support uses the sequential capture schedule. The capture
layer enforces that choice. Acquiring both camera-instance leases reserves
the devices; it does not authorize concurrent streaming. A split pair cannot
inherit a concurrent qualification from an ordinary pair or either side
alone. Existing sensor-policy, per-operation eligibility, PAD and quality
requirements remain in force.

Both instance keys are acquired together in deterministic order and both
selected incarnations are revalidated against one live publication before
opening either side. Revalidate identity, qualified location, recorded path
and classified role. Failure releases both leases and opens neither side.
The opened descriptors and captured frames retain the existing anti-injection
and provenance checks, extended to represent the two authorized incarnations
rather than bypassing a single-camera check.

If either side changes or leaves during capture, the request cannot combine
old and new evidence or retarget to a replacement. The normal refusal and
password fallback apply. A reconnect with an unchanged persistent key still
requires fresh live proof. Runtime incarnation IDs are never persisted as
credential identity.

Future concurrent split support needs its own qualification design covering
the complete pair, both connection contexts and invalidation when either
incarnation changes.

### 6. Existing wire contracts stay closed

`CameraCandidate` and `CandidateWire` retain their role-free physical-group
contract. A candidate carries `instance_id`, `generation` and
`endpoint_paths`; its decoder rejects unknown fields. Split-pair role and
location information is exposed only through a separate opt-in request and
reply. Existing clients keep receiving their existing reply shapes.

For non-root peers, both sides use the existing daemon-instance endpoint
tokens. Neither real node path, binding identity nor serial is sent. Display
controller labels, root-domain labels and relative ports are share-safe
projections; the raw controller path and complete internal binding key are
not made public merely because the new reply is opt-in. Root may receive the
full pair facts under the existing posture rules.

The new request's authorization and effects must be explicit in the daemon's
posture tables. Redaction tests cover every reply or event carrying its data
and its error paths. A new client meeting an older daemon reports unsupported
split management rather than falling back to a less specific operation.

### 7. Pairing does not establish exposure or enable authentication

ADR-0031 section 4 remains unchanged: YUYV luma does not acquire a clipping
ceiling from a USB descriptor or an administrator's pairing decision.
`clipping_white_level(IrPixel::YuyvLuma, ...)` remains `None`.

That format-specific refusal is not the activation gate. A split pair with
native GREY IR can already have a clipping ceiling. All split enrollment and
authentication paths remain explicitly disabled until step 5's complete-pair
binding and request-path enforcement are implemented and tested. A successful
lease acquisition in step 4 cannot bypass this gate.

## Consequences

- A host such as the T480 can eventually use explicitly authorized separate
  RGB and IR devices, with a distinct binding class and live two-device proof.
- A pin authorizes a relationship; the account's enrollment and request policy
  still decide whether it may authenticate. Names, discovery adjacency and
  collection order do not supply that authority.
- Moving a side to a different qualified location changes its binding key.
  Renumbering a node requires updating its path but not re-enrolling when the
  complete persistent pair key remains the same.
- Non-USB nodes and USB nodes with incomplete or ambiguous controller/root
  topology cannot participate in this initial split-pair class.
- Ordinary connected pairs and their stored bindings retain their behavior.
  Overlap with one is a refused split authorization, not an implicit override.
- The T480 still needs the separate YUYV exposure work and attended validation
  before it is documented as supporting face authentication. This ADR alone
  is not that evidence.

## Rejected alternatives

- **Widen `ConnectedPair`.** That would make its one-camera identity and
  incarnation conditional in every existing consumer.
- **Use identity or the node name alone.** Identity can name several units,
  and node names can move between units.
- **Use a USB bus number as persistent location.** Bus numbers are allocated
  dynamically (ADR-0007).
- **Use only controller and relative ports.** xHCI's independently numbered
  USB2 and USB3 root hubs can share that tuple.
- **Infer a cross-device pair from proximity or missing pin fields.** Neither
  establishes the administrator's requested relationship.
- **Treat authorization-list order as account preference.** That would replace
  the existing primary-first, canonical-secondary selection contract.
- **Add roles to `CameraCandidate`.** Its existing closed decoder rejects them;
  new data belongs to the opt-in contract.
- **Use the YUYV refusal as the activation gate.** It does not cover native
  GREY or establish a complete credential binding.

## Acceptance tests

These cases gate the implementation phases:

1. No split authorization: ordinary pairing, selection and existing inventory
   wire shapes match the prior behavior for the same publication.
2. A pin cannot classify an unknown, metadata-only or wrong-role node. Missing
   USB evidence, two wanted-role nodes or a missing side refuse it.
3. Mixed supervisor incarnations or publication revisions refuse candidate
   construction. Different per-side instance IDs and generations are retained
   as two distinct device proofs, not mistaken for mixed publications.
4. Two same-identity units at equal relative ports in the USB2 and SuperSpeed
   root domains of one controller have different unit and pair keys. Equal
   relative ports under different controllers differ too.
5. Bus renumbering with unchanged controller/domain/ports preserves the key.
   Node renumbering still requires the recorded-path update. Missing or
   ambiguous controller/domain facts never match a wildcard.
6. Replugging either side invalidates live proof but preserves the credential
   key when all persistent facts match. Replacement hardware presenting every
   recorded fact remains indistinguishable, as the documented limitation.
7. RGB=A/IR=B and RGB=B/IR=A produce different pair keys. Reordering discovery
   does not change either key, and two authorized pairs cannot form a hybrid.
8. Ordinary pairs retain their device claims. Overlapping split records yield
   only the first resolvable pair; reordering independent records does not
   alter the account's primary-first and canonical-secondary ranking.
9. A split authorization alone does not satisfy enrollment binding. Legacy
   pins, incomplete bindings and `NotApplicable` fallback do not authorize it.
   Removing authorization does not move credentials or reactivate a store.
10. Pinned selection names one complete pair key. A missing selected record
    refuses; environment overrides cannot bypass authorization; forbidding
    external cameras rejects either external side.
11. Concurrent readers and crash recovery observe a coherent old or new
    configuration. Malformed state is a refusal, not automatic selection.
    Mixed-version management fails visibly without an old-setter fallback.
12. Both leases and revalidation precede the first open. Either side changing
    before or during capture refuses the attempt without mixing generations,
    pooling pairs or retaining one lease after a two-sided failure.
13. A valid ordinary concurrent qualification cannot enable concurrent split
    capture. Existing sensor-policy and quality checks still run.
14. Frozen old decoders accept existing replies from a daemon with split
    records. New non-root replies, events and errors expose no raw paths,
    binding identities, serials or internal controller paths.
15. Every split enrollment and authentication entry point is refused before
    step 5, including a native-GREY fixture. After activation, a mismatched
    complete binding still refuses before any grant.
16. Pairing never yields a YUYV clipping ceiling. T480 face-authentication
    support waits for separate exposure work and hardware acceptance.

## Phasing

1. Land this proposed ADR alone, with the ADR-0029 amendment pointers.
2. Add the separate data model, qualified-location facts and pure pin resolver;
   publish no usable split candidates yet. Test identity and ambiguity cases.
3. Add administrator configuration, selection references and the opt-in wire
   contract. Define and test serialization, upgrades, coherent publication and
   redaction. Configured candidates remain unavailable to enrollment/auth.
4. Add split-aware lease acquisition, revalidation and sequential capture
   provenance. Keep the explicit enrollment/authentication gate closed and
   prove that it holds for native GREY as well as YUYV.
5. Add complete split-aware primary/secondary bindings and request-path
   resolution. Validate legacy separation, account selection and all activation
   tests before enabling split enrollment or authentication.

The YUYV exposure change required by the T480 remains separate from these
phases. Neither accepting this ADR nor completing an intermediate phase
establishes supported face authentication on that hardware.

## Sources for USB location

- [ADR-0007](0007-context-bound-capture-qualification.md), durable identity and
  connection context.
- [Linux v6.8 xHCI PCI setup](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/host/xhci-pci.c#L568-L632),
  two root hubs under one PCI device.
- [Linux v6.8 root-hub port arrays](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/host/xhci-mem.c#L2139-L2164),
  [constructed independently](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/host/xhci-mem.c#L2276-L2277).
