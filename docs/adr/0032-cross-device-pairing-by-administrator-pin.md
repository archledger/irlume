# ADR-0032: Cross-device RGB+IR pairing by administrator pin

## Status

Proposed 2026-09-28. Based on the proposal in #938 by @maurerr, with
maintainer refinements to identity, selection, compatibility and activation.

Amends ADR-0029 sections 1 and 6 to add a separate pairing class and coherent
publication of its authorization and selection. `ConnectedPair` retains its
one-physical-camera invariant. Existing account selection, including the
implemented incomplete-legacy-binding `NotApplicable` behavior, remains in
force for ordinary pairs.

Amends ADR-0014's admission posture for split pairs: their paired evidence
always requires IR-identity-verified grant arms, regardless of measured skew.

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
In automatic mode, keep eligible primary first, regardless of pair class.
Eligible secondary pairs have this total order:

1. Ordinary pairs (class tag 0), ordered by their existing
   `(rgb identity, ir identity)` comparison.
2. Split pairs (class tag 1), ordered by `(RGB unit key, IR unit key)`. Compare
   each unit key's fields in this order: binding identity, controller identity,
   root-hub protocol domain, relative port chain. Compare canonical raw text
   fields bytewise and port chains lexicographically by numeric port number;
   a proper prefix sorts before the longer value.

The comparison uses typed fields, not concatenated display labels or node
paths. Equal complete pair keys retain the existing ambiguity refusal;
store position never breaks a tie. This preserves the relative order of
ordinary secondary pairs. Reordering discovery, stores or non-overlapping
authorization records does not change this account-scoped ranking.

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
daemon-validated privileged configuration operation. An operation that adds
or replaces an authorization, or selects a split pair, carries the expected
supervisor ID and publication revision from the displayed opt-in inventory,
plus both displayed instance IDs, generations and selected endpoints in role
order. Preserve this guard through confirmation and privilege approval.
Endpoint tokens and matching persistent facts alone are insufficient: a
replug can reuse the same path and token.

At the mutation boundary, the daemon requires a complete current publication
matching the expected supervisor, revision and both candidate guards, then
validates identities, locations and roles from that publication. Serialize
this check with inventory publication and configuration mutation so a change
cannot land between the check and commit. Any mismatch or unavailable
inventory refuses without changing authorization or selection and requires
a fresh listing and confirmation. Removing an authorization need not require
its cameras to be connected; removal never authorizes a replacement.

An update that both authorizes and selects a split pair publishes one
coherent old or new state
under the configuration lock, extending ADR-0029 section 6. A malformed or
unreadable authorization state, or an unresolved selected-pair reference,
refuses the split operation; it is not read as a fresh automatic setup.

Step 3 must specify the bounded, versioned collection encoding, selected-pair
reference, atomic publication and upgrade behavior. The ordinary four-key
pin remains compatible when split configuration is absent. New split
management requests fail visibly against an older daemon; the client never
downgrades them to the ordinary setter and reports success.

#### 4.1. Step 3 schema and publication

##### 4.1.1 Typed keys, canonical text and ordering

A **unit key** is `(binding identity, controller identity, root-hub
protocol domain, relative port chain)`. A **pair key** is a class tag plus,
for the split class, the RGB unit key followed by the IR unit key.
Ordinary pairs keep their existing key and sort first (class tag 0); split
pairs are class tag 1 (section 3).

Comparison uses typed fields, never concatenated text or
`SplitPair::binding_key()` (whose dotted port text is not numeric):

- identity and controller: bytewise on the canonical raw text;
- root-hub domain: bytewise on the canonical text in the table below, so
  text order and typed order always agree; never by enum declaration
  order;
- port chain: element by element as numbers; a proper prefix sorts before
  the longer chain.

| Domain | Canonical text | Order |
|---|---|---|
| SuperSpeed root hub | `superspeed` | 0 |
| USB2 root hub | `usb2` | 1 |

The order is exactly the bytewise order of the canonical text. In effect
it is an arbitrary-but-fixed choice: it exists only so equal fields
compare equal and ranking is deterministic, and it carries no
preference. A new domain value requires an ADR amendment, and its
canonical text must keep text order and typed order consistent; an
existing order position is never renumbered. The canonical domain text
names the root-hub protocol domain, never the dynamically numbered
sysfs `usbN` bus, and is distinct from `SplitPair::binding_key()`'s
NUL-joined encoding (which renders the domain `ss`); the two encodings
never meet, and typed equality is authoritative. The serialized
pair-key text as a whole is never sorted for ranking; only the typed
comparator is, and its field order is exactly the per-field orders
above, including the domain's canonical-text order.

**Canonical text of a split pair key** (used where a key must be stored;
the typed form is authoritative):

```
split1;<rgb unit>;<ir unit>
unit  = <identity>|<controller>|<domain>|<ports>
ports = <decimal>(.<decimal>)*          each 1..=255, no leading zeros
```

The observation-side parser accepts the wider `u8` form; the canonical
text is what the encoder writes, and a side whose observed chain is
empty or holds a `0` element has no canonical text, so the encoder
refuses that side rather than writing a non-canonical key. Fields are
percent-encoded: every byte outside `A-Z a-z 0-9 : . _ -` becomes `%XX`
with uppercase hex. This keeps `;` `|` `=` whitespace, control bytes and
any serial text unambiguous. This is its own encoding, not RFC 3986
percent-encoding (which reserves `:` and leaves `~` unescaped), so a
URL encoder or decoder must not be substituted for it. The encoding is
injective and the decoder rejects non-canonical input (lowercase hex
digits, unnecessary escapes, leading zeros), so each key has exactly
one text and text equality equals typed equality. Example:

```
split1;5986:2113:200901010001|0000:00:14.0|usb2|8;5986:1141:200901010001|0000:00:14.0|usb2|5
```

Node paths are not part of the key; they remain part of the
authorization record's live-resolution checks (section 2).

##### 4.1.2 Authorization generations

The ordered authorization collection is stored as **immutable generation
files** in `/etc/irlume/split-pairs/`, a root-owned directory (mode
0700) that holds only these generations and their writer temporaries:

- name: `<N>.conf`, `N` a decimal `u64` >= 1 without leading zeros; a
  name that does not match this grammar is not a generation: it is
  ignored by the `N` scan and never deleted by retention; each
  generation file is root-owned, mode 0600;
- a generation is never modified after publication; a change is a new
  generation with a larger `N`;
- contents: line-oriented `key=value`, same unsafe-value rules as
  `cameras.conf`; mandatory `version=1`; indexed records
  `pair.<i>.rgb_identity`, `.rgb_path`, `.rgb_controller`, `.rgb_domain`,
  `.rgb_ports` and the same with `ir_`; `<i>` contiguous from 0; record
  order is overlap-resolution priority (section 1) and is not an account
  preference (section 3);
- a record is well-formed only if every field is present and valid. A
  missing or unrecognized component is Malformed, never a wildcard
  (section 2);
- bounds, enforced by parser and writer: at most 16 records, 1024 bytes
  per line, 64 KiB per file, 6 port elements per chain (the chain bound is
  the USB limit of five cascaded hubs: a root port plus one element per
  hub). The chain bound is stricter than the existing diagnostics wire
  bound (`MAX_USB_PORT_DEPTH`, 8) and than the passive observation
  parser, both of which accept longer chains; no such chain can
  enumerate under the USB limit, so the diagnostics bound can be
  tightened later;
- unknown keys in a generation are Malformed (the file is immutable and
  versioned, so there is no forward-compat ignoring); an unknown `version`
  is Malformed.

The parser is pure and scans the whole file so every problem is reported.
States: **Absent** (no generation referenced), **Unreadable**,
**Malformed**, **DigestMismatch**, **Valid**.

##### 4.1.3 Publication protocol

Selection and the reference live in `cameras.conf` (ADR-0029 section 6,
as amended with this change). Authorization data lives in a generation.
Because camera-pin readers do not take the writer lock, a lock around two
independent file replacements would not give readers a coherent state.
The protocol instead makes `cameras.conf` the single atomic commit point
that names an already-durable, immutable generation.

Writer, holding `lock_exclusive` on `cameras.conf` to serialize writers:

1. Read and validate the current `cameras.conf`; refuse if it is
   unreadable or malformed. Compute `N = max(highest generation number
   in the generation directory, referenced generation) + 1` so a number
   is never reused, including after a crash; only canonical names count
   as generations for that scan.
2. Write the new generation to a temporary file in the same directory
   (0600), fsync the file, rename it to `<N>.conf`, fsync the
   directory: the same temp-file, fsync, rename and directory-fsync
   discipline the existing atomic writers use. Writer temporaries carry
   a leading dot and a `.tmp.` marker (`.{name}.tmp.{pid}.{seq}`), so
   the sweep can tell them from generation names and from foreign
   files, which it never deletes.
3. Compute `sha256` over the exact bytes of the generation file.
4. Publish `cameras.conf` in one atomic rename containing the existing
   five keys unchanged plus `split_generation` and `split_digest`, and
   `split_pair` when a pair is selected, then fsync the directory.
5. Best-effort retention (4.1.5).

Reader (any process):

1. Read `cameras.conf` once; the rename guarantees a whole file.
2. If no split key is present at all: split selection is Absent;
   valid ordinary behavior is exactly as before this ADR. Invalid ordinary
   selection refuses under the 2026-10-04 coherent-reader amendment below.
3. Otherwise open exactly generation `split_generation`, verify its
   digest equals `split_digest`, then parse it. A missing file, digest
   mismatch or malformed file refuses the split operation. A present
   `split_pair` must resolve inside that generation or the operation
   refuses; it never falls back to the ordinary pin or another pair,
   and never reads as a fresh automatic setup. A referenced generation
   with no `split_pair` is Valid with no split selection: authorizations
   are live, nothing is selected, and the ordinary pin keeps its
   existing meaning.
4. If the open fails because the file is missing, re-read `cameras.conf`
   once; if the referenced generation changed, retry with the new one
   (bounded to one retry), otherwise refuse.

Crash analysis:

| Crash point | On-disk result | Effect |
|---|---|---|
| before step 2 completes | possibly a temp file | none; cleaned on next write |
| after step 2, before step 4 | unreferenced generation `N` | none visible; collected by retention; `N` is never reused |
| during step 4 | rename is atomic: old or new `cameras.conf` | old or new coherent state |
| after step 4, before step 5 | extra old generations | none; collected later |

##### 4.1.4 Removal and the selected pair

Removing an authorization publishes a new generation without it, and does
not need the cameras to be connected (section 4). If the removed record
is the selected pair, the same `cameras.conf` publication drops
`split_pair` only, so selection never references a pair the generation no
longer holds while the remaining records stay reachable; in `pinned`
mode the ordinary four-key pin applies again. Removing the last record
drops the split keys entirely. Removal never authorizes a replacement.

##### 4.1.5 Retention

After a successful publication, keep exactly two generations: the one
the new `cameras.conf` references, and its **immediate predecessor**,
defined as the generation the `cameras.conf` the writer read in step 1
referenced, which is what the previous publication pointed at. That is
what lets a reader holding the previous `cameras.conf` still open its
generation. Every other generation file is deleted, including
unreferenced orphans with numbers above the predecessor (such as a
generation written before a crash interrupted publication). The
referenced generation is never deleted.

Generation cleanup runs only in the writer, at publication time,
because only there is the predecessor known: it comes from the
`cameras.conf` read in step 1, not from the directory contents, and a
restart that finds several generations cannot tell an orphan from the
predecessor. Failure to delete is harmless and is retried at the next
publication. Every deletion runs under the `cameras.conf` writer lock.
At daemon start, a sweep under that lock deletes leftover writer
temporary files and unreferenced generations numbered above the
referenced one, which cannot be the predecessor; generations below the
reference wait for the next publication.

Edges: on the first split publication only the referenced generation is
kept, nothing having been de-referenced; after a publication that
removed the split keys, the just de-referenced generation counts as the
predecessor and is kept. Either way a reader holding the previous
`cameras.conf` can still open its generation.

##### 4.1.6 Upgrade, downgrade and visible failure

- Without split keys, every reader and writer behaves exactly as today,
  and the ordinary four-key pin keeps its meaning.
- An older daemon reads only the four pin keys and reports the new keys
  as ignored lines with the usual startup warnings. Because split
  enrollment and authentication stay refused until Step 5, an older
  daemon ignoring split selection cannot authenticate with it.
- New split management uses new request and reply types. An older daemon
  fails them visibly; a new client reports "unsupported" and never falls
  back to `SetCameras` or `SetCamerasIfCurrent`. The digest uses `sha256`,
  already a dependency of the crate that hosts config parsing, so no new
  dependency is involved.
- Because `mode` is parsed but reserved on current main (automatic
  selection has no production caller yet), Step 3 defines and tests the
  persisted and status contract only, and does not assume automatic
  selection is integrated.

##### 4.1.7 Status and redaction

A root-only status reports the state (Absent / Unreadable / Malformed /
DigestMismatch / Valid), record count, referenced generation and whether
the selection resolves. Non-root peers receive no identities, serials,
paths or raw controller paths, only the share-safe projections of
section 6.

##### 4.1.8 Additional tests required for Step 3

- Concurrent reader while a writer publishes: always a whole old or
  whole new state, never a mix.
- Crash injection after each writer step in 4.1.3, including leftover
  temp files and orphan generations; `N` never reused.
- Digest mismatch, missing generation, malformed generation, a missing
  half of the generation pair, `split_pair` without the pair, and an
  unresolved `split_pair` each refuse with no fallback. A referenced
  generation with no `split_pair` is Valid and selects nothing.
- Removing the selected record drops only `split_pair`; removing the
  last record drops all split keys; both keep the ordinary pin
  coherent.
- Retention never deletes the referenced generation and keeps the
  predecessor.
- Canonical key round-trip, rejection of non-canonical text, numeric
  port ordering (8 before 10), proper-prefix ordering, and domain
  ordering pinned to the table.
- The ordinary four-key pin and `cameras.conf` without split keys are
  unchanged.
- The activation gate stays closed for enrollment and authentication,
  including a native-GREY fixture.

### 5. Sequential capture and two-incarnation revalidation

Initial split support uses the sequential capture schedule. The capture
layer enforces that choice. Acquiring both camera-instance leases reserves
the devices; it does not authorize concurrent streaming. A split pair cannot
inherit a concurrent qualification from an ordinary pair or either side
alone. Existing sensor-policy, per-operation eligibility, PAD and quality
requirements remain in force.

Every paired split assessment must carry sequential admission posture
(`sequential_pair`), including captures at or below
`MAX_CROSS_SPECTRUM_SKEW`. The current skew-only
`pair_admitted_sequentially` rule is insufficient for this class: a short
gap does not make two physical devices a concurrent pair. Propagate the
split provenance into assessment and grant decisions, including retries;
never infer this posture from elapsed time alone. As in ADR-0014, both the
RGB-primary and fusion grant arms are unavailable on this paired evidence.
Only the IR-identity-verified fallback and calibrated-centroid arms may grant,
with all their existing thresholds and gates. Pairing budgets and stale-RGB
discard behavior remain unchanged; an IR-only decision retains its existing
IR identity requirements.

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
The opt-in listing includes the publication and per-side guards required by
section 4; management echoes those displayed guards without refreshing them
silently after confirmation.

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
   With an unavailable primary and mixed secondary classes, an eligible
   ordinary pair precedes every split pair, even one with a smaller identity.
   A split primary still precedes ordinary secondaries. Split secondaries
   follow the field comparison in section 3 under input permutations;
   duplicate complete keys refuse as ambiguous rather than using store order.
9. A split authorization alone does not satisfy enrollment binding. Legacy
   pins, incomplete bindings and `NotApplicable` fallback do not authorize it.
   Removing authorization does not move credentials or reactivate a store.
   With a missing or one-sided primary and no chosen complete secondary,
   `NotApplicable` retains the standing ordinary pair under its existing
   authentication checks; it neither refuses selection solely for the
   incomplete binding nor admits a standing split pair.
10. Pinned selection names one complete pair key. A missing selected record
    refuses; environment overrides cannot bypass authorization; forbidding
    external cameras rejects either external side.
11. Concurrent readers and crash recovery observe a coherent old or new
    configuration. Malformed state is a refusal, not automatic selection.
    Mixed-version management fails visibly without an old-setter fallback.
    Replug either side between listing, confirmation and commit, including
    reuse of the same identity, location, path and endpoint token: the stale
    instance/generation guard refuses with no configuration change. A changed
    supervisor or revision, mixed displayed publications and unavailable
    inventory also refuse. Race publication against the commit to verify the
    check and mutation boundary. An unchanged guarded publication succeeds.
12. Both leases and revalidation precede the first open. Either side changing
    before or during capture refuses the attempt without mixing generations,
    pooling pairs or retaining one lease after a two-sided failure.
13. A valid ordinary concurrent qualification cannot enable concurrent split
    capture. Existing sensor-policy and quality checks still run.
    At skew below, equal to and above 3 s within the sequential budget,
    paired split evidence retains sequential admission posture. A high RGB
    match with IR below identity thresholds cannot grant through RGB-primary
    or fusion; retry paths retain this restriction. Ordinary-pair behavior
    and stale-evidence handling remain unchanged.
14. Frozen old decoders accept existing replies from a daemon with split
    records. New non-root replies, events and errors expose no raw paths,
    binding identities, serials or internal controller paths.
15. Every split enrollment and authentication entry point is refused before
    step 5, including a native-GREY fixture. After activation, a mismatched
    complete binding still refuses before any grant.
16. Pairing never yields a YUYV clipping ceiling. T480 face-authentication
    support waits for separate exposure work and hardware acceptance.

## Phasing

1. Land this proposed ADR alone, with ADR-0014 and ADR-0029 amendment pointers.
2. Add the separate data model, qualified-location facts and pure pin resolver;
   publish no usable split candidates yet. Test identity and ambiguity cases.
3. Add administrator configuration, selection references and the opt-in wire
   contract. Define and test serialization, upgrades, displayed-inventory
   guards, coherent publication and redaction, per the schema and
   publication protocol in §4.1. Configured candidates remain
   unavailable to enrollment/auth.
4. Add split-aware lease acquisition, revalidation and sequential capture
   provenance and unconditional split sequential admission posture. Keep the
   explicit enrollment/authentication gate closed and prove that it holds
   for native GREY as well as YUYV.
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

## Amendment 2026-10-04: Step 5 ownership and account-binding contract

Step 5 owns publication of resolved split pairs into the internal connected
view. Camera code is the only producer: the daemon supplies a coherently read
authorization generation, and `connected_pairs_with_split` resolves its records
from one current inventory publication under one lock. It reads no configuration
file, opens no camera and does not initialize a missing supervisor. Ordinary
pairs retain their separate collection and device claims; indexed refusals
retain the cause of each unresolved split record. Step 3 continues to own
authorization-file publication and management, not usable account candidates.

The public `ConnectedPairs` construction contract retains its original six
fields. The richer result is a separate `ResolvedConnectedPairs` wrapper,
containing the ordinary view plus split pairs and indexed refusals. Existing
ordinary callers do not acquire required fields or a new return type.

Primary and secondary account bindings use one semantic ordinary/split type.
An ordinary value keeps the historical object containing optional `rgb` and
`ir` identities. Ordinary primary parsing and serialization preserve empty
and long strings accepted by the old representation; secondary-store limits
still apply at the secondary validation boundary. A complete ordinary key
requires both nonempty identities. No partial ordinary value authorizes split.

A split binding is the canonical section 4.1.1 text encoded as a JSON string
at the binding value. It contains the whole RGB unit key followed by the IR
unit key, with no node path, instance ID or generation. Frozen old primary
and secondary struct readers reject that string in plaintext and decrypted
envelopes. An old secondary reader rejects its whole split-containing store,
including ordinary groups beside the split record. There is no read-time
conversion from legacy identities to split locations, and a newer writer
does not rewrite ordinary values into tagged objects.

The existing ordinary addition operation retains its encoding. A split
addition has a distinct operation variant carrying the canonical whole key;
it cannot be flattened into the ordinary identity fields. Confirmation,
credential-management approval and publication validate the same exact
account, group and role-labelled binding. Opaque group-ID stems and reply
identity projections are display/handle data, never split authority.

Core owns the pure account ranking policy. The ordinary adapter and typed
mixed-class selector share one ranker, including existing skip precedence,
ambiguity reporting and lazy eligibility. A split primary remains a complete
binding when unavailable; it cannot become legacy `NotApplicable`. Malformed
split primaries refuse. The external policy requires both sides to be fixed
when external cameras are forbidden. Selection supplies no machine
authorization or live camera proof.

The secondary coordinator retains the exact binding privately alongside
the existing generation, primary digest and group-ID metadata. Its bound
grant check repeats those checks against current files and also requires
whole-binding equality, including when a pair changes without a generation
bump. A metadata-only compatibility check cannot admit a split group.
Complete-key pinning borrows the requesting account's already loaded key
and primary snapshot; it does not add a second unseal. Ordinary optional-side
matching and exact ordinary pinning remain separate supported behaviors.

Existing inventory and enrollment replies retain their wire shapes. Private
daemon caches retain binding class so loaded and cached summaries cannot
reinterpret split identities as ordinary. Identity-only presence never proves
a split connection; typed whole-pair observations are required. Accountless
and single-endpoint diagnostics do not grant, and do not derive a split
matching target by dropping its location or other side.

These foundations are an intermediate Step 5 slice. Engine request preparation
must still consume the selected whole pair before any preflight or open,
preserve its authority and provenance through the attempt, and enforce the
behavioral native-GREY entry-point matrix. The split acquisition activation
gate stays closed. Enabling enrollment/authentication remains a separate
reviewed source change after the complete software and physical acceptance
matrix. Section 7's YUYV exposure refusal and the T480 hardware gate remain
unchanged.

## Amendment 2026-10-04: coherent selection reads and refusal precedence

Request preparation consumes ordinary mode, ordinary pin and verified split
authorization from one strict `cameras.conf` observation. The combined
`CameraSelectionSnapshot` retains that observation with its `SplitReadState`;
reading mode or pin separately can mix publications. This snapshot establishes
configuration facts only; camera code must still resolve a whole pair from a
current inventory publication and the request must retain live authority.

When a referenced generation is missing, the reader observes `cameras.conf`
once more. It returns the final observation with that observation's split
verification or refusal. It reads a moved generation or digest once more,
with no further retry. An unchanged missing generation/digest refuses without
another generation read, including when the selected pair text becomes
malformed. A final removal of the split reference uses the final ordinary
selection and Absent state together. A valid generation cannot repair a
malformed ordinary selection; an unreadable final configuration remains
Unreadable. Existing malformed-pair generation/count diagnostics remain
available when the referenced generation can be verified.

Unreadable or malformed camera selection, an invalid referenced generation,
and an unresolved selected split must refuse camera-backed requests even
with a proven ordinary environment override. A valid explicit ordinary
override keeps precedence over valid configured choices. Refusal preserves
password fallback. This decision changes no parser grammar: `mode=pinned`
still requires complete ordinary RGB/IR paths.

The combined reader and its retry regressions do not complete Engine/daemon
request enforcement. Step 5 must enforce this policy before preflight, probe
or open and before adding trust or preparing a face-backed secret. Split
activation stays closed until its software and physical acceptance passes.

## Amendment 2026-10-04: request configuration gate

The first runtime gate rejects invalid or unreadable selection and failed
generation, digest or selected-key verification before considering an ordinary
environment override. A valid selected split remains refused at the closed
activation boundary unless the override proves a unique classified ordinary
pair in one healthy Current publication. The existing combined external-camera
policy includes both the configured prohibition and the legacy fixed-device
gate. Paths or independently observed identities cannot prove ordinary class.

`CameraRequestScope` retains that configuration observation and passive view
across daemon enrollment probes and nested Engine entries. It clears request
state and restores standing endpoints and IR availability on return or unwind.
Nested entries refuse endpoint/availability mutation and drift of a retained
ordinary pair's supervisor, instance, generation or pair facts. They do not
reread selection or rerank in the middle of the request. Passive revalidation
is an observation at the entry boundary; it neither reserves a device nor
replaces lease/open continuity checks.

Daemon enrollment and guided sessions prepare after authorization/account
ownership and before session-start events, summary invalidation, probe or
preflight. Direct Engine enrollment, addition, authentication, assessment and
positioning entries also gate. Identify and positioning explicitly refuse
selected split configuration rather than projecting it to an ordinary path.
Authentication and face-backed password release retain their existing consent,
retry admission and account-lock ordering. IR readiness and optional evaluation
also reject invalid or selected split configuration without authorizing capture.

Behavioral tests use a current-thread, non-granting camera fixture that records
real lease/open attempts. Its backend always refuses opens and constructs no fd
or camera handle. Native GREY fixture evidence exercises the real format-role
classifier and decoder on synthetic bytes; it is not negotiation or physical
acceptance. Ordinary controls reach preflight and lease/open boundaries, and
refused requests retain primary/envelope bytes and emit no session-start event.

This gate unit does not complete account routing. The encrypted dual loader
still overlaps camera opens, automatic account selection is not wired into the
Engine, and IR-only target resolution still uses its existing configured-pair
reader. Exact primary snapshot/key adoption, secondary selection/pin coherence
and chosen-pair IR targets remain the next Step 5 delivery. Split activation
and physical acceptance remain separate gates.

## Amendment 2026-10-04: pre-open primary snapshot

Dual authentication now resolves `PrimarySnapshot` before its first camera
lease or open, using the same owned-receiver loader lifecycle as IR-only. It
retains the exact bytes parsed, including ciphertext for protected enrollment,
and moves the load's key once into `RequestTemplateKey`. Secondary reads and
grant checks borrow that allocation. Timeout/cancellation retains receiver
ownership until load/lock work drains; this is cooperative cleanup, not a hard
interruption of TPM work. The no-store instant denial remains before a loader
starts or its timing/lock work is recorded. Windows and PAD budgets are unchanged.

`pin_with_primary_snapshot` reads only the secondary, verifies the requesting
owner, and checks activation against the supplied primary bytes. Complete bindings use the strict
class-aware key pin; incomplete ordinary live bindings retain legacy ordinary
partial matching. The primary path is retained for later boundary checks, not
opened or decrypted again during pinning. Later missing or changed primary
bytes still refuse a secondary grant. Real-primary retired-eye policy precedes
the secondary bridge's default fields, and a stored split primary refuses before
ordinary acquisition while activation is closed.

The retained ordinary request proof is revalidated after protected load and
again before acquisition, including any secondary resolution wait. IR-only
also revalidates before its lease. These passive checks do not replace existing
lease/open continuity checks or establish atomic selection/acquisition.

This removes the dual loader/open overlap described in the earlier request-gate
amendment. Automatic account ranking, expected selected-pair lease requests,
secondary selection/pin snapshot coherence, chosen-pair IR targets, and daemon
chosen-tier/window/standing-pair semantics remain the next delivery. Neither
this prerequisite nor its synthetic tests enable split capture or satisfy
physical acceptance.

## Amendment 2026-10-04: automatic account routing

Fresh or Automatic selection without an explicit ordinary environment pair
uses `select_bound_for_account` before acquiring cameras. The Engine builds
complete ordinary/split candidates from its retained Current view and checks
template eligibility in each account-scoped enrollment. Primary precedence,
secondary ordering, ambiguity, activation and external-camera policy remain
the selector's decisions. `NotApplicable` retains the incomplete ordinary
primary path. A chosen split or split primary refuses while activation is
closed; biometric refusal never reranks to another camera.

The primary load supplies the exact parsed bytes and one request-owned key.
The Engine loads the secondary through that borrowed key, selects a group,
and calls `pin_key_from_loaded` with that same secondary snapshot. Authorized
authentication may resolve a pending commit first. Readiness uses read-only
primary loading and non-recovering secondary resolution, including the legacy
configured-target path. It leaves stores, journals and standing endpoints
unchanged. No-candidate IR requests retain the configured-target guard and its
refusal cause before protected loading.

`OrdinaryLeaseRequest` retains the chosen supervisor and complete runtime pair.
Acquisition checks them under one inventory lock, retains the resulting lease
reference across contention, and revalidates before returning. The Engine also
rechecks retained account-store authority after admission and lease contention,
immediately before opening cameras. Camera continuity and account authority
remain separate checks. IR routing uses `ir_target_for_pair` for a chosen pair,
retaining the existing topology, metadata, emitter and privacy checks.

The preparation-admission callback receives the selected Engine and final
window before camera work. The daemon checks chosen-tier policy and binds any
shared unlock there, after reserving `FaceAttempt`. Preparation refusal, errors
and cancellation retain that charge. Static, pinned, forced-convenience and
no-candidate guards keep their early ordering. The advisory only defers standing
tier when Current candidates exist; it grants no selection authority.

Selection can shorten the original window but cannot widen it or restart its
clock, including an explicit grace override. Zero keeps one-shot semantics,
and a finite cap cannot become unbounded. Capture, reply admission and
`FaceCompletion` retain the same final window. Outer cleanup clears selection,
primary/secondary pins and request-key authority on return or unwind; an
automatic standing endpoint choice may remain as specified by ADR-0029.

Regression tests cover primary/secondary preparation, store drift after
admission and during a registered lease wait, capped-window/override/zero
behavior, unwind cleanup, read-only journal refusal with a recovery control,
and actual daemon tier/charge ordering. Synthetic backends refuse all opens.
These tests establish software boundaries, not successful physical capture or
split acceptance. Split activation remains closed.
