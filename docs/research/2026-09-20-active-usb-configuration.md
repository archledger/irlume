# Active USB configuration scope (MS-02)

Date: September 20, 2026. Baseline: `1260206f`.

## Reproduced problem

Linux's USB `descriptors` attribute includes the device descriptor and every
configuration. The previous parser tracked the VideoControl interface number
but not the active configuration. An inactive configuration with the same
interface/unit numbers could supply a Microsoft XU, or an inactive duplicate
could hide the active one as ambiguous. The fd-derived identity also ignored
`bConfigurationValue`.

Five new regression checks failed before the correction: accepting an inactive
Microsoft unit, losing an active unit to an inactive duplicate, identical
fingerprints across active configurations, accepting missing/invalid active
configuration state, and accepting malformed trailing descriptor framing. The
single-configuration ASUS fixture and decimal-configuration positive control
passed before and after.

## Contract and implementation

Primary sources, pinned to Linux v7.2:

- [USB sysfs ABI](https://github.com/torvalds/linux/blob/v7.2/Documentation/ABI/stable/sysfs-bus-usb):
  `bConfigurationValue` names the active configuration. `descriptors` includes
  all configurations. Walk by individual `bLength`; `wTotalLength` can overstate
  the available data and must not be used to seek between configurations.
- [USB sysfs implementation](https://github.com/torvalds/linux/blob/v7.2/drivers/usb/core/sysfs.c#L24-L42):
  active-configuration attributes are read under the USB device lock;
  bConfigurationValue uses decimal `%u` output.
- [USB interface naming](https://github.com/torvalds/linux/blob/v7.2/drivers/usb/core/message.c#L2203-L2204):
  the kernel names an interface `<device>:<configuration>.<interface>` with
  decimal configuration/interface numbers. The bInterfaceNumber attribute is
  hexadecimal, so the representations are parsed separately.
- [V4L2 device lifetime](https://github.com/torvalds/linux/blob/v7.2/drivers/media/v4l2-core/v4l2-dev.c#L176-L199):
  the minor is freed for reuse only when the last user exits.
  [Unregistration](https://github.com/torvalds/linux/blob/v7.2/drivers/media/v4l2-core/v4l2-dev.c#L1122-L1135)
  clears the registered flag, and the
  [ioctl wrapper](https://github.com/torvalds/linux/blob/v7.2/drivers/media/v4l2-core/v4l2-dev.c#L359-L370)
  refuses an unregistered device.

The fd collector resolves its USB interface/device from the open character
device as before. It now requires a readable nonzero configuration value that
agrees with the resolved interface directory and bInterfaceNumber. Configuration
and interface are checked again after reading descriptor/identity data. Missing,
unconfigured, changed, mismatched or malformed observations fail closed.

The identity retains the **complete original descriptor blob** and the observed
active configuration. Unit selection uses a temporary view containing the device
prefix and only the active configuration's descriptors. Every byte in that view
is copied from the cached kernel blob. No fields are synthesized: the original
bNumConfigurations still describes the physical device, and the view is not a
replacement full USB descriptor file. Configuration values are identifiers, not
positional indices.

The selector rejects duplicate configuration values, missing active values,
incomplete descriptor framing, short configuration/interface headers, and an
inconsistent configuration count in the source blob. It does not infer missing
optional descriptors from wTotalLength. Unknown payload bytes are skipped by
their enclosing bLength, never scanned for familiar IDs.

The extension-unit parser accepts exactly one configuration view. A raw,
unscoped multi-configuration blob returns no units. It validates the complete
supplied framing rather than returning authority from a valid prefix before a
malformed tail. Existing GUID, selector-bit and unique-Microsoft-unit checks
remain part of admission.

## Persistence and compatibility

`CameraIdentity.descriptors` retains all descriptor bytes, including inactive
configurations. The identity also carries `active_configuration`.
`descriptor_fingerprint()` binds both facts. Emitter journals, stream records,
capture qualification and the raw diagnostic tool use that common digest.
The restore tests exercise both record validators against two configurations
on the same synthetic device/port.

For a single-configuration device, the observation is byte-for-byte identical
to the previous complete blob. Its descriptor digest, restoration filing key
and capture-qualification identity therefore remain stable. The real captured
ASUS fixture pins that compatibility.

For a multi-configuration device the digest is SHA-256 over the fixed bytes
`irlume-usb-configuration-v1\0`, followed by the one-byte configuration value and
the complete raw blob. A legacy unscoped whole-blob hash cannot authorize a
restore against this configuration-bound identity; neither can a record from
another configuration. Existing capture qualifications under the old identity
must be measured again. No new optional persisted field can be silently ignored
by an older reader. The digest's changed meaning for multi-configuration devices
is deliberate and documented.

An initial implementation hashed only the filtered view. A final-review
regression changed only an inactive configuration and demonstrated that this
would discard existing identity evidence. It was corrected before publication:
all raw bytes now contribute to the digest. The regression pins that adding
configuration scope never weakens the previous whole-device description.

The built-in literal emitter recipes contain no configuration selector. They
are therefore limited to single-configuration devices. A multi-configuration
device can use the existing explicitly discovered, currently validated
device-default path. The fix does not license applying a compiled payload to a
newly disambiguated configuration on the strength of VID:PID alone.

## Query and lifecycle checks

Every UVC extension query checks that its fd still resolves to an interface in
the active configuration, including raw diagnostic queries and restoration.
SET_CUR checks before logging/attempt bookkeeping and again at the final ioctl
boundary. Failure returns ESTALE and reaches no transport call. Existing
camera-operation leases remain required for writes. The override memo also
includes the configuration value.

The regression seam substitutes only the fd/sysfs observation before the
existing fake UVC transport. Tests change actual files in a synthetic sysfs tree
and prove that reads, forward writes and restoration cannot reach that transport
after a configuration mismatch. Another test moves configuration after the
outer SET precheck and verifies that the final ioctl check refuses it.

These are userspace observations and existing kernel lifetime guarantees, not
an atomic USB compare-and-swap. They do not prove resistance to a hostile kernel
or lying firmware. No physical reconfiguration, firmware write or camera-damage
scenario was exercised in this software-only change.

## Verification and remaining work

Tests cover both active/inactive orders, repeated unit IDs, inactive duplicate
GUIDs, decimal configuration identifiers, missing/invalid attributes, changes
during collection, malformed framing, opaque payload matches, deliberately
incorrect wTotalLength, persistent-record scope and single-configuration byte
compatibility. The UVC fuzz harness also checks arbitrary descriptor input and
a generated two-configuration selection oracle.

Physical multi-configuration hardware qualification remains outstanding. MS-05
(metadata format and buffer-size ownership/restoration) is the next separate
work package. This change does not identify the cause of any previously observed
NexiGo cold-start deadline; MS-03's queue-ownership work remains separate.
