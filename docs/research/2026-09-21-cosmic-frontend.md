# COSMIC frontend qualification, 2026-09-21

The explicit-yes PAM correction passed live prompt and password-fallback checks
on Fedora 44 with COSMIC **1.8.0-1.fc44**. This qualifies frontend initiation and
fallback only. A denial-only RPC fixture returned no biometric grant and no
credential; no camera, enrollment or real face match was involved.

## Environment and method

The disposable KVM guest booted the official Fedora COSMIC Live 44-1.7 x86_64
image, SHA-256
`86ed49a1f0c32ab3e19846b692b0a1b35fa827154069f32b1ec0e08d42bb20e6`.
The checksum's Fedora 44 signature and the image digest were verified before boot.
The image initially contained COSMIC 1.0.9. Its empty-submit behavior differs
from 1.8.0, so initial image trials are not counted as the R6 reproduction.

The guest then received 21 Fedora-signed COSMIC 1.8.0 packages from the official
Fedora 44 repositories, after a complete dependency preflight. The host received
no package installation. Final components included:

- cosmic-greeter, cosmic-session and cosmic-comp: `1.8.0-1.fc44`
- greetd: `0.10.3-6.fc44`
- Linux-PAM: `1.7.2-1.fc44`
- systemd: `259.5-1.fc44`

The guest had four virtual CPUs, 8 GiB RAM, no network adapter and no USB/camera
passthrough. QMP input drove the real greeter and locker. Guest-only serial
administration used a debug shell; the live image's firstboot wizard was masked
for that boot after it blocked serial setup. Neither changed the tested PAM
authentication rules. Screenshots were 1280×800.

The real built `pam_irlume.so` ran above the stock password stack for an ephemeral
account with a nonempty password. A root-owned Unix listener at Irlume's actual
`/run/irlume.sock` returned `UnsealUnavailable`, then refused `Authenticate`.
It recorded only request kind and kernel peer PID/UID/GID. Wrong-password controls
failed, while the correct password authenticated through the stock provider.

SELinux stayed **Enforcing**. The initial cold-greeter trial exposed the expected
socket denial while the test guest lacked Irlume's policy. Loading the unchanged
`packaging/selinux` module and recreating the fixture socket gave it the normal
`irlume_runtime_t` label. The confined `xdm_t` greeter could then reach the fixture
through the shipped rule. No permissive mode or generated allow rule was used.

## Results

| Surface / action | Observation |
| --- | --- |
| Baseline 1.8.0 greeter and locker: empty Enter | No RPC request; face selection could not begin |
| Baseline cold login: typed password | Wrong password refused; correct password reached the desktop, without RPC |
| Baseline locker: correct password | Desktop unlocked without RPC |
| Corrected greeter and locker: initial prompt | `Password or yes for face:` visible in full, with hidden input |
| Corrected: empty Enter | No new RPC request |
| Corrected: `yes` | `UnsealPassword` followed by `Authenticate`; caller UID 0 at cold login, UID 1000 at the locker |
| Fixture refuses face | Fresh `Password:` prompt, with the selection consumed |
| Wrong fallback password | Authentication refused; a new attempt remained available |
| Correct fallback password | Desktop reached/unlocked; no additional face request |
| Direct password on the corrected locker | Desktop unlocked without a face request |

The first candidate's longer prompt clipped before the word “face.” The final
shorter prompt above was rechecked in both real interfaces. Its native PAM binary
SHA-256 was
`35c6fdecf692d354c6608a8612c6efc2ae5bccee11cea30eec8d6b75ff88aa13`.
An atomic file replacement alone left an existing frontend using the old prompt;
final checks used fresh frontend processes and confirmed the displayed text.

## Two compatibility findings

**Vendor-only PAM layout.** Fedora's `cosmic-greeter-1.8.0-1.fc44` ships
`/usr/lib/pam.d/cosmic-greeter`, with no `/etc` copy on a fresh package layout.
The old COSMIC table entry had no vendor fallback and skipped that surface. The
correction adds the existing materialize-override path. A regression using the
exact vendor file first failed, then verified enable, idempotent enable, removal
of only the generated override, and unchanged vendor bytes.

**RGB-only session binding.** The actual locker ran under
`user@1000.service/app.slice/cosmic-greeter.scope`. `GetSessionByPID` returned no
session for that live process, although the same account had an active local
Wayland session on seat0. The current daemon binding therefore refuses that
RGB-only request shape. No account-wide session fallback was added. This needs a
separate qualified frontend-purpose contract; the input correction does not solve it.

## Limits and cleanup

These tests did not measure face-recognition accuracy, spoof resistance, genuine
face grants, physical camera behavior, or user-credential release. They also do
not establish automatic cancellation of synchronous PAM work through Esc or typing.
The denial fixture is not evidence of a successful real-daemon biometric attempt.

The guest was powered off normally. Its temporary PAM override, password, RPC
fixture and policy installation existed only in the disposable live overlay.
Host desktop, PAM, Irlume services, enrollment, cameras and existing VMs were
untouched. The temporary guest password is excluded from retained evidence.
