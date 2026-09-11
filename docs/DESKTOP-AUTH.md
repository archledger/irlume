# On-demand desktop face authentication

Irlume's desktop direction is on-demand consent through stock authentication
interfaces. Select a face attempt explicitly; ordinary password authentication
remains available. Experimental automatic desktop integration has been retired.
Contributors may propose future frontend support, but it is not an active
Irlume implementation target or a promised upstream feature.

## Existing desktop flow

The current on-demand PAM path waits for input. A successfully returned empty
password response selects one face attempt. A nonempty password proceeds to the
password provider. Cancelling the initial conversation, EOF, or a missing token
returns without contacting the daemon. The consumed empty face-selection token
is cleared so a refusal or timeout can reach a fresh password prompt.

Existing greeter compatibility remains supported: the established `facefirst`,
`ondemand`, and legacy `wait` arguments are retained where existing deployments
use them. The standard on-demand desktop setup does not use `wait`. This cleanup
does not migrate existing PAM files or change credential-release behavior.

The separate `irlume auth consent` setting controls typed confirmation for
privileged sudo/polkit requests. Its existing owner opt-in is retained and does
not enable automatic desktop scanning.

The separate experimental sensor policy is also machine-wide and owner-selected.
Absent configuration remains dual RGB+IR; root must use
`irlume auth sensor ir-only --yes` to write
`face_sensor_policy=ir-only-experimental`, and `irlume auth sensor dual` restores
the default. It is independent of PAM `Method`, sequential/concurrent capture
scheduling, and privileged confirmation. IR-only attempts use the configured,
enrollment-bound IR target with mandatory IR PAD and compatible enrollment; they
never probe or silently fall back to RGB. The mode remains experimental; source
availability is not authentication qualification.

`irlume auth sensor preflight [user]` is camera-free. A ready result means only
that prerequisites were observed. It does not establish capture timing, a usable
login, or qualification. Missing prerequisites, old/unexpected daemon responses,
and unknown readiness values fail to the password path.

## Bounded attempts and cleanup

One monotonic authentication window covers engine setup, presence retries and
final daemon response admission. The normal defaults are unchanged: 15 seconds
for login, lock, and unknown services; 5 seconds for short privileged services
including sudo, doas, and polkit. These are maximum admission windows, not
required scan durations. A completed denial or a retry that cannot fit may finish
earlier. `IRLUME_GRACE_MS` remains the explicit 0–60000 ms override; zero retains
legacy single-attempt behavior. A measured
fixed-startup empty-view IR capture on one Minihost took about 5.5 seconds before
identity work, so prerequisite-ready does not imply the five-second services can
complete. The target-bound IR route now uses adaptive startup while retaining the
full 30-interval rate window, rate floor and continuity checks. Healthy startup
can avoid the fixed ten-dequeue exclusion; a slow stream can use up to ten extra
dequeues before the ordinary delivery gate accepts or refuses it. IR-only opt-in
does not extend a service window. The historical fixed-startup measurement above
does not predict the duration of a current attempt.

Matches and prepared credentials observed after expiry are discarded. Capture
checks expiry before and after returned driver calls and at inference
boundaries. Expiry does not trigger camera recovery, hardware demotion or
another scan. Camera and emitter owners perform their normal cleanup.
Disconnect cancellation and these deadline protections are shared with
on-demand requests and remain in place.

A driver, inference, TPM operation or enrollment-loader cleanup already in
progress can return later. These windows are not hard physical camera-off
guarantees. PAM bounds the complete response-reading phase to 25 seconds,
including partial reads. Connection/send time precedes that read budget; daemon
queue waiting after the send consumes it. Queue waiting precedes the separate
engine authentication window.
The legacy PAM `wait` loop is outside this bounded on-demand contract.

The daemon durably reserves one unsuccessful request before engine work; a
reservation write failure prevents the attempt. A grant is admitted immediately
before the first response byte, then the complete response is written and flushed.
Only after that delivery succeeds does the daemon durably reset the face budget.
If reset persistence reports failure, the already delivered grant cannot be
retracted and the reset is unconfirmed. The charge may remain and block the next
face request. If the reset rename became visible but was not confirmed durable, a
later successful authoritative read may sync and recognize that visible reset. A
partial or failed response delivery retains the charge and never attempts reset.

## Frontend boundary

Irlume does not supply the experimental native desktop scanning integration,
an automatic desktop toggle, a custom KDE fork, or a background unlock
controller. Legacy `facefirst` still scans immediately in existing compatibility
deployments; it is preserved rather than expanded by this decision. The
experimental `kde-face` service classification and its native integration plan
have been removed. Unknown services retain the existing restrictive policy;
the supported `kde` service remains a screen unlock.

Esc-to-cancel and typing-to-switch during an active face request are not
shortcuts implemented by Irlume. A stock frontend owns its password UI and PAM
worker lifecycle; cancellation of a queued PAM conversation does not itself
interrupt a synchronous daemon request or invalidate a queued success.
Supported frontend lifecycle integration would need separate contributor and
upstream work. No integration is enabled based solely on a service name.

## Validation scope

Controlled tests cover expiry before capture, late grants, capture and inference
boundaries, retry accounting, partial socket replies, and fresh password fallback
through a real userspace PAM stack. They do not establish a universal hardware
release time. Physical camera-descriptor release measurements must be reported
with the actual test window and sampling limits; descriptor closure and logged
emitter restoration do not independently prove optical darkness.
