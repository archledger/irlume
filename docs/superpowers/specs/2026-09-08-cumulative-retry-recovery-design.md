# Cumulative face-attempt limits and verified recovery

Status: proposed design, ready for review; not implemented or enabled.
Agent: codex. Date: 2026-09-08.
Source baseline: `feat/privileged-consent-controls` at
`fe7339c18bf44a08bc1736b1300c7c04cf9d91fb`, including the existing local
consented-authentication and fusion-documentation changes.

## Objective and recommendation

Bound unsuccessful face-authentication attempts across cooldowns and daemon
restarts while keeping ordinary password authentication available. Restore face
access through an explicit, independently verified password operation. Keep the
consented on-demand flow and existing greeter compatibility.

Recommended defaults: five failed attempts, then at least 30 seconds before
each further attempt; at 50 failures, stop face capture and require recovery.
Cooldown expiry allows another attempt but does not clear the failure count.
A completed, admissible face success before exhaustion clears the count.

These are proposed product defaults, informed by
[NIST SP 800-63B-4 sections 3.2.2–3.2.3](https://pages.nist.gov/800-63-4/sp800-63b.html#biometric).
The biometric section distinguishes consecutive failures, delays after the
initial allowance, an overall ceiling, and an alternative authentication method.
Selecting these values does not establish NIST compliance or biometric accuracy.

## Current implementation and gaps

- `crates/irlume-daemon/src/retry_throttle.rs` already persists strict, root-owned
  UID/name-bound version-1 records with monotonic deadlines and boot identity.
  It serializes file updates and refuses face on unsafe or unavailable state.
- `Record::arm` resets strikes to zero. Cooldown expiry also clears strikes.
  Consequently, the current default permits repeated five-failure batches.
- `Authenticate` and `do_unseal_password_scoped` share the throttle. They check
  before capture and record the final outcome afterward. There is no durable
  reservation before engine work, and errors can bypass terminal recording.
- The authentication loop retries incomplete presence evidence. Below-threshold
  identity and hard spoof results are terminal. The proposed counting unit is
  one admitted authentication request, not a camera frame or template comparison.
- `operation_authorization.rs` already binds OS approval to the requesting
  process, account, exact request and freshness window. Its polkit result does
  not identify the authentication factor used. The existing enrollment spec
  explicitly permits the configured polkit stack to use Irlume or fingerprint.
- `password_matches_login` is a keyring preflight, not a recovery verifier: it
  returns unknown for unsupported accounts and its existing caller can proceed.
  It also does not perform PAM account management. Do not reuse that contract.
- Template-key recovery already exists and has its own authorization. Retry
  recovery must not implicitly replace a passphrase, reseal a key or re-enroll.

## Approaches considered

| Approach | Benefit | Trade-off |
|---|---|---|
| Explicit password verification through a dedicated PAM service — recommended | Direct non-biometric proof; independent of the display manager and optional template recovery setup | Requires a bounded helper, packaging and confinement qualification |
| Verify the existing template recovery passphrase | Reuses a separately held credential | Not configured for every account; coupling retry reset to template-key recovery creates availability and lifecycle complexity |
| Reset after ordinary login or generic polkit authorization | Convenient when supported | No existing trustworthy password-success event; generic approval can use face; desktop-specific hooks conflict with the chosen product direction |

## Policy and state transitions

Keep face and recovery-verification budgets separate. Neither locks the Linux
account, changes its password, nor writes a system-wide password lockout counter.

| Event | Face-budget effect |
|---|---|
| Unauthorized request, policy refusal or cancellation before reservation | No change; no capture |
| Admitted request | Durably reserve one slot before engine work |
| Terminal spoof or below-threshold result | Finalize the reserved failure |
| Existing chargeable deadline/runtime/other denial | Finalize the reserved failure |
| Known no-face, uncertain evidence, missing IR face or setup-unavailable result, with no terminal identity/attack decision | Return only this request's reservation; preserve prior history |
| Clean cancellation proven to precede any terminal identity/attack decision | Return only this request's reservation; preserve prior history |
| Cancellation/error after a terminal decision, ambiguous interruption, panic or process death | Keep the reservation charged; do not gain a free attempt |
| Valid completed face grant, including required consent and successful credential preparation when applicable | Clear face history only through durable completion |
| Cooldown expires | Clear the deadline, retain cumulative failures |
| Count reaches 50 after a failed/unknown attempt | Enter recovery-required state; further requests do not start capture |
| Verified explicit recovery | Clear face history and recovery-verification failures atomically |

The 50th reserved request may still succeed: admission is allowed with 49
previous failures, and refused with 50 settled failures. An unfinished reservation
consumes capacity; restarting cannot create a 51st opportunity.

Do not infer exemptions from human-readable reason strings or just the final
error variant. Add an internal accounting result that records whether any
terminal identity/attack decision occurred. Its state is owned by the engine and
daemon, never supplied by the socket client. Keep presence-only internal retries
within the existing time and PAD-vote budgets. Verify that every decisive grant
or refusal ends the request; a future change permitting another decisive attempt
inside one request must acquire another budget slot first.

Existing non-chargeable outcomes remain non-chargeable when positively
established. The deliberate tightening is that unknown completion cannot refund
an attempt. A normal early cancellation remains free; a killed daemon may leave
one conservatively charged slot.

Retain the existing `IRLUME_RATE_LIMIT` and `IRLUME_RATE_COOLDOWN_SECS` controls
for initial allowance and delay. Apply delays after every subsequent failed
request once the configured initial allowance is reached. The new overall face
ceiling is fixed at 50 in this first version. Existing `IRLUME_RATE_LIMIT=0`
continues disabling the legacy delay mechanism, but does not disable the new
cumulative ceiling. Document that intentional configuration change prominently;
custom delay settings do not inherit the default-policy assurance claim.

## Durable accounting and races

Extend the private store to version 2 at the existing fixed retry location.
Retain ownership, mode, link, size, schema, NSS and clock checks. Store only
account identity, version, generation, failure counts, cooldowns and pending
reservation metadata. Do not store scores, face data, credentials or PAM replies.

The proposed private API consists of admission/reservation, settlement, status,
and verified reset. A reservation is a non-cloneable internal capability bound
to account, store generation and a unique operation identity. Settlement consumes
it once. Do not expose a reusable reset or reservation token in the protocol.

Under the store lock, admission reads current state, resolves abandoned work,
checks the ceiling/deadline, and publishes the charged reservation durably.
Release the file lock before capture or password verification. Permit only one
active face reservation per account; preserve the existing worker serialization
and make duplicate admission fail explicitly. Settlement reopens the authoritative
state and checks reservation identity and generation before changing it.

Retain an OS-held operation lock for the reservation lifetime so another process
cannot mistake a live reservation for an abandoned one. Reboot/process death
releases that lock but leaves the durable charge. On recovery of abandoned work,
settle it as a failed/unknown attempt and arm the applicable cooldown. A reboot
rearms a stored cooldown conservatively; it never clears failure counts.

Late settlements from before a verified reset cannot modify the new generation.
Reset is serialized with face admission/settlement and rejects or waits within a
bounded deadline while live face work exists. A successful password check must
remain bound to its account, request and reset generation until the commit.

On write/rename/fsync ambiguity, refuse face and treat the visible record as
authoritative on the next read, as today. Never restore a stale cached count.
Keep the existing completion/deadline gates and the rule that credential
preparation must succeed before a grant clears history. Eligibility must be
checked before and after persistence. Delivery of a successful socket response
cannot be made atomic with a disk commit: a crash after a verified successful
decision is distinct from a crash with an unknown decision and must be documented
and tested as such. No claim of exact response-delivery accounting is made.

## Verified recovery and user experience

Proposed commands, not currently available:

- `irlume retry status`: explain ready, cooling down, recovery required or state
  unavailable; show own-account counts and wait where appropriate.
- `irlume retry reset`: prompt for the current account password without echo;
  verify it independently, then reset only the retry state.
- Root may reset a named account as an explicit administrative override. This is
  trusted administrator authority, not proof of a fresh human password check.

Use an additive protocol operation with a zeroizing secret type and root-or-own
account authorization. A non-root caller cannot select another identity, a PAM
service, executable, configuration directory or helper environment. Existing PAM
clients keep their current denial/fallback response shapes; new CLI features use
capability negotiation and explain when the daemon is too old.

The daemon launches a fixed root-owned helper through a private bounded channel.
The helper is not setuid and exposes no public service. It uses a fixed dedicated
PAM service, calls authentication and account management, and requires explicit
success from both. Locked, expired, password-change-required, unsupported and
unavailable cases do not reset. It does not open a session or change a password.
One request permits one bounded password exchange, not an unbounded conversation.
Passwords never appear in arguments, environment, logs or saved files.

The shipped recovery service must use a reviewed non-biometric password backend;
it must not include the ordinary desktop/polkit stack, Irlume, fingerprint,
automatic credential retrieval or a permissive authentication module. For the
first implementation, qualify local Linux passwords with `pam_unix` and account
checks on the supported package targets. Do not pretend this supports LDAP,
SSSD or systemd-homed automatically. Those account backends need separately
reviewed password-only services; until qualified, self-service reset fails closed
with administrator guidance. Ordinary login through the existing OS stack stays
available. Root modifications to PAM remain within the administrator trust
boundary; no parser can certify arbitrary administrator-authored PAM behavior.

Bound helper runtime and concurrency, cancel on client disappearance, and reap
the helper on all paths. Run it outside the camera worker and store lock. A new
internal proof is bound to the exact requesting connection, live process,
account, operation and generation; consume it once with the existing short
freshness discipline. Neither a client assertion, a generic polkit grant, nor a
successful unrelated recovery/keyring operation substitutes for this proof.

The password-verification endpoint also needs persistent guessing protection:
five failed checks, then a 30-second delay before each further check, and at 50
failed checks disable self-service retry reset until explicit administrator
repair. Successful verified recovery clears that dedicated counter. Reserve
before invoking the verifier so repeated crashes cannot bypass it. Do not reuse
or modify the system-wide PAM password-failure tally. Reaching this separate
limit still leaves ordinary password login available.

Before enabling the overall face ceiling on an installed host, qualify the
recovery helper, package service and confinement rules. Missing/broken recovery
must be visible in status and installation checks. Never silently relax a face
limit because the helper becomes unavailable.

## Migration, compatibility and limits

Version-1 records cannot reconstruct failures erased by earlier cooldowns.
Treat upgrade as the beginning of the cumulative-policy epoch, retain known
strikes, and preserve any active cooldown. For an active legacy cooldown whose
strikes were reset to zero, begin the new count at the configured initial
allowance (at least one); label this a migration seed, not reconstructed history.
Do not claim the new ceiling retrospectively covers pre-upgrade attempts.

Convert under the store lock with durable publication before new admission.
Malformed records and UID/name mismatches continue refusing face and require
administrator repair; the ordinary reset path does not reinterpret corrupt state
as zero. Missing records follow the existing adoption semantics. Root deletion,
disk rollback and account-identity reconciliation remain administrative trust
boundaries, not tamper-proof counter guarantees.

The old binary rejects version 2 because its reader requires version 1. A rollback
must therefore be coordinated and preserve an explicit password-only fallback;
do not translate version 2 to version 1 and silently discard cumulative history.
Test downgrade behavior before deployment. Keep the earlier installed rollback
separate from any future retry-state migration rollback.

No display-manager hooks, automatic stock-desktop face integration, matcher/PAD
threshold changes, biometric measurements or dim-light tests belong to this work.
The optional privileged consent waiver cannot waive retry limits or recovery proof.

## Implementation slices and acceptance evidence

1. Implement and qualify the independently verified recovery boundary, its
   dedicated guessing protection, protocol/CLI and package/confinement integration.
   Keep the new overall face ceiling inactive until this route is qualified.
2. Add version-2 reservations, settlement and migration. Exercise the state machine
   with injected clocks/writers and real private files/processes.
3. Connect both verify and credential-release paths, explicit accounting phases,
   status/fallback wording and configuration migration guidance. Activate the
   policy only after the combined acceptance tests pass.

Required new checks: failures 4/5/6/49/50; no fresh burst after cooldown; successful
50th attempt; clean exemptions versus unknown cancellation; one decisive attempt
per reservation; no cross-account/profile/service bypass; concurrent admission;
kill/restart/reboot and stale settlement; failed writes before/after rename and
directory sync; full counter overflow/schema/ownership validation; v1 migration
and old-binary refusal; expiry during settlement and credential preparation;
reset proof replay/wrong account/expired peer; missing, compromised or failed
helper; wrong/locked/expired password; prohibited biometric verifier path;
independent recovery guessing limits; legacy PAM fallback for both verification
and unseal; unsupported-account guidance without resetting anything.

Use real PAM wrapper integration for helper contracts, plus package-specific
password-backend qualification. Do not authenticate the user's real account,
alter their PAM files or run cameras during unit tests. Hardware installation
qualification remains a later attended step.

This design was reviewed against current source and the installed Linux-PAM
1.7.2 headers/man pages. Existing retry and authorization tests provide baseline
evidence only; they do not validate this unimplemented proposal.
