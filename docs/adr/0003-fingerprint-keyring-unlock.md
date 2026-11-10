# ADR-0003: Fingerprint → TPM keyring unlock

**Status:** Accepted; implemented 2026-07-03.
**Context:** the login-keyring stays locked after a fingerprint login.

## Problem

GNOME Keyring's `login` keyring is encrypted with the user's **login password**;
it auto-unlocks only when a PAM module hands that password to
`pam_gnome_keyring` as `PAM_AUTHTOK`. A **password** login does this via
`pam_unix`. A **fingerprint** login (`pam_fprintd`) authenticates the user but
produces *no password* (and its `success=N` jump skips `pam_unix` entirely), so
the keyring never gets a password and stays locked. The first app that needs a
secret (a browser, etc.) then prompts the user to type it. This is stock
`fprintd` behaviour on every distro, not an irlume defect; irlume only surfaces
it by making fingerprint the login method.

Windows Hello does not have this gap: a fingerprint match releases credentials
from the TPM-backed Hello container. irlume already does the equivalent for the
**face/IR** path (`UnsealPassword`: face match → TPM-unseal → `PAM_AUTHTOK`).
This ADR extends that to fingerprint.

## Decision

The auth/session rules below are amended by the 2026-10-01 and 2026-10-06
sections.

Add `pam_irlume.so keyring`, wired at the **post-auth landing** of the greeter /
lock-screen stack (after `@include common-auth`, before `pam_gnome_keyring`). It
runs only when a trusted factor has already succeeded in this transaction:

- If `PAM_AUTHTOK` is **set** (password typed, or the face `unseal` line already
  provided it) → do nothing; the keyring unlocks from it.
- If `PAM_AUTHTOK` is **empty** (a fingerprint login) → request `UnsealKeyring`
  from the daemon and set the returned password as `PAM_AUTHTOK`.

Always returns `PAM_IGNORE`: keyring unlock is best-effort and never fails or
blocks a login.

The daemon's `UnsealKeyring` releases the sealed login password on:

1. **root peer** (`SO_PEERCRED` uid 0): the login stack runs as root; and
2. a **login / lock-screen service class** (`biopolicy::classify` ∈
   {`ScreenUnlock`, `Login`}), never `sudo`, elevation, remote, or unknown; and
3. a **sealed password exists** (`keyring arm` was run).

It does **not** perform a biometric check itself: the daemon cannot re-verify
a fingerprint (`fprintd` owns the sensor), and `pam_fprintd` has already
authenticated the user before `pam_irlume keyring` is reached.

Enable it by arming the keyring (`irlume keyring arm`) and wiring the greeter
(`irlume login enable --apply`, which now emits the `keyring` line). It is a
no-op until armed, and it is **independent of the camera tier**: a convenience
(RGB-only) laptop with a fingerprint reader gets keyring unlock, because the
trusted factor is the fingerprint, not the camera.

## Security analysis

**What is preserved.** At-rest protection is unchanged: the password is
TPM-sealed, so a **stolen disk / backup image cannot unseal it** (needs the live
TPM). Verified by the same cross-machine test as the face path
([SECURITY_AT_REST.md](../SECURITY_AT_REST.md)). On the machine itself this
depends on the storage and the policy; see the 2026-09-27 amendment below.

**The residual (documented, accepted).** `UnsealKeyring` releases the password to
*any root peer* in a login-class PAM context; it does not, and cannot, prove a
fingerprint actually occurred (a root process can call the daemon directly,
bypassing PAM, and forge the service string). So a **live root attacker can
obtain the sealed password.** This does **not** expand root's power: a live-root
attacker on the running machine can already read the unlocked keyring, ptrace
`gnome-keyring`, or keylog the next login. **Root remains the trust boundary**,
consistent with the rest of irlume's threat model and with Windows Hello, whose
container is likewise compromisable by a live administrator.

The service-class gate (2) is defence-in-depth, not a barrier against root: it
stops the `keyring` line from releasing the credential if mis-wired into a
non-login stack (e.g. `sudo`), but a direct caller can forge the service name.

**Strictly weaker than the face path** in one way: the face `UnsealPassword`
requires a daemon-verified **live biometric**, so even a live-root attacker
can't unseal without presenting a real face. Fingerprint keyring unlock can't
match that without the daemon owning the sensor.

## Alternatives considered

- **Empty-password keyring** (seahorse): auto-unlocks but stores secrets
  unencrypted at rest. Rejected as the default; a worse security posture than
  this.
- **Daemon-side fprintd verify** (daemon claims the reader over D-Bus and
  verifies the fingerprint itself before unsealing): would be as strong as the
  face path against live root (a root attacker couldn't fake a swipe to the
  daemon). Rejected *for now*: it means the daemon owns fingerprint auth (async
  D-Bus in a currently-sync daemon, replacing `pam_fprintd`), a large change.
  **Recorded as the future hardening** that closes the live-root residual.

## Amendment 2026-09-27: at-rest protection on the machine itself

"What is preserved" holds for a disk or backup image read on another
machine. On the machine itself, a TPM seal binds the boot chain it measures,
not the root filesystem. Where irlume's state directory is not on encrypted
storage, someone with the machine can change the installed system offline
(for example, add a service that runs as root) and boot the unchanged boot
chain; the PCRs then match the policy, whichever it is, and the sealed
keyring secret unseals on that machine. A policy that does not cover the
boot loader code (PCR 4) leaves a second path: another operating system
signed with the same keys reproduces what it binds and can unseal the secret
directly, without changing the installed system. That holds for the literal
PCR 7 policy (Tier 3, used where no pcrlock policy covering a
firmware-measured PCR is provisioned), a literal `IRLUME_PCRS` set without
PCR 4 (PCRs 0 to 3 measure this machine's firmware, which is the same
whatever it boots), a signed PCR 11 policy (Tier 1) from an earlier release,
and a pcrlock policy (Tier 2) without PCR 4, which systemd-pcrlock makes
when the binaries measured there are not locked (`lock-pe`, `lock-uki`). A
policy that covers PCR 4 closes the second path only where the boot loader
also measures what it loads next (a unified kernel image does; a GRUB boot
leaves the initrd and the kernel command line to PCRs 9 and 8), and never
closes the first.

What protects the sealed secret at rest on this machine is full-disk
encryption unlocked by a passphrase or PIN (a volume the TPM or a key file
unlocks alone does not count), or an integrity-verified root filesystem
(dm-verity) that covers everything the boot runs and reads configuration
from, with its root hash bound by a pcrlock policy or a signature, together
with a pcrlock policy that covers PCR 4. A pcrlock policy is worth having in
addition to encryption, not instead of it.

Keyring arming stays opt-in and every tier stays supported. `irlume keyring
arm` (after an arm) and `irlume doctor` (check `sealed-storage`) report this
for the account's keyring secret and template key: a warning when either is
sealed and no dm-crypt layer is found under the directory that holds it or
under the installed system (`/`, `/usr`, `/etc`), or the storage cannot be
established, and information whenever it is on
dm-crypt,
since the storage does not show how that volume unlocks, naming each sealed
secret's policy another operating system may reproduce
([SECURITY_AT_REST.md](../SECURITY_AT_REST.md), layer 3). `irlume setup`,
`irlume keyring reseal` and the TUI show the same guidance after a seal.

## Amendment 2026-10-01: warm accounts, session delivery and upgrades

### 1. Withhold the fingerprint lane's auth-phase release on a warm account

The `keyring` auth line sends `UnsealKeyring { auth_phase: true, ... }`.
As introduced by #863 and tightened by #864, irlumed answers
`KeyringUnlockNotNeeded` without releasing a secret when the account has a
live local graphical session, or its account/session state cannot be read.
The rule covers every secret kind. It avoids re-opening a keyring the owner
locked manually, or starting another wallet daemon, on a fingerprint unlock.

Here a warm account has a logind session with that account's UID,
`CLASS=user`, `STATE=active` or `online`, `TYPE=x11`, `wayland` or `mir`, and
`REMOTE=0`. A remote desktop, SSH session, text console, greeter or closing
session alone does not establish this condition. A runtime directory or
session bus alone is insufficient. The rule is account-wide: a second login
for an account with an existing desktop also withholds the auth-phase release.

The module enforces this rule before sending the request too (#859). This
covers a replaced `pam_irlume.so` talking to an older daemon that ignores
`auth_phase` until the package restarts it. It resolves the UID through a
bounded `getent passwd` child and scans logind's session records. It uses no
`loginctl`, no in-process NSS lookup and no `/run/user` fallback for this
guard. The UID must come from one record with the requested account name;
an unavailable lookup or canonical-name disagreement withholds the release.

The observation shares a 250 ms deadline. The existing PAM helper reader
caps stdout at 4096 bytes and termination/reaping at another 200 ms. The
session scan caps directory entries at 1024 and each record at 16 KiB,
rejects symlinks and non-regular session records, and uses nonblocking opens
so a FIFO cannot hold up authentication. Legacy `<id>.ref` FIFOs are not
session records. Unreadable, malformed, unsupported or incomplete evidence
withholds the release. The check reads logind's current state; it does not
lock logind against session changes after the observation.

Withholding returns `PAM_IGNORE`, leaves `PAM_AUTHTOK` untouched and grants
no authentication. The typed password and other factor keep their existing
PAM control flow. This module guard supplements the daemon's independent
checks; root remains the trust boundary described above.

### 2. Keep the current backend-specific phase contracts

The original password-only decision has expanded to three secret kinds:

| Kind | Cold-account `keyring` auth line | `reseal` session line |
|---|---|---|
| Login password | Sets `PAM_AUTHTOK` for the later vendor auth hook | Does not request or deliver this kind |
| KDE wallet key | Hands the key to the wallet helper; stashes it only when the helper reports `NotReady` | Delivers that deferred key once; no stash-less release query |
| GNOME keyring token | Stashes the token in zeroizing PAM data, never in `PAM_AUTHTOK` | Delivers the stash once, or requests a token if auth supplied none |

The auth request reports `have_password`, including a wallet already started
by an earlier face line. The daemon skips password-derived secrets when they
are already served. A GNOME token still needs its own delivery because the
typed login password does not open a token-keyed keyring.

The GNOME session query uses `have_password: true, auth_phase: false`. It
accepts only `GnomeKeyringToken`. This query remains available when the
auth-phase warm guard withheld a release: a new session needs its token even
though logind already lists the account as live. Resealing from a stashed,
verified password precedes token delivery. Session delivery stays best-effort
and returns `PAM_IGNORE` on failure.

There is no wire change. Both flags retain their existing `serde(default)`
behavior. Older modules omitting `auth_phase` still receive the historical
release behavior from a newer daemon; the daemon cannot infer which phase
such a caller meant. Updated modules suppress warm/unknown auth requests
before an older daemon can act on them, while established cold requests and
session queries retain their existing shapes.

### 3. Deferred session-only migration

Moving every fingerprint-lane release to `open_session` remains deferred.
It is not implemented by the warm guard or by this amendment. In
[GNOME Keyring 50.0](https://github.com/GNOME/gnome-keyring/blob/50.0/pam/gkr-pam-module.c),
the auth hook reads `PAM_AUTHTOK` and can stash `gkr_system_authtok`; the
session hook reads that stash. In
[kwallet-pam v6.4.5](https://github.com/KDE/kwallet-pam/blob/v6.4.5/pam_kwallet.c),
the auth hook stores `kwallet5_key` for the session hook. Assigning
`PAM_AUTHTOK` only in irlume's session hook would not supply either auth stash.
The KDE-key and GNOME-token paths also have different helper and stack-order
contracts, as the table records.

A later migration needs a tested delivery path for all three kinds, including
vendor hook ordering, cold first login, second login, password fallback and
mixed module/daemon versions. The separate GNOME waiter initialization race is
outside this amendment. The migration itself is the 2026-10-06 amendment
below, which answers these requirements.

### Acceptance tests

`crates/irlume-pam/tests/pamwrap.rs` runs the real module in a synthetic PAM
stack against a daemon fixture that ignores the phase flag. The
`pamwrap_keyring_upgrade_*` tests require:

- No auth request for a warm or unknown account; the typed password survives
  and the guard cannot turn a failing authentication stack into a success.
- Explicit graphical properties, with remote, TTY, greeter, closing and
  other-account cases distinguished; runtime-directory presence is irrelevant.
- Bounded refusal for stalled, failed, oversized or malformed account lookups
  and oversized, symlinked, special or excessive session records.
- Cold password delivery reaches the auth consumer; a warm account's new
  session still obtains and delivers its GNOME token exactly once.

Existing GNOME-stash and KDE auth/deferred-session tests must continue to pass.

## Amendment 2026-10-03: serialize token arm with PAM removal

GNOME token `SealPassword` holds the same PAM writer lock as login disable,
apply, rollback and reconcile. The authoritative delivery check and durable
token-envelope publication occur under one uninterrupted lock lifetime.
The CLI's earlier preflight remains advisory. A new daemon applies the check
to every token arm and re-arm, including requests from older clients.

The daemon resolves the installed `irlume` sibling of its own executable.
Both the selected path and its resolved ancestry must be root-owned and
non-writable by other accounts; setuid/setgid helpers are refused. The daemon
checks the executable's identity and modification metadata again after the
helper finishes. FHS packages install both binaries in `/usr/bin`, source
installs use `/usr/local/bin`, and Nix keeps the sibling in the same store
output. PATH and client requests select neither binary.

The helper's fixed private mode requires root and a root-origin Unix socket
on stdin. It reads one bounded account name, takes `lock_pam()` including
legacy migration exclusions, and runs the existing delivery parser without
daemon IPC or a capability query. Success transfers every held lock's open
file description using `SCM_RIGHTS`. The daemon requires successful helper
completion and descriptor proof, validates the private primary lock's inode,
and retains all descriptions through `arm_gnome_token` or `rearm_gnome_token`.
It rechecks the account binding after acquiring the guard. The transferred
locks are released by closing their last descriptions, never by an explicit
unlock during handoff.

Helper observation and descriptor reception share a five-second deadline.
The existing bounded child collector kills failed or expired helpers and
retains pending reaps within its child budget. An absent helper, an older
binary that sends no descriptors, a failed delivery check, or invalid proof
refuses sealing and leaves the existing envelope intact. Upgrade both
binaries and retry after checking login wiring. Login-password and KDE-key
sealing keep their existing behavior and do not acquire this guard.

If ordinary disable takes the lock first, the helper sees the removed
delivery line and refuses arm. If arm takes it first, disable waits until
the envelope is published, then its existing token check refuses removal.
An explicit root `--force` remains an intentional bypass. Package managers
and administrator edits do not take this lock. The change does not serialize
all account-local arm/disarm/re-key operations or resolve a lost GNOME CHANGE
reply; envelope-before-re-key ordering remains the recovery boundary.

AppArmor's FHS and source-install profiles permit the fixed helper to inherit
the daemon profile with `ix`, with PAM/manager/package reads and lock access.
They retain the shadow deny and grant no PAM write permission. The systemd
and Nix service sandboxes keep their existing read-only `/etc` and capability
bounding set. A confinement refusal follows the same no-seal failure path.

The `token_lock` CLI integration tests coordinate arm-first through the real
disable lock-wait diagnostic and test disable-first through actual removal.
The daemon tests exercise the installed sibling in a private root, reject
missing, writable-ancestry and success-only helpers, retain descriptors after
helper exit, and preserve envelopes when proof fails. Software-TPM tests use
real subprocess/lock fixtures while keeping their existing seal assertions.

## Amendment 2026-10-06: the fingerprint lane releases from the session phase

The 2026-10-01 section 3 deferred moving every fingerprint-lane release to
`open_session`. This amendment performs that migration (#859, plan items 2.1
and 2.2). A PAM stack keeps executing `optional` lines after a failed
`required` anchor or a failed substack, and the module cannot ask what the
lines above it returned, so any auth-phase release could follow a failed
factor: a wrong finger or a timeout released the sealed secret into a
transaction that was about to fail (the audit's X4/F17). `pam_open_session`
runs only after `pam_authenticate` and `pam_acct_mgmt` both succeeded, which
is the proof the auth phase never had.

### 1. The auth-phase `keyring` line releases nothing

The line stays in every stack the wiring writes, as the post-auth landing
marker `login status` and unwire recognize, but it makes no request, sets no
token and runs no probe: it returns `PAM_IGNORE` immediately. The bounded
module-side warm guard of #863/#977 (`keyring_session::auth_release_allowed`,
with its `getent` child and logind scan) is deleted with it: a module that
never sends an auth-phase `UnsealKeyring` needs no guard on one, which is a
strictly stronger form of the same guarantee. The daemon-side warm rule of
section 1 above is unchanged and keeps covering modules from before this
amendment, which still send `auth_phase: true` until they are replaced.

### 2. The `reseal` session line releases, at most once per handle

`pam_sm_open_session` with the `reseal` argument now performs the release
after the self-heal reseal:

- A GNOME keyring token the auth phase stashed (the face `unseal` line's
  release) is delivered without a new request, as before.
- Otherwise one `UnsealKeyring { have_password, auth_phase: false }` request
  serves the fingerprint lane and the stash-less logins together. The reply
  is routed by kind: a GNOME token and a login password both go to
  `irlume-gkr-unlock` (the control socket takes the keyring's own secret; a
  password-keyed keyring's secret is the login password, and the #850 waiter
  handles a `--login` daemon that is not initialized yet), and a KDE wallet
  key goes to `irlume-kwallet-init`, which at this phase finds
  `/run/user/<uid>` in place (#821's delivery moment). The
  `KeyringUnlockNotNeeded` and error replies deliver nothing; the vendor
  password path keeps whatever it had.

The emptied-stash sentinel remains the once-guard: a second `open_session`
on the same handle neither asks again nor starts a second helper. A
transaction makes at most one release request, in line with ADR-0025's
one-unseal discipline.

### 3. `have_password` is verified evidence, not presence

The query's flag now reports evidence, not a cached token: a wallet this
login already started (`PAM_KWALLET5_LOGIN`), or a stashed password the
daemon just accepted for resealing, counts as a password; a token merely
cached in `PAM_AUTHTOK` does not, because it may be a typo the stack
recovered from by granting on another factor (the audit's F23 residual
half: after a wrong password and a successful fingerprint, the release now
still happens and the keyring still unlocks). A typed-password login on a
wired stack still reports `true`: the `reseal` auth line stashed the
password the stack accepted and the daemon's reseal reply confirms it, so
the daemon answers `KeyringUnlockNotNeeded` for a password-derived envelope
without touching the TPM, exactly as before. Where the daemon cannot read
the login hash (the Debian-family AppArmor profile, LDAP, SSSD), its
acceptance cannot verify anything and the typo residual of #836 remains:
the flag stays `true` and the release is skipped, as before this amendment.

### 4. Phase contracts after the move

| Kind | `keyring` auth line | `reseal` session line |
|---|---|---|
| Login password | Requests nothing | Released when no password evidence exists and delivered to the keyring control socket |
| KDE wallet key | Requests nothing | Released when no password evidence exists; `irlume-kwallet-init` starts the wallet (the not-ready exit is final: no stash, no later phase) |
| GNOME keyring token | Requests nothing | Stash delivered if auth released one (face lane); otherwise released and delivered via `irlume-gkr-unlock` |

Assigning `PAM_AUTHTOK` in the session hook would supply neither vendor
stash (the GNOME and KDE auth hooks have already run), which is why the
login password goes to the control socket instead. A hand-written stack
whose keyring line has no matching `reseal` session line therefore leaves
the keyring locked after a fingerprint login; the wiring writes the session
line everywhere it writes the keyring line, and the arm-time delivery
checks of #865/#982 already require a provably reached session rule for
token arms. Extending that arm-time requirement to password and wallet-key
arms is follow-up work.

### 5. Mixed versions

- New module, old daemon: the module sends no auth-phase request; the one
  session request omits nothing an old daemon needs (older daemons ignore
  `auth_phase` and answer it as they always answered session queries), and
  delivery is module-side, so it works against every daemon that releases.
- Old module, new daemon: unchanged behavior, warm rule included, until the
  package replaces the module.
- Neither version double-releases: each release query belongs to one
  `open_session` on one handle, and the once-guard sentinel holds the
  second one back.

The warm-second-login question for password and wallet-key kinds (a second
login of an account whose desktop already runs) keeps the shape section 1
left it: the session query is exempt from the warm rule because the session
being opened needs its secret, and lock-state-aware delivery for warm
accounts is the separate setcred follow-up the plan records as item 2.3.

### Acceptance tests

`crates/irlume-pam/tests/pamwrap.rs` drives the real module through
pam_wrapper:

- `pamwrap_fp_keyring_failed_{substack,required_anchor,fedora_greeter_landing}_sends_no_unseal`:
  three stack shapes whose factor fails send no `UnsealKeyring` (one was
  sent from the auth phase before).
- `pamwrap_fp_keyring_success_releases_once_in_the_session_phase` and
  `pamwrap_fp_keyring_session_query_ignores_a_cached_wrong_token`: a
  successful factor releases exactly once, from the session phase, and a
  cached wrong token does not count as password evidence.
- `pamwrap_keyring_upgrade_withholds_warm_release_and_preserves_password`
  and `pamwrap_keyring_auth_line_is_inert_under_hostile_account_state`:
  the auth-phase line asks nothing, warm or cold, typed or not, under
  hostile account state, and never consumes the password or grants.
- The GNOME token, KDE wallet and reseal suites pin the session-phase
  delivery, the once-guard, the running-wallet interlock and the evidence
  rule per kind.

Daemon-side warm withholding keeps its own tests in `irlume-daemon`
(`a_warm_unlock_releases_no_keyring_secret` and the unseal gates).

## Amendment 2026-11-08: defer a cold-login face wallet key

This changes delivery after an existing successful face match; it changes
no daemon authorization, PAD requirement, credential kind or wire message.

### 1. Opt in only on login stacks with a session consumer

After a cold boot, `pam_systemd` creates `/run/user/<uid>` during session
opening, not during authentication. A face match can therefore unseal a KDE
wallet key while `irlume-kwallet-init` cannot yet start the wallet. Treating
that condition as a failed delivery forces an unnecessary password login.

The `defer_wallet` PAM argument allows that key to wait in the current PAM
transaction until its `reseal` session hook runs. The login wiring adds this
argument together with that hook. Separate lock stacks and NixOS's
password-only wiring do not opt in. Existing hand-written stacks without the
argument retain their password fallback; a hand-written opt-in must include
the session consumer after the runtime directory is established.

Only the helper's explicit session-not-ready exit permits deferral. The
helper returns it only for a missing runtime directory, after finding a
wallet backend. An unreadable path, a non-directory or symlink, a missing
backend, a malformed key, timeout or other helper failure remains a failed
delivery. No directory is created during authentication.

### 2. Hold the key only in transaction-local zeroizing memory

A successful stash is an explicit delivery outcome, like the existing GNOME
token stash. It never sets `PAM_AUTHTOK`, so `kr` does not send a KDE key into
the password stack. The stash binds the key to the exact PAM user and
service. Failed registration cannot grant authentication.

The session hook destructively takes the key before checking that binding or
invoking a helper. It does not ask the daemon for another secret. The
running-wallet interlock still prevents a second wallet daemon. A failed or
not-ready session delivery is final for that transaction; repeated session
opening cannot retry it. A new primary authentication attempt, session
closure and transaction destruction discard any pending key. Optional
`keyring` and `reseal` auth markers do not discard it.

### 3. Acceptance tests and remaining qualification

The real-PAM fixtures must show that a cold face login succeeds before a
session-only readiness marker is created, then delivers the same key once
after that marker, with no second credential request and no wallet key in
`PAM_AUTHTOK`. Both sufficient and numeric-jump greeter controls are covered.
Negative cases cover legacy no-opt-in fallback, malformed keys, helper
failure, changed user/service, repeated authentication and the existing
running-wallet interlock. Password, fingerprint and GNOME-token tests remain
required. Physical cold-boot login and desktop wallet use require a separate
attended qualification; a passing fixture is not that qualification.

### 4. Establish the authentication attempt before any factor

Managed greeter and fingerprint recipes start their auth chain with
`pam_irlume.so begin reseal service=SERVICE`. The service is the top-level
PAM service owning the file. A marker reached inside another service's include
does not reset that outer transaction. The new module handles the arguments
before reading the user or token: it discards the prior attempt's state and
returns `PAM_IGNORE`, without prompting or requesting a credential. The
`reseal` carrier keeps the entry non-authenticating on older modules too;
an older module still needs replacement to provide the reset guarantee.

This entry precedes any provider that can return a sufficient success,
including providers in inline includes. Credential-granting rules remain
below their existing policy gates. The post-auth `reseal` line also removes
any previously cached password before examining the current token, without
discarding a face-released key from the same attempt.

All stashed secrets share one user/service-bound transaction state. Session
opening marks it consumed before resealing, making a credential request or
delivering to a helper. That transition needs no fallible PAM-data replacement.
Failure to create the state before any side effect can be retried by a later
session call; it never permits a second release after consumption.

## Amendment 2026-11-10: a GNOME keyring token arm is one-way

This amendment records the disarm side of a GNOME keyring token arm. It
changes no authentication decision, PAD requirement, release gate or
credential kind. The 2026-10-03 ordering, a durable envelope before the
keyring is re-keyed, stays the recovery boundary for arming.

### 1. A token envelope is kept while its holders cannot be excluded

Arming re-keys the login keyring to a random token; the envelope under
`/var/lib/irlume/keyring` is irlumed's copy of that token. A holder, in this
amendment, is a client that has received the token from irlumed and can
present it to gnome-keyring, to unlock the keyring or to re-key it, at any
later time. The uninstall and login guards use the word differently: their
"token holders" (`sealed_token_holders`) are the accounts that have a token
envelope.

A login delivers the token in the root-only `UnsealPassword` and
`UnsealKeyring` replies to the PAM transaction, which hands it to
`irlume-gkr-unlock`; that helper presents the token to gnome-keyring to
unlock the keyring and sets no other credential. Outside a login the token
leaves irlumed in two replies, each to root or the account's owner:

- `TokenSealed`, answering a `SealPassword` that armed or re-armed a token (a
  re-arm returns the token already armed);
- `PasswordUnsealed { kind: GnomeKeyringToken }`, answering
  `ReleaseTokenForDisarm`.

irlumed cannot establish that no holder remains:

- it keeps no record of the tokens it returned, and a record held in memory
  would not survive a restart;
- an older client takes part in no newer exchange;
- a correct password and an unchanged envelope show what the requester knows,
  not what a holder does later;
- a count or a deadline must never expire into permission to remove.

While a holder remains, the keyring can be keyed to the token at any later
time, and without the envelope nothing can reproduce that secret. No irlume
request, command or flag therefore removes a token envelope. An envelope
irlumed cannot read may be a token and is kept under the same rule.
Login-password and KDE wallet-key envelopes are outside it:
`irlume keyring forget` erases them.

### 2. `DisarmKeyring { user }`

`irlume keyring forget` sends `DisarmKeyring { user }`. The request carries
no kind, password or flag. irlumed reads the envelope's kind when the request
runs, on the single mutation worker and serialized with `SealPassword` and
`ResealPassword`, so the answer follows the envelope of that moment, whatever
an earlier `KeyringInfo` reply said.

| Table | `DisarmKeyring` |
|---|---|
| `posture` | `RootOrTarget` (verb "forget password for"), enrollment `Reads`, camera `NoCapture` |
| `classify` | `Plain` |
| `approval_operation` | `None` |
| `request_kind` | `WalletUpdate`, mutating |
| `diagnostic_operation_class` | `Status` |

It shares its dispatch arm and its function (`forget_non_token`) with
`ForgetPassword`. The reply is `PasswordForgotten` after a login-password or
KDE wallet-key envelope is erased, and when no envelope exists. For a token
envelope, or one irlumed cannot read, the reply is an error and the envelope
is kept.

Mixed versions: only a daemon that reads the kind when the request runs
knows the name. An older daemon answers `Error("bad request")`; the client
treats that as final, reports that irlumed needs a restart after the upgrade,
and never sends `ForgetPassword` in its place. `ForgetPassword` stays for
older clients and runs the same code.

### 3. `ReleaseTokenForDisarm` remains for older clients

No current client sends `ReleaseTokenForDisarm`. The request stays on the
wire as it is, for an older CLI whose `keyring forget` sends it.

| Table | `ReleaseTokenForDisarm` |
|---|---|
| `posture` | `RootOrTarget` (verb "release the keyring token for"), enrollment `Reads`, camera `NoCapture` |
| `classify` | `Plain` |
| `approval_operation` | `None` |
| `request_kind` | `WalletAuthentication`, not mutating |
| `diagnostic_operation_class` | `Authentication` |

It answers `PasswordUnsealed { kind: GnomeKeyringToken }` once the supplied
password opens the token's password wrap, and the envelope stays armed.

An older CLI then re-keys the keyring back to the password and sends
`ForgetPassword`, which is refused under section 2. The end state is a
keyring keyed to the password, a token envelope still armed, and a CLI that
reports the forget as failed. A face or fingerprint login then leaves the
keyring locked, since the delivered token does not open it. A later
`irlume keyring arm` re-keys the keyring to the same token where irlumed
can check the password against the login hash. Where it cannot (the
shipped AppArmor profile, LDAP, SSSD), irlumed refuses a re-arm over an
armed token, and this end state stays.

### 4. What a disarm would need

Token disarm stays unavailable until a separate decision record defines it.
That record has to provide:

- the release and the re-key back as one account-bound transaction under
  irlumed's control, with the envelope removed only on confirmed success;
- a transaction that fails closed across a daemon restart: an interrupted
  one keeps the envelope;
- the retirement of `ReleaseTokenForDisarm`;
- a rule for envelopes armed earlier, whose holders are unknown.

### Consequences

- `irlume keyring forget` refuses a GNOME keyring token with no prompt and no
  disarm request, with or without `--force`. It refuses the same way when
  irlumed does not report the envelope's kind or cannot read the envelope.
  The read-only `KeyringInfo` reply gives the CLI the kind; irlumed decides
  again when `DisarmKeyring` runs.
- `irlume uninstall` refuses while an account has a token envelope. It reads
  the stores again after irlumed has stopped and before any envelope,
  enrollment or state tree is removed; a refusal at that point leaves PAM
  un-wired, irlumed stopped, and the data and the installation in place.
- `irlume login disable`, and any other run that would remove the session
  line that delivers a token, refuses while an account has a token envelope.
  `--force` passes that wiring guard only: it removes the delivery line and
  keeps the envelope, and the keyring then stays locked.
- A token arm on Fedora 43 or 44 has no supported path to Fedora 45, where
  the login screen unlocks the login keyring through oo7.
- A login with a typed password, on a stack wired with the re-seal, repairs
  one change at a time. After a password change the seal opens and the wrap
  moves to the new password; after a firmware or Secure Boot change the
  typed password opens the wrap and the seal is bound again. When both have
  changed since the last such login, neither half opens: the envelope is
  left as it is and the token cannot be delivered. The two exits are the
  earlier boot state and the earlier password, each followed by such a
  login.
- A token envelope recorded for another uid, as after an account name is
  reused, is not released, not re-sealed, not returned for a re-arm and not
  removed.
- A re-key that fails after the seal leaves a token envelope, which counts
  as a token for every guard above. A later `irlume keyring arm`, run in the
  account's own graphical session, completes the re-key where irlumed can
  check the password against the login hash. Where it cannot, that arm is
  refused: the envelope stays, the keyring stays keyed to the password, and
  a face or fingerprint login leaves the keyring locked.
- An arm of another kind over a token is refused and changes nothing.

### Acceptance tests

- `irlume-common`:
  `disarm_keyring_is_additive_and_never_decodes_as_legacy_forget` pins the
  wire form.
- `irlume-core`:
  `a_token_envelope_stays_armed_after_a_release_and_a_refused_forget`,
  `non_token_forget_refuses_tokens_and_unknown_formats`,
  `a_sealed_secret_recorded_for_another_uid_is_not_released` and
  `rearming_reuses_the_existing_token_rather_than_minting`; on a software
  TPM, `a_token_envelope_heals_from_whichever_half_survives` covers the
  one-change repairs and the refusal of the combined case.
- `irlume-daemon`:
  `a_disarm_keeps_a_token_envelope_under_either_request_name`,
  `a_release_then_a_forget_leaves_the_token_envelope_armed`,
  `an_account_disarms_its_own_keyring_and_no_other`,
  `legacy_forget_refuses_a_new_token_after_stale_password_observation`,
  `a_checked_seal_never_replaces_a_token_or_an_unreadable_envelope` and
  `an_arm_on_an_oo7_home_keeps_an_armed_token`; on a software TPM,
  `tpm_unverified_reseal_rewraps_the_token_under_the_new_password`,
  `tpm_owner_reseal_leaves_the_token_envelope_unchanged` and
  `tpm_a_checked_new_password_rewraps_the_token`.
- `irlume-cli`:
  `wallet_forget_refuses_a_token_before_asking_or_sending_anything`,
  `wallet_forget_stale_non_token_snapshot_cannot_bypass_daemon_refusal`,
  `a_minted_token_is_kept_when_the_rekey_answer_is_lost`,
  `a_token_arm_in_a_session_without_an_initialized_gnome_keyring_sends_nothing`,
  `token_free_refuses_a_token_and_passes_a_sweep_error_through` and
  `teardown_rereads_the_stores_after_the_stop_and_before_any_data_removal`,
  which reads `uninstall.rs` as text and pins the order of the calls.
