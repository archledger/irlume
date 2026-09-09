# Private retry password verifier

`/usr/libexec/irlume-password-verify USER` is a root-only, **non-setuid**
helper. Both real and effective UID must be zero. The daemon supplies a cleared
environment and a private stdin pipe containing 1–4096 raw password bytes,
terminated by EOF. NUL is invalid; no newline is added or removed. The fixed
PAM service is `irlume-retry-reset`. Exit codes are 0 (verified), 1 (denied),
and 2 (invalid or unavailable). It prints no password or prompt.

The helper requires successful authentication and account management, one
password prompt, and an unchanged final PAM_USER. Conversation failures remain
latched through PAM cleanup. Owned input is zeroized on normal returns. Core
dumps are disabled, and an intrinsic ten-second deadline terminates a wedged
input/PAM transaction. The signal handler uses `_exit`, so deadline termination
reclaims process memory without running Rust destructors. The daemon separately
bounds, cancels and reaps the process.

The shipped service uses only `pam_unix` authentication and account checks;
it has no session, password-changing, biometric, include, nullok, or failure-tally
modules. This is a local Linux password boundary. LDAP, SSSD and homed are not
qualified. Administrators can modify their system PAM policy, but the daemon
refuses a service that differs from the reviewed stack.

Run `scripts/test-password-helper.sh` from the repository. It builds the helper
and a private synthetic PAM module, runs an unprivileged refusal, then uses
`sudo -n setpriv` to run the actual libpam suite with no-new-privileges and only
DAC_OVERRIDE/FOWNER in its capability bounding set. The suite requires a C
compiler, PAM development headers, pam_wrapper and util-linux. Missing root or
wrapper prerequisites fail; the ordinary Cargo invocation leaves the explicitly
ignored root fixture unrun. Tests never alter installed PAM files, read a real
password database or authenticate a real account.

AppArmor profiles contain a dedicated helper child profile; only that child
receives shadow access. Enforcing AppArmor recovery remains unavailable until
its transition under no-new-privileges is qualified. Policy parsing is not
runtime qualification. The existing daemon capability set and no-new-privileges
setting remain unchanged. The Fedora SELinux policy currently runs the daemon
in `unconfined_service_t`; this change adds no SELinux shadow permission and
makes no claim of a new isolated SELinux helper domain. Package installation,
real pam_unix local-account behavior on each supported distribution and actual
AppArmor transitions require separate qualification before enabling a cumulative
face ceiling.
