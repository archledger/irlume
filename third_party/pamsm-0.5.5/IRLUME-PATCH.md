# irlume patch to pamsm 0.5.5

- Upstream: https://github.com/rcatolino/pam_sm_rust
- Upstream commit recorded by crates.io: `a51131ebaa252a9c77727f65d962d33d8a632e87`
- Crate: `pamsm` 0.5.5
- crates.io checksum: `aad7ddca63c73e80eb4ace88e130c9b513da6ec1284becd9fc1fc385a9a72a64`
- License: GPL-3.0 (preserved in `License`)
- Local delta: expose `PamLibExt::clear_authtok`, implemented with
  `pam_set_item(PAM_AUTHTOK, NULL)`, and replace the generic borrowed-response
  `conv` wrapper with a narrow response-free `info` wrapper over `pam_prompt`.
- Reason: a privileged PAM module must remove the reserved `yes` token before
  camera work so downstream password fallback receives a fresh prompt.
- Removal: replace this directory when an audited upstream release provides
  equivalent token clearing and safe informational messaging, and all PAM/KDE
  acceptance tests pass.

All packaged upstream files are preserved byte-for-byte except
`src/libpam.rs`, which carries the documented local delta. Cargo's local
`.cargo-ok` extraction marker is not source and is intentionally omitted.
