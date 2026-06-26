//! `pam_irlume.so` — the thin, UNPRIVILEGED PAM module.
//!
//! It does almost nothing itself: open the Unix socket to `irlumed`, send an
//! `Authenticate { user }` request, and map the `AuthResult` to a PAM return
//! code. No camera, no models, no templates, no image data ever live here —
//! that is the whole point of the privilege split.
//!
//! Per NIST SP 800-63B-4, face is one factor of MFA and a non-biometric
//! fallback MUST always exist: on any failure/timeout return PAM_AUTH_ERR (or
//! PAM_AUTHINFO_UNAVAIL) so the stack falls through to password. Configure as
//! `auth sufficient pam_irlume.so` above `pam_unix.so`.
//!
//! Implementation: the `pamsm` crate (`pam_module!` macro + PamServiceModule).

// TODO: implement PamServiceModule::authenticate:
//   let user = pam.get_user()?;
//   let resp = irlume_common client request Authenticate { user } over SOCKET_PATH;
//   match resp { AuthResult{granted:true,live:true,..} => PamError::SUCCESS,
//                _ => PamError::AUTH_ERR }   // fall through to password
//
// pamsm::pam_module!(IrlumePam);

/// Placeholder so the cdylib builds before `pamsm` is wired in.
#[no_mangle]
pub extern "C" fn irlume_pam_placeholder() {}
