// Copyright (c) 2017 raphael.catolino@gmail.com

#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use pam_types::PamHandle;
use std::fmt;
use std::os::raw::c_int;

/// Opaque PAM handle, with additional native methods available via `PamLibExt`.
#[repr(transparent)]
pub struct Pam(pub(crate) PamHandle);

impl Pam {
    /// This allows sending the `Pam` handle to another thread.
    /// ```rust
    /// # use pamsm::Pam;
    /// # fn wrapper(pamh: &mut Pam) {
    /// std::thread::scope(|s| {
    ///     let borrowed = pamh.as_send_ref();
    ///     s.spawn(move || {
    ///          let pamh: &Pam = borrowed.into();
    ///     });
    /// });
    /// # }
    /// ```
    /// Synchronized across multiple threads:
    /// ```rust
    /// # use pamsm::Pam;
    /// # fn wrapper(pamh: &mut Pam) {
    /// std::thread::scope(|s| {
    ///     let shared_1 = std::sync::Arc::new(std::sync::Mutex::new(pamh.as_send_ref()));
    ///     let shared_2 = shared_1.clone();
    ///     s.spawn(move || {
    ///          let pamh: &Pam = &*shared_1.lock().unwrap();
    ///     });
    ///     s.spawn(move || {
    ///          let pamh: &Pam = &*shared_2.lock().unwrap();
    ///     });
    /// });
    /// # }
    /// ```
    pub fn as_send_ref(&mut self) -> PamSendRef<'_> {
        PamSendRef(self)
    }
}

impl<'a> From<&'a mut Pam> for PamSendRef<'a> {
    fn from(value: &'a mut Pam) -> Self {
        Self(value)
    }
}

/// This sendable reference to [`Pam`] can be created via [`Pam::as_send_ref`] or `From`/`Into`.
pub struct PamSendRef<'a>(&'a mut Pam);

unsafe impl<'a> Send for PamSendRef<'a> {}

impl std::ops::Deref for PamSendRef<'_> {
    type Target = Pam;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> From<PamSendRef<'a>> for &'a mut Pam {
    fn from(value: PamSendRef<'a>) -> Self {
        value.0
    }
}

impl<'a> From<PamSendRef<'a>> for &'a Pam {
    fn from(value: PamSendRef<'a>) -> Self {
        value.0
    }
}

bitflags! {
    pub struct PamFlags : c_int {
        const DATA_REPLACE = 0x2000_0000;
        const SILENT = 0x8000;
        const DISALLOW_NULL_AUTHTOK = 0x0001;
        const ESTABLISH_CRED = 0x0002;
        const DELETE_CRED = 0x0004;
        const REINITIALIZE_CRED = 0x0008;
        const REFRESH_CRED = 0x0010;
        const CHANGE_EXPIRED_AUTHTOK = 0x0020;
    }
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

macro_rules! int_enum {
    ( $name:ident ($ukey:ident = $uvalue:expr) {
        $( $key:ident = $value:expr ),*
    }) => {
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub enum $name {
            $( $key = $value, )*
            $ukey = $uvalue,
        }
        impl $name {
            #[cfg(feature = "libpam")]
            pub(crate) fn new(r: c_int) -> $name {
                match r {
                    $( $value => $name::$key, )*
                    _ => $name::$ukey,
                }
            }
        }
    }
}

int_enum! {
    PamError (UNKNOWN_RESULT = -1) {
        SUCCESS    = 0,		/* Successful function return */
        OPEN_ERR   = 1,		/* dlopen() failure when dynamically */
        SYMBOL_ERR     = 2,	/* Symbol not found */
        SERVICE_ERR    = 3,	/* Error in service module */
        SYSTEM_ERR     = 4,	/* System error */
        BUF_ERR    = 5,		/* Memory buffer error */
        PERM_DENIED    = 6,	/* Permission denied */
        AUTH_ERR   = 7,		/* Authentication failure */
        CRED_INSUFFICIENT  = 8,	/* Can not access authentication data */
        AUTHINFO_UNAVAIL   = 9,	/* Underlying authentication service can not retrieve authentication information  */
        USER_UNKNOWN   = 10,	/* User not known to the underlying authenticaiton module */
        MAXTRIES   = 11,		/* An authentication service has maintained a retry count which has been reached. No further retries should be attempted */
        NEW_AUTHTOK_REQD   = 12,	/* New authentication token required. */
        ACCT_EXPIRED   = 13,	/* User account has expired */
        SESSION_ERR    = 14,	/* Can not make/remove an entry for the specified session */
        CRED_UNAVAIL   = 15,	/* Underlying authentication service can not retrieve user credentials */
        CRED_EXPIRED   = 16,	/* User credentials expired */
        CRED_ERR   = 17,		/* Failure setting user credentials */
        NO_MODULE_DATA     = 18,	/* No module specific data is present */
        CONV_ERR   = 19,		/* Conversation error */
        AUTHTOK_ERR    = 20,	/* Authentication token manipulation error */
        AUTHTOK_RECOVERY_ERR   = 21, /* Authentication information cannot be recovered */
        AUTHTOK_LOCK_BUSY  = 22,   /* Authentication token lock busy */
        AUTHTOK_DISABLE_AGING  = 23, /* Authentication token aging disabled */
        TRY_AGAIN  = 24,	/* Preliminary check by password service */
        IGNORE     = 25,		/* Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient */
        ABORT  = 26,            /* Critical error (?module fail now request) */
        AUTHTOK_EXPIRED    = 27, /* user's authentication token has expired */
        MODULE_UNKNOWN     = 28, /* module is not known */
        BAD_ITEM           = 29, /* Bad item passed to *_item() */
        CONV_AGAIN         = 30, /* conversation function is event driven and data is not available yet */
        INCOMPLETE         = 31 /* please call this function again to complete authentication stack. Before calling again, verify that conversation is completed */
    }
}

/// Default service module implementation.
/// All default functions return SERVICE_ERR.
/// You can override functions depending on what kind of module you implement.
/// See the respective pam_sm_* man pages for documentation.
pub trait PamServiceModule {
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn close_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn authenticate(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn acct_mgmt(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn chauthtok(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }
}

/// Define entrypoints for the PAM module.
///
/// This macro must be called exactly once in a PAM module.
/// It then exports all the pam_sm_* symbols.
///
/// The argument to the macro is a type implementing the
/// `PamServiceModule` trait.
///
/// # Example
///
/// ```ignore
/// // lib.rs
/// #[macro_use] extern crate pamsm;
///
/// pam_module!(MyPamService);
/// ```
#[macro_export]
macro_rules! pam_module {
    ($pamsm_ty:ty) => {
        // Check trait bound on input type.
        fn _check_pamsm_trait<T: pamsm::PamServiceModule>() {}
        fn _t() {
            _check_pamsm_trait::<$pamsm_ty>()
        }

        // Callback entry definition.
        macro_rules! pam_callback {
            ($pam_cb:ident, $rust_cb:ident) => {
                #[no_mangle]
                #[doc(hidden)]
                pub unsafe extern "C" fn $pam_cb(
                    pamh: pamsm::Pam,
                    flags: std::os::raw::c_int,
                    argc: std::os::raw::c_int,
                    argv: *const *const std::os::raw::c_char,
                ) -> std::os::raw::c_int {
                    use std::os::raw::c_int;
                    if argc < 0 {
                        return pamsm::PamError::SERVICE_ERR as std::os::raw::c_int;
                    }

                    let mut args = Vec::<String>::with_capacity(argc as usize);
                    for count in 0..(argc as isize) {
                        match {
                            std::ffi::CStr::from_ptr(
                                *argv.offset(count) as *const std::os::raw::c_char
                            )
                            .to_str()
                        } {
                            Ok(s) => args.push(s.to_owned()),
                            Err(_) => return pamsm::PamError::SERVICE_ERR as c_int,
                        };
                    }
                    <$pamsm_ty>::$rust_cb(pamh, pamsm::PamFlags::from_bits_unchecked(flags), args) as c_int
                }
            };
        }

        pam_callback!(pam_sm_open_session, open_session);
        pam_callback!(pam_sm_close_session, close_session);
        pam_callback!(pam_sm_authenticate, authenticate);
        pam_callback!(pam_sm_setcred, setcred);
        pam_callback!(pam_sm_acct_mgmt, acct_mgmt);
        pam_callback!(pam_sm_chauthtok, chauthtok);
    };
}
