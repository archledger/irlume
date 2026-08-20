#![allow(dead_code)]

use pam::{Pam, PamError, PamFlags};
use pam_types::{LogLvl, PamConv, PamHandle, PamItemType, PamMessage, PamMsgStyle, PamResponse};
use std::ffi::{CStr, CString, NulError};
use std::ops::Deref;
use std::option::Option;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

pub type PamResult<T> = Result<T, PamError>;
/// Prototype of the callback used with [`PamLibExt::send_bytes`]
pub type PamCleanupCb = fn(&Vec<u8>, Pam, PamFlags, PamError);

#[derive(Clone)]
struct PamByteData {
    cb: Option<PamCleanupCb>,
    data: Vec<u8>,
}

/// Trait to implement for data stored with pam using [`PamLibExt::send_data`]
/// in order to provide a cleanup callback.
/// # Example
/// ```
/// extern crate pamsm;
/// use pamsm::{Pam, PamData, PamError, PamFlags};
/// use std::fs::write;
///
/// struct Token([u8; 32]);
///
/// impl PamData for Token {
///     fn cleanup(&self, _pam: Pam, flags: PamFlags, status: PamError) {
///         if !flags.contains(PamFlags::DATA_REPLACE) && status == PamError::SUCCESS {
///             match write(".token.bin", self.0) {
///                 Ok(_) => (),
///                 Err(err) => {
///                     if !flags.contains(PamFlags::SILENT) {
///                         println!("Error persisting token : {:?}", err);
///                     }
///                 }
///             };
///         }
///     }
/// }
/// ```
pub trait PamData {
    /// The cleanup method will be called before the data is dropped by pam.
    /// See `pam_set_data (3)`
    fn cleanup(&self, _pam: Pam, _flags: PamFlags, _status: PamError) {}
}

impl PamData for PamByteData {
    fn cleanup(&self, pam: Pam, flags: PamFlags, status: PamError) {
        if let Some(cb) = self.cb {
            (cb)(&self.data, pam, flags, status);
        }
    }
}

/// Blanket implementation for types that implement `Deref<T>` when `T` implements `PamData`.
impl<T: PamData, U> PamData for U
where
    U: Deref<Target = T>,
{
    fn cleanup(&self, pam: Pam, flags: PamFlags, status: PamError) {
        T::cleanup(self, pam, flags, status)
    }
}

impl PamError {
    fn to_result<T>(self, ok: T) -> PamResult<T> {
        if self == PamError::SUCCESS {
            Ok(ok)
        } else {
            Err(self)
        }
    }
}

/// This contains a private marker trait, used to seal private traits.
mod private {
    pub trait Sealed {}
    impl Sealed for super::Pam {}
}

impl Pam {
    // End users should call the item specific methods
    fn get_cstr_item(&self, item_type: PamItemType) -> PamResult<Option<&CStr>> {
        match item_type {
            PamItemType::CONV | PamItemType::FAIL_DELAY | PamItemType::XAUTHDATA => {
                panic!("Error, get_cstr_item can only be used with pam item returning c-strings")
            }
            _ => (),
        }
        let mut raw_item: *const c_void = ptr::null();
        let r = unsafe { PamError::new(pam_get_item(self.0, item_type as c_int, &mut raw_item)) };
        if raw_item.is_null() {
            r.to_result(None)
        } else {
            // pam should keep the underlying token allocated during the lifetime of the module
            r.to_result(Some(unsafe { CStr::from_ptr(raw_item as *const c_char) }))
        }
    }
}

/// Extension trait over `Pam`, usually provided by the `libpam` shared library.
pub trait PamLibExt: private::Sealed {
    /// Get the username. If the PAM_USER item is not set, this function
    /// prompts for a username (like get_authtok).
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    /// Get the username, i.e. the PAM_USER item. If it's not set return None.
    fn get_cached_user(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token.
    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached old authentication token.
    fn get_cached_oldauthtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token or prompt the user for one if there isn't any.
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    fn set_authtok(&self, authtok: &CString) -> PamResult<()>;

    /// Remove the cached authentication token from this PAM transaction.
    ///
    /// # Errors
    ///
    /// Returns the error reported by `pam_set_item` when PAM cannot clear the
    /// token.
    fn clear_authtok(&self) -> PamResult<()>;

    /// Get the remote hostname.
    fn get_rhost(&self) -> PamResult<Option<&CStr>>;

    /// Get the remote username.
    fn get_ruser(&self) -> PamResult<Option<&CStr>>;

    /// Get the service name.
    fn get_service(&self) -> PamResult<Option<&CStr>>;

    /// Prompt the user for custom input.
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn conv(&self, prompt: Option<&str>, style: PamMsgStyle) -> PamResult<Option<&CStr>>;

    /// Get a variable from the pam environment list.
    fn getenv(&self, name: &str) -> PamResult<Option<&CStr>>;

    /// Put a variable in the pam environment list.
    /// `name_value` takes for form documented in pam_putent(3) :
    ///
    /// - `NAME=value` will set variable `NAME` to value `value`
    /// - `NAME=` will set variable `NAME` to an empty value
    /// - `NAME` will unset the variable `NAME`
    fn putenv(&self, name_value: &str) -> PamResult<()>;

    /// Send data to be stored by the pam library under the name `module_name`.
    /// The data can then be retrieved from a different
    /// callback in this module, or even by a different module
    /// using [`retrieve_data<T>`][Self::retrieve_data].
    ///
    /// When this method is called a second time with the same `module_name`, the method
    /// [`PamData::cleanup`] is called on the data previously stored.
    /// The same happens when the application calls `pam_end (3)`
    ///
    /// If your data can be converted into / from [`Vec<u8>`][std::vec::Vec]
    /// you should consider using the [`send_bytes`][Self::send_bytes] method instead.
    ///
    /// # Safety
    /// This method should not be used if the [`send_bytes`][Self::send_bytes] method is also used
    /// with the same `module_name`.
    unsafe fn send_data<T: PamData + Clone + Send>(
        &self,
        module_name: &str,
        data: T,
    ) -> PamResult<()>;

    /// Retrieve data previously stored with [`send_data<T>`][Self::send_data].
    ///
    /// Note that the result is a _copy_ of the data and not a shared reference,
    /// which differs from the behavior of the underlying `pam_get_data (3)` function.
    ///
    /// If you want to share the data instead you can wrap it in [`Arc`][std::sync::Arc].
    /// # Safety
    /// The type parameter `T` must be the same as the one used in
    /// [`send_data<T>`][Self::send_data] with the name `module_name`.
    ///
    /// If the data was stored with [`send_bytes`][Self::send_bytes] you must use
    /// [`retrieve_bytes`][Self::retrieve_bytes] instead.
    unsafe fn retrieve_data<T: PamData + Clone + Send>(&self, module_name: &str) -> PamResult<T>;

    /// Similar to [`send_data`][Self::send_data], but only works with [`Vec<u8>`][std::vec::Vec].
    /// The PamData trait doesn't have to be implemented on the data, a callback can be passed
    /// as an argument instead.
    fn send_bytes(
        &self,
        module_name: &str,
        data: Vec<u8>,
        cb: Option<PamCleanupCb>,
    ) -> PamResult<()>;

    /// Retrieve bytes previously stored with [`send_bytes`][Self::send_bytes].
    /// The result is a clone of the data.
    fn retrieve_bytes(&self, module_name: &str) -> PamResult<Vec<u8>>;

    /// Send a message to syslog.
    fn syslog(&self, lvl: LogLvl, msg: &str) -> PamResult<()>;
}

impl From<NulError> for PamError {
    fn from(_: NulError) -> PamError {
        PamError::SERVICE_ERR
    }
}

impl PamLibExt for Pam {
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = match prompt {
            None => None,
            Some(p) => Some(CString::new(p)?),
        };
        let mut raw_user: *const c_char = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_user(
                self.0,
                &mut raw_user,
                cprompt.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            ))
        };

        if raw_user.is_null() {
            r.to_result(None)
        } else {
            r.to_result(Some(unsafe { CStr::from_ptr(raw_user) }))
        }
    }

    fn get_cached_user(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::USER)
    }

    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::AUTHTOK)
    }

    fn get_cached_oldauthtok(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::OLDAUTHTOK)
    }

    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = match prompt {
            None => None,
            Some(p) => Some(CString::new(p)?),
        };
        let mut raw_at: *const c_char = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_authtok(
                self.0,
                PamItemType::AUTHTOK as i32,
                &mut raw_at,
                cprompt.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            ))
        };

        if raw_at.is_null() {
            r.to_result(None)
        } else {
            r.to_result(unsafe { Some(CStr::from_ptr(raw_at)) })
        }
    }

    fn set_authtok(&self, authtok: &CString) -> PamResult<()> {
        unsafe {
            set_item(
                self.0,
                PamItemType::AUTHTOK,
                authtok.as_ptr() as *const c_void,
            )
        }
    }

    fn clear_authtok(&self) -> PamResult<()> {
        // SAFETY: `self.0` is the live handle supplied by libpam, AUTHTOK is a
        // string item, and Linux-PAM defines a null item pointer as clearing it.
        unsafe { set_item(self.0, PamItemType::AUTHTOK, ptr::null()) }
    }

    fn get_rhost(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::RHOST)
    }

    fn get_ruser(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::RUSER)
    }

    fn get_service(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::SERVICE)
    }

    fn conv(&self, prompt: Option<&str>, style: PamMsgStyle) -> PamResult<Option<&CStr>> {
        let mut conv_pointer: *const c_void = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_item(
                self.0,
                PamItemType::CONV as c_int,
                &mut conv_pointer,
            ))
        };

        if r != PamError::SUCCESS {
            return Err(r);
        }

        if conv_pointer.is_null() {
            return Ok(None);
        }

        let conv = unsafe { &*(conv_pointer as *const PamConv) };
        let mut resp_ptr: *mut PamResponse = ptr::null_mut();
        let msg_cstr = CString::new(prompt.unwrap_or(""))?;
        let msg = PamMessage {
            msg_style: style,
            msg: msg_cstr.as_ptr(),
        };

        match conv.cb.map(|cb| {
            PamError::new(cb(
                1,
                &mut (&msg as *const PamMessage),
                &mut resp_ptr,
                conv.appdata_ptr,
            ))
        }) {
            Some(PamError::SUCCESS) => {
                Ok(unsafe { (*resp_ptr).resp }.map(|r| unsafe { CStr::from_ptr(r.as_ptr()) }))
            }
            Some(ret) => Err(ret),
            None => Ok(None),
        }
    }

    fn getenv(&self, name: &str) -> PamResult<Option<&CStr>> {
        let cname = CString::new(name)?;
        let cenv = unsafe { pam_getenv(self.0, cname.as_ptr()) };

        if cenv.is_null() {
            Ok(None)
        } else {
            unsafe { Ok(Some(CStr::from_ptr(cenv))) }
        }
    }

    fn putenv(&self, name_value: &str) -> PamResult<()> {
        let cenv = CString::new(name_value)?;
        unsafe { PamError::new(pam_putenv(self.0, cenv.as_ptr())).to_result(()) }
    }

    unsafe fn send_data<T: PamData + Clone + Send>(
        &self,
        module_name: &str,
        data: T,
    ) -> PamResult<()> {
        // The data has to be allocated on the heap because it will outlive the call stack.
        let data_copy = Box::new(data);
        PamError::new(pam_set_data(
            self.0,
            CString::new(module_name)?.as_ptr(),
            Box::into_raw(data_copy) as *mut c_void,
            Some(pam_data_cleanup::<T>),
        ))
        .to_result(())
    }

    unsafe fn retrieve_data<T: PamData + Clone + Send>(&self, module_name: &str) -> PamResult<T> {
        let mut data_ptr: *const c_void = ptr::null();
        // pam_get_data should be safe as long as T is the type that what used in send_data.
        PamError::new(pam_get_data(
            self.0,
            CString::new(module_name)?.as_ptr(),
            &mut data_ptr,
        ))
        .to_result(data_ptr as *const T)
        .map(|ptr| (*ptr).clone()) // pam guaranties the data is valid when SUCCESS is returned.
    }

    fn send_bytes(
        &self,
        module_name: &str,
        data: Vec<u8>,
        cb: Option<PamCleanupCb>,
    ) -> PamResult<()> {
        let data_cb = PamByteData { cb, data };
        unsafe { self.send_data(module_name, data_cb) }
    }

    fn retrieve_bytes(&self, module_name: &str) -> PamResult<Vec<u8>> {
        unsafe { self.retrieve_data::<PamByteData>(module_name) }.map(|data_cb| data_cb.data)
    }

    fn syslog(&self, lvl: LogLvl, msg: &str) -> PamResult<()> {
        let fmt = b"%s\0".as_ptr() as *const c_char;
        let cmsg = CString::new(msg)?;
        unsafe {
            pam_syslog(self.0, lvl as c_int, fmt, cmsg.as_ptr());
        }
        Ok(())
    }
}

unsafe extern "C" fn pam_data_cleanup<T: PamData + Clone + Send>(
    handle: PamHandle,
    data: *mut c_void,
    error_status: c_int,
) {
    Box::from_raw(data as *mut T).cleanup(
        Pam(handle),
        PamFlags::from_bits_truncate(error_status),
        PamError::new(error_status & 0xff),
    );
}

unsafe fn set_item(pamh: PamHandle, item_type: PamItemType, item: *const c_void) -> PamResult<()> {
    PamError::new(pam_set_item(pamh, item_type as c_int, item)).to_result(())
}

// Raw functions
#[link(name = "pam")]
extern "C" {
    pub fn pam_set_item(pamh: PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    pub fn pam_get_item(pamh: PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    pub fn pam_strerror(pamh: PamHandle, errnum: c_int) -> *const c_char;
    pub fn pam_putenv(pamh: PamHandle, name_value: *const c_char) -> c_int;
    pub fn pam_getenv(pamh: PamHandle, name: *const c_char) -> *const c_char;
    pub fn pam_getenvlist(pamh: PamHandle) -> *mut *mut c_char;

    pub fn pam_set_data(
        pamh: PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<unsafe extern "C" fn(_: PamHandle, _: *mut c_void, _: c_int)>,
    ) -> c_int;
    pub fn pam_get_data(
        pamh: PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
    pub fn pam_get_user(pamh: PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    pub fn pam_get_authtok(
        pamh: PamHandle,
        item: c_int,
        authok_ptr: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    pub fn pam_syslog(pamh: PamHandle, priority: c_int, fmt: *const c_char, ...) -> c_void;
}
