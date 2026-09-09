// SPDX-License-Identifier: GPL-3.0-or-later
//! Private, non-setuid local-password verifier. Linux-PAM ABI follows
//! security/pam_appl.h and pam_conv(3). The root daemon bounds its lifetime,
//! supplies a cleared environment, and owns stdin/stdout/stderr pipes.
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;
use std::ptr;
use zeroize::Zeroizing;

const UNAVAILABLE: u8 = 2;
const PAM_CONV_ERR: libc::c_int = 19;
const PAM_BUF_ERR: libc::c_int = 5;
const PAM_USER: libc::c_int = 2;
const PAM_FLAGS: libc::c_int = 0x8000 | 1; // SILENT | DISALLOW_NULL_AUTHTOK

#[repr(C)]
struct Message {
    style: libc::c_int,
    text: *const libc::c_char,
}
#[repr(C)]
struct Response {
    text: *mut libc::c_char,
    code: libc::c_int,
}
#[repr(C)]
struct Conversation {
    callback: unsafe extern "C" fn(
        libc::c_int,
        *const *const Message,
        *mut *mut Response,
        *mut libc::c_void,
    ) -> libc::c_int,
    data: *mut libc::c_void,
}
#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const libc::c_char,
        user: *const libc::c_char,
        conv: *const Conversation,
        handle: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn pam_authenticate(handle: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    fn pam_acct_mgmt(handle: *mut libc::c_void, flags: libc::c_int) -> libc::c_int;
    fn pam_get_item(
        handle: *mut libc::c_void,
        item: libc::c_int,
        value: *mut *const libc::c_void,
    ) -> libc::c_int;
    fn pam_end(handle: *mut libc::c_void, status: libc::c_int) -> libc::c_int;
}

struct Exchange<'a> {
    secret: &'a [u8],
    prompted: bool,
    failed: bool,
}

// PAM modules are trusted native code. Linux-PAM supplies an array of count
// valid message pointers, a writable response pointer and our live Exchange.
// On success PAM owns calloc allocations and must scrub/free responses; on
// failure we retain ownership and release every allocation before returning.
unsafe extern "C" fn converse(
    count: libc::c_int,
    messages: *const *const Message,
    output: *mut *mut Response,
    data: *mut libc::c_void,
) -> libc::c_int {
    if data.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: pam_start receives the unique Exchange pointer, live through pam_end.
    let exchange = unsafe { &mut *data.cast::<Exchange<'_>>() };
    let previous_failure = exchange.failed;
    exchange.failed = true;
    if output.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: the callback contract supplies a writable response pointer.
    unsafe {
        *output = ptr::null_mut();
    }
    if previous_failure {
        return PAM_CONV_ERR;
    }
    if !(1..=32).contains(&count) || messages.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: Linux-PAM supplies count message pointers; count was bounded above.
    let messages = unsafe { std::slice::from_raw_parts(messages, count as usize) };
    let mut password_index = None;
    for (index, message) in messages.iter().enumerate() {
        if message.is_null() {
            return PAM_CONV_ERR;
        }
        // SAFETY: each non-null message pointer is valid for the callback.
        match unsafe { (**message).style } {
            1 if !exchange.prompted && password_index.is_none() => password_index = Some(index),
            3 | 4 => {} // Discard informational/error text without copying or printing it.
            _ => return PAM_CONV_ERR,
        }
    }
    // SAFETY: bounded positive count and correct C layout; calloc is free-compatible.
    let responses =
        unsafe { libc::calloc(count as usize, size_of::<Response>()).cast::<Response>() };
    if responses.is_null() {
        return PAM_BUF_ERR;
    }
    if let Some(index) = password_index {
        // SAFETY: secret length is <=4096; calloc reserves its NUL terminator.
        let password = unsafe { libc::calloc(exchange.secret.len() + 1, 1).cast::<u8>() };
        if password.is_null() {
            // SAFETY: responses is our live allocation; no child allocations exist.
            unsafe {
                libc::free(responses.cast());
            }
            return PAM_BUF_ERR;
        }
        // SAFETY: source and destination are disjoint and valid for the bounded
        // length; index is within the response allocation. PAM assumes ownership.
        unsafe {
            ptr::copy_nonoverlapping(exchange.secret.as_ptr(), password, exchange.secret.len());
            (*responses.add(index)).text = password.cast();
        }
        exchange.prompted = true;
    }
    // SAFETY: output is writable; ownership passes to the PAM caller on success.
    unsafe {
        *output = responses;
    }
    exchange.failed = false;
    0
}

fn verify(user: &CStr, secret: &[u8]) -> u8 {
    let mut exchange = Exchange {
        secret,
        prompted: false,
        failed: false,
    };
    let conv = Conversation {
        callback: converse,
        data: (&mut exchange as *mut Exchange<'_>).cast(),
    };
    let mut handle = ptr::null_mut();
    // SAFETY: strings and conversation remain live until pam_end; handle is writable.
    let start = unsafe {
        pam_start(
            c"irlume-retry-reset".as_ptr(),
            user.as_ptr(),
            &conv,
            &mut handle,
        )
    };
    if start != 0 || handle.is_null() {
        return UNAVAILABLE;
    }
    // SAFETY: pam_start succeeded and handle remains exclusively owned here.
    let mut status = unsafe { pam_authenticate(handle, PAM_FLAGS) };
    if status == 0 {
        // SAFETY: the same live authenticated transaction is used for account policy.
        status = unsafe { pam_acct_mgmt(handle, PAM_FLAGS) };
    }
    let mut identity = ptr::null();
    // SAFETY: live handle and writable item output; PAM owns the returned string.
    let identity_status = unsafe { pam_get_item(handle, PAM_USER, &mut identity) };
    let identity_matches = identity_status == 0 && !identity.is_null()
        // SAFETY: PAM_USER is a NUL-terminated string owned by this live handle.
        && unsafe { CStr::from_ptr(identity.cast()) } == user;
    // SAFETY: release this successful pam_start exactly once, with its last status.
    // Cleanup callbacks may converse, so inspect the latched failure only AFTER
    // pam_end. The borrowed identity was compared before the handle was freed.
    if unsafe { pam_end(handle, status) } != 0 {
        return UNAVAILABLE;
    }
    if exchange.failed || !identity_matches {
        UNAVAILABLE
    } else if status == 0 {
        if exchange.prompted {
            0
        } else {
            UNAVAILABLE
        }
    } else if matches!(status, 6..=8 | 10..=13 | 16 | 27) {
        1
    } else {
        UNAVAILABLE
    }
}

unsafe extern "C" fn timeout(_: libc::c_int) {
    // SAFETY: _exit is async-signal-safe; no core or credential diagnostics.
    // Rust destructors cannot safely run in a signal handler. The kernel
    // reclaims the process's memory; ordinary returns scrub owned input.
    unsafe {
        libc::_exit(UNAVAILABLE.into());
    }
}

fn run() -> u8 {
    // SAFETY: getuid/geteuid are memory-free queries. Both must be root so a
    // mistakenly setuid-installed binary never authenticates an ordinary caller.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return UNAVAILABLE;
    }
    // SAFETY: PR_SET_DUMPABLE accepts a scalar zero; prevents credential core dumps.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return UNAVAILABLE;
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointer; only lowering this process's core limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return UNAVAILABLE;
    }
    // SAFETY: zero initializes sigaction; sigemptyset initializes its mask;
    // the handler uses only async-signal-safe _exit. No other threads exist.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = timeout as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGALRM, &action, ptr::null_mut()) != 0 {
            return UNAVAILABLE;
        }
        let mut alarm_mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut alarm_mask);
        libc::sigaddset(&mut alarm_mask, libc::SIGALRM);
        if libc::sigprocmask(libc::SIG_UNBLOCK, &alarm_mask, ptr::null_mut()) != 0 {
            return UNAVAILABLE;
        }
        libc::alarm(10);
    }
    let mut args = std::env::args_os().skip(1);
    let Some(user) = args.next() else {
        return UNAVAILABLE;
    };
    if args.next().is_some() || user.is_empty() || user.as_bytes().len() > 256 {
        return UNAVAILABLE;
    }
    let Ok(user) = CString::new(user.as_bytes()) else {
        return UNAVAILABLE;
    };
    // Fixed allocation avoids realloc leaving old secret copies unsanitized.
    let mut secret = Zeroizing::new([0u8; 4097]);
    let mut length = 0;
    loop {
        let remaining = &mut secret[length..];
        // SAFETY: stdin is the inherited input descriptor; remaining is a live,
        // exclusively borrowed writable slice for exactly the supplied length.
        // A direct read avoids std::io::Stdin's unsanitized global input buffer.
        let read = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                remaining.as_mut_ptr().cast(),
                remaining.len(),
            )
        };
        if read == 0 {
            break;
        }
        if read < 0 {
            // An interrupted read transfers no bytes. Retry within the existing
            // SIGALRM deadline; every other OS error makes recovery unavailable.
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return UNAVAILABLE;
        }
        // read(2) returns at most remaining.len(), so this addition stays within
        // the fixed allocation; the extra byte detects an oversized input.
        length += read as usize;
        if length > 4096 {
            return UNAVAILABLE;
        }
    }
    if length == 0 || secret[..length].contains(&0) {
        return UNAVAILABLE;
    }
    verify(&user, &secret[..length])
}

fn main() -> ExitCode {
    ExitCode::from(run())
}
