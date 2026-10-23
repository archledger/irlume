// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Observe the real ort builder against its supplied stub API, in fresh children.

use super::*;
use ort::sys;
use std::ffi::{c_char, c_void, CStr};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

static MODE: AtomicUsize = AtomicUsize::new(0);
static APPENDS: AtomicUsize = AtomicUsize::new(0);
static SELECTED: AtomicUsize = AtomicUsize::new(0);
static CREATED: AtomicUsize = AtomicUsize::new(0);
static INHERITED: AtomicUsize = AtomicUsize::new(0);
static AUTOMATIC_CPU: AtomicUsize = AtomicUsize::new(0);
static ENV: u8 = 0;
static OPTIONS: u8 = 0;
static FIRST: u8 = 0;
static SECOND: u8 = 0;

fn failure(message: &str) -> sys::OrtStatusPtr {
    sys::stub::Error::new_sys(sys::OrtErrorCode::ORT_FAIL, message)
}

unsafe extern "system" fn create_status(
    code: sys::OrtErrorCode,
    message: *const c_char,
) -> sys::OrtStatusPtr {
    // The native CreateStatus contract copies a borrowed message. The pinned
    // stub instead takes ownership, so replace that callback in this test API.
    // SAFETY: ort passes a live NUL-terminated message for this call.
    let message = unsafe { CStr::from_ptr(message) }.to_string_lossy();
    sys::stub::Error::new_sys(code, message)
}

unsafe extern "system" fn create_env(
    _: sys::OrtLoggingLevel,
    _: *const c_char,
    out: *mut *mut sys::OrtEnv,
) -> sys::OrtStatusPtr {
    if MODE.load(SeqCst) == 1 {
        return failure("test environment unavailable");
    }
    // SAFETY: ort supplies a writable out-pointer; this opaque handle is never dereferenced.
    unsafe { *out = std::ptr::addr_of!(ENV).cast_mut().cast() };
    sys::OrtStatusPtr::default()
}

unsafe extern "system" fn create_options(
    out: *mut *mut sys::OrtSessionOptions,
) -> sys::OrtStatusPtr {
    // SAFETY: ort supplies a writable out-pointer; stub release functions do not free it.
    unsafe { *out = std::ptr::addr_of!(OPTIONS).cast_mut().cast() };
    sys::OrtStatusPtr::default()
}

unsafe extern "system" fn devices(
    _: *const sys::OrtEnv,
    out: *mut *const *const sys::OrtEpDevice,
    count: *mut usize,
) -> sys::OrtStatusPtr {
    let mode = MODE.load(SeqCst);
    if mode == 2 {
        return failure("test enumeration unavailable");
    }
    // The tiny pointer table lives for this child process. The API borrows it
    // across enumeration and registration; no fake handle is dereferenced.
    let pointers = Box::leak(Box::new([
        std::ptr::addr_of!(FIRST).cast::<sys::OrtEpDevice>(),
        std::ptr::addr_of!(SECOND).cast::<sys::OrtEpDevice>(),
    ]));
    // SAFETY: both out-pointers come from ort and pointers retains the returned table.
    unsafe {
        *out = pointers.as_ptr();
        *count = match mode {
            3 => 0,
            0 | 7 => 2,
            _ => 1,
        };
    }
    sys::OrtStatusPtr::default()
}

unsafe extern "system" fn ep_name(device: *const sys::OrtEpDevice) -> *const c_char {
    match MODE.load(SeqCst) {
        0 if device == std::ptr::addr_of!(FIRST).cast() => c"OtherCpuProvider".as_ptr(),
        4 => c"OtherCpuProvider".as_ptr(),
        9 => c"\xff".as_ptr(),
        _ => c"CPUExecutionProvider".as_ptr(),
    }
}

unsafe extern "system" fn ep_vendor(_: *const sys::OrtEpDevice) -> *const c_char {
    match MODE.load(SeqCst) {
        5 => c"OtherVendor".as_ptr(),
        10 => c"\xff".as_ptr(),
        _ => c"Microsoft".as_ptr(),
    }
}

unsafe extern "system" fn hardware(
    device: *const sys::OrtEpDevice,
) -> *const sys::OrtHardwareDevice {
    device.cast()
}

unsafe extern "system" fn device_type(
    _: *const sys::OrtHardwareDevice,
) -> sys::OrtHardwareDeviceType {
    if MODE.load(SeqCst) == 6 {
        sys::OrtHardwareDeviceType::OrtHardwareDeviceType_GPU
    } else {
        sys::OrtHardwareDeviceType::OrtHardwareDeviceType_CPU
    }
}

unsafe extern "system" fn append(
    _: *mut sys::OrtSessionOptions,
    _: *mut sys::OrtEnv,
    devices: *const *const sys::OrtEpDevice,
    count: usize,
    _: *const *const c_char,
    _: *const *const c_char,
    options: usize,
) -> sys::OrtStatusPtr {
    APPENDS.fetch_add(1, SeqCst);
    if count != 1 || options != 0 {
        return failure("test requires one exact CPU with unchanged options");
    }
    // SAFETY: ort supplies an array of count valid device pointers; count is one.
    SELECTED.store(unsafe { *devices } as usize, SeqCst);
    if MODE.load(SeqCst) == 8 {
        return failure("test CPU registration unavailable");
    }
    sys::OrtStatusPtr::default()
}

unsafe extern "system" fn policy(
    _: *mut sys::OrtSessionOptions,
    policy: sys::OrtExecutionProviderDevicePolicy,
) -> sys::OrtStatusPtr {
    if policy == sys::OrtExecutionProviderDevicePolicy::OrtExecutionProviderDevicePolicy_PREFER_CPU
    {
        AUTOMATIC_CPU.fetch_add(1, SeqCst);
    }
    sys::OrtStatusPtr::default()
}

unsafe extern "system" fn inherited(_: *mut sys::OrtSessionOptions) -> sys::OrtStatusPtr {
    INHERITED.fetch_add(1, SeqCst);
    failure("test inherited provider reached")
}

unsafe extern "system" fn create_session(
    _: *const sys::OrtEnv,
    _: *const c_void,
    _: usize,
    _: *const sys::OrtSessionOptions,
    _: *mut *mut sys::OrtSession,
) -> sys::OrtStatusPtr {
    CREATED.fetch_add(1, SeqCst);
    // No graph is executed; a successful configuration reaches this known refusal.
    failure("test session creation reached")
}

fn exercise(mode: usize) {
    MODE.store(mode, SeqCst);
    let mut api = sys::stub::api();
    api.CreateStatus = create_status;
    api.CreateEnv = create_env;
    api.CreateSessionOptions = create_options;
    api.GetEpDevices = devices;
    api.EpDevice_EpName = ep_name;
    api.EpDevice_EpVendor = ep_vendor;
    api.EpDevice_Device = hardware;
    api.HardwareDevice_Type = device_type;
    api.SessionOptionsAppendExecutionProvider_V2 = append;
    api.SessionOptionsSetEpSelectionPolicy = policy;
    api.EnableCpuMemArena = inherited;
    api.CreateSessionFromArray = create_session;
    assert!(ort::set_api(api));
    assert!(ort::init()
        .with_execution_providers([ort::ep::CPU::default()
            .with_arena_allocator(true)
            .build()
            .error_on_failure()])
        .commit());
    let result = session_options(&SMALL_POOL);
    if mode == 0 {
        let error = result.unwrap().commit_from_memory(&[]).err().unwrap();
        assert!(error.to_string().contains("test session creation reached"));
        assert_eq!(APPENDS.load(SeqCst), 1);
        assert_eq!(SELECTED.load(SeqCst), std::ptr::addr_of!(SECOND) as usize);
        assert_eq!(CREATED.load(SeqCst), 1);
    } else {
        assert!(
            result.is_err(),
            "case {mode} must refuse before committing a session"
        );
        assert_eq!(CREATED.load(SeqCst), 0);
        assert_eq!(APPENDS.load(SeqCst), usize::from(mode == 8));
    }
    assert_eq!(INHERITED.load(SeqCst), 0);
    assert_eq!(
        AUTOMATIC_CPU.load(SeqCst),
        0,
        "no PreferCPU fallback in evidence builds"
    );
}

#[test]
fn exact_cpu_selection_refuses_missing_ambiguous_and_failed_devices() {
    const TEST: &str = "onnx::reference_isolation_api_tests::exact_cpu_selection_refuses_missing_ambiguous_and_failed_devices";
    const CASE: &str = "IRLUME_TEST_REFERENCE_API_CASE";
    if let Ok(mode) = std::env::var(CASE) {
        exercise(mode.parse().unwrap());
        return;
    }
    for mode in 0..=10 {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CASE, mode.to_string())
            .env_remove("IRLUME_TEST_ALLOW_UNCERTIFIED_EP")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {mode}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}
