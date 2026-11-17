// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Metadata-only observation of the real reply encoder's output allocation.
//!
//! Allocator callbacks never inspect payload bytes. Live-output and explicit
//! wipe checks use the returned initialized slice, not allocation capacity.
//! This is not an at-free wipe witness or a normal-allocator recovery test.

#[path = "../src/reply_encoding.rs"]
mod reply_encoding;

use irlume_common::{KeyringSecretKind, Response, SecretBytes};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicPtr, AtomicUsize, Ordering};
use zeroize::Zeroize;

struct ObservedSystem;

#[global_allocator]
static ALLOCATOR: ObservedSystem = ObservedSystem;

static OWNER: AtomicIsize = AtomicIsize::new(0);
static NOMINATED: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static SIZE: AtomicUsize = AtomicUsize::new(0);
static ALIGN: AtomicUsize = AtomicUsize::new(0);
static MOVES: AtomicUsize = AtomicUsize::new(0);
static RELEASES: AtomicUsize = AtomicUsize::new(0);
static REJECT_NEXT: AtomicBool = AtomicBool::new(false);
static REJECTIONS: AtomicUsize = AtomicUsize::new(0);
static FOLLOW_ON_SUCCESSES: AtomicUsize = AtomicUsize::new(0);

fn thread_id() -> isize {
    // SAFETY: Linux gettid takes no pointer arguments. syscall's result and
    // isize have the same width on the Linux targets used by this crate.
    unsafe { libc::syscall(libc::SYS_gettid) as isize }
}

fn observing_this_thread() -> bool {
    let owner = OWNER.load(Ordering::SeqCst);
    owner > 0 && thread_id() == owner
}

fn nominate(pointer: *mut u8, layout: Layout) {
    if pointer.is_null() || !observing_this_thread() {
        return;
    }
    if REJECTIONS.load(Ordering::SeqCst) > 0 {
        FOLLOW_ON_SUCCESSES.fetch_add(1, Ordering::SeqCst);
    }
    if !NOMINATED.swap(true, Ordering::SeqCst) {
        CURRENT.store(pointer, Ordering::SeqCst);
        SIZE.store(layout.size(), Ordering::SeqCst);
        ALIGN.store(layout.align(), Ordering::SeqCst);
    }
}

fn reject_requested_allocation(layout: Layout) -> bool {
    if observing_this_thread() && REJECT_NEXT.swap(false, Ordering::SeqCst) {
        // This is a selected failed attempt, not a successful allocation.
        // Keep nomination sticky so later error bookkeeping is not selected.
        NOMINATED.store(true, Ordering::SeqCst);
        SIZE.store(layout.size(), Ordering::SeqCst);
        ALIGN.store(layout.align(), Ordering::SeqCst);
        REJECTIONS.fetch_add(1, Ordering::SeqCst);
        true
    } else {
        false
    }
}

// SAFETY: All successfully returned blocks originate from System. A nominated
// realloc uses GlobalAlloc's default allocate/copy/free contract.
// Tracking is metadata only; callbacks do not allocate Rust bookkeeping,
// interpret bytes, format, assert, lock or unwind.
unsafe impl GlobalAlloc for ObservedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if reject_requested_allocation(layout) {
            return ptr::null_mut();
        }
        // SAFETY: GlobalAlloc's caller supplies a valid nonzero layout.
        let pointer = unsafe { System.alloc(layout) };
        nominate(pointer, layout);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if reject_requested_allocation(layout) {
            return ptr::null_mut();
        }
        // SAFETY: The same caller contract holds for System::alloc_zeroed.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        nominate(pointer, layout);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if observing_this_thread() && CURRENT.load(Ordering::SeqCst) == pointer {
            CURRENT.store(ptr::null_mut(), Ordering::SeqCst);
            RELEASES.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: Every block originates from System, with the caller's matching
        // layout. Tracking never releases memory or dereferences the pointer.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !observing_this_thread() || CURRENT.load(Ordering::SeqCst) != pointer {
            // SAFETY: Forward the caller's valid realloc contract unchanged.
            return unsafe { System.realloc(pointer, layout, new_size) };
        }
        let Ok(replacement_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return ptr::null_mut();
        };
        // SAFETY: A valid realloc request has a nonzero, representable new size.
        // The old block remains allocated while the replacement is obtained.
        let replacement = unsafe { System.alloc(replacement_layout) };
        if replacement.is_null() {
            return replacement;
        }
        // SAFETY: The two live System allocations cannot overlap. Untyped copy
        // preserves initializedness, including any uninitialized spare bytes.
        // Neither this copy nor the callback interprets the payload as u8 values.
        unsafe {
            ptr::copy_nonoverlapping(pointer, replacement, layout.size().min(new_size));
        }
        CURRENT.store(replacement, Ordering::SeqCst);
        SIZE.store(new_size, Ordering::SeqCst);
        ALIGN.store(layout.align(), Ordering::SeqCst);
        MOVES.fetch_add(1, Ordering::SeqCst);
        // SAFETY: This is the original live System block and its original
        // layout. It is released exactly once, only after a successful copy.
        unsafe { System.dealloc(pointer, layout) };
        replacement
    }
}

#[derive(Clone, Copy, Default)]
struct Observation {
    nominated: bool,
    moves: usize,
    releases: usize,
    outstanding: bool,
    bytes: usize,
    rejections: usize,
    follow_on_successes: usize,
}

struct Observe;

impl Observe {
    fn begin() -> Self {
        // Warm the native selector before observation; never use a potentially
        // initializing std::thread::current() inside allocator callbacks.
        let owner = thread_id();
        assert!(owner > 0);
        assert_eq!(thread_id(), owner);
        assert_eq!(OWNER.load(Ordering::SeqCst), 0);
        NOMINATED.store(false, Ordering::SeqCst);
        CURRENT.store(ptr::null_mut(), Ordering::SeqCst);
        SIZE.store(0, Ordering::SeqCst);
        ALIGN.store(0, Ordering::SeqCst);
        MOVES.store(0, Ordering::SeqCst);
        RELEASES.store(0, Ordering::SeqCst);
        REJECT_NEXT.store(false, Ordering::SeqCst);
        REJECTIONS.store(0, Ordering::SeqCst);
        FOLLOW_ON_SUCCESSES.store(0, Ordering::SeqCst);
        OWNER.store(owner, Ordering::SeqCst);
        Self
    }

    fn owns(&self, bytes: &[u8], capacity: usize) -> bool {
        CURRENT.load(Ordering::SeqCst).cast_const() == bytes.as_ptr()
            && SIZE.load(Ordering::SeqCst) == capacity
            && ALIGN.load(Ordering::SeqCst) == 1
    }

    fn reject_next_allocation(&self) {
        assert!(!NOMINATED.load(Ordering::SeqCst));
        REJECT_NEXT.store(true, Ordering::SeqCst);
    }

    fn finish(self) -> Observation {
        let observation = Observation {
            nominated: NOMINATED.load(Ordering::SeqCst),
            moves: MOVES.load(Ordering::SeqCst),
            releases: RELEASES.load(Ordering::SeqCst),
            outstanding: !CURRENT.load(Ordering::SeqCst).is_null(),
            bytes: SIZE.load(Ordering::SeqCst),
            rejections: REJECTIONS.load(Ordering::SeqCst),
            follow_on_successes: FOLLOW_ON_SUCCESSES.load(Ordering::SeqCst),
        };
        drop(self);
        observation
    }
}

impl Drop for Observe {
    fn drop(&mut self) {
        // Metadata does not own memory. Disarming never releases a recorded
        // pointer; normal values retain responsibility for their allocations.
        OWNER.store(0, Ordering::SeqCst);
        REJECT_NEXT.store(false, Ordering::SeqCst);
        CURRENT.store(ptr::null_mut(), Ordering::SeqCst);
    }
}

fn moving_allocator_control() {
    let observation = Observe::begin();
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(b"control");
    let initial_address = bytes.as_ptr() as usize;
    bytes.reserve_exact(64);
    let moved = bytes.as_ptr() as usize != initial_address;
    let identity = observation.owns(&bytes, bytes.capacity());
    let contents = bytes == b"control";
    drop(bytes);
    let observed = observation.finish();

    assert!(observed.nominated && identity && contents);
    assert!(
        observed.moves > 0 && moved,
        "the test allocator must actually force distinct movement"
    );
    assert_eq!(observed.releases, 1);
    assert!(!observed.outstanding);
}

const PARTIAL_ROOM: &str = "room for a synthetic partial serialization output payload";

struct PartialFailure {
    calls: Cell<usize>,
    panic: bool,
}

impl serde::Serialize for PartialFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let call = self.calls.replace(self.calls.get() + 1);
        if call == 0 {
            return serializer.serialize_str(PARTIAL_ROOM);
        }
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&"synthetic prefix")?;
        assert!(!self.panic, "synthetic second-pass unwind");
        Err(serde::ser::Error::custom("synthetic second-pass error"))
    }
}

fn partial_failure_releases_the_output(panic: bool) {
    let input = PartialFailure {
        calls: Cell::new(0),
        panic,
    };
    let expected_bytes = PARTIAL_ROOM.len() + 3; // quotes and newline
    let observation = Observe::begin();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reply_encoding::prepare_line(&input)
    }));
    // Keep the returned error/panic payload alive through this snapshot. It
    // cannot masquerade as an already-released output allocation.
    let observed = observation.finish();
    let expected_failure = if panic {
        result.as_ref().err().is_some_and(|payload| {
            payload
                .downcast_ref::<&str>()
                .is_some_and(|text| *text == "synthetic second-pass unwind")
                || payload
                    .downcast_ref::<String>()
                    .is_some_and(|text| text == "synthetic second-pass unwind")
        })
    } else {
        matches!(&result, Ok(Err(_)))
    };
    drop(result);

    assert!(expected_failure);
    assert_eq!(input.calls.get(), 2);
    assert!(observed.nominated);
    assert_eq!(observed.bytes, expected_bytes);
    assert_eq!(observed.releases, 1);
    assert_eq!(observed.moves, 0);
    assert_eq!(observed.rejections, 0);
    assert!(!observed.outstanding);
}

fn reservation_failure_precedes_admission_and_socket_bytes() {
    let response = Response::Ok("synthetic reservation failure".into());
    let expected_bytes = serde_json::to_vec(&response).unwrap().len() + 1;
    let (server, mut client) = UnixStream::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    let mut admitted = false;
    let observation = Observe::begin();
    observation.reject_next_allocation();

    let result = reply_encoding::respond_admitted(server, &response, |_| {
        admitted = true;
        Ok(())
    });

    let rejected_was_nominated = NOMINATED.load(Ordering::SeqCst);
    let before_probe = FOLLOW_ON_SUCCESSES.load(Ordering::SeqCst);
    let mut bookkeeping = Vec::<u8>::new();
    let probe_succeeded = bookkeeping.try_reserve_exact(32).is_ok();
    let probe_capacity = bookkeeping.capacity();
    let probe_callback_seen = FOLLOW_ON_SUCCESSES.load(Ordering::SeqCst) > before_probe;
    // Keep the successful probe alive through the snapshot. It must neither
    // replace the failed nomination nor appear as a released output.
    let observed = observation.finish();
    drop(bookkeeping);
    assert!(!admitted, "failed preparation must precede admission");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 0);
    assert_eq!(observed.rejections, 1);
    assert!(rejected_was_nominated && observed.nominated);
    assert!(probe_succeeded && probe_capacity >= 32);
    assert!(
        probe_callback_seen,
        "observe the successful follow-on callback"
    );
    assert!(observed.follow_on_successes > 0);
    assert_eq!(observed.bytes, expected_bytes);
    assert_eq!(observed.moves, 0);
    assert_eq!(observed.releases, 0);
    assert!(!observed.outstanding);
}

#[test]
fn prepared_secret_output_never_reallocates() {
    // Only this test arms observation. The module's pure/socket controls may
    // run on other libtest threads and cannot nominate allocations here.
    moving_allocator_control();
    let responses = [
        Response::PasswordUnsealed {
            secret: SecretBytes::new(vec![255; 4096]),
            kind: KeyringSecretKind::LoginPassword,
        },
        Response::TokenSealed {
            token: SecretBytes::new(vec![255; 4096]),
            minted: true,
        },
    ];
    let mut observations = [Observation::default(); 2];
    let mut valid = [false; 2];
    for (index, response) in responses.iter().enumerate() {
        let mut expected = serde_json::to_vec(response).unwrap();
        expected.push(b'\n');
        let observation = Observe::begin();

        let mut line = reply_encoding::prepare_line(response).unwrap();
        let identity = observation.owns(&line, line.capacity());
        let exact_wire = line.as_slice() == expected.as_slice();
        let live_prefix = line.windows(11).any(|bytes| bytes == b"255,255,255");
        // This checks initialized live bytes only. Automatic cleanup on drop
        // and error is separately justified by Zeroizing's type and source.
        let live_length = line.len();
        line.as_mut_slice().zeroize();
        let live_wipe =
            live_length > 0 && line.len() == live_length && line.iter().all(|byte| *byte == 0);
        drop(line);

        observations[index] = observation.finish();
        valid[index] = identity && exact_wire && live_prefix && live_wipe;
    }
    for (observed, valid) in observations.iter().zip(valid) {
        assert!(
            observed.nominated && valid,
            "require the actual live output allocation"
        );
        assert_eq!(observed.releases, 1, "one terminal output release");
        assert!(
            !observed.outstanding,
            "the output must be dropped before disarming"
        );
    }
    assert_eq!(
        observations.map(|observed| observed.moves),
        [0, 0],
        "complete secret output preparation must not reallocate"
    );
    partial_failure_releases_the_output(false);
    partial_failure_releases_the_output(true);
    reservation_failure_precedes_admission_and_socket_bytes();
}
