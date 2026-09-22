// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Fault injection at the ioctl/mmap boundary; startup, Drop and fd close are real.
use super::super::*;
use std::{
    io::Read,
    os::{fd::IntoRawFd, unix::net::UnixStream},
    sync::{Arc, Mutex},
};

pub(crate) struct FakeDevice {
    format: (u32, u32),
    events: Vec<String>,
    fail: Option<&'static str>,
    writes: Vec<(u32, u32)>,
    mapped: usize,
    closes: usize,
    negotiated: Option<(u32, u32)>,
    failed_set_applies: bool,
    count: u32,
    length: Option<u32>,
    map_failure_at: Option<u32>,
    error_frame: bool,
    dequeued: bool,
    /// Scripted DQBUF flags, consumed before the one-shot `error_frame` path.
    frame_flags: std::collections::VecDeque<u32>,
    delivered: u32,
}

impl FakeDevice {
    fn new(format: (u32, u32)) -> Self {
        Self {
            format,
            events: Vec::new(),
            fail: None,
            writes: Vec::new(),
            mapped: 0,
            closes: 0,
            negotiated: None,
            failed_set_applies: false,
            count: 2,
            length: None,
            map_failure_at: None,
            error_frame: false,
            dequeued: false,
            frame_flags: std::collections::VecDeque::new(),
            delivered: 0,
        }
    }

    pub(crate) fn unmapped(&mut self) {
        assert!(self.mapped > 0, "unmap without a live metadata mapping");
        self.mapped -= 1;
        self.events.push("unmap".into());
    }

    pub(crate) fn view_created(&mut self) {
        self.events.push("view".into());
    }

    pub(crate) fn closed(&mut self) {
        self.closes += 1;
        self.events.push("close".into());
    }

    // SAFETY: the caller must pass the initialized, writable ABI type matching
    // request, just as required by the real ioctl boundary.
    pub(crate) unsafe fn ioctl(
        &mut self,
        request: libc::c_ulong,
        argp: *mut libc::c_void,
        what: &str,
    ) -> Result<(), String> {
        self.events.push(what.into());
        if self.fail == Some(what) && request != vidioc_s_fmt() {
            return Err(format!("injected {what} failure"));
        }
        if request == vidioc_g_fmt() || request == vidioc_s_fmt() {
            // SAFETY: the request identifies the V4l2Format provided by caller.
            let f = unsafe { &mut *argp.cast::<V4l2Format>() };
            assert_eq!(f.kind, META_CAPTURE);
            if request == vidioc_s_fmt() {
                self.writes.push((f.dataformat, f.buffersize));
                if self.fail == Some(what) {
                    if self.failed_set_applies {
                        self.format = (f.dataformat, f.buffersize.max(10240));
                    }
                    return Err("injected S_FMT failure".into());
                }
                // Linux v7.2 uvc_meta_v4l2_try/set_format lower-bounds size.
                self.format = self
                    .negotiated
                    .take()
                    .unwrap_or((f.dataformat, f.buffersize.max(10240)));
            }
            (f.dataformat, f.buffersize) = self.format;
        } else if request == vidioc_reqbufs() {
            // SAFETY: REQBUFS takes V4l2RequestBuffers.
            let req = unsafe { &mut *argp.cast::<V4l2RequestBuffers>() };
            if req.count == 0 {
                assert_eq!(self.mapped, 0, "release must follow every unmap");
            } else {
                req.count = self.count;
            }
        } else if request == vidioc_querybuf() {
            // SAFETY: QUERYBUF takes V4l2Buffer.
            let buf = unsafe { &mut *argp.cast::<V4l2Buffer>() };
            buf.length = self.length.unwrap_or(self.format.1);
        } else if request == vidioc_dqbuf() {
            // SAFETY: DQBUF takes the initialized metadata V4l2Buffer.
            let buf = unsafe { &mut *argp.cast::<V4l2Buffer>() };
            if self.delivered > 0 || !self.frame_flags.is_empty() {
                let Some(flags) = self.frame_flags.pop_front() else {
                    return Err("no metadata ready".into());
                };
                buf.index = self.delivered % self.count;
                self.delivered += 1;
                buf.bytesused = 16;
                buf.flags = flags;
                return Ok(());
            }
            if self.dequeued {
                return Err("no metadata ready".into());
            }
            self.dequeued = true;
            buf.index = 0;
            buf.bytesused = 16;
            buf.flags = if self.error_frame { 0x40 } else { 0 };
        } else {
            assert!(
                request == vidioc_qbuf()
                    || request == vidioc_streamon()
                    || request == vidioc_streamoff(),
                "unexpected ioctl {what}"
            );
        }
        Ok(())
    }
}

pub(crate) fn map_buffer(
    device: &Arc<Mutex<FakeDevice>>,
    buf: &V4l2Buffer,
) -> Result<MappedBuffer, String> {
    let mut state = device.lock().unwrap();
    state.events.push("map".into());
    if state.fail == Some("map") || state.map_failure_at == Some(buf.index) {
        return Err("injected map failure".into());
    }
    if buf.length == 0 || buf.length > MAX_META_BUFFER_SIZE {
        return Err("fake refuses an unsafe test allocation".into());
    }
    // SAFETY: independent anonymous mapping with a positive fake-driver length;
    // MappedBuffer owns it and uses the real munmap in Drop.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            buf.length as usize,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    state.mapped += 1;
    Ok(MappedBuffer {
        ptr,
        len: buf.length as usize,
        lifecycle: Some(device.clone()),
    })
}

fn log_for(device: &Arc<Mutex<FakeDevice>>) -> (IlluminationLog, UnixStream) {
    let (peer, owned) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    let mut log = IlluminationLog::from_fd(owned.into_raw_fd(), "fake-metadata");
    log.lifecycle = Some(device.clone());
    (log, peer)
}

fn assert_closed(device: &Arc<Mutex<FakeDevice>>, mut peer: UnixStream) {
    assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0, "fd must be closed");
    let state = device.lock().unwrap();
    assert_eq!(state.closes, 1);
    assert_eq!(state.mapped, 0);
    assert_eq!(state.events.last().map(String::as_str), Some("close"));
}

#[test]
fn initial_get_failure_never_writes_a_guessed_restore() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCM, 65536))));
    device.lock().unwrap().fail = Some("G_FMT");
    let (mut log, peer) = log_for(&device);
    assert!(log.start().is_err());
    drop(log);
    assert_closed(&device, peer);
    let state = device.lock().unwrap();
    assert!(
        state.writes.is_empty(),
        "unexpected writes: {:?}",
        state.writes
    );
    assert_eq!(state.format, (UVCM, 65536));
    assert_eq!(state.events, ["G_FMT", "close"]);
}

#[test]
fn successful_capture_restores_fourcc_and_nondefault_buffer_size() {
    for initial in [(UVCH, 65536), (UVCM, 32768), (UVCH, u32::MAX)] {
        let device = Arc::new(Mutex::new(FakeDevice::new(initial)));
        let (mut log, peer) = log_for(&device);
        log.start().unwrap();
        drop(log);
        assert_closed(&device, peer);
        let state = device.lock().unwrap();
        assert_eq!(state.format, initial, "events: {:?}", state.events);
        let release = state.events.iter().position(|e| e == "REQBUFS(0)").unwrap();
        let restore = state.events.iter().rposition(|e| e == "S_FMT").unwrap();
        let stop = state.events.iter().position(|e| e == "STREAMOFF").unwrap();
        let unmap = state.events.iter().position(|e| e == "unmap").unwrap();
        assert!(stop < unmap && unmap < release);
        assert!(release < restore, "release before format restore");
    }
}

#[test]
fn startup_requests_capacity_for_multi_header_frames() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 10240))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    let negotiated = device.lock().unwrap().format;
    drop(log);
    assert_closed(&device, peer);
    // uvcvideo completes a metadata buffer only with an image frame, so the
    // first buffer collects every payload header sent during sensor start-up:
    // 54 KiB on a Logitech BRIO and up to 68 KiB measured on a NexiGo N930W.
    assert_eq!(
        negotiated,
        (UVCM, 1024 * 1024),
        "start-up and multi-header frames overflow smaller metadata buffers"
    );
    assert_eq!(device.lock().unwrap().format, (UVCH, 10240));
}

#[test]
fn later_startup_failures_restore_the_complete_observed_format() {
    for failure in ["REQBUFS", "QUERYBUF", "map", "QBUF", "STREAMON"] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        device.lock().unwrap().fail = Some(failure);
        let (mut log, peer) = log_for(&device);
        assert!(log.start().is_err(), "{failure}");
        drop(log);
        assert_closed(&device, peer);
        assert_eq!(device.lock().unwrap().format, (UVCH, 65536), "{failure}");
    }
}

#[test]
fn already_uvcm_still_restores_a_changed_buffer_size() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCM, 10240))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    assert_eq!(
        device.lock().unwrap().format,
        (UVCM, REQUESTED_META_BUFFER_SIZE)
    );
    drop(log);
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().format, (UVCM, 10240));
}

#[test]
fn a_failed_format_write_never_acquires_restore_authority() {
    for applied in [false, true] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        {
            let mut state = device.lock().unwrap();
            state.fail = Some("S_FMT");
            state.failed_set_applies = applied;
        }
        let (mut log, peer) = log_for(&device);
        assert!(log.start().is_err());
        // The failed call might have changed the device. Even a matching current
        // format is not proof this fd owns it; never issue a speculative undo.
        device.lock().unwrap().fail = None;
        drop(log);
        assert_closed(&device, peer);
        let state = device.lock().unwrap();
        assert_eq!(state.writes.len(), 1, "applied={applied}");
        assert!(!state.events.iter().any(|e| e == "REQBUFS(0)"));
    }
}

#[test]
fn coerced_negotiation_restores_only_if_it_changed_state() {
    for size in [10240, 65536] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, size))));
        device.lock().unwrap().negotiated = Some((UVCH, 10240));
        let (mut log, peer) = log_for(&device);
        assert!(log.start().unwrap_err().contains("does not accept"));
        drop(log);
        assert_closed(&device, peer);
        let state = device.lock().unwrap();
        assert_eq!(state.format, (UVCH, size));
        assert_eq!(state.writes.len(), if size == 10240 { 1 } else { 2 });
        assert!(!state.events.iter().any(|e| e == "REQBUFS"));
    }
}

#[test]
fn negotiated_size_not_requested_size_is_the_owned_value() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
    device.lock().unwrap().negotiated = Some((UVCM, 32768));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    drop(log);
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().format, (UVCH, 65536));
}

#[test]
fn foreign_fourcc_or_buffer_size_is_never_overwritten() {
    for foreign in [(UVCH, 32768), (UVCM, 32768)] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        let (mut log, peer) = log_for(&device);
        log.start().unwrap();
        device.lock().unwrap().format = foreign;
        drop(log);
        assert_closed(&device, peer);
        let state = device.lock().unwrap();
        assert_eq!(state.format, foreign);
        assert_eq!(state.writes.len(), 1);
    }
}

#[test]
fn failed_restore_read_does_not_authorize_a_write() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    device.lock().unwrap().fail = Some("G_FMT");
    drop(log);
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().writes.len(), 1);
}

#[test]
fn unchanged_negotiation_does_not_restore_someone_elses_later_format() {
    let device = Arc::new(Mutex::new(FakeDevice::new((
        UVCM,
        REQUESTED_META_BUFFER_SIZE,
    ))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    device.lock().unwrap().format = (UVCH, 10240);
    drop(log);
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().writes.len(), 1);
    assert_eq!(device.lock().unwrap().format, (UVCH, 10240));
}

#[test]
fn partial_mapping_failure_unmaps_before_release_and_restore() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
    device.lock().unwrap().map_failure_at = Some(1);
    let (mut log, peer) = log_for(&device);
    assert!(log.start().is_err());
    drop(log);
    assert_closed(&device, peer);
    let state = device.lock().unwrap();
    assert_eq!(state.format, (UVCH, 65536));
    let unmap = state.events.iter().position(|e| e == "unmap").unwrap();
    let release = state.events.iter().position(|e| e == "REQBUFS(0)").unwrap();
    let restore = state.events.iter().rposition(|e| e == "S_FMT").unwrap();
    assert!(unmap < release && release < restore);
}

#[test]
fn teardown_errors_still_close_and_never_restore_before_release() {
    for failure in ["STREAMOFF", "REQBUFS(0)", "S_FMT"] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        let (mut log, peer) = log_for(&device);
        log.start().unwrap();
        device.lock().unwrap().fail = Some(failure);
        drop(log);
        assert_closed(&device, peer);
        let state = device.lock().unwrap();
        assert_eq!(
            state.writes.len(),
            if failure == "REQBUFS(0)" { 1 } else { 2 }
        );
        if failure == "STREAMOFF" {
            assert_eq!(state.format, (UVCH, 65536));
        }
    }
}

#[test]
fn unbounded_or_empty_negotiated_buffers_are_refused_before_allocation() {
    for size in [0, u32::MAX] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        device.lock().unwrap().negotiated = Some((UVCM, size));
        let (mut log, peer) = log_for(&device);
        let result = log.start();
        drop(log);
        assert_closed(&device, peer);
        assert!(result.is_err(), "size={size}");
        let state = device.lock().unwrap();
        assert!(!state.events.iter().any(|e| e == "REQBUFS"));
        assert_eq!(state.format, (UVCH, 65536));
    }
}

#[test]
fn buffer_count_and_mapping_lengths_are_bounded() {
    for (count, length) in [(0, 10240), (9, 10240), (2, 0), (2, u32::MAX)] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        {
            let mut state = device.lock().unwrap();
            state.count = count;
            state.length = Some(length);
        }
        let (mut log, peer) = log_for(&device);
        let result = log.start();
        drop(log);
        assert_closed(&device, peer);
        assert!(result.is_err(), "count={count}, length={length}");
        let state = device.lock().unwrap();
        assert!(!state.events.iter().any(|e| e == "map"));
        assert_eq!(state.format, (UVCH, 65536));
    }
}

#[test]
fn failed_or_adjusted_restore_is_not_retried() {
    for applied in [false, true] {
        let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
        let (mut log, peer) = log_for(&device);
        log.start().unwrap();
        {
            let mut state = device.lock().unwrap();
            state.fail = Some("S_FMT");
            state.failed_set_applies = applied;
        }
        drop(log);
        assert_closed(&device, peer);
        let state = device.lock().unwrap();
        assert_eq!(state.writes.len(), 2);
        assert_eq!(
            state.format,
            if applied {
                (UVCH, 65536)
            } else {
                (UVCM, REQUESTED_META_BUFFER_SIZE)
            }
        );
    }
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    device.lock().unwrap().negotiated = Some((UVCH, 32768));
    drop(log);
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().writes.len(), 2);
    assert_eq!(device.lock().unwrap().format, (UVCH, 32768));
}

#[test]
fn fixed_size_kernel_snapshot_round_trips() {
    // Linux v6.12 reports 10240 irrespective of the requested buffer size.
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 10240))));
    device.lock().unwrap().negotiated = Some((UVCM, 10240));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    device.lock().unwrap().negotiated = Some((UVCH, 10240));
    drop(log);
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().format, (UVCH, 10240));
}

#[test]
fn unwind_releases_the_ring_and_restores_the_snapshot() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCM, 10240))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = log;
        panic!("capture consumer unwound");
    }));
    assert!(result.is_err());
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().format, (UVCM, 10240));
}

#[test]
fn error_metadata_never_forms_a_view_or_requeues_the_buffer() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 10240))));
    device.lock().unwrap().error_frame = true;
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    let queued = device
        .lock()
        .unwrap()
        .events
        .iter()
        .filter(|e| *e == "QBUF")
        .count();
    log.drain();
    log.drain();
    let events = device.lock().unwrap().events.clone();
    assert!(!events.iter().any(|e| e == "view"));
    assert_eq!(events.iter().filter(|e| *e == "QBUF").count(), queued);
    drop(log);
    assert_closed(&device, peer);
}

fn count(device: &Arc<Mutex<FakeDevice>>, event: &str) -> usize {
    device
        .lock()
        .unwrap()
        .events
        .iter()
        .filter(|e| *e == event)
        .count()
}

#[test]
fn startup_error_metadata_is_parked_and_later_records_still_drain() {
    // uvcvideo copies the paired image buffer's ERROR onto the metadata buffer,
    // so a camera whose first image frame is ERROR-marked also delivers its
    // first metadata buffer ERROR-marked; later buffers are sound.
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 10240))));
    device.lock().unwrap().frame_flags = [0x40, 0, 0].into();
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    let queued = count(&device, "QBUF");
    log.drain();
    assert!(!log.retired);
    assert_eq!(
        count(&device, "view"),
        2,
        "the parked buffer is never viewed"
    );
    assert_eq!(
        count(&device, "QBUF"),
        queued + 2,
        "the parked buffer is never requeued"
    );
    drop(log);
    assert_closed(&device, peer);
}

#[test]
fn error_metadata_after_a_delivered_buffer_retires_the_ring() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 10240))));
    device.lock().unwrap().frame_flags = [0, 0x40, 0].into();
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    let queued = count(&device, "QBUF");
    log.drain();
    assert!(log.retired);
    assert_eq!(count(&device, "view"), 1);
    assert_eq!(count(&device, "QBUF"), queued + 1);
    log.drain();
    assert_eq!(count(&device, "DQBUF"), 2, "a retired ring is not drained");
    drop(log);
    assert_closed(&device, peer);
}

#[test]
fn startup_parking_is_bounded_for_metadata() {
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 10240))));
    {
        let mut state = device.lock().unwrap();
        state.count = 8;
        state.frame_flags = [0x40, 0x40, 0x40, 0].into();
    }
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    log.drain();
    assert!(log.retired);
    assert_eq!(count(&device, "view"), 0);
    assert_eq!(count(&device, "DQBUF"), 3);
    drop(log);
    assert_closed(&device, peer);
}

#[test]
fn metadata_drop_waits_for_acknowledged_main_producer_stop() {
    let producer = crate::capture_shutdown::Producer::for_test();
    let events = Arc::new(Mutex::new(Vec::new()));
    producer.begin().unwrap();
    let log = IlluminationLog::test_sentinel(events.clone()).with_producer(producer.clone());
    drop(log);
    assert!(events.lock().unwrap().is_empty());
    producer.stopped();
    assert_eq!(*events.lock().unwrap(), ["metadata-drop"]);
}

#[test]
fn deferred_metadata_keeps_its_real_fd_mappings_and_original_format_snapshot() {
    let producer = crate::capture_shutdown::Producer::for_test();
    let device = Arc::new(Mutex::new(FakeDevice::new((UVCH, 65536))));
    let (mut log, peer) = log_for(&device);
    log.start().unwrap();
    producer.begin().unwrap();
    drop(log.with_producer(producer.clone()));
    let state = device.lock().unwrap();
    assert_eq!(state.closes, 0);
    assert_eq!(state.mapped, 2);
    assert!(!state
        .events
        .iter()
        .any(|e| e == "STREAMOFF" || e == "REQBUFS(0)"));
    drop(state);
    producer.stopped();
    assert_closed(&device, peer);
    assert_eq!(device.lock().unwrap().format, (UVCH, 65536));
}
