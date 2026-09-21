// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

pub(super) struct FakeIo {
    queued: Vec<bool>,
    polls: VecDeque<Result<i32, i32>>,
    dequeues: VecDeque<Result<u32, i32>>,
    events: Vec<String>,
    fail: Option<&'static str>,
    fail_map: Option<u32>,
    mapped: usize,
    granted: u32,
    sequence: u32,
    flags: u32,
    consume_on_error: bool,
    shared_events: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl Default for FakeIo {
    fn default() -> Self {
        Self {
            queued: Vec::new(),
            polls: VecDeque::new(),
            dequeues: VecDeque::new(),
            events: Vec::new(),
            fail: None,
            fail_map: None,
            mapped: 0,
            granted: 4,
            sequence: 0,
            flags: 0x2000, // V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC
            consume_on_error: false,
            shared_events: None,
        }
    }
}

impl FakeIo {
    pub(super) fn view_created(&mut self) {
        self.events.push("view".into());
    }

    pub(super) fn poll(&mut self) -> io::Result<i32> {
        self.events.push("poll".into());
        self.polls
            .pop_front()
            .unwrap_or(Ok(1))
            .map_err(io::Error::from_raw_os_error)
    }

    pub(super) fn unmapped(&mut self) {
        assert!(self.mapped > 0, "unmap without a live mapping");
        self.mapped -= 1;
        self.events.push("unmap".into());
        if let Some(events) = &self.shared_events {
            events.lock().unwrap().push("image-unmap");
        }
    }

    /// # Safety
    /// `arg` must name the initialized, writable ABI structure for `request`.
    pub(super) unsafe fn ioctl(
        &mut self,
        request: vidioc::_IOC_TYPE,
        arg: *mut libc::c_void,
        operation: &str,
    ) -> io::Result<()> {
        self.events.push(operation.into());
        if let Some(events) = &self.shared_events {
            match operation {
                "STREAMOFF" => events.lock().unwrap().push("image-stop"),
                "REQBUFS(0)" => events.lock().unwrap().push("image-release"),
                _ => {}
            }
        }
        if self.fail == Some(operation)
            || (self.fail == Some("teardown") && matches!(operation, "STREAMOFF" | "REQBUFS(0)"))
        {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if request == vidioc::VIDIOC_REQBUFS {
            // SAFETY: the request identifies the caller's requestbuffers.
            let req = unsafe { &mut *arg.cast::<v4l2_requestbuffers>() };
            assert_eq!((req.type_, req.memory), (1, 1));
            if req.count == 0 {
                assert_eq!(self.mapped, 0, "unmap before releasing the ring");
                self.queued.clear();
            } else {
                req.count = self.granted;
                self.queued = vec![false; self.granted as usize];
            }
        } else if request == vidioc::VIDIOC_STREAMON || request == vidioc::VIDIOC_STREAMOFF {
            // SAFETY: STREAMON/OFF takes a buffer-type integer.
            assert_eq!(unsafe { *arg.cast::<u32>() }, 1);
            if request == vidioc::VIDIOC_STREAMON {
                assert!(self.queued.iter().all(|q| *q));
            } else {
                self.queued.fill(false);
            }
        } else {
            // SAFETY: QUERYBUF/QBUF/DQBUF takes the caller's v4l2_buffer.
            let buf = unsafe { &mut *arg.cast::<v4l2_buffer>() };
            assert_eq!((buf.type_, buf.memory), (1, 1));
            if request == vidioc::VIDIOC_QUERYBUF {
                buf.length = 16;
            } else if request == vidioc::VIDIOC_QBUF {
                let Some(queued) = self.queued.get_mut(buf.index as usize) else {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                };
                if *queued {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                *queued = true;
            } else if request == vidioc::VIDIOC_DQBUF {
                let result = self.dequeues.pop_front().unwrap_or_else(|| {
                    self.queued
                        .iter()
                        .position(|q| *q)
                        .map(|i| i as u32)
                        .ok_or(libc::EAGAIN)
                });
                if result.is_err() && self.consume_on_error {
                    if let Some(index) = self.queued.iter().position(|q| *q) {
                        self.queued[index] = false;
                    }
                }
                buf.index = result.map_err(io::Error::from_raw_os_error)?;
                if let Some(queued) = self.queued.get_mut(buf.index as usize) {
                    assert!(*queued, "dequeue only kernel-owned buffers");
                    *queued = false;
                }
                self.sequence += 1;
                buf.sequence = self.sequence;
                buf.bytesused = 16;
                buf.flags = self.flags;
                buf.timestamp.tv_usec = i64::from(self.sequence) * 1000;
            } else {
                panic!("unexpected request {operation}");
            }
        }
        Ok(())
    }
}

pub(super) fn map(fake: &Arc<Mutex<FakeIo>>, buf: &v4l2_buffer) -> io::Result<Mapping> {
    let mut state = fake.lock().unwrap();
    state.events.push("map".into());
    if state.fail_map == Some(buf.index) {
        return Err(io::Error::from_raw_os_error(libc::ENOMEM));
    }
    assert_eq!(buf.length, 16);
    // SAFETY: this positive-size anonymous mapping is privately owned by the
    // returned Mapping, whose production Drop performs munmap.
    let ptr = unsafe {
        v4l2::mmap(
            std::ptr::null_mut(),
            16,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )?
    };
    let ptr = std::ptr::NonNull::new(ptr).unwrap();
    // SAFETY: all 16 bytes belong to this writable anonymous mapping.
    unsafe { ptr.as_ptr().cast::<u8>().write_bytes(42, 16) };
    state.mapped += 1;
    Ok(Mapping {
        ptr,
        len: 16,
        fake: Some(fake.clone()),
    })
}

fn stream(fake: &Arc<Mutex<FakeIo>>) -> MmapCapture {
    // The fake intercepts only kernel operations; Handle lifetime and mappings
    // remain real. This path never opens a camera.
    let device = Device::with_path("/dev/null").unwrap();
    let mut stream = MmapCapture::test_new(device.handle(), 5000);
    stream.fake = Some(fake.clone());
    stream.allocate(4).unwrap();
    stream
}

fn calls(fake: &Arc<Mutex<FakeIo>>, operation: &str) -> usize {
    fake.lock()
        .unwrap()
        .events
        .iter()
        .filter(|e| *e == operation)
        .count()
}

fn dequeue_error(stream: &mut MmapCapture) -> io::Error {
    stream.dequeue().err().expect("expected dequeue failure")
}

#[test]
fn timeout_before_first_frame_does_not_queue_a_kernel_owned_buffer() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls = [Ok(0), Ok(0), Ok(1)].into();
    let mut stream = stream(&fake);
    for _ in 0..2 {
        assert_eq!(dequeue_error(&mut stream).kind(), io::ErrorKind::TimedOut);
    }
    let (bytes, meta) = stream.dequeue().unwrap();
    assert_eq!(bytes, &[42; 16]);
    assert_eq!(meta.sequence, 1);
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert_eq!(calls(&fake, "poll"), 3);
    assert_eq!(calls(&fake, "DQBUF"), 1);
    assert_eq!(calls(&fake, "STREAMON"), 1);
}

#[test]
fn timeout_after_success_returns_the_held_buffer_only_once() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls = [Ok(1), Ok(0), Ok(0), Ok(1), Ok(1)].into();
    let mut stream = stream(&fake);
    assert_eq!(stream.dequeue().unwrap().1.sequence, 1);
    for _ in 0..2 {
        assert_eq!(dequeue_error(&mut stream).kind(), io::ErrorKind::TimedOut);
    }
    assert_eq!(stream.dequeue().unwrap().1.sequence, 2);
    assert_eq!(calls(&fake, "QBUF"), 5);
    assert_eq!(stream.dequeue().unwrap().1.sequence, 3);
    assert_eq!(calls(&fake, "QBUF"), 6);
    assert_eq!(calls(&fake, "STREAMON"), 1);
}

#[test]
fn poll_interrupt_and_dequeue_eagain_retry_without_duplicate_queue() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    {
        let mut f = fake.lock().unwrap();
        f.polls = [Err(libc::EINTR), Ok(1), Ok(1)].into();
        f.dequeues = [Err(libc::EAGAIN), Ok(0)].into();
    }
    let mut stream = stream(&fake);
    assert_eq!(dequeue_error(&mut stream).raw_os_error(), Some(libc::EINTR));
    assert_eq!(
        dequeue_error(&mut stream).raw_os_error(),
        Some(libc::EAGAIN)
    );
    stream.dequeue().unwrap();
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert_eq!(calls(&fake, "poll"), 3);
}

#[test]
fn dequeue_error_with_unknown_consumed_buffer_never_guesses_an_index() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    {
        let mut f = fake.lock().unwrap();
        f.consume_on_error = true;
        f.dequeues = [Err(libc::EIO), Ok(1)].into();
    }
    let mut stream = stream(&fake);
    assert_eq!(dequeue_error(&mut stream).raw_os_error(), Some(libc::EIO));
    stream.dequeue().unwrap();
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert!(!fake.lock().unwrap().queued[0]);
}

#[test]
fn setup_or_queue_failure_refuses_further_io_and_still_releases() {
    for failure in ["QBUF", "STREAMON"] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        let mut stream = stream(&fake);
        fake.lock().unwrap().fail = Some(failure);
        assert_eq!(dequeue_error(&mut stream).raw_os_error(), Some(libc::EIO));
        let before = fake.lock().unwrap().events.clone();
        assert!(stream.dequeue().is_err());
        assert_eq!(fake.lock().unwrap().events, before);
        drop(stream);
        assert_eq!(calls(&fake, "STREAMOFF"), 1);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
        assert_eq!(fake.lock().unwrap().mapped, 0);
    }
}

#[test]
fn a_failed_requeue_after_a_frame_is_not_retried_speculatively() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    let mut stream = stream(&fake);
    stream.dequeue().unwrap();
    fake.lock().unwrap().fail = Some("QBUF");
    assert_eq!(dequeue_error(&mut stream).raw_os_error(), Some(libc::EIO));
    assert!(stream.dequeue().is_err());
    assert_eq!(calls(&fake, "QBUF"), 5);
    assert_eq!(calls(&fake, "DQBUF"), 1);
}

#[test]
fn invalid_dequeued_index_returns_no_bytes_and_retires_the_queue() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().dequeues.push_back(Ok(4));
    let mut stream = stream(&fake);
    assert_eq!(
        dequeue_error(&mut stream).kind(),
        io::ErrorKind::InvalidData
    );
    assert!(stream.dequeue().is_err());
    assert_eq!(calls(&fake, "DQBUF"), 1);
    assert_eq!(calls(&fake, "QBUF"), 4);
}

#[test]
fn cleanup_after_timeout_stops_then_unmaps_then_releases_once() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls.push_back(Ok(0));
    let mut stream = stream(&fake);
    let weak = Arc::downgrade(&stream.handle);
    assert!(stream.dequeue().is_err());
    drop(stream);
    assert!(
        weak.upgrade().is_none(),
        "the final device handle was released"
    );
    let state = fake.lock().unwrap();
    let stop = state.events.iter().position(|e| e == "STREAMOFF").unwrap();
    assert_eq!(
        &state.events[stop..],
        &[
            "STREAMOFF",
            "unmap",
            "unmap",
            "unmap",
            "unmap",
            "REQBUFS(0)"
        ]
    );
}

#[test]
fn partial_mapping_and_allocation_errors_release_every_acquired_resource() {
    for failure in ["REQBUFS", "QUERYBUF", "map"] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        {
            let mut state = fake.lock().unwrap();
            if failure == "map" {
                state.fail_map = Some(2);
            } else {
                state.fail = Some(failure);
            }
        }
        let device = Device::with_path("/dev/null").unwrap();
        let mut stream = MmapCapture::test_new(device.handle(), 5000);
        stream.fake = Some(fake.clone());
        assert!(stream.allocate(4).is_err());
        drop(stream);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
        assert_eq!(fake.lock().unwrap().mapped, 0);
    }
}

#[test]
fn teardown_distinguishes_unconfirmed_stop_from_failed_release() {
    for failure in ["STREAMOFF", "REQBUFS(0)"] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        let mut stream = stream(&fake);
        let producer = stream.producer();
        stream.dequeue().unwrap();
        fake.lock().unwrap().fail = Some(failure);
        drop(stream);
        assert_eq!(calls(&fake, "STREAMOFF"), 1);
        if failure == "STREAMOFF" {
            assert_eq!(calls(&fake, "REQBUFS(0)"), 0);
            assert_eq!(fake.lock().unwrap().mapped, 4);
            assert!(producer.check().is_err());
        } else {
            assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
            assert_eq!(fake.lock().unwrap().mapped, 0);
            assert!(producer.check().is_ok());
        }
    }
}

#[test]
fn delivered_corruption_retires_before_the_trusted_boundary_can_borrow_bytes() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().flags |= 0x40; // V4L2_BUF_FLAG_ERROR
    let mut stream = stream(&fake);
    let layout = crate::frame_provenance::PayloadLayout::new(*b"GREY", 4, 4, 4).unwrap();
    assert!(crate::dequeue_validated_typed(&mut stream, layout, || Ok(())).is_err());
    fake.lock().unwrap().flags = 0x2000;
    assert!(crate::dequeue_validated_typed(&mut stream, layout, || Ok(())).is_err());
    assert_eq!(calls(&fake, "view"), 0);
    assert_eq!(calls(&fake, "QBUF"), 4);
}

#[test]
fn error_buffer_is_retired_before_any_mapped_view_or_requeue() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().flags |= 0x40;
    let mut stream = stream(&fake);
    assert_eq!(
        dequeue_error(&mut stream).kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(calls(&fake, "view"), 0);
    assert!(stream.dequeue().is_err());
    assert_eq!(calls(&fake, "DQBUF"), 1);
    assert_eq!(calls(&fake, "QBUF"), 4);
}

#[test]
fn unconfirmed_stop_retains_mappings_instead_of_releasing_the_ring() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    let mut stream = stream(&fake);
    stream.dequeue().unwrap();
    let producer = stream.producer();
    fake.lock().unwrap().fail = Some("STREAMOFF");
    drop(stream);
    assert_eq!(fake.lock().unwrap().mapped, 4);
    assert_eq!(calls(&fake, "REQBUFS(0)"), 0);
    assert!(producer.check().is_err());
}

struct ValidatedMmap(MmapCapture);

impl crate::ValidatedStream for ValidatedMmap {
    fn quiesce(&mut self) -> io::Result<()> {
        self.0.quiesce()
    }
    fn next_validated(
        &mut self,
    ) -> Result<(&[u8], crate::frame_provenance::DequeuedBufferFacts), crate::ValidatedDequeueError>
    {
        let layout = crate::frame_provenance::PayloadLayout::new(*b"GREY", 4, 4, 4).unwrap();
        crate::dequeue_validated_typed(&mut self.0, layout, || Ok(()))
    }
}

fn tracked(
    fake: &Arc<Mutex<FakeIo>>,
    control: &crate::CaptureControl,
) -> crate::TrackedStream<ValidatedMmap> {
    let interval = crate::frame_interval::FrameInterval::new(1, 30).unwrap();
    crate::TrackedStream::new(
        ValidatedMmap(stream(fake)),
        crate::rate_gate::StreamRateConfig::new(
            crate::contracts::StreamRole::Ir,
            interval,
            interval,
        ),
    )
    .with_control(control)
}

#[test]
fn warmup_reaches_the_third_window_and_reports_each_completed_timeout() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls = [Ok(0), Ok(0), Ok(1)].into();
    let heartbeats = Arc::new(AtomicUsize::new(0));
    let mark = heartbeats.clone();
    let control = crate::CaptureControl::with_progress(Arc::new(move || {
        mark.fetch_add(1, Ordering::SeqCst);
    }));
    let mut tracked = tracked(&fake, &control);
    let mut sleeps = 0;
    crate::warm_up_with(
        "fake",
        || tracked.next_discarded(),
        |_| sleeps += 1,
        &control.progress,
    )
    .unwrap();
    assert_eq!(heartbeats.load(Ordering::SeqCst), 2);
    assert_eq!(sleeps, 2);
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert_eq!(calls(&fake, "poll"), 3);
    assert_eq!(calls(&fake, "DQBUF"), 1);
}

#[test]
fn silent_warmup_spends_the_bounded_budget_without_duplicate_queues() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls = [Ok(0); 8].into();
    let heartbeats = Arc::new(AtomicUsize::new(0));
    let mark = heartbeats.clone();
    let control = crate::CaptureControl::with_progress(Arc::new(move || {
        mark.fetch_add(1, Ordering::SeqCst);
    }));
    let mut tracked = tracked(&fake, &control);
    let mut sleeps = 0;
    assert!(crate::warm_up_with(
        "fake",
        || tracked.next_discarded(),
        |_| sleeps += 1,
        &control.progress
    )
    .is_err());
    assert_eq!(heartbeats.load(Ordering::SeqCst), 8);
    assert_eq!(sleeps, 7);
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert_eq!(calls(&fake, "poll"), 8);
    assert_eq!(calls(&fake, "DQBUF"), 0);
}

#[test]
fn cancellation_after_a_timeout_precedes_another_kernel_operation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls.push_back(Ok(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let mark = cancelled.clone();
    let control = crate::CaptureControl::new(
        Arc::new(move || {
            mark.store(true, Ordering::SeqCst);
        }),
        Arc::new(move || cancelled.load(Ordering::SeqCst)),
    );
    let mut tracked = tracked(&fake, &control);
    let result = crate::warm_up_with(
        "fake",
        || tracked.next_discarded(),
        |_| {},
        &control.progress,
    );
    assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
    assert_eq!(calls(&fake, "poll"), 1);
    assert_eq!(calls(&fake, "QBUF"), 4);
    drop(tracked);
    assert_eq!(calls(&fake, "STREAMOFF"), 1);
    assert_eq!(fake.lock().unwrap().mapped, 0);
}

#[test]
fn deadline_after_a_timeout_is_not_another_retryable_driver_timeout() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().polls.push_back(Ok(0));
    let control = crate::CaptureControl::with_progress(crate::no_progress());
    let mut tracked = tracked(&fake, &control);
    assert_eq!(
        tracked.next_discarded().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    tracked.control = control
        .clone()
        .with_deadline(Some(std::time::Instant::now()));
    let mut sleeps = 0;
    let result = crate::warm_up_with(
        "fake",
        || tracked.next_discarded(),
        |_| sleeps += 1,
        &control.progress,
    );
    assert!(matches!(result, Err(irlume_common::Error::DeadlineExpired)));
    assert_eq!(sleeps, 0);
    assert_eq!(calls(&fake, "poll"), 1);
    assert_eq!(calls(&fake, "QBUF"), 4);
}

#[test]
fn an_unwinding_consumer_retains_resources_after_unconfirmed_stop() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    let mut stream = stream(&fake);
    stream.dequeue().unwrap();
    let producer = stream.producer();
    fake.lock().unwrap().fail = Some("teardown");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _stream = stream;
        panic!("consumer unwound");
    }));
    assert!(result.is_err());
    assert_eq!(calls(&fake, "STREAMOFF"), 1);
    assert_eq!(calls(&fake, "REQBUFS(0)"), 0);
    assert_eq!(fake.lock().unwrap().mapped, 4);
    assert!(producer.check().is_err());
}

#[test]
fn the_driver_granted_count_controls_the_ring_and_zero_is_refused() {
    for count in [0, 2, 5] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        fake.lock().unwrap().granted = count;
        let device = Device::with_path("/dev/null").unwrap();
        let mut stream = MmapCapture::test_new(device.handle(), 5000);
        stream.fake = Some(fake.clone());
        let allocated = stream.allocate(4);
        if count == 0 {
            assert!(allocated.is_err());
        } else {
            allocated.unwrap();
            stream.dequeue().unwrap();
            assert_eq!(calls(&fake, "QBUF"), count as usize);
        }
        drop(stream);
        assert_eq!(fake.lock().unwrap().mapped, 0);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
    }
}

#[test]
fn coupled_owner_stops_metadata_before_releasing_image_queue_ownership() {
    for unwind in [false, true] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        let events = Arc::new(Mutex::new(Vec::new()));
        fake.lock().unwrap().shared_events = Some(events.clone());
        let mut raw = stream(&fake);
        raw.dequeue().unwrap();
        let producer = raw.producer();
        let interval = crate::frame_interval::FrameInterval::new(1, 30).unwrap();
        let owner = crate::IrCaptureResources {
            stream: crate::TrackedStream::new(
                ValidatedMmap(raw),
                crate::rate_gate::StreamRateConfig::new(
                    crate::contracts::StreamRole::Ir,
                    interval,
                    interval,
                ),
            ),
            meta: Some(
                crate::ir_metadata::IlluminationLog::test_sentinel(events.clone())
                    .with_producer(producer.clone()),
            ),
            _mode: crate::ir_emitter::StreamMode::test_sentinel(events.clone())
                .with_producer(producer),
        };
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _owner = owner;
                    panic!("consumer failure");
                }))
                .is_err()
            );
        } else {
            drop(owner);
        }
        let observed = events.lock().unwrap().clone();
        assert_eq!(
            observed,
            [
                "image-stop",
                "metadata-drop",
                "image-unmap",
                "image-unmap",
                "image-unmap",
                "image-unmap",
                "image-release",
                "emitter-restore"
            ]
        );
    }
}

#[test]
fn coupled_owner_keeps_metadata_and_emitter_when_image_stop_is_unconfirmed() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    let events = Arc::new(Mutex::new(Vec::new()));
    fake.lock().unwrap().shared_events = Some(events.clone());
    let mut raw = stream(&fake);
    raw.dequeue().unwrap();
    let producer = raw.producer(); // Keep this isolated test retention domain alive.
    let interval = crate::frame_interval::FrameInterval::new(1, 30).unwrap();
    let owner = crate::IrCaptureResources {
        stream: crate::TrackedStream::new(
            ValidatedMmap(raw),
            crate::rate_gate::StreamRateConfig::new(
                crate::contracts::StreamRole::Ir,
                interval,
                interval,
            ),
        ),
        meta: Some(
            crate::ir_metadata::IlluminationLog::test_sentinel(events.clone())
                .with_producer(producer.clone()),
        ),
        _mode: crate::ir_emitter::StreamMode::test_sentinel(events.clone())
            .with_producer(producer.clone()),
    };
    fake.lock().unwrap().fail = Some("STREAMOFF");
    drop(owner);
    assert_eq!(events.lock().unwrap().clone(), ["image-stop"]);
    assert_eq!(fake.lock().unwrap().mapped, 4);
    assert!(producer.check().is_err());
}

#[test]
fn failed_stop_retains_all_owners_even_when_stderr_is_closed() {
    use std::io::{Read, Write};
    const CHILD: &str = "IRLUME_TEST_CLOSED_STDERR_SHUTDOWN";
    if std::env::var_os(CHILD).is_some() {
        std::panic::set_hook(Box::new(|_| {}));
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut raw = stream(&fake);
        raw.dequeue().unwrap();
        let producer = raw.producer();
        let handle = Arc::downgrade(&raw.handle);
        drop(
            crate::ir_metadata::IlluminationLog::test_sentinel(events.clone())
                .with_producer(producer.clone()),
        );
        drop(
            crate::ir_emitter::StreamMode::test_sentinel(events.clone())
                .with_producer(producer.clone()),
        );
        std::io::stdin().read_exact(&mut [0u8]).unwrap();
        fake.lock().unwrap().fail = Some("STREAMOFF");
        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(raw)));
        assert!(
            stopped.is_ok(),
            "diagnostic output must not unwind containment"
        );
        assert!(events.lock().unwrap().clone().is_empty());
        assert!(producer.check().is_err());
        assert_eq!(fake.lock().unwrap().mapped, 4);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 0);
        assert!(
            handle.upgrade().is_some(),
            "retained ring must keep the fd alive"
        );
        return;
    }
    let _env = crate::testenv::env_lock();
    for broken in [false, true] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "mmap_capture::tests::failed_stop_retains_all_owners_even_when_stderr_is_closed",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        if broken {
            drop(child.stderr.take());
        }
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "broken={broken}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
