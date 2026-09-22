// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Single-planar capture transport with explicit dequeue ownership.
//!
//! v4l 0.14's CaptureStream::next requeues its last index even after a poll
//! timeout returned no buffer. Its private arena prevents an external wrapper
//! from retrieving a directly dequeued frame. Keep format negotiation and device
//! handles in v4l, but own this capture ring and its queue transitions here.
//! Timeout/retry policy, leases, cancellation and payload validation remain in
//! the callers. No reopen or new continuity epoch is hidden in a retry.

use std::{io, ptr::NonNull, sync::Arc, time::Duration};
use v4l::{
    buffer::{Metadata, Type},
    device::{Device, Handle},
    memory::Memory,
    v4l2::{self, vidioc},
    v4l_sys::{v4l2_buffer, v4l2_requestbuffers},
};

use crate::CaptureDequeue;

#[derive(Clone, Copy, Debug)]
enum Operation {
    Queue,
    Start,
    Wait,
    Dequeue,
    Retired,
}

/// Preserve which operation failed across the io::Error-based policy layers.
/// An errno alone cannot authorize a retry of a queue mutation.
#[derive(Debug)]
struct CaptureIoError {
    operation: Operation,
    source: io::Error,
}

impl std::fmt::Display for CaptureIoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = match self.operation {
            Operation::Queue => "VIDIOC_QBUF",
            Operation::Start => "VIDIOC_STREAMON",
            Operation::Wait => "capture poll",
            Operation::Dequeue => "VIDIOC_DQBUF",
            Operation::Retired => "retired capture queue",
        };
        write!(formatter, "{operation}: {}", self.source)
    }
}

impl std::error::Error for CaptureIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn operation_error(operation: Operation, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), CaptureIoError { operation, source })
}

fn capture_error(error: &io::Error) -> Option<&CaptureIoError> {
    error.get_ref()?.downcast_ref()
}

/// Retain errno-based diagnostics when an operation context wraps a raw error.
pub(super) fn source_io(error: &io::Error) -> &io::Error {
    capture_error(error).map_or(error, |error| &error.source)
}

/// `None` leaves non-transport errors to the caller's existing policy. The
/// transport authorizes only another wait/dequeue, never a failed queue/start.
pub(super) fn warmup_retry(error: &io::Error) -> Option<bool> {
    let error = capture_error(error)?;
    Some(match error.operation {
        Operation::Queue | Operation::Start | Operation::Retired => false,
        Operation::Wait | Operation::Dequeue => {
            matches!(error.source.raw_os_error(), Some(libc::EIO | libc::ENODEV))
                || matches!(
                    error.source.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::NotConnected
                        | io::ErrorKind::Other
                        | io::ErrorKind::TimedOut
                )
        }
    })
}

/// ERROR-marked buffers that may be parked before a stream delivers its first
/// frame. A Logitech BRIO marks exactly one: the first IR buffer after its RGB
/// sensor path was used. Two leaves margin without hiding a failing stream.
const MAX_PARKED_STARTUP_ERRORS: u32 = 2;

struct Mapping {
    ptr: NonNull<libc::c_void>,
    len: usize,
    #[cfg(test)]
    fake: Option<Arc<std::sync::Mutex<tests::FakeIo>>>,
}

// SAFETY: a Mapping has one owner, MmapCapture. Moving it transfers the mapped
// view; slices borrow that owner and are exposed only after a successful dequeue.
// It is deliberately not Sync. Drop unmaps the view exactly once.
unsafe impl Send for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this is the exact live mapping returned by map_buffer.
        if let Err(error) = unsafe { v4l2::munmap(self.ptr.as_ptr(), self.len) } {
            irlume_common::dlog!("capture buffer unmap failed: {error}");
        }
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            fake.lock().unwrap().unmapped();
        }
    }
}

pub(super) struct MmapCapture {
    handle: Arc<Handle>,
    buffers: Vec<Mapping>,
    timeout_ms: i32,
    buffers_requested: bool,
    active: bool,
    /// Only a successful DQBUF can supply an index we may queue next time.
    held: Option<u32>,
    /// A failed QBUF/STREAMON has an uncertain outcome: do not repeat it.
    failed: bool,
    producer: crate::capture_shutdown::Producer,
    stop_attempted: bool,
    /// ERROR-marked start-up buffers left dequeued: never viewed or requeued.
    parked: u32,
    /// Parking ends with the first delivered frame; later ERROR retires the ring.
    delivered: bool,
    #[cfg(test)]
    fake: Option<Arc<std::sync::Mutex<tests::FakeIo>>>,
}

impl MmapCapture {
    pub(super) fn with_buffers(device: &Device, count: u32, timeout: Duration) -> io::Result<Self> {
        crate::capture_shutdown::check_capture()?;
        let timeout_ms = timeout.as_millis().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "capture poll timeout is too large",
            )
        })?;
        let mut stream = Self::new(device.handle(), timeout_ms);
        stream.allocate(count)?;
        Ok(stream)
    }

    fn new(handle: Arc<Handle>, timeout_ms: i32) -> Self {
        Self {
            handle,
            buffers: Vec::new(),
            timeout_ms,
            buffers_requested: false,
            active: false,
            held: None,
            failed: false,
            producer: crate::capture_shutdown::Producer::new(),
            stop_attempted: false,
            parked: 0,
            delivered: false,
            #[cfg(test)]
            fake: None,
        }
    }

    pub(super) fn producer(&self) -> crate::capture_shutdown::Producer {
        self.producer.clone()
    }

    #[cfg(test)]
    fn test_new(handle: Arc<Handle>, timeout_ms: i32) -> Self {
        let mut stream = Self::new(handle, timeout_ms);
        stream.producer = crate::capture_shutdown::Producer::for_test();
        stream
    }

    fn allocate(&mut self, count: u32) -> io::Result<()> {
        let mut req = request_buffers(count);
        // The owner exists before the ioctl, so partial allocation/mapping
        // failures run the same stop, unmap and REQBUFS(0) cleanup as success.
        self.buffers_requested = true;
        self.ioctl(
            vidioc::VIDIOC_REQBUFS,
            (&mut req as *mut v4l2_requestbuffers).cast(),
            "REQBUFS",
        )?;
        if req.count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no capture buffers granted",
            ));
        }
        for index in 0..req.count {
            let mut buf = buffer(index);
            self.ioctl(
                vidioc::VIDIOC_QUERYBUF,
                (&mut buf as *mut v4l2_buffer).cast(),
                "QUERYBUF",
            )?;
            if buf.length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty capture mapping",
                ));
            }
            self.buffers.push(self.map_buffer(&buf)?);
        }
        Ok(())
    }

    fn map_buffer(&self, buf: &v4l2_buffer) -> io::Result<Mapping> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return tests::map(fake, buf);
        }
        // SAFETY: QUERYBUF supplied this nonzero length and MMAP offset for an
        // allocated buffer on our held fd. The returned Mapping owns the view.
        let ptr = unsafe {
            v4l2::mmap(
                std::ptr::null_mut(),
                buf.length as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.handle.fd(),
                buf.m.offset.into(),
            )?
        };
        let Some(ptr) = NonNull::new(ptr) else {
            // SAFETY: mmap succeeded at address zero, which cannot back a Rust
            // reference. Release that mapping rather than ever exposing it.
            unsafe { v4l2::munmap(ptr, buf.length as usize) }?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "null capture mapping",
            ));
        };
        Ok(Mapping {
            ptr,
            len: buf.length as usize,
            #[cfg(test)]
            fake: None,
        })
    }

    fn ioctl(
        &self,
        request: vidioc::_IOC_TYPE,
        arg: *mut libc::c_void,
        operation: &str,
    ) -> io::Result<()> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            // SAFETY: each call below uses the ABI object matching request.
            return unsafe { fake.lock().unwrap().ioctl(request, arg, operation) };
        }
        let _ = operation;
        // SAFETY: handle keeps the fd live and callers supply the correctly
        // initialized ABI structure or type integer matching request.
        unsafe { v4l2::ioctl(self.handle.fd(), request, arg) }
    }

    fn queue(&self, index: u32) -> io::Result<()> {
        let mut buf = buffer(index);
        self.ioctl(
            vidioc::VIDIOC_QBUF,
            (&mut buf as *mut v4l2_buffer).cast(),
            "QBUF",
        )
        .map_err(|error| operation_error(Operation::Queue, error))
    }

    fn wait(&self) -> io::Result<()> {
        #[cfg(test)]
        let result = if let Some(fake) = &self.fake {
            fake.lock().unwrap().poll()
        } else {
            self.handle.poll(libc::POLLIN, self.timeout_ms)
        };
        #[cfg(not(test))]
        let result = self.handle.poll(libc::POLLIN, self.timeout_ms);
        if result? == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "VIDIOC_DQBUF"));
        }
        Ok(())
    }
}

impl CaptureDequeue for MmapCapture {
    fn dequeue(&mut self) -> io::Result<(&[u8], Metadata)> {
        self.producer.check()?;
        if self.failed {
            return Err(operation_error(
                Operation::Retired,
                io::Error::other("capture queue state is uncertain; recreate the stream"),
            ));
        }
        if !self.active {
            self.failed = true;
            for index in 0..self.buffers.len() {
                self.queue(index as u32)?;
            }
            let mut kind = Type::VideoCapture as u32;
            self.producer.begin()?;
            self.ioctl(
                vidioc::VIDIOC_STREAMON,
                (&mut kind as *mut u32).cast(),
                "STREAMON",
            )
            .map_err(|error| operation_error(Operation::Start, error))?;
            self.active = true;
            self.failed = false;
        } else if let Some(index) = self.held.take() {
            self.failed = true;
            self.queue(index)?;
            self.failed = false;
        }

        // No userspace-owned buffer exists past this point until DQBUF succeeds.
        // A timeout, interruption or EAGAIN therefore retries only the wait/DQ.
        // EIO may even consume an unidentified buffer: never guess its index.
        let buf = loop {
            self.wait()
                .map_err(|error| operation_error(Operation::Wait, error))?;
            let mut buf = buffer(0);
            self.ioctl(
                vidioc::VIDIOC_DQBUF,
                (&mut buf as *mut v4l2_buffer).cast(),
                "DQBUF",
            )
            .map_err(|error| operation_error(Operation::Dequeue, error))?;
            self.producer.check()?;
            if buf.flags & v4l::buffer::Flags::ERROR.bits() == 0 {
                break buf;
            }
            // Affected UVC cancel paths can publish ERROR before async copies
            // finish. No mapped reference or requeue is permissible here.
            //
            // Some cameras mark a start-up frame as ERROR while the stream
            // itself is sound. Parking keeps both rules: the buffer stays
            // dequeued and unviewed until teardown, as in a retired ring, and
            // the kernel keeps at least one other buffer to fill.
            let remaining = self.buffers.len().saturating_sub(self.parked as usize + 1);
            if self.delivered || self.parked >= MAX_PARKED_STARTUP_ERRORS || remaining == 0 {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "driver returned an error-marked capture buffer; ring retired",
                ));
            }
            self.parked += 1;
            irlume_common::dlog!(
                "parked error-marked start-up capture buffer {}",
                self.parked
            );
        };
        let Some(mapping) = self.buffers.get(buf.index as usize) else {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dequeued capture index is out of range",
            ));
        };
        self.held = Some(buf.index);
        self.delivered = true;
        let metadata = Metadata {
            bytesused: buf.bytesused,
            flags: buf.flags.into(),
            field: buf.field,
            timestamp: buf.timestamp.into(),
            sequence: buf.sequence,
        };
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            fake.lock().unwrap().view_created();
        }
        // SAFETY: non-ERROR DQBUF transfers a normally completed buffer to
        // userspace. This relies on initialized mapping backing (as supplied by
        // UVC/vb2), completion of driver writes, one queue operator, and no
        // independent authorized writer. ERROR completion is rejected above
        // because affected UVC cancellation can finish async copies later.
        // The slice is bounded by the mapping and borrows self, preventing our
        // QBUF/unmap while borrowed. Later bytesused validation checks payload
        // bounds; it does not establish initialization or writer exclusion.
        let bytes =
            unsafe { std::slice::from_raw_parts(mapping.ptr.as_ptr().cast::<u8>(), mapping.len) };
        Ok((bytes, metadata))
    }

    fn quiesce(&mut self) -> io::Result<()> {
        self.failed = true;
        if self.stop_attempted {
            return if self.producer.is_quiescent() {
                Ok(())
            } else {
                Err(io::Error::other("capture stream stop remains unconfirmed"))
            };
        }
        self.stop_attempted = true;
        let mut kind = Type::VideoCapture as u32;
        let result = self.ioctl(
            vidioc::VIDIOC_STREAMOFF,
            (&mut kind as *mut u32).cast(),
            "STREAMOFF",
        );
        match &result {
            Ok(()) => self.producer.stopped(),
            Err(_) if !self.producer.is_quiescent() => self.producer.unconfirmed(),
            Err(_) => {} // STREAMON was never attempted: no producer to drain.
        }
        result
    }
}

impl Drop for MmapCapture {
    fn drop(&mut self) {
        if !self.buffers_requested {
            return;
        }
        if let Err(error) = self.quiesce() {
            irlume_common::dlog!("capture STREAMOFF failed: {error}");
        }
        if !self.producer.is_quiescent() {
            // Keep the allocation reference, mapped views and file description
            // alive. The native domain never drops these on guessed close or
            // disconnect evidence; subsequent capture admission is faulted.
            self.producer
                .after_stop((self.handle.clone(), std::mem::take(&mut self.buffers)));
            return;
        }
        self.buffers.clear();
        let mut req = request_buffers(0);
        if let Err(error) = self.ioctl(
            vidioc::VIDIOC_REQBUFS,
            (&mut req as *mut v4l2_requestbuffers).cast(),
            "REQBUFS(0)",
        ) {
            irlume_common::dlog!("capture REQBUFS(0) failed: {error}");
        }
    }
}

fn buffer(index: u32) -> v4l2_buffer {
    // SAFETY: v4l2_buffer is a plain kernel ABI object; all-zero fields/unions
    // are valid. Set the required index, type and memory before every ioctl.
    let mut buf: v4l2_buffer = unsafe { std::mem::zeroed() };
    buf.index = index;
    buf.type_ = Type::VideoCapture as u32;
    buf.memory = Memory::Mmap as u32;
    buf
}

fn request_buffers(count: u32) -> v4l2_requestbuffers {
    // SAFETY: v4l2_requestbuffers is a plain kernel ABI object, with reserved
    // fields required to be zero. Initialize count, type and memory below.
    let mut req: v4l2_requestbuffers = unsafe { std::mem::zeroed() };
    req.count = count;
    req.type_ = Type::VideoCapture as u32;
    req.memory = Memory::Mmap as u32;
    req
}

#[cfg(test)]
mod tests;
