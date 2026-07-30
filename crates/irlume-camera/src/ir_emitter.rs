// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Active-IR emitter activation for Windows-Hello-class UVC cameras.
//!
//! Hello camera modules pair a greyscale NIR sensor with an 850nm illuminator
//! that `uvcvideo` does not drive, so IR frames come back black until something
//! puts the camera into its face-authentication mode. On Windows the vendor
//! driver does that through a UVC Extension Unit control.
//!
//! irlume used to find that control by writing guessed payloads to every unit
//! 0..=31 and selector 0..=15 until the picture brightened. That destroyed a
//! reporter's camera (#159). Nothing here guesses any more:
//!
//! - [`enable`] applies a control that is already known, and for anything
//!   applied automatically it first checks the USB descriptor says the camera
//!   implements it.
//! - [`discover`] finds a control by reading the descriptor, considering only
//!   Microsoft's documented camera-control extension unit, and building the
//!   value to write from the camera's own answers about that control.
//!
//! Precedence for [`enable`]: `IRLUME_IR_EMITTER=off` disables; an explicit
//! `IRLUME_IR_EMITTER=unit:sel:b,b,...` supplies the bytes and may name a
//! vendor's unit rather than Microsoft's, because a person reading vendor
//! documentation is the case it exists for; otherwise the persisted config or
//! the built-in table.
//!
//! **Every one of those passes the descriptor check.** The override used to
//! skip it: it was written before identity was even read, so arbitrary bytes
//! went to an arbitrary unit on whichever device was open, and because [`enable`]
//! runs every eighth frame of every capture, one variable in the daemon's
//! environment repeated that write for the life of the process. Naming a control
//! is consent to write it; it is not consent to write to a control the camera
//! has never said it has, and it is not consent to keep writing it forever. See
//! `apply_override`.
//!
//! Approach credit: EmixamPP/linux-enable-ir-emitter (MIT) for the idea of
//! driving the emitter from userspace. The search it uses is exactly what is no
//! longer done here; upstream gates that behind an interactive warning about
//! firmware corruption, which irlume did not.

use std::os::raw::c_int;
use std::path::PathBuf;

const UVC_SET_CUR: u8 = 0x01;
const UVC_GET_CUR: u8 = 0x81;
const UVC_GET_LEN: u8 = 0x85;
const UVC_GET_MIN: u8 = 0x82;
const UVC_GET_RES: u8 = 0x84;
const UVC_GET_MAX: u8 = 0x83;
const UVC_GET_INFO: u8 = 0x86;
const UVC_GET_DEF: u8 = 0x87;

/// `struct uvc_xu_control_query` from `linux/uvcvideo.h`.
#[repr(C)]
struct UvcXuControlQuery {
    unit: u8,
    selector: u8,
    query: u8,
    size: u16,
    data: *mut u8,
}

/// `UVCIOC_CTRL_QUERY` = `_IOWR('u', 0x21, struct uvc_xu_control_query)`.
const fn uvcioc_ctrl_query() -> libc::c_ulong {
    const DIR_RW: libc::c_ulong = 3;
    let size = core::mem::size_of::<UvcXuControlQuery>() as libc::c_ulong;
    (DIR_RW << 30) | (size << 16) | ((b'u' as libc::c_ulong) << 8) | 0x21
}

#[derive(Clone, Debug, PartialEq)]
pub struct EmitterControl {
    pub unit: u8,
    pub selector: u8,
    pub payload: Vec<u8>,
}

impl EmitterControl {
    /// Serialize as `unit:selector:b,b,...` (the `IRLUME_IR_EMITTER` syntax).
    pub fn encode(&self) -> String {
        let p: Vec<String> = self.payload.iter().map(|b| b.to_string()).collect();
        format!("{}:{}:{}", self.unit, self.selector, p.join(","))
    }
}

/// 8-bit greyscale mean above which an IR capture counts as usable for
/// authentication. Emitter-only illumination measures ~40-140 on validated
/// hardware (Zenbook, N930W); an unlit sensor sits below ~35 even in a bright
/// room.
///
/// This answers "is this frame good enough to authenticate against". It is
/// deliberately NOT what decides whether an emitter control works: that is a
/// question about whether writing the control changed anything, and it is
/// answered by a lift over the emitter-off baseline. The same camera here has
/// measured anywhere from 38 to 168 depending only on what was in front of it.
pub(crate) const IR_LIT_MEAN: f32 = 40.0;
/// Minimum mean lift over the emitter-off baseline before [`discover`]
/// calls a control a success; filters ambient flicker and exposure drift.
const AUTOCONF_MIN_LIFT: f32 = 20.0;

/// Built-in table, keyed on USB `idVendor:idProduct`. Verified on-hardware.
///
/// This used to match a substring of the V4L card name, so every camera whose
/// name happened to contain "ASUS" received nine bytes at unit 14 selector 6.
/// A name is not an identity, and the entry is only meaningful for the exact
/// module it was validated against. The unit number is still checked against the
/// descriptor before anything is written; see [`control_is_documented`].
///
/// Both entries address Microsoft's Face Authentication control (0x06). The
/// payload was validated on that hardware and is kept verbatim: it is not
/// derived from a rule irlume knows, so it is not extrapolated to other cameras.
fn known_control(vid: u16, pid: u16) -> Option<EmitterControl> {
    const HELLO_FACE_AUTH: [u8; 9] = [1, 3, 2, 0, 0, 0, 0, 0, 0];
    match (vid, pid) {
        // Shinetech "ASUS FHD webcam" in the Zenbook S 14; MS-XU is unit 14.
        (0x3277, 0x0059) => Some(EmitterControl {
            unit: 14,
            selector: crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
            payload: HELLO_FACE_AUTH.to_vec(),
        }),
        // NexiGo HelloCam N930W; MS-XU is unit 4.
        (0x3443, 0xc803) => Some(EmitterControl {
            unit: 4,
            selector: crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
            payload: HELLO_FACE_AUTH.to_vec(),
        }),
        // Anything else runs `irlume ir-setup`, or sets IRLUME_IR_EMITTER if the
        // vendor documents a control.
        _ => None,
    }
}

/// Whether a control may be written to the camera behind `id` without anyone
/// asking at this moment: it must sit on that camera's Microsoft camera-control
/// unit and name a selector the unit advertises.
///
/// Everything applied automatically goes through this, and the identity comes
/// from the file descriptor that will receive the write, so the descriptor that
/// authorises a write always describes the device that gets it.
///
/// Deliberately not memoised. A cache keyed on a device-node name would survive
/// a replug and authorise a different camera that inherited `/dev/video2`, and a
/// cached refusal would outlive a transient sysfs failure. Reading roughly a
/// kilobyte from sysfs costs far less than writing to the wrong camera.
pub(crate) fn control_is_documented(
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> bool {
    match id.microsoft_xu() {
        Some(ms) => ms.unit_id == ctrl.unit && ms.advertises(ctrl.selector),
        None => false,
    }
}

/// Persisted config path (written by `ir-setup`, read by [`enable`]).
fn conf_path() -> PathBuf {
    std::env::var("IRLUME_IR_EMITTER_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/irlume/ir_emitter.conf"))
}

/// Which control `ir-setup` found, if it was recorded for the camera now
/// attached. Coordinates only:
///
/// ```text
/// 3277:0059 14:6
/// ```
///
/// **No payload is stored.** A stored payload is an unauthenticated value that
/// gets replayed into the camera on every capture forever, and nothing about a
/// file proves the bytes in it were ever the device's own. Recording only which
/// control worked means the value written is re-read from the camera through
/// `GET_DEF` at the moment it is used, and passes the same checks a fresh
/// discovery run applies.
///
/// The camera is recorded because unit and selector numbers are per-camera: a
/// file written for one module would otherwise be replayed into another that
/// happens to expose something at the same coordinates.
///
/// Files written before 0.7.1 have a payload and no camera, and are refused.
/// They came from a search that wrote invented payloads until the picture
/// brightened, there is no record of which camera they belong to, and the
/// control they name cannot be assumed harmless because the current camera has
/// something at the same numbers. Anyone affected re-runs `irlume ir-setup`, or
/// is covered by the built-in table.
fn load_conf(id: &crate::uvc_descriptor::CameraIdentity) -> Option<(u8, u8)> {
    let raw = std::fs::read_to_string(conf_path()).ok()?;
    let line = raw.lines().next()?.trim();
    let (recorded, coords) = line.split_once(' ')?;
    if !recorded.eq_ignore_ascii_case(&id.usb_id()) {
        return None;
    }
    let (unit, selector) = coords.trim().split_once(':')?;
    // A third field means this is an old file carrying a payload, or a
    // malformed one. Either way it is not a record this version wrote.
    if selector.contains(':') {
        return None;
    }
    let (unit, selector) = (parse_u8(unit)?, parse_u8(selector)?);
    // Only the two controls discovery can ever record. Without this a file
    // reading "3277:0059 14:1" would put GET_INFO, GET_LEN, GET_DEF and SET_CUR
    // traffic onto Microsoft's Focus control on every capture, and no version of
    // this code could have written that file.
    if selector != crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION
        && selector != crate::uvc_descriptor::MSXU_IR_TORCH
    {
        return None;
    }
    Some((unit, selector))
}

/// Record which control worked, stamped with the camera it was found on.
///
/// Versions before 0.7.1 stored the payload too, and a second "brightness boost"
/// line found by writing 0xFF across a control of unknown meaning. Neither is
/// written or read any more.
pub fn save_conf(
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> std::io::Result<()> {
    let path = conf_path();
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    // Atomic and fsynced, because the undo record is dropped on the strength of
    // this call returning. `std::fs::write` closes the file without syncing
    // anything, so a successful return only meant the bytes were in the page
    // cache: a power loss immediately afterwards left the record durably GONE
    // and the configuration naming the control that is now lit possibly absent.
    // `commit` says it is called once the configuration is durable, and that was
    // not true of what it was called after.
    //
    // A requested 0644, which the process umask then narrows: under the shipped
    // `UMask=0027` the file lands at 0640, exactly as `std::fs::write` left it
    // before this became atomic. The mode is unchanged by this commit, and the
    // earlier comment here claiming a plain 0644 was simply wrong about the
    // machine it runs on.
    irlume_common::write_atomic_mode(
        &path,
        format!("{} {}:{}", id.usb_id(), ctrl.unit, ctrl.selector).as_bytes(),
        0o644,
    )?;
    irlume_common::fsync_ancestors(dir).map_err(std::io::Error::other)
}

/// Parse `unit:selector:b,b,b,...` (decimal or `0x` hex bytes).
fn parse_control(raw: &str) -> Option<EmitterControl> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut parts = raw.split(':');
    let unit = parse_u8(parts.next()?)?;
    let selector = parse_u8(parts.next()?)?;
    // Every byte must parse. `filter_map` silently dropped invalid fields, so
    // "14:6:1,bad,3" became the two-byte payload [1, 3]: a typo or a corrupted
    // file quietly became a different write.
    let payload: Option<Vec<u8>> = parts.next()?.split(',').map(parse_u8).collect();
    let payload = payload?;
    if payload.is_empty() {
        return None;
    }
    // A trailing field means the value is not what its author thought it was.
    if parts.next().is_some() {
        return None;
    }
    Some(EmitterControl {
        unit,
        selector,
        payload,
    })
}

/// What `IRLUME_IR_EMITTER` says, with "not set" kept distinct from "set to
/// something unusable".
///
/// Those were one case. `std::env::var(..).ok()` and a failed parse both became
/// `None`, and `None` meant "no override, carry on to the persisted config or
/// the built-in table". So a typo in a value written to REPLACE the built-in
/// payload caused irlume to write the built-in payload, repeatedly, and said
/// nothing.
#[derive(Debug, PartialEq)]
enum OverrideSetting {
    /// Not set. The persisted config and the built-in table still apply.
    Absent,
    /// `off` or `none`: drive nothing at all.
    Disabled,
    /// A control to apply, subject to every check in `apply_override`.
    Control(EmitterControl),
    /// Set to something that is not a control. Carries why, for the message.
    Malformed(String),
}

fn override_setting(raw: std::result::Result<String, std::env::VarError>) -> OverrideSetting {
    let raw = match raw {
        Err(std::env::VarError::NotPresent) => return OverrideSetting::Absent,
        // Set, and not readable as text. Refusing is the only honest answer:
        // irlume cannot tell what was asked for.
        Err(std::env::VarError::NotUnicode(_)) => {
            return OverrideSetting::Malformed("is not valid text".into())
        }
        Ok(raw) => raw,
    };
    match raw.trim() {
        "off" | "none" => OverrideSetting::Disabled,
        // An empty value is someone clearing the variable, not a typo.
        "" => OverrideSetting::Absent,
        trimmed => match parse_control(trimmed) {
            Some(ctrl) => OverrideSetting::Control(ctrl),
            None => OverrideSetting::Malformed(format!(
                "is set to {trimmed:?}, which is not unit:selector:bytes, so nothing was driven; \
                 unset it to use the camera's own control"
            )),
        },
    }
}

fn parse_u8(s: &str) -> Option<u8> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

// --- low-level UVC extension-unit I/O ------------------------------------------

/// Why an extension-unit request failed.
///
/// The old code reduced every failure to `false`. A camera that had stopped
/// answering was therefore indistinguishable from one politely reporting that it
/// does not implement a control, which is how the sweep in #159 kept writing to
/// a device that had already stopped responding: seven `SET_CUR` timeouts on one
/// selector, then on to the next two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XuError {
    /// The request was refused without reaching the device, or the device
    /// answered with a stall, which is how a camera says "I do not implement
    /// that". Expected while checking what exists, and safe to continue past.
    Unsupported,
    /// The device did not answer, or the bus reported an error. The hardware is
    /// in an unknown state and nothing further may be sent to it.
    Unresponsive(i32),
}

impl XuError {
    fn from_errno(errno: i32) -> Self {
        match errno {
            // Rejected by the kernel before any USB traffic, or a device stall.
            // Neither indicates the device is in trouble.
            libc::EINVAL | libc::ENOENT | libc::EPIPE | libc::EACCES | libc::EPERM => {
                Self::Unsupported
            }
            // ETIMEDOUT, EPROTO, EILSEQ, ENODEV, EIO and anything unrecognised.
            // Unknown errnos are treated as dangerous on purpose: the failure
            // mode of guessing wrong here is a destroyed camera.
            other => Self::Unresponsive(other),
        }
    }
}

impl std::fmt::Display for XuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "control not supported"),
            Self::Unresponsive(e) => write!(
                f,
                "camera did not answer ({})",
                std::io::Error::from_raw_os_error(*e)
            ),
        }
    }
}

type XuResult<T> = std::result::Result<T, XuError>;

fn xu_query(fd: c_int, unit: u8, selector: u8, query: u8, data: &mut [u8]) -> XuResult<()> {
    // Every read is traced HERE, not in `get_of`, because `get_len` and
    // `get_info` have fixed widths and call this directly. The trace used to sit
    // in `get_of` under a comment calling it "the single choke point for every
    // READ", which was simply untrue: the two queries the ordering claim is
    // ABOUT were the two it could not see. A hardware run produced a transcript
    // with no GET_LEN in it at all, which is what caught it. The unit tests
    // could not: the stand-in camera intercepts at this level and sees
    // everything either way.
    //
    // `SET_CUR` is left to `set_cur`, which prints the payload bytes, so each
    // ioctl appears exactly once and the order can be read straight off.
    if query != UVC_SET_CUR && std::env::var_os("IRLUME_LOG_EMITTER_WRITES").is_some() {
        let name = match query {
            UVC_GET_CUR => "GET_CUR",
            UVC_GET_LEN => "GET_LEN",
            UVC_GET_INFO => "GET_INFO",
            UVC_GET_DEF => "GET_DEF",
            UVC_GET_MIN => "GET_MIN",
            UVC_GET_MAX => "GET_MAX",
            UVC_GET_RES => "GET_RES",
            other => &format!("GET_{other:#04x}"),
        };
        eprintln!(
            "irlume: {name} unit{unit}/sel{selector} size={}",
            data.len()
        );
    }
    // A test may stand in for the camera here. Every read and every write in
    // this module funnels through this one call, so a fake installed here can
    // drive the whole discovery sequence, record the exact order of requests,
    // and make a chosen one fail.
    //
    // That matters more than usual. The guards on this path are ORDERINGS
    // between ioctls — the record durable before the first write, no second
    // write after the camera refuses one, the attempt counted before the retry —
    // and an ordering leaves nothing behind for a test to inspect afterwards.
    // Four mutants that each reintroduced a hardware-destructive defect survived
    // the entire suite before this existed, because nothing without a camera
    // could reach the code at all.
    #[cfg(test)]
    if let Some(result) = fake_camera::intercept(unit, selector, query, data) {
        return result;
    }
    let mut q = UvcXuControlQuery {
        unit,
        selector,
        query,
        size: data.len() as u16,
        data: data.as_mut_ptr(),
    };
    // SAFETY: fd is a valid open UVC fd owned by the caller; data outlives the call.
    let rc = unsafe { libc::ioctl(fd, uvcioc_ctrl_query(), &mut q as *mut UvcXuControlQuery) };
    if rc >= 0 {
        return Ok(());
    }
    Err(XuError::from_errno(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    ))
}

/// A stand-in camera for tests, installed in front of [`xu_query`].
///
/// Thread-local, so tests that use it need no lock and cannot disturb each
/// other. Absent by default, in which case every query goes to the real ioctl
/// exactly as before.
#[cfg(test)]
pub(crate) mod fake_camera {
    use super::{XuError, XuResult, UVC_GET_CUR, UVC_GET_INFO, UVC_GET_LEN, UVC_SET_CUR};
    use std::cell::RefCell;

    /// One request the code under test made, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Request {
        Get {
            query: u8,
            size: usize,
        },
        Set(Vec<u8>),
        /// A check installed as `at_first_write` failed. Recorded rather than
        /// panicked so the assertion belongs to the test, not to the fake.
        FailedPrecondition(String),
    }

    // `at_first_write` is a boxed closure, so this cannot derive Debug. Nothing
    // needs it to.
    #[derive(Default)]
    pub(crate) struct Camera {
        /// What `GET_CUR` answers. Updated by an accepted `SET_CUR`, like a real
        /// control, so a read-back reflects what was written.
        pub(crate) current: Vec<u8>,
        pub(crate) len: usize,
        /// `GET_INFO`: D0 get, D1 set.
        pub(crate) info: u8,
        /// `GET_DEF`, `GET_MAX`, `GET_MIN`, `GET_RES`. Separate from `current`
        /// because the payload discovery intends is DERIVED from them: a fake
        /// that answered every query with the same bytes would make
        /// `intended_value` equal the current value and the run would stop
        /// before writing anything, which is a pass for the wrong reason.
        pub(crate) def: Vec<u8>,
        pub(crate) max: Vec<u8>,
        pub(crate) min: Vec<u8>,
        pub(crate) res: Vec<u8>,
        /// Fail the Nth `SET_CUR` (1-based) with this errno, and every one after
        /// it. Models a camera that stops answering, which is the state this
        /// module must send nothing further to.
        pub(crate) fail_set_from: Option<(usize, i32)>,
        /// Fail every `GET_CUR` from now on. A camera can stop answering a READ
        /// too, and what the code must do about it differs: an ioctl error means
        /// send nothing further, while a value that merely disagrees means the
        /// control still needs putting back.
        pub(crate) fail_get_cur: Option<i32>,
        /// After this many `GET_CUR`s, the control quietly becomes this value.
        ///
        /// Models something OTHER than irlume writing the control mid-sequence,
        /// which is the only way to exercise the gap between an authorising read
        /// and the write it authorises.
        pub(crate) change_after_gets: Option<(usize, Vec<u8>)>,
        /// `GET_CUR`s seen so far.
        pub(crate) gets_seen: usize,
        /// `SET_CUR`s seen so far, so `fail_set_from` can count.
        pub(crate) sets_seen: usize,
        /// Run at the instant the first `SET_CUR` is intercepted, before it is
        /// recorded or applied.
        ///
        /// The only way to observe "the record was on disk BEFORE the camera was
        /// written to". Checking after the run cannot tell that apart from a
        /// record written afterwards, and a test that cannot tell them apart is
        /// not a test of the ordering: review pointed out that the first version
        /// of this assertion would have passed with `open` moved below the write,
        /// which is the crash window the whole module exists to close.
        #[allow(clippy::type_complexity)]
        pub(crate) at_first_write: Option<Box<dyn FnMut() -> Result<(), String>>>,
        /// Every request, in order.
        pub(crate) log: Vec<Request>,
    }

    thread_local! {
        static CAMERA: RefCell<Option<Camera>> = const { RefCell::new(None) };
    }

    /// Install a fake for the rest of this test, and take it back at the end.
    pub(crate) struct Installed;

    impl Drop for Installed {
        fn drop(&mut self) {
            CAMERA.with(|c| *c.borrow_mut() = None);
        }
    }

    pub(crate) fn install(camera: Camera) -> Installed {
        CAMERA.with(|c| *c.borrow_mut() = Some(camera));
        Installed
    }

    /// Everything the fake was asked, in order.
    pub(crate) fn log() -> Vec<Request> {
        CAMERA.with(|c| {
            c.borrow()
                .as_ref()
                .map(|cam| cam.log.clone())
                .unwrap_or_default()
        })
    }

    /// Make every later `GET_CUR` fail.
    pub(crate) fn fail_reads(errno: i32) {
        CAMERA.with(|c| {
            if let Some(cam) = c.borrow_mut().as_mut() {
                cam.fail_get_cur = Some(errno);
            }
        });
    }

    /// Force what the control reports, without a write.
    ///
    /// Models a camera that accepted a `SET_CUR` and is nonetheless holding
    /// something else: a clamp, a partial apply, or a mode it resolved
    /// differently. The fake normally follows an accepted write, which is right
    /// for every other test and useless for this one.
    pub(crate) fn set_current(value: Vec<u8>) {
        CAMERA.with(|c| {
            if let Some(cam) = c.borrow_mut().as_mut() {
                cam.current = value;
            }
        });
    }

    /// What the control holds now.
    pub(crate) fn current() -> Vec<u8> {
        CAMERA.with(|c| {
            c.borrow()
                .as_ref()
                .map(|cam| cam.current.clone())
                .unwrap_or_default()
        })
    }

    /// `None` when no fake is installed, so the real ioctl runs.
    pub(crate) fn intercept(
        _unit: u8,
        _selector: u8,
        query: u8,
        data: &mut [u8],
    ) -> Option<XuResult<()>> {
        CAMERA.with(|cell| {
            let mut borrowed = cell.borrow_mut();
            let cam = borrowed.as_mut()?;
            Some(match query {
                UVC_SET_CUR => {
                    cam.sets_seen += 1;
                    if cam.sets_seen == 1 {
                        if let Some(check) = cam.at_first_write.as_mut() {
                            if let Err(why) = check() {
                                cam.log.push(Request::FailedPrecondition(why));
                                return Some(Err(XuError::from_errno(libc::EIO)));
                            }
                        }
                    }
                    cam.log.push(Request::Set(data.to_vec()));
                    match cam.fail_set_from {
                        Some((from, errno)) if cam.sets_seen >= from => {
                            Err(XuError::from_errno(errno))
                        }
                        _ => {
                            // An accepted write changes what the control holds,
                            // so a read-back sees it. A fake whose GET_CUR never
                            // moved would make the read-back check pass for the
                            // wrong reason.
                            cam.current = data.to_vec();
                            Ok(())
                        }
                    }
                }
                UVC_GET_LEN => {
                    cam.log.push(Request::Get {
                        query,
                        size: data.len(),
                    });
                    // Little-endian u16, as the UVC specification defines it.
                    data[0] = (cam.len & 0xff) as u8;
                    if data.len() > 1 {
                        data[1] = ((cam.len >> 8) & 0xff) as u8;
                    }
                    Ok(())
                }
                UVC_GET_INFO => {
                    cam.log.push(Request::Get {
                        query,
                        size: data.len(),
                    });
                    data[0] = cam.info;
                    Ok(())
                }
                UVC_GET_CUR => {
                    cam.gets_seen += 1;
                    cam.log.push(Request::Get {
                        query,
                        size: data.len(),
                    });
                    if let Some(errno) = cam.fail_get_cur {
                        return Some(Err(XuError::from_errno(errno)));
                    }
                    // Answer THIS read first, then change, so the read that
                    // triggers the change still sees the old value.
                    let pending = cam
                        .change_after_gets
                        .as_ref()
                        .filter(|(after, _)| cam.gets_seen >= *after)
                        .map(|(_, v)| v.clone());
                    for (slot, byte) in data.iter_mut().zip(cam.current.iter()) {
                        *slot = *byte;
                    }
                    if let Some(v) = pending {
                        cam.current = v;
                        cam.change_after_gets = None;
                    }
                    Ok(())
                }
                other => {
                    cam.log.push(Request::Get {
                        query: other,
                        size: data.len(),
                    });
                    let source = match other {
                        super::UVC_GET_DEF => &cam.def,
                        super::UVC_GET_MAX => &cam.max,
                        super::UVC_GET_MIN => &cam.min,
                        super::UVC_GET_RES => &cam.res,
                        _ => &cam.current,
                    };
                    for (slot, byte) in data.iter_mut().zip(source.iter()) {
                        *slot = *byte;
                    }
                    Ok(())
                }
            })
        })
    }
}

/// GET_LEN bounds check: a plausible XU control reports 1..=64 payload bytes;
/// anything else (0 from a phantom control, or an absurd length) is rejected.
fn valid_ctrl_len(len: usize) -> Option<usize> {
    (1..=64).contains(&len).then_some(len)
}

/// Payload length of XU control (unit, selector), via `GET_LEN`. Read-only.
fn get_len(fd: c_int, unit: u8, selector: u8) -> XuResult<usize> {
    let mut buf = [0u8; 2];
    xu_query(fd, unit, selector, UVC_GET_LEN, &mut buf)?;
    valid_ctrl_len(usize::from(u16::from_le_bytes(buf))).ok_or(XuError::Unsupported)
}

/// `GET_INFO` capability byte (UVC 1.5 table 4-3).
fn get_info(fd: c_int, unit: u8, selector: u8) -> XuResult<u8> {
    let mut buf = [0u8; 1];
    xu_query(fd, unit, selector, UVC_GET_INFO, &mut buf)?;
    Ok(buf[0])
}

/// Read `size` bytes from a control. Sized reads only; `get_len` and `get_info`
/// have fixed widths and go straight to [`xu_query`], which is where the tracing
/// lives precisely because of that.
fn get_of(fd: c_int, unit: u8, selector: u8, query: u8, size: usize) -> XuResult<Vec<u8>> {
    let mut buf = vec![0u8; size];
    xu_query(fd, unit, selector, query, &mut buf)?;
    Ok(buf)
}

fn get_cur(fd: c_int, unit: u8, selector: u8, size: usize) -> XuResult<Vec<u8>> {
    get_of(fd, unit, selector, UVC_GET_CUR, size)
}

/// The only place anything is written to a camera. Every caller goes through
/// here, so `IRLUME_LOG_EMITTER_WRITES=1` shows every emitter write irlume makes,
/// including restores. That claim was made once while the logging sat on a
/// single path and missed the one actually in use, which is exactly the sort of
/// thing this project can no longer afford to be casual about.
fn set_cur(fd: c_int, unit: u8, selector: u8, payload: &[u8]) -> XuResult<()> {
    if std::env::var_os("IRLUME_LOG_EMITTER_WRITES").is_some() {
        eprintln!("irlume: SET_CUR unit{unit}/sel{selector}: {payload:02x?}");
    }
    #[cfg(test)]
    writes_attempted().fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut data = payload.to_vec();
    xu_query(fd, unit, selector, UVC_SET_CUR, &mut data)
}

/// Counts every write this module attempts, so a test can assert that a path
/// sent NOTHING to the camera.
///
/// A returned `false` cannot make that claim: a refused write and a write the
/// device rejected are both `false`, and the whole of #179 was a path that
/// looked like the second while being the first. Counting at the single choke
/// point makes "no ioctl reached the device" an assertion rather than a reading
/// of the control flow.
#[cfg(test)]
fn writes_attempted() -> &'static std::sync::atomic::AtomicUsize {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    &N
}

/// `GET_INFO` says the control accepts `SET_CUR` and is not currently disabled.
///
/// D1 is "supports SET value requests". D2 and D5 mean the control is disabled
/// by an automatic mode or by the current Commit state, in which case a write is
/// not merely useless, it is a write the device has said it is not ready for.
pub(crate) fn info_allows_set(info: u8) -> bool {
    const SET_SUPPORTED: u8 = 1 << 1;
    const DISABLED_BY_AUTOMATIC: u8 = 1 << 2;
    const DISABLED_BY_COMMIT_STATE: u8 = 1 << 5;
    info & SET_SUPPORTED != 0
        && info & DISABLED_BY_AUTOMATIC == 0
        && info & DISABLED_BY_COMMIT_STATE == 0
}

/// Light the emitter on the open `fd` for `device`, if a control is configured.
/// Returns whether a `SET_CUR` succeeded. Best-effort.
///
/// Three kinds of control reach here and they are not trusted equally:
///
/// - `IRLUME_IR_EMITTER` is a person typing a control they got from vendor
///   documentation. Naming a control is consent to write it, so the unit may be
///   a vendor's rather than Microsoft's; it is not consent to write to a control
///   the camera has never said it has. It goes through `apply_override`, which
///   requires the same evidence from the descriptor and the device that every
///   other write here requires, and is attempted at most once per camera per
///   process.
/// - A control `ir-setup` recorded is applied by re-reading the camera's own
///   default for it. The file stores coordinates, never a payload, so the bytes
///   written are the device's and are checked the same way discovery checks
///   them.
/// - The built-in table carries a payload, because it is a compiled-in constant
///   validated against that exact USB product rather than a value read from a
///   file that anything could have written.
///
/// All three must name a control the attached camera's descriptor says it
/// implements.
///
/// At most one write is attempted. Selection falls through only when a candidate
/// fails validation, which happens before any ioctl. Once a `SET_CUR` has been
/// sent, its result is the answer: sending a second payload to a camera that just
/// failed to accept the first is how the search in #159 kept going.
pub fn enable(fd: c_int, card: &str, device: &str) -> bool {
    let _ = (card, device);
    let setting = override_setting(std::env::var("IRLUME_IR_EMITTER"));
    let wanted = match setting {
        OverrideSetting::Disabled => return false,
        // A value that is set but cannot be read as a control is NOT the same as
        // no value. Treating it as absent fell through to the built-in table, so
        // one mistyped byte in an override meant to replace that payload made
        // irlume write the payload instead, every eighth frame. Setting the
        // variable is consent to the control named in it and to nothing else.
        OverrideSetting::Malformed(why) => {
            eprintln!("irlume: refusing to drive the IR emitter: IRLUME_IR_EMITTER {why}");
            return false;
        }
        OverrideSetting::Absent => None,
        OverrideSetting::Control(ctrl) => Some(ctrl),
    };

    // Identity comes from the descriptor that will receive the write, not from a
    // path that could point somewhere else by the time the ioctl runs.
    //
    // The override used to be applied before this point, so a camera whose
    // descriptors could not be read was still written to. It is now the first
    // thing every path needs, including the override: without the descriptor
    // there is no evidence about anything, and #159 is what writing without
    // evidence costs.
    let id = match crate::uvc_descriptor::identity_from_fd(fd) {
        Ok(id) => id,
        Err(err) => {
            // Someone who set the variable is owed the reason. Failing silently
            // here reads as "applied, and the camera is dark", which is the
            // reading every other refusal in this file exists to prevent. The
            // automatic paths stay quiet: no one asked for them, and a camera
            // with no readable descriptor is the ordinary case for a device
            // irlume does not drive.
            if let Some(ctrl) = &wanted {
                eprintln!(
                    "irlume: refusing IRLUME_IR_EMITTER={}: could not read the open camera's USB \
                     descriptors ({err}), so unit {} selector {} cannot be checked against them",
                    ctrl.encode(),
                    ctrl.unit,
                    ctrl.selector
                );
            }
            return false;
        }
    };

    // Before anything is applied. A control an interrupted setup left changed is
    // not where its owner left it, and the value applied below would be layered
    // on top of it.
    //
    // This is a write to camera firmware on a path nobody explicitly asked for,
    // which everything else in this file is written to avoid. It is allowed here
    // because it is not a new class of write: the bytes are the camera's own,
    // read from this control moments before an earlier run changed it, the
    // control is one this camera publishes, and this path is already about to
    // write to that same control. It is the difference between putting something
    // back and trying something out.
    //
    // The `off` and malformed branches returned above and are not reached, so
    // `IRLUME_IR_EMITTER=off` still means irlume sends the camera nothing. A
    // record pending on a machine set that way surfaces through `irlume doctor`
    // instead.
    let recovery = recover_pending_write(fd, &id);
    let action = planned_action(&recovery, wanted, &id);
    report_recovery(&id, recovery);

    match action {
        CaptureAction::Nothing => false,
        CaptureAction::Override(ctrl) => apply_override(fd, &id, &ctrl),
        CaptureAction::DeviceDefault { unit, selector } => {
            apply_device_default(fd, unit, selector).is_ok()
        }
        CaptureAction::KnownPayload(ctrl) => apply_known_payload(fd, &ctrl).is_ok(),
    }
}

/// Which control, if any, a capture should apply to this camera.
///
/// Extracted so the decision is a VALUE. Every input is either pure or a file
/// read a test can point somewhere else, which `enable` itself is not: it needs
/// an open camera to reach any of this, so nothing below could be tested at all
/// while it lived inline. The gap was not theoretical. `enable` used to run the
/// recovery pass, log that a camera must not be written to, and then apply the
/// configured control to the very unit and selector the unresolved record named,
/// at every stream open and every eighth frame of a burst.
fn planned_action(
    recovery: &RecoveryOutcome,
    wanted: Option<EmitterControl>,
    id: &crate::uvc_descriptor::CameraIdentity,
) -> CaptureAction {
    // First, before any of the three sources are consulted: all three write to
    // the same extension unit an unresolved record is about.
    //
    // The cost of refusing is the emitter, so IR authentication does not light
    // and the user falls back to a password until a human resolves it. #159 is
    // a camera that never enumerated again after unverified extension-unit
    // writes, and a control that has already failed to read back what was
    // written to it is the clearest available sign of that territory.
    if !recovery.permits_capture_write() {
        return CaptureAction::Nothing;
    }

    if let Some(ctrl) = wanted {
        return CaptureAction::Override(ctrl);
    }

    if let Some((unit, selector)) = load_conf(id) {
        let recorded = EmitterControl {
            unit,
            selector,
            payload: Vec::new(),
        };
        if control_is_documented(id, &recorded) {
            return CaptureAction::DeviceDefault { unit, selector };
        }
    }

    match known_control(id.vid, id.pid).filter(|c| control_is_documented(id, c)) {
        Some(ctrl) => CaptureAction::KnownPayload(ctrl),
        None => CaptureAction::Nothing,
    }
}

/// What `enable` decided to send the camera. `Nothing` means no ioctl at all.
#[derive(Debug, Clone, PartialEq)]
enum CaptureAction {
    Nothing,
    Override(EmitterControl),
    DeviceDefault { unit: u8, selector: u8 },
    KnownPayload(EmitterControl),
}

/// Why an `IRLUME_IR_EMITTER` override was not written to the camera.
///
/// Each variant names something the camera itself failed to say, so the message
/// can tell the person who set the variable which claim was not backed up rather
/// than leaving them to conclude the value was wrong and try another one.
/// Crate-private: `ir_emitter` is a `pub mod`, so a `pub` type in it becomes
/// part of `irlume-camera`'s public API, and this one is only ever produced and
/// consumed inside this file.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum OverrideRefusal {
    /// The USB descriptor has no extension unit with that id.
    NoSuchUnit { unit: u8, seen: Vec<u8> },
    /// The unit exists but its `bmControls` does not advertise that selector.
    NotAdvertised { unit: u8, selector: u8 },
    /// `GET_INFO` says the control does not accept a write right now.
    WriteNotAccepted { unit: u8, selector: u8, info: u8 },
    /// `GET_LEN` disagrees with how many bytes the override supplies.
    WrongLength {
        unit: u8,
        selector: u8,
        wants: usize,
        given: usize,
    },
    /// A request the descriptor says the control answers went unanswered, so the
    /// control is not demonstrably the one the documentation described.
    Unreadable {
        unit: u8,
        selector: u8,
        err: XuError,
    },
}

impl std::fmt::Display for OverrideRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchUnit { unit, seen } => write!(
                f,
                "this camera publishes no extension unit {unit} (it has units {seen:?})"
            ),
            Self::NotAdvertised { unit, selector } => write!(
                f,
                "unit {unit} does not advertise selector {selector} in its descriptor"
            ),
            Self::WriteNotAccepted {
                unit,
                selector,
                info,
            } => write!(
                f,
                "unit {unit} selector {selector} reports capabilities {info:#04x}, \
                 which does not accept a write right now"
            ),
            Self::WrongLength {
                unit,
                selector,
                wants,
                given,
            } => write!(
                f,
                "unit {unit} selector {selector} takes {wants} bytes, not the {given} given"
            ),
            Self::Unreadable {
                unit,
                selector,
                err,
            } => write!(
                f,
                "unit {unit} selector {selector} did not answer a request its own descriptor \
                 says it implements ({err})"
            ),
        }
    }
}

/// The descriptor half of the override's gate: the named unit must exist on this
/// camera and advertise the named selector.
///
/// This is what separates a control someone read out of vendor documentation
/// from a coordinate they guessed. It deliberately does NOT require Microsoft's
/// camera-control GUID, which [`control_is_documented`] does: the override
/// exists for cameras that have no Microsoft unit, so requiring one would leave
/// it reachable only where discovery already works. A vendor unit that publishes
/// a selector has stated the control is there. What #159 destroyed a camera by
/// doing was writing to units and selectors nothing had published at all.
///
/// Pure, given an identity, so every refusal is tested without a camera.
pub(crate) fn override_is_published(
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> std::result::Result<(), OverrideRefusal> {
    let units = id.extension_units();
    let Some(unit) = units.iter().find(|u| u.unit_id == ctrl.unit) else {
        return Err(OverrideRefusal::NoSuchUnit {
            unit: ctrl.unit,
            seen: units.iter().map(|u| u.unit_id).collect(),
        });
    };
    if !unit.advertises(ctrl.selector) {
        return Err(OverrideRefusal::NotAdvertised {
            unit: ctrl.unit,
            selector: ctrl.selector,
        });
    }
    Ok(())
}

/// Which control on which open device a decision was about.
///
/// Every field comes from the descriptor that will receive the ioctl. An earlier
/// version keyed partly on the caller's `device` string, which meant the check
/// and the record identified different objects: `enable` takes the fd and the
/// path separately, so two calls on ONE open camera with two spellings of its
/// path were two records and two permitted writes, and one spelling shared
/// between two matching cameras aliased them into one.
///
/// `st_rdev` is the kernel's identifier for the character device behind the fd,
/// so it cannot be spelled two ways. The USB identity and interface number come
/// with it because a node number is reused after a replug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OverrideKey {
    rdev: libc::dev_t,
    interface_number: u8,
    vid: u16,
    pid: u16,
    unit: u8,
    selector: u8,
}

/// What was decided, and for which bytes.
///
/// The payload is kept because the decision was about it. Without it, changing
/// `IRLUME_IR_EMITTER` to a different payload at the same unit and selector
/// returned the cached `true`: the caller was told the value it asked for was
/// active when the camera held different bytes, and the new payload was never
/// length-checked or written.
struct OverrideDecision {
    payload: Vec<u8>,
    applied: bool,
}

type OverrideMemo = std::sync::Mutex<std::collections::HashMap<OverrideKey, OverrideDecision>>;

/// Whether the override has already been decided for one control on one open
/// camera in this process, and what was decided.
///
/// The override used to be re-sent on every [`enable`], which is every eighth
/// frame of every capture: one variable in `irlumed`'s environment became an
/// unbounded stream of firmware writes lasting as long as the daemon. Repeated
/// writes are what #159 ended in, so the answer is computed once and reused,
/// including when it was a refusal or a failed write. A control that self-clears
/// will therefore go dark rather than be re-driven; for bytes irlume cannot
/// check, not writing again is the safer of the two failures.
///
/// What the key cannot distinguish is the same model replugged onto the same
/// node mid-process, since the kernel may hand back the same `st_rdev`. That
/// keeps the earlier answer, which errs towards not writing.
/// What an existing record means for the value now being asked for.
#[derive(Debug, PartialEq)]
enum Reuse {
    /// The same bytes were already decided; that answer stands.
    Answer(bool),
    /// The same control, different bytes. Neither answering from the record nor
    /// writing again is right, so refuse.
    RefuseChanged,
    /// Nothing decided yet.
    Decide,
}

/// Separated from the plumbing because it is the policy, and because the
/// alternative is untestable: with no camera attached every path through
/// `apply_override` returns false, so a test there cannot tell a stale answer
/// from a correct refusal. Here it can.
fn reuse(existing: Option<&OverrideDecision>, wanted: &[u8]) -> Reuse {
    match existing {
        None => Reuse::Decide,
        Some(d) if d.payload == wanted => Reuse::Answer(d.applied),
        Some(_) => Reuse::RefuseChanged,
    }
}

/// Identify the control and the open device a decision is about.
///
/// `fstat` on the fd rather than the path the caller passed, so the record names
/// the same object the ioctl will reach.
fn override_key(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> std::io::Result<OverrideKey> {
    // SAFETY: fstat writes into `st` and borrows `fd` for the call only.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OverrideKey {
        rdev: st.st_rdev,
        interface_number: id.interface_number,
        vid: id.vid,
        pid: id.pid,
        unit: ctrl.unit,
        selector: ctrl.selector,
    })
}

fn override_memo() -> &'static OverrideMemo {
    static MEMO: std::sync::OnceLock<OverrideMemo> = std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}

/// Apply an `IRLUME_IR_EMITTER` override, writing at most once per control per
/// camera per process, and only with the evidence every other write here
/// requires.
///
/// The record bounds the WRITES. It is not used as an answer about the camera's
/// present state: a remembered success re-reads `GET_CUR` and reports whether
/// the control still holds the payload, because "we wrote this once" and "this
/// is set now" stop being the same statement the moment a camera resets.
///
/// The override is still an escape hatch: the unit may be a vendor's, and the
/// bytes are the person's rather than the camera's own `GET_DEF`. What it no
/// longer is, is exempt. Before anything is sent, the descriptor has to publish
/// the unit and the selector, `GET_INFO` has to say a write is accepted now, the
/// payload has to be the length `GET_LEN` states, and `GET_CUR` has to answer.
///
/// The current value is read for two reasons and neither is a restore: this
/// function's purpose is to leave the emitter lit, so it deliberately does not
/// put the control back. It is read because a control that cannot be read is not
/// demonstrably the control the documentation described, and because a control
/// already holding the payload needs no write at all.
fn apply_override(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> bool {
    let key = match override_key(fd, id, ctrl) {
        Ok(key) => key,
        Err(err) => {
            eprintln!(
                "irlume: refusing IRLUME_IR_EMITTER={}: cannot identify the open device ({err}), \
                 so irlume cannot tell whether this was already applied",
                ctrl.encode()
            );
            return false;
        }
    };

    // ONE guard spans the lookup, the device access and the record. Taking the
    // lock twice around an unlocked middle would have made "at most once" a
    // description of the happy path: two callers can both miss, both write, and
    // then both record the same answer. The window is the whole point of the
    // limiter, so it is closed rather than commented.
    //
    // Holding a lock across ioctls is deliberate. It serialises the first
    // override decision across cameras too, which costs one `GET_INFO`/`GET_LEN`/
    // `GET_CUR` round trip of waiting, once per camera per process, and is not
    // reachable from a capture loop after that.
    let mut memo = match override_memo().lock() {
        Ok(memo) => memo,
        // A poisoned lock means a thread panicked mid-decision. Ignoring it
        // would make every later call a miss, which turns the write limiter off
        // exactly when the process has already shown it is not well.
        Err(_) => {
            eprintln!(
                "irlume: refusing IRLUME_IR_EMITTER={}: the one-write record is unavailable \
                 after a panic, so irlume cannot tell whether this was already applied",
                ctrl.encode()
            );
            return false;
        }
    };
    match reuse(memo.get(&key), &ctrl.payload) {
        // A remembered refusal stands: re-running the checks every capture is
        // the traffic the record exists to stop, and the answer is "no" either
        // way.
        Reuse::Answer(false) => return false,
        // A remembered SUCCESS is not repeated back. It says a write happened,
        // which is not the same as the control holding that value now, and the
        // gap between them is real: a camera that resets or re-enumerates can
        // land on the same device number with the same USB id and interface, and
        // returning the old `true` would claim an emitter is lit on a control
        // nothing has set. Callers use this answer to decide whether to tell the
        // user their infrared is dark.
        //
        // So the record is used for what it is good for, which is not writing
        // again, and the current state is read rather than assumed. If the
        // control has drifted, the honest answer is that the emitter is not on;
        // writing it back would be the second write this whole change exists to
        // prevent.
        Reuse::Answer(true) => {
            return match get_cur(fd, ctrl.unit, ctrl.selector, ctrl.payload.len()) {
                Ok(current) => current == ctrl.payload,
                Err(_) => false,
            }
        }
        Reuse::RefuseChanged => {
            eprintln!(
                "irlume: refusing IRLUME_IR_EMITTER={}: unit {} selector {} was already decided \
                 this run for different bytes, and a second value is not written to a control in \
                 one run; restart to apply it",
                ctrl.encode(),
                ctrl.unit,
                ctrl.selector
            );
            return false;
        }
        Reuse::Decide => {}
    }
    let applied = match check_and_apply_override(fd, id, ctrl) {
        Ok(applied) => applied,
        Err(why) => {
            // Silence here would read as "the value was applied and the camera
            // is simply dark", which is the reading that sends someone back to
            // try another unit and selector.
            eprintln!(
                "irlume: refusing IRLUME_IR_EMITTER={}: {why}",
                ctrl.encode()
            );
            false
        }
    };
    memo.insert(
        key,
        OverrideDecision {
            payload: ctrl.payload.clone(),
            applied,
        },
    );
    applied
}

/// Test-only: hold a caller inside the gate so another thread can observe what
/// is true while the device is being talked to.
///
/// The property under test is "the memo lock is held across the device access",
/// and it cannot be observed from outside without stopping time in the middle.
/// Two racing threads would not do: whether the second one gets in is a question
/// of scheduling, so it could pass while the window was wide open.
/// Parks ONLY the thread that armed it. `cargo test` runs tests in parallel in
/// one process, so a flag saying merely "someone is armed" would park whichever
/// unrelated test reached this line first; that thread holds no memo lock, so
/// the observer would see the lock free and report a race that is not there.
#[cfg(test)]
fn park_inside_for_test() {
    use std::sync::atomic::Ordering::SeqCst;
    let armed = test_park().armed.lock().unwrap_or_else(|e| e.into_inner());
    if *armed != Some(std::thread::current().id()) {
        return;
    }
    drop(armed);
    test_park().reached.store(true, SeqCst);
    while !test_park().release.load(SeqCst) {
        std::thread::yield_now();
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestPark {
    armed: std::sync::Mutex<Option<std::thread::ThreadId>>,
    reached: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
fn test_park() -> &'static TestPark {
    static P: std::sync::OnceLock<TestPark> = std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}

/// The gate itself, separated from the memo and the message so a test can assert
/// on the reason rather than on a bare `false`.
fn check_and_apply_override(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> std::result::Result<bool, OverrideRefusal> {
    #[cfg(test)]
    park_inside_for_test();

    // First, and before the fd is touched at all: a unit this camera does not
    // publish is refused without a single ioctl reaching the device.
    override_is_published(id, ctrl)?;

    let (unit, selector) = (ctrl.unit, ctrl.selector);
    // Every query failure below is reported the same way for the reason
    // `DiscoveryError::Unresponsive` collapses its two cases: the selector was
    // just confirmed as advertised, so a failure is the camera contradicting its
    // own descriptor, and uvcvideo's errnos cannot separate a healthy refusal
    // from a device in trouble. Either way nothing further is sent.
    let info = get_info(fd, unit, selector).map_err(|err| OverrideRefusal::Unreadable {
        unit,
        selector,
        err,
    })?;
    if !info_allows_set(info) {
        return Err(OverrideRefusal::WriteNotAccepted {
            unit,
            selector,
            info,
        });
    }
    let len = get_len(fd, unit, selector).map_err(|err| OverrideRefusal::Unreadable {
        unit,
        selector,
        err,
    })?;
    if len != ctrl.payload.len() {
        return Err(OverrideRefusal::WrongLength {
            unit,
            selector,
            wants: len,
            given: ctrl.payload.len(),
        });
    }
    let current = get_cur(fd, unit, selector, len).map_err(|err| OverrideRefusal::Unreadable {
        unit,
        selector,
        err,
    })?;
    if current == ctrl.payload {
        // Already holding what the override asks for. Reporting success is
        // accurate and costs the camera nothing.
        return Ok(true);
    }
    Ok(set_cur(fd, unit, selector, &ctrl.payload).is_ok())
}

/// Apply a validated built-in payload, with the same gate every other automatic
/// write passes.
///
/// A table entry is a constant rather than something read from the camera, so it
/// cannot be re-derived; but the camera still has to say it accepts a write of
/// that size right now. Writing a nine-byte payload to a control the camera has
/// just reported as disabled, or as a different length, is not something a
/// validated VID:PID should buy.
fn apply_known_payload(fd: c_int, ctrl: &EmitterControl) -> XuResult<()> {
    if !info_allows_set(get_info(fd, ctrl.unit, ctrl.selector)?) {
        return Err(XuError::Unsupported);
    }
    if get_len(fd, ctrl.unit, ctrl.selector)? != ctrl.payload.len() {
        return Err(XuError::Unsupported);
    }
    set_cur(fd, ctrl.unit, ctrl.selector, &ctrl.payload)
}

/// The bytes to write for one documented control, or why the camera has not
/// clearly said what it accepts.
///
/// Discovery and every later capture both go through this, so a control that
/// `ir-setup` recorded is re-derived exactly as it was found. Persisting only
/// coordinates is coherent because of that: the camera is the authority at both
/// moments, and nothing is replayed out of a file.
fn intended_value(
    fd: c_int,
    unit: u8,
    selector: u8,
    len: usize,
) -> XuResult<std::result::Result<Vec<u8>, String>> {
    let def = get_of(fd, unit, selector, UVC_GET_DEF, len)?;
    if selector == crate::uvc_descriptor::MSXU_IR_TORCH {
        // Microsoft specifies IR Torch's GET_INFO as exactly 3: a synchronous
        // control supporting GET_CUR and SET_CUR and nothing else. A different
        // answer means this is not the control the specification describes, and
        // the checks below would be validating against the wrong contract.
        const IR_TORCH_INFO: u8 = 3;
        let info = get_info(fd, unit, selector)?;
        if info != IR_TORCH_INFO {
            return Ok(Err(format!(
                "its capabilities are {info:#04x}; the specification requires exactly 0x03 for IR Torch"
            )));
        }
        // Microsoft specifies IR Torch's default as an active mode, so it is
        // used directly, after checking it against the specification.
        let min = get_of(fd, unit, selector, UVC_GET_MIN, len)?;
        let max = get_of(fd, unit, selector, UVC_GET_MAX, len)?;
        let res = get_of(fd, unit, selector, UVC_GET_RES, len)?;
        return Ok(ir_torch_default_is_usable(&def, &min, &max, &res).map(|()| def));
    }
    // Face Authentication's default is general-purpose mode on a dual-purpose
    // interface, so it is derived from the camera's advertised capabilities.
    let max = get_of(fd, unit, selector, UVC_GET_MAX, len)?;
    Ok(face_auth_payload(&def, &max))
}

/// Apply a control's own default, with the checks discovery makes.
///
/// This is how a control recorded by `ir-setup` is re-applied. Nothing is
/// replayed from the file: the value is read out of the camera immediately
/// before it is written back.
fn apply_device_default(fd: c_int, unit: u8, selector: u8) -> XuResult<()> {
    if !info_allows_set(get_info(fd, unit, selector)?) {
        return Err(XuError::Unsupported);
    }
    let len = get_len(fd, unit, selector)?;
    let Ok(wanted) = intended_value(fd, unit, selector, len)? else {
        return Err(XuError::Unsupported);
    };
    set_cur(fd, unit, selector, &wanted)
}

/// Why discovery could not produce a control.
#[derive(Debug, Clone, PartialEq)]
pub enum DiscoveryError {
    /// The USB descriptors could not be read. Never a reason to start guessing.
    Descriptors(String),
    /// The camera has no Microsoft-XU, so irlume has no documented control to
    /// address on it.
    NoMicrosoftXu { seen: Vec<u8> },
    /// The Microsoft-XU is present but advertises no control irlume can use, or
    /// the ones it advertises did not light anything.
    NoUsableControl { unit: u8, tried: Vec<String> },
    /// The camera stopped answering. Discovery is abandoned immediately.
    Unresponsive {
        unit: u8,
        selector: u8,
        err: XuError,
    },
    /// The camera stopped delivering frames, so nothing can be concluded and
    /// nothing further may be sent.
    MeasurementFailed,
    /// Another irlume process is already working on this camera.
    CameraBusy,
    /// A control was changed and could not be put back.
    RestoreFailed {
        unit: u8,
        selector: u8,
        err: XuError,
    },
    /// An earlier run left a control changed and this one could not undo it.
    ///
    /// Discovery's first act is to read a control and treat the answer as the
    /// value to go back to. Run against a control still holding a previous run's
    /// exploratory value, it would record that as the original and the real one
    /// would be gone for good.
    UnresolvedChange,
    /// The undo record could not be written, so nothing was sent to the camera.
    JournalUnwritable(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Descriptors(e) => write!(f, "could not read the camera's USB descriptors: {e}"),
            // This names the escape hatch, so it also has to say what setting it
            // does. "set IRLUME_IR_EMITTER=unit:selector:bytes" reads like a
            // configuration key, and it prints when IR is dark, which is exactly
            // when someone is willing to try numbers. The bytes go to firmware.
            Self::NoMicrosoftXu { seen } => write!(
                f,
                "this camera has no Microsoft camera-control extension unit (found units {seen:?}), \
                 so irlume has no documented way to drive its emitter. If the vendor documents a \
                 control for it, IRLUME_IR_EMITTER=unit:selector:bytes sends those bytes to the \
                 camera's firmware; irlume checks the camera publishes that control before writing, \
                 but the bytes themselves are yours. Do not try numbers to see what happens: that is \
                 what left one reporter's camera unable to enumerate at all (#159)"
            ),
            Self::NoUsableControl { unit, tried } => write!(
                f,
                "unit {unit} advertises no usable emitter control ({})",
                tried.join("; ")
            ),
            // Two different situations reach here, and calling a refusal
            // "stopped responding" would be untrue. Both still end the run:
            // only selectors the descriptor advertises are reached, so either
            // way the camera is contradicting what it published, and uvcvideo's
            // errnos cannot reliably separate a healthy refusal from a device in
            // trouble (it maps "wrong state" to EACCES and "invalid unit,
            // control or request, or a hardware error" to EIO).
            Self::Unresponsive {
                unit,
                selector,
                err: XuError::Unsupported,
            } => write!(
                f,
                "unit {unit} selector {selector} refused a request its own descriptor says it \
                 implements, so setup stopped rather than push a camera that is contradicting itself"
            ),
            Self::Unresponsive { unit, selector, err } => write!(
                f,
                "camera stopped responding at unit {unit} selector {selector} ({err}); \
                 stopped without sending anything further. Unplug and reconnect it before retrying"
            ),
            Self::MeasurementFailed => write!(
                f,
                "the camera stopped delivering frames during setup, so nothing further was sent. \
                 Check the camera is not in use by another program and try again"
            ),
            Self::RestoreFailed { unit, selector, err } => write!(
                f,
                "unit {unit} selector {selector} was changed and could not be restored ({err}); \
                 power the camera down fully before using it again"
            ),
            Self::CameraBusy => write!(
                f,
                "another irlume process is already working on this camera's emitter; \
                 nothing was sent to it. Wait for that to finish and try again"
            ),
            Self::UnresolvedChange => write!(
                f,
                "an earlier setup run left a control on this camera changed and it could not be \
                 put back, so this run stopped before reading anything: it would have recorded \
                 the changed value as the one to go back to. The original bytes are in {}. \
                 Unplug and reconnect the camera, or power it down fully, and try again",
                crate::emitter_journal::store_dir().display()
            ),
            Self::JournalUnwritable(why) => write!(
                f,
                "nothing was sent to the camera because the record of how to undo it could not \
                 be written ({why}). Setup writes that record first on purpose, so that a crash \
                 or a power loss part-way through still leaves something that can put the \
                 control back"
            ),
        }
    }
}

/// Which signal asked the current run to stop, or 0.
static ABORT_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// The whole signal handler. Storing to a lock-free atomic is one of the very
/// few things a handler may do; putting the camera back is not, so that happens
/// on the normal return path where syscalls, locks and allocation are allowed.
extern "C" fn note_abort_signal(signum: c_int) {
    ABORT_SIGNAL.store(signum, std::sync::atomic::Ordering::SeqCst);
}

/// Whether a fatal signal arrived during this discovery run.
///
/// Polled by the measurement closure, which is the only part of discovery that
/// blocks for any length of time. Returning `None` from it aborts the run
/// through the ordinary restore path.
pub fn abort_requested() -> bool {
    ABORT_SIGNAL.load(std::sync::atomic::Ordering::SeqCst) != 0
}

/// Turns a fatal signal arriving mid-discovery into an orderly abort, then lets
/// it kill the process as it was going to.
///
/// Without this, a `systemd` stop or a watchdog SIGTERM during `ir-setup`
/// terminates the daemon on the default disposition: no unwinding, so no `Drop`
/// runs, so the control stays changed. The undo record still covers that case,
/// but it covers it at the NEXT capture, which is minutes or a reboot away. This
/// closes it now for every signal that can actually be caught.
///
/// Installed without `SA_RESTART`, which HELPS but cannot be relied on. A
/// process-directed signal is delivered to an arbitrary thread that has it
/// unblocked, and only that thread's syscall is interrupted (signal(7)); the
/// daemon runs a watchdog, a listener and a connection thread besides the camera
/// worker, so the frame wait may never see `EINTR` at all. An earlier version of
/// this comment claimed the abort was therefore noticed in milliseconds, which
/// was not true for any delivery that landed on another thread.
///
/// What makes the abort effective is that [`abort_requested`] is polled between
/// frames and again immediately before each write to the camera, so the delay is
/// bounded by one frame timeout rather than by which thread the kernel chose.
///
/// `SIGKILL` and a power loss are exactly the cases a handler cannot reach. They
/// are the record's job.
pub struct AbortOnSignal {
    saved: Vec<(c_int, libc::sigaction)>,
}

impl AbortOnSignal {
    /// Catch the fatal signals for the caller's scope.
    ///
    /// Best-effort: a signal whose disposition cannot be changed is skipped
    /// rather than failing the run, because the record covers it and refusing to
    /// set up a camera over a `sigaction` failure helps nobody.
    pub fn install() -> Self {
        ABORT_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut saved = Vec::new();
        for signum in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: `action` is fully initialised below before use, and
            // `note_abort_signal` touches nothing but one lock-free atomic.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = note_abort_signal as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                action.sa_flags = 0; // no SA_RESTART: let the frame dequeue fail with EINTR
                let mut previous: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(signum, &action, &mut previous) == 0 {
                    saved.push((signum, previous));
                }
            }
        }
        Self { saved }
    }
}

impl Drop for AbortOnSignal {
    fn drop(&mut self) {
        for (signum, previous) in &self.saved {
            // SAFETY: `previous` is what sigaction handed back for this signal.
            unsafe {
                libc::sigaction(*signum, previous, std::ptr::null_mut());
            }
        }
        // The signal was caught to get the camera put back, not to ignore it.
        // The original disposition is restored above, so re-raising now does
        // whatever would have happened had this guard never existed.
        let pending = ABORT_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
        if pending != 0 {
            // SAFETY: raising a signal at its restored disposition.
            unsafe {
                libc::raise(pending);
            }
        }
    }
}

/// Holds the undo data for an exploratory write for as long as the control is
/// not known to be back where it was found.
///
/// The record reaches disk before the first `SET_CUR` and is removed only after
/// the control has been read back holding the original again. In between, the
/// guard's `Drop` puts the control back on any path that leaves the function
/// early — a panic in the frame decoder, a `?` on an ioctl — which the explicit
/// restores in `try_documented_control` cannot cover because they are statements
/// that only run when control reaches them.
///
/// `Drop` is best-effort by nature: it cannot report a failure and it does not
/// run for `SIGKILL` or a power loss. The record is what covers those, and it is
/// deliberately left in place when the restore cannot be confirmed.
#[derive(Debug)]
struct ExploratoryWrite {
    fd: c_int,
    unit: u8,
    selector: u8,
    original: Vec<u8>,
    /// The value this run applies. Kept so `commit` can confirm the camera is
    /// actually holding it before the undo data is thrown away.
    attempted: Vec<u8>,
    /// The record exactly as it was written, so the removal cannot target a
    /// different file than the save did.
    record: crate::emitter_journal::PendingWrite,
    /// Set once the control is confirmed back at `original`, or once the applied
    /// value is durably recorded in the configuration. Until then the record
    /// stays on disk and `Drop` still tries.
    resolved: bool,
    /// Whether the exploratory value is KNOWN to be on the camera and the camera
    /// is still answering.
    ///
    /// `Drop` writes only when this is true. Without it, an explicit restore that
    /// failed was immediately retried by `Drop` on the way out: an ioctl error
    /// from this unit is how this crate decides a camera has stopped answering,
    /// and its own rule is that nothing further may be sent to it. Sending the
    /// same request again to hardware just classified as unresponsive is the
    /// #159 hazard, and it bypassed the attempt budget entirely, which only
    /// governs later recovery passes.
    ///
    /// Every ioctl that returns an error clears it, because an error leaves the
    /// state uncertain. The record stays open in that case, so the next capture
    /// resolves it through recovery, where each attempt is counted and durable.
    exploratory_value_is_live: bool,
}

impl ExploratoryWrite {
    /// Record the undo data durably. Call BEFORE the first `SET_CUR`.
    ///
    /// A failure here is a refusal to write to the camera at all. Discovery
    /// without a durable record of the original is the behaviour this exists to
    /// end, so "the journal could not be written" cannot degrade into "write
    /// anyway and hope".
    fn open(
        fd: c_int,
        id: &crate::uvc_descriptor::CameraIdentity,
        unit: u8,
        selector: u8,
        len: usize,
        original: &[u8],
        attempted: &[u8],
    ) -> Result<Self, String> {
        let descriptor_sha256 = crate::emitter_journal::fingerprint(id);
        let record = crate::emitter_journal::PendingWrite {
            schema_version: crate::emitter_journal::SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            descriptor_sha256: descriptor_sha256.clone(),
            usb_id: id.usb_id(),
            interface_number: id.interface_number,
            unit,
            selector,
            len,
            original: crate::emitter_journal::to_hex(original),
            attempted: crate::emitter_journal::to_hex(attempted),
            restore_attempts: 0,
            // Deliberately NOT recorded any more. The per-camera `flock` is what
            // excludes a concurrent run, held across the whole of discovery, and
            // a capture beside it gets `Busy` before it reads anything.
            //
            // A pid was worse than redundant. `save` publishes by rename and
            // fsyncs afterwards, so a failure in those durability steps returns
            // an error while leaving the record visible — carrying the pid of a
            // daemon that lives for days. Every later recovery would then see
            // the owner still running and refuse, turning IR authentication off
            // until the machine was restarted, over a record whose camera was
            // never written to. Old records carrying the pair are still read and
            // still honoured.
            boot_id: None,
            pid: None,
            serial: id.serial.clone(),
            usb_devpath: id.usb_devpath.clone(),
        };
        crate::emitter_journal::save(&record)?;
        Ok(Self {
            fd,
            unit,
            selector,
            original: original.to_vec(),
            attempted: attempted.to_vec(),
            record,
            resolved: false,
            // Nothing has been written yet.
            exploratory_value_is_live: false,
        })
    }

    /// Put the exploratory value on the camera, arming the guard only if the
    /// camera accepted it.
    ///
    /// Disarmed BEFORE the ioctl, armed after. An error in between leaves the
    /// state uncertain, and the safe reading of uncertain is "do not send this
    /// camera anything else".
    fn apply_exploratory(&mut self, value: &[u8]) -> XuResult<()> {
        self.exploratory_value_is_live = false;
        set_cur(self.fd, self.unit, self.selector, value)?;
        self.exploratory_value_is_live = true;
        Ok(())
    }

    /// Put the original back, once.
    ///
    /// Disarms first either way: if this succeeds there is nothing left for
    /// `Drop` to do, and if it fails `Drop` must not repeat it. The record stays
    /// open until `confirm_restored` proves the control holds the original.
    fn restore_once(&mut self) -> XuResult<()> {
        self.exploratory_value_is_live = false;
        set_cur(self.fd, self.unit, self.selector, &self.original)
    }

    /// Read the control back and drop the record only if it holds the original.
    ///
    /// The caller has already issued the restoring `SET_CUR`. That call
    /// returning success says the ioctl was accepted, not that the control now
    /// holds those bytes, and assuming the two are the same thing is what left
    /// the camera changed in the first place.
    fn confirm_restored(&mut self) -> Result<(), String> {
        let now = get_cur(self.fd, self.unit, self.selector, self.original.len())
            .map_err(|e| format!("read the control back: {e}"))?;
        crate::emitter_journal::trace(&format!("read back {now:02x?}"));
        if now != self.original {
            return Err(format!(
                "the control reads {:02x?} after being restored to {:02x?}",
                now, self.original
            ));
        }
        crate::emitter_journal::clear(&self.record)?;
        self.resolved = true;
        Ok(())
    }

    /// The control is deliberately left at the applied value, and the
    /// configuration naming it is durable. Confirm it, then drop the record.
    ///
    /// Ordering matters: called only AFTER `save_conf`. A crash between a
    /// successful discovery and that write leaves the camera lit with nothing on
    /// disk saying which control did it, which is the same unrecorded change
    /// this module exists to prevent, so until the configuration lands the
    /// record stays open and the guard would put the control back.
    ///
    fn commit(&mut self) -> Result<(), String> {
        crate::emitter_journal::clear(&self.record)?;
        self.resolved = true;
        Ok(())
    }

    /// Confirm the camera is holding the value this run applied.
    ///
    /// Called BEFORE the configuration is written, not after. A `SET_CUR`
    /// returning success says the ioctl was accepted, not that the control holds
    /// those bytes, and this is the last chance to find out before anything
    /// durable is published about it. Ordering the other way round installed the
    /// configuration first, so a failed verification still left a file naming
    /// this control for every later capture to apply automatically — which is
    /// the write the verification exists to prevent.
    ///
    /// An ioctl error disarms the guard: the camera has just failed to answer,
    /// and this module's rule is that nothing further is sent to a camera in
    /// that state. A value mismatch does NOT disarm it, because there the camera
    /// is answering fine and the control genuinely needs putting back.
    fn confirm_applied(&mut self) -> Result<(), String> {
        let now = match get_cur(self.fd, self.unit, self.selector, self.attempted.len()) {
            Ok(now) => now,
            Err(e) => {
                self.exploratory_value_is_live = false;
                return Err(format!("read the applied control back: {e}"));
            }
        };
        crate::emitter_journal::trace(&format!("read back applied {now:02x?}"));
        if now != self.attempted {
            return Err(format!(
                "the control reads {now:02x?} after being set to {:02x?}",
                self.attempted
            ));
        }
        Ok(())
    }
}

impl Drop for ExploratoryWrite {
    fn drop(&mut self) {
        // `exploratory_value_is_live` is the whole difference between putting
        // back a change this run is known to have made and poking a camera that
        // has already failed to answer. Only the first is worth a write.
        if self.resolved || !self.exploratory_value_is_live {
            return;
        }
        self.exploratory_value_is_live = false;
        // Best effort, and deliberately quiet about its own failure: the record
        // is still on disk, so a failure here is recovered at the next capture
        // rather than lost — and there, unlike here, every attempt is counted
        // and made durable before it is made. What must not happen is leaving
        // the control changed AND clearing the record, so the clear only runs
        // behind a confirmed read-back.
        if set_cur(self.fd, self.unit, self.selector, &self.original).is_ok() {
            let _ = self.confirm_restored();
        }
    }
}

/// Put back anything an interrupted run left changed on this camera.
///
/// Runs before discovery and before any capture applies a control, because both
/// of those would otherwise build on a control that is not where its owner left
/// it — discovery worst of all, since its first act is to read the current value
/// and call it the original.
///
/// Returns what happened, for the caller to log. Every decision it makes is in
/// [`crate::emitter_journal::record_applies`] and
/// [`crate::emitter_journal::restore_decision`], which are pure and tested; this
/// function is the ioctls and the bookkeeping around them.
pub(crate) fn recover_pending_write(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
) -> RecoveryOutcome {
    // The lock covers the WHOLE pass, from the read to the removal. Without it
    // the record read at the start was removed at the end without being looked
    // at again, so a second process that resolved it and saved a new one in
    // between had its live record deleted.
    match crate::emitter_journal::lock_camera(id) {
        Ok(Some(lock)) => {
            let outcome = recover_pending_write_locked(fd, id);
            drop(lock);
            outcome
        }
        Ok(None) => RecoveryOutcome::Busy,
        Err(why) => RecoveryOutcome::Unresolved(format!("lock the camera: {why}")),
    }
}

/// The recovery pass proper. The caller holds this camera's lock.
fn recover_pending_write_locked(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
) -> RecoveryOutcome {
    use crate::emitter_journal as journal;

    let record = match journal::load(id) {
        Ok(journal::Situation::Nothing) => return RecoveryOutcome::NothingPending,
        Ok(journal::Situation::Mine(record)) => *record,
        // A record about a camera of the same model at a different port, or one
        // written before records carried a port at all. Its bytes were read from
        // a control this run cannot confirm is the same one, so writing them
        // here would be guessing, and clearing it afterwards would destroy the
        // only description of a change still outstanding somewhere else.
        //
        // Loud rather than silent, and it stops this camera's emitter, because
        // the alternative reading is that this IS the camera and it is still
        // holding an exploratory value.
        Ok(journal::Situation::SameModelElsewhere(record)) => {
            return RecoveryOutcome::Unconfirmed {
                unit: record.unit,
                selector: record.selector,
                original: record.original.clone(),
                recorded_at: if record.usb_devpath.is_empty() {
                    "a build that did not record which port it was on".into()
                } else {
                    record.usb_devpath.clone()
                },
            }
        }
        // A store that cannot be read may be hiding a change to THIS camera, so
        // it is unresolved rather than "nothing pending".
        Err(why) => return RecoveryOutcome::Unresolved(why),
    };
    if let Err(mismatch) = journal::record_applies(&record, id) {
        use journal::Mismatch;
        return match mismatch {
            // Not about this camera. Everything else is.
            Mismatch::DifferentCamera => RecoveryOutcome::ForAnotherCamera,
            Mismatch::OwnerStillRunning { pid } => RecoveryOutcome::OwnerStillRunning { pid },
            Mismatch::OutOfAttempts { attempts } => RecoveryOutcome::Unresolved(format!(
                "{attempts} attempts to put it back did not take, so no more will be made"
            )),
            Mismatch::UnsupportedSchema { found, supported } => RecoveryOutcome::Unresolved(
                format!("the record is schema {found} and this build implements {supported}"),
            ),
            Mismatch::Malformed(why) => RecoveryOutcome::Unresolved(format!("malformed: {why}")),
            Mismatch::ControlNotPublished => RecoveryOutcome::Unresolved(
                "the record names a control this camera does not publish".into(),
            ),
        };
    }

    // Read the control before deciding anything. A restore that is not needed is
    // still a write to firmware.
    //
    // Sequenced, not gathered into a tuple. A tuple evaluates every operand
    // before the match runs, so an earlier version issued `GET_CUR` sized by the
    // RECORD while `GET_LEN` was being fetched in the same expression: a record
    // saying 64 against a camera reporting 3 sent a 64-byte control request to
    // firmware, and only then was the mismatch noticed. The camera's own answer
    // has to come first and gate the rest.
    let len = match get_len(fd, record.unit, record.selector) {
        Ok(len) => len,
        Err(e) => return RecoveryOutcome::Unresolved(format!("query the control length: {e}")),
    };
    if len != record.len {
        return RecoveryOutcome::Unresolved(format!(
            "the control is {len} bytes and the record was written when it was {}, \
             so the recorded bytes are not this control's value",
            record.len
        ));
    }
    let info = match get_info(fd, record.unit, record.selector) {
        Ok(info) => info,
        Err(e) => return RecoveryOutcome::Unresolved(format!("query the control: {e}")),
    };
    // Sized by what the camera just reported, which the check above has proved
    // equal to the record's.
    let current = match get_cur(fd, record.unit, record.selector, len) {
        Ok(current) => current,
        Err(e) => return RecoveryOutcome::Unresolved(format!("read the control: {e}")),
    };
    let now = journal::ControlNow {
        len,
        writable: info_allows_set(info),
        current,
    };

    match journal::restore_decision(&record, &now) {
        journal::Restore::AlreadyRestored => match journal::clear(&record) {
            Ok(()) => RecoveryOutcome::AlreadyRestored,
            // The control holds its original. Only the store is unhappy, and the
            // store does not decide what the camera holds.
            Err(why) => RecoveryOutcome::RestoredRecordKept(why),
        },
        journal::Restore::Refuse(why) => RecoveryOutcome::Unresolved(why),
        journal::Restore::Write(original) => {
            // Count the attempt BEFORE the write and make it durable. Counting
            // after would leave a kill during the restore uncounted, and a
            // control that never reads back as restored would then be written to
            // at every capture forever.
            let mut spent = record.clone();
            spent.restore_attempts += 1;
            // Drop the owner rather than claiming it. The recorded owner is
            // already known dead, and writing THIS process in would be worse:
            // recovery usually runs inside the long-lived daemon, so a refusal
            // would leave a record owned by a process that stays alive for days
            // and every later pass would skip it as somebody else's business.
            // The attempt counter is what limits repeats.
            spent.boot_id = None;
            spent.pid = None;
            if let Err(why) = journal::save(&spent) {
                // The attempt could not be counted, so making it would be an
                // uncounted write: exactly the loop the counter exists to stop.
                return RecoveryOutcome::Unresolved(format!("count the attempt: {why}"));
            }

            // Read the control AGAIN, immediately before writing it.
            //
            // The authorisation above was made before `journal::save`, which is
            // a whole durable transaction: create, write, fsync, rename, fsync
            // the directory, fsync its ancestors. A check made on one side of
            // that and acted on from the other is a check-then-act with a
            // filesystem's worth of time in the middle, and the camera lock
            // excludes other irlume processes, not a vendor tool or another UVC
            // client. Without this, the refusal to undo somebody else's change
            // only covered changes made before the first GET_CUR.
            //
            // A syscall-sized window remains and cannot be closed here: UVC
            // offers no compare-and-set. What is claimed is narrowed to match.
            let attempted = match journal::from_hex(&record.attempted) {
                Ok(bytes) => bytes,
                Err(why) => return RecoveryOutcome::Unresolved(format!("attempted: {why}")),
            };
            match get_cur(fd, record.unit, record.selector, original.len()) {
                Ok(now) if now == attempted => {}
                Ok(now) => {
                    return RecoveryOutcome::Unresolved(format!(
                        "the control changed while the attempt was being recorded: it holds \
                         {now:02x?}, not this run's value {attempted:02x?}; nothing was written"
                    ))
                }
                Err(e) => {
                    return RecoveryOutcome::Unresolved(format!(
                        "recheck the control before restoring it: {e}"
                    ))
                }
            }

            if let Err(e) = set_cur(fd, record.unit, record.selector, &original) {
                return RecoveryOutcome::Unresolved(format!("restore: {e}"));
            }
            match get_cur(fd, record.unit, record.selector, original.len()) {
                Ok(back) if back == original => match journal::clear(&record) {
                    Ok(()) => RecoveryOutcome::Restored {
                        unit: record.unit,
                        selector: record.selector,
                    },
                    Err(why) => RecoveryOutcome::RestoredRecordKept(why),
                },
                Ok(back) => RecoveryOutcome::Unresolved(format!(
                    "the control reads {back:02x?} after being restored to {original:02x?}"
                )),
                Err(e) => RecoveryOutcome::Unresolved(format!("read the control back: {e}")),
            }
        }
    }
}

/// Log a recovery outcome once per camera per process.
///
/// `enable` runs at every stream open AND every eighth frame of a burst, so an
/// outcome that repeats — a record that cannot be acted on stays on disk and is
/// re-read every time — would otherwise put the same line into the journal
/// several times a second. Keyed by the camera and the kind of outcome, so a
/// later change of outcome on the same camera still prints.
fn report_recovery(id: &crate::uvc_descriptor::CameraIdentity, outcome: RecoveryOutcome) {
    let Some(line) = outcome.message() else {
        return;
    };
    static REPORTED: std::sync::Mutex<Option<std::collections::HashSet<String>>> =
        std::sync::Mutex::new(None);
    let key = format!(
        "{}:{}",
        crate::emitter_journal::fingerprint(id),
        outcome.kind()
    );
    // A poisoned lock means another thread panicked while holding it. Recovering
    // the set is right here: the worst case of a wrong answer is a duplicated or
    // a dropped log line, and taking the panic instead would turn a logging
    // detail into a failed capture.
    let mut guard = REPORTED.lock().unwrap_or_else(|e| e.into_inner());
    if guard.get_or_insert_with(Default::default).insert(key) {
        eprintln!("{line}");
    }
}

/// What a recovery pass did.
///
/// The variants are split by what the CALLER must do next, not by what went
/// wrong. Three call sites ask this type two questions — may I write to this
/// camera, and may discovery start — and both answers live here rather than
/// being re-derived from a reason string at each site.
///
/// "Could not read" used to be one variant covering the store, the control, and
/// the removal of a record after a confirmed restore. Those call for opposite
/// actions: a control that will not answer means stop, while a record that will
/// not delete after the control is provably back means the camera is fine and
/// the store is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    NothingPending,
    /// A record exists for a DIFFERENT camera. Ordinary on a machine with two of
    /// them, and none of this camera's business: it must not stop the emitter
    /// here, which is the whole reason this is not folded in with the refusals.
    ForAnotherCamera,
    /// The control already held the original and the record was dropped.
    AlreadyRestored,
    Restored {
        unit: u8,
        selector: u8,
    },
    /// The control is confirmed back at its original, but the record could not be
    /// removed. The camera is in the right state, so capture may proceed; the
    /// store is not, so discovery may not, because it could not record its own
    /// next write either.
    RestoredRecordKept(String),
    /// A run that opened a record on this camera is still going. Silent, and it
    /// stops both a capture write and a second discovery: the control is
    /// SUPPOSED to be changed right now.
    OwnerStillRunning {
        pid: u32,
    },
    /// Another irlume process holds this camera's lock. Kernel-enforced, unlike
    /// the pid in a record, and non-blocking so a capture never waits behind a
    /// setup run. Silent and treated exactly like `OwnerStillRunning`: somebody
    /// else is already looking after this camera.
    Busy,
    /// An outstanding change on THIS camera that could not be resolved. Nothing
    /// further may be written to it by any path.
    Unresolved(String),
    /// A record for a camera of the SAME MODEL that this run cannot confirm is
    /// the camera in front of it: a different port, or a record from a build
    /// that did not store one.
    ///
    /// Two units of one model publish byte-identical descriptors, so the model
    /// digest alone cannot tell them apart. Acting on the record would write one
    /// camera's bytes into another and then delete the record on a successful
    /// read-back, leaving the camera that was actually changed with no undo data
    /// at all. Reported, never acted on, and it stops writes here because the
    /// other reading is that this IS that camera, still holding an exploratory
    /// value.
    Unconfirmed {
        unit: u8,
        selector: u8,
        original: String,
        recorded_at: String,
    },
}

impl RecoveryOutcome {
    /// One line for the log, or nothing when there was nothing to do.
    ///
    /// A different camera and a live setup run are silent: both are ordinary and
    /// both would otherwise print at every capture. Everything else is loud. A
    /// pending firmware change that cannot be undone is the operator's problem,
    /// not a debug detail, and each of those messages now also says that the
    /// emitter is off as a result, because a user whose face login stopped
    /// working is owed the reason in the same line.
    pub(crate) fn message(&self) -> Option<String> {
        let store = crate::emitter_journal::store_dir();
        match self {
            Self::NothingPending | Self::ForAnotherCamera => None,
            Self::OwnerStillRunning { .. } | Self::Busy => None,
            Self::AlreadyRestored => Some(
                "irlume: an interrupted emitter setup was already undone; \
                 dropped its undo record"
                    .into(),
            ),
            Self::Restored { unit, selector } => Some(format!(
                "irlume: an interrupted emitter setup had left unit {unit} selector {selector} \
                 changed; put it back to the value the camera reported before that run"
            )),
            Self::RestoredRecordKept(why) => Some(format!(
                "irlume: an emitter control was put back and confirmed, but its undo record in \
                 {} could not be removed ({why}). The camera is in the right state; \
                 `irlume ir-setup` will refuse until the record can be written",
                store.display()
            )),
            Self::Unresolved(why) => Some(format!(
                "irlume: an emitter control on this camera was left changed by an interrupted \
                 setup and has not been put back ({why}). irlume will not write to this \
                 camera's emitter until it is resolved, so IR face authentication will not \
                 light. The recorded original is in {}",
                store.display()
            )),
            Self::Unconfirmed {
                unit,
                selector,
                original,
                recorded_at,
            } => Some(format!(
                "irlume: a camera of this model was left with unit {unit} selector {selector} \
                 changed by an interrupted setup, recorded at {recorded_at}, and this camera is \
                 not at that address. Two units of one model are indistinguishable from their \
                 USB descriptors, so irlume will not write those bytes into this one and will \
                 not write to its emitter at all until the record is resolved: IR face \
                 authentication will not light. Reconnect the camera to the port it was set up \
                 on and it will be put back automatically. The original value is {original}, \
                 recorded in {}",
                store.display()
            )),
        }
    }

    /// A stable tag for the kind of outcome, for de-duplicating log lines.
    fn kind(&self) -> &'static str {
        match self {
            Self::NothingPending => "nothing",
            Self::ForAnotherCamera => "another-camera",
            Self::AlreadyRestored => "already-restored",
            Self::Restored { .. } => "restored",
            Self::RestoredRecordKept(_) => "restored-record-kept",
            Self::OwnerStillRunning { .. } => "owner-running",
            Self::Busy => "busy",
            Self::Unresolved(_) => "unresolved",
            Self::Unconfirmed { .. } => "unconfirmed",
        }
    }

    /// Whether a capture may go on to apply an emitter control to this camera.
    ///
    /// Reporting that a camera must not be written to and then writing to it is
    /// worse than never having checked. `enable` used to do exactly that: it
    /// logged "nothing further will be written to it" and then applied the
    /// configured control to that same unit and selector on the next line, at
    /// every stream open and every eighth frame of a burst.
    ///
    /// Refusing costs the IR emitter, so face authentication does not light and
    /// the user falls back to a password until a human resolves it. That is the
    /// cheaper side of the trade: #159 is a camera that never enumerated again
    /// after unverified extension-unit writes, and a control that has already
    /// failed to read back what was written to it is the clearest sign available
    /// that this camera is in that territory.
    ///
    /// A record for ANOTHER camera permits the write. It has nothing to say about
    /// this one, and treating it as a refusal would put a machine with a detached
    /// second camera into password-only login for no reason.
    pub(crate) fn permits_capture_write(&self) -> bool {
        match self {
            Self::NothingPending
            | Self::ForAnotherCamera
            | Self::AlreadyRestored
            | Self::Restored { .. }
            // The control is confirmed back at its original. Only the store is
            // unhappy, and the store does not decide what the camera holds.
            | Self::RestoredRecordKept(_) => true,
            Self::OwnerStillRunning { .. }
            | Self::Busy
            | Self::Unresolved(_)
            | Self::Unconfirmed { .. } => false,
        }
    }

    /// Whether discovery may start.
    ///
    /// Stricter than [`Self::permits_capture_write`] in one place: a record that
    /// could not be removed also stops discovery, because discovery's first act
    /// is to write a record of its own, and a store that cannot be written to
    /// cannot hold one.
    ///
    /// Discovery's second act is to read the control and call the answer the
    /// original, so running it against a control still holding a previous run's
    /// exploratory value would record the wrong bytes as the thing to go back to
    /// and destroy the real ones.
    pub(crate) fn blocks_discovery(&self) -> bool {
        match self {
            Self::NothingPending
            | Self::ForAnotherCamera
            | Self::AlreadyRestored
            | Self::Restored { .. } => false,
            Self::RestoredRecordKept(_)
            | Self::OwnerStillRunning { .. }
            | Self::Busy
            | Self::Unresolved(_)
            | Self::Unconfirmed { .. } => true,
        }
    }
}

/// Find and apply the camera's IR emitter control, using only what the hardware
/// itself documents.
///
/// This replaces a search that wrote guessed payloads to units 0..=31 and
/// selectors 0..=15 until the picture got brighter. That search destroyed a
/// reporter's camera (#159). The replacement never guesses:
///
/// 1. The USB descriptor says which extension units exist and what each one is.
///    Only the unit whose GUID is Microsoft's documented camera-control
///    extension is considered; a vendor unit of unknown purpose is never
///    addressed at all.
/// 2. `bmControls` says which selectors that unit implements. Only advertised
///    selectors are touched.
/// 3. `GET_INFO` says whether the control accepts a write right now.
/// 4. **`GET_DEF` supplies the bytes.** The value written is the manufacturer's
///    own default for that control, read from the device moments earlier. irlume
///    never composes a payload.
/// 5. Any sign that the camera has stopped answering aborts everything
///    immediately. Nothing is retried and no other control is tried afterwards.
///
/// Preference order is IR Torch first (its whole purpose is the lamp), then Face
/// Authentication (which drives the illuminator as a side effect of putting a
/// streaming interface into face-auth mode).
pub fn discover<F: FnMut() -> Option<f32>>(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    measure: &mut F,
) -> std::result::Result<Discovered, DiscoveryError> {
    let ms = id
        .microsoft_xu()
        .ok_or_else(|| DiscoveryError::NoMicrosoftXu {
            seen: id.extension_units().iter().map(|u| u.unit_id).collect(),
        })?;

    // ONE lock for the whole run: the recovery pass, every exploratory write,
    // and the record that describes them. Taking it separately for recovery and
    // then again for the writes would leave a gap in which another process could
    // resolve this camera and start its own setup, and the record this run then
    // wrote would be filed over the top of that one.
    let lock = match crate::emitter_journal::lock_camera(id) {
        Ok(Some(lock)) => lock,
        Ok(None) => return Err(DiscoveryError::CameraBusy),
        Err(why) => return Err(DiscoveryError::JournalUnwritable(why)),
    };

    // Before the first GET_CUR, not after. Discovery reads the control and calls
    // the answer the original; against a control still holding an earlier run's
    // exploratory value that reading is wrong, and recording it would overwrite
    // the only copy of the real one.
    let recovery = recover_pending_write_locked(fd, id);
    if let Some(line) = recovery.message() {
        eprintln!("{line}");
    }
    if recovery.blocks_discovery() {
        return Err(DiscoveryError::UnresolvedChange);
    }

    let mut tried = Vec::new();

    for selector in [
        crate::uvc_descriptor::MSXU_IR_TORCH,
        crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
    ] {
        if !ms.advertises(selector) {
            tried.push(format!("selector {selector:#04x} not advertised"));
            continue;
        }
        match try_documented_control(fd, id, ms.unit_id, selector, measure) {
            // The lock travels with the open record: the camera stays held until
            // the configuration naming the applied control is durable, so nothing
            // else can file a record over this one in between.
            Ok(Attempt::Lit(control, pending)) => {
                return Ok(Discovered {
                    control,
                    pending,
                    _lock: lock,
                })
            }
            Ok(Attempt::AlreadyApplied) => tried.push(format!(
                "selector {selector:#04x} is already set to the value setup would apply"
            )),
            Ok(Attempt::NotUsable(why)) => tried.push(format!("selector {selector:#04x}: {why}")),
            Err(TryFailure::Measurement) => return Err(DiscoveryError::MeasurementFailed),
            Err(TryFailure::Restore(err)) => {
                return Err(DiscoveryError::RestoreFailed {
                    unit: ms.unit_id,
                    selector,
                    err,
                })
            }
            Err(TryFailure::Journal(why)) => return Err(DiscoveryError::JournalUnwritable(why)),
            // Any error at all stops everything. Only selectors the descriptor
            // advertises are reached, so a failure here is the camera
            // contradicting its own descriptor, and the errno cannot be relied
            // on to say how badly: uvcvideo maps "wrong state" to EACCES and
            // "invalid unit/control/request, or a hardware error" to EIO, so a
            // healthy refusal and a device in trouble are not cleanly separable
            // from userspace. Continuing past one is what the old search did.
            Err(TryFailure::Query(err)) => {
                return Err(DiscoveryError::Unresponsive {
                    unit: ms.unit_id,
                    selector,
                    err,
                })
            }
        }
    }

    Err(DiscoveryError::NoUsableControl {
        unit: ms.unit_id,
        tried,
    })
}

/// A discovery run that has left the camera lit, and the undo record that stays
/// open until the configuration naming that control is on disk.
///
/// The record is deliberately not resolved by a successful discovery. Between
/// `discover` returning and `save_conf` landing, the camera is changed and
/// nothing on disk says which control did it; dropping this value without
/// calling [`Discovered::committed`] puts the control back, which is the right
/// outcome when the configuration could not be written.
#[derive(Debug)]
pub struct Discovered {
    control: EmitterControl,
    pending: ExploratoryWrite,
    /// Held until this value is dropped or committed, so no other process files
    /// a record for this camera while its record is still open.
    _lock: crate::emitter_journal::CameraLock,
}

impl Discovered {
    pub fn control(&self) -> &EmitterControl {
        &self.control
    }

    /// Confirm the camera is holding what this run applied.
    ///
    /// Call BEFORE writing the configuration. Failing here drops `self`, which
    /// puts the control back, and nothing durable has been published about it.
    pub fn confirm_applied(&mut self) -> std::result::Result<(), String> {
        self.pending.confirm_applied()
    }

    /// Release the undo record. Call only once the configuration naming this
    /// control is durable.
    pub fn committed(mut self) -> std::result::Result<(), String> {
        self.pending.commit()
    }

    /// Confirm, publish, release — in that order, as one step.
    ///
    /// The order is the whole point and it lived in the caller, where nothing
    /// without a real camera could reach it: a mutant deleting the confirmation
    /// survived the entire suite because the test that covers this reproduced
    /// the sequence itself instead of running the one that ships. As a method it
    /// is reachable with a stand-in camera, so the ordering is asserted on the
    /// code the daemon actually executes.
    ///
    /// Confirmation first, because publishing a configuration for a control the
    /// camera did not take leaves a file every later capture applies. The record
    /// last, because until the configuration is durable the camera is changed
    /// with nothing saying which control did it, and dropping `self` unresolved
    /// puts it back.
    pub fn finish(
        mut self,
        id: &crate::uvc_descriptor::CameraIdentity,
    ) -> std::result::Result<(), String> {
        self.pending.confirm_applied()?;
        if let Err(e) = save_conf(id, &self.control) {
            // "It returned an error" is not "nothing became visible". The
            // configuration is published by a rename, which is atomic and
            // immediate, and the fsyncs that make it DURABLE come afterwards. A
            // failure in those leaves the file in place, and every later capture
            // reads it and applies that control automatically.
            //
            // So when the configuration is visible, the camera is not put back
            // and the record is not cleared: the undo data must outlive a
            // half-published configuration, or a crash that loses the file would
            // leave a lit emitter with nothing describing it. The next capture
            // recovers from the record first and then applies the configuration
            // through the ordinary guarded path.
            if load_conf(id) == Some((self.control.unit, self.control.selector)) {
                self.pending.exploratory_value_is_live = false;
            }
            return Err(format!("save the emitter config: {e}"));
        }
        self.pending.commit()
    }
}

/// What one advertised control turned out to be.
///
/// `Lit` is the large variant because it carries the open undo record, which now
/// holds the whole `PendingWrite` so the removal cannot target a different file
/// than the save did. Boxing it would move an allocation onto the success path of
/// an operation that already spends seconds on camera I/O, and discovery returns
/// exactly one of these per run.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Attempt {
    /// Lit, and still holding the applied value, with its undo record open.
    Lit(EmitterControl, ExploratoryWrite),
    /// The control is already set to the value setup would apply, so writing it
    /// again could not demonstrate anything.
    AlreadyApplied,
    /// Usable but it did not brighten the image, or its default failed the
    /// checks the specification allows. The control was left as it was found.
    NotUsable(String),
}

#[derive(Debug)]
enum TryFailure {
    Query(XuError),
    Restore(XuError),
    /// The undo record could not be written, or could not be confirmed dropped.
    /// A refusal to touch the camera rather than a reason to write anyway.
    Journal(String),
    /// The camera stopped delivering frames. The streaming side going quiet is
    /// as much a sign of trouble as a control request going unanswered, and the
    /// old code turned it into "the picture is dark" and carried on.
    Measurement,
}

impl From<XuError> for TryFailure {
    fn from(e: XuError) -> Self {
        Self::Query(e)
    }
}

/// Try one advertised, documented control, leaving it as it was found unless it
/// worked.
fn try_documented_control<F: FnMut() -> Option<f32>>(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    unit: u8,
    selector: u8,
    measure: &mut F,
) -> std::result::Result<Attempt, TryFailure> {
    if !info_allows_set(get_info(fd, unit, selector)?) {
        return Ok(Attempt::NotUsable(
            "the camera reports it does not accept a write to this control right now".into(),
        ));
    }
    let len = get_len(fd, unit, selector)?;

    // Nothing is written that cannot be put back. A set-only control would have
    // to be left in whatever state the attempt produced, and "we changed
    // something on your camera and cannot undo it" is not an acceptable outcome
    // of a discovery run.
    let original = get_cur(fd, unit, selector, len)?;

    // The same derivation every later capture will use, so what is recorded is
    // reproducible rather than a value that only existed during setup.
    let wanted = match intended_value(fd, unit, selector, len)? {
        Ok(v) => v,
        Err(why) => return Ok(Attempt::NotUsable(why)),
    };

    // Nothing here assumes what "off" looks like.
    //
    // An earlier version wrote the control's own default to establish an unlit
    // baseline. That is wrong for IR Torch, whose default the specification
    // requires to be an ACTIVE mode, and which this file enforces a few
    // functions away: setup would have switched the lamp on, called the result
    // the off state, and then written the identical value again expecting a
    // change. IR Torch discovery could never have succeeded.
    //
    // Instead the control is compared against whatever state it is already in.
    // If it is already set to the value setup would apply, there is nothing to
    // learn from writing it again, and saying so is more honest than measuring
    // a difference that cannot exist.
    if original == wanted {
        return Ok(Attempt::AlreadyApplied);
    }

    let Some(before) = measure() else {
        return Err(TryFailure::Measurement);
    };

    // Durable before the write, not after. Everything from here to the last
    // restore is the window a kill used to make unrecoverable: the original
    // existed only in this stack frame, and two camera measurements sit inside
    // it. `pending` also restores the control from `Drop`, which covers the
    // paths no statement below can — a panic in the decoder, or an ioctl error
    // taken by `?`.
    // Re-checked here, not only inside `measure`. A process-directed signal is
    // delivered to an ARBITRARY thread that has it unblocked, and the daemon has
    // several; the camera worker's frame wait may never see EINTR at all. So the
    // abort is polled again at each point that is about to change the camera,
    // rather than relied on to interrupt a syscall.
    if abort_requested() {
        return Err(TryFailure::Measurement);
    }

    let mut pending = ExploratoryWrite::open(fd, id, unit, selector, len, &original, &wanted)
        .map_err(TryFailure::Journal)?;

    if abort_requested() {
        return Err(TryFailure::Measurement);
    }
    pending.apply_exploratory(&wanted)?;
    let Some(lit) = measure() else {
        // The stream died after the control was changed. Aborting without
        // putting it back would leave the camera altered by a run that
        // concluded nothing.
        pending.restore_once().map_err(TryFailure::Restore)?;
        pending.confirm_restored().map_err(TryFailure::Journal)?;
        return Err(TryFailure::Measurement);
    };

    // The question is whether writing this control changed the image, not
    // whether the resulting image is bright enough to authenticate against.
    // Those are different questions; conflating them made success depend on room
    // lighting, and the same camera here has measured 38 to 168 depending only
    // on what was in front of it.
    if lit < before + AUTOCONF_MIN_LIFT {
        pending.restore_once().map_err(TryFailure::Restore)?;
        pending.confirm_restored().map_err(TryFailure::Journal)?;
        return Ok(Attempt::NotUsable(format!(
            "the image did not brighten (before {before:.0}, after {lit:.0}, needs +{AUTOCONF_MIN_LIFT:.0})"
        )));
    }

    // A single before-and-after pair is not evidence. Someone moving, a cloud,
    // or an exposure transition produces the same twenty points as a working
    // illuminator. Put the control back and require the brightness to fall with
    // it: a change that does not follow the control is not caused by it.
    pending.restore_once().map_err(TryFailure::Restore)?;
    let Some(after_restore) = measure() else {
        return Err(TryFailure::Measurement);
    };
    if after_restore >= lit - AUTOCONF_MIN_LIFT {
        // Restored above, and this branch writes nothing further, so the record
        // is resolvable here. The read-back is what resolves it: the restoring
        // `set_cur` returning success says the ioctl was accepted, not that the
        // control holds those bytes.
        pending.confirm_restored().map_err(TryFailure::Journal)?;
        return Ok(Attempt::NotUsable(format!(
            "the image brightened but stayed bright when the control was put back \
             ({before:.0} before, {lit:.0} with it set, {after_restore:.0} after undoing it), \
             so the change did not come from this control"
        )));
    }

    // It followed the control both ways. Apply it and report it.
    //
    // The record stays OPEN. The camera is deliberately changed from here on,
    // and until `save_conf` records which control did it there is still nothing
    // on disk that could put it back. `Discovered::committed` closes it.
    if abort_requested() {
        return Err(TryFailure::Measurement);
    }
    pending.apply_exploratory(&wanted)?;
    Ok(Attempt::Lit(
        EmitterControl {
            unit,
            selector,
            payload: wanted,
        },
        pending,
    ))
}

/// Build a Face Authentication `SET_CUR` payload from what the camera says it
/// supports.
///
/// Every byte comes from the device. `GET_MAX` is defined to list all and only
/// the streaming interfaces capable of a face-authentication mode, and to say
/// which of the two each one supports. This selects, for each interface the
/// camera advertised, exactly the mode the camera advertised for it.
///
/// It exists because `GET_DEF` cannot be used here. Microsoft specifies that an
/// interface which is also usable for general-purpose capture defaults to D0,
/// and both cameras this was validated against do exactly that: they report
/// `GET_MAX 01 03 03` and `GET_DEF 01 03 01`, so writing the default back leaves
/// the interface in general-purpose mode and the illuminator dark.
///
/// On both of those cameras this produces `01 03 02`, byte for byte the payload
/// separately validated on each of them.
///
/// Layout, confirmed against both: `bNumEntries`, then two bytes per entry,
/// `bStreamingInterface` and `bmControlFlags`, zero-padded to `GET_LEN`.
///
/// Every structural contradiction is a refusal rather than a repair. The point
/// is not to get a payload out of the camera; it is to write nothing when the
/// camera has not clearly said what it accepts.
pub(crate) fn face_auth_payload(def: &[u8], max: &[u8]) -> std::result::Result<Vec<u8>, String> {
    // Microsoft's three modes for a streaming interface:
    //   D0 general purpose
    //   D1 alternative frame illumination: the camera strobes the illuminator
    //      on and off across successive frames and marks each one
    //   D2 background subtraction: the camera returns ambient-subtracted images
    //
    // These are not two flavours of the same thing. irlume's capture path pairs
    // a lit frame with an adjacent dark one, which is D1's behaviour; a D2
    // stream would hand it already-subtracted images and everything downstream
    // would be measuring something else. Only D1 is selected here.
    const D0_GENERAL: u8 = 1 << 0;
    const D1_ALTERNATIVE_ILLUMINATION: u8 = 1 << 1;
    const D2_BACKGROUND_SUBTRACTION: u8 = 1 << 2;
    const DEFINED: u8 = D0_GENERAL | D1_ALTERNATIVE_ILLUMINATION | D2_BACKGROUND_SUBTRACTION;

    let len = max.len();
    if len != def.len() {
        return Err(format!(
            "its maximum is {len} bytes and its default is {}; they describe the same control and must match",
            def.len()
        ));
    }
    // One count byte, then whole two-byte entries.
    if len < 3 || !(len - 1).is_multiple_of(2) {
        return Err(format!("a {len}-byte payload cannot hold whole entries"));
    }

    let entries = usize::from(max[0]);
    let capacity = (len - 1) / 2;
    if entries == 0 {
        return Err("it advertises no interface capable of face authentication".into());
    }
    if entries > capacity {
        return Err(format!(
            "it claims {entries} entries, which does not fit in {len} bytes"
        ));
    }
    if usize::from(def[0]) > capacity {
        return Err("its default claims more entries than it can hold".into());
    }
    // GET_DEF describes the same interfaces GET_MAX listed. A control whose two
    // answers disagree is not describing one coherent thing, and the value about
    // to be written is built from only one of them.
    if def[0] != max[0] {
        return Err(format!(
            "it lists {} interfaces at maximum but {} by default",
            max[0], def[0]
        ));
    }

    let mut out = vec![0u8; len];
    out[0] = max[0];
    let mut seen: Vec<u8> = Vec::with_capacity(entries);

    for i in 0..entries {
        let at = 1 + i * 2;
        let interface = max[at];
        let flags = max[at + 1];

        if flags & !DEFINED != 0 {
            return Err(format!(
                "interface {interface} advertises flags {flags:#04x}, which sets bits the specification does not define"
            ));
        }
        // GET_MAX lists only interfaces capable of D1 or D2, and no interface
        // may be capable of both. Anything else is the camera contradicting the
        // list it just produced.
        let mode = flags & (D1_ALTERNATIVE_ILLUMINATION | D2_BACKGROUND_SUBTRACTION);
        if mode != D1_ALTERNATIVE_ILLUMINATION && mode != D2_BACKGROUND_SUBTRACTION {
            return Err(format!(
                "interface {interface} advertises {flags:#04x}, which is not exactly one face-authentication mode"
            ));
        }
        // A background-subtraction interface is refused rather than driven.
        // Selecting it would produce a stream this code does not know how to
        // read, and quietly getting different pixels than expected is how the
        // brightness heuristics elsewhere would start lying.
        if mode == D2_BACKGROUND_SUBTRACTION {
            return Err(format!(
                "interface {interface} offers only background subtraction (D2); irlume reads the \
                 alternating-illumination stream (D1) and will not select a mode it cannot interpret"
            ));
        }
        if seen.contains(&interface) {
            return Err(format!("interface {interface} is listed more than once"));
        }
        seen.push(interface);

        // The default must name the same interface, with a mode that is also one
        // of the three defined ones. Otherwise the two answers describe
        // different controls.
        if def[at] != interface {
            return Err(format!(
                "its default names interface {} where its maximum names {interface}",
                def[at]
            ));
        }
        let def_flags = def[at + 1];
        if def_flags & !DEFINED != 0 || def_flags.count_ones() != 1 {
            return Err(format!(
                "interface {interface} has a default mode of {def_flags:#04x}, which is not one \
                 defined mode"
            ));
        }

        out[at] = interface;
        // Exactly one bit, and one the camera named for this interface.
        out[at + 1] = mode;
    }

    // Bytes past the entries are not described by anything and must be zero in
    // both answers; a control putting data there is not the layout being parsed.
    let tail = 1 + entries * 2;
    if max[tail..].iter().any(|&b| b != 0) || def[tail..].iter().any(|&b| b != 0) {
        return Err("it reports data past the interfaces it listed".into());
    }

    Ok(out)
}

/// Whether an IR Torch `GET_DEF` value is one the specification says may be
/// written back.
///
/// Microsoft pins this control down completely, so the value can be checked
/// rather than trusted. The payload is `dwMode` then `dwValue`, both 32-bit
/// little-endian, and:
///
/// - `GET_LEN` is 8, so anything else is not this control.
/// - `GET_DEF`'s mode is the mode to be in before streaming begins, and must be
///   2 (ON) or 4 (ALTERNATING). A default of 0 (OFF) or some other bit pattern
///   would not turn the lamp on, and writing it back would be pointless.
/// - `GET_MAX`'s mode is a capability bitmap. D0 (OFF) is always supported, and
///   at least one active mode must be. The default's mode has to be one the
///   camera actually claims.
/// - `dwValue` is a power level, and must sit between the reported minimum and
///   maximum.
///
/// Reading a value from firmware is not evidence that writing it is safe, and
/// these are the invariants the published specification lets irlume insist on.
pub(crate) fn ir_torch_default_is_usable(
    def: &[u8],
    min: &[u8],
    max: &[u8],
    res: &[u8],
) -> std::result::Result<(), String> {
    const MODE_ON: u32 = 2;
    const MODE_ALTERNATING: u32 = 4;
    const MODE_OFF_BIT: u32 = 1;

    let dword = |b: &[u8], at: usize| -> Option<u32> {
        b.get(at..at + 4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
    };
    for (name, buf) in [
        ("default", def),
        ("minimum", min),
        ("maximum", max),
        ("resolution", res),
    ] {
        if buf.len() != 8 {
            return Err(format!(
                "the camera reported an {name} of {} bytes; IR Torch is defined as 8",
                buf.len()
            ));
        }
    }
    let (Some(def_mode), Some(def_value)) = (dword(def, 0), dword(def, 4)) else {
        return Err("could not read the default".into());
    };
    let (Some(max_mode), Some(max_value)) = (dword(max, 0), dword(max, 4)) else {
        return Err("could not read the maximum".into());
    };
    let (Some(min_mode), Some(min_value)) = (dword(min, 0), dword(min, 4)) else {
        return Err("could not read the minimum".into());
    };

    if def_mode != MODE_ON && def_mode != MODE_ALTERNATING {
        return Err(format!(
            "its default mode is {def_mode}, and the specification requires 2 (on) or 4 (alternating)"
        ));
    }
    if max_mode & MODE_OFF_BIT == 0 {
        return Err(
            "the camera does not report the off mode, so its capabilities are malformed".into(),
        );
    }
    // The capability bitmap is defined over D0 to D2 only. A value carrying
    // anything above that is not describing this control.
    const DEFINED_MODES: u32 = MODE_OFF_BIT | MODE_ON | MODE_ALTERNATING;
    if max_mode & !DEFINED_MODES != 0 {
        return Err(format!(
            "its capability bitmap {max_mode:#x} sets bits the specification does not define"
        ));
    }
    // The minimum's mode field is specified as zero.
    if min_mode != 0 {
        return Err(format!(
            "its reported minimum mode is {min_mode}, and the specification requires 0"
        ));
    }
    if max_mode & def_mode == 0 {
        return Err(format!(
            "its default mode {def_mode} is not among the modes it says it supports ({max_mode:#x})"
        ));
    }
    if min_value > max_value {
        return Err(format!(
            "its reported power range is inverted ({min_value} to {max_value})"
        ));
    }
    if def_value < min_value || def_value > max_value {
        return Err(format!(
            "its default power {def_value} is outside the range it reports ({min_value} to {max_value})"
        ));
    }

    // GET_RES is mandatory and constrains the range: its mode field is zero, its
    // step is non-zero, the span divides evenly by it, and a real setting sits on
    // the grid. A control failing these is contradicting its own definition.
    let (Some(res_mode), Some(step)) = (dword(res, 0), dword(res, 4)) else {
        return Err("could not read the resolution".into());
    };
    if res_mode != 0 {
        return Err(format!(
            "its reported resolution mode is {res_mode}, and the specification requires 0"
        ));
    }
    if step == 0 {
        return Err("it reports a power step of zero, which the specification forbids".into());
    }
    let span = max_value - min_value;
    if !span.is_multiple_of(step) {
        return Err(format!(
            "its power range {min_value} to {max_value} does not divide evenly by its step {step}"
        ));
    }
    if !(def_value - min_value).is_multiple_of(step) {
        return Err(format!(
            "its default power {def_value} does not sit on its own step grid of {step}"
        ));
    }
    Ok(())
}

/// What a camera's extension units are, read from its USB descriptors.
///
/// This is what `ir-setup --dry-run` reports. It sends nothing to the device at
/// all: the previous version issued `GET_LEN` to all 512 unit and selector
/// combinations, which is traffic to controls the camera never claimed to have.
pub fn describe_units(device: &str) -> std::io::Result<Vec<String>> {
    let (desc, interface) = crate::uvc_descriptor::usb_context(device)?;
    Ok(
        crate::uvc_descriptor::extension_units_for_interface(&desc, interface)
            .iter()
            .map(|u| {
                let kind = if u.is_microsoft_xu() {
                    " (Microsoft camera control)"
                } else {
                    " (vendor-defined; irlume will not write to it)"
                };
                let selectors: Vec<String> = (1u8..=64)
                    .filter(|s| u.advertises(*s))
                    .map(|s| format!("{s:#04x}"))
                    .collect();
                format!(
                    "unit {}{}: advertises [{}]",
                    u.unit_id,
                    kind,
                    selectors.join(", ")
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caught signal must set the flag the measurement loop polls, and the
    /// guard must hand the signal back to whatever disposition it displaced.
    ///
    /// SIGINT is set to SIG_IGN around the whole test, so the re-raise on drop
    /// is a no-op instead of killing the test binary. That also makes the
    /// restore assertion real: SIG_IGN is what must come back.
    #[test]
    fn a_caught_signal_is_noted_and_then_handed_back() {
        // Signal dispositions are process-global, like the environment, so this
        // contends on the same lock rather than racing the tests that flip env
        // vars while this one is swapping handlers.
        let _lock = crate::testenv::env_lock();

        // SAFETY: every sigaction below is fully initialised before use.
        unsafe {
            let mut ignore: libc::sigaction = std::mem::zeroed();
            ignore.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ignore.sa_mask);
            let mut before: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGINT, &ignore, &mut before), 0);

            {
                let _guard = AbortOnSignal::install();
                assert!(!abort_requested(), "nothing raised yet");
                assert_eq!(libc::raise(libc::SIGINT), 0);
                assert!(
                    abort_requested(),
                    "the handler must record the signal for the measurement loop to see"
                );
            } // drop restores SIG_IGN, then re-raises into it

            let mut after: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGINT, std::ptr::null(), &mut after),
                0
            );
            assert_eq!(
                after.sa_sigaction,
                libc::SIG_IGN,
                "the guard must put the previous disposition back"
            );
            assert!(
                !abort_requested(),
                "the flag must not leak into the next run"
            );

            libc::sigaction(libc::SIGINT, &before, std::ptr::null_mut());
        }
    }

    /// Every outcome, and what each one lets the two callers do.
    ///
    /// Written as one exhaustive table rather than a test per variant because
    /// the defect was not a wrong answer for one case: `enable` did not ask the
    /// question at all, logged "nothing further will be written to it", and then
    /// wrote to that same unit and selector on the next line. A table makes
    /// adding a variant without deciding its policy impossible to miss.
    #[test]
    fn each_recovery_outcome_decides_what_the_callers_may_do() {
        // (outcome, may capture write, blocks discovery, is logged)
        let table = [
            (RecoveryOutcome::NothingPending, true, false, false),
            (RecoveryOutcome::ForAnotherCamera, true, false, false),
            (RecoveryOutcome::AlreadyRestored, true, false, true),
            (
                RecoveryOutcome::Restored {
                    unit: 14,
                    selector: 6,
                },
                true,
                false,
                true,
            ),
            // The camera is provably right and only the store is wrong, so a
            // capture proceeds; discovery cannot, because its first act is to
            // write a record into that same store.
            (
                RecoveryOutcome::RestoredRecordKept("read-only fs".into()),
                true,
                true,
                true,
            ),
            // Silent: a setup run in flight is ordinary, and it is about to
            // resolve its own record. It still stops both writers.
            (
                RecoveryOutcome::OwnerStillRunning { pid: 1234 },
                false,
                true,
                false,
            ),
            (
                RecoveryOutcome::Unresolved("3 attempts did not take".into()),
                false,
                true,
                true,
            ),
            // Another irlume process holds this camera. Silent, and it stops
            // both writers: it is being looked after already.
            (RecoveryOutcome::Busy, false, true, false),
            // A same-model record this run cannot confirm belongs here.
            (
                RecoveryOutcome::Unconfirmed {
                    unit: 14,
                    selector: 6,
                    original: "010301".into(),
                    recorded_at: "/devices/pci0000:00/0000:00:14.0/usb3/3-5".into(),
                },
                false,
                true,
                true,
            ),
        ];

        // The comment above this test used to claim a table made "adding a
        // variant without deciding its policy impossible to miss", and then two
        // variants were added and missed exactly that way. A comment cannot
        // enforce anything. This match can: it is exhaustive, so a new variant
        // stops the crate compiling until somebody writes down what it means.
        fn stated_policy(outcome: &RecoveryOutcome) -> (bool, bool) {
            match outcome {
                RecoveryOutcome::NothingPending => (true, false),
                RecoveryOutcome::ForAnotherCamera => (true, false),
                RecoveryOutcome::AlreadyRestored => (true, false),
                RecoveryOutcome::Restored { .. } => (true, false),
                RecoveryOutcome::RestoredRecordKept(_) => (true, true),
                RecoveryOutcome::OwnerStillRunning { .. } => (false, true),
                RecoveryOutcome::Busy => (false, true),
                RecoveryOutcome::Unresolved(_) => (false, true),
                RecoveryOutcome::Unconfirmed { .. } => (false, true),
            }
        }
        for (outcome, may_write, blocks, _) in &table {
            assert_eq!(
                stated_policy(outcome),
                (*may_write, *blocks),
                "the table and the exhaustive statement disagree for {outcome:?}"
            );
        }
        for (outcome, may_write, blocks, logged) in table {
            assert_eq!(
                outcome.permits_capture_write(),
                may_write,
                "capture policy for {outcome:?}"
            );
            assert_eq!(
                outcome.blocks_discovery(),
                blocks,
                "discovery policy for {outcome:?}"
            );
            assert_eq!(
                outcome.message().is_some(),
                logged,
                "logging for {outcome:?}"
            );
        }
    }

    /// Drive one whole `try_documented_control` run against a stand-in camera.
    ///
    /// Returns the ordered request log and the value the control ends up
    /// holding. `IRLUME_STATE_DIR` points at a scratch directory so the undo
    /// record is real.
    fn run_discovery(
        camera: fake_camera::Camera,
        tag: &str,
        mut measure: impl FnMut() -> Option<f32>,
    ) -> (
        std::result::Result<Attempt, TryFailure>,
        Vec<fake_camera::Request>,
        Vec<u8>,
        std::path::PathBuf,
    ) {
        let dir = std::env::temp_dir().join(format!("irlume-discovery-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _fake = fake_camera::install(camera);
        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");
        // fd is never reached: the fake intercepts before the ioctl.
        let outcome = try_documented_control(-1, &id, ms.unit_id, selector, &mut measure);
        (outcome, fake_camera::log(), fake_camera::current(), dir)
    }

    /// A camera shaped like the two this module was validated against: they
    /// report `GET_MAX 01 03 03` and `GET_DEF 01 03 01`, from which
    /// `face_auth_payload` derives `01 03 02`. Using the real numbers means the
    /// run reaches a write for the same reason a real one does.
    fn a_working_camera() -> fake_camera::Camera {
        fake_camera::Camera {
            current: vec![1, 3, 1],
            len: 3,
            // D0 get + D1 set, and none of the disabled bits.
            info: 0b0000_0011,
            def: vec![1, 3, 1],
            max: vec![1, 3, 3],
            min: vec![0, 0, 0],
            res: vec![1, 1, 1],
            ..Default::default()
        }
    }

    /// The undo record is on disk, complete and correct, AT THE MOMENT the first
    /// byte reaches the camera.
    ///
    /// Asserted from inside the interception of that write, because no check
    /// made afterwards can tell "saved before the write" from "saved after it".
    /// The first version of this test looked at the store when the run was over
    /// and would have passed with `ExploratoryWrite::open` moved below
    /// `apply_exploratory`, which is precisely the crash window this module
    /// exists to close. Review caught that; the mutant is in the harness now.
    #[test]
    fn the_undo_record_is_on_disk_before_the_first_write() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-discovery-record-first");
        let _ = std::fs::remove_dir_all(&dir);

        let expected = {
            // Same env the run will use, so the path resolves identically.
            let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
            let id = identity(0x3277, 0x0059);
            crate::emitter_journal::record_path(&crate::emitter_journal::filing_key(&id))
        };

        let mut camera = a_working_camera();
        camera.at_first_write = Some(Box::new(move || {
            let body = std::fs::read_to_string(&expected)
                .map_err(|e| format!("no record at {} yet: {e}", expected.display()))?;
            let record: crate::emitter_journal::PendingWrite = serde_json::from_str(&body)
                .map_err(|e| format!("the record is not complete json: {e}"))?;
            // The bytes that make it an undo record, not just a file.
            if record.original != "010301" {
                return Err(format!("original is {}", record.original));
            }
            Ok(())
        }));

        let mut brightness = [10.0f32, 90.0, 10.0].into_iter();
        let (outcome, log, _current, dir) =
            run_discovery(camera, "record-first", move || brightness.next());

        assert!(
            !log.iter()
                .any(|r| matches!(r, fake_camera::Request::FailedPrecondition(_))),
            "the record must already be on disk when the camera is first written to: {log:?}"
        );
        assert!(
            log.iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "a run that never wrote proves nothing about ordering: {log:?}"
        );
        assert!(
            matches!(outcome, Ok(Attempt::Lit(..))),
            "the fixture must reach a successful discovery: {outcome:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A camera that says "yes" to the final write but holds something else must
    /// not have its undo data deleted.
    ///
    /// `commit` used to clear on the strength of the `SET_CUR` returning
    /// success, which is precisely the assumption the rest of this module
    /// refuses to make. `ir_emitter.conf` stores coordinates and no payload, so
    /// once the record is gone nothing holds the original bytes at all.
    #[test]
    fn a_final_write_the_camera_did_not_take_keeps_the_undo_record() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-commit-readback");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        let _fake = fake_camera::install(a_working_camera());
        let mut pending =
            ExploratoryWrite::open(-1, &id, ms.unit_id, selector, 3, &[1, 3, 1], &[1, 3, 2])
                .expect("open the record");
        pending
            .apply_exploratory(&[1, 3, 2])
            .expect("the fake accepts the write");

        // The camera quietly holds something else. The fake's GET_CUR follows an
        // accepted SET_CUR, so this is forced directly.
        fake_camera::set_current(vec![1, 3, 3]);

        let err = pending
            .confirm_applied()
            .expect_err("an unconfirmed control must not be accepted");
        assert!(err.contains("[01, 03, 03]"), "{err}");
        assert!(
            !pending.resolved,
            "an unconfirmed control leaves the guard armed so Drop restores it"
        );
        assert!(
            pending.exploratory_value_is_live,
            "the camera is answering, so the control still needs putting back"
        );

        let store = dir.join("ir-emitter-journal");
        assert_eq!(
            std::fs::read_dir(&store).map(|d| d.count()).unwrap_or(0),
            1,
            "the undo record must survive: nothing else holds the original bytes"
        );
        drop(pending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed verification leaves NO configuration behind.
    ///
    /// Drives `Discovered::finish`, the sequence the daemon actually runs, not a
    /// copy of it: an earlier version of this test reproduced the ordering
    /// itself, so a mutant deleting the confirmation from the shipped path
    /// survived the whole suite. `save_conf` used to run first, and a camera that
    /// did not take the final write still ended up named in a file every later
    /// capture applies, which is the write the verification exists to prevent.
    #[test]
    fn a_failed_verification_publishes_no_configuration() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-verify-order");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let conf = dir.join("ir_emitter.conf");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);
        let _confenv = EnvGuard::set("IRLUME_IR_EMITTER_CONF", &conf);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        let _fake = fake_camera::install(a_working_camera());
        let mut pending =
            ExploratoryWrite::open(-1, &id, ms.unit_id, selector, 3, &[1, 3, 1], &[1, 3, 2])
                .expect("open the record");
        pending
            .apply_exploratory(&[1, 3, 2])
            .expect("write accepted");

        let found = Discovered {
            control: EmitterControl {
                unit: ms.unit_id,
                selector,
                payload: vec![1, 3, 2],
            },
            pending,
            _lock: crate::emitter_journal::lock_camera(&id)
                .expect("lock")
                .expect("not busy"),
        };

        // The camera quietly holds something else.
        fake_camera::set_current(vec![1, 3, 3]);
        let err = found.finish(&id).expect_err("finish must refuse");

        assert!(err.contains("[01, 03, 03]"), "{err}");
        assert!(
            !conf.exists(),
            "a control the camera did not take must not be named in a config \
             that every later capture applies"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same sequence, succeeding: the config lands and the record goes.
    ///
    /// Without this the assertion above would pass on a `finish` that never
    /// wrote a config at all.
    #[test]
    fn a_confirmed_application_publishes_the_config_and_drops_the_record() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-verify-order-ok");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let conf = dir.join("ir_emitter.conf");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);
        let _confenv = EnvGuard::set("IRLUME_IR_EMITTER_CONF", &conf);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        let _fake = fake_camera::install(a_working_camera());
        let mut pending =
            ExploratoryWrite::open(-1, &id, ms.unit_id, selector, 3, &[1, 3, 1], &[1, 3, 2])
                .expect("open the record");
        pending
            .apply_exploratory(&[1, 3, 2])
            .expect("write accepted");

        let found = Discovered {
            control: EmitterControl {
                unit: ms.unit_id,
                selector,
                payload: vec![1, 3, 2],
            },
            pending,
            _lock: crate::emitter_journal::lock_camera(&id)
                .expect("lock")
                .expect("not busy"),
        };
        found.finish(&id).expect("the camera took the write");

        assert_eq!(
            std::fs::read_to_string(&conf).expect("the config must be written"),
            format!("{} {}:{selector}", id.usb_id(), ms.unit_id)
        );
        assert_eq!(
            std::fs::read_dir(dir.join("ir-emitter-journal"))
                .map(|d| d
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                    .count())
                .unwrap_or(0),
            0,
            "the record is released once the config is durable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record this build writes carries no owner, so a leftover one is always
    /// recoverable.
    ///
    /// `save` publishes by rename and fsyncs afterwards. A failure in those
    /// durability steps returns an error while leaving the record visible, and a
    /// record carrying the pid of the long-lived daemon would then be refused by
    /// every later recovery as "somebody else's" until the machine restarted —
    /// over a record whose camera was never written to. The per-camera lock is
    /// what excludes a concurrent run.
    #[test]
    fn a_new_record_records_no_owning_process() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-record-no-owner");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        let _fake = fake_camera::install(a_working_camera());
        let pending =
            ExploratoryWrite::open(-1, &id, ms.unit_id, selector, 3, &[1, 3, 1], &[1, 3, 2])
                .expect("open the record");
        std::mem::forget(pending); // leave the record exactly as `open` wrote it

        let record = match crate::emitter_journal::load(&id).expect("load") {
            crate::emitter_journal::Situation::Mine(r) => *r,
            other => panic!("expected this camera's own record: {other:?}"),
        };
        assert_eq!(record.pid, None, "a live pid would strand this record");
        assert_eq!(record.boot_id, None);
        // And it is recoverable rather than somebody else's business.
        assert_eq!(
            crate::emitter_journal::record_applies(&record, &id),
            Ok(()),
            "a leftover record must be actionable once the lock is released"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A camera that stops answering a READ during verification is not written
    /// to again either.
    ///
    /// An ioctl error is how this module decides a camera has stopped answering,
    /// and its rule is that nothing further is sent to one in that state. The
    /// verification's failure path has to disarm the guard for the same reason
    /// the write paths do, or `Drop` sends a restore to hardware that has just
    /// failed to respond.
    ///
    /// A mismatched VALUE is the opposite case and must keep the guard armed:
    /// there the camera is answering and the control genuinely needs putting
    /// back. Both are asserted here so neither can be traded for the other.
    #[test]
    fn a_camera_that_stops_answering_during_verification_is_left_alone() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-verify-read-fails");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        let _fake = fake_camera::install(a_working_camera());
        let mut pending =
            ExploratoryWrite::open(-1, &id, ms.unit_id, selector, 3, &[1, 3, 1], &[1, 3, 2])
                .expect("open the record");
        pending
            .apply_exploratory(&[1, 3, 2])
            .expect("write accepted");
        let writes_before = fake_camera::log()
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set(_)))
            .count();

        fake_camera::fail_reads(libc::EIO);
        pending
            .confirm_applied()
            .expect_err("a camera that will not answer cannot confirm anything");
        assert!(
            !pending.exploratory_value_is_live,
            "an ioctl error must disarm the guard"
        );

        drop(pending);
        let writes_after = fake_camera::log()
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set(_)))
            .count();
        assert_eq!(
            writes_after, writes_before,
            "nothing further may be sent to a camera that stopped answering"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A configuration that IS visible after a failed save keeps its undo record
    /// and leaves the camera alone.
    ///
    /// The config is published by a rename and made durable afterwards, so a
    /// failure in the durability half returns an error while the file stays in
    /// place, and every later capture reads it and applies that control. Putting
    /// the camera back and clearing the record there would leave a machine that
    /// re-lights the emitter from a config with no undo data behind it.
    #[test]
    fn a_visible_config_after_a_failed_save_keeps_the_record() {
        use std::os::unix::fs::PermissionsExt as _;
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-conf-half-published");
        let _ = std::fs::remove_dir_all(&dir);
        let confdir = dir.join("etc");
        std::fs::create_dir_all(&confdir).expect("scratch dirs");
        let conf = confdir.join("ir_emitter.conf");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);
        let _confenv = EnvGuard::set("IRLUME_IR_EMITTER_CONF", &conf);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        // The state the finding describes: the configuration naming this control
        // is READABLE, and the save nevertheless reports failure. Provoked by
        // taking write permission off the directory, so the temp file cannot be
        // created, with the published file already there.
        std::fs::write(&conf, format!("{} {}:{selector}", id.usb_id(), ms.unit_id))
            .expect("publish a config");
        std::fs::set_permissions(&confdir, std::fs::Permissions::from_mode(0o500))
            .expect("make the directory unwritable");

        let _fake = fake_camera::install(a_working_camera());
        let mut pending =
            ExploratoryWrite::open(-1, &id, ms.unit_id, selector, 3, &[1, 3, 1], &[1, 3, 2])
                .expect("open the record");
        pending
            .apply_exploratory(&[1, 3, 2])
            .expect("write accepted");
        let writes_before = fake_camera::log()
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set(_)))
            .count();

        let found = Discovered {
            control: EmitterControl {
                unit: ms.unit_id,
                selector,
                payload: vec![1, 3, 2],
            },
            pending,
            _lock: crate::emitter_journal::lock_camera(&id)
                .expect("lock")
                .expect("not busy"),
        };
        let err = found.finish(&id).expect_err("the save must fail");
        assert!(err.contains("save the emitter config"), "{err}");

        std::fs::set_permissions(&confdir, std::fs::Permissions::from_mode(0o700))
            .expect("restore");
        assert!(conf.exists(), "the premise: the config is still visible");
        assert_eq!(
            std::fs::read_dir(dir.join("ir-emitter-journal"))
                .map(|d| d.filter_map(|e| e.ok()).count())
                .unwrap_or(0),
            1,
            "the undo record must outlive a half-published configuration"
        );
        assert_eq!(
            fake_camera::log()
                .iter()
                .filter(|r| matches!(r, fake_camera::Request::Set(_)))
                .count(),
            writes_before,
            "and the camera must not be put back behind a config that will re-apply it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A camera that refuses the restoring write must not be written to again.
    ///
    /// The guard's `Drop` used to repeat the identical `SET_CUR` on the way out,
    /// against hardware this crate had just classified as unresponsive, and
    /// outside the attempt budget entirely. That is the #159 hazard: the rule
    /// here is that after an error nothing further is sent.
    #[test]
    fn a_camera_that_refuses_a_restore_is_not_written_to_again() {
        let _lock = crate::testenv::env_lock();
        // Accept the exploratory write, then fail every write after it.
        let camera = fake_camera::Camera {
            fail_set_from: Some((2, libc::EIO)),
            ..a_working_camera()
        };
        // Bright, then the stream dies, which is the path that restores.
        let mut brightness = [10.0f32].into_iter();
        let (outcome, log, _current, dir) =
            run_discovery(camera, "restore-refused", move || brightness.next());

        assert!(
            matches!(outcome, Err(TryFailure::Restore(_))),
            "the refused restore is what the run reports"
        );
        let writes = log
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set(_)))
            .count();
        assert_eq!(
            writes, 2,
            "one exploratory write and one restore attempt, and nothing after the refusal: {log:?}"
        );
        // The record stays, so the next capture resolves it through recovery,
        // where every attempt is counted and durable before it is made.
        let store = dir.join("ir-emitter-journal");
        let remaining = std::fs::read_dir(&store)
            .map(|d| d.count())
            .unwrap_or_default();
        assert_eq!(remaining, 1, "the undo record is left for recovery");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A camera that refuses the FIRST write has not been changed, so there is
    /// nothing for `Drop` to put back and it must send nothing.
    #[test]
    fn a_refused_first_write_produces_no_second_one() {
        let _lock = crate::testenv::env_lock();
        let camera = fake_camera::Camera {
            fail_set_from: Some((1, libc::EIO)),
            ..a_working_camera()
        };
        let mut brightness = [10.0f32].into_iter();
        let (outcome, log, current, dir) =
            run_discovery(camera, "first-write-refused", move || brightness.next());

        assert!(matches!(outcome, Err(TryFailure::Query(_))), "{outcome:?}");
        let writes = log
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set(_)))
            .count();
        assert_eq!(
            writes, 1,
            "exactly one write, which the camera refused: {log:?}"
        );
        assert_eq!(current, vec![1, 3, 1], "the control was never changed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run that stops early because the signal flag is set must not have
    /// written to the camera at all.
    ///
    /// The flag is polled directly before each write rather than relied on to
    /// interrupt a frame wait: a process-directed signal goes to an arbitrary
    /// thread, so the camera worker may never see EINTR.
    #[test]
    fn an_abort_before_the_first_write_sends_the_camera_nothing() {
        let _lock = crate::testenv::env_lock();
        // Measurement succeeds; the abort is what stops the run.
        let guard = AbortOnSignal::install();
        ABORT_SIGNAL.store(libc::SIGTERM, std::sync::atomic::Ordering::SeqCst);
        assert!(
            abort_requested(),
            "the flag must be set for this to mean anything"
        );

        let (outcome, log, current, dir) =
            run_discovery(a_working_camera(), "abort-first", || Some(10.0));

        // Take the flag back before the guard drops, so nothing is re-raised at
        // the test binary.
        ABORT_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
        drop(guard);

        assert!(
            matches!(outcome, Err(TryFailure::Measurement)),
            "{outcome:?}"
        );
        assert!(
            !log.iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may reach a camera after a stop signal: {log:?}"
        );
        assert_eq!(current, vec![1, 3, 1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Recovery sizes its `GET_CUR` from the length the CAMERA reports, never
    /// from the record.
    ///
    /// The three queries used to sit in one tuple, and a tuple evaluates every
    /// operand before the match runs: a record claiming 64 bytes against a
    /// camera reporting 3 sent a 64-byte control request to firmware, and only
    /// afterwards was the mismatch noticed. This is an ordering between two
    /// ioctls, so the request log is the only thing that can show it.
    #[test]
    fn recovery_asks_the_camera_its_length_before_reading_the_control() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-recovery-length");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        // Recovery takes the camera lock before any ioctl, so a test that cannot
        // create it never reaches the code under test — and would still see an
        // `Unresolved` outcome, for entirely the wrong reason. The GET_LEN
        // assertion below is what caught that.
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        // A record that claims a 64-byte control, against a camera that says 3.
        let record = crate::emitter_journal::PendingWrite {
            schema_version: crate::emitter_journal::SCHEMA_VERSION,
            engine_version: "test".into(),
            descriptor_sha256: crate::emitter_journal::fingerprint(&id),
            usb_id: id.usb_id(),
            interface_number: id.interface_number,
            unit: ms.unit_id,
            selector,
            len: 64,
            original: crate::emitter_journal::to_hex(&[0u8; 64]),
            attempted: crate::emitter_journal::to_hex(&[1u8; 64]),
            restore_attempts: 0,
            boot_id: None,
            pid: None,
            serial: id.serial.clone(),
            usb_devpath: id.usb_devpath.clone(),
        };
        crate::emitter_journal::save(&record).expect("plant the record");

        let _fake = fake_camera::install(a_working_camera());
        let outcome = recover_pending_write(-1, &id);
        let log = fake_camera::log();

        assert!(
            matches!(outcome, RecoveryOutcome::Unresolved(_)),
            "a length the camera contradicts is unresolved: {outcome:?}"
        );
        assert!(
            !log.iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "nothing is written: {log:?}"
        );
        assert!(
            !log.iter().any(|r| matches!(
                r,
                fake_camera::Request::Get {
                    query: UVC_GET_CUR,
                    ..
                }
            )),
            "the control is never read once its length is contradicted: {log:?}"
        );
        // And the guard has to be reachable: the camera really was asked.
        assert!(
            log.iter().any(|r| matches!(
                r,
                fake_camera::Request::Get {
                    query: UVC_GET_LEN,
                    ..
                }
            )),
            "GET_LEN must have been issued, or this proves nothing: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A camera another process holds is not touched at all.
    ///
    /// Driven against a real second process holding the lock, because `flock` is
    /// per open file description: taking it twice inside this process would
    /// succeed no matter what the code did.
    #[test]
    fn a_locked_camera_is_not_queried_or_written() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-recovery-locked");
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let id = identity(0x3277, 0x0059);
        // Create the store and the lock path the same way production does.
        let held = crate::emitter_journal::lock_camera(&id)
            .expect("take the lock")
            .expect("not busy");
        // Asked for by the same code the daemon uses, not rebuilt from the
        // filing key: the lock is deliberately keyed on something narrower, and
        // a test that constructs the name itself stops holding the lock the
        // moment that changes. It did, and this caught it.
        let path = crate::emitter_journal::lock_path_for_test(&id);
        drop(held);

        // The child signals readiness by creating a marker AFTER `flock` has
        // granted it the lock. Inferring readiness by racing it for the lock
        // instead made this test timing-dependent: on a loaded machine the
        // child had not started yet, our own attempt succeeded, and the test
        // failed with nothing wrong in the code.
        let ready = dir.join("holder-has-the-lock");
        let mut holder = std::process::Command::new("flock")
            .args([
                path.to_str().expect("path"),
                "-c",
                &format!("touch {}; sleep 30", ready.display()),
            ])
            .spawn()
            .expect("spawn the lock holder");

        let mut taken = false;
        for _ in 0..600 {
            if ready.exists() {
                taken = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }

        let (outcome, log) = if taken {
            let _fake = fake_camera::install(a_working_camera());
            let outcome = recover_pending_write(-1, &id);
            (outcome, fake_camera::log())
        } else {
            (RecoveryOutcome::NothingPending, Vec::new())
        };

        let _ = holder.kill();
        let _ = holder.wait();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(taken, "the second process never took the lock");
        assert_eq!(
            outcome,
            RecoveryOutcome::Busy,
            "a camera somebody else holds is busy, not free"
        );
        assert!(
            log.is_empty(),
            "a busy camera must be sent nothing at all, not even a read: {log:?}"
        );
    }

    /// The emitter config is REPLACED, not truncated in place.
    ///
    /// The undo record is dropped on the strength of this call returning, so a
    /// return that only means "the bytes are in the page cache" breaks the
    /// ordering `commit` documents. An fsync leaves no trace, but the inode does:
    /// truncate-in-place keeps it and passes through an empty moment, a rename
    /// gives a new one. A test on the final CONTENT passes either way, which is
    /// why it is asserted on the inode.
    #[test]
    fn the_emitter_config_is_replaced_rather_than_truncated() {
        use std::os::unix::fs::MetadataExt as _;
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-save-conf-atomic");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let conf = dir.join("ir_emitter.conf");
        let _env = EnvGuard::set("IRLUME_IR_EMITTER_CONF", &conf);

        let id = identity(0x3277, 0x0059);
        save_conf(
            &id,
            &EmitterControl {
                unit: 14,
                selector: 6,
                payload: vec![],
            },
        )
        .expect("first write");
        let first = std::fs::metadata(&conf).expect("stat").ino();

        save_conf(
            &id,
            &EmitterControl {
                unit: 14,
                selector: 10,
                payload: vec![],
            },
        )
        .expect("second write");
        let second = std::fs::metadata(&conf).expect("stat").ino();

        assert_ne!(
            first, second,
            "a rewrite must land on a fresh inode, not truncate the live file"
        );
        assert_eq!(
            std::fs::read_to_string(&conf).expect("read"),
            format!("{} 14:10", id.usb_id())
        );
        // The requested mode NARROWED BY THE PROCESS UMASK, which is what
        // actually happens. A bare 0644 assertion passed only because the test
        // binary's umask is 0022; the daemon ships `UMask=0027`, so the real
        // file is 0640 and this was green here while false on the machine that
        // matters.
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: umask is process-global, and the env lock held by this test
        // serialises it against every other test that touches process state.
        let previous = unsafe { libc::umask(0o027) };
        let masked = dir.join("masked.conf");
        irlume_common::write_atomic_mode(&masked, b"x", 0o644).expect("write");
        let masked_mode = std::fs::metadata(&masked)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        unsafe { libc::umask(previous) };
        assert_eq!(
            masked_mode, 0o640,
            "a requested 0644 under UMask=0027 is 0640, which is what the shipped \
             daemon has always produced"
        );
        assert_eq!(
            std::fs::metadata(&conf).expect("stat").permissions().mode() & 0o777,
            0o644 & !previous,
            "and the config written above follows the same rule"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A control changed AFTER recovery authorised the restore is not
    /// overwritten.
    ///
    /// The authorisation read happens, then the attempt counter is written and
    /// fsynced — a create, a write, a rename and several directory syncs — and
    /// only then the restore. Acting on the earlier read across all of that is a
    /// check-then-act with a filesystem's worth of time in it, and the camera
    /// lock excludes other irlume processes, not a vendor tool. So the control
    /// is read again immediately before the write.
    #[test]
    fn a_control_changed_while_the_attempt_was_recorded_is_not_overwritten() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-recheck-before-restore");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);

        let id = identity(0x3277, 0x0059);
        let ms = id.microsoft_xu().expect("fixture has a Microsoft XU");
        let selector = [
            crate::uvc_descriptor::MSXU_IR_TORCH,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
        ]
        .into_iter()
        .find(|s| ms.advertises(*s))
        .expect("fixture advertises an emitter selector");

        crate::emitter_journal::save(&crate::emitter_journal::PendingWrite {
            schema_version: crate::emitter_journal::SCHEMA_VERSION,
            engine_version: "test".into(),
            descriptor_sha256: crate::emitter_journal::fingerprint(&id),
            usb_id: id.usb_id(),
            interface_number: id.interface_number,
            unit: ms.unit_id,
            selector,
            len: 3,
            original: crate::emitter_journal::to_hex(&[1, 3, 1]),
            attempted: crate::emitter_journal::to_hex(&[1, 3, 2]),
            restore_attempts: 0,
            boot_id: None,
            pid: None,
            serial: id.serial.clone(),
            usb_devpath: id.usb_devpath.clone(),
        })
        .expect("plant the record");

        // Holding this run's exploratory value at the authorising read, and
        // something else's by the time the write would happen.
        let camera = fake_camera::Camera {
            current: vec![1, 3, 2],
            change_after_gets: Some((1, vec![1, 3, 3])),
            ..a_working_camera()
        };
        let _fake = fake_camera::install(camera);

        let outcome = recover_pending_write(-1, &id);
        let log = fake_camera::log();

        assert!(
            matches!(outcome, RecoveryOutcome::Unresolved(ref why) if why.contains("[01, 03, 03]")),
            "the second read must be what decides: {outcome:?}"
        );
        assert!(
            !log.iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "nothing may be written over a value irlume did not put there: {log:?}"
        );
        // And the read really did happen twice, or the guard was never reached.
        assert!(
            log.iter()
                .filter(|r| matches!(
                    r,
                    fake_camera::Request::Get {
                        query: UVC_GET_CUR,
                        ..
                    }
                ))
                .count()
                >= 2,
            "the control must be re-read immediately before the write: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unresolved record stops ALL THREE of the sources a capture can apply
    /// from, not just the recovery write.
    ///
    /// This is the finding review caught: the refusal was logged and then the
    /// configured control was applied to the very unit and selector the record
    /// named, on the next line, at every stream open and every eighth frame of a
    /// burst. Each source is checked separately, because a guard placed before
    /// the override alone would leave the other two writing.
    #[test]
    fn an_unresolved_record_stops_every_source_a_capture_could_write_from() {
        let _lock = crate::testenv::env_lock();
        let id = identity(0x3277, 0x0059);
        let blocked = [
            RecoveryOutcome::Unresolved("3 attempts did not take".into()),
            RecoveryOutcome::OwnerStillRunning { pid: 4321 },
        ];

        for recovery in &blocked {
            // Source 1: the env override, the only path the user asked for.
            assert_eq!(
                planned_action(
                    recovery,
                    Some(EmitterControl {
                        unit: 14,
                        selector: 6,
                        payload: vec![1, 3, 2],
                    }),
                    &id
                ),
                CaptureAction::Nothing,
                "override under {recovery:?}"
            );

            // Source 2: the control ir-setup recorded. Pointed at a real conf so
            // the branch is genuinely reachable, otherwise this would pass
            // because there was nothing to apply.
            let dir = std::env::temp_dir().join("irlume-planned-action");
            let _ = std::fs::create_dir_all(&dir);
            let conf = dir.join("ir_emitter.conf");
            let (unit, selector) = {
                let ms = id.microsoft_xu().expect("fixture publishes a Microsoft XU");
                let selector = [
                    crate::uvc_descriptor::MSXU_IR_TORCH,
                    crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
                ]
                .into_iter()
                .find(|s| ms.advertises(*s))
                .expect("fixture advertises an emitter selector");
                (ms.unit_id, selector)
            };
            std::fs::write(&conf, format!("{} {unit}:{selector}", id.usb_id()))
                .expect("write conf");
            let _env = EnvGuard::set("IRLUME_IR_EMITTER_CONF", &conf);

            assert_eq!(
                planned_action(&RecoveryOutcome::NothingPending, None, &id),
                CaptureAction::DeviceDefault { unit, selector },
                "the conf branch must be reachable, or the next assertion proves nothing"
            );
            assert_eq!(
                planned_action(recovery, None, &id),
                CaptureAction::Nothing,
                "recorded control under {recovery:?}"
            );
            drop(_env);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A record belonging to a DIFFERENT camera must not turn this camera's
    /// emitter off. A machine with a detached second camera would otherwise drop
    /// to password-only login for no reason.
    #[test]
    fn a_record_for_another_camera_does_not_stop_this_one() {
        let _lock = crate::testenv::env_lock();
        let _env = EnvGuard::unset("IRLUME_IR_EMITTER_CONF");
        let id = identity(0x3277, 0x0059);
        let ctrl = EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2],
        };
        assert_eq!(
            planned_action(&RecoveryOutcome::ForAnotherCamera, Some(ctrl.clone()), &id),
            CaptureAction::Override(ctrl),
            "another camera's record is not this camera's business"
        );
    }

    /// The message an operator reads has to say why face authentication stopped,
    /// not only that a record exists. A refusal that does not explain the symptom
    /// sends someone hunting through the wrong subsystem.
    #[test]
    fn a_refusal_says_the_emitter_will_not_light() {
        // The message embeds `store_dir()`, which reads `IRLUME_STATE_DIR`. Read
        // once here and once in the assertion, with other tests flipping that
        // variable in the same process, the two could disagree and this failed
        // for reasons having nothing to do with the message. It showed up as a
        // test that "caught" unrelated mutants.
        let _lock = crate::testenv::env_lock();
        let _env = EnvGuard::set("IRLUME_STATE_DIR", "/var/lib/irlume-message-test");
        let msg = RecoveryOutcome::Unresolved("the control reads [1, 3, 2]".into())
            .message()
            .expect("a refusal is always reported");
        assert!(msg.contains("will not write"), "{msg}");
        assert!(msg.contains("will not light"), "{msg}");
        // And where to find the bytes that would put it back.
        assert!(
            msg.contains(&crate::emitter_journal::store_dir().display().to_string()),
            "{msg}"
        );
    }

    #[test]
    fn encode_parse_roundtrip() {
        let c = EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2, 0],
        };
        assert_eq!(parse_control(&c.encode()), Some(c));
    }

    use crate::testenv::EnvGuard;

    /// Serializes access to the process env vars these tests flip
    /// (`IRLUME_IR_EMITTER`, `IRLUME_IR_EMITTER_CONF`).
    ///
    /// `crate::testenv::ENV_LOCK`, not a private one. A module-private mutex
    /// over a process-global serialises the module against itself and nothing
    /// else, so these raced the capture tests in `lib.rs` that flip their own
    /// variables in the same process.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::testenv::env_lock()
    }

    /// An fd that is open but is not a UVC device, so every XU ioctl fails
    /// (ENOTTY): exercises the query-failure paths without touching a camera.
    /// A camera identity backed by the real ASUS descriptor bytes, so these
    /// exercise the same parsing path production uses.
    fn identity(vid: u16, pid: u16) -> crate::uvc_descriptor::CameraIdentity {
        crate::uvc_descriptor::CameraIdentity {
            descriptors: include_bytes!("../tests/fixtures/asus-3277-0059.descriptors").to_vec(),
            interface_number: 2,
            vid,
            pid,
            serial: Some("200901010001".into()),
            usb_devpath: "/devices/pci0000:00/0000:00:14.0/usb3/3-5".into(),
        }
    }

    fn non_uvc_fd() -> std::fs::File {
        std::fs::File::open("/dev/null").expect("open /dev/null")
    }

    #[test]
    fn parse_control_accepts_decimal_and_hex() {
        assert_eq!(
            parse_control("14:6:1,3,2"),
            Some(EmitterControl {
                unit: 14,
                selector: 6,
                payload: vec![1, 3, 2],
            })
        );
        assert_eq!(
            parse_control(" 0x0E:0X06:0x01,255 "),
            Some(EmitterControl {
                unit: 14,
                selector: 6,
                payload: vec![1, 255],
            })
        );
    }

    #[test]
    fn parse_control_rejects_garbage() {
        // Empty / non-numeric / missing fields.
        assert_eq!(parse_control(""), None);
        assert_eq!(parse_control("   "), None);
        assert_eq!(parse_control("abc"), None);
        assert_eq!(parse_control("1:2"), None); // no payload section
        assert_eq!(parse_control("1:2:"), None); // empty payload
        assert_eq!(parse_control("x:2:1"), None); // bad unit
        assert_eq!(parse_control("1:y:1"), None); // bad selector
                                                  // Out-of-range unit/selector (u8 overflow) fail the whole parse.
        assert_eq!(parse_control("256:1:1"), None);
        assert_eq!(parse_control("1:300:1"), None);
        assert_eq!(parse_control("1:2:300"), None); // byte out of range

        // Any unparseable byte rejects the whole control. This previously
        // dropped the bad field and kept going, so "1:2:1,300,2" became the
        // two-byte payload [1, 2]: a typo or a corrupted file quietly turned
        // into a different write than the one its author wrote down.
        assert_eq!(parse_control("1:2:1,300,2"), None);
        assert_eq!(parse_control("1:2:1,bad,2"), None);
        assert_eq!(parse_control("1:2:1,,2"), None);
        assert_eq!(parse_control("1:2:1,2,"), None);

        // A trailing field means the value is not what it appears to be.
        assert_eq!(parse_control("1:2:3:4"), None);

        // Hex and decimal still parse, and a valid payload is unchanged.
        assert_eq!(
            parse_control("14:6:1,0x03,2").map(|c| c.payload),
            Some(vec![1, 3, 2])
        );
    }

    #[test]
    fn known_control_table_is_keyed_on_usb_identity_not_a_name() {
        // The two modules the payload was validated on.
        let asus = known_control(0x3277, 0x0059).expect("ASUS entry");
        assert_eq!(asus.unit, 14);
        assert_eq!(
            asus.selector,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION
        );

        let nexigo = known_control(0x3443, 0xc803).expect("N930W entry");
        assert_eq!(nexigo.unit, 4);
        assert_eq!(
            nexigo.selector,
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION
        );

        // A different camera gets nothing, however it names itself. The old
        // table matched `card.contains("ASUS")`, so any camera with that word
        // in its name received nine bytes at unit 14 selector 6.
        assert_eq!(known_control(0x046d, 0x085e), None); // Logitech Brio
        assert_eq!(known_control(0x3277, 0x0060), None); // same vendor, other product
        assert_eq!(known_control(0x0000, 0x0000), None);
    }

    #[test]
    fn valid_ctrl_len_bounds() {
        // GET_LEN plausibility: 1..=64 accepted, 0 and oversize rejected.
        assert_eq!(valid_ctrl_len(0), None);
        assert_eq!(valid_ctrl_len(1), Some(1));
        assert_eq!(valid_ctrl_len(9), Some(9));
        assert_eq!(valid_ctrl_len(64), Some(64));
        assert_eq!(valid_ctrl_len(65), None);
        assert_eq!(valid_ctrl_len(usize::MAX), None);
    }

    #[test]
    fn a_persisted_control_is_bound_to_the_camera_it_was_found_on() {
        let _g = env_guard();
        let dir = std::env::temp_dir().join(format!("irlume-emitter-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("ir_emitter.conf");
        std::env::set_var("IRLUME_IR_EMITTER_CONF", &conf);

        let asus = identity(0x3277, 0x0059);
        let other = identity(0x046d, 0x085e);
        let ctrl = EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2],
        };

        save_conf(&asus, &ctrl).unwrap();
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "3277:0059 14:6",
            "the file records which camera and which control, and no payload"
        );
        assert_eq!(load_conf(&asus), Some((14, 6)));

        // The reason the identity is recorded: unit and selector numbers mean
        // nothing across cameras, so a file written for one module must not be
        // replayed into another that happens to expose something at the same
        // coordinates.
        assert_eq!(load_conf(&other), None);

        // A file written before 0.7.1 has no identity. It came from a search
        // that wrote invented payloads until the picture brightened, and there
        // is no record of what camera it belongs to, so it is refused outright.
        std::fs::write(&conf, "14:6:1,3,2").unwrap();
        assert_eq!(load_conf(&asus), None);
        // Including one that carries the old second "boost" line.
        std::fs::write(&conf, "4:13:1,3,2,0\n4:9:255,255").unwrap();
        assert_eq!(load_conf(&asus), None);

        // Only the two controls discovery can record are accepted. A file
        // naming any other Microsoft selector would otherwise put query and
        // write traffic onto an unrelated control on every capture.
        std::fs::write(&conf, "3277:0059 14:1").unwrap();
        assert_eq!(load_conf(&asus), None, "Focus is not an emitter control");
        std::fs::write(&conf, "3277:0059 14:9").unwrap();
        assert_eq!(load_conf(&asus), None, "Metadata is not an emitter control");
        std::fs::write(&conf, "3277:0059 14:10").unwrap();
        assert_eq!(load_conf(&asus), Some((14, 10)), "IR Torch is");

        // A stamped file that still carries a payload is refused too. Storing a
        // payload at all is the defect: it is an unauthenticated value that
        // would be replayed into the camera on every capture, and nothing about
        // a file proves those bytes were ever the device's own.
        std::fs::write(&conf, "3277:0059 14:6:1,3,2").unwrap();
        assert_eq!(load_conf(&asus), None);

        std::fs::remove_file(&conf).unwrap();
        assert_eq!(load_conf(&asus), None);

        std::env::remove_var("IRLUME_IR_EMITTER_CONF");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A control is only applied automatically when the attached camera's own
    /// descriptor says that unit is Microsoft's and advertises that selector.
    #[test]
    fn only_a_control_the_camera_documents_is_applied_automatically() {
        let asus = identity(0x3277, 0x0059);

        // Unit 14 selector 6 is the Microsoft Face Authentication control on
        // this camera, confirmed against its real descriptor.
        assert!(control_is_documented(
            &asus,
            &EmitterControl {
                unit: 14,
                selector: 6,
                payload: vec![1, 3, 2]
            }
        ));

        // The shape that killed the reporter's camera: a vendor unit this
        // camera does not present as Microsoft's, at an unadvertised selector.
        assert!(!control_is_documented(
            &asus,
            &EmitterControl {
                unit: 4,
                selector: 13,
                payload: vec![1, 3, 2, 0]
            }
        ));
        // Right unit, selector the descriptor does not advertise.
        assert!(!control_is_documented(
            &asus,
            &EmitterControl {
                unit: 14,
                selector: 10,
                payload: vec![0; 8]
            }
        ));
        // A unit that exists on the OTHER VideoControl function of the same
        // physical camera. Unit numbers are not addresses.
        assert!(!control_is_documented(
            &asus,
            &EmitterControl {
                unit: 7,
                selector: 6,
                payload: vec![1]
            }
        ));
    }

    #[test]
    fn enable_honors_off_env_and_config_precedence() {
        const DEV: &str = "/dev/irlume-test-missing";
        let _g = env_guard();
        let dir = std::env::temp_dir().join(format!("irlume-emitter-en-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Point the conf away from any real /var/lib/irlume install.
        std::env::set_var("IRLUME_IR_EMITTER_CONF", dir.join("none.conf"));
        let f = non_uvc_fd();
        use std::os::fd::AsRawFd;
        let fd = f.as_raw_fd();

        // `off`/`none` disable before any control lookup or ioctl.
        std::env::set_var("IRLUME_IR_EMITTER", "off");
        assert!(!enable(fd, "ASUS", DEV));
        std::env::set_var("IRLUME_IR_EMITTER", "none");
        assert!(!enable(fd, "ASUS", DEV));
        // A valid env control is parsed, but SET_CUR on a non-UVC fd fails.
        std::env::set_var("IRLUME_IR_EMITTER", "14:6:1,3,2");
        assert!(!enable(fd, "whatever", DEV));
        std::env::remove_var("IRLUME_IR_EMITTER");
        // The card string is no longer consulted at all; identity comes from
        // the USB IDs, and DEV does not exist, so nothing is applied.
        assert!(!enable(fd, "Some Unknown Cam", DEV));
        // A table entry now requires the USB identity to match AND the
        // descriptor to confirm the unit, neither of which a fake path offers.
        assert!(!enable(fd, "ASUS", DEV));
        // A persisted control naming an undocumented unit is refused: this is
        // the migration path that stops pre-0.7.1 configs from writing.
        save_conf(
            &identity(0x3277, 0x0059),
            &EmitterControl {
                unit: 1,
                selector: 2,
                payload: vec![7],
            },
        )
        .unwrap();
        assert!(!enable(fd, "Some Unknown Cam", DEV));

        std::env::remove_var("IRLUME_IR_EMITTER_CONF");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- #159 safety properties -------------------------------------------

    /// A camera that has stopped answering must be distinguishable from one that
    /// simply does not implement a control. Collapsing the two is what let the
    /// old sweep keep writing to a dying camera.
    #[test]
    fn a_timeout_is_not_mistaken_for_an_unsupported_control() {
        assert_eq!(XuError::from_errno(libc::EPIPE), XuError::Unsupported);
        assert_eq!(XuError::from_errno(libc::EINVAL), XuError::Unsupported);
        assert_eq!(XuError::from_errno(libc::ENOENT), XuError::Unsupported);

        // ETIMEDOUT is the errno behind the -110 in the #159 report.
        assert_eq!(
            XuError::from_errno(libc::ETIMEDOUT),
            XuError::Unresponsive(libc::ETIMEDOUT)
        );
        for e in [libc::ENODEV, libc::EPROTO, libc::EILSEQ, libc::EIO] {
            assert_eq!(XuError::from_errno(e), XuError::Unresponsive(e));
        }
    }

    /// An errno nobody anticipated must be treated as dangerous, not as a
    /// harmless "unsupported". Getting this default backwards is how a new
    /// failure mode would silently become another sweep.
    #[test]
    fn an_unrecognised_errno_is_treated_as_dangerous() {
        assert_eq!(XuError::from_errno(0), XuError::Unresponsive(0));
        assert_eq!(XuError::from_errno(9999), XuError::Unresponsive(9999));
    }

    #[test]
    fn a_control_is_only_written_when_get_info_permits_it() {
        const GET: u8 = 1 << 0;
        const SET: u8 = 1 << 1;
        const AUTO_DISABLED: u8 = 1 << 2;
        const COMMIT_DISABLED: u8 = 1 << 5;

        assert!(info_allows_set(SET));
        assert!(info_allows_set(GET | SET));
        // Microsoft specifies GET_INFO = 3 for IR Torch.
        assert!(info_allows_set(3));

        assert!(
            !info_allows_set(GET),
            "read-only control must not be written"
        );
        assert!(!info_allows_set(0));
        assert!(!info_allows_set(SET | AUTO_DISABLED));
        assert!(!info_allows_set(SET | COMMIT_DISABLED));
    }

    /// The emitter path must refuse a camera whose descriptors it cannot read,
    /// rather than falling back to probing. This is the exact decision that
    /// separates the new code from the one that destroyed a camera.
    #[test]
    fn discovery_refuses_a_camera_with_no_microsoft_control_unit() {
        let _g = env_guard();
        let f = non_uvc_fd();
        let mut measure = || Some(0.0f32);
        // Interface 0 of the real ASUS camera: two vendor extension units and
        // no Microsoft one. Exactly the case the old code answered by writing
        // guessed payloads to both of them.
        let no_ms = crate::uvc_descriptor::CameraIdentity {
            descriptors: include_bytes!("../tests/fixtures/asus-3277-0059.descriptors").to_vec(),
            interface_number: 0,
            vid: 0x3277,
            pid: 0x0059,
            serial: Some("200901010001".into()),
            usb_devpath: "/devices/pci0000:00/0000:00:14.0/usb3/3-5".into(),
        };
        let err = discover(std::os::fd::AsRawFd::as_raw_fd(&f), &no_ms, &mut measure).unwrap_err();
        match err {
            DiscoveryError::NoMicrosoftXu { seen } => assert_eq!(seen, vec![4, 7]),
            other => panic!("expected NoMicrosoftXu, got {other:?}"),
        }
    }

    /// Every failure mode has to say what happened and what to do, because the
    /// user of this path is someone whose camera is not working.
    #[test]
    fn discovery_errors_explain_themselves() {
        let no_xu = DiscoveryError::NoMicrosoftXu { seen: vec![4, 7] };
        let s = no_xu.to_string();
        assert!(s.contains("[4, 7]"), "{s}");
        assert!(s.contains("IRLUME_IR_EMITTER"), "{s}");

        // A refusal is not a dead camera and must not be reported as one.
        let refused = DiscoveryError::Unresponsive {
            unit: 14,
            selector: 6,
            err: XuError::Unsupported,
        };
        let r = refused.to_string();
        assert!(r.contains("refused a request"), "{r}");
        assert!(!r.contains("stopped responding"), "{r}");

        let dead = DiscoveryError::Unresponsive {
            unit: 4,
            selector: 13,
            err: XuError::Unresponsive(libc::ETIMEDOUT),
        };
        let s = dead.to_string();
        assert!(s.contains("unit 4"), "{s}");
        assert!(s.contains("anything further"), "{s}");

        let stuck = DiscoveryError::RestoreFailed {
            unit: 4,
            selector: 13,
            err: XuError::Unsupported,
        };
        assert!(stuck.to_string().contains("could not be restored"));
    }

    // --- IR Torch value checking ------------------------------------------

    fn torch(mode: u32, value: u32) -> Vec<u8> {
        let mut v = mode.to_le_bytes().to_vec();
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    /// Microsoft's own example shape: OFF plus ON supported, default ON at a
    /// power inside the reported range.
    #[test]
    fn a_spec_conformant_ir_torch_default_is_accepted() {
        let min = torch(0, 10);
        let max = torch(0b011, 200); // D0 off + D1 on
        assert_eq!(
            ir_torch_default_is_usable(&torch(2, 120), &min, &max, &torch(0, 1)),
            Ok(())
        );

        // ALTERNATING, where the camera says it supports it.
        let max_alt = torch(0b101, 200); // D0 off + D2 alternating
        assert_eq!(
            ir_torch_default_is_usable(&torch(4, 200), &min, &max_alt, &torch(0, 1)),
            Ok(())
        );
    }

    #[test]
    fn an_ir_torch_default_that_would_not_turn_the_lamp_on_is_refused() {
        let min = torch(0, 10);
        let max = torch(0b011, 200);
        // OFF as a default. Writing it back could not light anything.
        assert!(ir_torch_default_is_usable(&torch(0, 100), &min, &max, &torch(0, 1)).is_err());
        // A mode the specification does not define.
        assert!(ir_torch_default_is_usable(&torch(3, 100), &min, &max, &torch(0, 1)).is_err());
        assert!(ir_torch_default_is_usable(&torch(255, 100), &min, &max, &torch(0, 1)).is_err());
    }

    /// The camera contradicting itself is the interesting case: it offers a
    /// default mode it also says it does not support.
    #[test]
    fn a_default_mode_the_camera_does_not_claim_is_refused() {
        let min = torch(0, 10);
        let only_on = torch(0b011, 200); // D0 + D1, no ALTERNATING
        assert!(ir_torch_default_is_usable(&torch(4, 100), &min, &only_on, &torch(0, 1)).is_err());

        // Capabilities without the mandatory OFF bit are malformed.
        let no_off = torch(0b010, 200);
        assert!(ir_torch_default_is_usable(&torch(2, 100), &min, &no_off, &torch(0, 1)).is_err());
    }

    #[test]
    fn an_out_of_range_or_inverted_power_is_refused() {
        let max = torch(0b011, 200);
        assert!(
            ir_torch_default_is_usable(&torch(2, 201), &torch(0, 10), &max, &torch(0, 1)).is_err()
        );
        assert!(
            ir_torch_default_is_usable(&torch(2, 5), &torch(0, 10), &max, &torch(0, 1)).is_err()
        );
        // min above max: the camera is not describing a usable range.
        assert!(
            ir_torch_default_is_usable(&torch(2, 100), &torch(0, 250), &max, &torch(0, 1)).is_err()
        );
    }

    /// GET_LEN for IR Torch is specified as 8. Anything else is not this
    /// control, whatever the descriptor claimed.
    #[test]
    fn an_ir_torch_payload_of_the_wrong_length_is_refused() {
        let min = torch(0, 10);
        let max = torch(0b011, 200);
        assert!(ir_torch_default_is_usable(&[0u8; 4], &min, &max, &torch(0, 1)).is_err());
        assert!(ir_torch_default_is_usable(&[0u8; 9], &min, &max, &torch(0, 1)).is_err());
        assert!(ir_torch_default_is_usable(&torch(2, 100), &[0u8; 2], &max, &torch(0, 1)).is_err());
        assert!(ir_torch_default_is_usable(&torch(2, 100), &min, &[], &torch(0, 1)).is_err());
    }

    /// Face Authentication deliberately gets no structural check: its layout is
    /// published only as figures, and inferring one is the failure mode this
    /// release exists to remove. It is written as the camera reported it, or
    /// not at all.
    #[test]
    fn face_authentication_is_not_subjected_to_ir_torch_rules() {
        assert_ne!(
            crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
            crate::uvc_descriptor::MSXU_IR_TORCH
        );
        // The validated 9-byte Hello payload would fail every IR Torch rule,
        // which is exactly why it is not run through them.
        let nine = vec![1u8, 3, 2, 0, 0, 0, 0, 0, 0];
        assert!(
            ir_torch_default_is_usable(&nine, &torch(0, 0), &torch(3, 9), &torch(0, 1)).is_err()
        );
    }

    /// Round 3 asked for these and the edit silently did not apply, so they get
    /// their own test: reserved capability bits, and a minimum whose mode field
    /// is not the zero the specification requires.
    #[test]
    fn ir_torch_capability_and_minimum_fields_are_checked() {
        let min = torch(0, 10);
        let max = torch(0b011, 200);
        assert_eq!(
            ir_torch_default_is_usable(&torch(2, 100), &min, &max, &torch(0, 1)),
            Ok(())
        );

        // A capability bitmap carrying bits outside D0 to D2.
        assert!(ir_torch_default_is_usable(
            &torch(2, 100),
            &min,
            &torch(0x8000_0003, 200),
            &torch(0, 1)
        )
        .is_err());
        assert!(ir_torch_default_is_usable(
            &torch(2, 100),
            &min,
            &torch(0b1011, 200),
            &torch(0, 1)
        )
        .is_err());

        // GET_MIN's mode field is specified as zero.
        assert!(
            ir_torch_default_is_usable(&torch(2, 100), &torch(2, 10), &max, &torch(0, 1)).is_err()
        );
        assert!(
            ir_torch_default_is_usable(&torch(2, 100), &torch(1, 10), &max, &torch(0, 1)).is_err()
        );
    }

    // --- the IRLUME_IR_EMITTER override's gate (#179) ------------------------

    use OverrideSetting::{Absent, Disabled, Malformed};

    fn ctrl(unit: u8, selector: u8, payload: Vec<u8>) -> EmitterControl {
        EmitterControl {
            unit,
            selector,
            payload,
        }
    }

    /// The override may address a VENDOR unit, which is the whole reason it
    /// exists: the message that advertises it prints when a camera has no
    /// Microsoft unit at all. What it may not address is a unit or selector the
    /// camera never published.
    #[test]
    fn the_override_accepts_a_vendor_unit_but_only_one_the_camera_publishes() {
        let asus = identity(0x3277, 0x0059);

        // Unit 10 on this camera's VideoControl interface is a vendor unit, not
        // Microsoft's, and its descriptor advertises selectors 10 and 11.
        let vendor = ctrl(10, 11, vec![1]);
        assert_eq!(override_is_published(&asus, &vendor), Ok(()));
        // The automatic paths still refuse it, and that difference is the point:
        // a vendor control is reachable only when a person names it.
        assert!(
            !control_is_documented(&asus, &vendor),
            "a vendor unit must never be written without someone naming it"
        );

        // Microsoft's own unit is equally acceptable when named.
        assert_eq!(
            override_is_published(&asus, &ctrl(14, 6, vec![1; 9])),
            Ok(())
        );

        // A selector that unit does not advertise. Unit 14 publishes 6 and 9;
        // IR Torch (10) is not implemented on this module.
        assert_eq!(
            override_is_published(&asus, &ctrl(14, 10, vec![0; 4])),
            Err(OverrideRefusal::NotAdvertised {
                unit: 14,
                selector: 10
            })
        );

        // Unit 4 exists on the OTHER VideoControl function of the same physical
        // camera and advertises selector 10 there. Unit numbers are not
        // addresses, so from this interface it does not exist.
        assert_eq!(
            override_is_published(&asus, &ctrl(4, 10, vec![0; 4])),
            Err(OverrideRefusal::NoSuchUnit {
                unit: 4,
                seen: vec![11, 10, 14]
            })
        );

        // The shape someone types when they are guessing.
        assert!(matches!(
            override_is_published(&asus, &ctrl(3, 1, vec![255])),
            Err(OverrideRefusal::NoSuchUnit { .. })
        ));
    }

    /// The descriptor gate runs BEFORE the file descriptor is touched.
    ///
    /// Proved with an fd that cannot serve any ioctl: -1 is never a valid
    /// descriptor, so if `get_info` ran first this would come back `Unreadable`.
    /// Getting `NoSuchUnit` out of it is the ordering, not a restatement of the
    /// previous test. This is the property #179 was about: the write used to
    /// happen with no descriptor read at all.
    #[test]
    fn an_unpublished_unit_is_refused_without_reaching_the_device() {
        let _g = env_guard();
        let asus = identity(0x3277, 0x0059);
        assert_eq!(
            check_and_apply_override(-1, &asus, &ctrl(3, 1, vec![255])),
            Err(OverrideRefusal::NoSuchUnit {
                unit: 3,
                seen: vec![11, 10, 14]
            })
        );
        assert_eq!(
            check_and_apply_override(-1, &asus, &ctrl(14, 10, vec![0; 4])),
            Err(OverrideRefusal::NotAdvertised {
                unit: 14,
                selector: 10
            })
        );
    }

    /// A published control on a descriptor that answers nothing is refused at
    /// the first query, so no `SET_CUR` is reached.
    ///
    /// `Unreadable` is only constructible before the write: the write is the
    /// last expression in the function and its result is an `Ok`. So this
    /// verdict IS the proof that nothing was sent.
    #[test]
    fn a_camera_that_will_not_answer_is_not_written_to() {
        let _g = env_guard();
        let asus = identity(0x3277, 0x0059);
        let f = non_uvc_fd();
        use std::os::fd::AsRawFd;
        assert!(matches!(
            check_and_apply_override(
                f.as_raw_fd(),
                &asus,
                &ctrl(14, 6, vec![1, 3, 2, 0, 0, 0, 0, 0, 0])
            ),
            Err(OverrideRefusal::Unreadable {
                unit: 14,
                selector: 6,
                ..
            })
        ));
    }

    /// **The regression test for #179 itself.**
    ///
    /// A set override on a device whose descriptors cannot be read must send
    /// nothing. The old code applied the override at the top of `enable`, before
    /// `identity_from_fd` was ever called, so this same call wrote nine bytes to
    /// unit 14 selector 6 of whatever `/dev/null` happened to be.
    ///
    /// Asserted on the write COUNT, not on the return value: both versions
    /// return false here, one because it refused and one because the device
    /// rejected what it was sent. Reintroducing the early return makes this fail.
    ///
    /// The counter is process-global; `env_guard` serialises this against the
    /// other tests that could reach a write, and the assertion is on the delta.
    #[test]
    fn a_set_override_writes_nothing_when_the_descriptor_cannot_be_read() {
        use std::os::fd::AsRawFd;
        use std::sync::atomic::Ordering::SeqCst;

        let _g = env_guard();
        let f = non_uvc_fd();
        std::env::set_var("IRLUME_IR_EMITTER", "14:6:1,3,2,0,0,0,0,0,0");
        let before = writes_attempted().load(SeqCst);
        let applied = enable(f.as_raw_fd(), "ASUS FHD webcam", "/dev/irlume-test-missing");
        let sent = writes_attempted().load(SeqCst) - before;
        std::env::remove_var("IRLUME_IR_EMITTER");

        assert!(!applied);
        assert_eq!(
            sent, 0,
            "an override was sent to a device whose descriptors were never read"
        );
    }

    /// A remembered success is not repeated back as an answer about the camera.
    ///
    /// Found in review of this PR. "We wrote this once" and "the control holds
    /// this now" stop being the same statement when a camera resets or
    /// re-enumerates onto the same device number with the same USB id, and
    /// callers use this answer to decide whether to tell the user their
    /// infrared is dark. The record still bounds the writes; it is just not
    /// consulted for present state.
    ///
    /// Asserted by seeding a success and then asking on a device that cannot
    /// answer `GET_CUR`. Returning the cached `true` fails this.
    #[test]
    fn a_remembered_success_is_rechecked_against_the_camera() {
        use std::os::fd::AsRawFd;
        use std::sync::atomic::Ordering::SeqCst;

        let _g = env_guard();
        let f = non_uvc_fd();
        let id = identity(0x3277, 0x0059);
        // Coordinates this test alone uses: the record is process-global.
        let c = ctrl(20, 21, vec![1, 3, 2]);
        let key = override_key(f.as_raw_fd(), &id, &c).unwrap();
        override_memo().lock().unwrap().insert(
            key,
            OverrideDecision {
                payload: c.payload.clone(),
                applied: true,
            },
        );

        let before = writes_attempted().load(SeqCst);
        let answer = apply_override(f.as_raw_fd(), &id, &c);
        assert_eq!(
            writes_attempted().load(SeqCst),
            before,
            "re-checking must not write"
        );
        assert!(
            !answer,
            "a camera that cannot answer GET_CUR must not be reported as lit \
             on the strength of an earlier write"
        );
    }

    /// A variable that is SET but unusable must not read as "not set".
    ///
    /// Found in review of this PR, and it is defect pattern 3: `.ok()` and a
    /// failed parse both became `None`, and `None` meant "carry on to the
    /// built-in table". So typing one bad byte into an override intended to
    /// REPLACE the built-in payload made irlume write the built-in payload
    /// instead, every eighth frame, silently. Setting the variable is consent to
    /// the control named in it and to nothing else.
    #[test]
    fn a_malformed_override_is_not_the_same_as_no_override() {
        use std::env::VarError;
        let set = |s: &str| override_setting(Ok(s.to_string()));

        assert_eq!(override_setting(Err(VarError::NotPresent)), Absent);
        assert_eq!(set("off"), Disabled);
        assert_eq!(set("  none  "), Disabled);
        assert_eq!(set(""), Absent, "an empty value is someone clearing it");
        assert_eq!(
            set("14:6:1,3,2"),
            OverrideSetting::Control(ctrl(14, 6, vec![1, 3, 2]))
        );

        // The exact shape from the review: one unparseable byte in a payload
        // meant to replace the N930W's built-in nine.
        for bad in [
            "4:6:1,3,bad,0,0,0,0,0,0",
            "4:6:",
            "4:6",
            "garbage",
            "4:6:1:2",
            "999:6:1",
        ] {
            assert!(
                matches!(set(bad), Malformed(_)),
                "{bad:?} must refuse, not fall through to the built-in table"
            );
        }
        // Set, and not text at all.
        assert!(matches!(
            override_setting(Err(VarError::NotUnicode("x".into()))),
            Malformed(_)
        ));
    }

    /// The record has to name the same object the check did, and the bytes it
    /// was about.
    ///
    /// Both found in review of this PR. The key was built from the caller's
    /// `device` string, so two spellings of one open camera were two records and
    /// two permitted writes; and it omitted the payload, so changing
    /// `IRLUME_IR_EMITTER` to different bytes at the same control returned the
    /// cached `true` for a value that was never length-checked or written.
    #[test]
    fn the_record_identifies_the_open_device_and_the_bytes_it_decided() {
        use std::os::fd::AsRawFd;
        let id = identity(0x3277, 0x0059);
        let a = non_uvc_fd();
        let b = non_uvc_fd();

        // Two OPENS of the same device node. The path string is not consulted at
        // all now, and both fds carry the same st_rdev, so they are one record.
        let ka = override_key(a.as_raw_fd(), &id, &ctrl(14, 6, vec![1; 9])).unwrap();
        let kb = override_key(b.as_raw_fd(), &id, &ctrl(14, 6, vec![1; 9])).unwrap();
        assert_eq!(ka, kb, "the same device reached twice must be one record");

        // Two DIFFERENT devices must not share a record, or one camera's
        // decision would suppress the check on another. This is the assertion
        // that fails if the key stops coming from the fd: with the old
        // caller-string key, one path spelling shared between two cameras
        // aliased them, and a constant would alias every camera.
        let other = std::fs::File::open("/dev/zero").expect("open /dev/zero");
        let kz = override_key(other.as_raw_fd(), &id, &ctrl(14, 6, vec![1; 9])).unwrap();
        assert_ne!(
            ka, kz,
            "two different devices were recorded as the same camera"
        );

        // A different control on the same camera is a different record.
        let kc = override_key(a.as_raw_fd(), &id, &ctrl(14, 9, vec![1; 9])).unwrap();
        assert_ne!(ka, kc);

        // The payload is NOT part of the key: the same control decided for
        // different bytes must find the earlier decision, so it can refuse
        // rather than silently report the old answer for new bytes.
        let kd = override_key(a.as_raw_fd(), &id, &ctrl(14, 6, vec![2; 9])).unwrap();
        assert_eq!(ka, kd);

        // A closed fd cannot be identified, and that refuses rather than
        // guessing a key that would let a write through unrecorded.
        assert!(override_key(-1, &id, &ctrl(14, 6, vec![1; 9])).is_err());
    }

    /// Asking for different bytes at a control already decided this run is
    /// refused, not answered from the record.
    ///
    /// The case that matters is a recorded SUCCESS: reusing it would tell the
    /// caller the bytes it just asked for are active on a camera holding
    /// different ones, having never length-checked them. It is asserted here
    /// rather than through `apply_override` because with no camera attached
    /// every path through that function returns false, so the stale answer and
    /// the correct refusal would be indistinguishable.
    #[test]
    fn changing_the_override_does_not_report_the_earlier_answer() {
        let applied = OverrideDecision {
            payload: vec![1, 3, 2],
            applied: true,
        };
        assert_eq!(reuse(Some(&applied), &[1, 3, 2]), Reuse::Answer(true));
        assert_eq!(reuse(Some(&applied), &[1, 3, 1]), Reuse::RefuseChanged);
        // A shorter prefix is not the same bytes either.
        assert_eq!(reuse(Some(&applied), &[1, 3]), Reuse::RefuseChanged);
        assert_eq!(reuse(None, &[1, 3, 2]), Reuse::Decide);

        // A recorded refusal is reused just as firmly: retrying it every capture
        // is what the limiter exists to stop.
        let refused = OverrideDecision {
            payload: vec![1, 3, 2],
            applied: false,
        };
        assert_eq!(reuse(Some(&refused), &[1, 3, 2]), Reuse::Answer(false));
    }

    /// "At most once per camera" has to survive two callers, or it describes
    /// only the happy path.
    ///
    /// The first version of this fix took the memo lock, dropped it, talked to
    /// the camera, then took it again to record the answer. Two threads could
    /// both miss and both write. Found in review of this PR; it is defect
    /// pattern 2, a check and its write being two moments.
    ///
    /// Asserted by stopping a caller INSIDE the gate and testing what is true
    /// while it is there: if the lock is held across the device access, no other
    /// thread can be in the same window. `try_lock` answers that with no
    /// scheduling assumption at all. Racing two real threads would not prove it,
    /// because the second thread losing the race is indistinguishable from the
    /// second thread being blocked.
    #[test]
    fn the_write_record_is_locked_across_the_device_access() {
        use std::sync::atomic::Ordering::SeqCst;

        let f = non_uvc_fd();
        let fd = {
            use std::os::fd::AsRawFd;
            f.as_raw_fd()
        };
        let parked = std::thread::spawn(move || {
            *test_park().armed.lock().unwrap() = Some(std::thread::current().id());
            // Through `apply_override`, because the lock it takes is the thing
            // under test. Unit 30 is not published, so the gate refuses before
            // any ioctl; what matters is only that the caller got INSIDE.
            // These coordinates are this test's alone: the memo is global, and a
            // control another test already decided would return from the record
            // without entering the gate at all.
            apply_override(fd, &identity(0x3277, 0x0059), &ctrl(30, 31, vec![255]))
        });

        // Bounded, because a caller that never arrives is a failure to report
        // rather than a suite that hangs with no output.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !test_park().reached.load(SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the parked caller never entered the gate"
            );
            std::thread::yield_now();
        }
        // The parked caller is between the lookup and the record. Anyone else
        // reaching `apply_override` right now must NOT be able to take the memo.
        let held = override_memo().try_lock().is_err();

        test_park().release.store(true, SeqCst);
        let _ = parked.join();
        *test_park().armed.lock().unwrap() = None;
        test_park().reached.store(false, SeqCst);
        test_park().release.store(false, SeqCst);

        assert!(
            held,
            "the memo was free while a caller was talking to the camera, \
             so a second caller could reach the same write"
        );
    }

    /// Every refusal has to name the control, or the person who set the variable
    /// cannot tell which of their two numbers the camera disputed.
    #[test]
    fn every_refusal_says_which_control_and_why() {
        for (refusal, must_contain) in [
            (
                OverrideRefusal::NoSuchUnit {
                    unit: 3,
                    seen: vec![11, 10, 14],
                },
                vec!["3", "11, 10, 14"],
            ),
            (
                OverrideRefusal::NotAdvertised {
                    unit: 14,
                    selector: 10,
                },
                vec!["14", "10", "advertise"],
            ),
            (
                OverrideRefusal::WriteNotAccepted {
                    unit: 14,
                    selector: 6,
                    info: 0x01,
                },
                vec!["14", "6", "0x01"],
            ),
            (
                OverrideRefusal::WrongLength {
                    unit: 14,
                    selector: 6,
                    wants: 9,
                    given: 3,
                },
                vec!["14", "6", "9 bytes", "3 given"],
            ),
            (
                OverrideRefusal::Unreadable {
                    unit: 14,
                    selector: 6,
                    err: XuError::Unresponsive(libc::ETIMEDOUT),
                },
                vec!["14", "6", "did not answer"],
            ),
        ] {
            let msg = refusal.to_string();
            for needle in must_contain {
                assert!(
                    msg.contains(needle),
                    "{refusal:?} message missing {needle:?}: {msg}"
                );
            }
        }
    }

    /// The onboarding hint prints when IR is dark, which is when someone is most
    /// willing to try numbers, so it has to say the bytes reach firmware.
    #[test]
    fn the_hint_that_offers_the_override_says_what_it_writes_to() {
        let msg = DiscoveryError::NoMicrosoftXu { seen: vec![1, 2] }.to_string();
        assert!(msg.contains("IRLUME_IR_EMITTER"), "{msg}");
        assert!(msg.contains("firmware"), "{msg}");
        assert!(msg.contains("#159"), "{msg}");
    }

    // --- Face Authentication derivation ------------------------------------

    /// The measurement this is built on. Both cameras report exactly these
    /// bytes, and both were separately validated to light their emitter with
    /// 01 03 02. The derivation has to reproduce that or it is not usable.
    #[test]
    fn the_derivation_reproduces_the_payload_validated_on_both_cameras() {
        let def = vec![1, 3, 1, 0, 0, 0, 0, 0, 0]; // D0, general purpose
        let max = vec![1, 3, 3, 0, 0, 0, 0, 0, 0]; // D0 | D1 supported
        let validated = vec![1, 3, 2, 0, 0, 0, 0, 0, 0]; // D1, face auth
        assert_eq!(face_auth_payload(&def, &max), Ok(validated.clone()));

        // And it is exactly what the built-in table carries for both.
        assert_eq!(known_control(0x3277, 0x0059).unwrap().payload, validated);
        assert_eq!(known_control(0x3443, 0xc803).unwrap().payload, validated);
    }

    /// D1 and D2 are not two flavours of the same thing. D1 alternates the
    /// illuminator across frames, which is what the capture path reads; D2
    /// returns ambient-subtracted images. An interface offering only D2 is
    /// refused rather than driven into a mode this code cannot interpret.
    #[test]
    fn a_background_subtraction_interface_is_refused_not_selected() {
        let def = vec![1, 3, 1, 0, 0, 0, 0, 0, 0];
        let max_d2_only = [1, 3, 0b101, 0, 0, 0, 0, 0, 0]; // D0 | D2
        let err = face_auth_payload(&def, &max_d2_only).unwrap_err();
        assert!(err.contains("background subtraction"), "{err}");
        assert!(err.contains("D1"), "{err}");
    }

    #[test]
    fn several_interfaces_advertising_alternating_illumination_are_all_selected() {
        let def = vec![2, 3, 1, 5, 1, 0, 0, 0, 0];
        let max = [2, 3, 0b011, 5, 0b011, 0, 0, 0, 0];
        assert_eq!(
            face_auth_payload(&def, &max),
            Ok(vec![2, 3, 0b010, 5, 0b010, 0, 0, 0, 0])
        );
    }

    /// Every structural contradiction is a refusal. A camera that has not
    /// clearly said what it accepts gets nothing written to it.
    #[test]
    fn a_camera_contradicting_itself_gets_nothing_written() {
        let def = vec![1, 3, 1, 0, 0, 0, 0, 0, 0];

        // Both face-auth modes at once: the specification forbids it.
        assert!(face_auth_payload(&def, &[1, 3, 0b111, 0, 0, 0, 0, 0, 0]).is_err());
        // Neither face-auth mode, yet listed in GET_MAX.
        assert!(face_auth_payload(&def, &[1, 3, 0b001, 0, 0, 0, 0, 0, 0]).is_err());
        // Undefined bits.
        assert!(face_auth_payload(&def, &[1, 3, 0b1011, 0, 0, 0, 0, 0, 0]).is_err());
        // No interfaces at all.
        assert!(face_auth_payload(&def, &[0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // More entries than the buffer can hold.
        assert!(face_auth_payload(&def, &[9, 3, 0b011, 0, 0, 0, 0, 0, 0]).is_err());
        // The same interface twice.
        let dup = vec![2, 3, 0b011, 3, 0b011, 0, 0, 0, 0];
        assert!(face_auth_payload(&[2, 3, 1, 3, 1, 0, 0, 0, 0], &dup).is_err());
        // Default and maximum describing different-sized controls.
        assert!(face_auth_payload(&[1, 3, 1], &[1, 3, 3, 0]).is_err());
        // A length that cannot hold whole entries.
        assert!(face_auth_payload(&[1, 3], &[1, 3]).is_err());
    }

    /// Nothing is invented: the output names only interfaces the camera listed,
    /// carries only bits the camera advertised, and is zero elsewhere.
    #[test]
    fn the_derivation_never_introduces_an_interface_the_camera_did_not_list() {
        let def = vec![1, 3, 1, 0, 0, 0, 0, 0, 0];
        let max = vec![1, 3, 0b011, 0, 0, 0, 0, 0, 0];
        let out = face_auth_payload(&def, &max).unwrap();
        assert_eq!(out.len(), max.len());
        assert_eq!(out[0], max[0], "entry count comes from the camera");
        assert_eq!(out[1], max[1], "interface number comes from the camera");
        assert_eq!(
            out[2] & !max[2],
            0,
            "no bit is set that the camera did not offer"
        );
        assert!(out[3..].iter().all(|&b| b == 0), "unused bytes are zeroed");
    }

    /// Round 5: GET_DEF was never checked against GET_MAX, so a control whose
    /// two answers described different interfaces still produced a payload.
    #[test]
    fn a_default_that_contradicts_the_maximum_is_refused() {
        let max = [1, 3, 0b011, 0, 0, 0, 0, 0, 0];

        // Default names a different interface than the maximum listed.
        assert!(face_auth_payload(&[1, 99, 1, 0, 0, 0, 0, 0, 0], &max).is_err());
        // Default lists a different number of interfaces.
        assert!(face_auth_payload(&[0, 0, 0, 0, 0, 0, 0, 0, 0], &max).is_err());
        assert!(face_auth_payload(&[2, 3, 1, 5, 1, 0, 0, 0, 0], &max).is_err());
        // Default carries a mode that is not one defined mode.
        assert!(face_auth_payload(&[1, 3, 0b011, 0, 0, 0, 0, 0, 0], &max).is_err());
        assert!(face_auth_payload(&[1, 3, 0b1000, 0, 0, 0, 0, 0, 0], &max).is_err());
        // Data past the interfaces either answer listed.
        assert!(face_auth_payload(&[1, 3, 1, 0, 0, 7, 0, 0, 0], &max).is_err());
        assert!(face_auth_payload(
            &[1, 3, 1, 0, 0, 0, 0, 0, 0],
            &[1, 3, 0b011, 0, 9, 0, 0, 0, 0]
        )
        .is_err());

        // The real pair from both cameras still works.
        assert_eq!(
            face_auth_payload(&[1, 3, 1, 0, 0, 0, 0, 0, 0], &max),
            Ok(vec![1, 3, 2, 0, 0, 0, 0, 0, 0])
        );
    }

    /// Round 5: GET_RES is mandatory and constrains the range. A control whose
    /// step is zero, or whose range or default does not sit on it, is
    /// contradicting its own definition.
    #[test]
    fn ir_torch_resolution_is_validated() {
        let min = torch(0, 10);
        let max = torch(0b011, 210);
        let res = torch(0, 10); // span 200 divides by 10; default 110 is on grid
        assert_eq!(
            ir_torch_default_is_usable(&torch(2, 110), &min, &max, &res),
            Ok(())
        );

        // A zero step is forbidden outright.
        assert!(ir_torch_default_is_usable(&torch(2, 110), &min, &max, &torch(0, 0)).is_err());
        // The resolution's mode field is specified as zero.
        assert!(ir_torch_default_is_usable(&torch(2, 110), &min, &max, &torch(2, 10)).is_err());
        // A span that does not divide evenly by the step.
        assert!(ir_torch_default_is_usable(&torch(2, 110), &min, &max, &torch(0, 30)).is_err());
        // A default that does not sit on the grid.
        assert!(ir_torch_default_is_usable(&torch(2, 115), &min, &max, &res).is_err());
        // A resolution of the wrong length.
        assert!(ir_torch_default_is_usable(&torch(2, 110), &min, &max, &[0u8; 4]).is_err());
    }

    /// Setup used to require the lit frame to clear an absolute brightness
    /// floor, so a working control failed in a dim room. Discovery asks whether
    /// the write changed the image; whether the image is bright enough to
    /// authenticate against is a separate question asked elsewhere.
    #[test]
    fn discovery_measures_change_not_absolute_brightness() {
        // A dim room: emitter off is nearly black, emitter on is well under the
        // authentication floor, but the control plainly did something.
        let baseline = 2.0f32;
        let lit = 25.0f32;
        assert!(lit < IR_LIT_MEAN, "this is the case that used to fail");
        assert!(
            lit >= baseline + AUTOCONF_MIN_LIFT,
            "a clear lift is what discovery is looking for"
        );

        // Ambient infrared with no real change must still be rejected.
        let bright_ambient = 120.0f32;
        assert!(bright_ambient + 5.0 < bright_ambient + AUTOCONF_MIN_LIFT);
    }

    // --- round 6 ---------------------------------------------------------

    /// The critical one. IR Torch's default is required by the specification to
    /// be an ACTIVE mode, and this file enforces that. An earlier version wrote
    /// that same default to establish an "off" baseline, so it switched the lamp
    /// on, called the result off, and then wrote the identical value again
    /// expecting a change. Discovery could never have succeeded on IR Torch.
    #[test]
    fn ir_torch_default_is_an_active_mode_so_it_cannot_be_an_off_state() {
        let min = torch(0, 10);
        let max = torch(0b011, 200);
        let res = torch(0, 10);

        // The validator only accepts an active default...
        assert_eq!(
            ir_torch_default_is_usable(&torch(2, 100), &min, &max, &res),
            Ok(())
        );
        // ...and rejects an off one outright.
        assert!(ir_torch_default_is_usable(&torch(0, 100), &min, &max, &res).is_err());
        assert!(ir_torch_default_is_usable(&torch(1, 100), &min, &max, &res).is_err());

        // Which is exactly why nothing may treat GET_DEF as "off": for this
        // control the specification guarantees the opposite.
    }

    /// A control already set to the value setup would apply teaches nothing by
    /// being written again, and the old code read that as "the control does not
    /// work". Observed on hardware as "before 50, after 52".
    #[test]
    fn a_control_already_at_the_target_value_is_reported_not_retried() {
        let already = vec![1u8, 3, 2, 0, 0, 0, 0, 0, 0];
        let wanted = face_auth_payload(
            &[1, 3, 1, 0, 0, 0, 0, 0, 0],
            &[1, 3, 0b011, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(
            already, wanted,
            "the state a working camera is already in is what setup would write"
        );
    }
}
