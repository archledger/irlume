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
    // Through `state_dir()`, like `emitter_journal::store_dir` and
    // `stream_record`, not the literal. This file decides whether the IR
    // emitter lights at login, and a sandboxed `ir-setup` set up exactly as
    // docs/INTEGRATION.md documents (SOCKET, STATE, KEYRING, RECOVERY,
    // TEMPLATE_KEY) would have written straight through to the live one. Same
    // split-resolution shape that emptied a real machine's template keys.
    std::env::var("IRLUME_IR_EMITTER_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| irlume_common::state_dir().join("ir_emitter.conf"))
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
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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

/// Whether `IRLUME_IR_EMITTER` is set to `off`/`none`: the user's explicit
/// "drive nothing". The dark-frame diagnosis silences itself on this (#185);
/// the old hint printed anyway, naming the very variable that was already set.
pub(crate) fn emitter_explicitly_disabled() -> bool {
    matches!(
        override_setting(std::env::var("IRLUME_IR_EMITTER")),
        OverrideSetting::Disabled
    )
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

/// Raw, guard-free extension-unit access, for TEST TOOLING ONLY.
///
/// Hidden from the documented API on purpose. Everything else in this module
/// wraps a write in evidence and an undo path; these wrappers exist so
/// `examples/xu_set.rs` and the hardware harnesses can put a control INTO a
/// state — parking it at its device default before a discovery run, or
/// planting another writer's value for the #188 leftover tests. Killing a
/// daemon mid-capture cannot do either: apply and restore are microseconds
/// apart, and a shell cannot interpose (measured on the NexiGo, pt192).
///
/// The bytes are the caller's. Nothing here validates a payload, and #159 is
/// what an invented one can cost; the only safe values are ones the device
/// itself reported (`GET_DEF`, `GET_CUR`).
#[doc(hidden)]
pub mod raw {
    use super::c_int;

    /// `GET_LEN` for a control, as the device reports it.
    pub fn get_len(fd: c_int, unit: u8, selector: u8) -> Result<usize, String> {
        super::get_len(fd, unit, selector).map_err(|e| e.to_string())
    }

    /// One sized read of `GET_CUR`.
    pub fn get_cur(fd: c_int, unit: u8, selector: u8, len: usize) -> Result<Vec<u8>, String> {
        super::get_cur(fd, unit, selector, len).map_err(|e| e.to_string())
    }

    /// One sized read of `GET_DEF`: the device's own parking value.
    pub fn get_def(fd: c_int, unit: u8, selector: u8, len: usize) -> Result<Vec<u8>, String> {
        super::get_of(fd, unit, selector, super::UVC_GET_DEF, len).map_err(|e| e.to_string())
    }

    /// ONE `SET_CUR`, owned by no guard, recorded in no journal.
    pub fn set_cur(fd: c_int, unit: u8, selector: u8, payload: &[u8]) -> Result<(), String> {
        super::set_cur(fd, unit, selector, payload).map_err(|e| e.to_string())
    }
}

/// What a capture write did, and what its one read answered.
///
/// When `outcome` is `Wrote`, `current` is what the write DISPLACED, read on
/// the same pass that decided to write, and it is the only value a stream
/// guard may put back.
#[derive(Debug)]
struct CaptureWrite {
    outcome: Applied,
    /// What `GET_CUR` answered immediately before the write decision.
    current: Vec<u8>,
    /// The leftover record covering the write (#188), on disk from just
    /// before the `SET_CUR` and confirmed after it. Present only when the
    /// outcome is `Wrote` and the store took both steps; carried to the
    /// stream guard, which resolves it when the change is no longer
    /// outstanding.
    record: Option<crate::stream_record::StreamRecord>,
    /// The per-camera stream lock, still held, in two cases: `AlreadyHeld`,
    /// where the caller needs it to CLAIM a crash leftover; and a `Wrote`
    /// whose record could not be saved, where the lock must outlive the
    /// bookkeeping trouble or a second irlume takes the camera mid-stream
    /// (review round 5). A recorded write's lock lives inside its record.
    lock: Option<crate::stream_record::StreamLock>,
}

impl CaptureWrite {
    /// Nothing was read and nothing was sent: a check refused before the
    /// control was consulted at all.
    fn refused() -> Self {
        CaptureWrite {
            outcome: Applied::Nothing,
            current: Vec::new(),
            record: None,
            lock: None,
        }
    }
}

/// The one tail every capture write goes through: read what the control holds,
/// and write only when it differs.
///
/// The read and the write decision are ONE pass, which is the point. `enable`
/// used to read `GET_CUR` itself, record that as the guard's restore value, and
/// then let the apply path read `GET_CUR` a second time to decide whether to
/// write. Another client landing between the two reads got the FIRST, stale
/// value restored over its own when the stream ended (#190). Here the value the
/// guard records is the value the write displaced, because they are the same
/// read.
///
/// The restore value used to be `GET_DEF`, on the reading that Microsoft's
/// sequence ends by "unsetting" the control. That destroys a non-default mode
/// another program deliberately established; putting back what was displaced
/// restores a control found at its default to its default, and a control found
/// anywhere else to where its owner left it.
///
/// A `SET_CUR` the camera rejects is `Nothing`, not an error: the callers that
/// used to propagate it discarded the detail, and the override memo records it
/// as a refusal either way. A `GET_CUR` that cannot be read IS an error — with
/// no answer there is no restore value, so nothing may be written.
///
/// Around the write sits the leftover record (#188), in two phases. The
/// PREPARED record goes on disk before the `SET_CUR`, because recording after
/// the write leaves a crash window with an unrecorded write in it; it is
/// rewritten as APPLIED once the camera accepts, because a record published
/// before a write that never happened must not authorise a claim — the value
/// it matches could be another program's later, deliberate choice. Both steps
/// happen under the per-camera stream lock, taken here BEFORE the read so the
/// value recorded as displaced is the one read under the same exclusion that
/// covers the write.
///
/// `current` is the last value THIS PROCESS observed before its `SET_CUR`.
/// UVC exposes GET_CUR and SET_CUR as separate requests with no
/// compare-and-swap, so the lock serialises irlume's own writers only; a
/// non-cooperating client can still move the control inside the window, and
/// its value would be overwritten and not restored. That window cannot be
/// closed from software on this interface.
///
/// Recording is BEST-EFFORT, in the opposite direction from the #183 journal,
/// and deliberately: a discovery write is exploratory bytes nobody can
/// re-derive, so an unwritable journal refuses the write; this record is
/// crash bookkeeping for a documented mode derived from the camera itself,
/// and refusing here would turn a full store, a read-only state directory or
/// a busy lock into IR authentication going dark. The cost of proceeding
/// unrecorded is that a kill mid-stream leaves a leftover no later session
/// can claim, which is exactly the pre-#188 status quo.
fn write_if_different(
    fd: c_int,
    unit: u8,
    selector: u8,
    len: usize,
    wanted: &[u8],
    id: &crate::uvc_descriptor::CameraIdentity,
) -> XuResult<CaptureWrite> {
    let lock = match crate::stream_record::acquire(id) {
        Ok(lock) => Some(lock),
        // A LIVE irlume guard owns this camera. Writing anyway — even
        // unrecorded — is what review round 4 caught: the owner's restore
        // would read the newcomer's bytes as "somebody else's", discard the
        // only record, and the newcomer's own restore would then put the
        // OWNER'S value back instead of the original. Nothing is sent at
        // all; the control keeps whatever the live owner is doing with it.
        Err(crate::stream_record::AcquireError::Busy) => {
            eprintln!(
                "irlume: not driving unit{unit}/sel{selector}: another live irlume stream \
                 owns this camera's emitter"
            );
            return Ok(CaptureWrite::refused());
        }
        // Machine trouble, nobody contesting: proceed without bookkeeping,
        // the same degradation as an unwritable record.
        Err(crate::stream_record::AcquireError::Unavailable(why)) => {
            eprintln!(
                "irlume: cannot lock unit{unit}/sel{selector}'s emitter bookkeeping ({why}); \
                 driving the emitter without crash recovery"
            );
            None
        }
    };
    let current = get_cur(fd, unit, selector, len)?;
    if current == *wanted {
        // Said distinctly from `Wrote` because the two diverge at stream end:
        // these bytes are another writer's state, and a guard armed here would
        // end the stream by writing over them. The lock rides along so the
        // caller can ask whether a stream record marks them as irlume's own.
        return Ok(CaptureWrite {
            outcome: Applied::AlreadyHeld,
            current,
            record: None,
            lock,
        });
    }
    let (record, bare_lock) = match lock {
        Some(lock) => {
            match crate::stream_record::save(lock, id, unit, selector, wanted, &current) {
                Ok(record) => (Some(record), None),
                // An applied record for a change that may still be live sits
                // at this camera's path. Writing would either destroy its
                // only recovery data (rename over it) or make an unrecorded
                // change on top of an unresolved one. Neither; nothing is
                // sent (review round 5).
                Err(crate::stream_record::SaveError::Outstanding {
                    unit: old_unit,
                    selector: old_selector,
                }) => {
                    eprintln!(
                        "irlume: not driving unit{unit}/sel{selector}: an unresolved record \
                         for unit{old_unit}/sel{old_selector} is outstanding on this camera \
                         and would be destroyed; a capture on that control resolves an \
                         applied record automatically, an unconfirmed one needs a look at \
                         the ir-emitter-stream store"
                    );
                    return Ok(CaptureWrite::refused());
                }
                // A record this build must not reason its way past: refuse
                // the write rather than either destroying it or stacking an
                // unrecorded change on top of it (review round 7).
                Err(crate::stream_record::SaveError::Protected { why }) => {
                    eprintln!("irlume: not driving unit{unit}/sel{selector}: {why}");
                    return Ok(CaptureWrite::refused());
                }
                // Machine trouble, nobody contesting. Proceed unrecorded, and
                // KEEP the lock: dropping it here handed the camera to a
                // second irlume mid-stream (review round 5).
                Err(crate::stream_record::SaveError::Unavailable { lock, why }) => {
                    eprintln!(
                        "irlume: cannot record this stream's write to unit{unit}/sel{selector} \
                         ({why}); driving the emitter anyway — a crash before the restore would \
                         leave the mode set with nothing marking it as irlume's"
                    );
                    (None, Some(lock))
                }
            }
        }
        // The lock itself is unavailable (reported at acquire); nobody
        // demonstrably contests the camera, so the write proceeds without
        // bookkeeping or exclusion — there is nothing left to hold.
        None => (None, None),
    };
    if set_cur(fd, unit, selector, wanted).is_ok() {
        // Confirm only after the camera accepted. A failure here leaves the
        // record PREPARED on disk — the write happened, but a crash from this
        // state leaves a leftover no claim will touch, which is reported and
        // is the safe direction — and the HANDLE is kept: it holds the stream
        // lock, which must live as long as the change does.
        let record = record.map(|r| match r.mark_applied() {
            Ok(r) => r,
            Err(e) => {
                let (r, why) = *e;
                eprintln!(
                    "irlume: the emitter write to unit{unit}/sel{selector} succeeded but its \
                     record could not be confirmed ({why}); a crash before the restore would \
                     leave a leftover no later session will claim"
                );
                r
            }
        });
        return Ok(CaptureWrite {
            outcome: Applied::Wrote,
            current,
            record,
            lock: bare_lock,
        });
    }
    // The write never landed, so the record describes a change that does not
    // exist; a leftover of it would refuse to claim anyway (prepared records
    // never authorise), but there is no reason to leave it lying around. A
    // failed removal is inert litter for the same reason, and no hardware
    // change exists for the lock to protect.
    if let Some(record) = record {
        if let Err(why) = record.resolve() {
            eprintln!("irlume: {why}");
        }
    }
    Ok(CaptureWrite {
        outcome: Applied::Nothing,
        current,
        record: None,
        lock: None,
    })
}

/// What one pass over a proc tree could establish about other holders of a
/// device node. `consumers` is only what the scan positively SAW; a blind spot
/// is a separate fact, never an empty list.
#[derive(Debug, Default, PartialEq)]
struct ConsumerScan {
    /// PIDs, with `comm`, of OTHER processes seen holding the node.
    consumers: Vec<(u32, String)>,
    /// At least one process refused inspection. Reading another process's
    /// `/proc/<pid>/fd` is gated by PTRACE_MODE_READ_FSCREDS, not by file
    /// permissions (proc_pid_fd(5), ptrace(2)); the packaged daemon keeps only
    /// CAP_DAC_OVERRIDE and CAP_FOWNER, and root without CAP_SYS_PTRACE does
    /// not pass that gate. Every cross-uid consumer in a desktop session
    /// therefore lands HERE, not in `consumers`. Collapsing this bit into "no
    /// consumer" is exactly how the scan failed open in production; closing
    /// the blind spot itself is #207.
    permission_denied: bool,
}

impl ConsumerScan {
    /// Only a consumer the scan actually saw stands the emitter down. A blind
    /// spot must not: under the packaged capability set the scan is blind to
    /// every cross-uid process, so treating `permission_denied` as a consumer
    /// would make every packaged capture inert and the emitter permanently
    /// dark. The caller reports the blind spot instead (#207 owns removing it).
    fn stands_down(&self) -> bool {
        !self.consumers.is_empty()
    }
}

/// Scan `proc_root` (`/proc` in production; a constructed tree in tests) for
/// other processes holding `dev` open.
///
/// The check is definitionally racy (a consumer can arrive one instant after
/// the scan), and that is acceptable for what it guards: honouring the sharing
/// contract for consumers that exist at decision time, not a mutual-exclusion
/// primitive (the kernel lock does that for irlume's own processes). Only a
/// PERMISSION denial marks the scan incomplete: a pid dir that vanished
/// mid-scan, an fd-less kernel thread, or a missing root are the ordinary
/// churn of /proc, and counting them as blind spots would put the degradation
/// warning on every scan on every machine.
fn foreign_consumers(proc_root: &std::path::Path, dev: &str, self_pid: u32) -> ConsumerScan {
    let mut scan = ConsumerScan::default();
    if dev.is_empty() {
        return scan;
    }
    let entries = match std::fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(err) => {
            scan.permission_denied = err.kind() == std::io::ErrorKind::PermissionDenied;
            return scan;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let fds = match std::fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    scan.permission_denied = true;
                }
                continue;
            }
        };
        let mut holds = false;
        for fd in fds {
            let Ok(fd) = fd else { continue };
            match std::fs::read_link(fd.path()) {
                Ok(target) if target.as_os_str() == std::ffi::OsStr::new(dev) => {
                    holds = true;
                    break;
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    scan.permission_denied = true;
                }
                Err(_) => {}
            }
        }
        if holds {
            let comm = std::fs::read_to_string(entry.path().join("comm"))
                .map(|c| c.trim().to_string())
                .unwrap_or_else(|_| "?".into());
            scan.consumers.push((pid, comm));
        }
    }
    scan
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
///
/// Takes the `Arc<Handle>` from `v4l::Device::handle()` rather than the raw fd
/// it wraps. The guard writes to this descriptor when the stream ends, and a
/// bare integer permitted the device to be dropped first, the number recycled
/// by the next `open`, and the restore delivered to whatever now holds it —
/// hardware-target substitution through the API of the type that exists to
/// prevent it (#189). Holding the `Arc` makes the descriptor outlive the guard
/// by construction.
pub fn enable(handle: std::sync::Arc<v4l::device::Handle>, card: &str, device: &str) -> StreamMode {
    let _ = card;
    let fd = handle.fd();
    let setting = override_setting(std::env::var("IRLUME_IR_EMITTER"));
    let wanted = match setting {
        OverrideSetting::Disabled => return StreamMode::inert(),
        // A value that is set but cannot be read as a control is NOT the same as
        // no value. Treating it as absent fell through to the built-in table, so
        // one mistyped byte in an override meant to replace that payload made
        // irlume write the payload instead, every eighth frame. Setting the
        // variable is consent to the control named in it and to nothing else.
        OverrideSetting::Malformed(why) => {
            eprintln!("irlume: refusing to drive the IR emitter: IRLUME_IR_EMITTER {why}");
            return StreamMode::inert();
        }
        OverrideSetting::Absent => None,
        OverrideSetting::Control(ctrl) => Some(ctrl),
    };

    // The Windows contract these modules are certified against permits many
    // frame consumers but exactly ONE controlling instance; sharing consumers
    // "cannot change KSPROPERTYSETID_ExtendedCameraControl controls", the
    // class the Hello extension unit belongs to, and inherit the controlling
    // application's media type (MediaCaptureSharingMode / MF FrameServer share
    // modes). irlume used to write the control regardless, relying on its
    // capture failing EBUSY later anyway. Honour the model instead of relying
    // on that (#169): when another PROCESS is seen holding this node, stand
    // down from the write and stream-or-fail with whatever state the
    // controlling application chose. Inert is the fail-safe direction: an
    // unlit emitter degrades this one capture toward the password, while a
    // write under a foreign owner mutates a stream that application is
    // mid-way through using. irlume-vs-irlume exclusion is handled separately
    // by the kernel lock; this covers everyone else.
    let scan = foreign_consumers(std::path::Path::new("/proc"), device, std::process::id());
    if scan.stands_down() {
        let who: Vec<String> = scan
            .consumers
            .iter()
            .take(3)
            .map(|(pid, comm)| format!("{comm}({pid})"))
            .collect();
        eprintln!(
            "irlume: not driving the IR emitter on {device}: another application holds this \
             camera ({}); its configuration is left untouched",
            who.join(", ")
        );
        return StreamMode::inert();
    }
    if scan.permission_denied {
        // Once per process, not per capture: under the packaged capability
        // set this is true on essentially every scan, and repeating it would
        // bury the journal while saying nothing new.
        static SCAN_DEGRADED: std::sync::Once = std::sync::Once::new();
        SCAN_DEGRADED.call_once(|| {
            eprintln!(
                "irlume: the camera-consumer scan could not inspect every process \
                 (permission denied), so a holder of {device} it cannot see goes \
                 undetected and the emitter write proceeds; see issue #207"
            );
        });
    }

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
            return StreamMode::inert();
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

    // Which control the write is going to. Needed here only to give the guard
    // its coordinates; every read of the control itself happens inside the
    // apply path, on the same pass that decides whether to write.
    let Some((unit, selector)) = action.coordinates() else {
        return StreamMode::inert();
    };

    // Armed only when irlume actually CHANGED the control, and the guard's
    // restore value is what that change DISPLACED — the answer of the one
    // `GET_CUR` in the apply path, not a separate earlier read. Recording an
    // earlier read left a window: another client writing between the two reads
    // got the stale value restored over its own (#190). Same rule as the #183
    // undo journal either way: irlume does not undo a change it did not make.
    // A refused write is a change that never happened, and an already-held
    // value is another writer's state. `Wrote` needs no "did it differ" check:
    // the tail only writes when the displaced value differs from the payload.
    //
    // Two answers, deliberately not one. The restore decides whether the guard
    // has something to put back; `active` decides what the caller tells the
    // user about their infrared. A control that already held the wanted value
    // is active and not irlume's to undo, and collapsing the pair reported it
    // dark.
    let (write, applied) = match action {
        CaptureAction::Nothing => (None, Vec::new()),
        CaptureAction::Override(ctrl) => {
            let payload = ctrl.payload.clone();
            (Some(apply_override(fd, &id, &ctrl)), payload)
        }
        CaptureAction::DeviceDefault { unit, selector } => {
            match apply_device_default(fd, &id, unit, selector) {
                Ok((w, sent)) => (Some(w), sent),
                Err(_) => (None, Vec::new()),
            }
        }
        CaptureAction::KnownPayload(ctrl) => match apply_known_payload(fd, &id, &ctrl) {
            Ok(w) => (Some(w), ctrl.payload),
            Err(_) => (None, Vec::new()),
        },
    };
    let active = write
        .as_ref()
        .is_some_and(|w| w.outcome != Applied::Nothing);
    // A POSITIVE statement of what the emitter path did, for a caller that
    // needs to verify it rather than infer it.
    //
    // The nightly hardware suite used to assert this by the ABSENCE of one
    // refusal message, which only covers the lock branch. `enable` returns
    // inert from several others: an unreadable USB identity, a recovery that
    // reports Busy or OwnerStillRunning (both deliberately silent), no
    // applicable control, and a failed `apply_device_default` or
    // `apply_known_payload`. Every one of those produces a capture that looks
    // exactly like a successful one from outside, and the comment beside
    // `applied_known_payload` already warns that a bool cannot tell "no ioctl
    // reached the device" from "the device rejected it" (#384 review).
    //
    // Off unless asked for: this is per-capture and would otherwise be noise on
    // the authentication path.
    if std::env::var_os("IRLUME_LOG_EMITTER_WRITES").is_some() {
        eprintln!(
            "irlume: capture emitter {}",
            match write.as_ref().map(|w| w.outcome) {
                Some(Applied::Wrote) => "write completed",
                Some(Applied::AlreadyHeld) => "already held the requested value",
                Some(Applied::Nothing) | None => "was not activated",
            }
        );
    }
    // What the guard owns: a write of its own, with the value it displaced —
    // or a crash leftover claimed through the stream record (#188). A control
    // already holding the wanted bytes is another writer's state EXCEPT when a
    // record for this camera, this control and these bytes marks it as
    // irlume's own unrestored change; then the guard arms with the recorded
    // displaced value and finishes what the killed stream could not. The claim
    // refuses while the record's writer is alive, which is also what keeps a
    // frozen-stream restart's fresh guard from taking the restore out from
    // under the old one in this same process.
    let (restore, record, lock) = match write {
        Some(w) => match w.outcome {
            Applied::Wrote => (Some(w.current), w.record, w.lock),
            Applied::AlreadyHeld => match w
                .lock
                .and_then(|lock| crate::stream_record::claim(lock, &id, unit, selector, &w.current))
            {
                Some((displaced, record)) => (Some(displaced), Some(record), None),
                None => (None, None, None),
            },
            Applied::Nothing => (None, None, None),
        },
        None => (None, None, None),
    };
    StreamMode {
        handle: Some(handle),
        unit,
        selector,
        armed: restore.is_some(),
        restore: restore.unwrap_or_default(),
        active,
        applied,
        record,
        _lock: lock,
    }
}

/// The face-auth mode held for the lifetime of ONE stream, put back when the
/// stream ends.
///
/// Microsoft's published sequence is set the property, start streaming, stop
/// streaming, unset it; the camera driver bring up guide lists the last two as
/// steps 4 and 5, and the HLK suite tests them. irlume used to do the first
/// three and simply leave the control set. On the ASUS module the control was
/// observed back at its default once streaming stopped, so that camera undoes it
/// unasked, but the NexiGo was observed still at the applied value outside a
/// capture. Relying on a camera to undo something irlume did is not a design.
///
/// What gets written back is the value the control HELD, read before anything is
/// applied, rather than a constructed "off" value or the camera's default. A
/// control sitting at its default is therefore restored to its default, which is
/// what "unset" means and is every case measured here; a control another program
/// deliberately left elsewhere is put back where they left it, rather than being
/// defaulted out from under them. Either way it is the camera's answer, not
/// irlume's guess.
///
/// `Drop` does the restoring, because the paths that need it most are the ones
/// no statement covers: an error taken by `?`, a panic in the decoder, a
/// cancelled request. Same reason the undo record in #183 restores from `Drop`.
#[must_use = "dropping this immediately puts the control back and leaves the stream unlit"]
pub struct StreamMode {
    /// The open camera the mode was applied through, kept alive for as long as
    /// this guard can write to it. `None` only for a guard over nothing, which
    /// never writes. A raw `c_int` here let a caller drop the `v4l::Device`
    /// first and have the restore land on whatever `open` handed the recycled
    /// number to next (#189); the `Arc` removes that state from the API.
    handle: Option<std::sync::Arc<v4l::device::Handle>>,
    unit: u8,
    selector: u8,
    /// What the control HELD before irlume touched it, captured before the first
    /// write. Not the camera's default: those coincide in the ordinary case and
    /// differ exactly when another program has set something, which is when
    /// putting the default back would destroy their state.
    restore: Vec<u8>,
    /// What this guard actually wrote, so the restore can check the control
    /// still holds it rather than trusting that nothing else moved.
    applied: Vec<u8>,
    /// True only while irlume's own change is outstanding; cleared once the
    /// control is back, so `Drop` never writes twice.
    armed: bool,
    /// Whether the control is ACTIVE for this stream, which is a different
    /// question from whether irlume changed it. A control that already held the
    /// wanted value is active and not irlume's to undo, so it is `active`
    /// without being `armed`. Collapsing the two made `lit()` report false there,
    /// and the caller prints "IR is dark with no active emitter" on that, which
    /// would have been a false statement about the camera.
    active: bool,
    /// The on-disk leftover record for the outstanding change (#188), locked
    /// for as long as this guard lives. Resolved (removed) when the guard
    /// concludes there is nothing left to undo; left behind, unlocked, when
    /// the restore write fails, so the next session can claim it.
    record: Option<crate::stream_record::StreamRecord>,
    /// The bare stream lock, held (never read) when this guard's write could
    /// not be RECORDED: the exclusion must still outlive the change, or a
    /// second irlume takes the camera mid-stream (review round 5). `None`
    /// whenever a record exists — the lock lives inside it then.
    _lock: Option<crate::stream_record::StreamLock>,
}

/// Why a restore did not put the control back.
///
/// Two causes, and a caller must be able to tell them apart: a camera that
/// refused or vanished is hardware trouble, while bookkeeping that could not
/// be written means the restore was deliberately NOT ATTEMPTED and the mode is
/// still applied (review round 3 — returning `Ok` there made a skipped
/// restore read as a completed one).
#[derive(Debug)]
pub enum RestoreError {
    /// The camera did not take the read or the write.
    Camera(XuError),
    /// The record could not be retired first, so no camera request was made:
    /// the mode stays applied and the record stays claimable.
    Bookkeeping(String),
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Camera(e) => write!(f, "{e}"),
            Self::Bookkeeping(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RestoreError {}

impl StreamMode {
    /// A guard over nothing: no control was applied, so `Drop` writes nothing.
    ///
    /// The ordinary outcome for hardware irlume does not drive, and the only
    /// safe representation of it. An `Option<StreamMode>` would let a caller
    /// write `let _ = ...` and silently discard a guard that DID hold a control.
    fn inert() -> Self {
        StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 0,
            selector: 0,
            restore: Vec::new(),
            applied: Vec::new(),
            armed: false,
            active: false,
        }
    }

    /// The descriptor the restore goes to, or -1 for a guard holding no camera.
    ///
    /// -1 is unreachable from an armed guard: `enable` is the only place that
    /// arms one, and it always installs the handle it wrote through.
    fn fd(&self) -> c_int {
        self.handle.as_ref().map_or(-1, |h| h.fd())
    }

    /// Whether the emitter control is active for this stream, whoever set it.
    ///
    /// NOT the same as whether irlume changed it, which is what governs the
    /// restore. A control already holding the wanted value is active, and
    /// reporting it dark would put "IR is dark with no active emitter" in front
    /// of a user whose emitter is on.
    pub fn lit(&self) -> bool {
        self.active
    }

    // There used to be a public `disarm()` here, for the frozen-stream
    // restart's ownership handover. The restart restores before reopening
    // since review round 4, which removed the method's one production caller
    // — and a disarmed guard holding an APPLIED record would abandon it,
    // unlocked and still authoritative, for a later stream to claim against
    // a value whose owner meant to keep it (review round 8). Ownership moves
    // by moving the whole guard, or not at all.

    /// Whether this guard owns an outstanding change that still has to be put
    /// back.
    ///
    /// NOT `lit`. That reports whether the control is ACTIVE, whoever set it,
    /// and the two diverge exactly where it matters: a control found already
    /// holding the wanted value is active and owns nothing. A caller deciding
    /// which of two guards keeps the restore has to ask this one, and the
    /// restart sites asked `lit` instead, so a replacement that wrote nothing
    /// took ownership from the guard that had.
    pub fn owns_restore(&self) -> bool {
        self.armed
    }

    /// Put the control back now, rather than waiting for the drop.
    ///
    /// Used by the frozen-stream restart paths, which must restore the old
    /// stream's change (and surface a failure) before opening and arming the
    /// replacement; `Drop` remains the ordinary end-of-session path, and can
    /// only print. `Err(Bookkeeping)` means no camera request was made at
    /// all — the mode is still applied, on purpose.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn restore(&mut self) -> std::result::Result<(), RestoreError> {
        if !self.armed {
            return Ok(());
        }
        // Disarmed first either way. If this succeeds there is nothing left for
        // `Drop` to do; if it fails, `Drop` repeating a write the camera has
        // just refused is how #159 territory is entered.
        //
        // The bare lock (an unrecorded write's exclusion) is held THROUGH the
        // restore below and released when this attempt finishes, success or
        // not: an explicitly restored guard no longer owns a live change, and
        // the frozen-stream restart calls restore() and then runs a fresh
        // enable while this guard still exists — a retained lock made that
        // enable refuse against its own predecessor and the reopened stream
        // ran dark (review round 9). A RECORDED write's lock lives in the
        // record and is released by resolve() on the same schedule.
        let _bare_lock = self._lock.take();

        // The early return above is DEFENCE IN DEPTH and a mutant deleting it
        // survives the suite. That is not a missing test: the read-back below
        // subsumes it. On a second call the control already holds `restore`,
        // which is not `applied`, so the "somebody else moved it" arm leaves it
        // alone and no write goes out either way. Kept rather than removed
        // because it states the intent at the top of the function, where the next
        // reader looks, and because a later change to the read-back would
        // otherwise silently take the only thing stopping a double write. The
        // mutant is recorded as unkillable by construction rather than dropped.
        self.armed = false;

        // Read it back before putting anything back. This guard knows what it
        // wrote, which is not the same as knowing what the control holds now: a
        // vendor tool or another client can move it while the stream runs, and
        // restoring on historical ownership alone would drop the default over
        // somebody else's newer value. The recovery path in #183 re-reads for
        // exactly this reason and refuses when the bytes have moved on; the
        // guard is the same decision at a shorter range.
        //
        // A control that no longer holds this guard's value is left alone. The
        // change irlume made is already gone, so there is nothing of its to undo.
        // Before anything touches the camera: make the record incapable of
        // authorising another restore. The unlink at the end can fail, and an
        // `applied` record outliving its own resolution would later authorise
        // a firmware write over whatever unrelated value happened to match it
        // (review round 2). If even the demotion cannot be written, nothing is
        // restored at all: the mode stays applied and the record stays
        // claimable, and the next session finishes the job when the store
        // recovers. Restoring anyway would recreate the exact hole, since a
        // store that cannot take a rename is not going to take the unlink.
        let record = match self.record.take() {
            Some(record) => match record.retire() {
                Ok(record) => Some(record),
                Err(e) => {
                    let (record, why) = *e;
                    // The handle drops HERE, on purpose: this guard will never
                    // write again, so releasing the lock is what lets the next
                    // session claim the still-applied record and finish the
                    // restore this one could not start.
                    drop(record);
                    return Err(RestoreError::Bookkeeping(format!(
                        "not restoring unit{}/sel{}: its stream record cannot be retired \
                         ({why}); the mode stays applied and the record stays claimable \
                         for the next session",
                        self.unit, self.selector
                    )));
                }
            },
            None => None,
        };
        let outcome = match get_cur(self.fd(), self.unit, self.selector, self.applied.len()) {
            Ok(now) if now != self.applied => {
                eprintln!(
                    "irlume: leaving unit{}/sel{} at {:02x?}: it no longer holds what irlume \
                     applied ({:02x?}), so the change to undo is not there",
                    self.unit, self.selector, now, self.applied
                );
                Ok(())
            }
            Ok(_) => set_cur(self.fd(), self.unit, self.selector, &self.restore),
            // An unreadable control authorises NOTHING: writing blind here
            // could put the restore value over bytes some other client set
            // mid-stream, the exact class this file exists to prevent. #184
            // chose to restore anyway, reasoning that a stranded mode was the
            // worse error — a calculus the claim machinery has since
            // inverted: this error path re-promotes the record below, so a
            // recorded change stays claimable and nothing strands, while an
            // unrecorded one surfaces through the caller (review round 13).
            Err(e) => Err(e),
        };
        match outcome {
            // Nothing is outstanding any more: the control is back, or the
            // change irlume made is already gone. Either way the record must
            // not outlive the fact it records (#188). A failed unlink costs
            // litter, not authority: the record was retired above.
            Ok(()) => {
                if let Some(record) = record {
                    if let Err(why) = record.resolve() {
                        eprintln!("irlume: {why}");
                    }
                }
                Ok(())
            }
            // The restore write failed, so the leftover is REAL again and the
            // record must go back into force for the next session to claim.
            // If the re-promotion fails too, that is reported and the
            // leftover goes unclaimed — the safe direction, twice over.
            Err(e) => {
                if let Some(record) = record {
                    match record.mark_applied() {
                        Ok(_kept) => {}
                        Err(e) => {
                            let why = e.1;
                            eprintln!(
                                "irlume: the failed restore's record could not be put back \
                                 into force ({why}); the leftover will not be claimed \
                                 automatically"
                            );
                        }
                    }
                }
                Err(RestoreError::Camera(e))
            }
        }
    }
}

impl Drop for StreamMode {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(e) = self.restore() {
            // Not fatal, and not silent. The camera keeps a mode irlume chose,
            // which is exactly the state this type exists to prevent, so it is
            // worth a line even though nothing here can react to it.
            eprintln!(
                "irlume: could not put unit{}/sel{} back to the value irlume displaced: {e}",
                self.unit, self.selector
            );
        }
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

impl CaptureAction {
    /// Which control this action will write to, or `None` when it writes
    /// nothing. Needed before the write, so the control's default can be read
    /// while it is still untouched.
    fn coordinates(&self) -> Option<(u8, u8)> {
        match self {
            CaptureAction::Nothing => None,
            CaptureAction::Override(c) | CaptureAction::KnownPayload(c) => {
                Some((c.unit, c.selector))
            }
            CaptureAction::DeviceDefault { unit, selector } => Some((*unit, *selector)),
        }
    }
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
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
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

/// What an apply path DID to the control, which is not the same question as
/// whether the payload was accepted.
///
/// A bare bool answered only the second question, and `enable` armed the
/// stream guard on it. That collapsed "a write went out" into "the control
/// holds these bytes": the guard armed on both, so ending a stream could set
/// `GET_DEF` over a value some other process had established, which is undoing
/// a change irlume never made. The rule is the #183 journal's: irlume restores
/// only what irlume changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applied {
    /// A `SET_CUR` went out and the camera took it.
    Wrote,
    /// The control already held the payload, so nothing was sent. The value is
    /// active, but it is not irlume's write, and it is not irlume's to undo.
    AlreadyHeld,
    /// Nothing reached the control: a check refused, the one-write record said
    /// no, or the camera rejected the write.
    Nothing,
}

/// Apply an `IRLUME_IR_EMITTER` override, writing at most once per control per
/// camera per process, and only with the evidence every other write here
/// requires.
///
/// The record bounds the CHECKS, not the writes. A remembered success means this
/// payload was already validated against this camera's descriptors, so the
/// checks and the refusal message do not run again; the value is still applied
/// for each new stream, because the mode is restored when the previous one
/// ended and the control is sitting at the camera's default.
///
/// It used to answer from a `GET_CUR` read-back instead, which was right while
/// irlume left the mode set for the life of the process. Under a per-stream
/// lifecycle that reported every stream after the first as dark.
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
) -> CaptureWrite {
    let key = match override_key(fd, id, ctrl) {
        Ok(key) => key,
        Err(err) => {
            eprintln!(
                "irlume: refusing IRLUME_IR_EMITTER={}: cannot identify the open device ({err}), \
                 so irlume cannot tell whether this was already applied",
                ctrl.encode()
            );
            return CaptureWrite::refused();
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
            return CaptureWrite::refused();
        }
    };
    match reuse(memo.get(&key), &ctrl.payload) {
        // A remembered refusal stands: re-running the checks every capture is
        // the traffic the record exists to stop, and the answer is "no" either
        // way.
        Reuse::Answer(false) => return CaptureWrite::refused(),
        // A remembered SUCCESS says this payload was checked against this
        // camera's descriptors and accepted. It does NOT say the control still
        // holds it, and since the mode is now restored when each stream ends it
        // usually does not: the next stream finds the camera's default there.
        //
        // Reading it back and reporting the difference as "the emitter is not
        // on" was right while irlume left the control set for the life of the
        // process. With a per-stream lifecycle it means the first stream in a
        // daemon lights and every later one runs dark, which on a machine that
        // authenticates in the dark is a lockout.
        //
        // So the memo is used for what it is good for, which is not re-running
        // the descriptor checks and the refusal message, and the value is
        // applied again for this stream. That is one write per stream, which is
        // the documented sequence, not the repeated writing this change removes.
        Reuse::Answer(true) => {
            return match check_and_apply_override(fd, id, ctrl) {
                Ok(write) => write,
                Err(why) => {
                    eprintln!(
                        "irlume: refusing IRLUME_IR_EMITTER={}: {why}",
                        ctrl.encode()
                    );
                    CaptureWrite::refused()
                }
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
            return CaptureWrite::refused();
        }
        Reuse::Decide => {}
    }
    let write = match check_and_apply_override(fd, id, ctrl) {
        Ok(write) => write,
        Err(why) => {
            // Silence here would read as "the value was applied and the camera
            // is simply dark", which is the reading that sends someone back to
            // try another unit and selector.
            eprintln!(
                "irlume: refusing IRLUME_IR_EMITTER={}: {why}",
                ctrl.encode()
            );
            CaptureWrite::refused()
        }
    };
    memo.insert(
        key,
        OverrideDecision {
            payload: ctrl.payload.clone(),
            // The record answers "was this payload accepted", so a value found
            // already in place counts the same as a write the camera took.
            applied: write.outcome != Applied::Nothing,
        },
    );
    write
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
) -> std::result::Result<CaptureWrite, OverrideRefusal> {
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
    write_if_different(fd, unit, selector, len, &ctrl.payload, id).map_err(|err| {
        OverrideRefusal::Unreadable {
            unit,
            selector,
            err,
        }
    })
}

/// Apply a validated built-in payload, with the same gate every other automatic
/// write passes.
///
/// A table entry is a constant rather than something read from the camera, so it
/// cannot be re-derived; but the camera still has to say it accepts a write of
/// that size right now. Writing a nine-byte payload to a control the camera has
/// just reported as disabled, or as a different length, is not something a
/// validated VID:PID should buy.
fn apply_known_payload(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> XuResult<CaptureWrite> {
    if !info_allows_set(get_info(fd, ctrl.unit, ctrl.selector)?) {
        return Err(XuError::Unsupported);
    }
    let len = get_len(fd, ctrl.unit, ctrl.selector)?;
    if len != ctrl.payload.len() {
        return Err(XuError::Unsupported);
    }
    write_if_different(fd, ctrl.unit, ctrl.selector, len, &ctrl.payload, id)
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
///
/// Returns the bytes that went out alongside the write's outcome, because only
/// this function derives them and the caller needs them: `enable` records what
/// the guard APPLIED, which for IR Torch is the camera's own default rather
/// than anything the caller named.
fn apply_device_default(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    unit: u8,
    selector: u8,
) -> XuResult<(CaptureWrite, Vec<u8>)> {
    if !info_allows_set(get_info(fd, unit, selector)?) {
        return Err(XuError::Unsupported);
    }
    let len = get_len(fd, unit, selector)?;
    let Ok(wanted) = intended_value(fd, unit, selector, len)? else {
        return Err(XuError::Unsupported);
    };
    let write = write_if_different(fd, unit, selector, len, &wanted, id)?;
    Ok((write, wanted))
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
    /// The caller's pre-write guard refused the next exploratory write, e.g.
    /// the privacy shutter engaged after setup began. Anything already changed
    /// was restored before this was returned.
    WriteRefused(String),
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
            Self::WriteRefused(why) => write!(
                f,
                "{why}; setup stopped without sending anything further, and anything it had \
                 already changed was put back"
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
    /// The PATH `save` wrote the record to.
    ///
    /// The removal uses this rather than a path derived from the record's
    /// contents, so it cannot target a different file than the save did. The
    /// record itself was kept here for that purpose and is no longer needed:
    /// deriving the name looked equivalent to remembering it and is not.
    record_path: std::path::PathBuf,
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
        let record_path = crate::emitter_journal::save(&record)?;
        Ok(Self {
            fd,
            unit,
            selector,
            original: original.to_vec(),
            attempted: attempted.to_vec(),
            record_path,
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

    /// Drop the record without touching the camera.
    ///
    /// For the one case where the record turns out to describe a state irlume
    /// never got to act on: nothing has been written, so there is nothing to
    /// undo, and leaving the record behind would make the next run refuse this
    /// camera over a change that never happened.
    fn abandon_before_write(&mut self) -> Result<(), String> {
        debug_assert!(
            !self.exploratory_value_is_live,
            "abandoning after the exploratory write would strand the control"
        );
        crate::emitter_journal::clear(&self.record_path)?;
        self.resolved = true;
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
        crate::emitter_journal::clear(&self.record_path)?;
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
        crate::emitter_journal::clear(&self.record_path)?;
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
        Err(why) => RecoveryOutcome::Unchecked(format!("lock the camera: {why}")),
    }
}

/// The recovery pass proper. The caller holds this camera's lock.
/// Whether a counted attempt may be followed by a firmware write.
///
/// Separated from the write that produces it so the decision can be exercised.
/// Nothing here can make a directory `fsync` fail, so a test going through
/// `save_at` cannot reach the middle arm and a mutant deleting it survives; the
/// outcome is a value, and the decision made about that value is testable even
/// when the condition producing it is not reachable.
fn counted_attempt_authorizes_write(
    saved: Result<(std::path::PathBuf, irlume_common::AtomicWrite), String>,
) -> Result<(), String> {
    match saved {
        Ok((_, irlume_common::AtomicWrite::Durable)) => Ok(()),
        // The attempt limit exists to bound firmware writes ACROSS CRASHES, so a
        // count a power loss can revert bounds nothing: the old record comes
        // back with the lower number and the same restore runs again, past the
        // limit. The increment IS visible, so refusing may cost an attempt with
        // no write ever made — at most MAX_RESTORE_ATTEMPTS refusals, against
        // unbounded writes to somebody's camera.
        Ok((_, irlume_common::AtomicWrite::VisibleNotDurable(e))) => Err(format!(
            "count the attempt: the updated record is visible but not durable ({e}); \
             refusing the write"
        )),
        // Nothing became visible, so nothing was spent and nothing may be
        // written: an uncounted write is the loop the counter exists to stop.
        Err(why) => Err(format!("count the attempt: {why}")),
    }
}

fn recover_pending_write_locked(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
) -> RecoveryOutcome {
    use crate::emitter_journal as journal;

    let (record_path, record) = match journal::load(id) {
        Ok(journal::Situation::Nothing) => return RecoveryOutcome::NothingPending,
        Ok(journal::Situation::Mine { path, record }) => (path, *record),
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
        journal::Restore::AlreadyRestored => match journal::clear(&record_path) {
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
            // To the path the record was FOUND at, not the one its contents
            // derive: a scanned record need not be filed under its own name, and
            // deriving here wrote the incremented record to a second file.
            if let Err(why) =
                counted_attempt_authorizes_write(journal::save_at(&record_path, &spent))
            {
                return RecoveryOutcome::Unresolved(why);
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
            // A pass that decides NOT to write must not spend an attempt. The
            // counter means "times the original was written back", and three
            // refusals that touched nothing would otherwise exhaust the budget
            // and leave the emitter off for good over writes that never
            // happened. The count is put back before returning.
            //
            // Rolling back can itself fail, and then the count stays high. That
            // direction is the safe one: too few retries leaves a reported,
            // recoverable record, while too many is what the budget exists to
            // prevent.
            let give_back = |outcome: RecoveryOutcome| -> RecoveryOutcome {
                match journal::save_at(&record_path, &record) {
                    Ok(_) => outcome,
                    Err(why) => RecoveryOutcome::Unresolved(format!(
                        "{}; and the unused attempt could not be given back ({why})",
                        match &outcome {
                            RecoveryOutcome::Unresolved(w) => w.clone(),
                            other => format!("{other:?}"),
                        }
                    )),
                }
            };
            let attempted = match journal::from_hex(&record.attempted) {
                Ok(bytes) => bytes,
                Err(why) => {
                    return give_back(RecoveryOutcome::Unresolved(format!("attempted: {why}")))
                }
            };
            match get_cur(fd, record.unit, record.selector, original.len()) {
                Ok(now) if now == attempted => {}
                Ok(now) => {
                    return give_back(RecoveryOutcome::Unresolved(format!(
                        "the control changed while the attempt was being recorded: it holds \
                         {now:02x?}, not this run's value {attempted:02x?}; nothing was written"
                    )))
                }
                Err(e) => {
                    return give_back(RecoveryOutcome::Unresolved(format!(
                        "recheck the control before restoring it: {e}"
                    )))
                }
            }

            if let Err(e) = set_cur(fd, record.unit, record.selector, &original) {
                return RecoveryOutcome::Unresolved(format!("restore: {e}"));
            }
            match get_cur(fd, record.unit, record.selector, original.len()) {
                Ok(back) if back == original => match journal::clear(&record_path) {
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
    /// The journal STATE COULD NOT BE EXAMINED (the per-camera lock was
    /// unavailable, e.g. an unprivileged process cannot create it under
    /// /run/lock). Not the same fact as [`Self::Unresolved`]: nothing was
    /// observed about any record, so the message must not claim one exists.
    /// The write refusal is identical, because a process that cannot check
    /// cannot know the camera is safe to write to (#210).
    Unchecked(String),
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
            Self::Unchecked(why) => Some(format!(
                "irlume: could not check whether an interrupted emitter setup left this \
                 camera changed ({why}). irlume will not write to this camera's emitter \
                 from this process until the lock error is resolved and the journal can \
                 be checked, so IR face authentication will not light here."
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
            Self::Unchecked(_) => "unchecked",
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
            | Self::Unchecked(_)
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
            | Self::Unchecked(_)
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
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn discover<F: FnMut() -> Option<f32>, G: FnMut() -> Result<(), String>>(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    measure: &mut F,
    // Consulted immediately before each FORWARD write (never before a
    // restore); an `Err` refuses the write and ends the run with its reason.
    // The caller supplies the privacy-shutter re-check through this, so the
    // check-to-write window is one syscall, not the whole discovery pipeline.
    before_forward_write: &mut G,
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
        match try_documented_control(fd, id, ms.unit_id, selector, measure, before_forward_write) {
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
            Err(TryFailure::Guard(why)) => return Err(DiscoveryError::WriteRefused(why)),
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn confirm_applied(&mut self) -> std::result::Result<(), String> {
        self.pending.confirm_applied()
    }

    /// Release the undo record. Call only once the configuration naming this
    /// control is durable.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
    /// The caller's pre-write guard (the privacy-shutter re-check) refused the
    /// next forward write. Nothing was sent; carries the guard's own reason.
    Guard(String),
}

impl From<XuError> for TryFailure {
    fn from(e: XuError) -> Self {
        Self::Query(e)
    }
}

/// Try one advertised, documented control, leaving it as it was found unless it
/// worked.
fn try_documented_control<F: FnMut() -> Option<f32>, G: FnMut() -> Result<(), String>>(
    fd: c_int,
    id: &crate::uvc_descriptor::CameraIdentity,
    unit: u8,
    selector: u8,
    measure: &mut F,
    before_forward_write: &mut G,
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

    // Read the control AGAIN, immediately before changing it.
    //
    // `original` was read before `intended_value`, before a whole baseline frame
    // measurement, and before the record's create/write/fsync/rename/fsync. The
    // per-camera flock excludes other irlume processes and nothing else: a
    // vendor tool or any other UVC client can move this control inside that
    // window. Recording a value that is no longer there means the restore later
    // writes bytes irlume never found, which is precisely the "we do not undo
    // somebody else's change" promise the rest of this file keeps. Recovery
    // already re-reads for the same reason; discovery did not.
    //
    // The residual race is one syscall wide and cannot be closed here: the UVC
    // interface offers GET_CUR and SET_CUR and no compare-and-set.
    let now = get_cur(fd, unit, selector, len)?;
    if now != original {
        // Nothing has been written, so the record describes a change that never
        // happened; drop it rather than leave the camera refused by the next run.
        pending
            .abandon_before_write()
            .map_err(TryFailure::Journal)?;
        return Ok(Attempt::NotUsable(format!(
            "the control changed while setup was measuring: it held {original:02x?} \
             when discovery began and {now:02x?} immediately before the write, so \
             something else is driving it; nothing was sent"
        )));
    }

    if abort_requested() {
        return Err(TryFailure::Measurement);
    }
    // The guard runs immediately before EACH forward write, not only at the
    // top of setup: the early sample there left format negotiation, the
    // settling frames, the journal fsyncs and the baseline burst as a window
    // in which the operator can engage the shutter, and this write would then
    // be spent measuring a blanked frame (#193 review). Restores are
    // deliberately not guarded: refusing to put a control back would leave it
    // changed, which is the worse outcome by this file's own rules.
    if let Err(why) = before_forward_write() {
        // Nothing has been written, so the record describes a change that
        // never happened; drop it, as the moved-control refusal above does.
        pending
            .abandon_before_write()
            .map_err(TryFailure::Journal)?;
        return Err(TryFailure::Guard(why));
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
    if let Err(why) = before_forward_write() {
        // The restore above already put the control back and this branch
        // writes nothing further, so the record resolves the same way the
        // stayed-bright refusal does.
        pending.confirm_restored().map_err(TryFailure::Journal)?;
        return Err(TryFailure::Guard(why));
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
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
    /// The nightly hardware suite greps for this line EXACTLY
    /// (`grep -Fxq` in .github/workflows/hardware-suite.yml), so a reword here
    /// silently turns that gate into one that can never pass, and the camera
    /// stage would fail every night for a reason nobody would look for in this
    /// file.
    ///
    /// That is not hypothetical: #383 is the same drift one layer over, where
    /// doctor's node line gained a suffix and the workflow's anchored match
    /// stopped firing for eight nights. Change the string here and change it
    /// there in the same commit (#384).
    #[test]
    fn the_emitter_write_marker_matches_what_ci_greps_for() {
        let workflow = include_str!("../../../.github/workflows/hardware-suite.yml");
        assert!(
            workflow.contains("irlume: capture emitter write completed"),
            "the workflow no longer greps for the marker this file emits"
        );
        // ...and the source really does emit that exact text, so the assertion
        // above cannot pass against a workflow string with no producer.
        //
        // The needles are assembled with `concat!` because `include_str!` pulls
        // in THIS module: spelled inline, they match their own assertion and the
        // check stays green with the marker reworded. Caught by mutation, which
        // is the only reason this comment exists (defect pattern 70, hit for the
        // third time in one session).
        let src = include_str!("ir_emitter.rs");
        let produced = concat!("\"write ", "completed\"");
        let format = concat!("irlume: capture ", "emitter {}");
        assert!(
            src.contains(produced) && src.contains(format),
            "the marker is no longer produced here; the workflow gate has no source"
        );
    }

    use super::*;

    /// Build a fake /proc tree: `pids` maps a pid to (comm, fd-targets).
    fn fake_proc(tag: &str, pids: &[(u32, &str, &[&str])]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("irlume-fproc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (pid, comm, targets) in pids {
            let fd = root.join(pid.to_string()).join("fd");
            std::fs::create_dir_all(&fd).unwrap();
            std::fs::write(root.join(pid.to_string()).join("comm"), format!("{comm}\n")).unwrap();
            for (i, t) in targets.iter().enumerate() {
                std::os::unix::fs::symlink(t, fd.join(i.to_string())).unwrap();
            }
        }
        // Non-pid entries the scanner must skip, as the real /proc has.
        std::fs::create_dir_all(root.join("sys")).unwrap();
        root
    }

    #[test]
    fn foreign_consumers_finds_other_processes_holding_the_node() {
        let root = fake_proc(
            "basic",
            &[
                (1234, "chrome", &["/dev/video2", "/home/user/x.log"]),
                (5678, "bash", &["/dev/pts/0"]),
                (9999, "irlumed", &["/dev/video2"]), // self: must be excluded
            ],
        );
        let got = foreign_consumers(&root, "/dev/video2", 9999);
        assert_eq!(got.consumers, vec![(1234, "chrome".to_string())]);
        // Everything in this tree was readable, so nothing was a blind spot.
        assert!(!got.permission_denied);
        // A different node has no foreign consumers here.
        assert!(foreign_consumers(&root, "/dev/video0", 9999)
            .consumers
            .is_empty());
        // The self pid holding it is not "foreign".
        assert!(
            foreign_consumers(&root, "/dev/video2", 1234)
                .consumers
                .len()
                == 1
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn foreign_consumers_fails_open_on_missing_or_odd_trees() {
        // A missing proc root, an empty dev, and a pid dir without fd/ must all
        // degrade to "no foreign consumers": the guard stands the emitter down
        // only on positive evidence, never on scan failure. None of these is a
        // permission DENIAL, so none may mark the scan incomplete either; that
        // bit carries "a process refused inspection", not "the tree was odd".
        let missing =
            foreign_consumers(std::path::Path::new("/nonexistent-proc"), "/dev/video2", 1);
        assert!(missing.consumers.is_empty());
        assert!(!missing.permission_denied);
        let root = fake_proc("odd", &[(4321, "sleep", &[])]);
        std::fs::remove_dir_all(root.join("4321").join("fd")).unwrap();
        let fdless = foreign_consumers(&root, "/dev/video2", 1);
        assert!(fdless.consumers.is_empty());
        assert!(!fdless.permission_denied);
        assert_eq!(foreign_consumers(&root, "", 1), ConsumerScan::default());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_unlistable_fd_dir_marks_the_scan_incomplete_not_empty() {
        use std::os::unix::fs::PermissionsExt;
        // One process holds the node but its fd dir cannot be listed: the
        // shape a ptrace-gated /proc presents to the packaged daemon (#207).
        // The observation and its failure must stay distinct: consumers empty
        // AND permission_denied set, never a bare empty list.
        let root = fake_proc("denied-list", &[(4321, "chrome", &["/dev/video2"])]);
        let fd_dir = root.join("4321").join("fd");
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&fd_dir).is_ok() {
            // A privileged run bypasses the denial this test constructs, so it
            // would prove nothing; say so instead of passing vacuously.
            eprintln!("not exercised: this uid bypasses directory permissions");
        } else {
            let scan = foreign_consumers(&root, "/dev/video2", 1);
            assert!(scan.consumers.is_empty());
            assert!(
                scan.permission_denied,
                "a denied fd listing must mark the scan incomplete"
            );
        }
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_denied_readlink_marks_the_scan_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        // r without x on the fd dir: the entry names list, their targets do
        // not resolve. Exercises the read_link arm, distinct from the
        // unlistable-dir arm above.
        let root = fake_proc("denied-link", &[(4321, "chrome", &["/dev/video2"])]);
        let fd_dir = root.join("4321").join("fd");
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o444)).unwrap();
        match std::fs::read_link(fd_dir.join("0")) {
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                let scan = foreign_consumers(&root, "/dev/video2", 1);
                assert!(scan.consumers.is_empty());
                assert!(
                    scan.permission_denied,
                    "a denied readlink must mark the scan incomplete"
                );
            }
            _ => eprintln!("not exercised: this uid bypasses directory permissions"),
        }
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_blind_spot_alone_does_not_stand_the_emitter_down() {
        // The packaged daemon sees permission_denied on essentially every
        // scan; standing down on it would keep the emitter permanently dark.
        // Only a consumer the scan SAW stands the write down.
        let blind = ConsumerScan {
            consumers: vec![],
            permission_denied: true,
        };
        assert!(!blind.stands_down());
        let seen = ConsumerScan {
            consumers: vec![(1234, "chrome".to_string())],
            permission_denied: true,
        };
        assert!(seen.stands_down());
    }

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
            // The journal state was never examined (lock unavailable). Loud,
            // and it stops both writers: a process that cannot check cannot
            // know the camera is safe to write to. Distinct from Unresolved
            // because its message asserts nothing about records (#210).
            (
                RecoveryOutcome::Unchecked("lock the camera: permission denied".into()),
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
                RecoveryOutcome::Unchecked(_) => (false, true),
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
        measure: impl FnMut() -> Option<f32>,
    ) -> (
        std::result::Result<Attempt, TryFailure>,
        Vec<fake_camera::Request>,
        Vec<u8>,
        std::path::PathBuf,
    ) {
        run_discovery_guarded(camera, tag, measure, || Ok(()))
    }

    fn run_discovery_guarded(
        camera: fake_camera::Camera,
        tag: &str,
        mut measure: impl FnMut() -> Option<f32>,
        mut guard: impl FnMut() -> Result<(), String>,
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
        let outcome =
            try_documented_control(-1, &id, ms.unit_id, selector, &mut measure, &mut guard);
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

    /// A lock the process cannot take means the journal state was never
    /// examined; the outcome must SAY that, not fabricate a pending record.
    /// Every unprivileged dev-tool capture used to print "an emitter control
    /// ... was left changed by an interrupted setup" on machines whose
    /// journal directory did not even exist (#210).
    ///
    /// The blocking fixture is a regular FILE where the lock directory
    /// belongs: ENOTDIR stops root and CAP_DAC_OVERRIDE exactly like an
    /// unprivileged uid (the container suite uses the same trick), so this
    /// test has no privileged skip arm to pass vacuously through.
    #[test]
    fn an_untakeable_lock_reports_unchecked_never_a_phantom_record() {
        let _lock = crate::testenv::env_lock();
        let dir =
            std::env::temp_dir().join(format!("irlume-unchecked-lockdir-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::write(&dir, b"not a directory").expect("blocking file");
        let _lockdir = EnvGuard::set("IRLUME_EMITTER_LOCK_DIR", &dir);
        let id = identity(0x3277, 0x0059);
        let fd = non_uvc_fd();
        use std::os::unix::io::AsRawFd as _;
        let outcome = recover_pending_write(fd.as_raw_fd(), &id);
        assert!(
            matches!(outcome, RecoveryOutcome::Unchecked(_)),
            "a lock setup failure is a failure to OBSERVE, got {outcome:?}"
        );
        let msg = outcome.message().expect("unchecked is loud");
        assert!(msg.contains("could not check"), "{msg}");
        assert!(
            !msg.contains("was left changed"),
            "the message must not claim a record was observed: {msg}"
        );
        assert!(
            !msg.contains("recorded original"),
            "the message must not claim a record exists: {msg}"
        );
        // And no unsupported assurance in the other direction: nothing here
        // knows whether any other process checked or recovered anything, and
        // the daemon itself can land here (EROFS, ENOSPC, a bad lock path).
        assert!(!msg.contains("checks and recovers on its own"), "{msg}");
        assert!(!msg.contains("expected and harmless"), "{msg}");
        assert!(
            !outcome.permits_capture_write(),
            "refusing is the safe half"
        );
        assert!(outcome.blocks_discovery());
        std::fs::remove_file(&dir).expect("remove blocking file");
    }

    /// A camera that says "yes" to the final write but holds something else
    /// must not have its undo data deleted.
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
        // Dropped normally, not forgotten. `open` leaves the guard disarmed —
        // nothing has been written to the camera yet — so `Drop` returns without
        // touching the control or the record, which is exactly the state this
        // test wants and is worth exercising rather than stepping around.
        // `mem::forget` leaked everything the guard owned, which LeakSanitizer
        // caught in CI and no ordinary test run would have.
        drop(pending);

        // Which also proves the disarmed drop left the record alone.
        let record = match crate::emitter_journal::load(&id).expect("load") {
            crate::emitter_journal::Situation::Mine { record, .. } => *record,
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
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::umask(previous)
        };
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

    /// A restoring write needs an attempt counted DURABLY, not merely visibly.
    ///
    /// The limit exists to bound firmware writes across crashes. A count that a
    /// power loss reverts bounds nothing: the old record returns with the lower
    /// number and the same restore runs again, past the limit. This reverses an
    /// earlier fix of mine that read "visible" as good enough here — it is good
    /// enough to say an attempt was SPENT, and not good enough to authorize the
    /// write that spends it.
    #[test]
    fn a_restore_needs_the_attempt_counted_durably_not_just_visibly() {
        let path = std::path::PathBuf::from("/var/lib/irlume/ir-emitter-journal/x.json");
        assert_eq!(
            counted_attempt_authorizes_write(Ok((
                path.clone(),
                irlume_common::AtomicWrite::Durable
            ))),
            Ok(()),
            "the ordinary durable path must still authorize the write"
        );

        let why = counted_attempt_authorizes_write(Ok((
            path,
            irlume_common::AtomicWrite::VisibleNotDurable(std::io::Error::other("no space")),
        )))
        .expect_err("a count a power loss can revert must NOT authorize a firmware write");
        assert!(
            why.contains("visible but not durable") && why.contains("refusing"),
            "the refusal must say why, got: {why}"
        );
        assert!(
            why.contains("no space"),
            "the underlying error must survive into the message, got: {why}"
        );

        // And nothing published at all is also a refusal, but for the other
        // reason: no attempt was spent, so a write here would be uncounted.
        let why = counted_attempt_authorizes_write(Err("disk full".into()))
            .expect_err("an unwritten record must not authorize a write either");
        assert!(why.contains("disk full"), "got: {why}");
    }

    /// The control goes back to the value irlume displaced when the stream
    /// ends — its own default here, because the fixture starts there.
    ///
    /// Microsoft's sequence ends by unsetting the property, and the HLK suite
    /// tests that it happened. irlume set the mode and left it. The ASUS module
    /// was observed back at its default once streaming stopped, so it undoes
    /// this unasked, but the NexiGo was observed still at the applied value
    /// outside a capture; leaning on a camera to undo irlume's change is not a
    /// design.
    #[test]
    fn a_stream_mode_puts_the_control_back_when_it_ends() {
        let _lock = crate::testenv::env_lock();
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2], // the applied face-auth value
            len: 3,
            def: vec![1, 3, 1], // what "unset" restores to
            ..a_working_camera()
        });
        {
            let _mode = StreamMode {
                handle: None,
                record: None,
                _lock: None,
                unit: 14,
                selector: 6,
                restore: vec![1, 3, 1],
                applied: vec![1, 3, 2],
                armed: true,
                active: true,
            };
            assert_eq!(
                fake_camera::current(),
                vec![1, 3, 2],
                "nothing may be written while the stream is still running"
            );
        }
        assert_eq!(
            fake_camera::current(),
            vec![1, 3, 1],
            "the control must be back at the camera's default once the guard drops"
        );
    }

    /// A guard that never applied anything writes nothing when it ends.
    ///
    /// The ordinary case on hardware irlume does not drive. Restoring here would
    /// be a write to a camera that was never touched, which is the class of
    /// write this whole module exists to stop, and it would land on a camera
    /// that had just REFUSED a write.
    #[test]
    fn a_stream_mode_that_applied_nothing_writes_nothing() {
        let _lock = crate::testenv::env_lock();
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![9, 9, 9],
            len: 3,
            ..a_working_camera()
        });
        drop(StreamMode::inert());
        drop(StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: false,
            active: true,
        });
        assert_eq!(
            fake_camera::current(),
            vec![9, 9, 9],
            "an unarmed guard must not touch the control"
        );
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set { .. })),
            "no write may be issued at all: {:?}",
            fake_camera::log()
        );
    }

    /// Ownership of the restore does not pass to a guard that owns nothing.
    ///
    /// The frozen-stream restart replaces the guard after reopening. The control
    /// survives a stream close on both cameras here, so the replacement usually
    /// finds the value already in place and comes back ACTIVE while owning
    /// nothing. Deciding on `lit` handed ownership to it and disarmed the guard
    /// that actually held the change, and the capture then ended without putting
    /// the control back at all: the exact leak the restart logic exists to stop.
    #[test]
    fn ownership_of_the_restore_does_not_pass_to_a_guard_that_owns_nothing() {
        let held = StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        // What `enable` returns on a reopen when the control survived: active,
        // because the mode IS applied, and owning nothing, because it wrote
        // nothing.
        let already = StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: false,
            active: true,
        };
        assert!(already.lit(), "the mode is active on the reopened stream");
        assert!(
            !already.owns_restore(),
            "but it wrote nothing, so it owes no restore"
        );
        assert!(
            held.owns_restore(),
            "the original guard is the one holding the change"
        );
        // Deciding on `lit` would swap them, which is the defect.
        assert_ne!(
            already.lit(),
            already.owns_restore(),
            "lit and owns_restore must not be read as the same question"
        );
    }

    /// A non-default mode another program established is put back, not replaced
    /// by the camera's default.
    ///
    /// The guard used to record `GET_DEF`, reading Microsoft's "unset the
    /// control" as "write the default". That is identical to putting back what
    /// was displaced whenever the control sits at its default, which is the
    /// ordinary case, and wrong the moment it does not: a camera another program
    /// deliberately left in a non-default mode came back at the DEFAULT once
    /// irlume finished, destroying that program's state while this file promises
    /// the opposite.
    #[test]
    fn a_non_default_mode_is_put_back_rather_than_defaulted() {
        let _lock = crate::testenv::env_lock();
        let default = vec![1, 3, 1];
        let theirs = vec![1, 3, 4]; // somebody else's non-default mode
        let ours = vec![1, 3, 2];
        let _fake = fake_camera::install(fake_camera::Camera {
            current: theirs.clone(),
            len: 3,
            def: default.clone(),
            ..a_working_camera()
        });
        // The guard as `enable` now builds it: restore is what the control HELD,
        // not what the camera calls its default.
        let mut mode = StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: theirs.clone(),
            applied: ours.clone(),
            armed: true,
            active: true,
        };
        fake_camera::set_current(ours.clone());
        mode.restore().expect("restore");
        assert_eq!(
            fake_camera::current(),
            theirs,
            "the mode that was there must come back, not the camera's default"
        );
        assert_ne!(
            fake_camera::current(),
            default,
            "restoring the default here would destroy another program's state"
        );
    }
    /// A control somebody else moved during the stream is left where they put
    /// it.
    ///
    /// The guard knows what it wrote; that is not the same as knowing what the
    /// control holds when the stream ends. A vendor tool or another client can
    /// move it in between, and restoring on historical ownership alone would put
    /// the camera's default over their newer value. #183's recovery re-reads for
    /// exactly this reason; this is the same decision at a shorter range.
    #[test]
    fn a_control_moved_by_someone_else_is_not_restored_over() {
        let _lock = crate::testenv::env_lock();
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            len: 3,
            ..a_working_camera()
        });
        let mut mode = StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        // Another writer moves it while the stream is running.
        fake_camera::set_current(vec![1, 3, 3]);
        mode.restore()
            .expect("a refusal to overwrite is not an error");
        drop(mode);
        assert_eq!(
            fake_camera::current(),
            vec![1, 3, 3],
            "the other writer's value must be left exactly where they put it"
        );
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no SET_CUR may be issued at all: {:?}",
            fake_camera::log()
        );
    }
    /// Restoring twice writes once.    /// Restoring twice writes once.
    ///
    /// The ordinary path calls `restore` explicitly, so it can report a failure
    /// that `Drop` would have to swallow, and then the guard drops as well. The
    /// second visit must send nothing: a control already back where it started
    /// does not need writing again, and the camera has no way to tell a
    /// redundant write from a meaningful one.
    ///
    /// Found by a surviving mutant. `Drop` checks `armed` before it calls
    /// `restore`, so the identical check inside `restore` is unreachable through
    /// a drop and nothing exercised it.
    #[test]
    fn restoring_twice_writes_once() {
        let _lock = crate::testenv::env_lock();
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            len: 3,
            ..a_working_camera()
        });
        let mut mode = StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        mode.restore().expect("the first restore writes");
        let after_first = fake_camera::log()
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set { .. }))
            .count();
        assert_eq!(after_first, 1, "the first restore must write exactly once");

        mode.restore().expect("the second restore is a no-op");
        drop(mode);
        let total = fake_camera::log()
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set { .. }))
            .count();
        assert_eq!(
            total, 1,
            "restoring again, and then dropping, must send nothing further"
        );
        assert_eq!(fake_camera::current(), vec![1, 3, 1]);
    }

    /// An override the control already holds is not written, and not undone.
    ///
    /// `check_and_apply_override` answers success for a control found already
    /// at the requested payload, without sending anything. The guard used to
    /// arm on that success, so the end of the stream set the default over
    /// bytes irlume never wrote: state established by another process or a
    /// vendor tool. `enable` now arms only on `Applied::Wrote`, so the report
    /// has to say which kind of success this was.
    #[test]
    fn an_override_the_control_already_holds_is_not_written_or_undone() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-already-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _fake = fake_camera::install(fake_camera::Camera {
            // Some other tool already put the exact payload the override names
            // into the control.
            current: vec![1, 3, 2],
            ..a_working_camera()
        });
        let asus = identity(0x3277, 0x0059);

        let outcome = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]));
        let held = outcome
            .as_ref()
            .expect("a value found in place is a success");
        assert_eq!(
            held.outcome,
            Applied::AlreadyHeld,
            "a value found in place is a success, but not irlume's write"
        );
        assert_eq!(held.current, vec![1, 3, 2]);
        assert!(
            held.record.is_none(),
            "no write went out, so there is no leftover to record"
        );
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "a control already holding the payload needs no write: {:?}",
            fake_camera::log()
        );

        // The guard, armed the way `enable` arms it: only for `Wrote`. Its end
        // must leave the other writer's bytes exactly where they were.
        drop(StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: matches!(&outcome, Ok(w) if w.outcome == Applied::Wrote),
            // Active either way: the control holds the payload, whoever set it.
            active: matches!(&outcome, Ok(w) if w.outcome != Applied::Nothing),
        });
        assert_eq!(
            fake_camera::current(),
            vec![1, 3, 2],
            "the stream end must not put the default over a value irlume never set"
        );

        // The AlreadyHeld result above still holds the per-camera stream
        // lock; while it lives, a second apply on this camera runs unrecorded
        // by design. Release it before staging the write below.
        drop(outcome);

        // The distinction cuts the other way too: a control holding something
        // else IS written, and that write is irlume's to undo.
        fake_camera::set_current(vec![1, 3, 1]);
        let written = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("a control holding something else is written");
        assert_eq!(written.outcome, Applied::Wrote);
        assert_eq!(
            written.current,
            vec![1, 3, 1],
            "a write reports the value it displaced, read on the same pass"
        );
        assert!(
            written.record.is_some(),
            "a write that went out is covered by a leftover record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A built-in payload the control already holds is not written or claimed.
    ///
    /// The override path refuses to claim a value it did not set, and the
    /// built-in table path did not: it wrote unconditionally and armed, so a
    /// value another process left there was rewritten, claimed, and cleared at
    /// the end of the stream. Same rule, applied in one place and not the other.
    #[test]
    fn a_known_payload_the_control_already_holds_is_not_rewritten() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-known-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let payload = vec![1, 3, 2];
        let _fake = fake_camera::install(fake_camera::Camera {
            current: payload.clone(),
            len: 3,
            info: 0b0000_0011,
            ..a_working_camera()
        });
        let ctrl = EmitterControl {
            unit: 14,
            selector: 6,
            payload: payload.clone(),
        };
        assert_eq!(
            apply_known_payload(-1, &asus, &ctrl)
                .expect("a control that already agrees is not an error")
                .outcome,
            Applied::AlreadyHeld,
            "the value is there; irlume did not put it there"
        );
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may be sent at all: {:?}",
            fake_camera::log()
        );
        // And a control holding something else is still written, or the guard
        // above would have turned the whole path off.
        fake_camera::set_current(vec![9, 9, 9]);
        let written =
            apply_known_payload(-1, &asus, &ctrl).expect("a control that disagrees is written");
        assert_eq!(written.outcome, Applied::Wrote);
        assert_eq!(
            written.current,
            vec![9, 9, 9],
            "the write reports the value it displaced"
        );
        assert_eq!(fake_camera::current(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The apply path reads the control ONCE, and the value it reports as
    /// displaced is that read's answer.
    ///
    /// Two reads was the defect (#190): `enable` recorded an early `GET_CUR` as
    /// the guard's restore value while the apply path decided on a later one,
    /// so a writer landing between them had its value overwritten by the stale
    /// record when the stream ended. The FULL request order is asserted, so a
    /// second `GET_CUR` reappearing anywhere in the path fails here rather than
    /// reopening the window quietly.
    #[test]
    fn one_read_decides_and_its_answer_is_what_the_write_displaced() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-one-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![7, 7, 7],
            len: 3,
            info: 0b0000_0011,
            ..a_working_camera()
        });
        let asus = identity(0x3277, 0x0059);
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("a published control with a valid payload is applied");
        assert_eq!(write.outcome, Applied::Wrote);
        assert_eq!(
            write.current,
            vec![7, 7, 7],
            "the displaced value is the one read's answer"
        );
        assert_eq!(
            fake_camera::log(),
            vec![
                fake_camera::Request::Get {
                    query: UVC_GET_INFO,
                    size: 1,
                },
                fake_camera::Request::Get {
                    query: UVC_GET_LEN,
                    size: 2,
                },
                fake_camera::Request::Get {
                    query: UVC_GET_CUR,
                    size: 3,
                },
                fake_camera::Request::Set(vec![1, 3, 2]),
            ],
            "exactly one GET_CUR, immediately before the write it authorises"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Records left in the stream store, as (filename count, parsed records).
    fn stream_store_state(
        dir: &std::path::Path,
    ) -> (usize, Vec<crate::stream_record::StreamWrite>) {
        let store = dir.join("ir-emitter-stream");
        let Ok(entries) = std::fs::read_dir(&store) else {
            return (0, Vec::new());
        };
        let mut names = 0;
        let mut records = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            names += 1;
            if let Ok(body) = std::fs::read_to_string(&path) {
                if let Ok(record) = serde_json::from_str(&body) {
                    records.push(record);
                }
            }
        }
        (names, records)
    }

    /// The leftover record is on disk BEFORE the `SET_CUR` and gone once the
    /// guard resolves (#188).
    ///
    /// The before half is observed at the instant of the write, the only place
    /// that distinguishes record-then-write from write-then-record — checking
    /// afterwards cannot tell them apart, and the gap between them is the
    /// crash window the record exists to cover. Same construction as the #183
    /// journal's ordering test, for the same reason.
    #[test]
    fn the_record_is_on_disk_before_the_write_and_gone_after_the_restore() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let probe = dir.clone();
        let _fake = fake_camera::install(fake_camera::Camera {
            at_first_write: Some(Box::new(move || {
                let (names, records) = stream_store_state(&probe);
                if names != 1 {
                    return Err(format!(
                        "{names} records on disk at the first SET_CUR, want 1"
                    ));
                }
                let [record] = records.as_slice() else {
                    return Err("the record on disk does not parse".to_string());
                };
                if record.applied != "010302" || record.displaced != "010301" {
                    return Err(format!(
                        "the record says applied={} displaced={}, want 010302/010301",
                        record.applied, record.displaced
                    ));
                }
                if record.state != crate::stream_record::WriteState::Prepared {
                    return Err(format!(
                        "the record is {:?} at the instant of the write; nothing has \
                         confirmed yet, so it must be Prepared",
                        record.state
                    ));
                }
                Ok(())
            })),
            ..a_working_camera()
        });
        let asus = identity(0x3277, 0x0059);
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("a published control with a valid payload is applied");
        assert_eq!(write.outcome, Applied::Wrote);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::FailedPrecondition(_))),
            "the record was not on disk when the write went out: {:?}",
            fake_camera::log()
        );
        let (_, records) = stream_store_state(&dir);
        assert_eq!(
            records[0].state,
            crate::stream_record::WriteState::Applied,
            "once the camera accepted, the record must be confirmed"
        );
        // The guard, wired the way `enable` wires it, resolves the record when
        // it puts the control back.
        drop(StreamMode {
            handle: None,
            record: write.record,
            _lock: None,
            unit: 14,
            selector: 6,
            restore: write.current,
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        });
        assert_eq!(fake_camera::current(), vec![1, 3, 1], "the control is back");
        assert_eq!(
            stream_store_state(&dir).0,
            0,
            "a record must not outlive a cleanly ended stream"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A killed stream's leftover is claimed by the next session and restored,
    /// and a claim while the writer still lives is refused (#188).
    ///
    /// The crash is simulated by dropping the record handle without resolving
    /// it, which is byte-for-byte what `SIGKILL` leaves: the file on disk, the
    /// lock released. Before that drop, the claim must refuse — the lock is
    /// the liveness signal, and this is the same-process shape the frozen
    /// stream restart depends on.
    #[test]
    fn a_crash_leftover_is_claimed_and_the_next_session_restores_it() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-claim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _fake = fake_camera::install(a_working_camera());
        let asus = identity(0x3277, 0x0059);

        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("the mode is applied");
        assert_eq!(write.outcome, Applied::Wrote);
        let record = write.record.expect("the write is covered by a record");

        // While the writer lives, the stream lock cannot be taken, so no
        // claim can even begin: the control's value is a RUNNING stream's
        // business. `flock` excludes per open file description, so this holds
        // within one process too, which is what the frozen-stream restart
        // leans on.
        assert!(
            matches!(
                crate::stream_record::acquire(&asus),
                Err(crate::stream_record::AcquireError::Busy)
            ),
            "the stream lock must be refused as BUSY while its owner lives"
        );

        // The crash: lock released, file kept, control still holding the mode.
        drop(record);
        assert_eq!(fake_camera::current(), vec![1, 3, 2]);

        // The next session finds the value already in place and the record
        // marks it as irlume's own.
        let next = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("the next session reads the control");
        assert_eq!(next.outcome, Applied::AlreadyHeld);
        let lock = next
            .lock
            .expect("the dead stream's lock is free for the next session");
        let (restore, claimed) = crate::stream_record::claim(lock, &asus, 14, 6, &next.current)
            .expect("the leftover is irlume's and must be claimed");
        assert_eq!(
            restore,
            vec![1, 3, 1],
            "the claim hands back what the killed stream displaced"
        );
        drop(StreamMode {
            handle: None,
            record: Some(claimed),
            _lock: None,
            unit: 14,
            selector: 6,
            restore,
            applied: next.current,
            armed: true,
            active: true,
        });
        assert_eq!(
            fake_camera::current(),
            vec![1, 3, 1],
            "the next session finishes the restore the killed one could not"
        );
        assert_eq!(stream_store_state(&dir).0, 0, "the claim is resolved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A kill BETWEEN the record and the write forges no ownership (#188,
    /// review round 1). The prepared record's bytes can match a value another
    /// program deliberately sets LATER; restoring over that would be a
    /// firmware write on the strength of a write that never happened.
    #[test]
    fn a_record_without_a_confirmed_write_is_not_claimed() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-prepared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        // The kill: a prepared record hits the disk and its process dies
        // before the SET_CUR. No hardware effect exists.
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        drop(
            crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
                .expect("the prepared record is on disk"),
        );
        // Later, another program deliberately sets the exact same bytes.
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            ..a_working_camera()
        });
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("the control reads");
        assert_eq!(write.outcome, Applied::AlreadyHeld);
        let lock = write.lock.expect("the dead process's lock is free");
        assert!(
            crate::stream_record::claim(lock, &asus, 14, 6, &write.current).is_none(),
            "a prepared record matches these bytes and must still authorise nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The record is demoted BEFORE the restoring write, so a failed unlink
    /// afterwards leaves litter, never authority (#188, review round 2).
    #[test]
    fn the_record_is_demoted_before_the_restoring_write() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-demote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        let record = crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
            .expect("the record is on disk")
            .mark_applied()
            .expect("the write is confirmed");
        let probe = dir.clone();
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            // The restore is the only SET this test issues; at its instant
            // the record must already be non-authoritative.
            at_first_write: Some(Box::new(move || {
                let (_, records) = stream_store_state(&probe);
                match records.as_slice() {
                    [r] if r.state == crate::stream_record::WriteState::Prepared => Ok(()),
                    [r] => Err(format!(
                        "the record is {:?} at the restoring write",
                        r.state
                    )),
                    other => Err(format!("{} records on disk", other.len())),
                }
            })),
            ..a_working_camera()
        });
        drop(StreamMode {
            handle: None,
            record: Some(record),
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        });
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::FailedPrecondition(_))),
            "the record still authorised a restore at the instant of the write: {:?}",
            fake_camera::log()
        );
        assert_eq!(fake_camera::current(), vec![1, 3, 1], "the control is back");
        assert_eq!(
            stream_store_state(&dir).0,
            0,
            "the record is gone afterwards"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record that cannot be demoted blocks the restore entirely: restoring
    /// under an `applied` record reopens the round-2 hole, since a store that
    /// cannot take a rename will not take the unlink either (#188).
    #[test]
    fn a_record_that_cannot_be_retired_blocks_the_restore() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-block-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        let record = crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
            .expect("the record is on disk")
            .mark_applied()
            .expect("the write is confirmed");
        // Break the store: the retire's temp file has nowhere to go.
        std::fs::remove_dir_all(&dir).expect("clear the store");
        std::fs::write(&dir, b"not a directory").expect("plant a file at the store root");
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            ..a_working_camera()
        });
        let mut mode = StreamMode {
            handle: None,
            record: Some(record),
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        let result = mode.restore();
        assert!(
            matches!(result, Err(RestoreError::Bookkeeping(_))),
            "a restore that sends no camera request must not report success: {result:?}"
        );
        assert!(
            !mode.owns_restore(),
            "the failed attempt must not be repeated by Drop"
        );
        drop(mode);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "nothing may be restored under a record that cannot be demoted: {:?}",
            fake_camera::log()
        );
        assert_eq!(
            fake_camera::current(),
            vec![1, 3, 2],
            "the mode stays applied, for the next session to claim"
        );
        let _ = std::fs::remove_file(&dir);
    }

    /// A record whose confirmation failed must not BLOCK the restore when the
    /// store stays broken (#188, review round 10): it is already `prepared`
    /// on disk and in memory, authorises nothing, and retiring it needs no
    /// rewrite. The hardware cleanup proceeds.
    #[test]
    fn a_failed_confirmation_does_not_block_the_restore() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-noblock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        let record = crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
            .expect("the prepared record is on disk");
        // The store breaks between the write and its confirmation, and STAYS
        // broken through the stream's end.
        std::fs::remove_dir_all(&dir).expect("clear the store");
        std::fs::write(&dir, b"not a directory").expect("plant a file at the store root");
        let record = match record.mark_applied() {
            Ok(_) => panic!("the confirmation must fail on the broken store"),
            Err(e) => e.0,
        };
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            ..a_working_camera()
        });
        let mut mode = StreamMode {
            handle: None,
            record: Some(record),
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        mode.restore()
            .expect("an unconfirmed record must not block the hardware cleanup");
        assert_eq!(
            fake_camera::current(),
            vec![1, 3, 1],
            "the control is back despite the broken store"
        );
        let _ = std::fs::remove_file(&dir);
    }

    /// An UNRECORDED guard whose restore write fails surfaces the failure:
    /// the caller (the frozen-stream restart) must know, because nothing on
    /// disk marks the leftover and a swallowed error would strand it
    /// (review round 12).
    #[test]
    fn an_unrecorded_guards_failed_restore_reports_the_camera_error() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-unrec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            fail_set_from: Some((1, libc::EIO)),
            ..a_working_camera()
        });
        let mut mode = StreamMode {
            handle: None,
            record: None,
            _lock: Some(lock),
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        let result = mode.restore();
        assert!(
            matches!(result, Err(RestoreError::Camera(_))),
            "a rejected unrecorded restore must surface, not vanish: {result:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unreadable control at restore time authorises no write: the value
    /// there might be a third party's, set mid-stream, and writing blind
    /// would put the restore bytes over it (review round 13). The record is
    /// re-promoted so the change stays claimable.
    #[test]
    fn an_unreadable_control_is_not_blindly_restored() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-blind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        let record = crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
            .expect("the record is on disk")
            .mark_applied()
            .expect("the write is confirmed");
        let _fake = fake_camera::install(fake_camera::Camera {
            // A third party moved the control mid-stream...
            current: vec![7, 7, 7],
            ..a_working_camera()
        });
        // ...and the read-back fails transiently.
        fake_camera::fail_reads(libc::EIO);
        let mut mode = StreamMode {
            handle: None,
            record: Some(record),
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        let result = mode.restore();
        assert!(
            matches!(result, Err(RestoreError::Camera(_))),
            "an unverifiable restore must surface, not succeed: {result:?}"
        );
        drop(mode);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may go to a control that cannot be read: {:?}",
            fake_camera::log()
        );
        assert_eq!(
            fake_camera::current(),
            vec![7, 7, 7],
            "the third party's value survives"
        );
        let (_, records) = stream_store_state(&dir);
        assert_eq!(
            records[0].state,
            crate::stream_record::WriteState::Applied,
            "the change stays claimable for a session that CAN read the control"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restore the camera rejects puts the record back into force, so the
    /// still-real leftover stays claimable (#188).
    #[test]
    fn a_failed_restore_repromotes_the_record() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-repromote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        let record = crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
            .expect("the record is on disk")
            .mark_applied()
            .expect("the write is confirmed");
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            fail_set_from: Some((1, libc::EIO)),
            ..a_working_camera()
        });
        drop(StreamMode {
            handle: None,
            record: Some(record),
            _lock: None,
            unit: 14,
            selector: 6,
            restore: vec![1, 3, 1],
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        });
        let (names, records) = stream_store_state(&dir);
        assert_eq!(names, 1, "the record survives the failed restore");
        assert_eq!(
            records[0].state,
            crate::stream_record::WriteState::Applied,
            "the leftover is real again, so the record is back in force"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write contested by a LIVE irlume guard is refused outright, not made
    /// unrecorded (#188, review round 4). An unrecorded second write would
    /// make the owner's restore read the newcomer's bytes as another
    /// program's, discard the only record, and the newcomer would then
    /// restore the OWNER'S value instead of the original: the camera ends at
    /// a value neither stream found, with nothing left to say so.
    #[test]
    fn a_contested_write_is_refused_not_made_unrecorded() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-busy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        // The live owner, holding the camera's stream lock.
        let owner = crate::stream_record::acquire(&asus).expect("the lock is free");
        let _fake = fake_camera::install(a_working_camera());
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("a busy refusal is not an ioctl error");
        assert_eq!(write.outcome, Applied::Nothing);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may reach a camera a live guard owns: {:?}",
            fake_camera::log()
        );
        assert!(
            !fake_camera::log().iter().any(|r| matches!(
                r,
                fake_camera::Request::Get {
                    query: UVC_GET_CUR,
                    ..
                }
            )),
            "the control is not even read once the lock reports a live owner: {:?}",
            fake_camera::log()
        );
        drop(owner);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write must not destroy an applied record for a DIFFERENT control
    /// (#188, review round 5): the record path is per camera, and renaming a
    /// new record over a live one erases the only recovery data the old
    /// change has. The write is refused instead.
    #[test]
    fn a_write_never_destroys_a_live_record_for_another_control() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-cross-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        // A crash left an applied record for selector 6.
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        drop(
            crate::stream_record::save(lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
                .expect("the record is on disk")
                .mark_applied()
                .expect("the write is confirmed"),
        );
        // Configuration has moved on: the next capture drives selector 9.
        let _fake = fake_camera::install(a_working_camera());
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 9, vec![1, 3, 2]))
            .expect("the refusal is not an ioctl error");
        assert_eq!(write.outcome, Applied::Nothing);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may land while another control's record is outstanding: {:?}",
            fake_camera::log()
        );
        let (names, records) = stream_store_state(&dir);
        assert_eq!(names, 1, "the old record survives untouched");
        assert_eq!(
            (records[0].unit, records[0].selector, records[0].state),
            (14, 6, crate::stream_record::WriteState::Applied),
            "selector 6's recovery data is intact"
        );

        // The same protection for the SAME control while its leftover is
        // live: the control still holds the old applied bytes, and a write
        // of different bytes would orphan them.
        fake_camera::set_current(vec![1, 3, 2]);
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 3]))
            .expect("the refusal is not an ioctl error");
        assert_eq!(write.outcome, Applied::Nothing);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "the live leftover's bytes are still in the control: {:?}",
            fake_camera::log()
        );

        // But a SUPERSEDED record (its bytes no longer in the control) is
        // replaced freely: the leftover it described is already gone.
        fake_camera::set_current(vec![9, 9, 9]);
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 3]))
            .expect("a superseded record does not block");
        assert_eq!(write.outcome, Applied::Wrote);
        let (_, records) = stream_store_state(&dir);
        assert_eq!(
            (records[0].selector, records[0].applied.as_str()),
            (6, "010303"),
            "the superseded record is replaced by the new write's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Plant a record through `save` and hand back its file path.
    fn plant_record(
        dir: &std::path::Path,
        id: &crate::uvc_descriptor::CameraIdentity,
        unit: u8,
        selector: u8,
        applied: &[u8],
        displaced: &[u8],
        confirmed: bool,
    ) -> std::path::PathBuf {
        let lock = crate::stream_record::acquire(id).expect("the lock is free");
        let record = crate::stream_record::save(lock, id, unit, selector, applied, displaced)
            .expect("plant a record");
        if confirmed {
            drop(record.mark_applied().expect("confirm the planted record"));
        } else {
            drop(record);
        }
        std::fs::read_dir(dir.join("ir-emitter-stream"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .expect("the planted record file")
    }

    /// Bookkeeping failure must not release the stream lock while the write
    /// it covers is live (#188, review round 5): the lock comes back from a
    /// failed save, rides the guard bare, and a failed confirmation keeps
    /// the record handle rather than dropping it.
    #[test]
    fn a_failed_save_keeps_the_lock_held_for_the_streams_lifetime() {
        // Staged via an UNREADABLE record file (EACCES), which is machine
        // trouble rather than a protected record. Meaningless as root, where
        // mode 000 still reads.
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: running as root, mode 000 does not refuse reads");
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-keeplock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let record_file = plant_record(&dir, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1], false);
        std::fs::set_permissions(&record_file, std::fs::Permissions::from_mode(0o000))
            .expect("make the record unreadable");

        let _fake = fake_camera::install(a_working_camera());
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("an unavailable store does not refuse the write");
        assert_eq!(
            write.outcome,
            Applied::Wrote,
            "machine trouble costs bookkeeping, not authentication"
        );
        assert!(write.record.is_none(), "nothing was recorded");
        assert!(
            write.lock.is_some(),
            "the lock must ride the unrecorded write for the stream's lifetime"
        );
        assert!(
            matches!(
                crate::stream_record::acquire(&asus),
                Err(crate::stream_record::AcquireError::Busy)
            ),
            "no second irlume may take the camera while the unrecorded change lives"
        );
        // The lock must also release on an EXPLICIT restore, before the guard
        // itself drops: the frozen-stream restart calls restore() and then
        // runs a fresh enable while the old guard still exists, and a
        // retained bare lock made that enable refuse against its own
        // predecessor (review round 9).
        let mut mode = StreamMode {
            handle: None,
            record: None,
            _lock: write.lock,
            unit: 14,
            selector: 6,
            restore: write.current,
            applied: vec![1, 3, 2],
            armed: true,
            active: true,
        };
        mode.restore().expect("the unrecorded change restores");
        assert!(
            crate::stream_record::acquire(&asus).is_ok(),
            "an explicitly restored guard must release its bare lock before \
             the replacement enable runs"
        );
        drop(mode);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `prepared` record whose write may have SUCCEEDED is protected from
    /// replacement (#188, review round 7): a crash between the `SET_CUR` and
    /// the confirmation leaves `prepared` on disk with the applied bytes in
    /// the control, and its displaced value is the only route back.
    /// "Authorises nothing" never meant "may be destroyed".
    #[test]
    fn a_prepared_record_whose_bytes_are_live_is_not_written_over() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-gap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        // The crash-in-the-gap shape: prepared record, applied bytes ON the
        // camera (the SET_CUR landed, the confirmation did not).
        let record_file = plant_record(&dir, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1], false);
        let before = std::fs::read(&record_file).expect("the planted record");
        let _fake = fake_camera::install(fake_camera::Camera {
            current: vec![1, 3, 2],
            ..a_working_camera()
        });
        // A later configuration wants different bytes on the same control.
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 3]))
            .expect("the refusal is not an ioctl error");
        assert_eq!(write.outcome, Applied::Nothing);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may stack on an unresolved change: {:?}",
            fake_camera::log()
        );
        assert_eq!(
            std::fs::read(&record_file).expect("still there"),
            before,
            "the gap record survives byte-for-byte"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record from a build with another schema is never written over
    /// (#188, review round 7): this build cannot know what it describes, and
    /// the claim path already refuses to act on it for the same reason.
    #[test]
    fn a_foreign_schema_record_is_not_written_over() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-schema-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let record_file = plant_record(&dir, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1], true);
        // A newer build's record: same shape, schema 2.
        let body = std::fs::read_to_string(&record_file).unwrap();
        let newer = body.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
        assert_ne!(body, newer, "the schema field must have been rewritten");
        std::fs::write(&record_file, &newer).unwrap();
        let _fake = fake_camera::install(a_working_camera());
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("the refusal is not an ioctl error");
        assert_eq!(write.outcome, Applied::Nothing);
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "no write may destroy recovery data this build cannot read: {:?}",
            fake_camera::log()
        );
        assert_eq!(
            std::fs::read_to_string(&record_file).expect("still there"),
            newer,
            "the foreign record survives byte-for-byte"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A value somebody else set is left alone: same bytes, no record, no
    /// claim, no write (#188).
    #[test]
    fn a_value_someone_else_set_is_not_claimed() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-other-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _fake = fake_camera::install(fake_camera::Camera {
            // Another tool already established the exact wanted value.
            current: vec![1, 3, 2],
            ..a_working_camera()
        });
        let asus = identity(0x3277, 0x0059);
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("the control reads");
        assert_eq!(write.outcome, Applied::AlreadyHeld);
        let lock = write.lock.expect("no other guard lives, the lock is free");
        assert!(
            crate::stream_record::claim(lock, &asus, 14, 6, &write.current).is_none(),
            "no record exists, so these bytes are another writer's state"
        );
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "nothing may be written to a control irlume never changed: {:?}",
            fake_camera::log()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Each claim spends one counted attempt, and the fourth is refused (#188).
    ///
    /// Simulates a control that keeps reading back as irlume's leftover no
    /// matter how many restores land — the pathology the counter exists for:
    /// without it, every stream open would send one more firmware write,
    /// forever.
    #[test]
    fn a_leftover_that_never_resolves_stops_being_claimed_after_three_attempts() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let asus = identity(0x3277, 0x0059);
        let seed_lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        crate::stream_record::save(seed_lock, &asus, 14, 6, &[1, 3, 2], &[1, 3, 1])
            .expect("seed the leftover")
            .mark_applied()
            .expect("the seed write is confirmed")
            // The seeding "stream" dies without resolving: the drop releases
            // the lock and keeps the file.
            ;
        for attempt in 1..=crate::stream_record::MAX_RESTORE_ATTEMPTS {
            let lock = crate::stream_record::acquire(&asus)
                .unwrap_or_else(|_| panic!("the lock is free before claim {attempt}"));
            let (restore, record) = crate::stream_record::claim(lock, &asus, 14, 6, &[1, 3, 2])
                .unwrap_or_else(|| panic!("claim {attempt} is within the limit"));
            // Every restore is ATTEMPTED and rejected by the camera: the
            // attempt is spent in retire()'s pre-write publication, the
            // SET_CUR fails, and the re-promotion puts the record back in
            // force for the next round. A claim abandoned without a restore
            // attempt spends nothing (review round 11).
            let _fake = fake_camera::install(fake_camera::Camera {
                current: vec![1, 3, 2],
                fail_set_from: Some((1, libc::EIO)),
                ..a_working_camera()
            });
            drop(StreamMode {
                handle: None,
                record: Some(record),
                _lock: None,
                unit: 14,
                selector: 6,
                restore,
                applied: vec![1, 3, 2],
                armed: true,
                active: true,
            });
            let (_, records) = stream_store_state(&dir);
            assert_eq!(
                records[0].restore_attempts, attempt,
                "the attempt is counted on disk in the step before the write"
            );
            assert_eq!(
                records[0].state,
                crate::stream_record::WriteState::Applied,
                "the failed restore re-promotes the record for the next round"
            );
        }
        let lock = crate::stream_record::acquire(&asus).expect("the lock is free");
        assert!(
            crate::stream_record::claim(lock, &asus, 14, 6, &[1, 3, 2]).is_none(),
            "the fourth claim is refused: the control never resolves and \
             writing again is the loop the counter stops"
        );
        assert_eq!(
            stream_store_state(&dir).0,
            1,
            "the spent record stays for a human, like the journal's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `SET_CUR` the camera rejects leaves no record behind (#188): the
    /// record would describe a change that never happened.
    #[test]
    fn a_rejected_write_leaves_no_record() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-rec-reject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _env = EnvGuard::set("IRLUME_STATE_DIR", &dir);
        let _fake = fake_camera::install(fake_camera::Camera {
            fail_set_from: Some((1, libc::EIO)),
            ..a_working_camera()
        });
        let asus = identity(0x3277, 0x0059);
        let write = check_and_apply_override(-1, &asus, &ctrl(14, 6, vec![1, 3, 2]))
            .expect("the checks pass; only the write is rejected");
        assert_eq!(write.outcome, Applied::Nothing);
        assert!(write.record.is_none());
        assert_eq!(
            stream_store_state(&dir).0,
            0,
            "a record must not describe a write the camera refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IR Torch's applied value IS the camera's default, so there is nothing
    /// for the stream end to restore.
    ///
    /// `intended_value` derives the torch payload from `GET_DEF`, which is the
    /// exact value the guard writes back. Arming on it made every stream end
    /// send a `SET_CUR` that changed nothing: one pointless firmware write per
    /// capture. `apply_device_default` reports the bytes it wrote so `enable`
    /// can see they equal the restore and leave the guard unarmed.
    #[test]
    fn applying_the_ir_torch_default_leaves_nothing_to_restore() {
        let _lock = crate::testenv::env_lock();
        let def = torch(2, 120); // ON, at a power inside the reported range
        let _fake = fake_camera::install(fake_camera::Camera {
            current: def.clone(),
            len: 8,
            // Exactly GET_CUR + SET_CUR, as the specification pins IR Torch.
            info: 3,
            def: def.clone(),
            min: torch(0, 10),
            max: torch(0b011, 200),
            res: torch(0, 1),
            ..Default::default()
        });

        let asus = identity(0x3277, 0x0059);
        let (write, sent) =
            apply_device_default(-1, &asus, 14, crate::uvc_descriptor::MSXU_IR_TORCH)
                .expect("a conformant torch takes its own default");
        assert_eq!(sent, def, "the applied bytes are the camera's own GET_DEF");
        // The fixture starts at the default, so there is nothing to write: the
        // torch's own value IS the default, which is the point of the case.
        assert_eq!(
            write.outcome,
            Applied::AlreadyHeld,
            "a control already at the value it wants is not written again"
        );

        // The guard, armed the way `enable` arms it: the write went out, but
        // it carried the restore bytes, so nothing is outstanding.
        drop(StreamMode {
            handle: None,
            record: None,
            _lock: None,
            unit: 14,
            selector: crate::uvc_descriptor::MSXU_IR_TORCH,
            restore: def.clone(),
            applied: vec![1, 3, 2],
            armed: write.outcome == Applied::Wrote,
            // The torch IS on: its default is an active mode. Active without
            // being armed is exactly the pair this field exists to separate.
            active: true,
        });
        let sets = fake_camera::log()
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set(_)))
            .count();
        assert_eq!(
            sets, 0,
            "the torch's own default was already there, so applying it writes \
             nothing and the stream's end has nothing to put back"
        );
    }

    /// Somebody else moves the control while setup is measuring, and setup
    /// notices BEFORE it writes.
    ///
    /// `original` is read, then `intended_value` runs, then a whole baseline
    /// frame measurement, then the record's create/write/fsync/rename/fsync. The
    /// per-camera flock excludes other irlume processes and nothing else, so a
    /// vendor tool can move the control anywhere inside that window. Recording a
    /// value that is no longer there means the eventual restore writes bytes
    /// irlume never found on this camera, which is the one thing the rest of
    /// this file promises not to do. Recovery already re-read for exactly this
    /// reason; discovery did not.
    #[test]
    fn discovery_refuses_when_the_control_moved_while_it_was_measuring() {
        let _lock = crate::testenv::env_lock();
        let camera = fake_camera::Camera {
            // The first GET_CUR answers [1,3,1] and THEN the control moves, so
            // the re-read immediately before the write is what sees it.
            change_after_gets: Some((1, vec![1, 3, 3])),
            ..a_working_camera()
        };
        let (outcome, log, current, dir) =
            run_discovery(camera, "moved-while-measuring", || Some(50.0));

        match outcome {
            Ok(Attempt::NotUsable(why)) => {
                assert!(
                    why.contains("changed while setup was measuring"),
                    "the refusal must name what happened, got: {why}"
                );
                assert!(
                    why.contains("nothing was sent"),
                    "and must say the camera was left alone, got: {why}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // The whole point: not one byte reached the camera.
        assert!(
            !log.iter()
                .any(|r| matches!(r, fake_camera::Request::Set { .. })),
            "nothing may be written once the control is known to have moved: {log:?}"
        );
        assert_eq!(
            current,
            vec![1, 3, 3],
            "the other writer's value must be left exactly as it was found"
        );
        // The re-read has to have actually happened, or this passed for the
        // wrong reason.
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
        // And the record is gone, because nothing was written: leaving it would
        // make the next run refuse this camera over a change never made.
        let store = dir.join("ir-emitter-journal");
        let left: Vec<_> = std::fs::read_dir(&store)
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(
            left.is_empty(),
            "no camera write happened, so no undo record may survive: {left:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The pre-write guard refusing before the FIRST exploratory write ends the
    /// run with the guard's reason and zero bytes sent (#193 review: the early
    /// privacy sample alone left the whole pipeline as a check-to-write window).
    #[test]
    fn a_guard_refusal_before_the_first_write_sends_nothing() {
        let _lock = crate::testenv::env_lock();
        let (outcome, log, current, dir) = run_discovery_guarded(
            a_working_camera(),
            "guard-first",
            || Some(50.0),
            || Err("the hardware privacy shutter is engaged".to_string()),
        );
        assert!(
            matches!(&outcome, Err(TryFailure::Guard(why)) if why.contains("engaged")),
            "the refusal must carry the guard's reason: {outcome:?}"
        );
        assert!(
            !log.iter()
                .any(|r| matches!(r, fake_camera::Request::Set { .. })),
            "a refused run may not write: {log:?}"
        );
        assert_eq!(current, vec![1, 3, 1], "the control is untouched");
        let left: Vec<_> = std::fs::read_dir(dir.join("ir-emitter-journal"))
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(
            left.is_empty(),
            "nothing was written, so no undo record may survive: {left:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The guard is consulted before EACH forward write, not once: a refusal
    /// arriving between the restore and the final re-apply leaves the control
    /// at its original value, with the record resolved and exactly the two
    /// writes of the measurement (apply, restore) on the wire.
    #[test]
    fn a_guard_refusal_before_the_final_write_leaves_the_control_restored() {
        let _lock = crate::testenv::env_lock();
        let mut readings = [10.0, 40.0, 10.0].into_iter();
        let mut calls = 0;
        let (outcome, log, current, dir) = run_discovery_guarded(
            a_working_camera(),
            "guard-final",
            || readings.next(),
            || {
                calls += 1;
                if calls == 1 {
                    Ok(())
                } else {
                    Err("the hardware privacy shutter is engaged".to_string())
                }
            },
        );
        assert!(
            matches!(&outcome, Err(TryFailure::Guard(why)) if why.contains("engaged")),
            "the second consultation must be able to refuse: {outcome:?}"
        );
        let sets: Vec<_> = log
            .iter()
            .filter(|r| matches!(r, fake_camera::Request::Set { .. }))
            .collect();
        assert_eq!(
            sets.len(),
            2,
            "exactly the measurement's apply and restore, nothing after the refusal: {log:?}"
        );
        assert_eq!(current, vec![1, 3, 1], "the control ends where it began");
        let left: Vec<_> = std::fs::read_dir(dir.join("ir-emitter-journal"))
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(
            left.is_empty(),
            "the restore was confirmed, so the record must be resolved: {left:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Recovering a MISFILED record leaves exactly one file behind, and then
    /// none.
    ///
    /// The attempt counter is written before the restoring write. Deriving that
    /// path from the record's contents put the incremented copy in a SECOND
    /// file, and the clear afterwards removed only the one that was read — two
    /// records for one operation, the survivor pending forever. The earlier
    /// misfiled test only reached the already-restored branch and never took
    /// this one.
    #[test]
    fn recovering_a_misfiled_record_leaves_no_duplicate() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-misfiled-attempt");
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

        let record = crate::emitter_journal::PendingWrite {
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
        };
        // Deliberately NOT under the name its own fields produce.
        let store = dir.join("ir-emitter-journal");
        std::fs::create_dir_all(&store).expect("store");
        let misfiled =
            store.join("1111111111111111111111111111111111111111111111111111111111111111.json");
        std::fs::write(
            &misfiled,
            serde_json::to_string(&record).expect("serialize"),
        )
        .expect("plant");

        // The control still holds this run's exploratory value, so recovery
        // takes the counting-and-restoring branch rather than already-restored.
        let camera = fake_camera::Camera {
            current: vec![1, 3, 2],
            ..a_working_camera()
        };
        let _fake = fake_camera::install(camera);

        let outcome = recover_pending_write(-1, &id);
        assert!(
            matches!(outcome, RecoveryOutcome::Restored { .. }),
            "the restoring branch must be the one taken: {outcome:?}"
        );
        let left = std::fs::read_dir(&store)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            left, 0,
            "one operation must not leave a second record behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refusal that writes nothing does not spend an attempt.
    ///
    /// The counter is incremented before the write so a kill during the write is
    /// counted. But the re-read that follows can refuse, and then nothing was
    /// written: three such passes would exhaust the budget and leave the emitter
    /// off for good over writes that never happened. The count goes back.
    #[test]
    fn a_refusal_that_writes_nothing_gives_the_attempt_back() {
        let _lock = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join("irlume-attempt-giveback");
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

        let record = crate::emitter_journal::PendingWrite {
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
        };
        let path = crate::emitter_journal::save(&record).expect("plant");

        // Authorises on the first read, then something else moves the control
        // before the re-read.
        let camera = fake_camera::Camera {
            current: vec![1, 3, 2],
            change_after_gets: Some((1, vec![1, 3, 3])),
            ..a_working_camera()
        };
        let _fake = fake_camera::install(camera);

        let outcome = recover_pending_write(-1, &id);
        assert!(
            matches!(outcome, RecoveryOutcome::Unresolved(_)),
            "{outcome:?}"
        );
        assert!(
            !fake_camera::log()
                .iter()
                .any(|r| matches!(r, fake_camera::Request::Set(_))),
            "nothing was written, so nothing should have been spent"
        );

        let after: crate::emitter_journal::PendingWrite =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read back"))
                .expect("parse");
        assert_eq!(
            after.restore_attempts, 0,
            "an attempt that wrote nothing must be given back"
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

    /// A real `Arc<Handle>` over a node that is not a UVC camera.
    ///
    /// `Device::with_path` is a plain `open(2)` with no ioctl, so `/dev/null`
    /// serves. The point is the TYPE: `enable` no longer accepts a bare
    /// integer, so a test reaches it the same way production does, through a
    /// handle that keeps the descriptor alive.
    fn non_uvc_handle() -> std::sync::Arc<v4l::device::Handle> {
        v4l::Device::with_path("/dev/null")
            .expect("open /dev/null")
            .handle()
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
        let h = non_uvc_handle();

        // `off`/`none` disable before any control lookup or ioctl.
        std::env::set_var("IRLUME_IR_EMITTER", "off");
        assert!(!enable(h.clone(), "ASUS", DEV).lit());
        std::env::set_var("IRLUME_IR_EMITTER", "none");
        assert!(!enable(h.clone(), "ASUS", DEV).lit());
        // A valid env control is parsed, but SET_CUR on a non-UVC fd fails.
        std::env::set_var("IRLUME_IR_EMITTER", "14:6:1,3,2");
        assert!(!enable(h.clone(), "whatever", DEV).lit());
        std::env::remove_var("IRLUME_IR_EMITTER");
        // The card string is no longer consulted at all; identity comes from
        // the USB IDs, and DEV does not exist, so nothing is applied.
        assert!(!enable(h.clone(), "Some Unknown Cam", DEV).lit());
        // A table entry now requires the USB identity to match AND the
        // descriptor to confirm the unit, neither of which a fake path offers.
        assert!(!enable(h.clone(), "ASUS", DEV).lit());
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
        assert!(!enable(h.clone(), "Some Unknown Cam", DEV).lit());

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
        let mut permit = || Ok(());
        let err = discover(
            std::os::fd::AsRawFd::as_raw_fd(&f),
            &no_ms,
            &mut measure,
            &mut permit,
        )
        .unwrap_err();
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
            check_and_apply_override(-1, &asus, &ctrl(3, 1, vec![255])).unwrap_err(),
            OverrideRefusal::NoSuchUnit {
                unit: 3,
                seen: vec![11, 10, 14]
            }
        );
        assert_eq!(
            check_and_apply_override(-1, &asus, &ctrl(14, 10, vec![0; 4])).unwrap_err(),
            OverrideRefusal::NotAdvertised {
                unit: 14,
                selector: 10
            }
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
        use std::sync::atomic::Ordering::SeqCst;

        let _g = env_guard();
        let h = non_uvc_handle();
        std::env::set_var("IRLUME_IR_EMITTER", "14:6:1,3,2,0,0,0,0,0,0");
        let before = writes_attempted().load(SeqCst);
        let applied = enable(h, "ASUS FHD webcam", "/dev/irlume-test-missing");
        let sent = writes_attempted().load(SeqCst) - before;
        std::env::remove_var("IRLUME_IR_EMITTER");

        assert!(!applied.lit());
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
        assert_eq!(
            answer.outcome,
            Applied::Nothing,
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
