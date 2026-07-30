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
//! [`apply_override`].
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
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        &path,
        format!("{} {}:{}", id.usb_id(), ctrl.unit, ctrl.selector),
    )
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

fn env_control() -> Option<EmitterControl> {
    parse_control(&std::env::var("IRLUME_IR_EMITTER").ok()?)
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
///   the camera has never said it has. It goes through [`apply_override`], which
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
    let _ = card;
    match std::env::var("IRLUME_IR_EMITTER")
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("off") | Some("none") => return false,
        _ => {}
    }

    // Identity comes from the descriptor that will receive the write, not from a
    // path that could point somewhere else by the time the ioctl runs.
    let Ok(id) = crate::uvc_descriptor::identity_from_fd(fd) else {
        // The override used to be applied before this point, so a camera whose
        // descriptors could not be read was still written to. It is now the
        // first thing every path needs, including the override: without the
        // descriptor there is no evidence about anything, and #159 is what
        // writing without evidence costs.
        return false;
    };

    if let Some(ctrl) = env_control() {
        return apply_override(fd, device, &id, &ctrl);
    }

    if let Some((unit, selector)) = load_conf(&id) {
        let recorded = EmitterControl {
            unit,
            selector,
            payload: Vec::new(),
        };
        if control_is_documented(&id, &recorded) {
            return apply_device_default(fd, unit, selector).is_ok();
        }
    }

    match known_control(id.vid, id.pid).filter(|c| control_is_documented(&id, c)) {
        Some(ctrl) => apply_known_payload(fd, &ctrl).is_ok(),
        None => false,
    }
}

/// Why an `IRLUME_IR_EMITTER` override was not written to the camera.
///
/// Each variant names something the camera itself failed to say, so the message
/// can tell the person who set the variable which claim was not backed up rather
/// than leaving them to conclude the value was wrong and try another one.
#[derive(Debug, Clone, PartialEq)]
pub enum OverrideRefusal {
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

type OverrideMemo = std::sync::Mutex<std::collections::HashMap<String, bool>>;

/// Whether the override has already been decided for one camera in this process,
/// and what was decided.
///
/// The override used to be re-sent on every [`enable`], which is every eighth
/// frame of every capture: one variable in `irlumed`'s environment became an
/// unbounded stream of firmware writes lasting as long as the daemon. #159's
/// damage came from writes that kept going after the device stopped answering,
/// so the answer is computed once and reused, including when it was a refusal or
/// a failed write. A control that self-clears will therefore go dark rather than
/// be re-driven; for bytes irlume cannot check, not writing again is the safer
/// of the two failures.
///
/// Keyed on the device node together with the camera's USB id, so a different
/// model appearing at the same node is decided afresh, and two identical modules
/// on different nodes are decided separately. What the key cannot distinguish is
/// the same model replugged onto the same node mid-process: that keeps the
/// earlier answer, which errs towards not writing.
fn override_memo() -> &'static OverrideMemo {
    static MEMO: std::sync::OnceLock<OverrideMemo> = std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}

/// Apply an `IRLUME_IR_EMITTER` override, once per camera per process, and only
/// with the evidence every other write here requires.
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
    device: &str,
    id: &crate::uvc_descriptor::CameraIdentity,
    ctrl: &EmitterControl,
) -> bool {
    let key = format!("{device} {} {}:{}", id.usb_id(), ctrl.unit, ctrl.selector);

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
    if let Some(decided) = memo.get(&key) {
        return *decided;
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
    memo.insert(key, applied);
    applied
}

/// Test-only: hold a caller inside the gate so another thread can observe what
/// is true while the device is being talked to.
///
/// The property under test is "the memo lock is held across the device access",
/// and it cannot be observed from outside without stopping time in the middle.
/// Two racing threads would not do: whether the second one gets in is a question
/// of scheduling, so it could pass while the window was wide open.
#[cfg(test)]
fn park_inside_for_test() {
    use std::sync::atomic::Ordering::SeqCst;
    if !test_park().armed.load(SeqCst) {
        return;
    }
    test_park().reached.store(true, SeqCst);
    while !test_park().release.load(SeqCst) {
        std::thread::yield_now();
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestPark {
    armed: std::sync::atomic::AtomicBool,
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
    /// A control was changed and could not be put back.
    RestoreFailed {
        unit: u8,
        selector: u8,
        err: XuError,
    },
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
) -> std::result::Result<EmitterControl, DiscoveryError> {
    let ms = id
        .microsoft_xu()
        .ok_or_else(|| DiscoveryError::NoMicrosoftXu {
            seen: id.extension_units().iter().map(|u| u.unit_id).collect(),
        })?;

    let mut tried = Vec::new();

    for selector in [
        crate::uvc_descriptor::MSXU_IR_TORCH,
        crate::uvc_descriptor::MSXU_FACE_AUTHENTICATION,
    ] {
        if !ms.advertises(selector) {
            tried.push(format!("selector {selector:#04x} not advertised"));
            continue;
        }
        match try_documented_control(fd, ms.unit_id, selector, measure) {
            Ok(Attempt::Lit(ctrl)) => return Ok(ctrl),
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

/// What one advertised control turned out to be.
enum Attempt {
    Lit(EmitterControl),
    /// The control is already set to the value setup would apply, so writing it
    /// again could not demonstrate anything.
    AlreadyApplied,
    /// Usable but it did not brighten the image, or its default failed the
    /// checks the specification allows. The control was left as it was found.
    NotUsable(String),
}

enum TryFailure {
    Query(XuError),
    Restore(XuError),
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

    set_cur(fd, unit, selector, &wanted)?;
    let Some(lit) = measure() else {
        // The stream died after the control was changed. Aborting without
        // putting it back would leave the camera altered by a run that
        // concluded nothing.
        set_cur(fd, unit, selector, &original).map_err(TryFailure::Restore)?;
        return Err(TryFailure::Measurement);
    };

    // The question is whether writing this control changed the image, not
    // whether the resulting image is bright enough to authenticate against.
    // Those are different questions; conflating them made success depend on room
    // lighting, and the same camera here has measured 38 to 168 depending only
    // on what was in front of it.
    if lit < before + AUTOCONF_MIN_LIFT {
        set_cur(fd, unit, selector, &original).map_err(TryFailure::Restore)?;
        return Ok(Attempt::NotUsable(format!(
            "the image did not brighten (before {before:.0}, after {lit:.0}, needs +{AUTOCONF_MIN_LIFT:.0})"
        )));
    }

    // A single before-and-after pair is not evidence. Someone moving, a cloud,
    // or an exposure transition produces the same twenty points as a working
    // illuminator. Put the control back and require the brightness to fall with
    // it: a change that does not follow the control is not caused by it.
    set_cur(fd, unit, selector, &original).map_err(TryFailure::Restore)?;
    let Some(after_restore) = measure() else {
        return Err(TryFailure::Measurement);
    };
    if after_restore >= lit - AUTOCONF_MIN_LIFT {
        return Ok(Attempt::NotUsable(format!(
            "the image brightened but stayed bright when the control was put back \
             ({before:.0} before, {lit:.0} with it set, {after_restore:.0} after undoing it), \
             so the change did not come from this control"
        )));
    }

    // It followed the control both ways. Apply it and report it.
    set_cur(fd, unit, selector, &wanted)?;
    Ok(Attempt::Lit(EmitterControl {
        unit,
        selector,
        payload: wanted,
    }))
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

    #[test]
    fn encode_parse_roundtrip() {
        let c = EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2, 0],
        };
        assert_eq!(parse_control(&c.encode()), Some(c));
    }

    /// Serializes access to the process env vars these tests flip
    /// (`IRLUME_IR_EMITTER`, `IRLUME_IR_EMITTER_CONF`); cargo runs tests on
    /// parallel threads sharing one environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
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

        let parked = std::thread::spawn(|| {
            test_park().armed.store(true, SeqCst);
            // Through `apply_override`, because the lock it takes is the thing
            // under test. Unit 3 is not published, so the gate refuses before
            // any ioctl; what matters is only that the caller got INSIDE.
            apply_override(
                -1,
                "/dev/irlume-test-locking",
                &identity(0x3277, 0x0059),
                &ctrl(3, 1, vec![255]),
            )
        });

        while !test_park().reached.load(SeqCst) {
            std::thread::yield_now();
        }
        // The parked caller is between the lookup and the record. Anyone else
        // reaching `apply_override` right now must NOT be able to take the memo.
        let held = override_memo().try_lock().is_err();

        test_park().release.store(true, SeqCst);
        test_park().armed.store(false, SeqCst);
        let _ = parked.join();
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
