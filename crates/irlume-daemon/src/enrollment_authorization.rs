// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-request OS authorization before trusted templates can be added.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use dbus::arg::{PropMap, Variant};
use dbus::channel::Channel;
use dbus::Message;
use irlume_common::Request;

use super::{peer_gone, posture, uid_of, EnrollmentEffect, Peer};

const ACTION: &str = "org.irlume.enroll";
const AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const OBJECT: &str = "/org/freedesktop/PolicyKit1/Authority";
const INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const APPROVAL_BUDGET: Duration = Duration::from_secs(60);
const QUEUE_FRESHNESS: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(100);
const REFUSED: &str = "enrollment requires OS authorization; approve the system dialog or register a terminal agent with pkttyagent";

pub(super) fn required(req: &Request, peer: &Peer) -> bool {
    peer.uid != 0 && posture(req).enrollment == EnrollmentEffect::AddsTrust
}

/// An open proc directory keeps lookups on the original process even if its
/// numeric PID is reused. Every read also checks for exit and UID changes.
struct Subject {
    directory: File,
    pid: u32,
    uid: u32,
    start: u64,
}

impl Subject {
    fn capture(peer: &Peer) -> Result<Self, String> {
        let pid = u32::try_from(peer.pid)
            .ok()
            .filter(|pid| *pid != 0)
            .ok_or(REFUSED)?;
        i32::try_from(peer.uid).map_err(|_| REFUSED)?;
        let directory = File::open(format!("/proc/{pid}")).map_err(|_| REFUSED)?;
        let mut subject = Self {
            directory,
            pid,
            uid: peer.uid,
            start: 0,
        };
        subject.start = subject.current_start()?;
        subject.validate(peer)?;
        Ok(subject)
    }

    fn read(&self, name: &std::ffi::CStr) -> Result<String, String> {
        // SAFETY: directory is a live owned descriptor; name is a fixed,
        // NUL-terminated relative filename. A successful fd is owned below.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(REFUSED.into());
        }
        // SAFETY: openat returned a fresh descriptor; File takes ownership once.
        let file = unsafe { File::from_raw_fd(fd) };
        let mut text = String::new();
        file.take(16 * 1024)
            .read_to_string(&mut text)
            .map_err(|_| REFUSED)?;
        Ok(text)
    }

    fn current_start(&self) -> Result<u64, String> {
        parse_start(&self.read(c"stat")?).ok_or_else(|| REFUSED.into())
    }

    fn validate(&self, peer: &Peer) -> Result<(), String> {
        if peer.pid <= 0
            || peer.pid as u32 != self.pid
            || peer.uid != self.uid
            || self.current_start()? != self.start
            || !uids_match(&self.read(c"status")?, self.uid)
        {
            return Err(REFUSED.into());
        }
        Ok(())
    }
}

fn parse_start(stat: &str) -> Option<u64> {
    // comm can contain spaces and ')' characters. Fields after the LAST ')'
    // start at state (field 3); starttime is field 22.
    let (_, rest) = stat.rsplit_once(')')?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    if matches!(*fields.first()?, "Z" | "X" | "x") {
        return None;
    }
    fields.get(19)?.parse().ok()
}

fn uids_match(status: &str, uid: u32) -> bool {
    let Some(line) = status.lines().find_map(|line| line.strip_prefix("Uid:")) else {
        return false;
    };
    let fields: Vec<_> = line.split_whitespace().collect();
    fields.len() == 4 && fields.iter().all(|field| field.parse::<u32>() == Ok(uid))
}

/// Not Clone or serializable. Only this module can issue a grant, and worker
/// dispatch consumes it before it can invalidate or mutate enrollment state.
pub(super) struct Grant {
    subject: Subject,
    request: String,
    approved: Instant,
}

impl Grant {
    pub(super) fn consume(self, req: &Request, peer: &Peer) -> Result<(), String> {
        if self.approved.elapsed() >= QUEUE_FRESHNESS
            || serde_json::to_string(req).map_err(|_| REFUSED)? != self.request
            || posture(req).user.and_then(uid_of) != Some(peer.uid)
        {
            return Err(REFUSED.into());
        }
        self.subject.validate(peer)
    }
}

#[derive(Default)]
struct Pending(Mutex<HashSet<u32>>);
struct Slot<'a> {
    pending: &'a Pending,
    uid: u32,
}
impl Pending {
    fn acquire(&self, uid: u32) -> Result<Slot<'_>, String> {
        let mut pending = self.0.lock().map_err(|_| REFUSED)?;
        if pending.len() >= 8 || !pending.insert(uid) {
            return Err(
                "another enrollment approval is pending; try again after it finishes".into(),
            );
        }
        Ok(Slot { pending: self, uid })
    }
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.0.lock() {
            pending.remove(&self.uid);
        }
    }
}

pub(super) fn authorize(
    req: &Request,
    peer: &Peer,
    stream: &UnixStream,
) -> Result<Option<Grant>, String> {
    authorize_using(req, peer, stream, |subject, req, deadline| {
        // Fixed system address, never a client/environment-selected session bus.
        let channel =
            Channel::open_private("unix:path=/run/dbus/system_bus_socket").map_err(|_| REFUSED)?;
        let hello = Message::new_method_call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
        )
        .map_err(|_| REFUSED)?;
        channel
            .send_with_reply_and_block(hello, Duration::from_secs(2))
            .map_err(|_| REFUSED)?;
        check(&channel, subject, req, deadline, || peer_gone(stream))
    })
}

fn authorize_using(
    req: &Request,
    peer: &Peer,
    stream: &UnixStream,
    verify: impl FnOnce(&Subject, &Request, Instant) -> Result<(), String>,
) -> Result<Option<Grant>, String> {
    if !required(req, peer) {
        return Ok(None);
    }
    if posture(req).user.and_then(uid_of) != Some(peer.uid) {
        return Err(REFUSED.into());
    }
    static PENDING: OnceLock<Pending> = OnceLock::new();
    let _slot = PENDING.get_or_init(Pending::default).acquire(peer.uid)?;
    let subject = Subject::capture(peer)?;
    let request = serde_json::to_string(req).map_err(|_| REFUSED)?;
    let deadline = Instant::now() + APPROVAL_BUDGET;
    verify(&subject, req, deadline)?;
    if peer_gone(stream) || Instant::now() >= deadline {
        return Err(REFUSED.into());
    }
    subject.validate(peer)?;
    Ok(Some(Grant {
        subject,
        request,
        approved: Instant::now(),
    }))
}

fn method(owner: &str, name: &str) -> Result<Message, String> {
    Message::new_method_call(owner, OBJECT, INTERFACE, name).map_err(|_| REFUSED.into())
}

fn approval_message(owner: &str, subject: &Subject, req: &Request) -> Result<Message, String> {
    let mut properties = PropMap::new();
    properties.insert("pid".into(), Variant(Box::new(subject.pid)));
    properties.insert("uid".into(), Variant(Box::new(subject.uid as i32)));
    properties.insert("start-time".into(), Variant(Box::new(subject.start)));
    let mut details = HashMap::<String, String>::new();
    details.insert("user".into(), posture(req).user.ok_or(REFUSED)?.into());
    let operation = match req {
        Request::Enroll { reset: true, .. } => "replace enrolled faces",
        Request::Enroll { .. } | Request::EnrollmentSession { improve: false, .. } => {
            "enroll a face"
        }
        Request::AddScan { .. } | Request::EnrollmentSession { improve: true, .. } => {
            "add face scans"
        }
        _ => return Err(REFUSED.into()),
    };
    details.insert("operation".into(), operation.into());
    details.insert(
        "polkit.message".into(),
        "Authenticate to $(operation) for $(user) in Irlume".into(),
    );
    // One private bus connection per request makes this cancellation ID unique
    // for its caller without exposing a token to the socket client.
    Ok(method(owner, "CheckAuthorization")?
        .append3(("unix-process", properties), ACTION, details)
        .append2(1u32, "enrollment"))
}

fn decode(mut reply: Message) -> Result<(), String> {
    reply.as_result().map_err(|_| REFUSED)?;
    let (allowed, _, _): (bool, bool, HashMap<String, String>) =
        reply.read1().map_err(|_| REFUSED)?;
    if allowed {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn authority_owner(channel: &Channel, deadline: Instant) -> Result<String, String> {
    let bus_call = |name, message: Message| -> Result<Message, String> {
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        if budget.is_zero() {
            return Err(REFUSED.into());
        }
        let mut reply = channel
            .send_with_reply_and_block(message, budget)
            .map_err(|_| REFUSED)?;
        // Only the bus itself can answer name ownership and activation.
        if reply.sender().as_ref().map(|sender| sender.as_ref()) != Some("org.freedesktop.DBus") {
            return Err(format!("{REFUSED} ({name})"));
        }
        reply.as_result().map_err(|_| REFUSED)?;
        Ok(reply)
    };
    let message = |name| {
        Message::new_method_call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            name,
        )
        .map_err(|_| REFUSED)
    };
    let reply =
        bus_call("authority", message("GetNameOwner")?.append1(AUTHORITY)).or_else(|_| {
            bus_call(
                "activation",
                message("StartServiceByName")?.append2(AUTHORITY, 0u32),
            )?;
            bus_call("authority", message("GetNameOwner")?.append1(AUTHORITY))
        })?;
    let owner: String = reply.read1().map_err(|_| REFUSED)?;
    if !owner.starts_with(':') {
        return Err(REFUSED.into());
    }
    Ok(owner)
}

fn check(
    channel: &Channel,
    subject: &Subject,
    req: &Request,
    deadline: Instant,
    mut gone: impl FnMut() -> bool,
) -> Result<(), String> {
    if gone() || Instant::now() >= deadline {
        return Err(REFUSED.into());
    }
    let owner = authority_owner(channel, deadline)?;
    let serial = channel
        .send(approval_message(&owner, subject, req)?)
        .map_err(|_| REFUSED)?;
    let outcome = loop {
        if gone() || Instant::now() >= deadline {
            break Err(REFUSED.into());
        }
        if channel.read_write(Some(POLL)).is_err() {
            break Err(REFUSED.into());
        }
        if let Some(reply) = channel.pop_message() {
            if reply.get_reply_serial() == Some(serial)
                && reply.sender().as_ref().map(|sender| sender.as_ref()) == Some(owner.as_str())
            {
                break decode(reply);
            }
        }
    };
    if outcome.is_err() {
        // Best effort, bounded cancellation on the SAME caller connection.
        // Dropping the channel also drops this caller's pending request.
        if let Ok(cancel) = method(&owner, "CancelCheckAuthorization") {
            let _ = channel.send_with_reply_and_block(
                cancel.append1("enrollment"),
                Duration::from_millis(250),
            );
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    fn peer() -> Peer {
        // SAFETY: these credential getters have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Peer {
            uid,
            gid,
            pid: std::process::id() as i32,
        }
    }

    fn request(peer: &Peer) -> Request {
        Request::Enroll {
            user: crate::users::name_for_uid(peer.uid).unwrap(),
            profile: None,
            scans: None,
            reset: false,
        }
    }

    #[test]
    fn process_identity_rejects_exit_uid_change_and_malformed_proc_records() {
        let peer = peer();
        let subject = Subject::capture(&peer).unwrap();
        subject.validate(&peer).unwrap();
        let changed = Peer {
            uid: peer.uid + 1,
            gid: peer.gid,
            pid: peer.pid,
        };
        assert!(subject.validate(&changed).is_err());
        assert!(!uids_match("Uid:\t1000 0 1000 1000\n", 1000));
        assert!(!uids_match("Uid:\t1000 1000 1000\n", 1000));
        assert!(!uids_match("Name:\tprocess\n", 1000));
        assert_eq!(
            parse_start("9 (strange ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777"),
            Some(777)
        );
        assert_eq!(
            parse_start("9 (zombie) Z 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777"),
            None
        );
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let child_peer = Peer {
            pid: child.id() as i32,
            uid: peer.uid,
            gid: peer.gid,
        };
        let pinned = Subject::capture(&child_peer).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(pinned.validate(&child_peer).is_err());
    }

    #[test]
    fn grant_is_bound_to_all_request_fields_and_expires_before_use() {
        let _passwd = crate::tests::passwd_lock();
        let peer = peer();
        let req = request(&peer);
        let grant = || Grant {
            subject: Subject::capture(&peer).unwrap(),
            request: serde_json::to_string(&req).unwrap(),
            approved: Instant::now(),
        };
        grant().consume(&req, &peer).unwrap();
        let mut changed = req.clone();
        if let Request::Enroll { reset, .. } = &mut changed {
            *reset = true;
        }
        assert!(grant().consume(&changed, &peer).is_err());
        let mut expired = grant();
        expired.approved -= Duration::from_secs(16);
        assert!(expired.consume(&req, &peer).is_err());
        let changed_peer = Peer {
            pid: peer.pid + 1,
            uid: peer.uid,
            gid: peer.gid,
        };
        assert!(grant().consume(&req, &changed_peer).is_err());
    }

    #[test]
    fn guided_approval_names_the_operation_and_binds_the_whole_capture_budget() {
        let _passwd = crate::tests::passwd_lock();
        let peer = peer();
        let user = crate::users::name_for_uid(peer.uid).unwrap();
        for improve in [false, true] {
            let req = Request::EnrollmentSession {
                user: user.clone(),
                profile: Some("Primary".into()),
                scans: 10,
                improve,
            };
            let subject = Subject::capture(&peer).unwrap();
            let message = approval_message(":1.42", &subject, &req).unwrap();
            type Args = (
                (String, PropMap),
                String,
                HashMap<String, String>,
                u32,
                String,
            );
            let (_, action, details, flags, _): Args = message.read_all().unwrap();
            assert_eq!(action, ACTION);
            assert_eq!(flags, 1);
            assert_eq!(
                details["operation"],
                if improve {
                    "add face scans"
                } else {
                    "enroll a face"
                }
            );
            let grant = || Grant {
                subject: Subject::capture(&peer).unwrap(),
                request: serde_json::to_string(&req).unwrap(),
                approved: Instant::now(),
            };
            grant().consume(&req, &peer).unwrap();
            for changed in [
                Request::EnrollmentSession {
                    user: user.clone(),
                    profile: Some("Primary".into()),
                    scans: 11,
                    improve,
                },
                Request::EnrollmentSession {
                    user: user.clone(),
                    profile: Some("Other".into()),
                    scans: 10,
                    improve,
                },
                Request::EnrollmentSession {
                    user: user.clone(),
                    profile: Some("Primary".into()),
                    scans: 10,
                    improve: !improve,
                },
                Request::EnrollmentSession {
                    user: "different-account".into(),
                    profile: Some("Primary".into()),
                    scans: 10,
                    improve,
                },
            ] {
                assert!(grant().consume(&changed, &peer).is_err());
            }
        }
    }

    #[test]
    fn pending_approvals_are_bounded_and_released_on_drop() {
        let pending = Pending::default();
        let first = pending.acquire(1).unwrap();
        assert!(pending.acquire(1).is_err());
        let rest: Vec<_> = (2..=8).map(|uid| pending.acquire(uid).unwrap()).collect();
        assert!(pending.acquire(9).is_err());
        drop(first);
        let replacement = pending.acquire(9).unwrap();
        drop(rest);
        drop(replacement);
        assert!(pending.acquire(1).is_ok());
    }

    struct Bus(Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn bus() -> (Bus, String) {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        (Bus(child), address.trim().into())
    }

    #[test]
    fn real_dbus_exchange_checks_subject_action_denial_and_cancellation() {
        let _passwd = crate::tests::passwd_lock();
        for mode in ["allow", "deny", "malformed", "cancel", "forged"] {
            let (_bus, address) = bus();
            let server = dbus::blocking::Connection::new_address(&address).unwrap();
            server.request_name(AUTHORITY, false, true, false).unwrap();
            let client = dbus::blocking::Connection::new_address(&address).unwrap();
            let peer = peer();
            let req = request(&peer);
            let subject = Subject::capture(&peer).unwrap();
            let expected = (subject.pid, subject.uid, subject.start);
            let expected_user = posture(&req).user.unwrap().to_owned();
            let intruder = dbus::blocking::Connection::new_address(&address).unwrap();
            let worker = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut checked = false;
                while Instant::now() < deadline {
                    server
                        .channel()
                        .read_write(Some(Duration::from_millis(10)))
                        .unwrap();
                    let Some(message) = server.channel().pop_message() else {
                        continue;
                    };
                    if message.member().as_ref().map(|m| m.as_ref()) == Some("CheckAuthorization") {
                        type Args = (
                            (String, PropMap),
                            String,
                            HashMap<String, String>,
                            u32,
                            String,
                        );
                        let (subject, action, details, flags, cancellation): Args =
                            message.read_all().unwrap();
                        assert_eq!(action, "org.irlume.enroll");
                        assert_eq!(flags, 1);
                        assert_eq!(subject.0, "unix-process");
                        assert_eq!(subject.1["pid"].0.as_u64(), Some(u64::from(expected.0)));
                        assert_eq!(subject.1["uid"].0.as_i64(), Some(i64::from(expected.1)));
                        assert_eq!(subject.1["start-time"].0.as_u64(), Some(expected.2));
                        assert_eq!(details["user"], expected_user);
                        assert_eq!(details["operation"], "enroll a face");
                        assert_eq!(cancellation, "enrollment");
                        checked = true;
                        if mode == "forged" {
                            intruder
                                .channel()
                                .send(message.method_return().append1((
                                    true,
                                    false,
                                    HashMap::<String, String>::new(),
                                )))
                                .unwrap();
                            intruder
                                .channel()
                                .read_write(Some(Duration::from_millis(20)))
                                .unwrap();
                            std::thread::sleep(Duration::from_millis(30));
                        }
                        if mode == "cancel" {
                            continue;
                        }
                        let reply = if mode == "malformed" {
                            message.method_return().append1(true)
                        } else {
                            message.method_return().append1((
                                mode == "allow",
                                false,
                                HashMap::<String, String>::new(),
                            ))
                        };
                        server.channel().send(reply).unwrap();
                        server
                            .channel()
                            .read_write(Some(Duration::from_millis(10)))
                            .unwrap();
                        if mode == "allow" {
                            return;
                        }
                    } else if message.member().as_ref().map(|m| m.as_ref())
                        == Some("CancelCheckAuthorization")
                    {
                        assert!(checked);
                        assert_eq!(message.read1::<String>().unwrap(), "enrollment");
                        server.channel().send(message.method_return()).unwrap();
                        server
                            .channel()
                            .read_write(Some(Duration::from_millis(10)))
                            .unwrap();
                        return;
                    }
                }
                panic!("authorization exchange did not finish: {mode}");
            });
            let started = Instant::now();
            let result = check(
                client.channel(),
                &subject,
                &req,
                started + Duration::from_secs(2),
                || mode == "cancel" && started.elapsed() > Duration::from_millis(100),
            );
            worker.join().unwrap();
            assert_eq!(result.is_ok(), mode == "allow", "{mode}");
        }
    }
}
