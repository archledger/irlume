// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A shared greeter name alone cannot authorize an RGB-only screen unlock.
//!
//! COSMIC's locker calls PAM in its own process, so the kernel peer can be
//! bound to that user's local graphical session. GDM's separate worker needs
//! a different, qualified provider contract; it is not admitted here.

use std::time::{Duration, Instant};

use dbus::arg::{prop_cast, PropMap, RefArg};
use dbus::channel::Channel;
use dbus::Message;

use super::{operation_authorization::Subject, uid_of, Peer};

pub(super) const REFUSED: &str =
    "RGB-only shared greeter: local screen-unlock context unavailable or changed; use your password";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Session {
    pub owner: String,
    pub path: String,
    pub id: String,
    pub uid: u32,
    pub seat: String,
    pub kind: String,
    pub class: String,
    pub state: String,
    pub active: bool,
    pub remote: bool,
    pub created: u64,
}

impl Session {
    fn permits(&self, uid: u32) -> bool {
        self.uid == uid
            && self.active
            && !self.remote
            && self.class == "user"
            && self.state == "active"
            && matches!(self.kind.as_str(), "wayland" | "x11")
            && bounded(&self.id)
            && bounded(&self.seat)
            && self.created != 0
    }
}

/// Retained only by one request and its response. The proc fd pins the peer
/// process, while the session snapshot pins logind's owner and session lifetime.
pub(super) struct Binding {
    subject: Subject,
    peer: Peer,
    user: String,
    session: Session,
}

impl Binding {
    pub(super) fn capture(user: &str, peer: &Peer) -> Result<Self, &'static str> {
        let uid = uid_of(user).ok_or(REFUSED)?;
        // A root greeter worker selecting another user is not that user's
        // in-session locker, even when that user has a runtime directory.
        if peer.uid != uid {
            return Err(REFUSED);
        }
        let subject = Subject::capture(peer).map_err(|_| REFUSED)?;
        let session = observe(peer)?;
        if !session.permits(uid) {
            return Err(REFUSED);
        }
        subject.validate(peer).map_err(|_| REFUSED)?;
        Ok(Self {
            subject,
            peer: peer.clone(),
            user: user.to_owned(),
            session,
        })
    }

    pub(super) fn validate(&self) -> Result<(), &'static str> {
        self.subject.validate(&self.peer).map_err(|_| REFUSED)?;
        if uid_of(&self.user) != Some(self.peer.uid) {
            return Err(REFUSED);
        }
        let current = observe(&self.peer)?;
        if current != self.session || !current.permits(self.peer.uid) {
            return Err(REFUSED);
        }
        self.subject.validate(&self.peer).map_err(|_| REFUSED)
    }
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn observe(peer: &Peer) -> Result<Session, &'static str> {
    #[cfg(test)]
    if let Some(result) = super::tests::shared_greeter::session_result(peer) {
        return result;
    }
    let deadline = Instant::now() + Duration::from_millis(800);
    // Never honor DBUS_SYSTEM_BUS_ADDRESS or a client-selected bus. As with
    // operation authorization, only the host's fixed system bus is trusted.
    let channel =
        Channel::open_private("unix:path=/run/dbus/system_bus_socket").map_err(|_| REFUSED)?;
    let call = |destination: &str, path: &str, interface: &str, method: &str| {
        Message::new_method_call(destination, path, interface, method).map_err(|_| REFUSED)
    };
    send(
        &channel,
        call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
        )?,
        deadline,
    )?;
    let owner: String = send(
        &channel,
        call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
        )?
        .append1("org.freedesktop.login1"),
        deadline,
    )?
    .read1()
    .map_err(|_| REFUSED)?;
    if !owner.starts_with(':') || !bounded(&owner) {
        return Err(REFUSED);
    }
    let pid = u32::try_from(peer.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or(REFUSED)?;
    let path: dbus::Path<'static> = send(
        &channel,
        call(
            &owner,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "GetSessionByPID",
        )?
        .append1(pid),
        deadline,
    )?
    .read1()
    .map_err(|_| REFUSED)?;
    if !path.starts_with("/org/freedesktop/login1/session/") || path.len() > 256 {
        return Err(REFUSED);
    }
    let properties: PropMap = send(
        &channel,
        call(&owner, &path, "org.freedesktop.DBus.Properties", "GetAll")?
            .append1("org.freedesktop.login1.Session"),
        deadline,
    )?
    .read1()
    .map_err(|_| REFUSED)?;
    session_from_properties(owner, path.to_string(), &properties)
}

fn send(channel: &Channel, message: Message, deadline: Instant) -> Result<Message, &'static str> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(REFUSED)?;
    if remaining.is_zero() {
        return Err(REFUSED);
    }
    let reply = channel
        .send_with_reply_and_block(message, remaining)
        .map_err(|_| REFUSED)?;
    if Instant::now() >= deadline {
        return Err(REFUSED);
    }
    Ok(reply)
}

fn session_from_properties(
    owner: String,
    path: String,
    properties: &PropMap,
) -> Result<Session, &'static str> {
    let string = |key| {
        prop_cast::<String>(properties, key)
            .filter(|value| bounded(value))
            .cloned()
            .ok_or(REFUSED)
    };
    let user = properties.get("User").ok_or(REFUSED)?;
    if user.0.signature() != "(uo)" {
        return Err(REFUSED);
    }
    let mut user = user.0.as_iter().ok_or(REFUSED)?;
    let uid = user
        .next()
        .and_then(RefArg::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or(REFUSED)?;
    // The D-Bus tuple's second field is an object path, checked by its signature.
    user.next().ok_or(REFUSED)?;
    if user.next().is_some() {
        return Err(REFUSED);
    }
    let seat = properties.get("Seat").ok_or(REFUSED)?;
    if seat.0.signature() != "(so)" {
        return Err(REFUSED);
    }
    let mut seat = seat.0.as_iter().ok_or(REFUSED)?;
    let seat_name = seat
        .next()
        .and_then(RefArg::as_str)
        .filter(|value| bounded(value))
        .ok_or(REFUSED)?
        .to_owned();
    seat.next().ok_or(REFUSED)?;
    if seat.next().is_some() {
        return Err(REFUSED);
    }
    Ok(Session {
        owner,
        path,
        id: string("Id")?,
        uid,
        seat: seat_name,
        kind: string("Type")?,
        class: string("Class")?,
        state: string("State")?,
        active: *prop_cast::<bool>(properties, "Active").ok_or(REFUSED)?,
        remote: *prop_cast::<bool>(properties, "Remote").ok_or(REFUSED)?,
        created: *prop_cast::<u64>(properties, "TimestampMonotonic").ok_or(REFUSED)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbus::arg::Variant;

    fn properties() -> PropMap {
        let mut props = PropMap::new();
        for (key, value) in [
            ("Id", "2"),
            ("Type", "wayland"),
            ("Class", "user"),
            ("State", "active"),
        ] {
            props.insert(key.into(), Variant(Box::new(value.to_owned())));
        }
        props.insert(
            "User".into(),
            Variant(Box::new((
                1000u32,
                dbus::Path::new("/org/freedesktop/login1/user/_1000").unwrap(),
            ))),
        );
        props.insert(
            "Seat".into(),
            Variant(Box::new((
                "seat0".to_owned(),
                dbus::Path::new("/org/freedesktop/login1/seat/seat0").unwrap(),
            ))),
        );
        props.insert("Active".into(), Variant(Box::new(true)));
        props.insert("Remote".into(), Variant(Box::new(false)));
        props.insert("TimestampMonotonic".into(), Variant(Box::new(1234u64)));
        props
    }

    fn decode(props: PropMap) -> Result<Session, &'static str> {
        // Exercise D-Bus variant/tuple serialization, not just locally boxed
        // Rust values. GetAll returns exactly this a{sv} property map.
        let message = Message::new_signal("/test", "org.irlume.Test", "Properties")
            .unwrap()
            .append1(props);
        let decoded: PropMap = message.read1().unwrap();
        session_from_properties(
            ":1.42".into(),
            "/org/freedesktop/login1/session/_32".into(),
            &decoded,
        )
    }

    #[test]
    fn logind_property_tuple_decoding_and_local_session_contract() {
        let session = decode(properties()).unwrap();
        assert!(session.permits(1000));
        assert!(!session.permits(1001));
        assert_eq!(session.created, 1234);
        for (key, value) in [
            ("Type", "tty"),
            ("Type", "unspecified"),
            ("Class", "greeter"),
            ("Class", "manager"),
            ("State", "closing"),
        ] {
            let mut props = properties();
            props.insert(key.into(), Variant(Box::new(value.to_owned())));
            assert!(!decode(props).unwrap().permits(1000), "{key}={value}");
        }
        for (key, value) in [("Remote", true), ("Active", false)] {
            let mut props = properties();
            props.insert(key.into(), Variant(Box::new(value)));
            assert!(!decode(props).unwrap().permits(1000));
        }
    }

    #[test]
    fn missing_malformed_and_unbounded_logind_properties_refuse() {
        for key in properties().keys() {
            let mut props = properties();
            props.remove(key);
            assert!(decode(props).is_err(), "missing {key}");
            let mut props = properties();
            props.insert(key.clone(), Variant(Box::new(1u32)));
            assert!(decode(props).is_err(), "wrong type {key}");
        }
        for value in [String::new(), "x".repeat(129), "bad\nvalue".into()] {
            let mut props = properties();
            props.insert("Id".into(), Variant(Box::new(value)));
            assert!(decode(props).is_err());
        }
        let mut props = properties();
        props.insert(
            "Seat".into(),
            Variant(Box::new((String::new(), dbus::Path::new("/").unwrap()))),
        );
        assert!(decode(props).is_err());
        let mut props = properties();
        props.insert("TimestampMonotonic".into(), Variant(Box::new(0u64)));
        assert!(!decode(props).unwrap().permits(1000));
    }
}
