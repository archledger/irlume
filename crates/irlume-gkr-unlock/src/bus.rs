// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The waiter's whole use of the user bus: learn when `org.gnome.keyring`
//! gains an owner, and who that owner is.
//!
//! The surface is kept small on purpose, because this process holds the
//! token. It runs only after the permanent drop to the user. It exports no
//! object and never replies to anything. It adds one match rule, limited to
//! `NameOwnerChanged` from the bus itself for that one name. Every other
//! incoming message is dropped unread. Every method call it makes carries
//! `NO_AUTO_START`, so nothing it does starts a service.

use std::path::Path;
use std::time::{Duration, Instant};

use dbus::channel::Channel;
use dbus::message::MessageType;
use dbus::strings::{BusName, Interface, Member};
use dbus::Message;

use crate::waiter::BusLost;

/// The name gnome-keyring claims during INITIALIZE.
pub(crate) const KEYRING_NAME: &str = "org.gnome.keyring";

const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";

/// The one match rule: owner changes of [`KEYRING_NAME`], sent by the bus.
pub(crate) const MATCH_RULE: &str = "type='signal',sender='org.freedesktop.DBus',\
interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus',\
arg0='org.gnome.keyring'";

/// Deadline for each method call. The calls to the bus answer at once; the
/// one to gnome-keyring waits for its main loop.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// A private connection to the user bus.
pub(crate) struct Bus {
    channel: Channel,
}

impl Bus {
    /// Connect to the bus at `path`, say Hello and subscribe.
    pub(crate) fn connect(path: &Path) -> Result<Bus, BusLost> {
        let channel = Channel::open_private(&address(path)).map_err(|_| BusLost)?;
        let bus = Bus { channel };
        bus.call(hello())?;
        bus.call(add_match())?;
        Ok(bus)
    }

    /// The unique name owning [`KEYRING_NAME`], if any.
    pub(crate) fn owner(&self) -> Result<Option<String>, BusLost> {
        let Some(call) = get_name_owner(KEYRING_NAME) else {
            return Ok(None);
        };
        match self.channel.send_with_reply_and_block(call, CALL_TIMEOUT) {
            Ok(reply) => Ok(reply.read1::<&str>().ok().and_then(unique_name)),
            Err(e) if e.name() == Some("org.freedesktop.DBus.Error.NameHasNoOwner") => Ok(None),
            Err(_) if !self.channel.is_connected() => Err(BusLost),
            // Anything else leaves the name as unowned for now; a
            // NameOwnerChanged still wakes the waiter.
            Err(_) => Ok(None),
        }
    }

    /// Wait up to `timeout` for an owner change of [`KEYRING_NAME`].
    pub(crate) fn next_owner_change(
        &self,
        timeout: Duration,
    ) -> Result<Option<Option<String>>, BusLost> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let message = self
                .channel
                .blocking_pop_message(left)
                .map_err(|_| BusLost)?;
            match message {
                Some(message) => {
                    if let Some(change) = owner_change(&message) {
                        return Ok(Some(change));
                    }
                    // Anything else is dropped unread.
                }
                None if !self.channel.is_connected() => return Err(BusLost),
                None if left.is_zero() => return Ok(None),
                None => {}
            }
        }
    }

    /// The pid of the process behind a unique name, from the bus.
    pub(crate) fn pid_of(&self, unique: &str) -> Option<u32> {
        let reply = self
            .channel
            .send_with_reply_and_block(get_pid(unique)?, CALL_TIMEOUT)
            .ok()?;
        reply.read1::<u32>().ok().filter(|pid| *pid != 0)
    }

    /// The control directory the owner `unique` reports.
    pub(crate) fn control_directory(&self, unique: &str) -> Option<String> {
        let reply = self
            .channel
            .send_with_reply_and_block(get_control_directory(unique)?, CALL_TIMEOUT)
            .ok()?;
        reply.read1::<&str>().ok().map(str::to_string)
    }

    fn call(&self, message: Option<Message>) -> Result<Message, BusLost> {
        self.channel
            .send_with_reply_and_block(message.ok_or(BusLost)?, CALL_TIMEOUT)
            .map_err(|_| BusLost)
    }
}

/// Every method call this module makes is built here, and none may start a
/// service. `None` for a name the bus would reject: each part is checked by
/// its typed constructor, which returns an error where the `&str` shortcut
/// would panic.
fn method_call(destination: &str, path: &str, interface: &str, member: &str) -> Option<Message> {
    let mut message = Message::method_call(
        &BusName::new(destination).ok()?,
        &dbus::Path::new(path).ok()?,
        &Interface::new(interface).ok()?,
        &Member::new(member).ok()?,
    );
    message.set_auto_start(false);
    Some(message)
}

fn hello() -> Option<Message> {
    method_call(BUS_NAME, BUS_PATH, BUS_NAME, "Hello")
}

fn add_match() -> Option<Message> {
    Some(method_call(BUS_NAME, BUS_PATH, BUS_NAME, "AddMatch")?.append1(MATCH_RULE))
}

fn get_name_owner(name: &str) -> Option<Message> {
    Some(method_call(BUS_NAME, BUS_PATH, BUS_NAME, "GetNameOwner")?.append1(name))
}

fn get_pid(unique: &str) -> Option<Message> {
    Some(method_call(BUS_NAME, BUS_PATH, BUS_NAME, "GetConnectionUnixProcessID")?.append1(unique))
}

/// gnome-keyring's `GetControlDirectory` (`daemon/dbus/gkd-dbus.c`), sent to
/// the owner's unique name so that exactly the connection that owns the name
/// answers.
fn get_control_directory(unique: &str) -> Option<Message> {
    method_call(
        unique,
        "/org/gnome/keyring/daemon",
        "org.gnome.keyring.Daemon",
        "GetControlDirectory",
    )
}

/// The new owner in a `NameOwnerChanged` for [`KEYRING_NAME`] from the bus
/// itself: `Some(Some(owner))`, `Some(None)` when the name was released.
/// `None` for every other message, whose body is never read.
fn owner_change(message: &Message) -> Option<Option<String>> {
    if message.msg_type() != MessageType::Signal
        || message.sender().as_deref() != Some(BUS_NAME)
        || message.interface().as_deref() != Some(BUS_NAME)
        || message.member().as_deref() != Some("NameOwnerChanged")
        || message.path().as_deref() != Some(BUS_PATH)
    {
        return None;
    }
    let (name, _old, new) = message.read3::<&str, &str, &str>().ok()?;
    if name != KEYRING_NAME {
        return None;
    }
    Some(unique_name(new))
}

/// A unique connection name (`:1.42`), or `None` for an empty or malformed
/// one.
fn unique_name(name: &str) -> Option<String> {
    let well_formed = name.len() <= 255
        && name.strip_prefix(':').is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        });
    well_formed.then(|| name.to_string())
}

/// A D-Bus address for a socket path. Bytes outside the set the address
/// syntax allows unescaped are written as `%XX`.
fn address(path: &Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    let mut out = String::from("unix:path=");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_/.\\*".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02x}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_match_rule_names_one_name_from_the_bus_itself() {
        assert_eq!(
            MATCH_RULE,
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',\
             member='NameOwnerChanged',path='/org/freedesktop/DBus',arg0='org.gnome.keyring'"
                .replace(' ', "")
        );
        let add = add_match().unwrap();
        assert_eq!(add.read1::<&str>().unwrap(), MATCH_RULE);
    }

    #[test]
    fn every_method_call_is_sent_without_auto_start() {
        for message in [
            hello(),
            add_match(),
            get_name_owner(KEYRING_NAME),
            get_pid(":1.7"),
            get_control_directory(":1.7"),
        ] {
            let message = message.expect("valid names");
            assert_eq!(message.msg_type(), MessageType::MethodCall);
            assert!(
                !message.get_auto_start(),
                "{:?} would start a service",
                message.member()
            );
        }
        // Every call goes through `method_call`, so the check above covers
        // any call added later.
        // The needles are split so these lines do not match themselves.
        let src = include_str!("bus.rs");
        let builders = ["method_call(", "new_method_call(", "call_with_args("];
        let counts: Vec<usize> = builders
            .iter()
            .map(|b| src.matches(&["Message::", b].concat()).count())
            .collect();
        assert_eq!(counts, [1, 0, 0], "{builders:?}");
    }

    fn signal(sender: &str, member: &str, args: (&str, &str, &str)) -> Message {
        let mut m = Message::new_signal(BUS_PATH, BUS_NAME, member)
            .unwrap()
            .append3(args.0, args.1, args.2);
        m.set_sender(Some(sender.into()));
        m
    }

    #[test]
    fn only_owner_changes_of_the_keyring_name_from_the_bus_are_read() {
        let claimed = signal(BUS_NAME, "NameOwnerChanged", (KEYRING_NAME, "", ":1.42"));
        assert_eq!(owner_change(&claimed), Some(Some(":1.42".into())));
        let released = signal(BUS_NAME, "NameOwnerChanged", (KEYRING_NAME, ":1.42", ""));
        assert_eq!(owner_change(&released), Some(None));

        // Forged by another connection: the bus stamps the real sender.
        let forged = signal(":1.9", "NameOwnerChanged", (KEYRING_NAME, "", ":1.9"));
        assert_eq!(owner_change(&forged), None);
        let other_name = signal(
            BUS_NAME,
            "NameOwnerChanged",
            ("org.freedesktop.secrets", "", ":1.42"),
        );
        assert_eq!(owner_change(&other_name), None);
        let other_member = signal(BUS_NAME, "NameAcquired", (KEYRING_NAME, "", ":1.42"));
        assert_eq!(owner_change(&other_member), None);
        let malformed = signal(BUS_NAME, "NameOwnerChanged", (KEYRING_NAME, "", "x.y"));
        assert_eq!(owner_change(&malformed), Some(None));

        let mut call = method_call(BUS_NAME, BUS_PATH, BUS_NAME, "NameOwnerChanged")
            .unwrap()
            .append3(KEYRING_NAME, "", ":1.42");
        call.set_sender(Some(BUS_NAME.into()));
        assert_eq!(owner_change(&call), None, "a method call is not a signal");
    }

    #[test]
    fn socket_paths_become_escaped_addresses() {
        assert_eq!(
            address(Path::new("/run/user/1000/bus")),
            "unix:path=/run/user/1000/bus"
        );
        assert_eq!(
            address(Path::new("/tmp/a b,c=d;e/bus")),
            "unix:path=/tmp/a%20b%2cc%3dd%3be/bus"
        );
    }

    #[test]
    fn unique_names_are_checked() {
        assert_eq!(unique_name(":1.5").as_deref(), Some(":1.5"));
        assert_eq!(unique_name(""), None);
        assert_eq!(unique_name("org.gnome.keyring"), None);
        assert_eq!(unique_name(":1.\n5"), None);
        assert_eq!(unique_name(":"), None);
        assert!(
            get_control_directory("not a name").is_none(),
            "no panic on a bad name"
        );
    }
}
