// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! gnome-keyring control-socket protocol (the channel `pam_gnome_keyring` uses).
//!
//! gnome-keyring-daemon listens on `$XDG_RUNTIME_DIR/keyring/control`, and this
//! socket, not D-Bus, is how the daemon's own PAM module unlocks the login
//! keyring at login and re-keys it on a password change. irlume uses the same
//! channel for the same two operations on a token-armed user ([`Op::Unlock`]
//! from the session helper, [`Op::Change`] from `keyring arm`/`forget`), because
//! the alternative, `busctl` with the secret in argv, publishes the secret in
//! `/proc/<pid>/cmdline`.
//!
//! Wire format, from gnome-keyring's `pam/gkr-pam-client.c` and
//! `egg/egg-buffer.c` (all integers big-endian `u32`):
//!
//! ```text
//! connect  -> 1 credentials byte (value 0; the kernel attaches SO_PASSCRED
//!             credentials to any byte sent over the socket)
//! request  -> total_len | op | (arg_len | arg_bytes)*
//!             where total_len covers itself and op (8 bytes) plus every
//!             argument's 4-byte length prefix and bytes
//! response -> total_len (= 8) | result
//! ```
//!
//! The daemon compares the peer's uid against its own, which is why the PAM
//! module (and irlume's session helper) must be running as the target user
//! before connecting; `gkr-pam-client.c` does the same seteuid dance.

use std::io::{Read, Write};

/// Control operations, from `daemon/control/gkd-control-codes.h`. Only the two
/// irlume needs are represented; `INITIALIZE` (0) replies with a variable-length
/// environment block this client does not parse, and `QUIT` (3) has no business
/// being reachable from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Unlock the login keyring with the single argument (the master secret).
    Unlock = 1,
    /// Re-key the login keyring: arguments are `(current secret, new secret)`,
    /// in that order (`change_keyring_password` in `gkr-pam-module.c` sends
    /// `argv[0] = original`). Headless: no prompt is shown, and a wrong
    /// `current` yields [`ControlResult::Denied`].
    Change = 2,
}

/// Result codes, from `gkd-control-codes.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlResult {
    Ok,
    /// The supplied secret was wrong.
    Denied,
    Failed,
    NoDaemon,
    /// A value outside the enum: protocol drift or a truncated reply.
    Unknown(u32),
}

impl ControlResult {
    fn from_code(code: u32) -> Self {
        match code {
            0 => ControlResult::Ok,
            1 => ControlResult::Denied,
            2 => ControlResult::Failed,
            3 => ControlResult::NoDaemon,
            other => ControlResult::Unknown(other),
        }
    }

    /// Human-readable outcome for logs and CLI messages.
    pub fn describe(&self) -> String {
        match self {
            ControlResult::Ok => "ok".into(),
            ControlResult::Denied => "denied (wrong secret)".into(),
            ControlResult::Failed => "failed".into(),
            ControlResult::NoDaemon => "no daemon".into(),
            ControlResult::Unknown(c) => format!("unknown result code {c}"),
        }
    }
}

/// Encode one request packet. Pure, so the exact bytes are testable against
/// the layout in `gkr-pam-client.c` without a socket.
pub fn encode_request(op: Op, args: &[&[u8]]) -> Vec<u8> {
    let total: usize = 8 + args.iter().map(|a| 4 + a.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(total as u32).to_be_bytes());
    buf.extend_from_slice(&(op as u32).to_be_bytes());
    for a in args {
        buf.extend_from_slice(&(a.len() as u32).to_be_bytes());
        buf.extend_from_slice(a);
    }
    buf
}

/// Decode the fixed 8-byte response. Errors name what was malformed rather than
/// collapsing into a result code, because a garbled reply and a `Failed` ask
/// for different reactions (report a bug vs. report the outcome).
pub fn decode_response(bytes: &[u8]) -> Result<ControlResult, String> {
    if bytes.len() != 8 {
        return Err(format!(
            "control reply was {} bytes, expected 8",
            bytes.len()
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if len != 8 {
        return Err(format!("control reply declared length {len}, expected 8"));
    }
    Ok(ControlResult::from_code(u32::from_be_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])))
}

/// Run one control operation over an already-connected stream.
///
/// Generic over the stream so tests can drive it with an in-memory pipe; the
/// real caller passes a `UnixStream` connected to `control_socket_path`.
pub fn call<S: Read + Write>(
    stream: &mut S,
    op: Op,
    args: &[&[u8]],
) -> Result<ControlResult, String> {
    // The credentials byte. Its value is ignored by the daemon; the kernel
    // attaches the sender's uid/gid/pid via SO_PASSCRED, which is what the
    // daemon actually reads.
    stream
        .write_all(&[0u8])
        .map_err(|e| format!("control socket write (credentials): {e}"))?;
    stream
        .write_all(&encode_request(op, args))
        .map_err(|e| format!("control socket write: {e}"))?;
    let mut reply = [0u8; 8];
    stream
        .read_exact(&mut reply)
        .map_err(|e| format!("control socket read: {e}"))?;
    decode_response(&reply)
}

/// The control socket, relative to the user's `XDG_RUNTIME_DIR`
/// (`get_control_file` in `gkr-pam-module.c` appends `/keyring/control`).
pub fn control_socket_path(runtime_dir: &std::path::Path) -> std::path::PathBuf {
    runtime_dir.join("keyring/control")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden bytes for a CHANGE, hand-assembled from the layout in
    /// `gkr-pam-client.c`: total covers the 8-byte header plus 4+len per arg.
    #[test]
    fn change_request_matches_the_gkr_client_layout() {
        let got = encode_request(Op::Change, &[b"old", b"newpw"]);
        let expect: Vec<u8> = [
            &(8u32 + 4 + 3 + 4 + 5).to_be_bytes()[..], // total = 24
            &2u32.to_be_bytes(),                       // GKD_CONTROL_OP_CHANGE
            &3u32.to_be_bytes(),
            b"old",
            &5u32.to_be_bytes(),
            b"newpw",
        ]
        .concat();
        assert_eq!(got, expect);
        // Big-endian, not native: the first length byte of a 24-byte packet
        // must be 0, and the last must be 24.
        assert_eq!(&got[..4], &[0, 0, 0, 24]);
    }

    #[test]
    fn unlock_request_carries_one_argument() {
        let got = encode_request(Op::Unlock, &[b"s3cret"]);
        assert_eq!(&got[..4], &(8u32 + 4 + 6).to_be_bytes());
        assert_eq!(&got[4..8], &1u32.to_be_bytes());
        assert_eq!(&got[8..12], &6u32.to_be_bytes());
        assert_eq!(&got[12..], b"s3cret");
    }

    #[test]
    fn responses_decode_each_result_code() {
        for (code, want) in [
            (0u32, ControlResult::Ok),
            (1, ControlResult::Denied),
            (2, ControlResult::Failed),
            (3, ControlResult::NoDaemon),
            (9, ControlResult::Unknown(9)),
        ] {
            let mut reply = 8u32.to_be_bytes().to_vec();
            reply.extend_from_slice(&code.to_be_bytes());
            assert_eq!(decode_response(&reply).unwrap(), want, "code {code}");
        }
    }

    #[test]
    fn malformed_responses_error_instead_of_guessing() {
        assert!(decode_response(&[0u8; 7]).is_err(), "short reply");
        assert!(decode_response(&[0u8; 9]).is_err(), "long reply");
        let mut wrong_len = 12u32.to_be_bytes().to_vec();
        wrong_len.extend_from_slice(&0u32.to_be_bytes());
        assert!(
            decode_response(&wrong_len).is_err(),
            "declared length must be 8"
        );
    }

    /// End-to-end over an in-memory stream: a scripted "daemon" that answers OK
    /// after asserting the exact request bytes.
    #[test]
    fn call_writes_credentials_byte_then_packet() {
        struct Script {
            written: Vec<u8>,
            reply: std::io::Cursor<Vec<u8>>,
        }
        impl Write for Script {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.written.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Read for Script {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reply.read(buf)
            }
        }
        let mut reply = 8u32.to_be_bytes().to_vec();
        reply.extend_from_slice(&0u32.to_be_bytes());
        let mut s = Script {
            written: Vec::new(),
            reply: std::io::Cursor::new(reply),
        };
        let res = call(&mut s, Op::Unlock, &[b"tok"]).unwrap();
        assert_eq!(res, ControlResult::Ok);
        assert_eq!(s.written[0], 0, "credentials byte first");
        assert_eq!(&s.written[1..], &encode_request(Op::Unlock, &[b"tok"])[..]);
    }
}
