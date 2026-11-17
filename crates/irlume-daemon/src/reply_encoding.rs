// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Complete-line preparation before final socket admission.

use irlume_common::Response;
use serde::Serialize;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use zeroize::Zeroizing;

#[derive(Default)]
struct Counter {
    bytes: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn line_storage(json_bytes: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let total = json_bytes
        .checked_add(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(total)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    // Reservation and initialization precede any encoded output. The writer
    // below receives only a fixed slice, never the growable Vec.
    bytes.resize(total, 0);
    Ok(bytes)
}

/// Prepare the compact JSON response and its terminating newline.
///
/// Production responses are immutable snapshots. Serialization reads them
/// twice; a changed output length is rejected without growing the output.
/// Same-length changes by a stateful custom serializer are not detected.
///
/// # Errors
///
/// Returns a serialization, length-overflow, allocation or size-mismatch error.
pub(super) fn prepare_line<T: Serialize + ?Sized>(response: &T) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut counter = Counter::default();
    serde_json::to_writer(&mut counter, response)?;
    let mut json = line_storage(counter.bytes)?;
    let mut remaining = &mut json[..counter.bytes];
    serde_json::to_writer(&mut remaining, response).map_err(|error| {
        // The fixed sink's I/O failure is an internal size mismatch, not a
        // client socket failure or cancellation.
        if error.is_io() {
            io::ErrorKind::InvalidData.into()
        } else {
            io::Error::from(error)
        }
    })?;
    if !remaining.is_empty() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    json[counter.bytes] = b'\n';
    Ok(json)
}

/// Prepare the complete response before admission and any socket write.
///
/// # Errors
///
/// Returns a preparation, admission, socket-write or flush error.
pub(super) fn respond_admitted(
    mut stream: UnixStream,
    response: &Response,
    admit: impl FnOnce(&UnixStream) -> io::Result<()>,
) -> io::Result<()> {
    let json = prepare_line(response)?;
    admit(&stream)?;
    stream.write_all(&json)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Read;

    #[test]
    fn prepared_reply_is_exact_compact_json_with_one_newline() {
        let response = Response::Ok("quoted\nmessage".into());
        let line = prepare_line(&response).unwrap();
        assert_eq!(&*line, b"{\"Ok\":\"quoted\\nmessage\"}\n");
    }

    #[test]
    fn admission_refusal_observes_no_response_bytes() {
        let response = Response::Ok("not delivered".into());
        let (server, mut client) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let mut admitted = false;

        let error = respond_admitted(server, &response, |_| {
            admitted = true;
            let mut byte = [0u8; 1];
            assert_eq!(
                client.read(&mut byte).unwrap_err().kind(),
                io::ErrorKind::WouldBlock,
                "no response byte precedes admission"
            );
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();

        assert!(admitted);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn counter_rejects_overflow_without_changing_its_count() {
        let mut counter = Counter { bytes: usize::MAX };
        let error = counter.write(b"x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(counter.bytes, usize::MAX);
    }

    #[test]
    fn line_storage_rejects_newline_and_capacity_overflow() {
        assert_eq!(
            line_storage(usize::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // A u8 Vec cannot have capacity above isize::MAX; this fails layout
        // validation without attempting an enormous native allocation.
        assert_eq!(
            line_storage(usize::MAX - 1).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
    }

    fn byte_payloads() -> [Vec<u8>; 3] {
        [
            Vec::new(),
            (0u8..=u8::MAX).collect(),
            vec![0, 9, 10, 99, 100, 255],
        ]
    }

    fn assert_existing_wire(response: &Response) {
        let mut expected = Zeroizing::new(serde_json::to_vec(response).unwrap());
        expected.push(b'\n');
        assert!(prepare_line(response).unwrap().as_slice() == expected.as_slice());
    }

    #[test]
    fn secret_and_escaped_responses_keep_existing_wire_bytes() {
        for kind in [
            irlume_common::KeyringSecretKind::LoginPassword,
            irlume_common::KeyringSecretKind::KdeWalletKey,
            irlume_common::KeyringSecretKind::GnomeKeyringToken,
        ] {
            for bytes in byte_payloads() {
                assert_existing_wire(&Response::PasswordUnsealed {
                    secret: irlume_common::SecretBytes::new(bytes),
                    kind,
                });
            }
        }
        for minted in [false, true] {
            for bytes in byte_payloads() {
                assert_existing_wire(&Response::TokenSealed {
                    token: irlume_common::SecretBytes::new(bytes),
                    minted,
                });
            }
        }
        assert_existing_wire(&Response::Ok(
            "quote \" slash \\ newline\n tab\t nul\0 💡".into(),
        ));
    }

    struct ChangedLength {
        calls: Cell<usize>,
        first: &'static str,
        second: &'static str,
    }

    impl Serialize for ChangedLength {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let call = self.calls.replace(self.calls.get() + 1);
            serializer.serialize_str(if call == 0 { self.first } else { self.second })
        }
    }

    #[test]
    fn changed_second_pass_lengths_are_rejected() {
        for (first, second, kind) in [
            ("longer first pass", "x", io::ErrorKind::InvalidData),
            ("x", "longer second pass", io::ErrorKind::InvalidData),
        ] {
            let changed = ChangedLength {
                calls: Cell::new(0),
                first,
                second,
            };
            let error = prepare_line(&changed).unwrap_err();
            assert_eq!(changed.calls.get(), 2);
            assert_eq!(error.kind(), kind);
        }
    }

    #[test]
    fn successful_admission_observes_no_bytes_then_writes_exact_line() {
        let response = Response::TokenSealed {
            token: irlume_common::SecretBytes::new((0u8..=u8::MAX).collect()),
            minted: false,
        };
        let mut expected = Zeroizing::new(serde_json::to_vec(&response).unwrap());
        expected.push(b'\n');
        let (server, mut client) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let mut admitted = false;

        respond_admitted(server, &response, |_| {
            admitted = true;
            assert_eq!(
                client.read(&mut [0u8; 1]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            Ok(())
        })
        .unwrap();

        assert!(admitted);
        let mut received = Zeroizing::new(Vec::new());
        client.read_to_end(&mut received).unwrap();
        assert!(received.as_slice() == expected.as_slice());
    }
}
