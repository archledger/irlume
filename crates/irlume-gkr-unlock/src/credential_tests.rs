// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic control-server fixtures. Never start a keyring daemon.

use super::*;
use std::io::Write as _;
use std::os::unix::net::UnixListener;
use waiter::World;

/// Real socket delivery with a synthetic bus identity. The listener's actual
/// SO_PEERCRED must still match before any credential bytes leave the helper.
struct Fixture<'a> {
    system: System<'a>,
    owner: u32,
}

impl World for Fixture<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn stop_requested(&self) -> bool {
        false
    }
    fn keyring_exists(&self) -> bool {
        self.system.keyring_exists()
    }
    fn control_socket_exists(&self) -> bool {
        self.system.control_socket_exists()
    }
    fn sleep(&mut self, _: Duration) {
        panic!("an immediate fixture must not retry")
    }
    fn log(&mut self, _: waiter::Event) {}
    fn report(&mut self, _: waiter::Status) {}
    fn connect_bus(&mut self) -> Result<(), BusLost> {
        Ok(())
    }
    fn owner(&mut self) -> Result<Option<String>, BusLost> {
        Ok(Some(":1.7".into()))
    }
    fn next_owner_change(&mut self, _: Duration) -> Result<Option<Option<String>>, BusLost> {
        panic!("an immediate fixture must not wait")
    }
    fn owner_pid(&mut self, _: &str) -> Option<u32> {
        Some(self.owner)
    }
    fn identify(&mut self, _: &str) -> Identity {
        panic!("the listener must be the synthetic bus owner")
    }
    fn send(&mut self, op: Op, args: &[&[u8]], expect: Expect) -> Sent {
        self.system.send(op, args, expect)
    }
}

fn protocol_fixture(input: &[u8], denied: bool) {
    let args = parse_args(["--password", "fixture"].map(OsString::from)).unwrap();
    let token = read_credential(input, args.input_mode).expect("supported login password bytes");
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("irlume-gkr-credential-{}-{id}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::fs::create_dir(root.join("keyring")).unwrap();
    let keyring = root.join("login.keyring");
    std::fs::write(&keyring, b"synthetic fixture, not a real keyring").unwrap();
    let listener = UnixListener::bind(root.join("keyring/control")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let expected = Zeroizing::new(input.to_vec());
    let (done, wait_done) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        for op in if denied { &[2u32][..] } else { &[2u32, 1][..] } {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut conn = loop {
                match listener.accept() {
                    Ok((conn, _)) => break conn,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing control request");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            conn.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut credentials = [255u8];
            conn.read_exact(&mut credentials).unwrap();
            assert_eq!(credentials, [0]);
            let mut header = [0u8; 8];
            conn.read_exact(&mut header).unwrap();
            let args = if *op == 2 { 2 } else { 1 };
            let length = 8 + args * (4 + expected.len());
            assert_eq!(
                u32::from_be_bytes(header[..4].try_into().unwrap()) as usize,
                length
            );
            assert_eq!(u32::from_be_bytes(header[4..].try_into().unwrap()), *op);
            for _ in 0..args {
                let mut size = [0u8; 4];
                conn.read_exact(&mut size).unwrap();
                assert_eq!(u32::from_be_bytes(size) as usize, expected.len());
                let mut bytes = Zeroizing::new(vec![0u8; expected.len()]);
                conn.read_exact(&mut bytes).unwrap();
                assert!(
                    bytes.as_slice() == expected.as_slice(),
                    "credential bytes changed"
                );
            }
            let result = if denied { 1u32 } else { 0u32 };
            conn.write_all(&8u32.to_be_bytes()).unwrap();
            conn.write_all(&result.to_be_bytes()).unwrap();
        }
        wait_done.recv_timeout(Duration::from_secs(5)).unwrap();
        if denied {
            assert!(
                matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
                "DENIED must not be followed by UNLOCK"
            );
        }
    });
    // SAFETY: getpid/getuid only read the fixture process's own identity.
    let (owner, uid) = unsafe { (libc::getpid() as u32, libc::getuid()) };
    let target = Target {
        token,
        uid,
        keyring,
        runtime_dir: root,
    };
    let mut fixture = Fixture {
        system: System::new(&target, Sink::Stderr, None),
        owner,
    };
    let outcome = waiter::run(
        &mut fixture,
        &target.token,
        &waiter::Plan {
            started: Instant::now(),
            bound: Duration::from_secs(10),
            uid,
        },
    );
    done.send(()).unwrap();
    server.join().unwrap();
    if denied {
        assert_eq!(outcome, waiter::Outcome::Stale { daemon_pid: owner });
    } else {
        assert!(
            matches!(outcome, waiter::Outcome::Delivered { daemon_pid, .. } if daemon_pid == owner)
        );
    }
}

#[test]
fn password_bytes_reach_the_real_control_protocol_unchanged() {
    protocol_fixture(" a synthetic café password \t\n".as_bytes(), false);
}

#[test]
fn maximum_length_password_reaches_the_real_control_protocol_unchanged() {
    protocol_fixture(&vec![b' '; MAX_PASSWORD_LEN], false);
}

#[test]
fn non_utf8_password_reaches_the_real_control_protocol_unchanged() {
    protocol_fixture(b"synthetic \xff password", false);
}

#[test]
fn denied_password_does_not_send_unlock() {
    protocol_fixture(b"synthetic rejected password", true);
}
