// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::io;

// Linux v7.2 include/uapi/linux/nsfs.h and arch/x86/entry/syscalls/syscall_64.tbl.
// libc 0.2.191's musl module does not supply this syscall constant.
const SYS_LISTNS: libc::c_long = 470;
const INITIAL_PID_NAMESPACE: u64 = 4;
const LAST_INITIAL_NAMESPACE: u64 = 8;

#[repr(C)]
struct NamespaceRequest {
    size: u32,
    spare: u32,
    ns_id: u64,
    ns_type: u32,
    spare2: u32,
    user_ns_id: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Initial,
    // Absence of the witness is not proof of a different namespace.
    NotObserved(u64),
}

fn observe_with(
    query: impl FnOnce(&NamespaceRequest, &mut u64) -> (libc::c_long, i32),
) -> Result<Observation, (&'static str, i32)> {
    let request = NamespaceRequest {
        size: 32,
        spare: 0,
        ns_id: INITIAL_PID_NAMESPACE - 1,
        ns_type: libc::CLONE_NEWPID as u32,
        spare2: 0,
        user_ns_id: u64::MAX, // LISTNS_CURRENT_USER, resolved inside the kernel.
    };
    let mut namespace_id = u64::MAX;
    let (count, errno) = query(&request, &mut namespace_id);
    match count {
        -1 => Err(("listns", errno)),
        0 => Ok(Observation::NotObserved(0)),
        1 if namespace_id == INITIAL_PID_NAMESPACE => Ok(Observation::Initial),
        1 if namespace_id > LAST_INITIAL_NAMESPACE && namespace_id < u64::MAX => {
            Ok(Observation::NotObserved(namespace_id))
        }
        _ => Err(("invalid listns result", 0)),
    }
}

fn observe() -> Result<Observation, (&'static str, i32)> {
    observe_with(|request, namespace_id| {
        // SAFETY: Linux x86-64 listns uses the initialized 32-byte v0 request,
        // a writable u64 array, its element count, and integer flags. Both
        // buffers remain live for the call. No path or descriptor is supplied.
        let result = unsafe { libc::syscall(SYS_LISTNS, request, namespace_id, 1usize, 0u32) };
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        (result, errno)
    })
}

pub(super) fn main() {
    if std::env::args_os().count() != 1 {
        std::process::exit(77);
    }
    let (initial, namespace_id, errno, status) = match observe() {
        Ok(Observation::Initial) => ("true", INITIAL_PID_NAMESPACE, 0, 0),
        Ok(Observation::NotObserved(id)) => ("false", id, 0, 0),
        Err((_, errno)) => ("null", 0, errno, 77),
    };
    // These independent identity syscalls are only fixture context, not part
    // of the namespace observation or a claim of authority.
    // SAFETY: getpid/getuid return this caller's identities with no pointers.
    let (pid, uid) = unsafe { (libc::getpid(), libc::getuid()) };
    let output = format!(
        "{{\"initial\":{initial},\"namespace_id\":{namespace_id},\"errno\":{errno},\"pid\":{pid},\"uid\":{uid}}}\n"
    );
    // SAFETY: integer flag query of the existing stdout descriptor.
    let flags = unsafe { libc::fcntl(1, libc::F_GETFL) };
    if flags < 0 {
        std::process::exit(77);
    }
    // SAFETY: integer flag update; refusing a full output pipe must not block.
    if unsafe { libc::fcntl(1, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        std::process::exit(77);
    }
    // SAFETY: initialized output bytes, bounded to a single short write.
    if unsafe { libc::write(1, output.as_ptr().cast(), output.len()) } != output.len() as isize {
        std::process::exit(77);
    }
    std::process::exit(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_binds_current_owner_and_one_pid_namespace() {
        let result = observe_with(|request, output| {
            assert_eq!(std::mem::size_of_val(request), 32);
            assert_eq!(request.size, 32);
            assert_eq!(request.spare, 0);
            assert_eq!(request.spare2, 0);
            assert_eq!(request.ns_type, libc::CLONE_NEWPID as u32);
            assert_eq!(request.ns_id, 3);
            assert_eq!(request.user_ns_id, u64::MAX);
            *output = 4;
            (1, 0)
        });
        assert_eq!(result, Ok(Observation::Initial));
    }

    #[test]
    fn missing_and_failed_queries_remain_errors() {
        for errno in [libc::ENOENT, libc::ENOSYS, libc::EPERM, libc::EINTR] {
            assert_eq!(observe_with(|_, _| (-1, errno)), Err(("listns", errno)));
        }
    }

    #[test]
    fn absence_is_not_a_namespace_identity_claim() {
        assert_eq!(observe_with(|_, _| (0, 0)), Ok(Observation::NotObserved(0)));
        assert_eq!(
            observe_with(|_, output| {
                *output = 9;
                (1, 0)
            }),
            Ok(Observation::NotObserved(9))
        );
    }

    #[test]
    fn invalid_counts_and_output_never_produce_an_observation() {
        for count in [-2, 2, i64::MAX] {
            assert!(observe_with(|_, output| {
                *output = 4;
                (count, 0)
            })
            .is_err());
        }
        for id in [0, 1, 2, 3, 5, 6, 7, 8, u64::MAX] {
            assert!(observe_with(|_, output| {
                *output = id;
                (1, 0)
            })
            .is_err());
        }
    }
}
