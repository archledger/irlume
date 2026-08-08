// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Memory-protection helper: `mlock` + `MADV_DONTDUMP` on the pages backing a
//! secret, so the plaintext can't be swapped to disk or captured in a core
//! dump while it's live. This complements (does not replace) `Zeroize`, which
//! scrubs *after* use; mlock protects the window *during* use.
//!
//! Best-effort: `RLIMIT_MEMLOCK` may reject the lock for unprivileged callers,
//! in which case we warn and carry on (auth must still work).

/// Lock the pages backing `buf` against swap and core dumps. Idempotent-ish;
/// safe to call on any slice. No-op for empty input.
pub fn lock_slice(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    // `mlock` rounds an unaligned start down to the page, but
    // `madvise(MADV_DONTDUMP)` returns EINVAL unless the address is page-aligned,
    // so a raw Vec pointer silently failed DONTDUMP. Align the start down and
    // extend the length so both calls cover the pages backing the secret.
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let page = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        n if n > 0 => n as usize,
        _ => 4096,
    };
    let start = buf.as_ptr() as usize;
    let aligned_start = start & !(page - 1);
    let len = (start - aligned_start) + buf.len();
    let ptr = aligned_start as *mut libc::c_void;
    // SAFETY: ptr/len describe a valid mapped range (the pages backing `buf`).
    unsafe {
        if libc::mlock(ptr, len) != 0 {
            eprintln!(
                "irlume: mlock failed ({}); secret may be swappable; raise RLIMIT_MEMLOCK",
                std::io::Error::last_os_error()
            );
        }
        if libc::madvise(ptr, len, libc::MADV_DONTDUMP) != 0 {
            eprintln!(
                "irlume: madvise DONTDUMP failed ({}); secret may appear in core dumps",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_unaligned_slices_are_handled() {
        // Empty input is the documented no-op.
        lock_slice(&[]);
        // A deliberately unaligned start (offset 1 into a multi-page buffer):
        // the alignment math must cover it without touching the contents.
        let buf = vec![7u8; 3 * 4096];
        lock_slice(&buf[1..2 * 4096 + 1]);
        assert!(
            buf.iter().all(|&b| b == 7),
            "locking must not alter the secret"
        );
    }

    // lock_slice is best-effort by contract: when RLIMIT_MEMLOCK forbids the
    // lock it must WARN and return (auth still works), never abort. mlock
    // cannot be made to fail in-process without breaking sibling tests, so
    // re-exec this test with the limit dropped to zero in the child.
    #[test]
    fn mlock_refusal_warns_and_continues() {
        if std::env::var("IRLUME_TEST_MEMLOCK_CHILD").is_ok() {
            // Drop the limit HERE, after exec, rather than in a pre_exec hook.
            // libtest runs every test on its own thread, so the parent is
            // multi-threaded at the fork and a post-fork child may use only
            // async-signal-safe calls; setrlimit is in neither POSIX's table nor
            // signal-safety(7). Lowering our own limit in an ordinary process is
            // plain libc usage with no such constraint (#363 review).
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `zero` is a fully initialised rlimit and the pointer is
            // valid for the call; lowering one's own soft and hard
            // RLIMIT_MEMLOCK is always permitted.
            let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) };
            assert_eq!(
                rc,
                0,
                "could not drop RLIMIT_MEMLOCK in the child: {}",
                std::io::Error::last_os_error()
            );
            let secret = vec![0x5a_u8; 4096];
            lock_slice(&secret);
            println!("survived-without-mlock");
            // Probe whether mlock reaches the kernel at all here. A sanitizer
            // runtime defines its own mlock and returns success without making
            // the syscall, so RLIMIT_MEMLOCK refuses nothing and the warning
            // this test looks for is never printed. Say so, rather than leaving
            // the parent to read an intercepted call as a missing warning.
            #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
            let page = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
                n if n > 0 => n as usize,
                _ => 4096,
            };
            let aligned = secret.as_ptr() as usize & !(page - 1);
            // SAFETY: `aligned` is the page containing a live 4 KiB allocation.
            if unsafe { libc::mlock(aligned as *mut libc::c_void, page) } == 0 {
                println!("mlock-not-enforced");
            }
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "memlock::tests::mlock_refusal_warns_and_continues",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("IRLUME_TEST_MEMLOCK_CHILD", "1");
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "a refused mlock must not fail the caller; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("survived-without-mlock"));
        if stdout.contains("mlock-not-enforced") {
            // Reported rather than passed silently: under ASan this test proves
            // only that the caller survived, not that the refusal was warned
            // about, and a reader of the log should know which.
            eprintln!(
                "SKIPPED the refusal-is-warned assertion: mlock is intercepted in this build \
                 (sanitizer runtime), so RLIMIT_MEMLOCK cannot refuse the lock"
            );
            return;
        }
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("mlock failed"),
            "the refusal must be reported (raise RLIMIT_MEMLOCK hint); stderr: {err}"
        );
    }
}
