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
            lock_slice(&vec![0x5a_u8; 4096]);
            println!("survived-without-mlock");
            return;
        }
        use std::os::unix::process::CommandExt;
        let exe = std::env::current_exe().unwrap();
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "memlock::tests::mlock_refusal_warns_and_continues",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("IRLUME_TEST_MEMLOCK_CHILD", "1");
        // SAFETY: setrlimit is async-signal-safe; nothing else runs between
        // fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                let zero = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "a refused mlock must not fail the caller; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("survived-without-mlock"));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("mlock failed"),
            "the refusal must be reported (raise RLIMIT_MEMLOCK hint); stderr: {err}"
        );
    }
}
