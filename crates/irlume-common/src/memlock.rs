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
    // `madvise(MADV_DONTDUMP)` returns EINVAL unless the address is page-aligned
    // — so a raw Vec pointer silently failed DONTDUMP. Align the start down and
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
                "irlume: mlock failed ({}); secret may be swappable — raise RLIMIT_MEMLOCK",
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
