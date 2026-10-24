// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Harmless private fixture: real CRT constructor followed by Rust main.

#[cfg(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    target_feature = "crt-static"
))]
#[path = "measurement_fixture_bootstrap/runtime.rs"]
mod runtime;

#[cfg(all(
    irlume_hw_evidence,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    target_feature = "crt-static"
))]
mod probe {
    use super::runtime;

    // The CRT calls this before Rust main. No Rust printing, allocation,
    // formatting, panic, thread state or runtime services may be used here.
    extern "C" fn constructor() {
        const MESSAGE: &[u8] = b"fixture: constructor\n";
        // SAFETY: MESSAGE is static initialized storage. One write only.
        if unsafe { libc::write(1, MESSAGE.as_ptr().cast(), MESSAGE.len()) }
            != MESSAGE.len() as isize
        {
            // SAFETY: _exit is the only failure path before Rust initialization.
            unsafe { libc::_exit(78) }
        }
    }

    #[used]
    #[link_section = ".init_array"]
    static CONSTRUCTOR: extern "C" fn() = constructor;

    fn check() -> runtime::Result<()> {
        runtime::posture("/fixture", false)?;
        runtime::pipe(1)?;
        if runtime::flags(1)? & libc::O_NONBLOCK == 0 {
            return Err("blocking output");
        }
        // SAFETY: F_GETFD has no pointer argument.
        if unsafe { libc::fcntl(1, libc::F_GETFD) } != 0 {
            return Err("cloexec output");
        }
        for fd in [0, 2] {
            let info = runtime::stat(fd)?;
            if info.st_mode & libc::S_IFMT != libc::S_IFCHR || info.st_rdev != libc::makedev(1, 3) {
                return Err("stdio");
            }
        }
        // read_dir itself opens the first unused descriptor (3). Anything
        // above it demonstrates an inherited descriptor leak.
        for entry in std::fs::read_dir("/proc/self/fd").map_err(|_| "fd census")? {
            let entry = entry.map_err(|_| "fd census")?;
            let fd: i32 = entry
                .file_name()
                .to_str()
                .ok_or("fd census")?
                .parse()
                .map_err(|_| "fd census")?;
            if !(0..=3).contains(&fd) {
                return Err("fd leak");
            }
        }
        Ok(())
    }

    fn marker(bytes: &[u8]) {
        // SAFETY: bytes is valid for its length; one nonblocking write only.
        if unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len()) } != bytes.len() as isize {
            // SAFETY: failure must not invoke further output or cleanup.
            unsafe { libc::_exit(78) }
        }
    }

    pub(super) fn main() {
        if check().is_err() {
            std::process::exit(79);
        }
        marker(b"fixture: main\n");
        if let Some("descendant" | "escaped" | "timeout") = option_env!("IRLUME_FIXTURE_MODE") {
            let mut ready = [-1; 2];
            // SAFETY: ready contains space for the two returned descriptors.
            if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                std::process::exit(80);
            }
            // SAFETY: this fixture has no worker threads or locks.
            let child = unsafe { libc::fork() };
            if child < 0 {
                std::process::exit(80);
            }
            if child == 0 {
                // SAFETY: the child owns this pipe read end and no longer uses it.
                unsafe { libc::close(ready[0]) };
                if option_env!("IRLUME_FIXTURE_MODE") != Some("descendant") {
                    // SAFETY: the child intentionally escapes the owned
                    // process group to test PID-namespace cleanup.
                    if unsafe { libc::setsid() } < 0 {
                        std::process::exit(81);
                    }
                }
                marker(b"fixture: descendant\n");
                // SAFETY: one initialized byte is sent to the parent; this
                // proves the descendant really inherited the result pipe.
                if unsafe { libc::write(ready[1], b"!".as_ptr().cast(), 1) } != 1 {
                    std::process::exit(82);
                }
                // SAFETY: ready[1] is no longer used after the acknowledgment.
                unsafe { libc::close(ready[1]) };
                loop {
                    // SAFETY: pause waits for signals and takes no pointers.
                    unsafe { libc::pause() };
                }
            }
            // SAFETY: parent closes its duplicate writer before reading.
            unsafe { libc::close(ready[1]) };
            let mut byte = 0_u8;
            // SAFETY: byte is writable storage; the controller bounds this
            // entire fixture, including a stuck or interrupted handshake.
            if unsafe { libc::read(ready[0], (&mut byte as *mut u8).cast(), 1) } != 1 {
                std::process::exit(83);
            }
            // SAFETY: the acknowledgment has been consumed.
            unsafe { libc::close(ready[0]) };
            if option_env!("IRLUME_FIXTURE_MODE") == Some("timeout") {
                loop {
                    // SAFETY: pause waits for controller SIGKILL.
                    unsafe { libc::pause() };
                }
            }
        }
    }
}

fn main() {
    #[cfg(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    ))]
    probe::main();
    #[cfg(not(all(
        irlume_hw_evidence,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        target_feature = "crt-static"
    )))]
    std::process::exit(77);
}
