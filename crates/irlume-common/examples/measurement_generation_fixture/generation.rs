// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod sys;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use sys::{check, error, Result};

const MODE: &str = match option_env!("IRLUME_FIXTURE_MODE") {
    Some(value) => value,
    None => "positive",
};
const PATHS: [&str; 3] = ["generation", "objects/early.bin", "objects/late.bin"];
const A: [&[u8]; 3] = [b"A", b"A-early", b"A-late"];
const B: [&[u8]; 3] = [b"B", b"B-early", b"B-late"];
const SEALS: i32 = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_EXEC
    | libc::F_SEAL_SEAL;
const FLAGS: u64 = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
// Linux x86-64 syscall_64.tbl; libc0.2.190's musl module lacks this constant.
const SYS_STATMOUNT: libc::c_long = 457;

#[repr(C)]
struct MountRequest {
    size: u32,
    spare: u32,
    mount_id: u64,
    mask: u64,
}

#[repr(C, align(8))]
struct MountBuffer([u8; 512]);

fn separate_mount_flags(path: &CString) -> Result<()> {
    let mut info = MaybeUninit::<libc::statx>::uninit();
    check(
        // SAFETY: terminated path and valid statx output; require the unique mount-ID field.
        unsafe {
            libc::syscall(
                libc::SYS_statx,
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
                libc::STATX_MNT_ID_UNIQUE,
                info.as_mut_ptr(),
            )
        },
        "statx mount id",
    )?;
    // SAFETY: successful statx initialized info; its mask qualifies mount_id below.
    let info = unsafe { info.assume_init() };
    if info.stx_mask & libc::STATX_MNT_ID_UNIQUE == 0 {
        return Err(("missing unique mount id", 0));
    }
    let request = MountRequest {
        size: 24,
        spare: 0,
        mount_id: info.stx_mnt_id,
        mask: 3,
    };
    let mut buffer = MountBuffer([0; 512]);
    check(
        // SAFETY: Linux mnt_id_req v0 is 24 bytes; aligned 512-byte fixed statmount output,
        // no strings requested. Both buffers stay live for the syscall.
        unsafe {
            libc::syscall(
                SYS_STATMOUNT,
                &request,
                buffer.0.as_mut_ptr(),
                512usize,
                0u32,
            )
        },
        "statmount",
    )?;
    let size = u32::from_ne_bytes(
        buffer.0[0..4]
            .try_into()
            .map_err(|_| ("statmount size", 0))?,
    );
    let mask = u64::from_ne_bytes(
        buffer.0[8..16]
            .try_into()
            .map_err(|_| ("statmount mask", 0))?,
    );
    let sb = u32::from_ne_bytes(
        buffer.0[32..36]
            .try_into()
            .map_err(|_| ("statmount sb", 0))?,
    );
    let id = u64::from_ne_bytes(
        buffer.0[40..48]
            .try_into()
            .map_err(|_| ("statmount id", 0))?,
    );
    let attrs = u64::from_ne_bytes(
        buffer.0[64..72]
            .try_into()
            .map_err(|_| ("statmount attrs", 0))?,
    );
    if !(72..=512).contains(&size) || mask & 3 != 3 || id != request.mount_id {
        return Err(("statmount fields", 0));
    }
    if sb & libc::MS_RDONLY as u32 == 0 {
        return Err(("superblock flags", 0));
    }
    if attrs & 15 != 15 {
        return Err(("mount attributes", 0));
    }
    Ok(())
}

fn cstring(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| ("path", 0))
}

fn contents(tag: u8, index: usize, corrupt: bool) -> &'static [u8] {
    if corrupt && tag == b'B' && index == 2 {
        b"wrong-late"
    } else if tag == b'A' {
        A[index]
    } else {
        B[index]
    }
}

fn mount_flags(path: &str) -> Result<()> {
    let path = cstring(path)?;
    let mut info = MaybeUninit::<libc::statvfs>::uninit();
    check(
        // SAFETY: path is terminated and info has space for statvfs's output.
        unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } as _,
        "statvfs",
    )?;
    // SAFETY: the successful call initialized the output.
    let info = unsafe { info.assume_init() };
    if info.f_flag & FLAGS != FLAGS {
        return Err(("mount flags", 0));
    }
    separate_mount_flags(&path)
}

fn names(path: &str, expected: &[&str]) -> Result<()> {
    let mut entries = fs::read_dir(path)
        .map_err(|_| error("directory"))?
        .map(|entry| {
            entry
                .map(|e| e.file_name())
                .map_err(|_| error("directory entry"))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort();
    if entries
        != expected
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
    {
        return Err(("tree entries", 0));
    }
    Ok(())
}

fn layout(root: &str) -> Result<()> {
    names(root, &[".old", "generation", "objects"])?;
    names(&format!("{root}/objects"), &["early.bin", "late.bin"])?;
    names(&format!("{root}/.old"), &[])?;
    mount_flags(root)?;
    let mut identities = Vec::new();
    for path in PATHS {
        let path = format!("{root}/{path}");
        let info = fs::symlink_metadata(&path).map_err(|_| error("leaf metadata"))?;
        if !info.is_file() || info.mode() & 0o7777 != 0o400 || info.len() > 4096 {
            return Err(("leaf metadata", 0));
        }
        let identity = (info.dev(), info.ino());
        if identities.contains(&identity) {
            return Err(("aliased leaf", 0));
        }
        identities.push(identity);
        mount_flags(&path)?;
    }
    Ok(())
}

fn compare(root: &str, tag: u8, indices: &[usize], corrupt: bool) -> Result<()> {
    for &index in indices {
        let path = format!("{root}/{}", PATHS[index]);
        let mut data = Vec::new();
        File::open(&path)
            .map_err(|_| error("leaf open"))?
            .take(4097)
            .read_to_end(&mut data)
            .map_err(|_| error("leaf read"))?;
        if data != contents(tag, index, corrupt) {
            return Err(("leaf content", index as i32));
        }
    }
    Ok(())
}

fn staged(root: &str, tag: u8) -> Result<()> {
    fs::create_dir(root).map_err(|_| error("stage directory"))?;
    let target = cstring(root)?;
    sys::mount(
        c"none",
        &target,
        c"tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        c"size=2097152,nr_inodes=32,mode=0755",
    )
    .map_err(|(_, errno)| ("tmpfs stage", errno))?;
    for suffix in [".old", "objects"] {
        fs::create_dir(format!("{root}/{suffix}")).map_err(|_| error("stage child"))?;
    }
    sys::mount(
        c"none",
        &cstring(&format!("{root}/objects"))?,
        c"tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        c"size=2097152,nr_inodes=32,mode=0755",
    )
    .map_err(|(_, errno)| ("nested tmpfs", errno))?;
    for (index, path) in PATHS.iter().enumerate() {
        let destination = format!("{root}/{path}");
        // SAFETY: constant NUL-terminated name and explicit no-exec flags.
        let file = sys::fd(
            unsafe {
                libc::memfd_create(
                    c"generation-fixture".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_NOEXEC_SEAL,
                )
            } as _,
            "memfd",
        )?;
        let data = contents(tag, index, MODE == "wrong-late");
        if file.write_at(data, 0).map_err(|_| error("fixture write"))? != data.len() {
            return Err(("short fixture write", 0));
        }
        check(
            // SAFETY: file is newly owned; fchmod operates on this descriptor only.
            unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } as _,
            "fixture mode",
        )?;
        check(
            // SAFETY: F_ADD_SEALS takes the integer bitmask, not a pointer.
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } as _,
            "fixture seals",
        )?;
        let seals = check(
            // SAFETY: F_GET_SEALS reads the flags of this owned descriptor.
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } as _,
            "fixture seal query",
        )? as i32;
        if seals & SEALS != SEALS {
            return Err(("fixture seal readback", 0));
        }
        let mut copy = [0u8; 4096];
        if file
            .read_at(&mut copy, 0)
            .map_err(|_| error("sealed source read"))?
            != data.len()
            || &copy[..data.len()] != data
        {
            return Err(("sealed source bytes", 0));
        }
        let destination = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|_| error("private destination"))?;
        if destination
            .write_at(&copy[..data.len()], 0)
            .map_err(|_| error("private copy write"))?
            != data.len()
        {
            return Err(("private copy short", 0));
        }
        check(
            // SAFETY: destination is a newly created private fixture file.
            unsafe { libc::fchmod(destination.as_raw_fd(), 0o400) } as _,
            "private copy mode",
        )?;
        let mut readback = [0u8; 4096];
        if destination
            .read_at(&mut readback, 0)
            .map_err(|_| error("private copy read"))?
            != data.len()
            || &readback[..data.len()] != data
        {
            return Err(("private copy bytes", 0));
        }
        drop((file, destination));
        if MODE == "fail-file" && tag == b'B' && index == 0 {
            return Err(("injected file", 0));
        }
    }
    for (index, path) in [root.to_owned(), format!("{root}/objects")]
        .iter()
        .enumerate()
    {
        if MODE == "unfrozen-submount" && index == 1 {
            continue;
        }
        sys::mount(
            c"none",
            &cstring(path)?,
            c"tmpfs",
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"",
        )
        .map_err(|(_, errno)| ("superblock readonly", errno))?;
    }
    let attr = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_RDONLY
            | libc::MOUNT_ATTR_NOSUID
            | libc::MOUNT_ATTR_NODEV
            | libc::MOUNT_ATTR_NOEXEC,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let flags = libc::AT_RECURSIVE;
    check(
        // SAFETY: valid path and initialized version-0 mount_attr; private fixture mounts only.
        unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                target.as_ptr(),
                flags,
                &attr,
                std::mem::size_of_val(&attr),
            )
        },
        "mount_setattr",
    )?;
    if MODE == "missing-mount-readonly" {
        let clear = libc::mount_attr {
            attr_set: 0,
            attr_clr: libc::MOUNT_ATTR_RDONLY,
            propagation: 0,
            userns_fd: 0,
        };
        let nested = cstring(&format!("{root}/objects"))?;
        check(
            // SAFETY: explicit negative control on this private mount only. The
            // superblock stays read-only while the per-mount attribute is cleared.
            unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    libc::AT_FDCWD,
                    nested.as_ptr(),
                    0u32,
                    &clear,
                    std::mem::size_of_val(&clear),
                )
            },
            "clear mount readonly",
        )?;
    }
    layout(root)?;
    compare(root, tag, &[0, 1, 2], MODE == "wrong-late")
}

fn publish(root: &str, tag: u8) -> Result<()> {
    let root = cstring(root)?;
    let recursive = if MODE == "nonrecursive-clone" {
        0
    } else {
        libc::AT_RECURSIVE as u32
    };
    // SAFETY: clones a known complete private mount tree and returns an owned mount descriptor.
    let tree = sys::fd(
        unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::OPEN_TREE_CLONE | libc::O_CLOEXEC as u32 | recursive,
            )
        },
        "open_tree",
    )?;
    if MODE == "fail-move" && tag == b'B' {
        return Err(("injected move", 0));
    }
    check(
        // SAFETY: tree is a valid detached mount; destination is a private fixture mount point.
        unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                tree.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_FDCWD,
                c"/current".as_ptr(),
                libc::MOVE_MOUNT_F_EMPTY_PATH,
            )
        },
        "move_mount",
    )?;
    drop(tree);
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn drop_caps() -> Result<()> {
    for cap in 0..64 {
        // SAFETY: queries a capability bit without pointers.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if present < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                continue;
            }
            return Err(error("cap bound read"));
        }
        if present != 0 {
            check(
                // SAFETY: bounding capability removal while CAP_SETPCAP is still effective.
                unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } as _,
                "cap bound drop",
            )?;
        }
    }
    check(
        // SAFETY: clears all ambient capabilities, no pointers used.
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } as _,
        "ambient clear",
    )?;
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    check(
        // SAFETY: Linux capability ABI v3 uses this header and two initialized data words.
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) },
        "capset",
    )?;
    check(
        // SAFETY: same ABI, now writing to the two data words for verification.
        unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) },
        "capget",
    )?;
    if data != [CapData::default(); 2] {
        return Err(("capabilities remain", 0));
    }
    for cap in 0..64 {
        // SAFETY: read-only capability query, with no pointers.
        let value = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if value == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            continue;
        }
        if value != 0 {
            return Err(("bounding set remains", 0));
        }
        // SAFETY: query this known supported ambient capability bit.
        if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) } != 0
        {
            return Err(("ambient remains", 0));
        }
    }
    // SAFETY: NNP is queried only; no memory arguments.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(("nnp", 0));
    }
    Ok(())
}

fn finish(result: Result<()>) -> ! {
    let status = match result {
        Ok(()) => 0,
        Err((operation, errno)) => {
            let _ = sys::send(2, format!("generation: {operation} ({errno})\n").as_bytes());
            77
        }
    };
    // SAFETY: each forked role exits without running duplicated parent destructors.
    unsafe { libc::_exit(status) }
}

fn consumer(input: RawFd, output: RawFd, tag: u8) -> Result<()> {
    sys::private_namespace()?;
    check(
        // SAFETY: selected tree contains a precreated .old; only this child's namespace changes.
        unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                c"/current".as_ptr(),
                c"/current/.old".as_ptr(),
            )
        },
        "pivot_root",
    )?;
    std::env::set_current_dir("/").map_err(|_| error("cwd"))?;
    if MODE != "keep-old-root" {
        check(
            // SAFETY: .old is the previous private root, with no retained handles needed.
            unsafe { libc::umount2(c"/.old".as_ptr(), libc::MNT_DETACH) } as _,
            "detach old root",
        )?;
    }
    // SAFETY: duplicate the role's owned pipe ends onto its standard descriptors.
    check(unsafe { libc::dup2(input, 0) } as _, "command fd")?;
    // SAFETY: stdout becomes only this consumer's status pipe.
    check(unsafe { libc::dup2(output, 1) } as _, "status fd")?;
    let marker = File::open("/objects/early.bin").map_err(|_| error("sentinel open"))?;
    // SAFETY: a deliberate high-numbered validation handle must be closed by close_range.
    let high = check(
        unsafe { libc::fcntl(marker.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 300) } as _,
        "sentinel fd",
    )?;
    if high != 300 {
        return Err(("sentinel slot", 0));
    }
    drop(marker);
    let last = if MODE == "leak-fd" { 299u32 } else { u32::MAX };
    check(
        // SAFETY: role I/O is now at0..2; close every inherited validation/root handle.
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, last, 0u32) },
        "close_range",
    )?;
    for fd in 3..512 {
        // SAFETY: read-only descriptor query, no ownership is taken.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        {
            return Err(("descriptor leak", fd));
        }
    }
    drop_caps()?;
    layout("/")?;
    if fs::symlink_metadata("/proc").is_ok() {
        return Err(("old root reachable", 0));
    }
    compare("/", tag, &[0, 1], false)?;
    sys::send(1, b"R")?;
    let mut command = [0];
    sys::receive(0, &mut command)?;
    if command[0] == b'C' {
        // SAFETY: explicit cancellation has its own exact status and no retained marker.
        unsafe { libc::_exit(81) }
    }
    if command[0] != b'G' {
        return Err(("consumer command", 0));
    }
    compare("/", tag, &[0, 1, 2], false)?;
    sys::send(1, b"D")
}

fn spawn(input: &File, output: &File, tag: u8) -> Result<libc::pid_t> {
    // SAFETY: the fixture has no threads; the child exits via _exit, not parent destructors.
    let pid = check(unsafe { libc::fork() } as _, "fork consumer")? as libc::pid_t;
    if pid == 0 {
        finish(consumer(input.as_raw_fd(), output.as_raw_fd(), tag));
    }
    Ok(pid)
}

fn publisher(
    control: File,
    report: File,
    a_input: File,
    a_output: File,
    b_input: File,
    b_output: File,
) -> Result<()> {
    sys::private_namespace()?;
    fs::create_dir("/current").map_err(|_| error("selection directory"))?;
    staged("/stage-a", b'A')?;
    publish("/stage-a", b'A')?;
    let a = spawn(&a_input, &a_output, b'A')?;
    drop((a_input, a_output));
    sys::send(report.as_raw_fd(), &a.to_le_bytes())?;
    // C sends this only after A's actual post-pivot READY, not after fork alone.
    sys::byte(control.as_raw_fd(), b'B')?;
    let construction = (|| {
        staged("/stage-b", b'B')?;
        if MODE == "fail-clone" {
            return Err(("injected clone", 0));
        }
        publish("/stage-b", b'B')?;
        if MODE == "fail-after-move" {
            return Err(("injected after move", 0));
        }
        Ok(())
    })();
    let expected_fault = match MODE {
        "fail-file" => Some(("injected file", 0)),
        "fail-clone" => Some(("injected clone", 0)),
        "fail-move" => Some(("injected move", 0)),
        "fail-after-move" => Some(("injected after move", 0)),
        _ => None,
    };
    let selected = if matches!(MODE, "fail-file" | "fail-clone" | "fail-move") {
        b'A'
    } else {
        b'B'
    };
    let b = if let Some(expected) = expected_fault {
        if construction != Err(expected) {
            return Err(("wrong injected failure", 0));
        }
        0
    } else {
        construction?;
        spawn(&b_input, &b_output, b'B')?
    };
    drop((b_input, b_output));
    // This checks P's selection path separately from A's isolated retained root.
    layout("/current")?;
    compare("/current", selected, &[0, 1, 2], MODE == "wrong-late")?;
    let fault = match MODE {
        "fail-file" => 1,
        "fail-clone" => 2,
        "fail-move" => 3,
        "fail-after-move" => 4,
        _ => 0,
    };
    let mut phase = [0u8; 6];
    phase[..4].copy_from_slice(&b.to_le_bytes());
    phase[4] = selected;
    phase[5] = fault;
    sys::send(report.as_raw_fd(), &phase)?;
    if MODE == "publisher-crash" {
        check(
            // SAFETY: deliberate termination of this role only, after all handles are closed.
            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) } as _,
            "publisher kill",
        )?;
        return Err(("publisher survived kill", 0));
    }
    Ok(())
}

fn output(value: &str) -> Result<()> {
    sys::send(1, value.as_bytes())
}

fn initial_posture() -> Result<()> {
    // This is a conformance guard, not an authentication or namespace-origin proof.
    // SAFETY: identity queries take no pointers.
    let identity = unsafe { (libc::getpid(), libc::getuid()) };
    if identity != (1, 0) {
        return Err(("fixture namespace", 0));
    }
    if std::env::args_os().collect::<Vec<_>>() != [std::ffi::OsString::from("/fixture")] {
        return Err(("arguments", 0));
    }
    if std::env::vars_os().any(|(k, v)| k != "PWD" || v != "/") {
        return Err(("environment", 0));
    }
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| error("initial census"))? {
        let fd = entry
            .map_err(|_| error("census entry"))?
            .file_name()
            .to_string_lossy()
            .parse::<i32>()
            .map_err(|_| ("census name", 0))?;
        if !(0..=3).contains(&fd) {
            return Err(("initial descriptor", fd));
        }
    }
    let limit = libc::rlimit {
        rlim_cur: 512,
        rlim_max: 512,
    };
    check(
        // SAFETY: lowers the bound only for this isolated fixture and descendants.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } as _,
        "fd bound",
    )?;
    for fd in [1, 2] {
        // SAFETY: standard descriptors are owned pipes; make diagnostic writes nonblocking.
        let flags = check(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } as _,
            "stdio flags",
        )?;
        check(
            // SAFETY: integer flag update on the same open descriptor.
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags as i32 | libc::O_NONBLOCK) } as _,
            "stdio nonblocking",
        )?;
    }
    Ok(())
}

fn run() -> Result<()> {
    initial_posture()?;
    let (p_read, p_write) = sys::pipe()?;
    let (p_report, p_status) = sys::pipe()?;
    let (a_read, a_write) = sys::pipe()?;
    let (a_report, a_status) = sys::pipe()?;
    let (b_read, b_write) = sys::pipe()?;
    let (b_report, b_status) = sys::pipe()?;
    // SAFETY: no threads/reaper; each role gets fixed pipe ownership and exits via _exit.
    let p = check(unsafe { libc::fork() } as _, "fork publisher")? as libc::pid_t;
    if p == 0 {
        drop((p_write, p_report, a_write, a_report, b_write, b_report));
        finish(publisher(
            p_read, p_status, a_read, a_status, b_read, b_status,
        ));
    }
    drop((p_read, p_status, a_read, a_status, b_read, b_status));
    let mut first = [0u8; 4];
    sys::receive(p_report.as_raw_fd(), &mut first)?;
    let a = i32::from_le_bytes(first);
    if a <= 1 || a == p {
        return Err(("consumer identity", 0));
    }
    sys::byte(a_report.as_raw_fd(), b'R')?;
    output("{\"event\":\"a_ready\"}\n")?;
    sys::send(p_write.as_raw_fd(), b"B")?;
    drop(p_write);
    let mut second = [0u8; 6];
    sys::receive(p_report.as_raw_fd(), &mut second)?;
    let b = i32::from_le_bytes(second[..4].try_into().map_err(|_| ("phase length", 0))?);
    let expected_fault = match MODE {
        "fail-file" => 1,
        "fail-clone" => 2,
        "fail-move" => 3,
        "fail-after-move" => 4,
        _ => 0,
    };
    let expected_selected = if (1..=3).contains(&expected_fault) {
        b'A'
    } else {
        b'B'
    };
    if second[4..] != [expected_selected, expected_fault]
        || (b == 0) != (expected_fault != 0)
        || b < 0
        || b == a
        || b == p
    {
        return Err(("publication phase", 0));
    }
    if b != 0 {
        sys::byte(b_report.as_raw_fd(), b'R')?;
    }
    output(&format!(
        "{{\"event\":\"published\",\"selected\":\"{}\",\"b_started\":{}}}\n",
        char::from(expected_selected.to_ascii_lowercase()),
        b != 0
    ))?;
    let p_status = if MODE == "publisher-crash" {
        libc::SIGKILL
    } else {
        0
    };
    sys::wait(p, p_status)?;
    sys::eof(&p_report)?;
    output(&format!(
        "{{\"event\":\"publisher_reaped\",\"status\":{p_status}}}\n"
    ))?;
    let cancelled = MODE == "cancel";
    if !cancelled {
        output("{\"event\":\"late_release\"}\n")?;
    }
    sys::send(a_write.as_raw_fd(), if cancelled { b"C" } else { b"G" })?;
    if b != 0 {
        sys::send(b_write.as_raw_fd(), if cancelled { b"C" } else { b"G" })?;
    }
    drop((a_write, b_write));
    for (pid, report) in [(a, a_report), (b, b_report)] {
        if pid != 0 {
            if !cancelled {
                sys::byte(report.as_raw_fd(), b'D')?;
            }
            sys::wait(pid, if cancelled { 81 << 8 } else { 0 })?;
        }
        sys::eof(&report)?;
    }
    let a_result = if cancelled { "cancelled" } else { "retained" };
    let b_result = if b == 0 { "not-started" } else { a_result };
    output(&format!("{{\"case\":\"{MODE}\",\"publisher_terminated\":true,\"published\":\"{}\",\"consumer_a\":\"{a_result}\",\"consumer_b\":\"{b_result}\",\"handles_closed\":true}}\n",char::from(expected_selected.to_ascii_lowercase())))
}

pub(super) fn main() {
    finish(run());
}
