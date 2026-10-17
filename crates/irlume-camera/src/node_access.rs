// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Whether a camera node is closed to everyone but root: the hard boundary
//! behind ADR-0031 §4 (Amendment 2026-10-17, #1069).
//!
//! A descriptor-attested YUYV IR camera without per-frame illumination records
//! gets its active-IR evidence from the burst's own proven alternation. That
//! proof reads the emitter control before and after the burst, and those reads
//! cannot see a change made and undone within the burst by another program
//! with access to the camera (`UVCIOC_CTRL_QUERY` carries no V4L2 priority).
//! When the node itself is closed to every non-root program, no such program
//! can run: the reads around the burst become the whole story and the evidence
//! no longer needs the experimental opt-in's confinement.
//!
//! The check reads the node's *current* state: owner, group, mode, the access
//! ACL, and whether the udev database still records the seat tag for it. A
//! node whose seat-user ACL is stale from before the rule shipped keeps the
//! confinement until the node is actually clean, and so does a node hardened
//! by hand on a live system (its database record keeps the tag, so the state
//! reverts at the next seat switch and proves nothing about descriptors opened
//! before). Every error reads as [`NodeAccess::Unreadable`], which is never
//! hardened.
//!
//! Two boundaries are deliberate. The group is NOT accepted: irlume's own
//! `EACCES` advice tells users to join `video`, so a seat user there would
//! silently keep full access to a root:video node. And permissions are checked
//! at open(2), so a descriptor opened before the node was closed stays usable.
//! The packaged rule's plug/boot application is the establishment proof for
//! that; a hand-set `chmod` on a live node has no such proof, and it is not
//! even stable, since logind re-grants the seat ACL at the next seat switch
//! while the udev database still carries the tag as current (its `Q:` lines;
//! the `G:` union is historical and never clears). The check below
//! therefore requires the tag's absence from the node's current tags, which
//! only a rule that removes it produces. The one window that leaves is an
//! administrator running `udevadm trigger` against the documentation: every
//! doc names plug/boot as the application path.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The access state of one camera node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAccess {
    /// Only root can open the node.
    Hardened,
    /// A non-root principal can open the node. The string names what grants
    /// it, for a doctor row; it is elaboration for a person, not a stable
    /// value to match on.
    Shared(String),
    /// The state could not be read. Unreadable never reads as hardened.
    Unreadable,
}

/// The node as the kernel last set it up: owner, group, mode and any access
/// ACL. Hardened is root-only: root-owned, root group, no group or world
/// permission, and no ACL entry naming another user or group.
pub fn node_access(path: &Path) -> NodeAccess {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return NodeAccess::Unreadable,
    };
    if meta.uid() != 0 {
        return NodeAccess::Shared(format!("owned by uid {}", meta.uid()));
    }
    if meta.gid() != 0 {
        return NodeAccess::Shared(format!("group {} can open it", meta.gid()));
    }
    match read_access_acl(path) {
        Err(_) => return NodeAccess::Unreadable,
        // No ACL: the mode alone governs.
        Ok(None) => {
            if meta.mode() & 0o077 != 0 {
                return NodeAccess::Shared("its group or the world can open it".to_string());
            }
        }
        Ok(Some(acl)) => match acl_keeps_it_closed(&acl) {
            Ok(true) => {}
            Ok(false) => {
                return NodeAccess::Shared(
                    "an access ACL names a user or group, or gives others permission".to_string(),
                )
            }
            Err(_) => return NodeAccess::Unreadable,
        },
    }
    // The seat tag must be gone from the node's udev database record, which is
    // what removing it in a rule (the packaged one, or an administrator's own)
    // records. While the tag is recorded, logind re-grants the seat ACL at the
    // next seat switch, and a hand-set permission change proves nothing about
    // descriptors opened before it (Codex #1109 round 3). Only a real device
    // node has a record; anything else is outside this module's question.
    if std::os::unix::fs::FileTypeExt::is_char_device(&meta.file_type()) {
        match db_records_seat_tag(meta.rdev()) {
            Some(true) => {
                return NodeAccess::Shared(
                    "the udev database still carries the seat tag as current for it, so \
                 permissions set by hand revert at the next seat switch and prove nothing \
                 about a descriptor opened before them; the packaged rule and a replug or \
                 boot are the durable form"
                        .to_string(),
                )
            }
            Some(false) => {}
            None => return NodeAccess::Unreadable,
        }
    }
    NodeAccess::Hardened
}

/// The major and minor of a device number, as glibc's `major`/`minor` split
/// them, for the `/run/udev/data/c<major>:<minor>` record name.
fn split_rdev(rdev: u64) -> (u32, u32) {
    (
        (((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xffff_f000)) as u32,
        ((rdev & 0xff) | ((rdev >> 12) & 0xffff_ff00)) as u32,
    )
}

/// Whether the node's udev database record carries the `uaccess` seat tag as
/// a CURRENT tag: `Some(true)` or `Some(false)` from the record, or `None`
/// when the record cannot be read or its format is unknown. The record's `G:`
/// lines are the historical union of every tag the device has had (a removed
/// tag stays listed; systemd `device_update_db`, and `device_remove_tag`
/// clears only the current set), so the answer reads the `Q:` lines, which
/// are what the uaccess builtin and logind consult. A record with no `V:`
/// version line predates the current-tags format and is unknown.
fn db_records_seat_tag(rdev: u64) -> Option<bool> {
    db_records_seat_tag_in(Path::new("/run/udev/data"), rdev)
}

/// [`db_records_seat_tag`] with the database root as an argument, so a test
/// drives it against a fixture directory.
fn db_records_seat_tag_in(db_root: &Path, rdev: u64) -> Option<bool> {
    let (major, minor) = split_rdev(rdev);
    let content = std::fs::read_to_string(db_root.join(format!("c{major}:{minor}"))).ok()?;
    db_content_records_seat_tag(&content)
}

/// The current tags of a udev database record are its `Q:<tag>` lines, under
/// a `V:<n>` database-version line. `G:` lines are the union of every tag the
/// record has ever carried and never lose a removed one.
fn db_content_records_seat_tag(content: &str) -> Option<bool> {
    if !content.lines().any(|line| line.starts_with("V:")) {
        return None;
    }
    Some(content.lines().any(|line| line == "Q:uaccess"))
}

/// The node's `system.posix_acl_access`, or `None` when it has only its
/// ordinary mode entries. A filesystem without ACL support (ENOTSUP) reads as
/// no ACL, because the mode alone governs there. Reads by path, never by
/// opening the node: a hardened node refuses an unprivileged open, which is
/// the state this check exists to report.
fn read_access_acl(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    const NAME: &[u8] = b"system.posix_acl_access\0";
    let c_path = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c_path) => c_path,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "node path carries an interior NUL",
            ))
        }
    };
    // SAFETY: both pointers stay valid for the call; a null buffer with size 0
    // asks the kernel for the required size.
    let size = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            NAME.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size < 0 {
        let error = std::io::Error::last_os_error();
        return if matches!(
            error.raw_os_error(),
            Some(libc::ENODATA) | Some(libc::ENOTSUP)
        ) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: buf is size bytes; both pointers stay valid for the call.
    let got = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            NAME.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if got < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(Some(buf))
}

/// Whether an access ACL keeps the node closed to everyone but root: no named
/// user or group entries, no permission for others, and no *effective* group
/// permission either - the owning group is already required to be root's, but
/// a non-root process whose supplementary groups include gid 0 opens a
/// GROUP_OBJ-writable node all the same (Codex #1109 round 2). The base
/// entries must all be present, since the kernel writes them together; a
/// malformed ACL is an error, and an error never reads as hardened.
fn acl_keeps_it_closed(acl: &[u8]) -> std::io::Result<bool> {
    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_USER: u16 = 0x02;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_GROUP: u16 = 0x08;
    const ACL_MASK: u16 = 0x10;
    const ACL_OTHER: u16 = 0x20;
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "access ACL does not parse");
    if acl.len() < 4 || u32::from_le_bytes(acl[..4].try_into().unwrap()) != 2 {
        return Err(invalid());
    }
    let entries = &acl[4..];
    if entries.len() % 8 != 0 || entries.is_empty() {
        return Err(invalid());
    }
    let mut user_obj = None;
    let mut group_obj: Option<u16> = None;
    let mut mask: Option<u16> = None;
    let mut other = None;
    for entry in entries.chunks_exact(8) {
        let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
        let perm = u16::from_le_bytes(entry[2..4].try_into().unwrap());
        match tag {
            ACL_USER | ACL_GROUP => return Ok(false),
            ACL_USER_OBJ => user_obj = Some(perm),
            ACL_GROUP_OBJ => group_obj = Some(perm),
            ACL_MASK => mask = Some(perm),
            ACL_OTHER => other = Some(perm),
            _ => {}
        }
    }
    let (Some(_), Some(group_obj), Some(other)) = (user_obj, group_obj, other) else {
        return Err(invalid());
    };
    // MASK bounds named entries (rejected above) and the group object alike;
    // without a mask the mode's group bits are the group object's.
    let effective_group = mask.map_or(group_obj, |mask| group_obj & mask);
    Ok(effective_group == 0 && other == 0)
}

/// Whether the ADR-0031 §4 burst proof may read this node as access-hardened.
pub(crate) fn hardened(path: &Path) -> bool {
    matches!(node_access(path), NodeAccess::Hardened)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// POSIX ACL wire format (acl(5)): u32 version (2), then 8-byte entries
    /// { u16 tag, u16 perm, u32 id }.
    fn acl_bytes(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = 2u32.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    #[test]
    fn base_acl_entries_keep_the_node_hardened() {
        let acl = acl_bytes(&[
            (0x01, 0b110, u32::MAX), // USER_OBJ rw (root)
            (0x04, 0b000, u32::MAX), // GROUP_OBJ none (root group)
            (0x20, 0b000, u32::MAX), // OTHER none
        ]);
        assert!(super::acl_keeps_it_closed(&acl).expect("a base ACL parses"));
    }

    /// Codex #1109 round 2: a writable group object lets a non-root process
    /// whose supplementary groups include gid 0 open the node, and MASK is
    /// what bounds the group object's effective permission.
    #[test]
    fn a_writable_group_object_shares_the_node() {
        let with_mask = acl_bytes(&[
            (0x01, 0b110, u32::MAX),
            (0x04, 0b110, u32::MAX), // GROUP_OBJ rw
            (0x10, 0b110, u32::MAX), // MASK rw
            (0x20, 0b000, u32::MAX),
        ]);
        assert!(!super::acl_keeps_it_closed(&with_mask).expect("parses"));
        let without_mask = acl_bytes(&[
            (0x01, 0b110, u32::MAX),
            (0x04, 0b100, u32::MAX), // GROUP_OBJ r, no mask: the mode's group bit
            (0x20, 0b000, u32::MAX),
        ]);
        assert!(!super::acl_keeps_it_closed(&without_mask).expect("parses"));
        // A zero mask clears the group object's effective permission.
        let masked_off = acl_bytes(&[
            (0x01, 0b110, u32::MAX),
            (0x04, 0b110, u32::MAX),
            (0x10, 0b000, u32::MAX),
            (0x20, 0b000, u32::MAX),
        ]);
        assert!(super::acl_keeps_it_closed(&masked_off).expect("parses"));
    }

    /// A base entry missing from the set the kernel writes together is
    /// malformed, and malformed never reads hardened.
    #[test]
    fn an_incomplete_base_acl_is_an_error() {
        let no_other = acl_bytes(&[(0x01, 0b110, u32::MAX), (0x04, 0b000, u32::MAX)]);
        assert!(super::acl_keeps_it_closed(&no_other).is_err());
        let no_group = acl_bytes(&[(0x01, 0b110, u32::MAX), (0x20, 0b000, u32::MAX)]);
        assert!(super::acl_keeps_it_closed(&no_group).is_err());
    }

    #[test]
    fn a_named_user_acl_entry_shares_the_node() {
        let acl = acl_bytes(&[
            (0x01, 0b110, u32::MAX),
            (0x02, 0b110, 1000), // named user, the seat's
            (0x04, 0b110, u32::MAX),
            (0x10, 0b110, u32::MAX),
            (0x20, 0b000, u32::MAX),
        ]);
        assert!(!super::acl_keeps_it_closed(&acl).expect("the ACL parses"));
    }

    #[test]
    fn a_named_group_acl_entry_shares_the_node() {
        let acl = acl_bytes(&[
            (0x01, 0b110, u32::MAX),
            (0x04, 0b110, u32::MAX),
            (0x08, 0b100, 1000), // named group
            (0x10, 0b100, u32::MAX),
            (0x20, 0b000, u32::MAX),
        ]);
        assert!(!super::acl_keeps_it_closed(&acl).expect("the ACL parses"));
    }

    #[test]
    fn world_permission_in_the_acl_shares_the_node() {
        let acl = acl_bytes(&[
            (0x01, 0b110, u32::MAX),
            (0x04, 0b110, u32::MAX),
            (0x20, 0b100, u32::MAX), // OTHER read
        ]);
        assert!(!super::acl_keeps_it_closed(&acl).expect("the ACL parses"));
    }

    #[test]
    fn a_malformed_acl_is_an_error_never_hardened() {
        assert!(super::acl_keeps_it_closed(&[]).is_err());
        assert!(super::acl_keeps_it_closed(&1u32.to_le_bytes()).is_err());
        let mut truncated = acl_bytes(&[(0x01, 0b110, u32::MAX)]);
        truncated.truncate(truncated.len() - 3);
        assert!(super::acl_keeps_it_closed(&truncated).is_err());
    }

    #[test]
    fn a_missing_node_reads_unreadable() {
        assert_eq!(
            node_access(Path::new("/dev/irlume-no-such-node")),
            NodeAccess::Unreadable
        );
    }

    #[test]
    fn a_world_accessible_node_reads_shared() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("irlume-node-access-{}-world", std::process::id()));
        std::fs::write(&tmp, b"").unwrap();
        let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o666);
        std::fs::set_permissions(&tmp, perms).unwrap();
        let state = node_access(&tmp);
        std::fs::remove_file(&tmp).unwrap();
        // A user-owned file trips the ownership check first; a root-owned one
        // (root lanes) reaches the world check. Either way 0666 is shared.
        // SAFETY: geteuid has no inputs to invalidate and never fails.
        let euid = unsafe { libc::geteuid() };
        match state {
            NodeAccess::Shared(ref why) if euid == 0 => {
                assert!(why.contains("world"), "got {state:?}")
            }
            NodeAccess::Shared(_) => {}
            other => panic!("0666 must read shared, got {other:?}"),
        }
    }

    /// A file readable by its group must read shared even when everything
    /// else is root's: the group boundary is not accepted (Codex #1109 round
    /// 1: irlume's own EACCES advice tells users to join `video`).
    #[test]
    fn a_group_readable_node_reads_shared() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("irlume-node-access-{}-group", std::process::id()));
        std::fs::write(&tmp, b"").unwrap();
        let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o640);
        std::fs::set_permissions(&tmp, perms).unwrap();
        let state = node_access(&tmp);
        std::fs::remove_file(&tmp).unwrap();
        assert!(
            matches!(state, NodeAccess::Shared(_)),
            "0640 must read shared, got {state:?}"
        );
    }

    /// Codex #1109 rounds 3 and 4: the durable hardened form needs the seat
    /// tag gone from the node's udev database record, which a tag-removing
    /// rule records and a hand-set permission change does not; and the record
    /// keeps a removed tag in its historical `G:` union forever, so the answer
    /// reads the current-tag `Q:` lines under a `V:` version line.
    #[test]
    fn the_database_record_decides_durability() {
        // A tagged node today (udev 259 shape).
        let tagged = "S:v4l/by-path/x-video-index0\nI:6894099\nE:ID_TYPE=video\nG:seat\nG:uaccess\nQ:seat\nQ:uaccess\nV:1\n";
        assert_eq!(db_content_records_seat_tag(tagged), Some(true));
        // The round-4 regression case: the rule removed the tag, so current
        // tags drop it while the historical union keeps it forever.
        let hardened = "S:v4l/by-path/x-video-index0\nI:6894099\nG:seat\nG:uaccess\nQ:seat\nV:1\n";
        assert_eq!(db_content_records_seat_tag(hardened), Some(false));
        // A record without the database-version line predates the
        // current-tags format and cannot answer.
        let ancient = "G:seat\nG:uaccess\n";
        assert_eq!(db_content_records_seat_tag(ancient), None);
        assert_eq!(db_content_records_seat_tag(""), None);
        // A longer tag that merely starts with the name is not the tag.
        assert_eq!(
            db_content_records_seat_tag("G:uaccess\nQ:uaccess-debug\nV:1\n"),
            Some(false)
        );

        let root = std::env::temp_dir().join(format!("irlume-udev-db-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let record = root.join("c81:2");
        std::fs::write(&record, tagged).unwrap();
        assert_eq!(db_records_seat_tag_in(&root, (81 << 8) | 2), Some(true));
        std::fs::write(&record, hardened).unwrap();
        assert_eq!(db_records_seat_tag_in(&root, (81 << 8) | 2), Some(false));
        std::fs::remove_file(&record).unwrap();
        assert_eq!(db_records_seat_tag_in(&root, (81 << 8) | 2), None);
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn split_rdev_matches_the_sysfs_record_name() {
        // /dev/video2 is 81:2; the record is c81:2.
        assert_eq!(split_rdev((81 << 8) | 2), (81, 2));
        // A major above 4096 exercises the high-field split (Linux dev_t).
        let (major, minor) = split_rdev((259 << 8) | 99);
        assert_eq!((major, minor), (259, 99));
    }

    #[test]
    fn ownership_and_group_decide() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("irlume-node-access-{}-owner", std::process::id()));
        std::fs::write(&tmp, b"").unwrap();
        let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
        std::fs::set_permissions(&tmp, perms).unwrap();
        let state = node_access(&tmp);
        std::fs::remove_file(&tmp).unwrap();
        // Root-run lanes (some CI containers) create the file uid 0 gid 0:
        // hardened. User lanes create it owned by the user: shared.
        // SAFETY: geteuid has no inputs to invalidate and never fails.
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(state, NodeAccess::Hardened);
        } else {
            assert!(
                matches!(state, NodeAccess::Shared(ref why) if why.contains("uid")),
                "a node owned by the seat user must read shared, got {state:?}"
            );
        }
    }
}
