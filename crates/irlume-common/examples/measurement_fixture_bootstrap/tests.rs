// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

#[test]
fn bootstrap_environment_is_exact_raw_pwd_not_authority() {
    assert!(runtime::environment_entries(&[b"PWD=/"], true));
    for entries in [
        vec![],
        vec![b"PWD=/wrong".as_slice()],
        vec![b"PWD=/", b"EXTRA=1"],
        vec![b"PWD=/", b"PWD=/"],
        vec![b"PWD=/", b"MALFORMED"],
        vec![b"PWD=\xff"],
    ] {
        assert!(!runtime::environment_entries(&entries, true));
    }
    assert!(runtime::environment_entries(&[], false));
    assert!(!runtime::environment_entries(&[b"PWD=/"], false));
}

#[test]
fn pins_are_exact_lowercase_sha256() {
    assert_eq!(pin(None), Err("pin-missing\n"));
    assert_eq!(pin(Some("bad")), Err("pin-invalid\n"));
    assert_eq!(pin(Some(&"A".repeat(64))), Err("pin-invalid\n"));
    assert_eq!(pin(Some(&"00".repeat(32))), Ok([0; 32]));
}

#[test]
fn short_and_interrupted_io_spends_one_shared_budget() {
    let mut budget = Budget(5);
    let mut calls = 0;
    let mut data = [0_u8; 3];
    read_exact(&mut data, 0, &mut budget, |buffer, _| {
        calls += 1;
        if calls == 1 {
            return Err(std::io::Error::from_raw_os_error(libc::EINTR));
        }
        buffer[0] = 9;
        Ok(1)
    })
    .unwrap();
    assert_eq!(data, [9; 3]);
    assert_eq!(budget.0, 1);
    let mut writes = 0;
    assert_eq!(
        write_all(&data, &mut budget, |_| {
            writes += 1;
            Ok(1)
        }),
        Err("io-budget\n")
    );
    assert_eq!(writes, 1);
}

#[test]
fn early_eof_zero_write_and_endless_eintr_refuse() {
    assert_eq!(
        read_exact(&mut [0; 1], 0, &mut Budget(5), |_, _| Ok(0)),
        Err("source-eof\n")
    );
    assert_eq!(write_all(&[1], &mut Budget(5), |_| Ok(0)), Err("write\n"));
    let mut budget = Budget(4);
    assert_eq!(
        read_exact(&mut [0; 1], 0, &mut budget, |_, _| Err(
            std::io::Error::from_raw_os_error(libc::EINTR)
        )),
        Err("io-budget\n")
    );
    assert_eq!(budget.0, 0);
}

#[test]
fn interrupted_reads_stop_after_exactly_1024_attempts() {
    let mut budget = Budget(MAX_IO_ATTEMPTS);
    let mut attempts = 0;
    let result = read_exact(&mut [0; 1], 0, &mut budget, |_, _| {
        attempts += 1;
        Err(io::Error::from_raw_os_error(libc::EINTR))
    });
    assert_eq!(result, Err("io-budget\n"));
    assert_eq!(attempts, 1024);
    assert_eq!(budget.0, 0);
}

#[test]
fn static_elf_rejects_scripts_pie_dynamic_and_truncation() {
    let mut bytes = [0; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    assert!(elf_header(&bytes[..64], 120).is_ok());
    bytes[16] = 3;
    assert_eq!(elf_header(&bytes[..64], 120), Err("elf-profile\n"));
    bytes[16] = 2;
    assert_eq!(elf_header(&bytes[..64], 90), Err("elf-table\n"));
    assert_eq!(elf_header(b"#!/bin/sh", 120), Err("elf-header\n"));
}

#[test]
fn kernel_seals_refuse_write_truncate_and_execution_mode_change() {
    let image = memfd().unwrap();
    let fd = image.as_raw_fd();
    assert_eq!(write(fd, &[1, 2, 3]).unwrap(), 3);
    // SAFETY: the test owns fd and deliberately sets its initial execution mode.
    assert_eq!(unsafe { libc::fchmod(fd, 0o500) }, 0);
    seal(fd, SEALS).unwrap();
    assert_eq!(
        write(fd, &[4]).unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    // SAFETY: each operation targets only the test-owned, sealed memfd.
    assert_eq!(unsafe { libc::ftruncate(fd, 1) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    // SAFETY: same test-owned memfd; F_SEAL_EXEC must lock executable bits.
    assert_eq!(unsafe { libc::fchmod(fd, 0o400) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    // SAFETY: F_GET_SEALS does not dereference pointers.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & SEALS, SEALS);
}

#[test]
fn kernel_missing_seal_and_shared_writable_mapping_refuse() {
    let image = memfd().unwrap();
    assert_eq!(
        seal(image.as_raw_fd(), SEALS & !libc::F_SEAL_EXEC),
        Err("seal-readback\n")
    );
    let image = memfd().unwrap();
    let fd = image.as_raw_fd();
    // SAFETY: this grows only a new test memfd, before mapping it.
    assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
    // SAFETY: 4096-byte shared mapping of a test-owned fd; released below.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_WRITE | libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    let outcome = seal(fd, SEALS);
    // SAFETY: mapping was returned by the successful mmap call above.
    assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
    assert_eq!(outcome, Err("seal\n"));
}

#[test]
fn kernel_snapshot_is_positional_and_sealed_bytes_survive_source_mutation() {
    let source = memfd().unwrap();
    write_all(&[7; 4096], &mut Budget(4), |b| write(source.as_raw_fd(), b)).unwrap();
    let mut budget = Budget(1024);
    // The source cursor is already at EOF. Only positional reads can succeed.
    let image = snapshot(source.as_raw_fd(), &mut budget).unwrap();
    seal(image.as_raw_fd(), SEALS).unwrap();
    assert_eq!(
        // SAFETY: replace bytes in the unsealed test source, not the snapshot.
        unsafe { libc::pwrite(source.as_raw_fd(), [8; 4096].as_ptr().cast(), 4096, 0) },
        4096
    );
    assert_eq!(
        hash(image.as_raw_fd(), 4096, &mut budget).unwrap(),
        Sha256::digest([7; 4096]).as_slice()
    );
    assert_ne!(
        hash(source.as_raw_fd(), 4096, &mut budget).unwrap(),
        hash(image.as_raw_fd(), 4096, &mut budget).unwrap()
    );
}

#[test]
fn kernel_source_limits_and_changed_metadata_refuse() {
    let source = memfd().unwrap();
    assert_eq!(
        source_size(&stat(source.as_raw_fd()).unwrap()),
        Err("source-size\n")
    );
    assert_eq!(
        // SAFETY: only a private memfd is resized; no allocation or host file.
        unsafe { libc::ftruncate(source.as_raw_fd(), LIMIT as i64 + 1) },
        0
    );
    assert_eq!(
        source_size(&stat(source.as_raw_fd()).unwrap()),
        Err("source-size\n")
    );
    assert_eq!(
        // SAFETY: resize the same private source to the inclusive bound.
        unsafe { libc::ftruncate(source.as_raw_fd(), LIMIT as i64) },
        0
    );
    let before = stat(source.as_raw_fd()).unwrap();
    assert_eq!(source_size(&before), Ok(LIMIT));
    let image = snapshot(source.as_raw_fd(), &mut Budget(1024)).unwrap();
    assert_eq!(stat(image.as_raw_fd()).unwrap().st_size, LIMIT as i64);
    // SAFETY: an observed source truncation must alter the metadata snapshot.
    assert_eq!(unsafe { libc::ftruncate(source.as_raw_fd(), 12) }, 0);
    assert!(!unchanged(&before, &stat(source.as_raw_fd()).unwrap()));
}
