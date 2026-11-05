// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

fn restore_confirmation_mode(id: &crate::uvc_descriptor::CameraIdentity) -> UvcMode {
    let lock = crate::stream_record::acquire(id).unwrap();
    let (restore, record) = crate::stream_record::claim(lock, id, 14, 6, &[1, 3, 2]).unwrap();
    UvcMode {
        handle: None,
        record: Some(record),
        _lock: None,
        unit: 14,
        selector: 6,
        restore,
        applied: vec![1, 3, 2],
        armed: true,
        active: true,
    }
}

#[test]
fn restore_confirmation_ignored_acknowledgement_keeps_record_claimable() {
    let _lock = crate::testenv::env_lock();
    let fixture = ConfigurationFixture::new("confirmation-ignored");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &fixture.root);
    let id = identity(0x3277, 0x0059);
    let path = plant_record(&fixture.root, &id, 14, 6, &[1, 3, 2], &[1, 3, 1], true);
    let _fake = fake_camera::install(fake_camera::Camera {
        current: vec![1, 3, 2],
        ignore_set_at: Some(1),
        ..a_working_camera()
    });
    let mut mode = restore_confirmation_mode(&id);
    let result = mode.restore();
    assert!(matches!(result, Err(RestoreError::Camera(_))), "{result:?}");
    assert_eq!(fake_camera::current(), vec![1, 3, 2]);
    let record: crate::stream_record::StreamWrite =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(record.state, crate::stream_record::WriteState::Applied);
    assert_eq!(record.restore_attempts, 1);
    let after = fake_camera::log();
    drop(mode);
    assert_eq!(fake_camera::log(), after, "Drop must not retry");
    let mut retry = restore_confirmation_mode(&id);
    retry.restore().unwrap();
    assert_eq!(fake_camera::current(), vec![1, 3, 1]);
    assert!(!path.exists());
}

#[test]
fn restore_confirmation_read_failure_preserves_record() {
    let _lock = crate::testenv::env_lock();
    let fixture = ConfigurationFixture::new("confirmation-read-failed");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &fixture.root);
    let id = identity(0x3277, 0x0059);
    let path = plant_record(&fixture.root, &id, 14, 6, &[1, 3, 2], &[1, 3, 1], true);
    let failed = std::rc::Rc::new(std::cell::Cell::new(false));
    let check = failed.clone();
    let _fake = fake_camera::install(fake_camera::Camera {
        current: vec![1, 3, 2],
        configuration_check: Some(Box::new(move || {
            if check.get() {
                Err(XuError::Unresponsive(libc::EIO))
            } else {
                Ok(())
            }
        })),
        at_first_write: Some(Box::new(move || {
            failed.set(true);
            Ok(())
        })),
        ..a_working_camera()
    });
    let mut mode = restore_confirmation_mode(&id);
    let result = mode.restore();
    assert!(matches!(result, Err(RestoreError::Camera(_))), "{result:?}");
    let record: crate::stream_record::StreamWrite =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(record.state, crate::stream_record::WriteState::Applied);
    assert_eq!(record.restore_attempts, 1);
    let after = fake_camera::log();
    drop(mode);
    assert_eq!(fake_camera::log(), after);
}

#[test]
fn restore_confirmation_unrecorded_ignored_write_reports_failure() {
    let _fake = fake_camera::install(fake_camera::Camera {
        current: vec![1, 3, 2],
        ignore_set_at: Some(1),
        ..a_working_camera()
    });
    let mut mode = UvcMode {
        handle: None,
        record: None,
        _lock: None,
        unit: 14,
        selector: 6,
        restore: vec![1, 3, 1],
        applied: vec![1, 3, 2],
        armed: true,
        active: true,
    };
    assert!(matches!(mode.restore(), Err(RestoreError::Camera(_))));
    let after = fake_camera::log();
    drop(mode);
    assert_eq!(fake_camera::log(), after);
}

#[test]
fn restore_confirmation_success_resolves_the_record() {
    let _lock = crate::testenv::env_lock();
    let fixture = ConfigurationFixture::new("confirmation-success");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &fixture.root);
    let id = identity(0x3277, 0x0059);
    let path = plant_record(&fixture.root, &id, 14, 6, &[1, 3, 2], &[1, 3, 1], true);
    let _fake = fake_camera::install(fake_camera::Camera {
        current: vec![1, 3, 2],
        ..a_working_camera()
    });
    let mut mode = restore_confirmation_mode(&id);
    mode.restore().unwrap();
    assert_eq!(fake_camera::current(), vec![1, 3, 1]);
    assert!(!path.exists());
}

#[test]
fn restore_confirmation_changed_control_is_not_written() {
    let _lock = crate::testenv::env_lock();
    let fixture = ConfigurationFixture::new("confirmation-third-party");
    let _state = EnvGuard::set("IRLUME_STATE_DIR", &fixture.root);
    let id = identity(0x3277, 0x0059);
    let path = plant_record(&fixture.root, &id, 14, 6, &[1, 3, 2], &[1, 3, 1], true);
    let _fake = fake_camera::install(fake_camera::Camera {
        current: vec![7, 7, 7],
        ..a_working_camera()
    });
    let mut mode = restore_confirmation_mode(&id);
    mode.restore().unwrap();
    assert_eq!(fake_camera::current(), vec![7, 7, 7]);
    assert!(!path.exists());
    assert!(!fake_camera::log()
        .iter()
        .any(|r| matches!(r, fake_camera::Request::Set(_))));
}

#[test]
fn restore_confirmation_rejected_write_stops_camera_io() {
    let _fake = fake_camera::install(fake_camera::Camera {
        current: vec![1, 3, 2],
        fail_set_from: Some((1, libc::EIO)),
        ..a_working_camera()
    });
    let mut mode = UvcMode {
        handle: None,
        record: None,
        _lock: None,
        unit: 14,
        selector: 6,
        restore: vec![1, 3, 1],
        applied: vec![1, 3, 2],
        armed: true,
        active: true,
    };
    assert!(matches!(mode.restore(), Err(RestoreError::Camera(_))));
    drop(mode);
    assert_eq!(
        fake_camera::log(),
        vec![
            fake_camera::Request::Get {
                query: UVC_GET_CUR,
                size: 3
            },
            fake_camera::Request::Set(vec![1, 3, 1])
        ]
    );
}
