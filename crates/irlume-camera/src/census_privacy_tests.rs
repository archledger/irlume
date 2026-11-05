// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#[test]
fn privacy_missing_node_is_unknown_not_released() {
    let roots = crate::hostfs::test::empty_fixture();
    let missing = roots.dev().join("video7").to_string_lossy().into_owned();
    let facts = facts_for(&missing, Role::Rgb, &Default::default());
    assert_eq!(
        facts.privacy, None,
        "an unsuccessful observation is not a released shutter"
    );
    let entry = node_entry_from_facts(&facts);
    assert_eq!(entry.privacy_engaged, None);
    assert_eq!(
        serde_json::to_value(&entry).unwrap().get("privacy_engaged"),
        Some(&serde_json::Value::Null)
    );
    assert!(!render_line(&entry).contains("privacy shutter"));
}

#[test]
fn privacy_observation_preserves_answered_and_absent_states() {
    assert_eq!(privacy_from_state(Ok(Some(true))), Some(true));
    assert_eq!(privacy_from_state(Ok(Some(false))), Some(false));
    assert_eq!(privacy_from_state(Ok(None)), Some(false));
    for errno in [libc::EIO, libc::EACCES, libc::ENODEV] {
        assert_eq!(
            privacy_from_state(Err(std::io::Error::from_raw_os_error(errno))),
            None
        );
    }
}
