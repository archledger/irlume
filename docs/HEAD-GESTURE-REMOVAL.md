# Head-gesture removal

Head gestures are removed in the unreleased source build after 0.11.3. Face
authentication no longer watches for nods or shakes before or after matching.
The change removes an optional intent step; it does not change recognition
thresholds, passive PAD, IR provenance, camera binding, retry accounting, or the
credential-release authorization boundary. Existing keyboard confirmation policy
for privileged PAM requests is unchanged. Cancel through the authentication
prompt; password and fingerprint fallback remain available.

The CLI `credential-release-challenge` command, developer `gesturecap` tool,
TUI gesture settings, and gesture-specific diagnostics are removed. Unknown
commands return an error and do not alter configuration.

Existing settings no longer affect authentication. Administrators may remove
`credential_release_challenge`, `service_gesture.*`, `polkit_gesture`, and
`consent_gesture` from `/etc/irlume/settings.conf`. Also remove old gesture-only
service environment overrides: `IRLUME_CREDENTIAL_RELEASE_CHALLENGE`,
`IRLUME_POLKIT_GESTURE`, `IRLUME_CONSENT_GESTURE`, `IRLUME_CONSENT_MAX_FRAMES`,
`IRLUME_DUMP_POSE_SERIES`, `IRLUME_NOD_PITCH_MIN`, and `IRLUME_SHAKE_*`.
These values cannot re-enable the deleted feature. No enrollment migration or
recapture is required. The separate retired eyes-open enrollment blocker still
requires `irlume profiles eyes-open off`; this change does not clear it.

Contract 1 retains the reserved doctor check `credential-release-challenge` as
`info`, and the wire field `declined_by_gesture` is always false from the new
daemon. Clients retain deny-only decoding of an older daemon's cancellation.
These compatibility fields perform no gesture detection and expose no controls.
Historical research and ADRs describe previous versions, not current behavior.
