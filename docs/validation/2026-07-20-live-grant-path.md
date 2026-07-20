# Live grant-path validation, 2026-07-20

The automated suite exercises the auth pipeline against fake hardware (swtpm,
v4l2loopback) up to the point a genuine enrolled face is required, which no CI
runner can provide. This is the on-hardware counterpart: the shipped 0.3.0
build (`irlume-0.3.0-1...fc44`, daemon active) on the reference ASUS Zenbook S
14, IR camera at `/dev/video2`, one enrolled user, exercised live.

## Match (1:N identify)

`irlume identify` with the operator in frame:

```
[identify] wisbfime (profile 'BEN', score 0.806) ✅
```

Real IR capture, YuNet detection, and AuraFace matching against the enrolled
profile, through the production daemon. Score 0.806 against the shipped 0.55
RGB / 0.55 IR thresholds.

## Grant (face-sudo, full production path)

Face-`sudo` is wired on this host. Triggering it (empty-password gesture) and
reading the Linux audit records shows the whole path: the daemon captured IR,
matched, ran the liveness gate, and released the grant to PAM.

```
op=PAM:authentication grantors=pam_irlume acct="wisbfime" exe="/usr/bin/sudo" res=success
op=PAM:setcred        grantors=pam_irlume acct="root"     exe="/usr/bin/sudo" res=success
```

The correct negative also appears in the same records: a non-interactive
`sudo -n true` (which cannot fire the camera) is `res=failed`, so the grant
came from a real face capture, not a cached credential.

## What this covers that CI cannot

The genuine-face branches of the match and liveness code: the IR/RGB
recognition comparison returning a live above-threshold match, and the
liveness gate computing real depth, glint, reflectance, and frontality cues on
a live face and returning `live`. The loopback harness only reaches the
no-face denial because its ffmpeg feed contains no face. These paths stay
`#[ignore]`-only in the suite and are validated here instead.

No biometric data is recorded in this file: the audit lines contain none, and
0.806 is a scalar score, consistent with how the project already publishes
match and PAD numbers.
