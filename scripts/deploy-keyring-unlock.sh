#!/usr/bin/env bash
# Deploy irlume keyring-unlock + face login/lock: install the rebuilt
# daemon/PAM/CLI, load the SELinux policy that lets the greeter reach the
# daemon socket, then wire face auth into the plasmalogin login greeter AND the
# KDE lock screen.
#
# FAIL-SAFE BY DESIGN: every face line is `[success=1 default=ignore]` or
# `sufficient`, so if the daemon/TPM/face/camera ever fails, login, lock, and
# wallet all fall through to the password exactly as today. The password is
# always the floor — this cannot lock you out.
#
# Run as root:  sudo bash scripts/deploy-keyring-unlock.sh
# Revert:       sudo bash scripts/deploy-keyring-unlock.sh --revert
set -euo pipefail

REPO="/home/wisbfime/irlume"
PAM_GREETER="/etc/pam.d/plasmalogin"
VENDOR_GREETER="/usr/lib/pam.d/plasmalogin"
MARKER="# irlume: face-unlock wiring — delete this file to restore the vendor copy"

# KDE lock screen rides the non-interactive `kde-fingerprint` parallel stack
# (kscreenlocker starts it the moment the screen appears) so face unlock needs
# no key press and never touches pam_unix/faillock. Plain verify with `wait`:
# the wallet is already open in-session, so no unseal is needed.
PAM_LOCK="/etc/pam.d/kde-fingerprint"
LOCK_STANZA="auth        sufficient    pam_irlume.so wait"
LOCK_BACKUP="${PAM_LOCK}.pre-irlume"

SELINUX_DIR="$REPO/packaging/selinux"
SELINUX_PP="$SELINUX_DIR/irlume.pp"

if [[ "${1:-}" == "--revert" ]]; then
    echo "[revert] removing greeter override + restoring vendor plasmalogin"
    if [[ -f "$PAM_GREETER" ]] && grep -q "irlume: face-unlock wiring" "$PAM_GREETER"; then
        rm -f "$PAM_GREETER"
        echo "[revert] removed $PAM_GREETER (vendor $VENDOR_GREETER is authoritative again)"
    else
        echo "[revert] no irlume-managed $PAM_GREETER found — nothing to undo"
    fi
    echo "[revert] unwiring lock screen ($PAM_LOCK)"
    if [[ -f "$LOCK_BACKUP" ]]; then
        mv -f "$LOCK_BACKUP" "$PAM_LOCK"
        echo "[revert] restored $PAM_LOCK from backup"
    elif [[ -f "$PAM_LOCK" ]] && grep -q "pam_irlume.so" "$PAM_LOCK"; then
        grep -v "pam_irlume.so" "$PAM_LOCK" > "${PAM_LOCK}.tmp" && mv "${PAM_LOCK}.tmp" "$PAM_LOCK"
        echo "[revert] stripped pam_irlume line from $PAM_LOCK"
    else
        echo "[revert] no irlume line in $PAM_LOCK — nothing to undo"
    fi
    echo "[revert] removing SELinux module"
    semodule -r irlume 2>/dev/null && echo "[revert] removed SELinux module 'irlume'" || echo "[revert] no SELinux module 'irlume'"
    echo "[revert] (daemon/PAM/CLI binaries left in place; 'systemctl disable --now irlumed' to stop)"
    exit 0
fi

[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }

echo "=== 1/5 install rebuilt binaries ==="
install -m755 "$REPO/target/release/irlumed"  /usr/local/bin/irlumed
install -m755 "$REPO/target/release/irlume"   /usr/local/bin/irlume
install -m644 "$REPO/target/release/libpam_irlume.so" /usr/lib64/security/pam_irlume.so
echo "    installed irlumed, irlume, pam_irlume.so"

echo "=== 2/5 load SELinux policy (greeter → daemon socket) ==="
if ! semodule -l | grep -q '^irlume$'; then
    if [[ ! -f "$SELINUX_PP" ]]; then
        echo "    building $SELINUX_PP"
        ( cd "$SELINUX_DIR" && make -f /usr/share/selinux/devel/Makefile irlume.pp >/dev/null )
    fi
    semodule -i "$SELINUX_PP"
    echo "    installed SELinux module 'irlume'"
else
    echo "    SELinux module 'irlume' already loaded"
fi

echo "=== 3/5 restart daemon (loads UnsealPassword handler; relabels socket) ==="
systemctl restart irlumed.service
sleep 2
systemctl is-active irlumed.service >/dev/null && echo "    irlumed active" || { echo "daemon failed to start"; exit 1; }
echo "    socket label: $(ls -Z /run/irlume.sock 2>/dev/null | awk '{print $1}')"

echo "=== 4/5 wire plasmalogin greeter (face → KWallet unlock) ==="
if [[ -f "$PAM_GREETER" ]] && grep -q "pam_irlume.so reseal" "$PAM_GREETER"; then
    echo "    already wired — skipping"
else
    {
        echo "$MARKER"
        awk '
            /^auth[[:space:]]+substack[[:space:]]+password-auth/ && !done {
                print "auth     [success=1 default=ignore]   pam_irlume.so unseal"
                print                                              # the substack password-auth line
                # Landing target for the success=1 jump. A numeric jump does NOT
                # itself authenticate; without an explicit success here the face
                # path falls off the end of the auth stack (kwallet auth returns
                # IGNORE, postlogin has no auth lines) and PAM defaults to
                # PAM_PERM_DENIED. optional pam_permit supplies that success and
                # is safe: it cannot override a prior password FAILURE (which sets
                # a negative impression first).
                print "auth        optional      pam_permit.so"
                # Self-heal line: runs AFTER password-auth in the same auth phase,
                # so PAM_AUTHTOK is set (typed password, or the password the unseal
                # line released on the face path). It re-binds the TPM-sealed
                # password to the current PCRs when they have moved -- a dbx/Secure
                # Boot update -- or the password changed, automatically on the next
                # password login, with no manual keyring arm. optional + always
                # IGNORE, so it can never affect the login outcome.
                print "auth        optional      pam_irlume.so reseal"
                done=1
                next
            }
            { print }
        ' "$VENDOR_GREETER"
    } > "$PAM_GREETER"
    chmod 644 "$PAM_GREETER"
    echo "    wrote $PAM_GREETER:"
    grep -nE "pam_irlume|password-auth|kwallet|gnome_keyring" "$PAM_GREETER" | sed 's/^/      /'
fi

echo "=== 5/5 wire KDE lock screen (kde-fingerprint, continuous-scan) ==="
if [[ ! -f "$PAM_LOCK" ]]; then
    echo "    $PAM_LOCK not present — skipping (no kscreenlocker fingerprint stack)"
elif grep -q "pam_irlume.so" "$PAM_LOCK"; then
    echo "    already wired — skipping"
else
    [[ -f "$LOCK_BACKUP" ]] || cp -a "$PAM_LOCK" "$LOCK_BACKUP"
    # Insert our line before the first auth directive (linhello pattern).
    awk -v stanza="$LOCK_STANZA" '
        !done && $1=="auth" { print stanza; done=1 }
        { print }
    ' "$LOCK_BACKUP" > "$PAM_LOCK"
    chmod 644 "$PAM_LOCK"
    echo "    wrote $PAM_LOCK (backup $LOCK_BACKUP):"
    grep -nE "pam_irlume|fingerprint-auth" "$PAM_LOCK" | sed 's/^/      /'
fi

echo
echo "=== DONE. Next (you, interactively): ==="
echo "  1. Arm your REAL login password:   irlume keyring arm   (skip if already armed)"
echo "  2. Confirm:                         irlume keyring status"
echo "  3. Lock the screen (Super+L), wait, look at the camera — it should unlock."
echo "  4. Log out, then face-login and check the wallet opens with NO password prompt."
echo "  5. Reboot and repeat 4 (the real cold-boot test)."
echo
echo "Revert anytime:  sudo bash $REPO/scripts/deploy-keyring-unlock.sh --revert"
