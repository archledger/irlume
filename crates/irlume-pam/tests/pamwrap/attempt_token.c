// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#include <security/pam_modules.h>
#include <stddef.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    static int attempt;
    ++attempt;
    const char *token = attempt == 1 ? "synthetic-old-password" : NULL;
    if (pam_set_item(pamh, PAM_AUTHTOK, token) != PAM_SUCCESS)
        return PAM_SYSTEM_ERR;
    return attempt == 1 ? PAM_IGNORE : PAM_SUCCESS;
}
