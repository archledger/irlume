// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    (void)flags;
    const void *token = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, &token) != PAM_SUCCESS ||
        (token != NULL && ((const char *)token)[0] != '\0'))
        return PAM_SESSION_ERR;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "fail-data") == 0 &&
            setenv("IRLUME_TEST_FAIL_PAM_DATA", "1", 1) != 0)
            return PAM_SESSION_ERR;
        if (strncmp(argv[i], "user=", 5) == 0 &&
            pam_set_item(pamh, PAM_USER, argv[i] + 5) != PAM_SUCCESS)
            return PAM_SESSION_ERR;
        if (strncmp(argv[i], "service=", 8) == 0 &&
            pam_set_item(pamh, PAM_SERVICE, argv[i] + 8) != PAM_SUCCESS)
            return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
