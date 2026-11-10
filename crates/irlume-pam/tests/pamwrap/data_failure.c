// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>

int pam_set_data(pam_handle_t *pamh, const char *name, void *data,
                 void (*cleanup)(pam_handle_t *, void *, int)) {
    if (getenv("IRLUME_TEST_FAIL_PAM_DATA") != NULL &&
        strncmp(name, "pam_irlume_", 11) == 0)
        return PAM_SYSTEM_ERR;
    typedef int (*set_data_fn)(pam_handle_t *, const char *, void *,
                               void (*)(pam_handle_t *, void *, int));
    set_data_fn next = (set_data_fn)dlsym(RTLD_NEXT, "pam_set_data");
    return next ? next(pamh, name, data, cleanup) : PAM_SYSTEM_ERR;
}
