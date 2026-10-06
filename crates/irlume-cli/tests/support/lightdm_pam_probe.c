/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright the irlume contributors. */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef MODULE
int pam_sm_authenticate(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags;
    int result = PAM_SUCCESS;
    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "fail")) result = PAM_AUTH_ERR;
        if (!strncmp(argv[i], "marker=", 7)) {
            FILE *f = fopen(argv[i] + 7, "a");
            if (!f) return PAM_SYSTEM_ERR;
            fputs("called\n", f);
            fclose(f);
        }
    }
    return result;
}
int pam_sm_setcred(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
#else
static int conversation(int n, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)n; (void)messages; (void)responses; (void)data;
    return PAM_CONV_ERR;
}

/* Independent oracle for the three mounts declared by the packaged unit. */
static int owned_mounts_present(void) {
    const char *paths[] = {
        "/run/irlume-lightdm-source/etc",
        "/run/irlume-lightdm-source/vendor",
        "/run/irlume-lightdm"
    };
    FILE *file = fopen("/proc/self/mountinfo", "r");
    if (!file) return -1;
    char *line = NULL;
    size_t capacity = 0;
    int found = 0;
    while (getline(&line, &capacity, file) >= 0) {
        char mountpoint[4096];
        if (sscanf(line, "%*s %*s %*s %*s %4095s", mountpoint) != 1) {
            found = -1;
            break;
        }
        for (int i = 0; i < 3; ++i)
            if (!strcmp(mountpoint, paths[i])) found |= 1 << i;
    }
    if (ferror(file)) found = -1;
    free(line);
    fclose(file);
    return found;
}

static int session_child(pam_handle_t *handle, int number) {
    int result = pam_open_session(handle, 0);
    if (result == PAM_SUCCESS) {
        int remaining = owned_mounts_present();
        if (remaining != 0) {
            fprintf(stderr, "session retained irlume-owned mounts: %d\n", remaining);
            result = PAM_SESSION_ERR;
        }
    }
    if (result == PAM_SUCCESS) {
        FILE *file = fopen("/etc/pam.d/session-can-write", "w");
        if (!file) result = PAM_SESSION_ERR;
        else { fputs("host policy remains writable\n", file); fclose(file); }
        if (result == PAM_SUCCESS) result = pam_close_session(handle, 0);
    }
    if (result == PAM_SUCCESS) printf("session-child-%d=clean\n", number);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 100;
    if (argc == 3) {
        int without_vendor = !strcmp(argv[2], "open-session-no-vendor");
        int unmounted_vendor = !strcmp(argv[2], "open-session-unmounted-vendor");
        if (strcmp(argv[2], "open-session") && !without_vendor && !unmounted_vendor) return 100;
        if (unmounted_vendor && umount2("/run/irlume-lightdm-source/vendor", MNT_DETACH)) return 103;
        const char *paths[] = {
            "/etc/pam.d", "/run/irlume-lightdm-source/etc",
            "/run/irlume-lightdm-source/vendor", "/run/irlume-lightdm"
        };
        for (int i = 0; i < 4; ++i) {
            if ((without_vendor || unmounted_vendor) && i == 2) continue;
            unsigned long flags = MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV;
            /* ExecPaths permits the retained PAM module in the runtime mount. */
            if (i != 3) flags |= MS_NOEXEC;
            if (mount(NULL, paths[i], NULL, flags, NULL)) return 101;
        }
        if (owned_mounts_present() != ((without_vendor || unmounted_vendor) ? 5 : 7)) return 102;
    }
    struct pam_conv conv = { conversation, NULL };
    pam_handle_t *handle = NULL;
    int result = pam_start(argv[1], "tester", &conv, &handle);
    if (result == PAM_SUCCESS) result = pam_authenticate(handle, 0);
    printf("auth=%d\n", result);
    if (result == PAM_SUCCESS) result = pam_acct_mgmt(handle, 0);
    if (result == PAM_SUCCESS && argc == 3) {
        /* Each child has an inherited protected namespace and real PAM handle. */
        for (int number = 1; number <= 2 && result == PAM_SUCCESS; ++number) {
            fflush(NULL);
            pid_t child = fork();
            if (child < 0) { result = PAM_SESSION_ERR; break; }
            if (child == 0) {
                int child_result = session_child(handle, number);
                pam_end(handle, child_result);
                fflush(NULL);
                _exit(child_result == PAM_SUCCESS ? 0 : 1);
            }
            int status;
            pid_t waited;
            do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                result = PAM_SESSION_ERR;
                break;
            }
            int expected_mounts = strcmp(argv[2], "open-session") ? 5 : 7;
            if (owned_mounts_present() != expected_mounts) { result = PAM_SESSION_ERR; break; }
            errno = 0;
            FILE *unexpected = fopen("/etc/pam.d/parent-must-stay-readonly", "w");
            if (unexpected) {
                fclose(unexpected);
                result = PAM_SESSION_ERR;
                break;
            }
            if (errno != EROFS) { result = PAM_SESSION_ERR; break; }
        }
        if (result == PAM_SUCCESS) puts("parent-view=protected");
    }
    if (handle) pam_end(handle, result);
    printf("%d\n", result);
    return result == PAM_SUCCESS ? 0 : 1;
}
#endif
