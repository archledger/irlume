/* Synthetic credentials only; never reads a host password database. */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int exchange(pam_handle_t *pamh, int style) {
    const struct pam_conv *conv = NULL;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv)) return PAM_SYSTEM_ERR;
    struct pam_message message = {style, "Synthetic prompt"};
    const struct pam_message *messages[] = {&message};
    struct pam_response *response = NULL;
    int result = conv->conv(1, messages, &response, conv->appdata_ptr);
    if (result != PAM_SUCCESS) return result;
    int good = response && response->resp &&
        strcmp(response->resp, "synthetic-test-password") == 0;
    if (response) {
        if (response->resp) {
            explicit_bzero(response->resp, strlen(response->resp));
            free(response->resp);
        }
        free(response);
    }
    return good ? PAM_SUCCESS : PAM_AUTH_ERR;
}
static void cleanup(pam_handle_t *pamh, void *data, int status) {
    (void)data; (void)status;
    exchange(pamh, PAM_PROMPT_ECHO_OFF);
}
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    const char *mode = argc ? argv[0] : "normal";
    if (!strcmp(mode, "hang")) { sleep(60); return PAM_SUCCESS; }
    if (!strcmp(mode, "no-prompt")) return PAM_SUCCESS;
    int result = exchange(pamh, !strcmp(mode, "echo") ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF);
    if (result) return result;
    if (!strcmp(mode, "repeat")) return exchange(pamh, PAM_PROMPT_ECHO_OFF);
    if (!strcmp(mode, "ignore-repeat-info")) { exchange(pamh, PAM_PROMPT_ECHO_OFF); exchange(pamh, PAM_TEXT_INFO); return PAM_SUCCESS; }
    if (!strcmp(mode, "ignore-repeat")) { exchange(pamh, PAM_PROMPT_ECHO_OFF); return PAM_SUCCESS; }
    if (!strcmp(mode, "end-repeat")) return pam_set_data(pamh, "fixture-cleanup", NULL, cleanup);
    if (!strcmp(mode, "mutate")) return pam_set_item(pamh, PAM_USER, "different-user");
    return PAM_SUCCESS;
}
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags;
    if (argc && !strcmp(argv[0], "expired")) return PAM_ACCT_EXPIRED;
    if (argc && !strcmp(argv[0], "change-required")) return PAM_NEW_AUTHTOK_REQD;
    return PAM_SUCCESS;
}
