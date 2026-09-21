// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Private fixture client/module for the camera-free daemon/PAM regression.
// All credentials here are synthetic; no host account password is consulted.
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PASSWORD_MODULE
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    char *answer = NULL;
    int rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &answer, "Fixture password: ");
    if (rc != PAM_SUCCESS) return rc;
    int result = answer && strcmp(answer, "fixture-password") == 0
        ? PAM_SUCCESS : PAM_AUTH_ERR;
    free(answer);
    return result;
}
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
#else
static int converse(int n, const struct pam_message **messages,
                    struct pam_response **out, void *data) {
    struct pam_response *responses = calloc((size_t)n, sizeof(*responses));
    if (!responses) return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            messages[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            // Policy fixtures must make the real module's explicit selection.
            // COSMIC uses nonempty yes; other on-demand services use empty Enter.
            const char *answer = strstr(messages[i]->msg, "Fixture password:")
                ? (const char *)data
                : strstr(messages[i]->msg, "Password, or type yes for face:")
                    ? "yes" : "";
            responses[i].resp = strdup(answer);
            if (!responses[i].resp) {
                for (int j = 0; j < i; j++) free(responses[j].resp);
                free(responses);
                return PAM_BUF_ERR;
            }
        }
    }
    *out = responses;
    return PAM_SUCCESS;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {converse, argv[3]};
    int rc = pam_start(argv[1], argv[2], &conv, &pamh);
    if (rc == PAM_SUCCESS) rc = pam_authenticate(pamh, 0);
    printf("pam_result=%d\n", rc);
    if (pamh) pam_end(pamh, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}
#endif
