// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Real PAM with a source-matched COSMIC conversation adapter, not a GUI test.
// cosmic-greeter 0b0d2925: locker Submit and greeter Auth ignore empty input.
// Inputs are synthetic test tokens. Never print response contents.
#define _POSIX_C_SOURCE 200809L
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void free_responses(struct pam_response *responses, int count) {
    for (int i = 0; i < count; i++) free(responses[i].resp);
    free(responses);
}

static int converse(int count, const struct pam_message **messages,
                    struct pam_response **out, void *data) {
    if (count <= 0) return PAM_CONV_ERR;
    struct pam_response *responses = calloc((size_t)count, sizeof(*responses));
    if (!responses) return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        if (messages[i]->msg_style != PAM_PROMPT_ECHO_OFF &&
            messages[i]->msg_style != PAM_PROMPT_ECHO_ON) continue;
        printf("PROMPT_%s:%s\n", messages[i]->msg_style == PAM_PROMPT_ECHO_OFF
               ? "HIDDEN" : "VISIBLE", messages[i]->msg);
        fflush(stdout);
        for (;;) {
            char *line = NULL;
            size_t size = 0;
            ssize_t length = getline(&line, &size, stdin);
            if (length < 0) {
                free(line);
                free_responses(responses, count);
                return PAM_CONV_ERR;
            }
            if (length && line[length - 1] == '\n') line[--length] = '\0';
            if (strcmp((const char *)data, "cosmic") == 0 && length == 0) {
                puts("EMPTY_DROPPED");
                fflush(stdout);
                free(line);
                continue;
            }
            responses[i].resp = line;
            break;
        }
    }
    *out = responses;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    pam_handle_t *pamh = NULL;
    struct pam_conv conversation = {converse, argv[3]};
    int result = pam_start(argv[1], "tester", &conversation, &pamh);
    if (result == PAM_SUCCESS) result = pam_authenticate(pamh, 0);
    printf("PAM_RESULT=%d\n", result);
    if (pamh) pam_end(pamh, result);
    return result == PAM_SUCCESS ? 0 : 1;
}
