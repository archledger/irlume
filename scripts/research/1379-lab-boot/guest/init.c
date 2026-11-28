/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "lab.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

static char receipt_nonce[33];

enum lab_case { INVALID, SMOKE, POLICY, MISSING_DENY };

void lab_event(const char *event)
{
    printf("BOOK2_BOOT_V1 %s %s\n", receipt_nonce, event);
    fflush(stdout);
}

static _Noreturn void poweroff(void)
{
    sync();
    reboot(RB_POWER_OFF);
    lab_event("ERROR_POWEROFF");
    _exit(EXIT_FAILURE);
}

static enum lab_case read_scope(void)
{
    char cmdline[512];
    enum lab_case choice = INVALID;
    FILE *file = fopen("/proc/cmdline", "r");
    if (!file)
        return INVALID;
    bool read_ok = fgets(cmdline, sizeof(cmdline), file) != NULL;
    fclose(file);
    if (!read_ok || !strchr(cmdline, '\n'))
        return INVALID;

    char *next;
    for (char *part = strtok_r(cmdline, " \n", &next); part;
         part = strtok_r(NULL, " \n", &next)) {
        if (strncmp(part, "book2_case=", 11) == 0) {
            if (choice != INVALID)
                return INVALID;
            const char *name = part + 11;
            if (strcmp(name, "smoke") == 0)
                choice = SMOKE;
            else if (strcmp(name, "policy") == 0)
                choice = POLICY;
            else if (strcmp(name, "missing-deny") == 0)
                choice = MISSING_DENY;
            else
                return INVALID;
        } else if (strncmp(part, "book2_nonce=", 12) == 0) {
            const char *value = part + 12;
            if (receipt_nonce[0] || strlen(value) != 32 ||
                strspn(value, "0123456789abcdef") != 32)
                return INVALID;
            memcpy(receipt_nonce, value, sizeof(receipt_nonce));
        }
    }
    return receipt_nonce[0] ? choice : INVALID;
}

int main(void)
{
    if (getpid() != 1 || geteuid() != 0)
        return EXIT_FAILURE;

    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        lab_event("ERROR_SCOPE");
        poweroff();
    }
    enum lab_case choice = read_scope();
    if (choice == INVALID) {
        lab_event("ERROR_SCOPE");
        poweroff();
    }
    lab_event("PID1");
    if (choice == SMOKE)
        lab_event("SMOKE_ONLY");
    else if (run_device_policy(choice == MISSING_DENY) != 0)
        lab_event("ERROR_POLICY");
    poweroff();
}
