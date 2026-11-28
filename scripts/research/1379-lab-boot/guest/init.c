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

static bool read_smoke_scope(void)
{
    char cmdline[512];
    bool smoke = false;
    FILE *file = fopen("/proc/cmdline", "r");
    if (!file)
        return false;
    bool read_ok = fgets(cmdline, sizeof(cmdline), file) != NULL;
    fclose(file);
    if (!read_ok || !strchr(cmdline, '\n'))
        return false;

    char *next;
    for (char *part = strtok_r(cmdline, " \n", &next); part;
         part = strtok_r(NULL, " \n", &next)) {
        if (strncmp(part, "book2_case=", 11) == 0) {
            if (smoke || strcmp(part + 11, "smoke") != 0)
                return false;
            smoke = true;
        } else if (strncmp(part, "book2_nonce=", 12) == 0) {
            const char *value = part + 12;
            if (receipt_nonce[0] || strlen(value) != 32 ||
                strspn(value, "0123456789abcdef") != 32)
                return false;
            memcpy(receipt_nonce, value, sizeof(receipt_nonce));
        }
    }
    return smoke && receipt_nonce[0];
}

int main(void)
{
    if (getpid() != 1 || geteuid() != 0)
        return EXIT_FAILURE;

    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0 ||
        !read_smoke_scope()) {
        lab_event("ERROR_SCOPE");
        poweroff();
    }
    lab_event("PID1");
    lab_event("SMOKE_ONLY");
    poweroff();
}
