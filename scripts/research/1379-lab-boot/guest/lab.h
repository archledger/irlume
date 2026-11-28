/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef IRLUME_BOOK2_LAB_H
#define IRLUME_BOOK2_LAB_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#define QUARANTINE "/sys/fs/cgroup/quarantine"
#define ALLOWED "/sys/fs/cgroup/allowed"

/*
 * Run first in every forked child: fds 0, 1 and 2 become an O_PATH handle of
 * "/", which refuses reads and writes and is not a device, so only PID 1 keeps
 * the console that the host reads receipts from.
 */
static inline int lab_detach_console(void)
{
    int sink = open("/", O_PATH | O_CLOEXEC);
    if (sink < 3)
        return -1;
    int status = dup2(sink, 0) == 0 && dup2(sink, 1) == 1 && dup2(sink, 2) == 2 ? 0 : -1;
    close(sink);
    return status;
}

/* True when no standard descriptor can write, so this process cannot add console records. */
static inline bool lab_console_withheld(void)
{
    for (int fd = 0; fd < 3; ++fd)
        if (write(fd, "", 0) != -1 || errno != EBADF)
            return false;
    return true;
}

void lab_event(const char *event);
struct device_rule {
    unsigned int major, minor;
    short access;
};

int attach_device_rules(int cgroup_fd, const struct device_rule *rules, size_t count);
int attach_device_filter(int cgroup_fd, bool permit_zero_read);
int enter_group(const char *group, pid_t pid);
int run_device_policy(bool missing_deny);
enum worker_result { WORKER_OK, WORKER_RETAINED, WORKER_ERROR };
int verify_worker_boundary(const char *quarantine, const char *allowed, bool kept_fd);

#endif
