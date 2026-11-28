/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef IRLUME_BOOK2_LAB_H
#define IRLUME_BOOK2_LAB_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define QUARANTINE "/sys/fs/cgroup/quarantine"
#define ALLOWED "/sys/fs/cgroup/allowed"

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
