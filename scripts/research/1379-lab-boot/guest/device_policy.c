/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "lab.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char *const aliases[] = {"/dev/zero", "/dev/book2-alias"};

int attach_device_filter(int cgroup_fd, bool permit_zero_read)
{
    const struct bpf_insn deny[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    const struct bpf_insn zero_read[] = {
        {.code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_2, .src_reg = BPF_REG_1,
         .off = offsetof(struct bpf_cgroup_dev_ctx, access_type)},
        {.code = BPF_JMP | BPF_JNE | BPF_K, .dst_reg = BPF_REG_2, .off = 5,
         .imm = (BPF_DEVCG_ACC_READ << 16) | BPF_DEVCG_DEV_CHAR},
        {.code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_2, .src_reg = BPF_REG_1,
         .off = offsetof(struct bpf_cgroup_dev_ctx, major)},
        {.code = BPF_JMP | BPF_JNE | BPF_K, .dst_reg = BPF_REG_2, .off = 3, .imm = 1},
        {.code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_2, .src_reg = BPF_REG_1,
         .off = offsetof(struct bpf_cgroup_dev_ctx, minor)},
        {.code = BPF_JMP | BPF_JNE | BPF_K, .dst_reg = BPF_REG_2, .off = 1, .imm = 5},
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 1},
        {.code = BPF_JMP | BPF_EXIT},
    };
    /* The verifier requires r0 initialized on both allow and reject edges. */
    struct bpf_insn scoped[sizeof(zero_read) / sizeof(*zero_read) + 1];
    scoped[0] = deny[0];
    memcpy(scoped + 1, zero_read, sizeof(zero_read));
    const struct bpf_insn *instructions = permit_zero_read ? scoped : deny;
    const union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_CGROUP_DEVICE,
        .expected_attach_type = BPF_CGROUP_DEVICE,
        .insn_cnt = permit_zero_read ? sizeof(scoped) / sizeof(*scoped) : sizeof(deny) / sizeof(*deny),
        .insns = (__u64)(unsigned long)instructions,
        .license = (__u64)(unsigned long)"GPL",
    };
    int program = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &load, sizeof(load));
    if (program < 0) {
        perror("dummy device filter load");
        return -1;
    }
    const union bpf_attr attach = {
        .target_fd = (unsigned int)cgroup_fd,
        .attach_bpf_fd = (unsigned int)program,
        .attach_type = BPF_CGROUP_DEVICE,
    };
    int status = (int)syscall(SYS_bpf, BPF_PROG_ATTACH, &attach, sizeof(attach));
    if (status < 0)
        perror("dummy device filter attach");
    return close(program) == 0 ? status : -1;
}

int enter_group(const char *group, pid_t pid)
{
    char path[128], member[64], expected[64], actual[64];
    int len = snprintf(path, sizeof(path), "%s/cgroup.procs", group);
    if (len < 0 || (size_t)len >= sizeof(path))
        return -1;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    len = snprintf(member, sizeof(member), "%ld\n", (long)pid);
    ssize_t written = write(fd, member, (size_t)len);
    if (close(fd) < 0 || written != len)
        return -1;
    snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long)pid);
    FILE *file = fopen(path, "re");
    if (!file)
        return -1;
    snprintf(expected, sizeof(expected), "0::%s\n", group + strlen("/sys/fs/cgroup"));
    bool matches = fgets(actual, sizeof(actual), file) && strcmp(actual, expected) == 0 &&
        fgetc(file) == EOF && !ferror(file);
    fclose(file);
    return matches ? 0 : -1;
}

static int attach_group(const char *path, bool permit_zero_read)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int status = attach_device_filter(fd, permit_zero_read);
    if (close(fd) < 0)
        return -1;
    return status;
}

static bool rejects_open(const char *path, int mode)
{
    int fd = open(path, mode | O_CLOEXEC);
    if (fd < 0)
        return errno == EPERM;
    close(fd);
    return false;
}

static bool reads_zero(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    unsigned char value = 1;
    ssize_t used = read(fd, &value, 1);
    return close(fd) == 0 && used == 1 && value == 0;
}

static bool identify_dummy(void)
{
    struct stat st;
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); ++i) {
        if (stat(aliases[i], &st) < 0 || !S_ISCHR(st.st_mode) || (st.st_mode & 0777) != 0666 ||
            major(st.st_rdev) != 1 || minor(st.st_rdev) != 5)
            return false;
    }
    char link[128];
    ssize_t n = readlink("/sys/dev/char/1:5", link, sizeof(link) - 1);
    if (n < 0)
        return false;
    link[n] = '\0';
    return strcmp(link, "../../devices/virtual/mem/zero") == 0;
}

static bool mknod_capable(void)
{
    char line[128];
    unsigned long long effective;
    FILE *self = fopen("/proc/self/status", "re");
    if (!self)
        return false;
    bool found = false;
    while (fgets(line, sizeof(line), self)) {
        if (sscanf(line, "CapEff: %llx", &effective) == 1) {
            found = (effective & (1ULL << CAP_MKNOD)) != 0;
            break;
        }
    }
    fclose(self);
    return found;
}

static int probe_zero_nonreplacement(void)
{
    errno = 0;
    if (syscall(SYS_delete_module, "zero", 0) != -1 || errno != ENOSYS)
        return -1;
    return identify_dummy() ? 0 : -1;
}

int run_device_policy(bool missing_deny)
{
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0 ||
        mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0 ||
        mkdir(QUARANTINE, 0700) < 0 || mkdir(ALLOWED, 0700) < 0)
        return -1;

    if ((!missing_deny && attach_group(QUARANTINE, false) < 0) ||
        enter_group(QUARANTINE, getpid()) < 0)
        return -1;
    if (!missing_deny)
        lab_event("DENY_ATTACHED");

    bool denied = rejects_open(aliases[0], O_RDONLY) && rejects_open(aliases[1], O_RDONLY) &&
        rejects_open("/dev/null", O_RDONLY);
    if (missing_deny) {
        if (denied || !reads_zero(aliases[0]))
            return -1;
        lab_event("REFUSED_NO_INITIAL_POLICY");
        return 0;
    }
    if (!denied)
        return -1;
    lab_event("PRE_INVENTORY_DENIED");
    if (!identify_dummy())
        return -1;
    printf("dummy character dev=1:5 fixed mem class, equal mode aliases\n");
    lab_event("DUMMY_IDENTIFIED");
    if (attach_group(ALLOWED, true) < 0)
        return -1;
    lab_event("WORKER_POLICY_ATTACHED");
    if (enter_group(ALLOWED, getpid()) < 0)
        return -1;

    bool checks = reads_zero(aliases[0]) && reads_zero(aliases[1]) &&
        rejects_open(aliases[0], O_WRONLY) && rejects_open(aliases[1], O_WRONLY) &&
        rejects_open("/dev/null", O_RDONLY);
    if (!checks || !mknod_capable() || access("/tmp", W_OK) < 0)
        return -1;
    if (mknod("/tmp/forbidden-alias", S_IFCHR | 0600, makedev(1, 5)) != -1 || errno != EPERM)
        return -1;
    if (enter_group(QUARANTINE, getpid()) < 0 || !rejects_open(aliases[0], O_RDONLY))
        return -1;
    printf("cgroup: both alias reads succeeded; writes, other minor and mknod denied\n");
    lab_event("ALIAS_ACCESS_CHECKED");
    if (probe_zero_nonreplacement() < 0)
        return -1;
    printf("dummy replacement: module syscall ENOSYS; same built-in identity retained\n");
    lab_event("REPLACEMENT_REFUSED");
    lab_event("POLICY_PASS");
    return 0;
}
