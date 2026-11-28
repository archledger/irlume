/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "lab.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { MAX_RULES = 64, FIXED_INSNS = 9, RULE_INSNS = 7 };

static struct bpf_insn insn(__u8 code, __u8 dst, __u8 src, __s16 off, __s32 imm)
{
    return (struct bpf_insn){.code = code, .dst_reg = dst, .src_reg = src, .off = off, .imm = imm};
}

/*
 * Admit a character device only when it matches a rule and the requested
 * access bits are a subset of the rule's bits; an O_RDWR open requests
 * read and write together. Everything else, block devices included, is
 * denied. No rules means deny all.
 */
int attach_device_rules(int cgroup_fd, const struct device_rule *rules, size_t count)
{
    if (count > MAX_RULES) {
        errno = E2BIG;
        return -1;
    }
    struct bpf_insn prog[FIXED_INSNS + MAX_RULES * RULE_INSNS];
    size_t n = 0;
    const int end = (int)(8 + RULE_INSNS * count);
    prog[n++] = insn(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0);
    if (count > 0) {
        prog[n++] = insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_2, BPF_REG_1,
                         offsetof(struct bpf_cgroup_dev_ctx, access_type), 0);
        prog[n++] = insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_3, BPF_REG_2, 0, 0);
        prog[n++] = insn(BPF_ALU64 | BPF_AND | BPF_K, BPF_REG_3, 0, 0, 0xffff);
        prog[n++] = insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_3, 0, (__s16)(end - 4 - 1),
                         BPF_DEVCG_DEV_CHAR);
        prog[n++] = insn(BPF_ALU64 | BPF_RSH | BPF_K, BPF_REG_2, 0, 0, 16);
        prog[n++] = insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_4, BPF_REG_1,
                         offsetof(struct bpf_cgroup_dev_ctx, major), 0);
        prog[n++] = insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_5, BPF_REG_1,
                         offsetof(struct bpf_cgroup_dev_ctx, minor), 0);
        for (size_t i = 0; i < count; i++) {
            const int base = (int)n;
            prog[n++] = insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_4, 0, 6, (__s32)rules[i].major);
            prog[n++] = insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_5, 0, 5, (__s32)rules[i].minor);
            prog[n++] = insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_3, BPF_REG_2, 0, 0);
            prog[n++] = insn(BPF_ALU64 | BPF_AND | BPF_K, BPF_REG_3, 0, 0,
                             (__s32)~(__u32)(unsigned short)rules[i].access);
            prog[n++] = insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_3, 0,
                             (__s16)(end - (base + 4) - 1), 0);
            prog[n++] = insn(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1);
            prog[n++] = insn(BPF_JMP | BPF_JA, 0, 0, (__s16)(end - (base + 6) - 1), 0);
        }
    }
    prog[n++] = insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    const union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_CGROUP_DEVICE,
        .expected_attach_type = BPF_CGROUP_DEVICE,
        .insn_cnt = (__u32)n,
        .insns = (__u64)(unsigned long)prog,
        .license = (__u64)(unsigned long)"GPL",
    };
    int program = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &load, sizeof(load));
    if (program < 0) {
        perror("device filter load");
        return -1;
    }
    const union bpf_attr attach = {
        .target_fd = (unsigned int)cgroup_fd,
        .attach_bpf_fd = (unsigned int)program,
        .attach_type = BPF_CGROUP_DEVICE,
    };
    int status = (int)syscall(SYS_bpf, BPF_PROG_ATTACH, &attach, sizeof(attach));
    if (status < 0)
        perror("device filter attach");
    return close(program) == 0 ? status : -1;
}

int attach_device_filter(int cgroup_fd, bool permit_zero_read)
{
    const struct device_rule zero_read = {.major = 1, .minor = 5, .access = BPF_DEVCG_ACC_READ};
    return attach_device_rules(cgroup_fd, &zero_read, permit_zero_read ? 1 : 0);
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
