/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "lab.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { GATE = 3, REPLY = 4, FIRST_EXTRA = 5, SEED = 40 };

static int apply_worker_filter(void)
{
#define ALLOW(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##nr, 0, 1), \
                  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        ALLOW(read), ALLOW(write), ALLOW(close), ALLOW(fcntl), ALLOW(openat),
        ALLOW(poll), ALLOW(getpid), ALLOW(exit), ALLOW(exit_group),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
#undef ALLOW
    const struct sock_fprog program = {
        .len = sizeof(rules) / sizeof(*rules),
        .filter = rules,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

static int sanitize_worker(int first_untrusted_fd, uid_t uid, gid_t gid)
{
    if (syscall(SYS_close_range, (unsigned int)first_untrusted_fd, UINT_MAX, 0) < 0 ||
        setgroups(0, NULL) < 0 || setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
        return -1;
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) < 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) < 0 ||
        real_uid != uid || effective_uid != uid || saved_uid != uid ||
        real_gid != gid || effective_gid != gid || saved_gid != gid ||
        getgroups(0, NULL) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return -1;
    return apply_worker_filter();
}

static bool closed_fd(int fd)
{
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

static bool no_peer_transfer(void)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != -1 || errno != EPERM)
        return false;
    char byte = 'x';
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(header)) = FIRST_EXTRA;
    if (sendmsg(REPLY, &message, MSG_DONTWAIT) != -1 || errno != EPERM ||
        recvmsg(GATE, &message, MSG_DONTWAIT) != -1 || errno != EPERM)
        return false;
    return syscall(SYS_pidfd_open, getpid(), 0) == -1 && errno == EPERM;
}

static bool wait_byte(int fd, char expected)
{
    struct pollfd watch = {.fd = fd, .events = POLLIN};
    char actual;
    return poll(&watch, 1, 2000) == 1 && (watch.revents & POLLIN) &&
        read(fd, &actual, 1) == 1 && actual == expected;
}

static bool finish_child(pid_t child)
{
    const struct timespec pause = {.tv_nsec = 5000000};
    int status;
    for (int i = 0; i < 400; ++i) {
        if (waitpid(child, &status, WNOHANG) == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        nanosleep(&pause, NULL);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return false;
}

static void owner_worker(int gate[2], int reply[2], bool kept_fd)
{
    close(gate[1]);
    close(reply[0]);
    if (gate[0] != GATE || dup2(reply[1], REPLY) != REPLY)
        _exit(1);
    close(reply[1]);
    if (!wait_byte(GATE, 'G'))
        _exit(1);
    if (kept_fd) {
        bool retained = !closed_fd(SEED);
        _exit(retained && write(REPLY, "R", 1) == 1 ? 0 : 1);
    }
    if (sanitize_worker(FIRST_EXTRA, 65532, 65532) != 0)
        _exit(1);
    if (!closed_fd(SEED)) {
        _exit(write(REPLY, "R", 1) == 1 ? 0 : 1);
    }
    int handle = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    unsigned char value = 1;
    if (handle != FIRST_EXTRA || read(handle, &value, 1) != 1 || value != 0 ||
        write(REPLY, "H", 1) != 1 || !wait_byte(GATE, 'T') || !no_peer_transfer() ||
        !closed_fd(FIRST_EXTRA + 1) || close(handle) < 0 || write(REPLY, "I", 1) != 1)
        _exit(1);
    _exit(0);
}

static bool prove_peer_denied(pid_t owner)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)owner, FIRST_EXTRA);
    char link[96];
    if (readlink(path, link, sizeof(link)) <= 0)
        return false;
    pid_t peer = fork();
    if (peer < 0)
        return false;
    if (!peer) {
        if (sanitize_worker(GATE, 65533, 65533) < 0)
            _exit(1);
        if (open(path, O_RDONLY | O_CLOEXEC) != -1 || (errno != EACCES && errno != EPERM))
            _exit(1);
        if (open("/dev/book2-alias", O_RDONLY | O_CLOEXEC) != -1 || errno != EPERM)
            _exit(1);
        _exit(0);
    }
    return finish_child(peer) && readlink(path, link, sizeof(link)) > 0;
}

int verify_worker_boundary(const char *quarantine, const char *allowed, bool kept_fd)
{
    int gate[2], reply[2];
    if (pipe2(gate, O_CLOEXEC) < 0 || pipe2(reply, O_CLOEXEC) < 0 ||
        enter_group(allowed, getpid()) < 0)
        return WORKER_ERROR;
    int dummy = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (dummy < 0 || fcntl(dummy, F_DUPFD_CLOEXEC, SEED) != SEED ||
        close(dummy) < 0 || enter_group(quarantine, getpid()) < 0)
        return WORKER_ERROR;

    pid_t child = fork();
    if (child < 0)
        return WORKER_ERROR;
    if (!child)
        owner_worker(gate, reply, kept_fd);
    close(SEED);
    close(gate[0]);
    close(reply[1]);

    int result = WORKER_ERROR;
    if (enter_group(allowed, child) == 0 && write(gate[1], "G", 1) == 1) {
        if (kept_fd) {
            if (wait_byte(reply[0], 'R'))
                result = WORKER_RETAINED;
        } else if (wait_byte(reply[0], 'H')) {
            lab_event("INHERITED_HANDLE_CLOSED");
            if (prove_peer_denied(child)) {
                lab_event("PEER_HANDLE_DENIED");
                if (write(gate[1], "T", 1) == 1 && wait_byte(reply[0], 'I')) {
                    lab_event("FD_IPC_DENIED");
                    result = WORKER_OK;
                }
            }
        }
    }
    close(gate[1]);
    close(reply[0]);
    return finish_child(child) ? result : WORKER_ERROR;
}
