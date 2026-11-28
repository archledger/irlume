// SPDX-License-Identifier: GPL-3.0-or-later
// Guest-only libcamera discovery worker for the Book 2 lab (B03). The trusted
// supervisor starts it with fd 3 (guard verdict pipe), fd 4 (control pipe)
// and fd 5 (report pipe). Its report is a label, not evidence: decisions rest
// on the simulated driver's log, process state and kernfs inodes.
#include <libcamera/camera_manager.h>

#include <cstddef>
#include <string>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

constexpr int kControlFd = 4;
constexpr int kReportFd = 5;

bool report(const std::string &line)
{
    std::string text = line + "\n";
    return write(kReportFd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
}

bool wait_for(const std::string &word)
{
    std::string line;
    char c;
    while (line.size() < 32) {
        ssize_t n = read(kControlFd, &c, 1);
        if (n != 1)
            return false;
        if (c == '\n')
            return line == word;
        line += c;
    }
    return false;
}

// Second seccomp stage: any exec kills the worker. The first stage, installed
// by the supervisor before exec, already kills process creation.
int forbid_exec()
{
    sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    sock_fprog prog = {static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])), filter};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

} // namespace

int main()
{
    if (forbid_exec() != 0)
        return 2;
    if (!report("READY") || !wait_for("go"))
        return 3;
    libcamera::CameraManager manager;
    int ret = manager.start();
    report(ret ? "START_FAILED " + std::to_string(ret) :
                 "CAMERAS " + std::to_string(manager.cameras().size()));
    bool released = wait_for("release");
    if (!ret)
        manager.stop();
    return released ? 0 : 4;
}
