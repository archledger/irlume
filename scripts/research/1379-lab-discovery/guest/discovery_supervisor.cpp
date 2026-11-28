// SPDX-License-Identifier: GPL-3.0-or-later
// Trusted PID 1 supervisor for the Book 2 discovery guest (B03). Guest only:
// it mounts, denies every device before inventory, reads the simulated graph
// under a narrow scope and reports receipts on the serial console.
extern "C" {
#include "lab.h"
}

#include "discovery_requests.h"
#include "lab_contract.h"

#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/media.h>
#include <linux/sched.h>
#include <linux/seccomp.h>

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace {

constexpr const char *kDebug = "/sys/kernel/debug/book2_lab_sim";
constexpr const char *kInventory = "/sys/fs/cgroup/inventory";
constexpr const char *kWorkerGroup = "/sys/fs/cgroup/worker";
constexpr const char *kWorkerPath = "/lab/discovery-worker";
constexpr const char *kWorkerLog = "/tmp/worker.log";
constexpr unsigned kWorkerId = 65532;
std::string nonce;
std::string lab_case;
bool debugfs_ready = false;
pid_t g_worker = 0;

void event(const std::string &text)
{
    std::printf("BOOK2_DISCOVERY_V1 %s %s\n", nonce.c_str(), text.c_str());
    std::fflush(stdout);
}

[[noreturn]] void poweroff()
{
    sync();
    reboot(RB_POWER_OFF);
    event("ERROR_POWEROFF");
    _exit(EXIT_FAILURE);
}

bool read_file(const std::string &path, std::string &out)
{
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    out.clear();
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return n == 0;
        }
        out.append(buf, static_cast<size_t>(n));
    }
}

bool write_file(const std::string &path, const std::string &data)
{
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t n = write(fd, data.data(), data.size());
    return close(fd) == 0 && n == static_cast<ssize_t>(data.size());
}

// The effect dump is the host verifier's raw input; it always comes last.
void dump_effects(pid_t worker)
{
    std::string text;
    if (!debugfs_ready || !read_file(std::string(kDebug) + "/effects", text)) {
        event("EFFECTS_UNREADABLE");
        return;
    }
    size_t count = 0, pos = 0;
    std::string dropped = "?";
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos)
            end = text.size();
        std::string line = text.substr(pos, end - pos);
        pos = end + 1;
        if (line.rfind("dropped ", 0) == 0) {
            dropped = line.substr(8);
            continue;
        }
        unsigned long long seq = 0;
        unsigned instance = 0;
        int tgid = 0, used = 0;
        if (std::sscanf(line.c_str(), "%llu %u %d %n", &seq, &instance, &tgid, &used) != 3 || used <= 0) {
            event("EFFECTS_MALFORMED");
            return;
        }
        const char *role = tgid == 1 ? "supervisor" : (worker > 0 && tgid == worker ? "worker" : "other");
        event("EFFECT " + std::to_string(seq) + " " + std::to_string(instance) + " " + role + " " +
              line.substr(static_cast<size_t>(used)));
        count++;
    }
    event("EFFECTS_END " + std::to_string(count) + " dropped=" + dropped);
}

[[noreturn]] void fail(const std::string &what)
{
    event("ERROR_" + what);
    dump_effects(g_worker);
    poweroff();
}

bool read_scope()
{
    std::string cmdline;
    if (!read_file("/proc/cmdline", cmdline) || cmdline.empty() || cmdline.back() != '\n')
        return false;
    size_t pos = 0;
    while (pos < cmdline.size()) {
        size_t end = cmdline.find_first_of(" \n", pos);
        std::string word = cmdline.substr(pos, end - pos);
        pos = end + 1;
        if (word.rfind("book2_case=", 0) == 0) {
            if (!lab_case.empty())
                return false;
            lab_case = word.substr(11);
        } else if (word.rfind("book2_nonce=", 0) == 0) {
            std::string value = word.substr(12);
            if (!nonce.empty() || value.size() != 32 ||
                value.find_first_not_of("0123456789abcdef") != std::string::npos)
                return false;
            nonce = value;
        }
    }
    static const char *const known[] = {"topology", "sim-controls", "stock-baseline", "lab-front",
                                        "graph-ir-link-enabled", "graph-extra-entity", "hotplug-extra-media",
                                        "sim-port-variant", "effect-unlisted-link", "replace-before-discovery",
                                        "generation-during-discovery", "replace-after-discovery"};
    return !nonce.empty() && std::find(std::begin(known), std::end(known), lab_case) != std::end(known);
}

struct MediaNode {
    std::string sysname, path;
    unsigned major = 0, minor = 0;
    ino_t inode = 0;
};

bool kernfs_inode(unsigned major, unsigned minor, ino_t &inode)
{
    struct stat st {};
    std::string path = "/sys/dev/char/" + std::to_string(major) + ":" + std::to_string(minor);
    if (stat(path.c_str(), &st) != 0)
        return false;
    inode = st.st_ino;
    return true;
}

std::vector<MediaNode> sysfs_media()
{
    std::vector<MediaNode> nodes;
    DIR *dir = opendir("/sys/bus/media/devices");
    if (!dir)
        return nodes;
    while (dirent *entry = readdir(dir)) {
        std::string name = entry->d_name;
        if (name.rfind("media", 0) != 0)
            continue;
        MediaNode node;
        node.sysname = name;
        std::string dev, uevent;
        if (!read_file("/sys/bus/media/devices/" + name + "/dev", dev) ||
            std::sscanf(dev.c_str(), "%u:%u", &node.major, &node.minor) != 2 ||
            !read_file("/sys/bus/media/devices/" + name + "/uevent", uevent))
            continue;
        size_t at = uevent.find("DEVNAME=");
        if (at == std::string::npos)
            continue;
        node.path = "/dev/" + uevent.substr(at + 8, uevent.find('\n', at) - at - 8);
        if (!kernfs_inode(node.major, node.minor, node.inode))
            continue;
        nodes.push_back(node);
    }
    closedir(dir);
    std::sort(nodes.begin(), nodes.end(), [](const MediaNode &a, const MediaNode &b) {
        return a.minor < b.minor;
    });
    return nodes;
}

// The kernfs inode of the registration must match before and after the open,
// and the descriptor must name the expected device number.
int open_bracketed(const MediaNode &node, int flags)
{
    ino_t before = 0, after = 0;
    if (!kernfs_inode(node.major, node.minor, before) || before != node.inode)
        return -1;
    int fd = open(node.path.c_str(), flags | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st {};
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(node.major, node.minor) ||
        !kernfs_inode(node.major, node.minor, after) || after != node.inode) {
        close(fd);
        return -1;
    }
    return fd;
}

bool make_group(const char *path, const std::vector<device_rule> &rules)
{
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        return false;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    int status = attach_device_rules(fd, rules.data(), rules.size());
    return close(fd) == 0 && status == 0;
}

// Read each media device's topology from a scope that admits only the
// inventoried media nodes, then return PID 1 to quarantine.
bool read_media(const std::vector<MediaNode> &nodes, std::vector<book2lab::Snapshot> &out)
{
    static bool scoped = false;
    if (!scoped) {
        std::vector<device_rule> rules;
        for (const auto &n : nodes)
            rules.push_back({n.major, n.minor, BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE});
        if (!make_group(kInventory, rules))
            return false;
        scoped = true;
    }
    if (enter_group(kInventory, getpid()) != 0)
        return false;
    bool ok = true;
    out.clear();
    for (const auto &n : nodes) {
        int fd = open_bracketed(n, O_RDONLY);
        book2lab::Snapshot t;
        ok = ok && fd >= 0 && book2lab::read_snapshot(fd, &t) == 0;
        if (fd >= 0)
            close(fd);
        out.push_back(t);
    }
    return enter_group(QUARANTINE, getpid()) == 0 && ok;
}

const MediaNode *find_role(const std::vector<MediaNode> &nodes, const std::vector<book2lab::Snapshot> &tops,
                           const std::string &role)
{
    for (size_t i = 0; i < nodes.size() && i < tops.size(); i++)
        if (book2lab::role_for_driver(tops[i].info.driver) == role)
            return &nodes[i];
    return nullptr;
}

void sim_controls(const std::vector<MediaNode> &before, const std::vector<book2lab::Snapshot> &tops)
{
    const MediaNode *cio2 = find_role(before, tops, "cio2");
    if (!cio2)
        fail("NO_CIO2");
    MediaNode old = *cio2;
    uint64_t old_version = tops[static_cast<size_t>(cio2 - before.data())].version;
    if (!write_file(std::string(kDebug) + "/control", "replace\n"))
        fail("CONTROL_REPLACE");
    std::vector<MediaNode> after = sysfs_media();
    std::vector<book2lab::Snapshot> fresh;
    if (!read_media(after, fresh))
        fail("REREAD_AFTER_REPLACE");
    const MediaNode *now = find_role(after, fresh, "cio2");
    if (!now)
        fail("NO_CIO2_AFTER_REPLACE");
    uint64_t version = fresh[static_cast<size_t>(now - after.data())].version;
    event(std::string("REPLACED same_devt=") + (now->major == old.major && now->minor == old.minor ? "1" : "0") +
          " same_version=" + (version == old_version ? "1" : "0") +
          " new_inode=" + (now->inode != old.inode ? "1" : "0"));
    if (!write_file(std::string(kDebug) + "/control", "add-entity\n") || !read_media(after, fresh))
        fail("CONTROL_ADD_ENTITY");
    now = find_role(after, fresh, "cio2");
    if (now && fresh[static_cast<size_t>(now - after.data())].version > version)
        event("VERSION_BUMPED");
    if (!write_file(std::string(kDebug) + "/control", "add-media\n"))
        fail("CONTROL_ADD_MEDIA");
    if (sysfs_media().size() == after.size() + 1)
        event("EXTRA_MEDIA_PRESENT");
    event("SIM_CONTROLS_PASS");
}

struct DevNode {
    std::string name, path;
    unsigned major = 0, minor = 0;
    ino_t inode = 0;
};

std::vector<DevNode> sysfs_v4l2()
{
    std::vector<DevNode> nodes;
    DIR *dir = opendir("/sys/class/video4linux");
    if (!dir)
        return nodes;
    while (dirent *entry = readdir(dir)) {
        std::string sys = entry->d_name;
        if (sys.rfind("video", 0) != 0 && sys.rfind("v4l-subdev", 0) != 0)
            continue;
        DevNode node;
        std::string base = "/sys/class/video4linux/" + sys, dev, uevent;
        if (!read_file(base + "/name", node.name) || !read_file(base + "/dev", dev) ||
            std::sscanf(dev.c_str(), "%u:%u", &node.major, &node.minor) != 2 ||
            !read_file(base + "/uevent", uevent) || !kernfs_inode(node.major, node.minor, node.inode))
            continue;
        if (!node.name.empty() && node.name.back() == '\n')
            node.name.pop_back();
        size_t at = uevent.find("DEVNAME=");
        if (at == std::string::npos)
            continue;
        node.path = "/dev/" + uevent.substr(at + 8, uevent.find('\n', at) - at - 8);
        nodes.push_back(node);
    }
    closedir(dir);
    std::sort(nodes.begin(), nodes.end(), [](const DevNode &a, const DevNode &b) { return a.name < b.name; });
    return nodes;
}

// Give each granted node to the worker UID alone; the worker cgroup admits
// exactly these device numbers. Everything else stays root-only and denied.
bool grant(const std::vector<std::string> &paths, std::vector<device_rule> &rules)
{
    for (const auto &path : paths) {
        struct stat st {};
        if (stat(path.c_str(), &st) != 0 || !S_ISCHR(st.st_mode) ||
            chown(path.c_str(), kWorkerId, kWorkerId) != 0 || chmod(path.c_str(), 0600) != 0)
            return false;
        rules.push_back({major(st.st_rdev), minor(st.st_rdev),
                         static_cast<short>(BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE)});
    }
    return true;
}

// First seccomp stage, installed before exec: deny by default, kill process
// creation, allow threads, and admit ioctl only for the discovery requests.
std::vector<sock_filter> worker_filter()
{
    static const int allowed[] = {
        SYS_read, SYS_write, SYS_close, SYS_fstat, SYS_stat, SYS_lstat, SYS_lseek, SYS_mmap,
        SYS_mprotect, SYS_munmap, SYS_brk, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
        SYS_pread64, SYS_readv, SYS_writev, SYS_access, SYS_sched_yield, SYS_mremap, SYS_madvise,
        SYS_dup, SYS_dup2, SYS_dup3, SYS_nanosleep, SYS_getpid, SYS_exit, SYS_uname, SYS_fcntl,
        SYS_getcwd, SYS_readlink, SYS_readlinkat, SYS_getdents64, SYS_getuid, SYS_getgid,
        SYS_geteuid, SYS_getegid, SYS_gettid, SYS_getppid, SYS_sigaltstack, SYS_prctl,
        SYS_arch_prctl, SYS_futex, SYS_sched_getaffinity, SYS_set_tid_address, SYS_set_robust_list,
        SYS_rseq, SYS_prlimit64, SYS_getrandom, SYS_openat, SYS_newfstatat, SYS_statx, SYS_eventfd2,
        SYS_poll, SYS_ppoll, SYS_pipe2, SYS_clock_gettime, SYS_clock_getres, SYS_clock_nanosleep,
        SYS_gettimeofday, SYS_exit_group, SYS_tgkill, SYS_faccessat, SYS_faccessat2, SYS_seccomp,
        SYS_restart_syscall, SYS_sysinfo, SYS_membarrier,
        // The worker's own second stage kills any later exec.
        SYS_execve,
    };
    const auto ret = [](uint32_t action) { return sock_filter BPF_STMT(BPF_RET | BPF_K, action); };
    const auto jeq = [](uint32_t value, uint8_t jt, uint8_t jf) {
        return sock_filter BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, jf);
    };
    const uint32_t eperm = SECCOMP_RET_ERRNO | EPERM;
    std::vector<sock_filter> f = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        jeq(AUDIT_ARCH_X86_64, 1, 0),
        ret(SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        jeq(SYS_fork, 0, 1), ret(SECCOMP_RET_KILL_PROCESS),
        jeq(SYS_vfork, 0, 1), ret(SECCOMP_RET_KILL_PROCESS),
        jeq(SYS_clone3, 0, 1), ret(SECCOMP_RET_ERRNO | ENOSYS),
        jeq(SYS_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 1),
        ret(SECCOMP_RET_ALLOW),
        ret(SECCOMP_RET_KILL_PROCESS),
    };
    const size_t requests = std::size(book2lab::kDiscoveryRequests);
    f.push_back(jeq(SYS_ioctl, 0, static_cast<uint8_t>(2 * requests + 2)));
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])));
    for (const auto &r : book2lab::kDiscoveryRequests) {
        f.push_back(jeq(static_cast<uint32_t>(r.request), 0, 1));
        f.push_back(ret(SECCOMP_RET_ALLOW));
    }
    f.push_back(ret(eperm));
    for (int nr : allowed) {
        f.push_back(jeq(static_cast<uint32_t>(nr), 0, 1));
        f.push_back(ret(SECCOMP_RET_ALLOW));
    }
    f.push_back(ret(eperm));
    return f;
}

struct Worker {
    pid_t pid = -1;
    int verdict = -1, control = -1, report = -1;
    int status = -1;
};

long now_ms()
{
    timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

bool read_line(int fd, std::string &line, int timeout_ms)
{
    line.clear();
    const long deadline = now_ms() + timeout_ms;
    while (line.size() < 256) {
        pollfd p {fd, POLLIN, 0};
        long left = deadline - now_ms();
        if (left <= 0 || poll(&p, 1, static_cast<int>(left)) != 1)
            return false;
        char c;
        if (read(fd, &c, 1) != 1)
            return false;
        if (c == '\n')
            return true;
        line += c;
    }
    return false;
}

void print_worker_log()
{
    std::string log;
    if (read_file(kWorkerLog, log)) {
        size_t start = log.size() > 6000 ? log.size() - 6000 : 0;
        size_t pos = start;
        while (pos < log.size()) {
            size_t end = log.find('\n', pos);
            if (end == std::string::npos)
                end = log.size();
            std::printf("WORKERLOG %s\n", log.substr(pos, end - pos).c_str());
            pos = end + 1;
        }
        std::fflush(stdout);
    }
}

[[noreturn]] void worker_fail(const std::string &what)
{
    print_worker_log();
    if (g_worker > 0)
        kill(g_worker, SIGKILL);
    fail(what);
}

bool launch_worker(const std::vector<device_rule> &rules, const std::vector<std::string> &extra_env, Worker &w)
{
    int verdict[2], control[2], report[2], input[2];
    if (!make_group(kWorkerGroup, rules) || pipe2(verdict, O_CLOEXEC) || pipe2(control, O_CLOEXEC) ||
        pipe2(report, O_CLOEXEC) || pipe2(input, O_CLOEXEC))
        return false;
    int log = open(kWorkerLog, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (log < 0)
        return false;
    std::vector<sock_filter> filter = worker_filter();
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        const int sources[6] = {input[0], log, log, verdict[1], control[0], report[1]};
        int high[6];
        for (int i = 0; i < 6; i++)
            if ((high[i] = fcntl(sources[i], F_DUPFD_CLOEXEC, 100 + i)) < 0)
                _exit(20);
        for (int i = 0; i < 6; i++)
            if (dup2(high[i], i) != i)
                _exit(21);
        if (enter_group(kWorkerGroup, getpid()) != 0 || syscall(SYS_close_range, 6U, ~0U, 0U) != 0 ||
            setgroups(0, nullptr) != 0 || setresgid(kWorkerId, kWorkerId, kWorkerId) != 0 ||
            setresuid(kWorkerId, kWorkerId, kWorkerId) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(22);
        sock_fprog prog = {static_cast<unsigned short>(filter.size()), filter.data()};
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
            _exit(23);
        std::vector<std::string> env = {"LC_ALL=C"};
        env.insert(env.end(), extra_env.begin(), extra_env.end());
        std::vector<char *> envp;
        for (auto &e : env)
            envp.push_back(e.data());
        envp.push_back(nullptr);
        char name[] = "discovery-worker";
        char *argv[] = {name, nullptr};
        execve(kWorkerPath, argv, envp.data());
        _exit(24);
    }
    for (int fd : {verdict[1], control[0], report[1], input[0], input[1], log})
        close(fd);
    g_worker = pid;
    w = {pid, verdict[0], control[1], report[0]};
    return true;
}

bool tell(int fd, const char *word)
{
    std::string text = std::string(word) + "\n";
    return write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
}

// READY, both seccomp stages present, go, report, release, bounded exit.
void run_worker(Worker &w, const std::function<void()> &before_release = {})
{
    std::string line, status;
    if (!read_line(w.report, line, 30000) || line != "READY") {
        int wstatus = 0;
        std::string why = "running";
        if (waitpid(w.pid, &wstatus, WNOHANG) == w.pid)
            why = WIFEXITED(wstatus) ? "exit=" + std::to_string(WEXITSTATUS(wstatus)) :
                                       "signal=" + std::to_string(WTERMSIG(wstatus));
        worker_fail("WORKER_NOT_READY " + why);
    }
    if (!read_file("/proc/" + std::to_string(w.pid) + "/status", status) ||
        status.find("\nSeccomp_filters:\t2\n") == std::string::npos)
        worker_fail("SECCOMP_STAGES");
    event("WORKER_READY");
    if (!tell(w.control, "go") || !read_line(w.report, line, 100000))
        worker_fail("NO_WORKER_REPORT");
    event(line);
    if (before_release)
        before_release();
    if (!tell(w.control, "release"))
        worker_fail("RELEASE");
    int wstatus = 0;
    const long deadline = now_ms() + 30000;
    pid_t done = 0;
    while ((done = waitpid(w.pid, &wstatus, WNOHANG)) == 0 && now_ms() < deadline)
        poll(nullptr, 0, 50);
    if (done != w.pid) {
        kill(w.pid, SIGKILL);
        waitpid(w.pid, &wstatus, 0);
        worker_fail("WORKER_EXIT_TIMEOUT");
    }
    w.status = wstatus;
    event("WORKER_EXITED " + (WIFEXITED(wstatus) ? std::to_string(WEXITSTATUS(wstatus)) :
                              "signal=" + std::to_string(WTERMSIG(wstatus))));
}

bool set_link(const MediaNode &media, const book2lab::Snapshot &t, const std::string &source, const std::string &sink,
              uint32_t flags)
{
    auto entity = [&](const std::string &name) -> uint32_t {
        for (const auto &e : t.entities)
            if (name == e.name)
                return e.id;
        return 0;
    };
    const uint32_t src = entity(source), dst = entity(sink);
    const media_v2_pad *src_pad = nullptr, *dst_pad = nullptr;
    for (const auto &l : t.links) {
        if ((l.flags & MEDIA_LNK_FL_LINK_TYPE) != MEDIA_LNK_FL_DATA_LINK)
            continue;
        const media_v2_pad *a = nullptr, *b = nullptr;
        for (const auto &p : t.pads) {
            if (p.id == l.source_id)
                a = &p;
            if (p.id == l.sink_id)
                b = &p;
        }
        if (a && b && a->entity_id == src && b->entity_id == dst)
            src_pad = a, dst_pad = b;
    }
    if (!src || !dst || !src_pad || !dst_pad || enter_group(kInventory, getpid()) != 0)
        return false;
    media_link_desc desc {};
    desc.source = {src, static_cast<uint16_t>(src_pad->index), MEDIA_PAD_FL_SOURCE, {}};
    desc.sink = {dst, static_cast<uint16_t>(dst_pad->index), MEDIA_PAD_FL_SINK, {}};
    desc.flags = flags;
    int fd = open_bracketed(media, O_RDWR);
    bool ok = fd >= 0 && ioctl(fd, MEDIA_IOC_SETUP_LINK, &desc) == 0;
    if (fd >= 0)
        close(fd);
    return enter_group(QUARANTINE, getpid()) == 0 && ok;
}

bool worker_record(const std::string &text)
{
    std::string log, needle = " " + std::to_string(g_worker) + " " + text + "\n";
    return read_file(std::string(kDebug) + "/effects", log) && log.find(needle) != std::string::npos;
}

// Observer sensitivity control: unpatched libcamera with every node granted.
void stock_baseline(const std::vector<MediaNode> &media, const std::vector<book2lab::Snapshot> &tops)
{
    const MediaNode *cio2 = find_role(media, tops, "cio2");
    if (!cio2 || !set_link(*cio2, tops[static_cast<size_t>(cio2 - media.data())], "ov7251 4-0060",
                           "ipu3-csi2 1", MEDIA_LNK_FL_ENABLED))
        fail("IR_LINK");
    event("IR_LINK_ENABLED");
    std::vector<std::string> paths;
    for (const auto &m : media)
        paths.push_back(m.path);
    for (const auto &n : sysfs_v4l2())
        paths.push_back(n.path);
    std::vector<device_rule> rules;
    Worker w;
    if (!grant(paths, rules) || !launch_worker(rules, {}, w))
        fail("LAUNCH");
    run_worker(w);
    if (!worker_record("open ov7251_4-0060"))
        fail("STOCK_EFFECTS");
    event("STOCK_EFFECTS_OBSERVED");
}

constexpr const char *kContractPath = "/lab/front.contract";
constexpr const char *kIpaDigestPath = "/lab/ipa_ipu3.sha256";
constexpr const char *kReservationDir = "/run/book2-lab";

bool graph_matches_contract(const book2lab::Reservation &contract, const std::vector<book2lab::Snapshot> &tops)
{
    std::set<std::string> want(contract.graph.begin(), contract.graph.end()), have;
    for (const auto &t : tops) {
        std::vector<std::string> records;
        if (!book2lab::graph_records(t, &records))
            return false;
        have.insert(records.begin(), records.end());
    }
    return want == have;
}

bool bind_node(book2lab::Reservation &r, const std::string &grant, const std::vector<book2lab::Snapshot> &tops,
               const std::vector<DevNode> &v4l2)
{
    for (const auto &t : tops)
        for (const auto &e : t.entities) {
            std::string name;
            if (!book2lab::label(e.name, &name) || name != grant)
                continue;
            for (const auto &l : t.links) {
                if ((l.flags & MEDIA_LNK_FL_LINK_TYPE) != MEDIA_LNK_FL_INTERFACE_LINK || l.sink_id != e.id)
                    continue;
                for (const auto &i : t.interfaces)
                    for (const auto &d : v4l2)
                        if (i.id == l.source_id && d.major == i.devnode.major && d.minor == i.devnode.minor) {
                            book2lab::Node n;
                            n.entity = grant;
                            n.entity_id = e.id;
                            n.major = d.major;
                            n.minor = d.minor;
                            n.inode = d.inode;
                            n.path = d.path;
                            r.nodes.push_back(n);
                            return true;
                        }
            }
        }
    return false;
}

// Bind the contract to this boot: media and granted node identities, the
// reserved topology versions and the IPA module identity and digest.
bool bind_reservation(book2lab::Reservation &r, const std::vector<MediaNode> &media,
                      const std::vector<book2lab::Snapshot> &tops)
{
    r.nonce = nonce;
    for (size_t i = 0; i < media.size(); i++) {
        book2lab::Node n;
        n.media = true;
        n.role = book2lab::role_for_driver(tops[i].info.driver);
        n.major = media[i].major;
        n.minor = media[i].minor;
        n.inode = media[i].inode;
        n.version = tops[i].version;
        n.path = media[i].path;
        r.nodes.push_back(n);
    }
    const std::vector<DevNode> v4l2 = sysfs_v4l2();
    for (const auto &grant : r.grants)
        if (grant != "cio2" && grant != "imgu" && !bind_node(r, grant, tops, v4l2))
            return false;
    struct stat st {};
    std::string digest;
    if (stat(r.ipa.path.c_str(), &st) != 0 || !read_file(kIpaDigestPath, digest) || digest.size() < 64)
        return false;
    r.bind_ipa = book2lab::BindIpa {r.ipa.path, static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino),
                                    static_cast<uint64_t>(st.st_size), digest.substr(0, 64)};
    return true;
}

bool write_reservation(const book2lab::Reservation &r)
{
    const std::string text = book2lab::serialize(r);
    const std::string path = std::string(kReservationDir) + "/reservation", tmp = path + ".new";
    if (!book2lab::parse_reservation(text) || (mkdir(kReservationDir, 0755) != 0 && errno != EEXIST))
        return false;
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
    if (fd < 0)
        return false;
    bool ok = write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    return close(fd) == 0 && ok && rename(tmp.c_str(), path.c_str()) == 0;
}

// The guard's verdict is a label for the receipt, never evidence.
std::string read_verdict(int fd)
{
    std::string line;
    if (!read_line(fd, line, 1000) || line.rfind("VERDICT ", 0) != 0)
        return "none";
    return line.substr(8);
}

std::vector<std::string> book2lab_tokens(const std::string &s)
{
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t end = s.find(' ', pos);
        out.push_back(s.substr(pos, end - pos));
        pos = end == std::string::npos ? s.size() : end + 1;
    }
    return out;
}

// Re-register the graph after reserving; record what a number-based check would see.
void replace_and_report(const book2lab::Reservation &r)
{
    const book2lab::Node *old = nullptr;
    for (const auto &n : r.nodes)
        if (n.media && n.role == "cio2")
            old = &n;
    if (!old || !write_file(std::string(kDebug) + "/control", "replace\n"))
        fail("CONTROL_REPLACE");
    std::vector<MediaNode> now = sysfs_media();
    std::vector<book2lab::Snapshot> fresh;
    if (!read_media(now, fresh))
        fail("REREAD_AFTER_REPLACE");
    const MediaNode *cio2 = find_role(now, fresh, "cio2");
    if (!cio2)
        fail("NO_CIO2_AFTER_REPLACE");
    const uint64_t version = fresh[static_cast<size_t>(cio2 - now.data())].version;
    event(std::string("REPLACED same_devt=") + (cio2->major == old->major && cio2->minor == old->minor ? "1" : "0") +
          " same_version=" + (version == old->version ? "1" : "0") + " new_inode=" + (cio2->inode != old->inode ? "1" : "0"));
}

enum class Ownership { Known, RefusedClean, Unknown };

struct Outcome {
    Ownership kind;
    std::string reason;
};

// Decide from trusted evidence only: the driver's log and open counts, process
// state, kernfs inodes and the live graph. The guard's verdict is not used.
Outcome classify_attempt(const book2lab::Reservation &r, const Worker &w)
{
    if (!WIFEXITED(w.status) || WEXITSTATUS(w.status) != 0)
        return {Ownership::Unknown, "worker-exit"};
    std::string counts, log;
    if (!read_file(std::string(kDebug) + "/open_counts", counts) || !read_file(std::string(kDebug) + "/effects", log))
        return {Ownership::Unknown, "observer"};
    for (size_t pos = 0; pos < counts.size();) {
        size_t end = counts.find('\n', pos);
        std::string line = counts.substr(pos, end - pos);
        pos = end == std::string::npos ? counts.size() : end + 1;
        if (!line.empty() && line.substr(line.rfind(' ') + 1) != "0")
            return {Ownership::Unknown, "open-handles"};
    }
    std::vector<std::string> worker_effects;
    std::set<std::string> granted(r.grants.begin(), r.grants.end());
    for (size_t pos = 0; pos < log.size();) {
        size_t end = log.find('\n', pos);
        std::string line = log.substr(pos, end - pos);
        pos = end == std::string::npos ? log.size() : end + 1;
        if (line.rfind("dropped ", 0) == 0) {
            if (line != "dropped 0")
                return {Ownership::Unknown, "dropped"};
            continue;
        }
        unsigned long long seq = 0;
        unsigned instance = 0;
        int tgid = 0, used = 0;
        if (std::sscanf(line.c_str(), "%llu %u %d %n", &seq, &instance, &tgid, &used) != 3)
            return {Ownership::Unknown, "observer"};
        if (tgid != 1 && tgid != w.pid)
            return {Ownership::Unknown, "foreign-process"};
        std::string text = line.substr(static_cast<size_t>(used));
        std::string kind = text.substr(0, text.find(' '));
        if (tgid != w.pid || kind == "control")
            continue;
        if (kind == "open" || kind == "release") {
            if (!granted.count(text.substr(text.find(' ') + 1)))
                return {Ownership::Unknown, "ungranted-node"};
            continue;
        }
        worker_effects.push_back(text);
    }
    std::vector<std::pair<unsigned, unsigned>> present;
    for (const auto &m : sysfs_media())
        present.emplace_back(m.major, m.minor);
    if (!book2lab::check_media_set(r, present).ok)
        return {Ownership::Unknown, "media-set"};
    for (const auto &n : r.nodes) {
        ino_t inode = 0;
        if (!kernfs_inode(n.major, n.minor, inode) || inode != n.inode)
            return {Ownership::Unknown, "replaced"};
    }
    // Expand listed effects into the driver's per-record form.
    std::multiset<std::string> expected;
    std::vector<size_t> link_index;
    for (size_t i = 0; i < r.effects.size(); i++) {
        const book2lab::Effect &e = r.effects[i];
        char buf[96];
        if (e.kind == book2lab::Effect::Kind::Ctrl) {
            for (const auto &[id, value] : e.controls) {
                std::snprintf(buf, sizeof(buf), "ctrl %s 0x%x=%lld", e.entity.c_str(), id, static_cast<long long>(value));
                expected.insert(buf);
            }
        } else if (e.kind == book2lab::Effect::Kind::Link) {
            std::snprintf(buf, sizeof(buf), "link %s:%u %s:%u 0x%x", e.entity.c_str(), e.pad, e.sink.c_str(), e.sink_pad, e.flags);
            expected.insert(buf);
            link_index.push_back(i);
        } else {
            std::snprintf(buf, sizeof(buf), "fmt %s %u active * %ux%u", e.entity.c_str(), e.pad, e.width, e.height);
            expected.insert(buf);
        }
    }
    book2lab::EffectLedger ledger;
    ledger.used.assign(r.effects.size(), false);
    for (const auto &effect : worker_effects) {
        std::string key = effect;
        if (key.rfind("fmt ", 0) == 0) {
            auto t = book2lab_tokens(key);
            if (t.size() == 6)
                key = "fmt " + t[1] + " " + t[2] + " " + t[3] + " * " + t[5];
        }
        auto it = expected.find(key);
        if (it == expected.end())
            return {Ownership::Unknown, "unlisted-effect"};
        expected.erase(it);
        if (key.rfind("link ", 0) == 0)
            for (size_t i : link_index) {
                const book2lab::Effect &e = r.effects[i];
                char buf[96];
                std::snprintf(buf, sizeof(buf), "link %s:%u %s:%u 0x%x", e.entity.c_str(), e.pad, e.sink.c_str(), e.sink_pad, e.flags);
                if (key == buf && !ledger.used[i]) {
                    ledger.used[i] = true;
                    break;
                }
            }
    }
    std::vector<MediaNode> media = sysfs_media();
    std::vector<book2lab::Snapshot> tops;
    if (!read_media(media, tops))
        return {Ownership::Unknown, "snapshot"};
    for (const auto &t : tops) {
        const std::string role = book2lab::role_for_driver(t.info.driver);
        book2lab::Verdict v = book2lab::compare_graph(r, role == "cio2" ? book2lab::Role::Cio2 : book2lab::Role::Imgu, t, ledger);
        if (!v.ok)
            return {Ownership::Unknown, v.reason};
    }
    if (worker_effects.empty())
        return {Ownership::RefusedClean, ""};
    if (!expected.empty())
        return {Ownership::Unknown, "partial-effects"};
    return {Ownership::Known, ""};
}

void run_ir_stub()
{
    int out[2];
    if (pipe2(out, O_CLOEXEC) != 0)
        fail("IR_STUB");
    pid_t pid = fork();
    if (pid == 0) {
        if (dup2(out[1], 1) != 1)
            _exit(30);
        char name[] = "ir-stub";
        char *argv[] = {name, nullptr};
        char *envp[] = {nullptr};
        execve("/lab/ir-stub", argv, envp);
        _exit(31);
    }
    close(out[1]);
    std::string line;
    int status = 0;
    bool ok = pid > 0 && read_line(out[0], line, 10000) && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0 && line == "IR_STUB_RAN";
    close(out[0]);
    if (!ok)
        fail("IR_STUB");
    event(line);
}

void finish_attempt(const book2lab::Reservation &r, const Worker &w)
{
    Outcome o = classify_attempt(r, w);
    if (o.kind == Ownership::Known) {
        event("OWNER_RELEASED");
        event("SECOND_BACKEND_STARTED");
        run_ir_stub();
    } else if (o.kind == Ownership::RefusedClean) {
        event("RELEASED_AFTER_REFUSAL");
        event("SECOND_BACKEND_BLOCKED refused");
    } else {
        event("HOLD " + o.reason);
        event("SECOND_BACKEND_BLOCKED unknown");
    }
}

void lab_discovery(const std::vector<MediaNode> &media, const std::vector<book2lab::Snapshot> &tops)
{
    std::string text;
    if (!read_file(kContractPath, text))
        fail("CONTRACT");
    std::optional<book2lab::Reservation> contract = book2lab::parse_contract(text);
    if (!contract || !book2lab::check_front(*contract).ok)
        fail("CONTRACT");
    if (!graph_matches_contract(*contract, tops)) {
        event("REFUSED_CONTRACT_GRAPH");
        event("REFUSED_BEFORE_RESERVATION");
        event("SECOND_BACKEND_BLOCKED refused");
        return;
    }
    book2lab::Reservation r = *contract;
    if (!bind_reservation(r, media, tops))
        fail("RESERVATION");
    if (lab_case == "effect-unlisted-link")
        r.effects.erase(std::remove_if(r.effects.begin(), r.effects.end(),
                                       [](const book2lab::Effect &e) { return e.kind == book2lab::Effect::Kind::Link; }),
                        r.effects.end());
    if (!write_reservation(r))
        fail("RESERVATION_WRITE");
    event("RESERVED");
    const MediaNode *cio2 = find_role(media, tops, "cio2");
    if (lab_case == "graph-ir-link-enabled") {
        if (!cio2 || !set_link(*cio2, tops[static_cast<size_t>(cio2 - media.data())], "ov7251 4-0060",
                               "ipu3-csi2 1", MEDIA_LNK_FL_ENABLED))
            fail("IR_LINK");
        event("IR_LINK_ENABLED");
    } else if (lab_case == "graph-extra-entity") {
        if (!write_file(std::string(kDebug) + "/control", "add-entity\n"))
            fail("CONTROL_ADD_ENTITY");
        event("ENTITY_ADDED");
    } else if (lab_case == "hotplug-extra-media") {
        if (!write_file(std::string(kDebug) + "/control", "add-media\n"))
            fail("CONTROL_ADD_MEDIA");
        event("MEDIA_ADDED");
    } else if (lab_case == "replace-before-discovery") {
        replace_and_report(r);
    } else if (lab_case == "generation-during-discovery") {
        if (!write_file(std::string(kDebug) + "/control", "bump-on-front-fmt\n"))
            fail("CONTROL_BUMP");
        event("BUMP_ARMED");
    }
    std::vector<std::string> paths;
    for (const auto &n : r.nodes)
        paths.push_back(n.path);
    std::vector<device_rule> rules;
    Worker w;
    if (!grant(paths, rules) || !launch_worker(rules, {}, w))
        fail("LAUNCH");
    std::function<void()> before_release;
    if (lab_case == "replace-after-discovery")
        before_release = [] {
            if (!write_file(std::string(kDebug) + "/control", "replace\n"))
                fail("CONTROL_REPLACE");
            event("REPLACED_AFTER_DISCOVERY");
        };
    run_worker(w, before_release);
    const std::string verdict = read_verdict(w.verdict);
    if (verdict == "none")
        print_worker_log();
    event("GUARD " + verdict);
    finish_attempt(r, w);
}

} // namespace

int main()
{
    if (getpid() != 1 || geteuid() != 0)
        return EXIT_FAILURE;
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0 || !read_scope()) {
        event("ERROR_SCOPE");
        poweroff();
    }
    event("PID1");
    /* Console keeps warnings and worse (WARN, KASAN, lockdep); info noise cannot split receipt lines. */
    klogctl(8, nullptr, 5);
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0 ||
        mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0 ||
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0755") != 0 ||
        mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0700") != 0 ||
        mount("debugfs", "/sys/kernel/debug", "debugfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0700") != 0)
        fail("MOUNT");
    debugfs_ready = true;
    if (!make_group(QUARANTINE, {}) || enter_group(QUARANTINE, getpid()) != 0)
        fail("QUARANTINE");
    event("DENY_ATTACHED");
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755") != 0)
        fail("DEVTMPFS");
    std::vector<MediaNode> nodes = sysfs_media();
    if (nodes.size() != 2)
        fail("MEDIA_COUNT");
    errno = 0;
    int probe = open(nodes[0].path.c_str(), O_RDONLY | O_CLOEXEC);
    if (probe >= 0 || errno != EPERM)
        fail("PRE_INVENTORY_OPEN");
    event("PRE_INVENTORY_DENIED");
    event("INTENT_RECORDED");
    std::vector<book2lab::Snapshot> tops;
    if (!read_media(nodes, tops))
        fail("TOPOLOGY");
    if (lab_case == "topology") {
        for (const auto &t : tops) {
            std::vector<std::string> records;
            if (!book2lab::graph_records(t, &records))
                fail("TOPOLOGY_RECORDS");
            for (const auto &r : records)
                event("TOPOLOGY " + r);
        }
        event("TOPOLOGY_READ");
    } else if (lab_case == "sim-controls") {
        sim_controls(nodes, tops);
    } else if (lab_case == "stock-baseline") {
        stock_baseline(nodes, tops);
    } else {
        lab_discovery(nodes, tops);
    }
    dump_effects(g_worker);
    poweroff();
}
