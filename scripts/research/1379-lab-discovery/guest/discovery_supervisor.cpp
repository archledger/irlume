// SPDX-License-Identifier: GPL-3.0-or-later
// Trusted PID 1 supervisor for the Book 2 discovery guest (B03). Guest only:
// it mounts, denies every device before inventory, reads the simulated graph
// under a narrow scope and reports receipts on the serial console.
extern "C" {
#include "lab.h"
}

#include <linux/bpf.h>
#include <linux/media.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace {

constexpr const char *kDebug = "/sys/kernel/debug/book2_lab_sim";
constexpr const char *kInventory = "/sys/fs/cgroup/inventory";
std::string nonce;
std::string lab_case;
bool debugfs_ready = false;

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
    dump_effects(0);
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
    static const char *const known[] = {"topology", "sim-controls"};
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

struct Topology {
    media_device_info info {};
    uint64_t version = 0;
    std::vector<media_v2_entity> entities;
    std::vector<media_v2_interface> interfaces;
    std::vector<media_v2_pad> pads;
    std::vector<media_v2_link> links;
};

bool read_topology(int fd, Topology &t)
{
    if (ioctl(fd, MEDIA_IOC_DEVICE_INFO, &t.info) != 0)
        return false;
    for (int attempt = 0; attempt < 4; attempt++) {
        media_v2_topology topo {};
        if (ioctl(fd, MEDIA_IOC_G_TOPOLOGY, &topo) != 0)
            return false;
        uint64_t version = topo.topology_version;
        t.entities.assign(topo.num_entities, {});
        t.interfaces.assign(topo.num_interfaces, {});
        t.pads.assign(topo.num_pads, {});
        t.links.assign(topo.num_links, {});
        topo.ptr_entities = reinterpret_cast<uintptr_t>(t.entities.data());
        topo.ptr_interfaces = reinterpret_cast<uintptr_t>(t.interfaces.data());
        topo.ptr_pads = reinterpret_cast<uintptr_t>(t.pads.data());
        topo.ptr_links = reinterpret_cast<uintptr_t>(t.links.data());
        if (ioctl(fd, MEDIA_IOC_G_TOPOLOGY, &topo) != 0)
            return false;
        if (topo.topology_version == version && topo.num_entities == t.entities.size() &&
            topo.num_interfaces == t.interfaces.size() && topo.num_pads == t.pads.size() &&
            topo.num_links == t.links.size()) {
            t.version = version;
            return true;
        }
    }
    return false;
}

// Contract names write spaces as '_'; a real underscore would be ambiguous.
bool label(const char *name, std::string &out)
{
    out = name;
    if (out.empty())
        return false;
    for (char &c : out) {
        if (c == '_' || c < 0x20 || c > 0x7e)
            return false;
        if (c == ' ')
            c = '_';
    }
    return true;
}

std::string role_of(const media_device_info &info)
{
    std::string driver = info.driver;
    return driver == "ipu3-cio2" ? "cio2" : driver == "ipu3-imgu" ? "imgu" : "other";
}

std::string hex(uint64_t value)
{
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
    return buf;
}

bool graph_records(const Topology &t, std::vector<std::string> &out)
{
    std::string role = role_of(t.info), model, name;
    if (!label(t.info.model, model))
        return false;
    out.push_back("media " + role + " " + t.info.driver + " " + model);
    auto entity_name = [&](uint32_t id, std::string &result) {
        for (const auto &e : t.entities)
            if (e.id == id)
                return label(e.name, result);
        return false;
    };
    auto pad = [&](uint32_t id) -> const media_v2_pad * {
        for (const auto &p : t.pads)
            if (p.id == id)
                return &p;
        return nullptr;
    };
    for (const auto &e : t.entities) {
        if (!label(e.name, name))
            return false;
        std::vector<const media_v2_pad *> pads;
        for (const auto &p : t.pads)
            if (p.entity_id == e.id)
                pads.push_back(&p);
        std::sort(pads.begin(), pads.end(), [](auto a, auto b) { return a->index < b->index; });
        std::string line = "entity " + role + " " + name + " " + hex(e.function);
        for (size_t i = 0; i < pads.size(); i++) {
            if (pads[i]->index != i)
                return false;
            line += pads[i]->flags & MEDIA_PAD_FL_SINK ? " sink" : " source";
        }
        out.push_back(line);
    }
    for (const auto &l : t.links) {
        uint32_t type = l.flags & MEDIA_LNK_FL_LINK_TYPE;
        if (type == MEDIA_LNK_FL_INTERFACE_LINK) {
            const media_v2_interface *intf = nullptr;
            for (const auto &i : t.interfaces)
                if (i.id == l.source_id)
                    intf = &i;
            if (!intf || !entity_name(l.sink_id, name))
                return false;
            std::string kind = intf->intf_type == MEDIA_INTF_T_V4L_VIDEO ? "video" :
                               intf->intf_type == MEDIA_INTF_T_V4L_SUBDEV ? "subdev" : hex(intf->intf_type);
            out.push_back("node " + name + " " + kind);
        } else if (type == MEDIA_LNK_FL_DATA_LINK) {
            const media_v2_pad *src = pad(l.source_id), *sink = pad(l.sink_id);
            std::string a, b;
            if (!src || !sink || !entity_name(src->entity_id, a) || !entity_name(sink->entity_id, b))
                return false;
            out.push_back("link " + role + " " + a + ":" + std::to_string(src->index) + " " + b + ":" +
                          std::to_string(sink->index) + " " + hex(l.flags));
        } else {
            std::string a, b;
            if (!entity_name(l.source_id, a) || !entity_name(l.sink_id, b))
                return false;
            out.push_back("ancillary " + role + " " + a + " " + b + " " + hex(l.flags));
        }
    }
    return true;
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
bool read_media(const std::vector<MediaNode> &nodes, std::vector<Topology> &out)
{
    static bool scoped = false;
    if (!scoped) {
        std::vector<device_rule> rules;
        for (const auto &n : nodes)
            rules.push_back({n.major, n.minor, BPF_DEVCG_ACC_READ});
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
        Topology t;
        ok = ok && fd >= 0 && read_topology(fd, t);
        if (fd >= 0)
            close(fd);
        out.push_back(t);
    }
    return enter_group(QUARANTINE, getpid()) == 0 && ok;
}

const MediaNode *find_role(const std::vector<MediaNode> &nodes, const std::vector<Topology> &tops,
                           const std::string &role)
{
    for (size_t i = 0; i < nodes.size() && i < tops.size(); i++)
        if (role_of(tops[i].info) == role)
            return &nodes[i];
    return nullptr;
}

void sim_controls(const std::vector<MediaNode> &before, const std::vector<Topology> &tops)
{
    const MediaNode *cio2 = find_role(before, tops, "cio2");
    if (!cio2)
        fail("NO_CIO2");
    MediaNode old = *cio2;
    uint64_t old_version = tops[static_cast<size_t>(cio2 - before.data())].version;
    if (!write_file(std::string(kDebug) + "/control", "replace\n"))
        fail("CONTROL_REPLACE");
    std::vector<MediaNode> after = sysfs_media();
    std::vector<Topology> fresh;
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
    std::vector<Topology> tops;
    if (!read_media(nodes, tops))
        fail("TOPOLOGY");
    if (lab_case == "topology") {
        for (const auto &t : tops) {
            std::vector<std::string> records;
            if (!graph_records(t, records))
                fail("TOPOLOGY_RECORDS");
            for (const auto &r : records)
                event("TOPOLOGY " + r);
        }
        event("TOPOLOGY_READ");
    } else if (lab_case == "sim-controls") {
        sim_controls(nodes, tops);
    }
    dump_effects(0);
    poweroff();
}
