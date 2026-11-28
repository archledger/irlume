// SPDX-License-Identifier: LGPL-2.1-or-later
#include "lab_contract.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

#include <sys/ioctl.h>
#include <sys/stat.h>

namespace book2lab {

namespace {

constexpr const char *kContractHeader = "BOOK2_LAB_CONTRACT_V1";
constexpr const char *kReservationHeader = "BOOK2_LAB_RESERVATION_V1";

std::vector<std::string> split(std::string_view line)
{
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos < line.size()) {
        size_t start = line.find_first_not_of(' ', pos);
        if (start == std::string_view::npos)
            break;
        size_t end = line.find(' ', start);
        out.emplace_back(line.substr(start, end == std::string_view::npos ? end : end - start));
        pos = end == std::string_view::npos ? line.size() : end;
    }
    return out;
}

std::string join(const std::vector<std::string> &tokens, size_t from = 0)
{
    std::string out;
    for (size_t i = from; i < tokens.size(); i++)
        out += (out.empty() ? "" : " ") + tokens[i];
    return out;
}

bool parse_number(const std::string &s, uint64_t *out, bool hex)
{
    if (hex ? s.size() < 3 || s.compare(0, 2, "0x") != 0 : s.empty())
        return false;
    const std::string digits = hex ? s.substr(2) : s;
    if (digits.find_first_not_of(hex ? "0123456789abcdef" : "0123456789") != std::string::npos ||
        digits.size() > 16)
        return false;
    errno = 0;
    char *end = nullptr;
    unsigned long long v = std::strtoull(digits.c_str(), &end, hex ? 16 : 10);
    if (errno || *end)
        return false;
    *out = v;
    return true;
}

bool parse_u32(const std::string &s, uint32_t *out, bool hex)
{
    uint64_t v = 0;
    if (!parse_number(s, &v, hex) || v > UINT32_MAX)
        return false;
    *out = static_cast<uint32_t>(v);
    return true;
}

bool parse_endpoint(const std::string &s, std::string *name, uint32_t *pad)
{
    size_t colon = s.rfind(':');
    if (colon == std::string::npos || colon == 0)
        return false;
    *name = s.substr(0, colon);
    return parse_u32(s.substr(colon + 1), pad, false);
}

bool parse_devt(const std::string &s, unsigned *major, unsigned *minor)
{
    size_t colon = s.find(':');
    uint32_t a = 0, b = 0;
    if (colon == std::string::npos || !parse_u32(s.substr(0, colon), &a, false) ||
        !parse_u32(s.substr(colon + 1), &b, false))
        return false;
    *major = a;
    *minor = b;
    return true;
}

bool is_role(const std::string &s)
{
    return s == "cio2" || s == "imgu";
}

bool is_name(const std::string &s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c > 0x20 && c < 0x7f; });
}

std::string hex(uint64_t value)
{
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
    return buf;
}

void normalize(Effect *e)
{
    std::sort(e->controls.begin(), e->controls.end());
}

bool parse_effect(const std::vector<std::string> &t, Effect *e)
{
    if (t.size() == 6 && t[1] == "link") {
        e->kind = Effect::Kind::Link;
        e->role = t[2];
        return is_role(t[2]) && parse_endpoint(t[3], &e->entity, &e->pad) &&
               parse_endpoint(t[4], &e->sink, &e->sink_pad) && parse_u32(t[5], &e->flags, true);
    }
    if (t.size() == 4 && t[1] == "ctrl") {
        e->kind = Effect::Kind::Ctrl;
        e->entity = t[2];
        size_t pos = 0;
        while (pos <= t[3].size()) {
            size_t comma = t[3].find(',', pos);
            std::string item = t[3].substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
            size_t eq = item.find('=');
            uint32_t id = 0;
            if (eq == std::string::npos || !parse_u32(item.substr(0, eq), &id, true))
                return false;
            std::string value = item.substr(eq + 1);
            bool negative = !value.empty() && value[0] == '-';
            uint64_t v = 0;
            if (!parse_number(negative ? value.substr(1) : value, &v, false))
                return false;
            e->controls.emplace_back(id, negative ? -static_cast<int64_t>(v) : static_cast<int64_t>(v));
            if (comma == std::string::npos)
                break;
            pos = comma + 1;
        }
        normalize(e);
        return is_name(e->entity) && !e->controls.empty();
    }
    if (t.size() == 6 && t[1] == "fmt") {
        e->kind = Effect::Kind::Fmt;
        e->entity = t[2];
        size_t x = t[5].find('x');
        return is_name(e->entity) && parse_u32(t[3], &e->pad, false) && parse_u32(t[4], &e->code, true) &&
               x != std::string::npos && parse_u32(t[5].substr(0, x), &e->width, false) &&
               parse_u32(t[5].substr(x + 1), &e->height, false);
    }
    return false;
}

// Entity label to role, from the contract's entity records.
std::map<std::string, std::string> entity_roles(const Reservation &r)
{
    std::map<std::string, std::string> roles;
    for (const auto &g : r.graph) {
        auto t = split(g);
        if (t[0] == "entity")
            roles[t[2]] = t[1];
    }
    return roles;
}

std::optional<Reservation> parse(std::string_view text, bool reservation)
{
    Reservation r;
    std::set<std::string> graph_seen, grants_seen, media_roles, bound_media, bound_nodes;
    bool header = false, front = false, ipa = false;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        std::string line(text.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos));
        pos = end == std::string_view::npos ? text.size() : end + 1;
        if (line.empty() || line[0] == '#')
            continue;
        auto t = split(line);
        if (t.empty())
            return std::nullopt;
        if (!header) {
            if (reservation ? t.size() != 2 || t[0] != kReservationHeader || t[1].size() != 32 ||
                                  t[1].find_first_not_of("0123456789abcdef") != std::string::npos
                            : t.size() != 1 || t[0] != kContractHeader)
                return std::nullopt;
            if (reservation)
                r.nonce = t[1];
            header = true;
            continue;
        }
        const std::string &kind = t[0];
        if (kind == "media" || kind == "entity" || kind == "node" || kind == "link") {
            uint32_t value = 0;
            std::string name;
            bool ok = false;
            if (kind == "media")
                ok = t.size() == 4 && is_role(t[1]) && media_roles.insert(t[1]).second;
            else if (kind == "entity")
                ok = t.size() >= 4 && is_role(t[1]) && is_name(t[2]) && parse_u32(t[3], &value, true) &&
                     std::all_of(t.begin() + 4, t.end(), [](const std::string &p) {
                         return p == "sink" || p == "source";
                     });
            else if (kind == "node")
                ok = t.size() == 3 && is_name(t[1]) && (t[2] == "video" || t[2] == "subdev");
            else
                ok = t.size() == 5 && is_role(t[1]) && parse_endpoint(t[2], &name, &value) &&
                     parse_endpoint(t[3], &name, &value) && parse_u32(t[4], &value, true);
            std::string normalized = join(t);
            if (!ok || !graph_seen.insert(normalized).second)
                return std::nullopt;
            r.graph.push_back(normalized);
        } else if (kind == "front") {
            if (front || t.size() != 5)
                return std::nullopt;
            r.front = {t[1], t[2], t[3], t[4]};
            front = true;
        } else if (kind == "grant") {
            if (t.size() != 2 || !grants_seen.insert(t[1]).second)
                return std::nullopt;
            r.grants.push_back(t[1]);
        } else if (kind == "effect") {
            Effect e;
            if (!parse_effect(t, &e))
                return std::nullopt;
            r.effects.push_back(e);
        } else if (kind == "ipa") {
            if (ipa || t.size() != 5 || !parse_u32(t[4], &r.ipa.version, false))
                return std::nullopt;
            r.ipa = {t[1], t[2], t[3], r.ipa.version};
            ipa = true;
        } else if (reservation && kind == "bind-media") {
            Node n;
            n.media = true;
            n.role = t.size() == 6 ? t[1] : "";
            if (t.size() != 6 || !is_role(t[1]) || !parse_devt(t[2], &n.major, &n.minor) ||
                !parse_number(t[3], &n.inode, false) || !parse_number(t[4], &n.version, false) ||
                !bound_media.insert(t[1]).second)
                return std::nullopt;
            n.path = t[5];
            r.nodes.push_back(n);
        } else if (reservation && kind == "bind-node") {
            Node n;
            if (t.size() != 6 || !is_name(t[1]) || !parse_u32(t[2], &n.entity_id, false) ||
                !parse_devt(t[3], &n.major, &n.minor) || !parse_number(t[4], &n.inode, false) ||
                !bound_nodes.insert(t[1]).second)
                return std::nullopt;
            n.entity = t[1];
            n.path = t[5];
            r.nodes.push_back(n);
        } else if (reservation && kind == "bind-ipa") {
            BindIpa b;
            if (r.bind_ipa || t.size() != 6 || !parse_number(t[2], &b.dev, false) ||
                !parse_number(t[3], &b.inode, false) || !parse_number(t[4], &b.size, false) ||
                t[5].size() != 64 || t[5].find_first_not_of("0123456789abcdef") != std::string::npos)
                return std::nullopt;
            b.path = t[1];
            b.sha256 = t[5];
            r.bind_ipa = b;
        } else {
            return std::nullopt;
        }
    }
    if (!header || !front || !ipa || media_roles.size() != 2)
        return std::nullopt;
    auto roles = entity_roles(r);
    for (const auto &g : r.grants)
        if (!is_role(g) && !roles.count(g))
            return std::nullopt;
    if (reservation) {
        if (bound_media.size() != 2 || !r.bind_ipa || r.bind_ipa->path != r.ipa.path)
            return std::nullopt;
        for (const auto &g : r.grants)
            if (!is_role(g) && !bound_nodes.count(g))
                return std::nullopt;
    }
    return r;
}

} // namespace

const char *role_name(Role role)
{
    return role == Role::Cio2 ? "cio2" : "imgu";
}

std::string role_for_driver(std::string_view driver)
{
    return driver == "ipu3-cio2" ? "cio2" : driver == "ipu3-imgu" ? "imgu" : "other";
}

bool label(const char *name, std::string *out)
{
    *out = name;
    if (out->empty())
        return false;
    for (char &c : *out) {
        if (c == '_' || c < 0x20 || c > 0x7e)
            return false;
        if (c == ' ')
            c = '_';
    }
    return true;
}

int read_snapshot(int fd, Snapshot *t)
{
    if (ioctl(fd, MEDIA_IOC_DEVICE_INFO, &t->info) != 0)
        return -errno;
    for (int attempt = 0; attempt < 4; attempt++) {
        media_v2_topology topo {};
        if (ioctl(fd, MEDIA_IOC_G_TOPOLOGY, &topo) != 0)
            return -errno;
        uint64_t version = topo.topology_version;
        t->entities.assign(topo.num_entities, {});
        t->interfaces.assign(topo.num_interfaces, {});
        t->pads.assign(topo.num_pads, {});
        t->links.assign(topo.num_links, {});
        topo.ptr_entities = reinterpret_cast<uintptr_t>(t->entities.data());
        topo.ptr_interfaces = reinterpret_cast<uintptr_t>(t->interfaces.data());
        topo.ptr_pads = reinterpret_cast<uintptr_t>(t->pads.data());
        topo.ptr_links = reinterpret_cast<uintptr_t>(t->links.data());
        if (ioctl(fd, MEDIA_IOC_G_TOPOLOGY, &topo) != 0)
            return -errno;
        if (topo.topology_version == version && topo.num_entities == t->entities.size() &&
            topo.num_interfaces == t->interfaces.size() && topo.num_pads == t->pads.size() &&
            topo.num_links == t->links.size()) {
            t->version = version;
            return 0;
        }
    }
    return -EAGAIN;
}

bool graph_records(const Snapshot &t, std::vector<std::string> *out)
{
    std::string role = role_for_driver(t.info.driver), model, name;
    if (!label(t.info.model, &model))
        return false;
    out->push_back("media " + role + " " + t.info.driver + " " + model);
    auto entity_name = [&](uint32_t id, std::string *result) {
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
        if (!label(e.name, &name))
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
        out->push_back(line);
    }
    for (const auto &l : t.links) {
        uint32_t type = l.flags & MEDIA_LNK_FL_LINK_TYPE;
        if (type == MEDIA_LNK_FL_INTERFACE_LINK) {
            const media_v2_interface *intf = nullptr;
            for (const auto &i : t.interfaces)
                if (i.id == l.source_id)
                    intf = &i;
            if (!intf || !entity_name(l.sink_id, &name))
                return false;
            std::string kind = intf->intf_type == MEDIA_INTF_T_V4L_VIDEO ? "video" :
                               intf->intf_type == MEDIA_INTF_T_V4L_SUBDEV ? "subdev" : hex(intf->intf_type);
            out->push_back("node " + name + " " + kind);
        } else if (type == MEDIA_LNK_FL_DATA_LINK) {
            const media_v2_pad *src = pad(l.source_id), *sink = pad(l.sink_id);
            std::string a, b;
            if (!src || !sink || !entity_name(src->entity_id, &a) || !entity_name(sink->entity_id, &b))
                return false;
            out->push_back("link " + role + " " + a + ":" + std::to_string(src->index) + " " + b + ":" +
                           std::to_string(sink->index) + " " + hex(l.flags));
        } else {
            std::string a, b;
            if (!entity_name(l.source_id, &a) || !entity_name(l.sink_id, &b))
                return false;
            out->push_back("ancillary " + role + " " + a + " " + b + " " + hex(l.flags));
        }
    }
    return true;
}

std::string format_effect(const Effect &e)
{
    switch (e.kind) {
    case Effect::Kind::Link:
        return "link " + e.role + " " + e.entity + ":" + std::to_string(e.pad) + " " + e.sink + ":" +
               std::to_string(e.sink_pad) + " " + hex(e.flags);
    case Effect::Kind::Ctrl: {
        std::string out = "ctrl " + e.entity + " ";
        for (size_t i = 0; i < e.controls.size(); i++)
            out += (i ? "," : "") + hex(e.controls[i].first) + "=" + std::to_string(e.controls[i].second);
        return out;
    }
    case Effect::Kind::Fmt:
        return "fmt " + e.entity + " " + std::to_string(e.pad) + " " + hex(e.code) + " " +
               std::to_string(e.width) + "x" + std::to_string(e.height);
    }
    return "";
}

std::optional<Reservation> parse_contract(std::string_view text)
{
    return parse(text, false);
}

std::optional<Reservation> parse_reservation(std::string_view text)
{
    return parse(text, true);
}

std::string serialize(const Reservation &r)
{
    std::string out = std::string(kReservationHeader) + " " + r.nonce + "\n";
    for (const auto &g : r.graph)
        out += g + "\n";
    out += "front " + r.front.sensor + " " + r.front.csi2 + " " + r.front.video + " " + r.front.imgu + "\n";
    for (const auto &g : r.grants)
        out += "grant " + g + "\n";
    for (const auto &e : r.effects)
        out += "effect " + format_effect(e) + "\n";
    out += "ipa " + r.ipa.path + " " + r.ipa.pipeline + " " + r.ipa.name + " " + std::to_string(r.ipa.version) + "\n";
    for (const auto &n : r.nodes) {
        std::string devt = std::to_string(n.major) + ":" + std::to_string(n.minor);
        if (n.media)
            out += "bind-media " + n.role + " " + devt + " " + std::to_string(n.inode) + " " +
                   std::to_string(n.version) + " " + n.path + "\n";
        else
            out += "bind-node " + n.entity + " " + std::to_string(n.entity_id) + " " + devt + " " +
                   std::to_string(n.inode) + " " + n.path + "\n";
    }
    if (r.bind_ipa)
        out += "bind-ipa " + r.bind_ipa->path + " " + std::to_string(r.bind_ipa->dev) + " " +
               std::to_string(r.bind_ipa->inode) + " " + std::to_string(r.bind_ipa->size) + " " +
               r.bind_ipa->sha256 + "\n";
    return out;
}

Verdict compare_graph(const Reservation &r, Role role, const Snapshot &s, const EffectLedger &ledger)
{
    const std::string want_role = role_name(role);
    std::vector<std::string> actual;
    if (!graph_records(s, &actual))
        return {false, "entity-set"};
    auto roles = entity_roles(r);
    // Expected link flags reflect listed link effects already consumed.
    std::map<std::string, std::string> link_flags;
    for (const auto &g : r.graph) {
        auto t = split(g);
        if (t[0] == "link" && t[1] == want_role)
            link_flags["link " + t[1] + " " + t[2] + " " + t[3]] = t[4];
    }
    for (size_t i = 0; i < r.effects.size() && i < ledger.used.size(); i++) {
        const Effect &e = r.effects[i];
        if (ledger.used[i] && e.kind == Effect::Kind::Link && e.role == want_role) {
            std::string key = "link " + e.role + " " + e.entity + ":" + std::to_string(e.pad) + " " + e.sink +
                              ":" + std::to_string(e.sink_pad);
            if (link_flags.count(key))
                link_flags[key] = hex(e.flags);
        }
    }
    std::set<std::string> want[4], have[4], want_names, have_names, want_links, have_links;
    auto bucket = [](const std::string &kind) {
        return kind == "media" ? 0 : kind == "entity" ? 1 : kind == "node" ? 2 : 3;
    };
    for (const auto &g : r.graph) {
        auto t = split(g);
        bool mine = t[0] == "node" ? roles.count(t[1]) && roles[t[1]] == want_role : t[1] == want_role;
        if (!mine)
            continue;
        if (t[0] == "link") {
            std::string key = "link " + t[1] + " " + t[2] + " " + t[3];
            want[3].insert(key + " " + link_flags[key]);
            want_links.insert(key);
        } else {
            want[bucket(t[0])].insert(g);
            if (t[0] == "entity")
                want_names.insert(t[2]);
        }
    }
    for (const auto &g : actual) {
        auto t = split(g);
        if (t[0] == "ancillary")
            return {false, "link-set"};
        if (!have[bucket(t[0])].insert(g).second)
            return {false, "graph-duplicate"};
        if (t[0] == "entity")
            have_names.insert(t[2]);
        if (t[0] == "link")
            have_links.insert("link " + t[1] + " " + t[2] + " " + t[3]);
    }
    if (want[0] != have[0])
        return {false, "device-info"};
    for (const auto &n : r.nodes)
        if (n.media && n.role == want_role && n.version != s.version)
            return {false, "version"};
    if (want_names != have_names)
        return {false, "entity-set"};
    if (want[1] != have[1])
        return {false, "pad-set"};
    for (const auto &n : r.nodes) {
        if (n.media || !roles.count(n.entity) || roles[n.entity] != want_role)
            continue;
        const media_v2_entity *entity = nullptr;
        std::string name;
        for (const auto &e : s.entities)
            if (label(e.name, &name) && name == n.entity)
                entity = &e;
        if (!entity || entity->id != n.entity_id)
            return {false, "entity-set"};
        bool devnode = false;
        for (const auto &l : s.links)
            if ((l.flags & MEDIA_LNK_FL_LINK_TYPE) == MEDIA_LNK_FL_INTERFACE_LINK && l.sink_id == entity->id)
                for (const auto &i : s.interfaces)
                    if (i.id == l.source_id && i.devnode.major == n.major && i.devnode.minor == n.minor)
                        devnode = true;
        if (!devnode)
            return {false, "interface"};
    }
    if (want[2] != have[2])
        return {false, "interface"};
    if (want_links != have_links)
        return {false, "link-set"};
    if (want[3] != have[3])
        return {false, "link-state"};
    return {};
}

Verdict check_front(const Reservation &r)
{
    const Front &f = r.front;
    std::map<std::string, std::pair<std::string, std::string>> entities; // name -> role, function
    std::vector<std::vector<std::string>> links;
    for (const auto &g : r.graph) {
        auto t = split(g);
        if (t[0] == "entity")
            entities[t[2]] = {t[1], t[3]};
        else if (t[0] == "link")
            links.push_back(t);
    }
    auto is = [&](const std::string &name, const char *role, const char *function) {
        auto it = entities.find(name);
        return it != entities.end() && it->second.first == role && it->second.second == function;
    };
    const std::string csi2 = "ipu3-csi2_", video = "ipu3-cio2_", imgu = "ipu3-imgu_";
    bool ok = is(f.sensor, "cio2", "0x20001") && is(f.csi2, "cio2", "0x5002") &&
              is(f.video, "cio2", "0x10001") && is(f.imgu, "imgu", "0x4006") &&
              f.csi2.compare(0, csi2.size(), csi2) == 0 && f.video.compare(0, video.size(), video) == 0 &&
              f.imgu.compare(0, imgu.size(), imgu) == 0 && f.csi2.substr(csi2.size()) == f.video.substr(video.size());
    int into_sink = 0;
    bool from_sensor = false, to_video = false;
    for (const auto &t : links) {
        if (t[1] == "cio2" && t[3] == f.csi2 + ":0") {
            into_sink++;
            from_sensor = t[2] == f.sensor + ":0";
        }
        if (t[1] == "cio2" && t[2] == f.csi2 + ":1" && t[3] == f.video + ":0")
            to_video = true;
    }
    if (!ok || into_sink != 1 || !from_sensor || !to_video)
        return {false, "front-binding"};
    return {};
}

// Both live graphs together equal the contract's graph records.
Verdict match_contract_graph(const Reservation &contract, const std::vector<Snapshot> &tops)
{
    std::set<std::string> want(contract.graph.begin(), contract.graph.end()), have;
    for (const auto &t : tops) {
        std::vector<std::string> records;
        if (!graph_records(t, &records))
            return {false, "graph-records"};
        for (const auto &record : records)
            if (!have.insert(record).second)
                return {false, "graph-duplicate"};
    }
    if (want != have)
        return {false, "contract-graph"};
    return {};
}

Verdict check_media_set(const Reservation &r, const std::vector<std::pair<unsigned, unsigned>> &present)
{
    std::set<std::pair<unsigned, unsigned>> want, have(present.begin(), present.end());
    for (const auto &n : r.nodes)
        if (n.media)
            want.insert({n.major, n.minor});
    for (const auto &p : have)
        if (!want.count(p))
            return {false, "extra-media"};
    if (want != have)
        return {false, "media-set"};
    return {};
}

Verdict match_effect(const Reservation &r, const Effect &e, EffectLedger *ledger)
{
    Effect want = e;
    normalize(&want);
    ledger->used.resize(r.effects.size(), false);
    bool reused = false;
    for (size_t i = 0; i < r.effects.size(); i++) {
        if (!(r.effects[i] == want))
            continue;
        if (!ledger->used[i]) {
            ledger->used[i] = true;
            return {};
        }
        reused = true;
    }
    return {false, reused ? "effect-reused" : "unlisted-effect"};
}

Verdict check_environment(const char *const *envp, const std::vector<std::string> &config_paths)
{
    for (const char *const *e = envp; e && *e; e++) {
        std::string_view entry(*e);
        if (entry.rfind("LIBCAMERA_", 0) == 0 || entry.rfind("HOME=", 0) == 0 ||
            entry.rfind("XDG_CONFIG_HOME=", 0) == 0)
            return {false, "environment"};
    }
    for (const auto &path : config_paths) {
        struct stat st {};
        if (stat(path.c_str(), &st) == 0 || errno != ENOENT)
            return {false, "configuration"};
    }
    return {};
}

namespace {

bool printable(std::string_view s)
{
    return std::all_of(s.begin(), s.end(), [](char c) { return c >= 0x20 && c <= 0x7e; });
}

bool digits(std::string_view s, size_t max)
{
    return !s.empty() && s.size() <= max && s.find_first_not_of("0123456789") == std::string_view::npos &&
           (s == "0" || s[0] != '0');
}

// Lines of a text that ends with '\n'; nullopt when the last line is cut off.
std::optional<std::vector<std::string_view>> complete_lines(std::string_view text)
{
    if (!text.empty() && text.back() != '\n')
        return std::nullopt;
    std::vector<std::string_view> out;
    for (size_t pos = 0; pos < text.size();) {
        size_t end = text.find('\n', pos);
        out.push_back(text.substr(pos, end - pos));
        pos = end + 1;
    }
    return out;
}

} // namespace

// The worker's report becomes one of two fixed forms or REPORT_INVALID, so it
// can never carry a second receipt line.
std::string sanitize_report(std::string_view line)
{
    if (line.rfind("CAMERAS ", 0) == 0 && digits(line.substr(8), 3))
        return std::string(line);
    if (line.rfind("START_FAILED -", 0) == 0 && digits(line.substr(14), 4) && line.substr(14) != "0")
        return std::string(line);
    return "REPORT_INVALID";
}

std::string sanitize_verdict(std::string_view line)
{
    if (line == "admit")
        return "admit";
    for (std::string_view kind : {std::string_view("refuse "), std::string_view("hold ")})
        if (line.rfind(kind, 0) == 0 && line.size() > kind.size() && line.size() <= 200 && line[kind.size()] != ' ' &&
            printable(line))
            return std::string(line);
    return "invalid";
}

std::string escape_log_line(std::string_view line)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : line) {
        if (c >= 0x20 && c <= 0x7e && c != '\\') {
            out += static_cast<char>(c);
        } else {
            out += "\\x";
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

/*
 * Missing proof is unknown: the log must start with exactly one "dropped 0"
 * header, number its records from 1 without gaps and hold exactly one
 * supervisor canary, and the open counts must list every granted driver node.
 */
Verdict parse_observer(std::string_view open_counts, std::string_view log, int worker_tgid,
                       const std::vector<std::string> &grants, ObserverRecords *out)
{
    out->worker_effects.clear();
    const auto records = complete_lines(log);
    if (!records || records->empty() || (*records)[0].rfind("dropped ", 0) != 0)
        return {false, "observer"};
    if ((*records)[0] != "dropped 0")
        return {false, "dropped"};
    const std::set<std::string> granted(grants.begin(), grants.end());
    unsigned canaries = 0;
    unsigned long long next = 1;
    for (size_t i = 1; i < records->size(); i++) {
        const std::string line((*records)[i]);
        unsigned long long seq = 0;
        unsigned instance = 0;
        int tgid = 0, used = 0;
        if (std::sscanf(line.c_str(), "%llu %u %d %n", &seq, &instance, &tgid, &used) != 3 || used <= 0 ||
            seq != next++)
            return {false, "observer"};
        if (tgid != 1 && tgid != worker_tgid)
            return {false, "foreign-process"};
        const std::string text = line.substr(static_cast<size_t>(used));
        if (tgid == 1) {
            canaries += text == "control canary";
            continue;
        }
        const std::string kind = text.substr(0, text.find(' '));
        if (kind == "control")
            continue;
        if (kind == "open" || kind == "release") {
            if (!granted.count(text.substr(text.find(' ') + 1)))
                return {false, "ungranted-node"};
            continue;
        }
        out->worker_effects.push_back(text);
    }
    if (canaries != 1)
        return {false, "observer"};
    const auto counts = complete_lines(open_counts);
    if (!counts)
        return {false, "observer"};
    std::set<std::string> listed;
    for (std::string_view line : *counts) {
        const std::vector<std::string> t = split(line);
        const bool negative = t.size() == 3 && t[2].size() > 1 && t[2][0] == '-';
        if (t.size() != 3 || !digits(t[0], 10) || !digits(negative ? std::string_view(t[2]).substr(1) : t[2], 10))
            return {false, "observer"};
        if (t[2] != "0")
            return {false, "open-handles"};
        listed.insert(t[1]);
    }
    for (const std::string &g : grants)
        if (g != "cio2" && g != "imgu" && !listed.count(g))
            return {false, "observer"};
    return {};
}

} // namespace book2lab
