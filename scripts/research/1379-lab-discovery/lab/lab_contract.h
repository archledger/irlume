// SPDX-License-Identifier: LGPL-2.1-or-later
// Book 2 lab contract and reservation format, media topology snapshots and
// the graph and effect checks shared by the guest supervisor and the lab
// build of libcamera. Names write spaces as '_'; a real underscore in a
// kernel name is refused because it would make the encoding ambiguous.
#ifndef BOOK2_LAB_CONTRACT_H
#define BOOK2_LAB_CONTRACT_H

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <linux/media.h>

namespace book2lab {

enum class Role { Cio2, Imgu };

const char *role_name(Role role);
std::string role_for_driver(std::string_view driver); // cio2, imgu or other

struct Verdict {
    bool ok = true;
    std::string reason;
};

struct Snapshot {
    media_device_info info {};
    uint64_t version = 0;
    std::vector<media_v2_entity> entities;
    std::vector<media_v2_interface> interfaces;
    std::vector<media_v2_pad> pads;
    std::vector<media_v2_link> links;
};

struct Front {
    std::string sensor, csi2, video, imgu;
};

struct Effect {
    enum class Kind { Link, Ctrl, Fmt };
    Kind kind = Kind::Link;
    std::string role;   // link: cio2 or imgu
    std::string entity; // link: source entity; ctrl and fmt: target entity
    uint32_t pad = 0;   // link: source pad; fmt: pad
    std::string sink;   // link: sink entity
    uint32_t sink_pad = 0;
    uint32_t flags = 0;
    std::vector<std::pair<uint32_t, int64_t>> controls; // ctrl, kept sorted by id
    uint32_t code = 0, width = 0, height = 0;           // fmt request
    bool operator==(const Effect &) const = default;
};

// A parsed bind-media (media == true) or bind-node record.
struct Node {
    bool media = false;
    std::string role;   // media only
    std::string entity; // node only
    uint32_t entity_id = 0;
    unsigned major = 0, minor = 0;
    uint64_t inode = 0;
    uint64_t version = 0; // media only: reserved topology version
    std::string path;
};

struct Ipa {
    std::string path, pipeline, name;
    uint32_t version = 0;
};

struct BindIpa {
    std::string path;
    uint64_t dev = 0, inode = 0, size = 0;
    std::string sha256;
};

struct Reservation {
    std::string nonce;               // empty for a bare contract
    std::vector<std::string> graph;  // media, entity, node and link records
    Front front;
    std::vector<std::string> grants; // entity labels or media roles
    std::vector<Effect> effects;     // a multiset: each entry is used once
    Ipa ipa;
    std::vector<Node> nodes;
    std::optional<BindIpa> bind_ipa;
};

struct EffectLedger {
    std::vector<bool> used;
};

bool label(const char *name, std::string *out);
int read_snapshot(int media_fd, Snapshot *out);
bool graph_records(const Snapshot &s, std::vector<std::string> *out);
std::string format_effect(const Effect &e);

std::optional<Reservation> parse_contract(std::string_view text);
std::optional<Reservation> parse_reservation(std::string_view text);
std::string serialize(const Reservation &r);

Verdict compare_graph(const Reservation &r, Role role, const Snapshot &s, const EffectLedger &ledger);
Verdict check_front(const Reservation &r);
Verdict check_media_set(const Reservation &r, const std::vector<std::pair<unsigned, unsigned>> &present);
Verdict match_effect(const Reservation &r, const Effect &e, EffectLedger *ledger);
Verdict check_environment(const char *const *envp, const std::vector<std::string> &config_paths);

} // namespace book2lab

#endif
