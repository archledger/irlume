// SPDX-License-Identifier: GPL-3.0-or-later
// Host tests for the Book 2 lab contract, reservation and graph checks.
#include "lab_contract.h"

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

using namespace book2lab;

namespace {

int failures = 0;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                              \
        }                                                                            \
    } while (0)

// A two-sensor CIO2 graph and a one-pipe ImgU graph, enough for every check.
const char *kContract = R"(BOOK2_LAB_CONTRACT_V1
# test graph
media cio2 ipu3-cio2 Intel_IPU3_CIO2
media imgu ipu3-imgu ipu3-imgu
entity cio2 ipu3-csi2_0 0x5002 sink source
entity cio2 ipu3-csi2_1 0x5002 sink source
entity cio2 ipu3-cio2_0 0x10001 sink
entity cio2 ov5693_2-0036 0x20001 source
entity cio2 ov7251_4-0060 0x20001 source
entity imgu ipu3-imgu_0 0x4006 sink
node ipu3-csi2_0 subdev
node ipu3-cio2_0 video
node ov5693_2-0036 subdev
node ipu3-imgu_0 subdev
link cio2 ov5693_2-0036:0 ipu3-csi2_0:0 0x0
link cio2 ov7251_4-0060:0 ipu3-csi2_1:0 0x0
link cio2 ipu3-csi2_0:1 ipu3-cio2_0:0 0x3
front ov5693_2-0036 ipu3-csi2_0 ipu3-cio2_0 ipu3-imgu_0
grant cio2
grant imgu
grant ov5693_2-0036
effect ctrl ov5693_2-0036 0x980914=0,0x980915=0
effect link cio2 ov5693_2-0036:0 ipu3-csi2_0:0 0x1
effect fmt ov5693_2-0036 0 0x0 2592x1944
ipa /usr/lib/libcamera/ipa/ipa_ipu3.so ipu3 ipu3 1
)";

const char *kBindings = R"(bind-media cio2 250:0 1001 40 /dev/media0
bind-media imgu 250:1 1002 7 /dev/media1
bind-node ov5693_2-0036 42 81:3 1003 /dev/v4l-subdev2
bind-ipa /usr/lib/libcamera/ipa/ipa_ipu3.so 2 77 4096 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
)";

std::string reservation_text(const std::string &contract = kContract)
{
    std::string body = contract.substr(contract.find('\n') + 1);
    return "BOOK2_LAB_RESERVATION_V1 0123456789abcdef0123456789abcdef\n" + body + kBindings;
}

struct GraphBuilder {
    Snapshot s;
    uint32_t next = 1;
    uint32_t entity(const char *name, uint32_t function)
    {
        media_v2_entity e {};
        e.id = next++;
        std::snprintf(e.name, sizeof(e.name), "%s", name);
        e.function = function;
        s.entities.push_back(e);
        return e.id;
    }
    uint32_t pad(uint32_t entity, uint32_t index, uint32_t flags)
    {
        media_v2_pad p {};
        p.id = next++;
        p.entity_id = entity;
        p.index = index;
        p.flags = flags;
        s.pads.push_back(p);
        return p.id;
    }
    void link(uint32_t source, uint32_t sink, uint32_t flags)
    {
        media_v2_link l {};
        l.id = next++;
        l.source_id = source;
        l.sink_id = sink;
        l.flags = flags;
        s.links.push_back(l);
    }
    void node(uint32_t entity, uint32_t type, uint32_t major, uint32_t minor)
    {
        media_v2_interface i {};
        i.id = next++;
        i.intf_type = type;
        i.devnode.major = major;
        i.devnode.minor = minor;
        s.interfaces.push_back(i);
        link(i.id, entity, MEDIA_LNK_FL_INTERFACE_LINK | MEDIA_LNK_FL_ENABLED | MEDIA_LNK_FL_IMMUTABLE);
    }
};

Snapshot cio2_graph(uint32_t ir_link_flags = 0, bool extra = false)
{
    GraphBuilder g;
    std::snprintf(g.s.info.driver, sizeof(g.s.info.driver), "ipu3-cio2");
    std::snprintf(g.s.info.model, sizeof(g.s.info.model), "Intel IPU3 CIO2");
    g.s.version = 40;
    uint32_t csi0 = g.entity("ipu3-csi2 0", 0x5002), csi1 = g.entity("ipu3-csi2 1", 0x5002);
    uint32_t front = g.entity("ov5693 2-0036", 0x20001), ir = g.entity("ov7251 4-0060", 0x20001);
    uint32_t video = g.entity("ipu3-cio2 0", 0x10001);
    uint32_t csi0_sink = g.pad(csi0, 0, MEDIA_PAD_FL_SINK);
    uint32_t csi0_src = g.pad(csi0, 1, MEDIA_PAD_FL_SOURCE);
    uint32_t video_sink = g.pad(video, 0, MEDIA_PAD_FL_SINK);
    uint32_t csi1_sink = g.pad(csi1, 0, MEDIA_PAD_FL_SINK);
    g.pad(csi1, 1, MEDIA_PAD_FL_SOURCE);
    uint32_t front_src = g.pad(front, 0, MEDIA_PAD_FL_SOURCE);
    uint32_t ir_src = g.pad(ir, 0, MEDIA_PAD_FL_SOURCE);
    g.link(front_src, csi0_sink, 0);
    g.link(ir_src, csi1_sink, ir_link_flags);
    g.link(csi0_src, video_sink, MEDIA_LNK_FL_ENABLED | MEDIA_LNK_FL_IMMUTABLE);
    g.node(video, MEDIA_INTF_T_V4L_VIDEO, 81, 0);
    g.node(csi0, MEDIA_INTF_T_V4L_SUBDEV, 81, 1);
    g.node(front, MEDIA_INTF_T_V4L_SUBDEV, 81, 3);
    if (extra)
        g.entity("book2-lab-extra", 0x20000);
    // The binding names entity id 42 for the front sensor.
    for (auto &e : g.s.entities)
        if (std::string(e.name) == "ov5693 2-0036")
            e.id = 42;
    for (auto &p : g.s.pads)
        if (p.entity_id == front)
            p.entity_id = 42;
    for (auto &l : g.s.links)
        if (l.sink_id == front)
            l.sink_id = 42;
    return g.s;
}

Snapshot imgu_graph()
{
    GraphBuilder g;
    g.next = 100;
    std::snprintf(g.s.info.driver, sizeof(g.s.info.driver), "ipu3-imgu");
    std::snprintf(g.s.info.model, sizeof(g.s.info.model), "ipu3-imgu");
    g.s.version = 7;
    uint32_t imgu = g.entity("ipu3-imgu 0", 0x4006);
    g.pad(imgu, 0, MEDIA_PAD_FL_SINK);
    g.node(imgu, MEDIA_INTF_T_V4L_SUBDEV, 81, 9);
    return g.s;
}

Reservation reserved()
{
    auto r = parse_reservation(reservation_text());
    CHECK(r.has_value());
    return r ? *r : Reservation {};
}

void graph_matches_reservation()
{
    Reservation r = reserved();
    EffectLedger ledger;
    CHECK(compare_graph(r, Role::Cio2, cio2_graph(), ledger).ok);
    CHECK(compare_graph(r, Role::Imgu, imgu_graph(), ledger).ok);
}

void link_state_change_without_version_change_refuses()
{
    Reservation r = reserved();
    EffectLedger ledger;
    Verdict v = compare_graph(r, Role::Cio2, cio2_graph(MEDIA_LNK_FL_ENABLED), ledger);
    CHECK(!v.ok);
    CHECK(v.reason == "link-state");
}

void extra_entity_refuses()
{
    Reservation r = reserved();
    EffectLedger ledger;
    Verdict same_version = compare_graph(r, Role::Cio2, cio2_graph(0, true), ledger);
    CHECK(!same_version.ok && same_version.reason == "entity-set");
    Snapshot bumped = cio2_graph(0, true);
    bumped.version = 43;
    Verdict v = compare_graph(r, Role::Cio2, bumped, ledger);
    CHECK(!v.ok && v.reason == "version");
}

void consumed_link_effect_updates_expected_state()
{
    Reservation r = reserved();
    EffectLedger ledger;
    Effect enable;
    enable.kind = Effect::Kind::Link;
    enable.role = "cio2";
    enable.entity = "ov5693_2-0036";
    enable.sink = "ipu3-csi2_0";
    enable.flags = MEDIA_LNK_FL_ENABLED;
    CHECK(match_effect(r, enable, &ledger).ok);
    Snapshot after = cio2_graph();
    for (auto &l : after.links)
        if ((l.flags & MEDIA_LNK_FL_LINK_TYPE) == MEDIA_LNK_FL_DATA_LINK && l.sink_id != 0 &&
            l.source_id == after.pads[5].id)
            l.flags = MEDIA_LNK_FL_ENABLED;
    CHECK(compare_graph(r, Role::Cio2, after, ledger).ok);
    CHECK(!compare_graph(r, Role::Cio2, cio2_graph(), ledger).ok);
}

void front_binding_on_wrong_port_refuses()
{
    std::string contract = kContract;
    std::string from = "front ov5693_2-0036 ipu3-csi2_0 ipu3-cio2_0";
    contract.replace(contract.find(from), from.size(), "front ov5693_2-0036 ipu3-csi2_1 ipu3-cio2_1");
    auto r = parse_reservation(reservation_text(contract));
    CHECK(r.has_value());
    if (r) {
        Verdict v = check_front(*r);
        CHECK(!v.ok && v.reason == "front-binding");
    }
    CHECK(check_front(reserved()).ok);
}

void extra_media_device_refuses()
{
    Reservation r = reserved();
    CHECK(check_media_set(r, {{250, 0}, {250, 1}}).ok);
    Verdict v = check_media_set(r, {{250, 0}, {250, 1}, {250, 2}});
    CHECK(!v.ok && v.reason == "extra-media");
    CHECK(!check_media_set(r, {{250, 0}}).ok);
}

Effect flips(std::vector<std::pair<uint32_t, int64_t>> controls)
{
    Effect e;
    e.kind = Effect::Kind::Ctrl;
    e.entity = "ov5693_2-0036";
    e.controls = std::move(controls);
    return e;
}

void effect_reused_refuses()
{
    Reservation r = reserved();
    EffectLedger ledger;
    CHECK(match_effect(r, flips({{0x980915, 0}, {0x980914, 0}}), &ledger).ok);
    Verdict v = match_effect(r, flips({{0x980914, 0}, {0x980915, 0}}), &ledger);
    CHECK(!v.ok && v.reason == "effect-reused");
}

void ctrl_set_with_extra_control_refuses()
{
    Reservation r = reserved();
    EffectLedger ledger;
    Verdict v = match_effect(r, flips({{0x980914, 0}, {0x980915, 0}, {0x9f0903, 0}}), &ledger);
    CHECK(!v.ok && v.reason == "unlisted-effect");
    Verdict wrong_value = match_effect(r, flips({{0x980914, 1}, {0x980915, 0}}), &ledger);
    CHECK(!wrong_value.ok && wrong_value.reason == "unlisted-effect");
}

void unknown_or_duplicate_record_refuses()
{
    CHECK(!parse_reservation(reservation_text() + "bogus record\n"));
    CHECK(!parse_reservation(reservation_text() + "front ov5693_2-0036 ipu3-csi2_0 ipu3-cio2_0 ipu3-imgu_0\n"));
    CHECK(!parse_reservation(reservation_text() + "media cio2 ipu3-cio2 Intel_IPU3_CIO2\n"));
    CHECK(!parse_reservation(reservation_text() + "grant cio2\n"));
    CHECK(!parse_reservation(std::string(kContract)));
    CHECK(parse_contract(kContract).has_value());
    std::string missing = reservation_text();
    missing.erase(missing.find("bind-node"), missing.find("bind-ipa") - missing.find("bind-node"));
    CHECK(!parse_reservation(missing));
}

void serialize_roundtrip()
{
    Reservation r = reserved();
    auto again = parse_reservation(serialize(r));
    CHECK(again.has_value());
    if (again) {
        CHECK(again->graph == r.graph);
        CHECK(again->effects == r.effects);
        CHECK(serialize(*again) == serialize(r));
    }
}

void libcamera_environment_or_configuration_refuses()
{
    const char *clean[] = {"LC_ALL=C", nullptr};
    const char *override_env[] = {"LC_ALL=C", "LIBCAMERA_IPA_FORCE_ISOLATION=1", nullptr};
    const char *home[] = {"HOME=/root", nullptr};
    char path[] = "/tmp/book2-lab-config-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(check_environment(clean, {"/nonexistent/configuration.yaml"}).ok);
    Verdict a = check_environment(override_env, {});
    CHECK(!a.ok && a.reason == "environment");
    Verdict b = check_environment(home, {});
    CHECK(!b.ok && b.reason == "environment");
    Verdict c = check_environment(clean, {path});
    CHECK(!c.ok && c.reason == "configuration");
    close(fd);
    unlink(path);
}

void env_override_variants_refuse()
{
    for (const char *var : {"LIBCAMERA_IPA_CONFIG_PATH=/tmp", "LIBCAMERA_IPA_FORCE_ISOLATION=1",
                            "LIBCAMERA_IPA_MODULE_PATH=/tmp", "LIBCAMERA_IPA_PROXY_PATH=/tmp",
                            "LIBCAMERA_PIPELINES_MATCH_LIST=ipu3", "LIBCAMERA_SOFTISP_MODE=cpu",
                            "LIBCAMERA_IPU3_TUNING_FILE=/tmp/x.yaml"}) {
        const char *envp[] = {"LC_ALL=C", var, nullptr};
        Verdict v = check_environment(envp, {});
        CHECK(!v.ok && v.reason == "environment");
    }
}

void configuration_file_refuses()
{
    const char *clean[] = {"LC_ALL=C", nullptr};
    char path[] = "/tmp/book2-lab-configuration-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    for (const std::vector<std::string> &paths : {std::vector<std::string>{path, "/nonexistent/a"},
                                                  std::vector<std::string>{"/nonexistent/a", path}}) {
        Verdict v = check_environment(clean, paths);
        CHECK(!v.ok && v.reason == "configuration");
    }
    close(fd);
    unlink(path);
}

} // namespace

int main()
{
    const std::vector<std::pair<const char *, std::function<void()>>> tests = {
        {"graph_matches_reservation", graph_matches_reservation},
        {"link_state_change_without_version_change_refuses", link_state_change_without_version_change_refuses},
        {"extra_entity_refuses", extra_entity_refuses},
        {"consumed_link_effect_updates_expected_state", consumed_link_effect_updates_expected_state},
        {"front_binding_on_wrong_port_refuses", front_binding_on_wrong_port_refuses},
        {"extra_media_device_refuses", extra_media_device_refuses},
        {"effect_reused_refuses", effect_reused_refuses},
        {"ctrl_set_with_extra_control_refuses", ctrl_set_with_extra_control_refuses},
        {"unknown_or_duplicate_record_refuses", unknown_or_duplicate_record_refuses},
        {"serialize_roundtrip", serialize_roundtrip},
        {"libcamera_environment_or_configuration_refuses", libcamera_environment_or_configuration_refuses},
        {"env_override_variants_refuse", env_override_variants_refuse},
        {"configuration_file_refuses", configuration_file_refuses},
    };
    for (const auto &[name, test] : tests) {
        int before = failures;
        test();
        std::printf("%s %s\n", failures == before ? "ok  " : "FAIL", name);
    }
    std::printf("%zu tests, %d failed checks\n", tests.size(), failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
