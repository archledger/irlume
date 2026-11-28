// SPDX-License-Identifier: GPL-3.0-or-later
// Host tests for the Book 2 lab contract, reservation and graph checks.
#include "lab_contract.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>
#include <linux/videodev2.h>
#include <linux/v4l2-subdev.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

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
effect fmt ov5693_2-0036 0 0x0 2592x1944 0x3007
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

// Two listed updates of one link: the last one applied sets the expected
// state, whatever order the contract lists them in.
void link_effects_apply_in_application_order()
{
    std::string contract = kContract;
    const std::string enable_line = "effect link cio2 ov5693_2-0036:0 ipu3-csi2_0:0 0x1\n";
    contract.replace(contract.find(enable_line), enable_line.size(),
                     "effect link cio2 ov5693_2-0036:0 ipu3-csi2_0:0 0x0\n" + enable_line);
    auto r = parse_reservation(reservation_text(contract));
    CHECK(r.has_value());
    if (!r)
        return;
    Effect enable;
    enable.kind = Effect::Kind::Link;
    enable.role = "cio2";
    enable.entity = "ov5693_2-0036";
    enable.sink = "ipu3-csi2_0";
    enable.flags = MEDIA_LNK_FL_ENABLED;
    Effect disable = enable;
    disable.flags = 0;
    const Snapshot disabled = cio2_graph();
    Snapshot enabled = cio2_graph();
    for (auto &l : enabled.links)
        if ((l.flags & MEDIA_LNK_FL_LINK_TYPE) == MEDIA_LNK_FL_DATA_LINK && l.source_id == enabled.pads[5].id)
            l.flags = MEDIA_LNK_FL_ENABLED;

    EffectLedger guard;
    CHECK(match_effect(*r, enable, &guard).ok && match_effect(*r, disable, &guard).ok);
    CHECK(compare_graph(*r, Role::Cio2, disabled, guard).ok);
    Verdict stale = compare_graph(*r, Role::Cio2, enabled, guard);
    CHECK(!stale.ok && stale.reason == "link-state");

    Replay observed = replay_driver_records(
        *r, {"link ov5693_2-0036:0 ipu3-csi2_0:0 0x1", "link ov5693_2-0036:0 ipu3-csi2_0:0 0x0"});
    CHECK(observed.verdict.ok);
    CHECK(compare_graph(*r, Role::Cio2, disabled, observed.ledger).ok);
    CHECK(!compare_graph(*r, Role::Cio2, enabled, observed.ledger).ok);

    EffectLedger reverse;
    CHECK(match_effect(*r, disable, &reverse).ok && match_effect(*r, enable, &reverse).ok);
    CHECK(compare_graph(*r, Role::Cio2, enabled, reverse).ok);
    CHECK(!compare_graph(*r, Role::Cio2, disabled, reverse).ok);
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

void worker_report_is_whitelisted()
{
    CHECK(sanitize_report("CAMERAS 1") == "CAMERAS 1");
    CHECK(sanitize_report("CAMERAS 0") == "CAMERAS 0");
    CHECK(sanitize_report("START_FAILED -19") == "START_FAILED -19");
    for (const char *bad : {"CAMERAS 1\rBOOK2_DISCOVERY_V1 0123 HOLD forged", "CAMERAS 1\x0b", "CAMERAS", "CAMERAS 01",
                            "CAMERAS 1 2", "CAMERAS 1000", "OWNER_RELEASED", "START_FAILED 0", "START_FAILED -", ""})
        CHECK(sanitize_report(bad) == "REPORT_INVALID");
}

void guard_verdict_is_printable()
{
    const char *link = "refuse unlisted-effect link cio2 ov5693_2-0036:0 ipu3-csi2_0:0 0x1";
    CHECK(sanitize_verdict("admit") == "admit");
    CHECK(sanitize_verdict("hold version") == "hold version");
    CHECK(sanitize_verdict(link) == link);
    for (const char *bad : {"refuse x\rBOOK2_DISCOVERY_V1 0123 HOLD forged", "hold version\x0c", "admit now",
                            "refuse ", "hold", "release", "refuse caf\xc3\xa9", ""})
        CHECK(sanitize_verdict(bad) == "invalid");
}

void worker_log_bytes_are_escaped()
{
    CHECK(escape_log_line("plain text: 1/2 [x]") == "plain text: 1/2 [x]");
    CHECK(escape_log_line("a\rb") == "a\\x0db");
    CHECK(escape_log_line(std::string("x\x85\x1c\x7fy")) == "x\\x85\\x1c\\x7fy");
    CHECK(escape_log_line("a\\x0d") == "a\\x5cx0d");
}

// Open counts and a driver log for one attempt: worker tgid 70, two granted nodes.
const char *kCounts = "1 ov5693_2-0036 0\n1 ipu3-csi2_0 0\n";
const std::vector<std::string> kObserverGrants = {"cio2", "imgu", "ov5693_2-0036", "ipu3-csi2_0"};
constexpr int kWorkerTgid = 70;

std::string observer_log(std::initializer_list<const char *> records, const char *header = "dropped 0\n")
{
    std::string text = header;
    unsigned seq = 1;
    for (const char *r : records)
        text += std::to_string(seq++) + " " + r + "\n";
    return text;
}

Verdict observe(const std::string &counts, const std::string &log, ObserverRecords *out = nullptr)
{
    ObserverRecords scratch;
    return parse_observer(counts, log, kWorkerTgid, kObserverGrants, out ? out : &scratch);
}

void observer_accepts_complete_log()
{
    ObserverRecords out;
    Verdict v = observe(kCounts, observer_log({"1 1 control canary", "1 70 open ov5693_2-0036",
                                               "1 70 ctrl ov5693_2-0036 0x980914=0", "1 70 control bump-fired",
                                               "1 70 release ov5693_2-0036"}), &out);
    CHECK(v.ok);
    CHECK(out.worker_effects == std::vector<std::string>{"ctrl ov5693_2-0036 0x980914=0"});
}

void observer_without_header_is_unknown()
{
    for (const std::string &log : {std::string(), observer_log({"1 1 control canary"}, "")}) {
        Verdict v = observe(kCounts, log);
        CHECK(!v.ok && v.reason == "observer");
    }
}

void observer_requires_one_supervisor_canary()
{
    for (const std::string &log : {observer_log({}), observer_log({"1 70 control canary"}),
                                   observer_log({"1 1 control canary", "1 1 control canary"})}) {
        Verdict v = observe(kCounts, log);
        CHECK(!v.ok && v.reason == "observer");
    }
}

void observer_rejects_gap_or_second_header()
{
    const std::string gap = "dropped 0\n1 1 1 control canary\n3 1 70 ctrl ov5693_2-0036 0x980914=0\n";
    const std::string twice = observer_log({"1 1 control canary"}) + "dropped 0\n";
    for (const std::string &log : {gap, twice}) {
        Verdict v = observe(kCounts, log);
        CHECK(!v.ok && v.reason == "observer");
    }
}

void observer_requires_count_for_every_granted_node()
{
    const std::string log = observer_log({"1 1 control canary"});
    for (const char *counts : {"", "1 ov5693_2-0036 0\n", "1 ov5693_2-0036 0\n1 ipu3-csi2_0 0\nmalformed\n"}) {
        Verdict v = observe(counts, log);
        CHECK(!v.ok && v.reason == "observer");
    }
}

void observer_keeps_specific_reasons()
{
    const std::string log = observer_log({"1 1 control canary"});
    CHECK(observe("1 ov5693_2-0036 1\n1 ipu3-csi2_0 0\n", log).reason == "open-handles");
    CHECK(observe(kCounts, observer_log({"1 1 control canary"}, "dropped 2\n")).reason == "dropped");
    CHECK(observe(kCounts, observer_log({"1 1 control canary", "1 99 ctrl x 0x1=0"})).reason == "foreign-process");
    CHECK(observe(kCounts, observer_log({"1 1 control canary", "1 70 open ov7251_4-0060"})).reason == "ungranted-node");
}

// The IR sensor is unbound, so only the duplicate check can notice a second copy.
media_v2_link ir_link_copy(const Snapshot &s)
{
    media_v2_link copy = s.links[1];
    copy.id = 950;
    return copy;
}

void duplicate_live_entity_refuses()
{
    Reservation r = reserved();
    EffectLedger ledger;
    Snapshot s = cio2_graph();
    for (const auto &e : std::vector<media_v2_entity>(s.entities))
        if (std::string(e.name) == "ov7251 4-0060") {
            media_v2_entity dup = e;
            dup.id = 900;
            s.entities.push_back(dup);
            for (const auto &p : std::vector<media_v2_pad>(s.pads))
                if (p.entity_id == e.id) {
                    media_v2_pad pad = p;
                    pad.id = 901;
                    pad.entity_id = 900;
                    s.pads.push_back(pad);
                }
        }
    Verdict v = compare_graph(r, Role::Cio2, s, ledger);
    CHECK(!v.ok && v.reason == "graph-duplicate");
}

void duplicate_live_link_refuses()
{
    Reservation r = reserved();
    EffectLedger ledger;
    Snapshot s = cio2_graph();
    s.links.push_back(ir_link_copy(s));
    Verdict v = compare_graph(r, Role::Cio2, s, ledger);
    CHECK(!v.ok && v.reason == "graph-duplicate");
}

void contract_graph_duplicate_refuses()
{
    auto contract = parse_contract(kContract);
    CHECK(contract.has_value());
    if (!contract)
        return;
    std::vector<Snapshot> tops = {cio2_graph(), imgu_graph()};
    Verdict clean = match_contract_graph(*contract, tops);
    CHECK(clean.ok);
    tops[0].links.push_back(ir_link_copy(tops[0]));
    Verdict v = match_contract_graph(*contract, tops);
    CHECK(!v.ok && v.reason == "graph-duplicate");
}

void whitespace_line_refuses()
{
    const std::string contract = std::string(kContract) + "   \n";
    CHECK(!parse_contract(contract).has_value());
    CHECK(!parse_reservation(reservation_text(contract)).has_value());
}

std::string contract_with_fmt(const char *fmt_line)
{
    std::string text = kContract;
    size_t at = text.find("effect fmt ");
    size_t end = text.find('\n', at);
    return text.substr(0, at) + fmt_line + text.substr(end);
}

void fmt_effect_requires_result_code()
{
    CHECK(!parse_contract(contract_with_fmt("effect fmt ov5693_2-0036 0 0x0 2592x1944")).has_value());
    auto r = parse_reservation(reservation_text(contract_with_fmt("effect fmt ov5693_2-0036 0 0x0 2592x1944 0x3007")));
    CHECK(r.has_value());
    if (!r)
        return;
    auto again = parse_reservation(serialize(*r));
    CHECK(again.has_value());
    for (const auto *res : {&*r, again ? &*again : &*r})
        for (const auto &e : res->effects)
            if (e.kind == Effect::Kind::Fmt)
                CHECK(e.result_code == 0x3007);
}

Reservation reserved_with_result_code()
{
    Reservation r = reserved();
    for (auto &e : r.effects)
        if (e.kind == Effect::Kind::Fmt)
            e.result_code = 0x3007;
    return r;
}

void request_matches_without_result_code()
{
    Reservation r = reserved_with_result_code();
    EffectLedger ledger;
    Effect request;
    request.kind = Effect::Kind::Fmt;
    request.entity = "ov5693_2-0036";
    request.width = 2592;
    request.height = 1944;
    CHECK(match_effect(r, request, &ledger).ok);
}

void driver_records_carry_result_code()
{
    const std::vector<std::string> records = driver_records(reserved_with_result_code());
    const std::vector<std::string> want = {"ctrl ov5693_2-0036 0x980914=0", "ctrl ov5693_2-0036 0x980915=0",
                                           "link ov5693_2-0036:0 ipu3-csi2_0:0 0x1",
                                           "fmt ov5693_2-0036 0 active 0x3007 2592x1944"};
    CHECK(records == want);
}

void replay_counts_listed_records()
{
    Reservation r = reserved_with_result_code();
    const std::vector<std::string> all = driver_records(r);
    Replay full = replay_driver_records(r, all);
    CHECK(full.verdict.ok && full.complete);
    Replay part = replay_driver_records(r, {all[0]});
    CHECK(part.verdict.ok && !part.complete);
    Replay twice = replay_driver_records(r, {all[2], all[2]});
    CHECK(!twice.verdict.ok && twice.verdict.reason == "unlisted-effect");
    Replay other = replay_driver_records(r, {"link ov7251_4-0060:0 ipu3-csi2_1:0 0x1"});
    CHECK(!other.verdict.ok && other.verdict.reason == "unlisted-effect");
}

void media_listing_fails_closed()
{
    char dir[] = "/tmp/book2-lab-media-XXXXXX";
    CHECK(mkdtemp(dir) != nullptr);
    const std::string root = dir;
    auto entry = [&](const char *name, const char *dev) {
        const std::string sub = root + "/" + name;
        CHECK(mkdir(sub.c_str(), 0700) == 0);
        if (dev) {
            FILE *f = std::fopen((sub + "/dev").c_str(), "we");
            CHECK(f != nullptr);
            if (f) {
                std::fputs(dev, f);
                std::fclose(f);
            }
        }
    };
    entry("media0", "250:0\n");
    entry("media1", "250:1\n");
    auto two = list_media_devices(root);
    CHECK(two && two->size() == 2);
    auto named = list_media_entries(root);
    CHECK(named && named->size() == 2);
    for (const auto &[name, minor] : {std::pair<std::string, unsigned>{"media0", 0}, {"media1", 1}})
        CHECK(named && std::any_of(named->begin(), named->end(), [&](const MediaEntry &e) {
                  return e.name == name && e.major == 250 && e.minor == minor;
              }));
    entry("media2", "garbage\n");
    CHECK(!list_media_devices(root).has_value());
    CHECK(!list_media_entries(root).has_value());
    std::remove((root + "/media2/dev").c_str());
    CHECK(!list_media_devices(root).has_value());
    CHECK(!list_media_devices(root + "/missing").has_value());
    for (const char *name : {"media0/dev", "media1/dev", "media0", "media1", "media2"})
        std::remove((root + "/" + name).c_str());
    rmdir(dir);
}

void ipa_maps_report_unbound_mapping()
{
    const BindIpa bind {"/usr/lib/libcamera/ipa/ipa_ipu3.so", makedev(0, 3), 25, 4096, std::string(64, '0')};
    const std::string bound = "7eff6fb37000-7eff6fb4f000 r--p 00000000 00:03 25"
                              "                         /usr/lib/libcamera/ipa/ipa_ipu3.so\n";
    const std::string unrelated = "7eff6fa00000-7eff6fa10000 r--p 00000000 00:03 30 /usr/lib/libcamera.so.0.8\n";
    const std::string other_inode = "7eff6fc00000-7eff6fc10000 r--p 00000000 00:03 26 /usr/lib/libcamera/ipa/ipa_ipu3.so\n";
    const std::string other_path = "7eff6fd00000-7eff6fd10000 r--p 00000000 00:03 25 /tmp/ipa_ipu3.so\n";
    CHECK(classify_ipa_maps(bound + unrelated, bind) == IpaMapping::Bound);
    CHECK(classify_ipa_maps(unrelated, bind) == IpaMapping::Absent);
    CHECK(classify_ipa_maps(bound + other_inode, bind) == IpaMapping::Unbound);
    CHECK(classify_ipa_maps(other_path, bind) == IpaMapping::Unbound);
}

// A refusal before any worker effect may release whether or not the module
// loaded; a known owner also needs the bound module mapped in its worker.
void ipa_route_hold_needs_the_bound_mapping_for_a_known_owner()
{
    CHECK(!ipa_route_hold(false, IpaMapping::Absent));
    CHECK(!ipa_route_hold(false, IpaMapping::Bound));
    CHECK(ipa_route_hold(false, IpaMapping::Unbound) == "ipa-route");
    CHECK(!ipa_route_hold(true, IpaMapping::Bound));
    CHECK(ipa_route_hold(true, IpaMapping::Unbound) == "ipa-route");
    CHECK(ipa_route_hold(true, IpaMapping::Absent) == "ipa-route");
}

void try_format_and_stale_controls_refuse()
{
    v4l2_subdev_format f {};
    f.which = V4L2_SUBDEV_FORMAT_TRY;
    f.format.width = 2592;
    f.format.height = 1944;
    RequestEffect try_fmt = subdev_request_effect(VIDIOC_SUBDEV_S_FMT, &f, "ov5693_2-0036");
    CHECK(!try_fmt.verdict.ok && try_fmt.verdict.reason == "unlisted-effect" && !try_fmt.effect);
    f.which = V4L2_SUBDEV_FORMAT_ACTIVE;
    RequestEffect active = subdev_request_effect(VIDIOC_SUBDEV_S_FMT, &f, "ov5693_2-0036");
    CHECK(active.verdict.ok && active.effect && active.effect->kind == Effect::Kind::Fmt && active.effect->width == 2592);
    v4l2_ext_control ctrl {};
    ctrl.id = 0x980914;
    v4l2_ext_controls cs {};
    cs.which = V4L2_CTRL_WHICH_DEF_VAL;
    cs.count = 1;
    cs.controls = &ctrl;
    CHECK(!subdev_request_effect(VIDIOC_S_EXT_CTRLS, &cs, "ov5693_2-0036").verdict.ok);
    cs.which = V4L2_CTRL_WHICH_CUR_VAL;
    cs.count = 0;
    CHECK(!subdev_request_effect(VIDIOC_S_EXT_CTRLS, &cs, "ov5693_2-0036").verdict.ok);
    cs.count = 1;
    RequestEffect set = subdev_request_effect(VIDIOC_S_EXT_CTRLS, &cs, "ov5693_2-0036");
    CHECK(set.verdict.ok && set.effect && set.effect->controls.size() == 1);
    v4l2_subdev_selection sel {};
    CHECK(subdev_request_effect(VIDIOC_SUBDEV_S_SELECTION, &sel, "ov5693_2-0036").verdict.reason == "unlisted-request");
}

} // namespace

int main()
{
    const std::vector<std::pair<const char *, std::function<void()>>> tests = {
        {"graph_matches_reservation", graph_matches_reservation},
        {"link_state_change_without_version_change_refuses", link_state_change_without_version_change_refuses},
        {"extra_entity_refuses", extra_entity_refuses},
        {"consumed_link_effect_updates_expected_state", consumed_link_effect_updates_expected_state},
        {"link_effects_apply_in_application_order", link_effects_apply_in_application_order},
        {"front_binding_on_wrong_port_refuses", front_binding_on_wrong_port_refuses},
        {"extra_media_device_refuses", extra_media_device_refuses},
        {"effect_reused_refuses", effect_reused_refuses},
        {"ctrl_set_with_extra_control_refuses", ctrl_set_with_extra_control_refuses},
        {"unknown_or_duplicate_record_refuses", unknown_or_duplicate_record_refuses},
        {"serialize_roundtrip", serialize_roundtrip},
        {"libcamera_environment_or_configuration_refuses", libcamera_environment_or_configuration_refuses},
        {"env_override_variants_refuse", env_override_variants_refuse},
        {"configuration_file_refuses", configuration_file_refuses},
        {"worker_report_is_whitelisted", worker_report_is_whitelisted},
        {"guard_verdict_is_printable", guard_verdict_is_printable},
        {"worker_log_bytes_are_escaped", worker_log_bytes_are_escaped},
        {"observer_accepts_complete_log", observer_accepts_complete_log},
        {"observer_without_header_is_unknown", observer_without_header_is_unknown},
        {"observer_requires_one_supervisor_canary", observer_requires_one_supervisor_canary},
        {"observer_rejects_gap_or_second_header", observer_rejects_gap_or_second_header},
        {"observer_requires_count_for_every_granted_node", observer_requires_count_for_every_granted_node},
        {"observer_keeps_specific_reasons", observer_keeps_specific_reasons},
        {"duplicate_live_entity_refuses", duplicate_live_entity_refuses},
        {"duplicate_live_link_refuses", duplicate_live_link_refuses},
        {"contract_graph_duplicate_refuses", contract_graph_duplicate_refuses},
        {"fmt_effect_requires_result_code", fmt_effect_requires_result_code},
        {"request_matches_without_result_code", request_matches_without_result_code},
        {"driver_records_carry_result_code", driver_records_carry_result_code},
        {"replay_counts_listed_records", replay_counts_listed_records},
        {"media_listing_fails_closed", media_listing_fails_closed},
        {"ipa_maps_report_unbound_mapping", ipa_maps_report_unbound_mapping},
        {"ipa_route_hold_needs_the_bound_mapping_for_a_known_owner", ipa_route_hold_needs_the_bound_mapping_for_a_known_owner},
        {"try_format_and_stale_controls_refuse", try_format_and_stale_controls_refuse},
        {"whitespace_line_refuses", whitespace_line_refuses},
    };
    for (const auto &[name, test] : tests) {
        int before = failures;
        test();
        std::printf("%s %s\n", failures == before ? "ok  " : "FAIL", name);
    }
    std::printf("%zu tests, %d failed checks\n", tests.size(), failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
