# Book 2 Discovery Proof Review Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the 14 minor findings the B03 whole-branch review deferred, then prove B03 again at the new head.

**Architecture:** Checks the review found lenient move into `lab/lab_contract`, where host tests reach them, and the guard and supervisor call them. Two driver pause points let guest cases change the IPA module or the graph between two discovery effects. The build stops finding or linking any host library outside an allowlist.

**Tech Stack:** The pins and tools of the [B03 plan][b03].

**Spec:** [Supervised capture lab design][spec], row B03, through the [B03 plan][b03] and its review findings below.

## Global Constraints

- Every constraint of the [B03 plan][b03] still holds: guest only, no device, host policy, product code or reporter contact.
- Each fix lands with a check that fails first. A fix that no test can reach gets a ledger ruling that says why.
- B03 passes again only when every case passes twice from a `git archive` export of one signed commit, and the five B01/B02 cases pass on an image built from the same export.

## Review Focus

- A pause that is never resumed: the paused thread must resume on its own timeout and record it, inside the 180 s guest limit.
- A worker's TRY format or stale control set after a refusal: refused, never admitted silently.
- A media entry that cannot be parsed: unknown, never skipped.
- A second IPA file mapped beside the bound one: reported, so the receipt fails.
- A contract line of spaces: refused, not undefined behavior.

## Findings

| Id | Finding | Task |
| --- | --- | --- |
| M1 | Trusted outcome matches formats on entity, pad and size, not code | 2 |
| M2 | Graph comparisons use sets, so duplicate records collapse | 1 |
| M3 | A whitespace-only contract line indexes an empty token list | 1 |
| M4 | The supervisor skips media entries it cannot parse | 3 |
| M5 | An effect is not refused before discovery admission | 4 |
| M6 | Configuration file paths are hard-coded | 4 |
| M7 | `IPA_NOT_MAPPED` cannot report a second mapping | 3 |
| M8 | The verifier's outcome rule ignores `link-failed` | 4 |
| M9 | `SIM_CONTROLS_PASS` prints even when a check failed | 4 |
| M10 | No case refuses an unlisted control or format, refuses in the IPA factory, replaces the graph between effects, or probes the worker's device cgroup | 6 |
| M11 | CMake finds a host libyuv; the NEEDED gate is a denylist | 5 |
| M12 | The guard admits TRY formats that the classifier counts as unlisted | 3 |
| M13 | The lab image ships the unused isolated IPA proxy | 5 |
| M14 | `.superpowers/` is not ignored | ruling: a repository-wide `.gitignore` change belongs in its own PR |

### Task 1: Contract lines and graph duplicates (M2, M3)

**Files:** `lab/lab_contract.{h,cpp}`, `lab/test_lab_contract.cpp`, `guest/discovery_supervisor.cpp`.

**Interfaces:** Produces `Verdict match_contract_graph(const Reservation &contract, const std::vector<Snapshot> &tops)`, which replaces the supervisor's `graph_matches_contract`. `parse_contract` and `parse_reservation` refuse a line of spaces. `compare_graph` and `match_contract_graph` refuse a repeated live record with reason `graph-duplicate`.

- [ ] Write `whitespace_line_refuses`, `duplicate_live_entity_refuses`, `duplicate_live_link_refuses` and `contract_graph_duplicate_refuses`; run them and watch them fail.
- [ ] Implement, run the host C++ suite, commit `test(research): refuse duplicate graph records and blank contract lines`.

### Task 2: Resulting format codes (M1)

**Files:** `lab/lab_contract.{h,cpp}`, `lab/test_lab_contract.cpp`, `contract/front.contract`, `guest/discovery_supervisor.cpp`.

**Interfaces:** `Effect` gains `uint32_t result_code` for formats. A contract format effect reads `effect fmt <entity> <pad> <code> <W>x<H> <result-code>`. `match_effect` ignores `result_code`, because a request does not carry it. Produces `std::vector<std::string> driver_records(const Reservation &r)`: each listed effect in the driver log's form, with formats as `fmt <entity> <pad> active <result-code> <W>x<H>`. `classify_attempt` compares worker records with it verbatim.

- [ ] Write `fmt_effect_requires_result_code`, `request_matches_without_result_code` and `driver_records_carry_result_code`; watch them fail.
- [ ] Implement; give both `front.contract` format effects result code `0x3007`; run the host suite; commit `test(research): check the resulting format code in trusted outcomes`.

### Task 3: Shared readers that fail closed (M4, M7, M12)

**Files:** `lab/lab_contract.{h,cpp}`, `lab/test_lab_contract.cpp`, `libcamera/lab_guard.cpp`, `guest/discovery_supervisor.cpp`, `run_discovery.py`.

**Interfaces:**
- `std::optional<std::vector<std::pair<unsigned, unsigned>>> list_media_devices(const std::string &bus_dir)` returns nothing when the directory or any `media*` entry's `dev` cannot be read and parsed. The guard's media-set check and the supervisor's listing use it; the supervisor treats nothing as `media-set` or a failed start.
- `enum class IpaMapping { Bound, Unbound, Absent }` and `IpaMapping classify_ipa_maps(std::string_view maps, const BindIpa &bind)`. `Unbound` covers a mapping of the bound path with another device or inode, and the bound device and inode under another path. The supervisor reports `Unbound` as `IPA_MAPPED_UNBOUND`, which no case expects.
- `struct RequestEffect { Verdict verdict; std::optional<Effect> effect; }` and `RequestEffect subdev_request_effect(unsigned long request, const void *arg, const std::string &entity)`. A TRY format, or a control set that is empty or not on current values, refuses `unlisted-effect`. The guard's `admitIoctl` uses it.

- [ ] Write `media_listing_fails_closed`, `ipa_maps_report_unbound_mapping` and `try_format_and_stale_controls_refuse` against versions that keep today's behavior; watch them fail.
- [ ] Implement, wire the guard and supervisor, run the host suite and check the guard compiles with libcamera's flags; commit `test(research): fail closed on unreadable media, extra IPA mappings and TRY formats`.

### Task 4: Guard, supervisor and verifier consistency (M5, M6, M8, M9)

**Files:** `libcamera/lab_guard.cpp`, `guest/discovery_supervisor.cpp`, `run_discovery.py`, `test_run_discovery.py`.

- [ ] M8: write `test_release_after_failed_link_fails`; watch it fail; count `link-failed` as a worker effect.
- [ ] M6: write `test_guard_config_paths_come_from_the_build`, which requires `kConfigFiles` to use `LIBCAMERA_SYSCONF_DIR` and `LIBCAMERA_DATA_DIR` from libcamera's `config.h`; watch it fail; implement. The guest case `ipa-force-isolation` proves the runtime path.
- [ ] M5: `admitEffect` refuses `discovery` unless `admitDiscovery` stored both media descriptors. The pinned call path cannot reach this, so it gets a ruling, a compile check and the full guest set instead of a failing test.
- [ ] M9: `sim_controls` prints `SIM_CONTROLS_PASS` only after all three facts hold, and fails otherwise; the `sim-controls` case proves the passing path.
- [ ] Run both host suites; commit `test(research): keep guard, supervisor and verifier outcomes consistent`.

### Task 5: Build isolation and image contents (M11, M13)

**Files:** `build_discovery_guest.sh`, `test_run_discovery.py`.

- [ ] Write `test_meson_setup_avoids_host_lookups`, `test_needed_gate_is_an_allowlist` and `test_lab_image_drops_isolated_proxy`; watch them fail.
- [ ] Implement:
  - a Meson native file with `cmake = 'false'`, and `-Dforce_fallback_for=libyuv`; the build fails if its setup log reports CMake or libyuv;
  - NEEDED entries limited to `ld-linux-x86-64.so.2`, `libc.so.6`, `libcamera-base.so.0.8`, `libcamera.so.0.8`, `libgcc_s.so.1`, `libgnutls.so.30`, `libm.so.6`, `libstdc++.so.6` and `libyaml-0.so.2`;
  - the lab stage without `usr/libexec/libcamera/ipu3_ipa_proxy`, with the build failing if `lab.list` names a proxy.
- [ ] Run shellcheck and the host suites; commit `build(research): keep host libraries and the isolated proxy out of the lab image`.

### Task 6: Sensitivity cases (M10)

**Files:** `kernel/book2-lab-sim/book2_lab_sim.c`, `guest/discovery_supervisor.cpp`, `contract/expected-effects.txt`, `run_discovery.py`, `test_run_discovery.py`.

**Interfaces:** Driver controls `pause-on-front-link` and `pause-on-front-fmt` arm one pause, after the front sensor's link enable or its active format set. The paused thread records `control paused`, waits for the control `resume` or 20 s, then records `control resumed` or `control pause-timeout`. While it waits for the worker's report, the supervisor polls the effect log every 50 ms, runs the case's action once at `control paused`, then writes `resume`.

| Case | Change | Required result |
| --- | --- | --- |
| `effect-unlisted-ctrl` | test-pattern control removed from the reservation | refused at that control after the flips, `HOLD partial-effects` |
| `effect-unlisted-fmt` | both format effects removed | refused at the first format, after the IPA loads, `HOLD partial-effects` |
| `ipa-replaced-before-factory` | IPA module replaced by a byte-identical copy during the pause after the front link | the factory refuses `ipa-identity` although the preflight admitted, `HOLD partial-effects` |
| `replace-during-discovery` | graph re-registered during the pause after the front format | hold, then `HOLD replaced` |
| `worker-cgroup-sibling` | a root probe inside the worker's device cgroup opens the IR and rear sensor nodes | both refused with `EPERM`; no worker starts |

- [ ] Add the five cases and their effect sections; run them on the Task 5 build and watch the supervisor refuse them as unknown.
- [ ] Implement, rebuild, run the new cases and every existing case; commit `test(research): cover factory, mid-discovery replacement and cgroup refusals`.

### Task 7: Prove, review, record and publish

- [ ] Update the README, then run the exact-head pipeline from an export: both builds, host suites, every case twice, the five B01/B02 cases, shellcheck and the docs gates.
- [ ] Request one independent review of `24c5f27a..HEAD`, which also covers the earlier fix pass; fix confirmed findings with a failing check first.
- [ ] Write a follow-up results record beside the first, archive it immutably and verify the copy by download; the first record stays unchanged.
- [ ] Push to the open pull request, update its Testing section and watch hosted CI.

[spec]: ../specs/2026-11-28-embedded-book2-lab-boundary-design.md
[b03]: 2026-11-28-embedded-book2-discovery-guards.md
