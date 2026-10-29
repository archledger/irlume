#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure rooted-profile checks. No service, mount or VM is created."""

import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


root = load("root", "measurement-job-root.py")
fixtures = load("root_fixtures", "test-measurement-job-closure.py")
guardian_tests = load("root_guardian_tests", "test-measurement-job-guardian.py")
# Literal, not derived from the module constants, so a reorder or drop is caught.
HIDDEN_PROFILE = (
    "-+/dev/pts",
    "-+/dev/ptmx",
    "-+/dev/shm",
    "-+/dev/mqueue",
    "-+/dev/hugepages",
    "-+/sys/fs/selinux",
    "-+/run/credentials",
    "-+/sys/firmware/efi/efivars",
    "-+/sys/fs/bpf",
    "-+/sys/fs/fuse/connections",
    "-+/sys/fs/pstore",
    "-+/sys/fs/smackfs",
    "-+/sys/kernel/config",
    "-+/sys/kernel/debug",
    "-+/sys/kernel/security",
    "-+/sys/kernel/tracing",
)


def selection():
    manifest, _ = fixtures.manifest()
    manifest["members"].extend(
        {"path": name, "kind": "directory", "mode": 0o500}
        for name in ("bin", "dev", "etc", "proc", "root", "run", "sys", "tmp", "var")
    )
    manifest["python"]["entry"] = "opt/irlume/measurement-job-guardian-native.py"
    next(m for m in manifest["members"] if m["path"] == "opt/irlume/entry.py")[
        "path"
    ] = manifest["python"]["entry"]
    manifest["members"].sort(key=lambda row: row["path"])
    data = root.closure.canonical(manifest)
    plan = {
        "scope": "contained-job-root-plan-v1",
        "run_id": "run-01",
        "uid": 1000,
        "gid": 1000,
        "root": {"path": "/private/runtime", "device": 1, "inode": 10},
        "attempt": {"path": "/private/attempt", "device": 1, "inode": 11},
        "base": {"path": "/private/base.raw", "device": 1, "inode": 12},
        "payload": {"path": "/private/payload.raw", "device": 1, "inode": 13},
        "manifest": {
            "path": "/private/runtime-manifest.json",
            "device": 1,
            "inode": 14,
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "launcher": {
            "path": "/usr/bin/bootstrap",
            "sha256": next(
                m["sha256"]
                for m in manifest["members"]
                if m["path"] == "usr/bin/bootstrap"
            ),
        },
        "host_namespaces": {
            "pid": 101,
            "user": 102,
            "mnt": 103,
            "net": 104,
            "cgroup": 105,
        },
        "host_api": {
            path: {"device": 2, "inode": 200 + index}
            for index, path in enumerate((*root.DENIED, "/run", "/tmp"))
        },
    }
    return plan, data


def mount_line(number, path, options="ro,nosuid,nodev,noexec", filesystem="tmpfs"):
    return f"{number} 1 0:{number} / {path} {options} - {filesystem} source rw\n"


def witness(plan):
    mounts = [
        ("/", "ro", "ext4"),
        ("/proc", "rw,nosuid,nodev,noexec", "proc"),
        ("/dev", "ro,nosuid,noexec", "tmpfs"),
        ("/sys", "ro,nosuid,nodev,noexec", "sysfs"),
        ("/sys/fs/cgroup", "ro,nosuid,nodev,noexec", "cgroup2"),
        ("/run", "rw,nosuid,nodev,noexec", "tmpfs"),
        ("/tmp", "rw,nosuid,nodev,noexec", "tmpfs"),
        (root.ATTEMPT, "rw,nosuid,nodev,noexec", "ext4"),
    ]
    mounts += [
        (p, "ro,nosuid,nodev,noexec", "ext4")
        for p in (
            "/run/irlume/base.raw",
            "/run/irlume/payload.raw",
            "/run/irlume/runtime-manifest.json",
            f"/run/user/{plan['uid']}/bus",
        )
    ]
    return {
        "root": {"device": 1, "inode": 10},
        "namespaces": {"pid": 201, "user": 202, "mnt": 203, "net": 204, "cgroup": 105},
        "uid_map": b"      1000       1000          1\n",
        "gid_map": b"      1000       1000          1\n",
        "status": b"Name:\tpython3\nPid:\t1\nPPid:\t0\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNStgid:\t1\nNSpid:\t1\nThreads:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        "fds": (0, 1, 2),
        "denied": dict.fromkeys((*root.DENIED, *root.KERNEL_DENIED)),
        "dev_log": None,
        "mountinfo": "".join(
            mount_line(i + 1, *row) for i, row in enumerate(mounts)
        ).encode(),
        "tmpfs": {
            path: {"device": 4, "inode": i + 500, "mode": mode, "bytes": 16 * 1024**2}
            for i, (path, mode) in enumerate((("/run", 0o40755), ("/tmp", 0o41777)))
        },
        "run_entries": (
            "/run/irlume",
            root.ATTEMPT,
            "/run/irlume/base.raw",
            "/run/irlume/payload.raw",
            "/run/irlume/runtime-manifest.json",
            "/run/user",
            "/run/user/1000",
            "/run/user/1000/bus",
        ),
        "os_release": None,
        "started_ns": 100,
        "finished_ns": 200,
    }


class ProfileTests(unittest.TestCase):
    def test_plan_scope_is_checked_without_object_equality(self):
        class Scope:
            def __eq__(self, other):
                raise AssertionError("untrusted scope equality")

        plan, _ = selection()
        plan["scope"] = Scope()
        with self.assertRaises(ValueError):
            root.check_plan(plan)

    def test_root_properties_roundtrip_real_wire_without_connecting_to_a_bus(self):
        import jeepney

        self.assertEqual(jeepney.__version__, "0.9.0")
        plan, _ = selection()
        entries = root.wire_properties(plan)
        address = jeepney.DBusAddress(
            "/org/freedesktop/systemd1",
            bus_name="org.freedesktop.systemd1",
            interface="org.freedesktop.systemd1.Manager",
        )
        message = jeepney.new_method_call(
            address,
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            ("test.service", "fail", entries, []),
        )
        wire = message.serialise(serial=1)
        parser = jeepney.Parser()
        for offset in range(0, len(wire), 7):
            parser.add_data(wire[offset : offset + 7])
        decoded = parser.get_next_message()
        self.assertIsNotNone(decoded)
        observed = dict(decoded.body[2])
        observed.update(PrivateUsers=("b", True), ProtectControlGroupsEx=("s", "yes"))
        self.assertIsNone(root.check_properties(observed, plan))
        self.assertIsNone(parser.get_next_message())

    def test_fixed_inert_profile_preserves_limits_and_omits_kvm(self):
        plan, data = selection()
        spec = root.guardian.Specification(**guardian_tests.specification()._asdict())
        props = root.service_properties(spec, plan, data)
        for key, value in root.guardian.service_properties(spec).items():
            self.assertEqual(props[key], value)
        self.assertEqual(props["PrivateUsersEx"], "self")
        self.assertEqual(
            (props["PrivatePIDs"], props["ProcSubset"], props["ProtectProc"]),
            ("yes", "pid", "invisible"),
        )
        self.assertIs(props["ProtectControlGroups"], True)
        self.assertIs(props["BindLogSockets"], False)
        self.assertEqual(props["DeviceAllow"], ())
        self.assertEqual(
            props["BindPaths"], (("/private/attempt", "/run/irlume/attempt", False, 0),)
        )
        self.assertEqual(props["InaccessiblePaths"], HIDDEN_PROFILE)
        self.assertFalse(
            any(p.startswith("-+/proc/") for p in props["InaccessiblePaths"])
        )
        self.assertEqual(props["ProtectHome"], "read-only")
        self.assertIs(props["ProtectKernelLogs"], True)
        self.assertEqual(
            (type(props["RestrictNamespaces"]), props["RestrictNamespaces"]), (int, 0)
        )
        self.assertEqual(
            root.entry_argv(plan, "c" * 64),
            (
                "/usr/bin/bootstrap",
                "--guardian",
                "/run/irlume/attempt/guardian-config.json",
                "c" * 64,
            ),
        )

    def test_plan_rejects_aliases_overlap_bad_types_and_unknown_fields(self):
        plan, _ = selection()
        for key, value in (("uid", True), ("gid", 0), ("extra", 1), ("scope", "v1")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_plan(dict(plan, **{key: value}))
        for path in (
            "/",
            "/private//base",
            "/private/../base",
            "/private/./base",
            "/bad\npath",
            "/a/",
            "/é",
        ):
            bad = copy.deepcopy(plan)
            bad["base"]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_plan(bad)
        for key in ("base", "payload", "manifest", "root"):
            bad = copy.deepcopy(plan)
            bad[key]["path"] = plan["attempt"]["path"] + "/nested"
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_plan(bad)
        bad = copy.deepcopy(plan)
        bad["base"]["inode"] = plan["payload"]["inode"]
        with self.assertRaises(ValueError):
            root.check_plan(bad)

    def test_selection_must_bind_fixed_entry_bootstrap_hash_and_no_api_code(self):
        plan, data = selection()
        root.check_selection(plan, data)
        for mutate in (
            lambda m: m["python"].update(entry="usr/bin/bootstrap"),
            lambda m: m.update(bootstrap="usr/bin/python3"),
            lambda m: m["members"].append(
                {"path": "run", "kind": "directory", "mode": 0o500}
            ),
        ):
            manifest = root.closure.decode_manifest(data, plan["manifest"]["sha256"])
            mutate(manifest)
            manifest["members"].sort(key=lambda row: row["path"])
            changed = root.closure.canonical(manifest)
            bad = copy.deepcopy(plan)
            bad["manifest"]["sha256"] = hashlib.sha256(changed).hexdigest()
            with self.assertRaises(ValueError):
                root.check_selection(bad, changed)
        with self.assertRaises(ValueError):
            root.check_selection(plan, data + b" ")

    def test_typed_readback_rejects_coercion_missing_and_unsafe_values(self):
        plan, _ = selection()
        variants = {
            key: (root.PROPERTY_TYPES[key], value)
            for key, value in root.root_properties(plan).items()
        }
        variants.update(PrivateUsers=("b", True), ProtectControlGroupsEx=("s", "yes"))
        self.assertIsNone(root.check_properties(variants, plan))
        for key in variants:
            bad = dict(variants)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                root.check_properties(bad, plan)
        for key, value in (
            ("PrivatePIDs", ("b", False)),
            ("PrivateUsers", ("b", 1)),
            ("PrivateUsersEx", ("s", "identity")),
            ("PrivateNetwork", ("b", False)),
            ("CapabilityBoundingSet", ("t", False)),
            ("ProtectControlGroupsEx", ("s", "strict")),
            ("BindLogSockets", ("b", True)),
            ("InaccessiblePaths", ("as", tuple("-" + p for p in root.DENIED))),
            ("InaccessiblePaths", ("as", root.DENIED)),
            (
                "BindPaths",
                ("a(ssbt)", (("/private/attempt", root.ATTEMPT, False, True),)),
            ),
            ("BindPaths", ("a(ssbt)", (("/private/attempt", root.ATTEMPT, True, 0),))),
            (
                "BindPaths",
                ("a(ssbt)", (("/private/attempt", root.ATTEMPT, False, 16384),)),
            ),
            ("DeviceAllow", ("a(ss)", (("/dev/kvm", "rw"),))),
            ("TemporaryFileSystem", ("a(ss)", (("/tmp", "rw"),))),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                root.check_properties(dict(variants, **{key: value}), plan)
        # The earlier layout also listed /proc/sys/fs, absent under ProcSubset=pid.
        sysctl = (*HIDDEN_PROFILE[:7], "-+/proc/sys/fs", *HIDDEN_PROFILE[7:])
        swapped = (*HIDDEN_PROFILE[:7], HIDDEN_PROFILE[8], HIDDEN_PROFILE[7])
        swapped += HIDDEN_PROFILE[9:]
        unrooted = tuple(
            "-/sys/kernel/debug" if p == "-+/sys/kernel/debug" else p
            for p in HIDDEN_PROFILE
        )
        for key, value, message in (
            ("PrivatePIDs", ("s", "no"), "effective root property: PrivatePIDs"),
            ("ProcSubset", ("s", "all"), "effective root property: ProcSubset"),
            ("ProcSubset", ("b", True), "root property signature"),
            *(
                ("ProtectProc", ("s", mode), "effective root property: ProtectProc")
                for mode in ("default", "noaccess", "ptraceable")
            ),
            ("ProtectHome", ("s", "no"), "effective root property: ProtectHome"),
            ("ProtectHome", ("s", "yes"), "effective root property: ProtectHome"),
            ("ProtectHome", ("s", "tmpfs"), "effective root property: ProtectHome"),
            ("ProtectHome", ("b", True), "root property signature"),
            (
                "ProtectKernelLogs",
                ("b", False),
                "effective root property: ProtectKernelLogs",
            ),
            (
                "RestrictNamespaces",
                ("t", 2**64 - 1),
                "effective root property: RestrictNamespaces",
            ),
            (
                "RestrictNamespaces",
                ("t", 0x10000000),
                "effective root property: RestrictNamespaces",
            ),
            ("RestrictNamespaces", ("b", True), "root property signature"),
            *(
                (
                    "InaccessiblePaths",
                    ("as", paths),
                    "effective root property: InaccessiblePaths",
                )
                for paths in (HIDDEN_PROFILE[:7], sysctl, swapped, unrooted)
            ),
        ):
            with (
                self.subTest(key=key, value=value),
                self.assertRaisesRegex(ValueError, message),
            ):
                root.check_properties(dict(variants, **{key: value}), plan)

    def test_selection_rejects_internally_valid_but_unselected_entries(self):
        for change in ("entry", "bootstrap-path", "bootstrap-digest"):
            plan, data = selection()
            manifest = root.closure.decode_manifest(data, plan["manifest"]["sha256"])
            if change == "entry":
                for member in manifest["members"]:
                    if member["path"] == manifest["python"]["entry"]:
                        member["path"] = "opt/irlume/other.py"
                manifest["python"]["entry"] = "opt/irlume/other.py"
            elif change == "bootstrap-path":
                manifest["bootstrap"] = "usr/bin/python3"
                plan["launcher"]["sha256"] = next(
                    m["sha256"]
                    for m in manifest["members"]
                    if m["path"] == "usr/bin/python3"
                )
            else:
                plan["launcher"]["sha256"] = "f" * 64
            manifest["members"].sort(key=lambda row: row["path"])
            data = root.closure.canonical(manifest)
            plan["manifest"]["sha256"] = hashlib.sha256(data).hexdigest()
            # Establish that it is valid closure metadata, not an earlier parser failure.
            root.closure.decode_manifest(data, plan["manifest"]["sha256"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                root.check_selection(plan, data)

    def test_root_profile_cannot_switch_the_selected_transaction(self):
        plan, data = selection()
        spec = root.guardian.Specification(
            **guardian_tests.specification(run_id="other")._asdict()
        )
        with self.assertRaises(ValueError):
            root.service_properties(spec, plan, data)


class ReviewCorrectionsTests(unittest.TestCase):
    def test_systemd_os_release_staging_mount_and_symlink_match_source(self):
        plan, _ = selection()
        row = witness(plan)
        stage = "/run/host/.os-release-stage"
        row["run_entries"] += (
            "/run/host",
            stage,
            stage + "/os-release",
            "/run/host/os-release",
        )
        row["mountinfo"] += mount_line(40, stage).encode()
        row["os_release"] = {
            "link_target": ".os-release-stage/os-release",
            "stage_mode": 0o40755,
            "file_mode": 0o100644,
        }
        self.assertIsNone(root.check_mounts(plan, row))
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        for changes in (
            {
                "mountinfo": row["mountinfo"].replace(
                    (stage + " ro").encode(), (stage + " rw").encode()
                )
            },
            {"run_entries": (*row["run_entries"], stage + "/extra")},
            {"os_release": {**row["os_release"], "link_target": "/etc/os-release"}},
            {"os_release": {**row["os_release"], "stage_mode": 0o100644}},
            {"os_release": {**row["os_release"], "file_mode": 0o120777}},
            {"os_release": {**row["os_release"], "file_mode": 0o100755}},
            {
                "os_release": {
                    **row["os_release"],
                    "stage_mode": None,
                    "file_mode": None,
                }
            },
            {
                "mountinfo": b"\n".join(
                    line
                    for line in row["mountinfo"].splitlines()
                    if stage.encode() not in line
                )
                + b"\n"
            },
            {
                "run_entries": tuple(
                    path for path in row["run_entries"] if path != stage + "/os-release"
                )
            },
            {"os_release": None},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **changes), 1000, 250)

    def test_optional_os_release_missing_stage_keeps_only_the_dangling_link(self):
        plan, _ = selection()
        row = witness(plan)
        row["run_entries"] += ("/run/host", "/run/host/os-release")
        row["os_release"] = {
            "link_target": ".os-release-stage/os-release",
            "stage_mode": None,
            "file_mode": None,
        }
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        with self.assertRaises(ValueError):
            root.check_core(
                plan,
                dict(
                    row,
                    mountinfo=row["mountinfo"]
                    + mount_line(40, "/run/host/os-release").encode(),
                ),
                1000,
                250,
            )

    def test_user_manager_maps_only_the_callers_selected_identity(self):
        self.assertIsNone(root.check_id_map(b"1000 1000 1\n", 1000))
        self.assertIsNone(root.check_id_map(b"1001 1001 1\n", 1001))
        with self.assertRaises(ValueError):
            root.check_id_map(b"0 0 1\n1000 1000 1\n", 1000)

    def test_private_propagation_is_explicit_and_typed(self):
        plan, _ = selection()
        self.assertEqual(root.root_properties(plan).get("MountFlags"), 1 << 18)
        variants = dict(root.wire_properties(plan))
        self.assertEqual(variants.get("MountFlags"), ("t", 1 << 18))
        variants.update(PrivateUsers=("b", True), ProtectControlGroupsEx=("s", "yes"))
        for invalid in (("s", "private"), ("t", True), ("t", 0), ("t", 1 << 20)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                root.check_properties(dict(variants, MountFlags=invalid), plan)

    def test_mount_at_denial_target_cannot_also_be_reported_absent(self):
        plan, _ = selection()
        row = witness(plan)
        for path in ("/dev/shm", "/dev/pts", "/run/credentials"):
            self.assertIsNone(row["denied"][path])
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_core(
                    plan,
                    dict(
                        row, mountinfo=row["mountinfo"] + mount_line(40, path).encode()
                    ),
                    1000,
                    250,
                )

    def test_private_propagation_rejects_slave_and_shared_effective_tags(self):
        plan, _ = selection()
        row = witness(plan)
        for tag in ("shared:42", "master:42", "propagate_from:42", "unbindable"):
            changed = row["mountinfo"].replace(
                b" - sysfs ", f" {tag} - sysfs ".encode()
            )
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, mountinfo=changed), 1000, 250)

    def test_inaccessible_ancestor_is_not_silently_converted_to_absence(self):
        plan, _ = selection()
        row = witness(plan)
        row["denied"]["/dev/ptmx"] = {"blocked_by": "/dev/pts"}
        with self.assertRaises(ValueError):
            root.check_core(plan, row, 1000, 250)


class ParserTests(unittest.TestCase):
    def test_exact_maps_allow_distinct_uid_gid_but_no_broad_mapping(self):
        self.assertIsNone(root.check_id_map(b"1001 1001 1\n", 1001))
        for data in (
            b"1001 1001 2\n",
            b"1001 1001 1",
            b"1001 1001 1\r\n",
            b"+1001 1001 1\n",
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                root.check_id_map(data, 1001)

    def test_mountinfo_parses_escaped_spaces_but_rejects_truncation_and_aliases(self):
        self.assertIn(
            "/some path", root.parse_mountinfo(mount_line(1, r"/some\040path").encode())
        )
        for data in (
            mount_line(1, "/").encode() * 2,
            mount_line(1, "/", "ro,rw").encode(),
            mount_line(1, "/").replace("0:1", "0:bad").encode(),
            mount_line(1, "/").replace("ro,nosuid", "ro,ro,nosuid").encode(),
            mount_line(1, "/").encode().rstrip(b"\n"),
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                root.parse_mountinfo(data)

    def test_property_wire_types_reject_malformed_structs_and_integer_ranges(self):
        for variant, kind in (
            (("as", "wrong"), "as"),
            (("a(ss)", [("one",)]), "a(ss)"),
            (("a(ssbt)", [("a", "b", 0, 0)]), "a(ssbt)"),
            (("t", -1), "t"),
            (("t", 2**64), "t"),
            (("s", "a\0b"), "s"),
            (("as", ["a"] * 65), "as"),
            (("s", "a" * 4097), "s"),
        ):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                root.normal_variant(variant, kind)


class CoreTests(unittest.TestCase):
    def test_denial_fallbacks_and_explicit_ptmx_ancestor_are_checked(self):
        plan, _ = selection()
        for mode in (0o10000, 0o60000, 0o140000):
            row = witness(plan)
            row["denied"]["/proc/kcore"] = {"device": 3, "inode": 501, "mode": mode}
            self.assertIsNone(root.check_core(plan, row, 1000, 250))
        row = witness(plan)
        row["denied"]["/dev/pts"] = {"device": 3, "inode": 502, "mode": 0o40000}
        row["denied"]["/dev/ptmx"] = {
            "device": 3,
            "inode": 503,
            "mode": 0o120777,
            "target": "pts/ptmx",
            "blocked_by": "/dev/pts",
        }
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        for change in (
            "missing-parent",
            "readable-parent",
            "wrong-target",
            "host-link",
            "link-mount",
        ):
            bad = copy.deepcopy(row)
            if change == "missing-parent":
                bad["denied"]["/dev/pts"] = None
            elif change == "readable-parent":
                bad["denied"]["/dev/pts"]["mode"] |= 0o700
            elif change == "wrong-target":
                bad["denied"]["/dev/ptmx"]["target"] = "/outside"
            elif change == "host-link":
                bad["denied"]["/dev/ptmx"].update(plan["host_api"]["/dev/ptmx"])
            else:
                bad["mountinfo"] += mount_line(90, "/dev/ptmx").encode()
            with self.subTest(change=change), self.assertRaises(ValueError):
                root.check_core(plan, bad, 1000, 250)

    def test_core_match_returns_no_qualification_or_authority(self):
        plan, _ = selection()
        self.assertIsNone(root.check_core(plan, witness(plan), 1000, 250))

    def test_later_deadline_cannot_revive_expired_startup_observations(self):
        plan, _ = selection()
        with self.assertRaises(ValueError):
            root.check_core(plan, witness(plan), 7_000_000_100, 6_000_000_100)

    def test_namespaces_root_and_identity_maps_are_independently_checked(self):
        plan, _ = selection()
        row = witness(plan)
        # Only the cgroup namespace stays the host's; PrivatePIDs= gives G its own.
        self.assertNotEqual(row["namespaces"]["pid"], plan["host_namespaces"]["pid"])
        for key in root.NAMESPACES:
            bad = copy.deepcopy(row)
            bad["namespaces"][key] = (
                plan["host_namespaces"][key] if key != "cgroup" else 999
            )
            with (
                self.subTest(namespace=key),
                self.assertRaisesRegex(ValueError, "rooted namespace mismatch: " + key),
            ):
                root.check_core(plan, bad, 1000, 250)
        for key, value in (
            ("root", {"device": 1, "inode": 99}),
            ("uid_map", b"0 0 4294967295\n"),
            ("gid_map", b"1000 1001 1\n"),
            ("uid_map", b"0 0 1\n1000 1000 1\n1000 1000 1\n"),
            ("fds", (0, 1, 2, 9)),
            ("fds", (0, 1, True)),
            ("fds", (0, 1)),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **{key: value}), 1000, 250)

    def test_process_caps_privileges_ids_threads_and_duplicate_fields_refuse(self):
        plan, _ = selection()
        row = witness(plan)
        for before, after in (
            (b"Threads:\t1", b"Threads:\t2"),
            (b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
            (b"Uid:\t1000", b"Uid:\t0"),
            (b"Gid:\t1000", b"Gid:\t0"),
            *[
                (cap + b":\t0000000000000000", cap + b":\t0000000000000001")
                for cap in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb")
            ],
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                root.check_core(
                    plan,
                    dict(row, status=row["status"].replace(before, after)),
                    1000,
                    250,
                )
        with self.assertRaises(ValueError):
            root.check_core(
                plan, dict(row, status=row["status"] + b"Threads:\t1\n"), 1000, 250
            )

    def test_status_requires_seccomp_filter_mode(self):
        plan, _ = selection()
        row = witness(plan)
        self.assertIn(b"\nSeccomp:\t2\n", row["status"])
        self.assertIsNone(root.check_status(row["status"], 1000, 1000))
        for after in (b"Seccomp:\t0\n", b"Seccomp:\t1\n", b""):
            status = row["status"].replace(b"Seccomp:\t2\n", after)
            with self.subTest(after=after):
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_status(status, 1000, 1000)
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_core(plan, dict(row, status=status), 1000, 250)

    def test_status_requires_the_pid_namespace_init(self):
        plan, _ = selection()
        row = witness(plan)
        for before, after in (
            (b"Pid:\t1\n", b"Pid:\t4242\n"),
            (b"Pid:\t1\n", b""),
            (b"PPid:\t0\n", b"PPid:\t1\n"),
            (b"PPid:\t0\n", b""),
            # A host-visible proc lists every namespace level of the PID.
            (b"NSpid:\t1\n", b"NSpid:\t4242\t1\n"),
            (b"NSpid:\t1\n", b"NSpid:\t4242\n"),
            (b"NSpid:\t1\n", b""),
        ):
            status = row["status"].replace(before, after)
            self.assertNotEqual(status, row["status"])
            with self.subTest(before=before, after=after):
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_status(status, 1000, 1000)
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_core(plan, dict(row, status=status), 1000, 250)

    def test_denied_nodes_cannot_be_readable_or_host_backed(self):
        plan, _ = selection()
        row = witness(plan)
        for path in root.DENIED:
            for node in (
                {"device": 3, "inode": 300, "mode": 0o40755},
                {**plan["host_api"][path], "mode": 0o40000},
            ):
                bad = copy.deepcopy(row)
                bad["denied"][path] = node
                with self.subTest(path=path, node=node), self.assertRaises(ValueError):
                    root.check_core(plan, bad, 1000, 250)
        with self.assertRaises(ValueError):
            root.check_core(
                plan,
                dict(row, dev_log={"device": 3, "inode": 400, "mode": 0o140666}),
                1000,
                250,
            )

    def test_mounts_refuse_writable_sys_cgroup_shadow_journal_or_missing_bind(self):
        plan, _ = selection()
        row = witness(plan)
        for path in ("/", "/sys", "/sys/fs/cgroup", "/run/irlume/base.raw"):
            bad = row["mountinfo"].replace(
                f" {path} ro".encode(), f" {path} rw".encode()
            )
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, mountinfo=bad), 1000, 250)
        for path in (
            "/usr/lib",
            "/run/systemd/journal/socket",
            "/dev/shm/escape",
            "/sys/unknown",
            "/run/irlume/attempt/nested",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_core(
                    plan,
                    dict(
                        row, mountinfo=row["mountinfo"] + mount_line(40, path).encode()
                    ),
                    1000,
                    250,
                )
        bad = (
            b"\n".join(
                line
                for line in row["mountinfo"].splitlines()
                if b"base.raw" not in line
            )
            + b"\n"
        )
        with self.assertRaises(ValueError):
            root.check_core(plan, dict(row, mountinfo=bad), 1000, 250)

    def test_tmpfs_and_run_contents_are_bounded_and_private(self):
        plan, _ = selection()
        row = witness(plan)
        for path in ("/run", "/tmp"):
            for changes in (
                plan["host_api"][path],
                {"bytes": 17 * 1024**2},
                {"mode": 0o40777},
            ):
                bad = copy.deepcopy(row)
                bad["tmpfs"][path].update(changes)
                with (
                    self.subTest(path=path, changes=changes),
                    self.assertRaises(ValueError),
                ):
                    root.check_core(plan, bad, 1000, 250)
        with self.assertRaises(ValueError):
            root.check_core(
                plan,
                dict(row, run_entries=(*row["run_entries"], "/run/unknown")),
                1000,
                250,
            )

    def test_deadlines_and_bounded_proc_parsers_fail_closed(self):
        plan, _ = selection()
        row = witness(plan)
        for changes, deadline, now in (
            ({}, 250, 250),
            ({"finished_ns": 1001}, 1000, 1200),
            ({"started_ns": 201}, 1000, 250),
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **changes), deadline, now)
        for key, bad in (
            ("uid_map", b"0 0 1\n" * 17),
            ("gid_map", b"9" * 4097),
            ("status", b"9" * 65537),
            ("mountinfo", b"9" * (1024**2 + 1)),
            ("mountinfo", row["mountinfo"] + b"broken"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **{key: bad}), 1000, 250)

    def test_effective_mount_flags_types_and_propagation_are_not_just_names(self):
        plan, _ = selection()
        row = witness(plan)
        for before, after in (
            (b"/run rw,nosuid,nodev,noexec", b"/run rw,nosuid,nodev"),
            (b"/tmp rw,nosuid,nodev,noexec", b"/tmp rw,nosuid,noexec"),
            (b" - cgroup2 ", b" - tmpfs "),
            (b"/dev ro,nosuid,noexec", b"/dev rw,nosuid,noexec"),
            (b" - sysfs ", b" shared:42 - sysfs "),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                root.check_core(
                    plan,
                    dict(row, mountinfo=row["mountinfo"].replace(before, after)),
                    1000,
                    250,
                )

    def test_optional_denial_and_kernel_mounts_have_explicit_negative_controls(self):
        plan, _ = selection()
        row = witness(plan)
        for i, path in enumerate((*root.DENIED, *root.KERNEL_DENIED)):
            row["denied"][path] = {"device": 3, "inode": 300, "mode": 0o40000}
            row["mountinfo"] += mount_line(40 + i, path).encode()
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        for path in (*root.DENIED, *root.KERNEL_DENIED, *root.KERNEL_READONLY):
            bad = copy.deepcopy(row)
            if path in bad["denied"]:
                bad["denied"][path]["mode"] = 0o40755
            else:
                bad["mountinfo"] += mount_line(
                    60, path, "rw,nosuid,nodev,noexec"
                ).encode()
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_core(plan, bad, 1000, 250)


if __name__ == "__main__":
    unittest.main()
