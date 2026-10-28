#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Compile-only final link for the private manager entry. Never runs native code."""

import hashlib
import importlib.util
import json
import re
import shutil
import sys
import time
from pathlib import Path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
job = load("entry_job", HERE / "measurement-job.py")
bootstrap = load("entry_bootstrap", HERE / "measurement-fixture-bootstrap.py")
TARGET = "x86_64-unknown-linux-musl"
VERSIONS = {"libc": "0.2.191", "sha2": "0.11.1", "serde_json": "1.0.154"}
FLAGS = [
    "--edition=2021",
    "--target",
    TARGET,
    "--cfg",
    "irlume_hw_evidence",
    "--check-cfg",
    "cfg(irlume_hw_evidence)",
    "--check-cfg",
    "cfg(test)",
    "-Dwarnings",
    "-Wunexpected_cfgs",
    "-Ctarget-feature=+crt-static",
    "-Crelocation-model=static",
    "-Clink-arg=-no-pie",
    "-Copt-level=z",
    "-Cdebuginfo=0",
    "-Clto=off",
]
REPORT_TESTS = (
    "case_inventory_names_every_native_variant_once",
    "case_policy_never_expects_no_job_created",
    "unknown_or_aliased_case_names_refuse",
    "frame_is_length_prefixed_json_and_preserves_complete_report",
    "bounds_and_quarantine_preserve_all_evidence",
    "no_job_does_not_gain_cleanup_facts",
    "encoder_rejects_bad_context_authority_and_invalid_wait",
    "emit_cross_language_corpus",
    "largest_integer_and_bounded_error_arrays_are_lossless",
    "every_context_digest_uuid_and_zero_epoch_is_checked",
)
RUNTIME_TESTS = (
    "confirmation_clock_failure_or_expiry_keeps_owner_without_retry",
    "quarantine_confirmation_follows_finalization_and_never_failed_reporting",
    "jobs_path_uses_the_native_filesystem_coordinate_system",
    "report_preparation_is_after_native_and_epipe_retains_quarantine",
    "report_preparation_failure_and_overrun_never_release_quarantine",
    "original_kernel_disposal_preserves_report_fd_and_late_failure_custody",
    "startup_failure_or_expiry_never_calls_execute",
    "missing_completion_budget_cannot_restart_finalization",
    "partial_writes_complete_but_zero_and_infinite_retry_refuse",
    "post_native_clock_and_encoding_failure_hold_quarantine",
    "expired_clean_return_retains_unclosed_sentinel_for_process_exit",
    "request_decodes_exact_fixed_protocol_and_keeps_reservation",
    "request_rejects_unbounded_unknown_and_noncanonical_fields",
    "preflight_requires_exact_process_and_descriptor_roles",
    "preflight_requires_shared_namespaces_exact_objects_and_empty_domain",
    "missing_admission_or_mismatched_input_never_invokes_native",
    "clean_finalization_closes_once_then_reports_within_same_budget",
    "finalization_failures_and_overruns_cannot_return_success",
    "quarantined_owner_survives_every_post_native_failure",
    "process_status_parser_requires_unique_complete_numeric_fields",
)


def make_roots(root, runtime=None):
    folder = root / "crates/irlume-common/examples/measurement_job_fixture"
    runtime = runtime or folder / "runtime.rs"
    header = "// SPDX-License-Identifier: GPL-3.0-or-later\n// Copyright the irlume contributors.\n"
    shared = "".join(
        f"#[path={json.dumps(str(path))}] pub mod {name};\n"
        for name, path in (
            ("kernel", folder / "kernel.rs"),
            ("report", folder / "report.rs"),
            ("runtime", runtime),
        )
    )
    native = "#![no_main]\n" + header + shared
    native += f"#[path={json.dumps(str(folder / 'sys.rs'))}] pub mod sys;\n"
    native += """/// # Safety
/// Called by the pinned C runtime with valid process arguments.
#[no_mangle]
pub unsafe extern "C" fn main(argc: i32, argv: *const *const libc::c_char) -> i32 {
    // SAFETY: C supplied the arguments; no protected boot admission is present.
    unsafe { runtime::native::irlume_job_runtime_entry(argc, argv, None) }
}
"""
    return native, header + shared


def select_dependencies(rows, output, versions=VERSIONS):
    finished = [r for r in rows if r.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True:
        raise ValueError("dependency build incomplete")
    expected = output.resolve() / TARGET / "release"
    result = {}
    for name, version in versions.items():
        matches = [
            r
            for r in rows
            if r.get("reason") == "compiler-artifact"
            and r.get("package_id") == bootstrap.package_id(name, version)
            and r.get("target", {}).get("name") == name
            and r.get("target", {}).get("kind") == ["lib"]
            and r.get("profile", {}).get("test") is False
        ]
        if len(matches) != 1 or matches[0].get("fresh") is not False:
            raise ValueError("ambiguous, missing or reused dependency")
        files = [Path(f) for f in matches[0]["filenames"] if f.endswith(".rlib")]
        if len(files) != 1:
            raise ValueError("ambiguous dependency output")
        try:
            file = files[0].resolve(strict=True)
        except OSError as error:
            raise ValueError("missing dependency") from error
        if file.parent not in (expected, expected / "deps"):
            raise ValueError("dependency outside output")
        result[name] = {
            "path": str(file),
            "sha256": hashlib.sha256(job.build_bytes(file)).hexdigest(),
        }
    return result


def check_link(data, symbols, dep_info, sources):
    bootstrap.static_elf(data)
    for symbol in (
        "main",
        "irlume_job_runtime_entry",
        "measurement_job_runtime::sys::run",
        "measurement_job_runtime::kernel::run_reserved",
    ):
        if (
            re.search(
                r"^[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[Tt]\s+" + re.escape(symbol) + r"$",
                symbols,
                re.MULTILINE,
            )
            is None
        ):
            raise ValueError("missing defined entry symbol: " + symbol)
    dependencies = set(dep_info.replace("\\\n", " ").split())
    if not all(str(path) in dependencies for path in sources):
        raise ValueError("native source absent from dep-info")


def check_startup_map(mapping, directory):
    names = ("crt1.o", "crti.o", "crtbegin.o", "crtend.o", "crtn.o")
    loaded = {
        line[5:]
        for line in mapping.splitlines()
        if line.startswith("LOAD ") and Path(line[5:]).name in names
    }
    if loaded != {str(directory / name) for name in names}:
        raise ValueError("startup objects differ from the pinned toolchain")


class RuntimeBuild(job.BuildSession):
    def __init__(self, output):
        super().__init__(output)
        self.inspection_tools = {}
        self.native = self.path / "manager"

    def direct_command(self, command):
        allowed = {
            "nm": ["-S", "-C", str(self.native)],
            "readelf": ["-h", "-l", "-d", "-n", str(self.native)],
            "cc": ["--version"],
            "ld": ["--version"],
        }
        for role, tool in self.inspection_tools.items():
            if command == [tool, *allowed[role]]:
                return command
        return super().direct_command(command)

    def pin_dependencies(self, artifacts):
        flags = []
        for name, value in artifacts.items():
            self.pins.add(value["path"])
            if self.pins.hashes[value["path"]] != value["sha256"]:
                raise RuntimeError("dependency changed during adoption")
            flags += ["--extern", name + "=" + value["path"]]
        return flags

    def build(self):
        for filename in (
            Path(__file__).resolve(),
            HERE / "test-build-measurement-job-runtime.py",
        ):
            self.pins.add(str(filename))
        for role in ("cc", "ld", "nm", "readelf"):
            found = shutil.which(role)
            if found is None:
                raise RuntimeError("missing build tool: " + role)
            tool = str(Path(found).resolve(strict=True))
            job.safe_path(tool)
            self.inspection_tools[role] = tool
            if tool not in self.pins.hashes:
                self.pins.add(tool)
        for role in ("cc", "ld"):
            self.command(role + "-version", [self.inspection_tools[role], "--version"])
        identity = self.command(
            "compiler-version", [self.rustup, "run", "1.88.0", "rustc", "-vV"]
        )
        if not identity.stdout.startswith("rustc 1.88.0 "):
            raise RuntimeError("wrong compiler version")
        sysroot = self.command(
            "sysroot", [self.rustup, "run", "1.88.0", "rustc", "--print", "sysroot"]
        ).stdout.strip()
        library = Path(sysroot) / "lib/rustlib" / TARGET / "lib"
        startup = [*library.glob("*.rlib"), *(library / "self-contained").glob("*")]
        if not startup or not (library / "self-contained/crt1.o").is_file():
            raise RuntimeError("missing static startup objects")
        for file in startup:
            if file.is_file() and str(file) not in self.pins.hashes:
                self.pins.add(str(file))
        output = self.path / "dependencies"
        environment = dict(
            self.environment,
            CARGO_TARGET_DIR=str(output),
            CARGO_PROFILE_RELEASE_LTO="false",
            RUSTFLAGS="-Ctarget-feature=+crt-static -Crelocation-model=static -Clink-arg=-no-pie -Copt-level=z -Clto=off",
        )
        command = [
            self.cargo,
            "+1.88.0",
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            TARGET,
            "--message-format=json",
        ]
        for name, version in VERSIONS.items():
            command += ["-p", name + "@" + version]
        result = self.command("entry-dependencies", command, env=environment)
        artifacts = select_dependencies(
            [json.loads(line) for line in result.stdout.splitlines()], output
        )
        directories = [output / TARGET / "release/deps", output / "release/deps"]
        for directory in directories:
            directory.mkdir(exist_ok=True)
        self.dependency_inputs = job.FrozenDirectories(directories)
        search = ["-Ldependency=" + str(d) for d in directories]
        search += self.pin_dependencies(artifacts)
        native, pure = make_roots(self.root)
        native_root = self.generated("manager-root.rs", native.encode())
        pure_root = self.generated("manager-tests.rs", pure.encode())
        folder = self.root / "crates/irlume-common/examples/measurement_job_fixture"
        control_native = self.generated(
            "native-control.rs",
            (folder / "runtime_native.rs").read_bytes()
            + b'\ncompile_error!("r2b-native-active-control");\n',
        )
        runtime = (folder / "runtime.rs").read_text()
        marker = '#[path = "runtime_native.rs"]'
        if runtime.count(marker) != 1:
            raise RuntimeError("native module boundary changed")
        controlled = self.generated(
            "runtime-control.rs",
            runtime.replace(
                marker, f"#[path={json.dumps(str(control_native))}]"
            ).encode(),
        )
        control, _ = make_roots(self.root, controlled)
        control_root = self.generated("manager-control-root.rs", control.encode())
        for file in (native_root, pure_root, control_native, controlled, control_root):
            self.pins.add(str(file))
        common = [*FLAGS, *search, "-Clinker=" + self.inspection_tools["cc"]]
        native_args = [
            str(native_root),
            *common,
            "--crate-name",
            "measurement_job_runtime",
            "-Clink-dead-code=yes",
            "-Cpanic=abort",
        ]
        mapping, dependencies = self.path / "manager.map", self.path / "manager.d"
        self.command(
            "native-final-link",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustc",
                *native_args,
                "-Clink-arg=-Wl,-Map=" + str(mapping),
                f"--emit=link={self.native},dep-info={dependencies}",
            ],
        )
        self.command(
            "native-clippy",
            [
                self.rustup,
                "run",
                "1.88.0",
                "clippy-driver",
                *native_args,
                *bootstrap.LINTS,
                "--emit=metadata",
                "-o",
                str(self.path / "native.rmeta"),
            ],
        )
        self.command(
            "native-doc",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustdoc",
                *native_args,
                "--document-private-items",
                "--out-dir",
                str(self.path / "docs"),
            ],
        )
        rejected = self.command(
            "native-active-control",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustc",
                str(control_root),
                *common,
                "--emit=metadata",
                "-o",
                str(self.path / "bad.rmeta"),
            ],
            failure=True,
        )
        if "r2b-native-active-control" not in rejected.stderr:
            raise RuntimeError("inactive native control")
        binary = self.path / "pure-tests"
        test_args = [str(pure_root), *common, "--test"]
        self.command(
            "pure-compile",
            [self.rustup, "run", "1.88.0", "rustc", *test_args, "-o", str(binary)],
        )
        self.command(
            "pure-clippy",
            [
                self.rustup,
                "run",
                "1.88.0",
                "clippy-driver",
                *test_args,
                *bootstrap.LINTS,
                "--emit=metadata",
                "-o",
                str(self.path / "pure.rmeta"),
            ],
        )
        self.allowed.add(
            str(binary), "pure", hashlib.sha256(job.build_bytes(binary)).hexdigest()
        )
        tests = self.command("pure-tests", [str(binary), "--nocapture"], safe=True)
        expected = tuple(n for n in job.RUST_TESTS if n.startswith("kernel::"))
        expected += tuple("report::tests::" + n for n in REPORT_TESTS)
        expected += tuple("runtime::tests::" + n for n in RUNTIME_TESTS)
        names = tuple(re.findall(r"^test (\S+) \.\.\. ok$", tests.stdout, re.MULTILINE))
        job.check_suite(
            expected,
            names,
            success=tests.returncode == 0,
            skipped=0 if "0 ignored" in tests.stdout else 1,
        )
        data = job.build_bytes(self.native, 16 * 1024 * 1024)
        symbols = self.command(
            "native-symbols",
            [self.inspection_tools["nm"], "-S", "-C", str(self.native)],
        ).stdout
        self.command(
            "native-elf",
            [
                self.inspection_tools["readelf"],
                "-h",
                "-l",
                "-d",
                "-n",
                str(self.native),
            ],
        )
        sources = [
            folder / name
            for name in (
                "kernel.rs",
                "sys.rs",
                "report.rs",
                "runtime.rs",
                "runtime_native.rs",
            )
        ]
        check_link(data, symbols, dependencies.read_text(), sources)
        check_startup_map(job.build_bytes(mapping).decode(), library / "self-contained")
        try:
            self.allowed.check(str(self.native), hashlib.sha256(data).hexdigest())
        except ValueError:
            pass
        else:
            raise RuntimeError("native executable entered execution allowlist")
        self.check()
        self.output.save(
            "finished",
            {
                "complete": True,
                "mode": "entry-link-only",
                "boot_admission": "unavailable",
                "native_executed": False,
                "runtime_qualified": False,
                "native_authorized": False,
                "full_contract_proven": False,
                "tests": len(names),
                "commands": len(self.records),
                "native_sha256": hashlib.sha256(data).hexdigest(),
                "native_bytes": len(data),
                "source_pins": self.pins.hashes,
                "artifacts": artifacts,
                "dependency_directories": self.dependency_inputs.hashes,
                "map_sha256": hashlib.sha256(job.build_bytes(mapping)).hexdigest(),
            },
        )
        self.check()


def build_entry(output, *, _context=RuntimeBuild):
    context = _context(output)
    try:
        context.start()
        context.build()
    except BaseException as error:
        try:
            context.failed(error)
        except job.FINALIZATION_FAILURES as secondary:
            error.add_note("receipt failure: " + str(secondary))
        try:
            context.close()
        except job.FINALIZATION_FAILURES as secondary:
            error.add_note("output close failure: " + str(secondary))
        raise
    else:
        context.close()
        if time.monotonic() >= context.deadline:
            raise TimeoutError("entry build deadline after close")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--build":
        raise SystemExit("usage: build-measurement-job-runtime.py --build FRESH_OUTPUT")
    build_entry(sys.argv[2])
