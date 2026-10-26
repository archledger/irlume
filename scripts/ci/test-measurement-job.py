#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Portable private-job input and evidence tests; no fixture execution."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "measurement_job", Path(__file__).with_name("measurement-job.py")
)
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)


def expected():
    return job.Expected(
        "run-01",
        "boot-01",
        41,
        (("normal", "fixture_complete"),),
        tuple(
            (role, f"/private/{role}", str(index) * 64)
            for index, role in enumerate(job.ROLES, 1)
        ),
    )


def profile():
    want = expected()
    return {
        "scope": job.SCOPE,
        "run_id": want.run_id,
        "boot_id": want.boot_id,
        "epoch": want.epoch,
        "cases": [list(case) for case in want.cases],
        "inputs": {
            role: {"path": path, "sha256": digest} for role, path, digest in want.inputs
        },
        "host_loss": {"owner": "test-owner", "mechanism": "external-watchdog"},
        "limits": dict(job.LIMITS),
    }


def evidence():
    want = expected()
    return {
        "scope": job.SCOPE,
        "mode": "model",
        "run_id": want.run_id,
        "boot_id": want.boot_id,
        "epoch": want.epoch,
        "hashes": {role: digest for role, _, digest in want.inputs},
        "native_authorized": False,
        "full_contract_proven": False,
        "complete": True,
        "expected_cases": 1,
        "cases": [
            {
                "id": "normal",
                "epoch": 41,
                "outcome": "fixture_complete",
                "reason": None,
                "cleanup": "complete",
                "total_j_empty": True,
                "fully_reaped": True,
                "consumers": 0,
                "leases_released": True,
                "custody_retained": False,
            }
        ],
    }


class InputTests(unittest.TestCase):
    def test_exact_separately_supplied_expectations(self):
        self.assertEqual(
            job.parse_profile(json.dumps(profile()).encode(), expected()), profile()
        )

    def test_self_selected_hash_cannot_replace_trusted_pin(self):
        value = profile()
        value["inputs"]["payload"]["sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            job.parse_profile(json.dumps(value).encode(), expected())

    def test_unknown_duplicate_and_nonfinite_json(self):
        raw = json.dumps(profile())
        for data in [
            raw[:-1] + ', "scope": "contained-job-lifetime-v1"}',
            raw.replace("41", "NaN"),
            raw[:-1] + ', "authorized": true}',
            "[]",
            "{}{}",
        ]:
            with self.subTest(data=data[:50]), self.assertRaises(ValueError):
                job.parse_profile(data.encode(), expected())

    def test_invalid_identity_types_counts_and_fixed_budgets(self):
        for key, value in [
            ("epoch", True),
            ("epoch", 0),
            ("run_id", "../escape"),
            ("cases", []),
            ("cases", [["normal", "fixture_complete"]] * 2),
            ("cases", [["extra", "fixture_complete"]]),
            ("limits", dict(job.LIMITS, host_seconds=301)),
            ("host_loss", {"owner": "", "mechanism": "external-watchdog"}),
        ]:
            row = dict(profile(), **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                job.parse_profile(json.dumps(row).encode(), expected())

    def test_hash_and_path_grammar_and_no_optional_attachments(self):
        for value in [
            "/private/../payload",
            "relative",
            "/private/a,b",
            "/private/a\n",
        ]:
            row = profile()
            row["inputs"]["payload"]["path"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                job.parse_profile(json.dumps(row).encode(), expected())
        for extra in ["network", "shares", "devices", "extra_args", "qualified"]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                job.parse_profile(
                    json.dumps(dict(profile(), **{extra: []})).encode(), expected()
                )

    def test_untrusted_and_trusted_input_sizes_are_bounded(self):
        with self.assertRaises(ValueError):
            job.parse_profile(b" " * (job.PROFILE_LIMIT + 1), expected())
        for want in [
            expected()._replace(epoch=True),
            expected()._replace(cases=()),
            expected()._replace(inputs=expected().inputs[:-1]),
            expected()._replace(cases=(("x", "fixture_complete"),) * 7),
        ]:
            with self.subTest(want=want), self.assertRaises(ValueError):
                job.parse_profile(json.dumps(profile()).encode(), want)


class EvidenceTests(unittest.TestCase):
    def check(self, row):
        return job.validate_evidence(json.dumps(row).encode(), expected())

    def test_complete_model_is_not_native_authorization(self):
        result = self.check(evidence())
        self.assertTrue(result["model_matched"])
        self.assertFalse(result["accepted"])
        self.assertFalse(result["native_authorized"])
        self.assertFalse(result["full_contract_proven"])

    def test_every_binding_and_nonexact_scalar_is_checked(self):
        for key, value in [
            ("run_id", "old"),
            ("boot_id", "old"),
            ("epoch", 40),
            ("epoch", True),
            ("mode", "kernel"),
            ("scope", "other"),
            ("complete", 1),
            ("expected_cases", True),
            ("expected_cases", 2),
            ("native_authorized", True),
            ("full_contract_proven", True),
            ("hashes", {}),
            ("extra", None),
        ]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(dict(evidence(), **{key: value}))

    def test_missing_duplicate_stale_conflicting_or_unreached_cases_refuse(self):
        for cases in [
            [],
            evidence()["cases"] * 2,
            [dict(evidence()["cases"][0], id="other")],
            [dict(evidence()["cases"][0], epoch=40)],
            [dict(evidence()["cases"][0], outcome="aborted_clean")],
        ]:
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                self.check(dict(evidence(), cases=cases))

    def test_cleanup_and_lease_assertions_are_not_optional(self):
        for key, value in [
            ("total_j_empty", False),
            ("fully_reaped", False),
            ("fully_reaped", 1),
            ("consumers", 1),
            ("consumers", False),
            ("leases_released", False),
            ("custody_retained", True),
            ("reason", "expired"),
            ("cleanup", "incomplete"),
            ("extra", 0),
        ]:
            row = evidence()
            row["cases"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(row)

    def test_duplicate_nested_keys_and_oversized_evidence_refuse(self):
        raw = json.dumps(evidence()).replace(
            '"consumers": 0', '"consumers": 1, "consumers": 0'
        )
        with self.assertRaises(ValueError):
            job.validate_evidence(raw.encode(), expected())
        with self.assertRaises(ValueError):
            job.validate_evidence(b" " * (job.EVIDENCE_LIMIT + 1), expected())

    def test_incomplete_cleanup_retains_custody_in_negative_model(self):
        want = expected()._replace(cases=(("normal", "cleanup_incomplete"),))
        row = evidence()
        row["cases"][0].update(
            outcome="cleanup_incomplete",
            reason="expired",
            cleanup="incomplete",
            total_j_empty=False,
            fully_reaped=False,
            leases_released=False,
            custody_retained=True,
        )
        self.assertTrue(
            job.validate_evidence(json.dumps(row).encode(), want)["model_matched"]
        )
        row["cases"][0]["leases_released"] = True
        with self.assertRaises(ValueError):
            job.validate_evidence(json.dumps(row).encode(), want)

    def test_evidence_does_not_mutate_trusted_expectations(self):
        before = copy.deepcopy(expected())
        self.check(evidence())
        self.assertEqual(expected(), before)


class FilesystemTests(unittest.TestCase):
    def info(self, **updates):
        values = {
            "st_uid": 1000,
            "st_mode": 0o100600,
            "st_size": 3,
            "st_dev": 1,
            "st_ino": 2,
            "st_mtime_ns": 3,
            "st_ctime_ns": 4,
        }
        return SimpleNamespace(**dict(values, **updates))

    def test_fresh_directory_refuses_existing_or_symlink_without_writing(self):
        with (
            mock.patch.object(job, "open_directory", return_value=13),
            mock.patch.object(
                job.os,
                "fstat",
                return_value=SimpleNamespace(st_uid=job.os.getuid(), st_mode=0o40700),
            ),
            mock.patch.object(job.os, "mkdir", side_effect=FileExistsError),
            mock.patch.object(job.os, "open") as opened,
            mock.patch.object(job.os, "close"),
        ):
            with self.assertRaises(FileExistsError):
                job.OwnedOutput.create("/private/run")
            opened.assert_not_called()

    def test_receipt_is_exclusive_nofollow_and_bounded(self):
        root = job.OwnedOutput(13)
        with (
            mock.patch.object(job.os, "open", return_value=14) as opened,
            mock.patch.object(job.os, "write", side_effect=lambda fd, data: len(data)),
            mock.patch.object(job.os, "fsync"),
            mock.patch.object(job.os, "close"),
        ):
            root.save("started", {"accepted": False})
            flags = opened.call_args.args[1]
            self.assertTrue(flags & job.os.O_EXCL)
            self.assertTrue(flags & job.os.O_NOFOLLOW)
            self.assertEqual(opened.call_args.kwargs["dir_fd"], 13)
            with self.assertRaises(ValueError):
                root.save("../escape", {})
            with self.assertRaises(ValueError):
                root.save("failure", {"x": "x" * job.PROFILE_LIMIT})

    def test_directory_walk_rejects_symlinks_and_foreign_writable_ancestors(self):
        for effect in [OSError("symlink"), 14]:
            with (
                self.subTest(effect=effect),
                mock.patch.object(job.os, "getuid", return_value=1000),
                mock.patch.object(job.os, "open", side_effect=[13, effect]) as opened,
                mock.patch.object(job.os, "fstat", return_value=self.info(st_uid=2000)),
                mock.patch.object(job.os, "close") as closed,
            ):
                with self.assertRaises((OSError, ValueError)):
                    job.open_directory("/foreign")
                self.assertTrue(opened.call_args.args[1] & job.os.O_NOFOLLOW)
                closed.assert_any_call(13)

    def test_foreign_output_parent_never_calls_mkdir(self):
        with (
            mock.patch.object(job, "open_directory", return_value=13),
            mock.patch.object(job.os, "getuid", return_value=1000),
            mock.patch.object(job.os, "fstat", return_value=self.info(st_uid=2000)),
            mock.patch.object(job.os, "mkdir") as mkdir,
            mock.patch.object(job.os, "open", return_value=14),
            mock.patch.object(job.os, "close"),
        ):
            with self.assertRaises(ValueError):
                job.OwnedOutput.create("/foreign/run")
            mkdir.assert_not_called()

    def test_new_output_is_private_and_anchored_to_parent_fd(self):
        with (
            mock.patch.object(job, "open_directory", return_value=13),
            mock.patch.object(job.os, "getuid", return_value=1000),
            mock.patch.object(job.os, "fstat", return_value=self.info(st_mode=0o40700)),
            mock.patch.object(job.os, "mkdir") as mkdir,
            mock.patch.object(job.os, "open", return_value=14),
            mock.patch.object(job.os, "close") as close,
        ):
            output = job.OwnedOutput.create("/private/run")
            mkdir.assert_called_once_with("run", 0o700, dir_fd=13)
            self.assertEqual(output.fd, 14)
            close.assert_called_once_with(13)

    def test_new_output_fd_closes_when_validation_raises(self):
        for failure in (OSError("fstat failed"), AssertionError("fstat fault")):
            with (
                self.subTest(failure=failure),
                mock.patch.object(job, "open_directory", return_value=13),
                mock.patch.object(job.os, "getuid", return_value=1000),
                mock.patch.object(
                    job.os, "fstat", side_effect=[self.info(st_mode=0o40700), failure]
                ),
                mock.patch.object(job.os, "mkdir"),
                mock.patch.object(job.os, "open", return_value=14),
                mock.patch.object(job.os, "close") as close,
            ):
                with self.assertRaises(type(failure)) as caught:
                    job.OwnedOutput.create("/private/run")
                self.assertIs(caught.exception, failure)
                self.assertCountEqual(
                    close.call_args_list, [mock.call(14), mock.call(13)]
                )

    def test_new_output_fd_closes_if_parent_close_prevents_transfer(self):
        failure = OSError("parent close failed")

        def close_fd(fd):
            if fd == 13:
                raise failure

        with (
            mock.patch.object(job, "open_directory", return_value=13),
            mock.patch.object(job.os, "getuid", return_value=1000),
            mock.patch.object(job.os, "fstat", return_value=self.info(st_mode=0o40700)),
            mock.patch.object(job.os, "mkdir"),
            mock.patch.object(job.os, "open", return_value=14),
            mock.patch.object(job.os, "close", side_effect=close_fd) as close,
        ):
            with self.assertRaises(OSError) as caught:
                job.OwnedOutput.create("/private/run")
            self.assertIs(caught.exception, failure)
            self.assertCountEqual(close.call_args_list, [mock.call(13), mock.call(14)])

    def test_directory_transfer_guards_child_before_closing_old_fd(self):
        for failure in (
            OSError("close failed"),
            KeyboardInterrupt("close interrupted"),
        ):

            def close_fd(fd, failure=failure):
                if fd == 13:
                    raise failure

            with (
                self.subTest(failure=failure),
                mock.patch.object(job.os, "open", side_effect=[13, 14]),
                mock.patch.object(job.os, "close", side_effect=close_fd) as close,
                mock.patch.object(job.os, "fstat") as fstat,
            ):
                with self.assertRaises(type(failure)) as caught:
                    job.open_directory("/private")
                self.assertIs(caught.exception, failure)
                self.assertEqual(close.call_args_list, [mock.call(13), mock.call(14)])
                fstat.assert_not_called()

    def test_input_transfer_guards_file_before_closing_parent_fd(self):
        for failure in (
            OSError("close failed"),
            KeyboardInterrupt("close interrupted"),
        ):

            def close_fd(fd, failure=failure):
                if fd == 13:
                    raise failure

            with (
                self.subTest(failure=failure),
                mock.patch.object(job, "open_directory", return_value=13),
                mock.patch.object(job.os, "open", return_value=14),
                mock.patch.object(job.os, "close", side_effect=close_fd) as close,
                mock.patch.object(job.os, "fstat") as fstat,
                mock.patch.object(job.os, "read") as read,
            ):
                with self.assertRaises(type(failure)) as caught:
                    job.observe_input("/private/input", limit=10, deadline=1)
                self.assertIs(caught.exception, failure)
                self.assertEqual(close.call_args_list, [mock.call(13), mock.call(14)])
                fstat.assert_not_called()
                read.assert_not_called()

    def test_partial_receipt_write_is_retained_and_never_replaced(self):
        root = job.OwnedOutput(13)
        with (
            mock.patch.object(job.os, "open", return_value=14),
            mock.patch.object(job.os, "write", side_effect=[1, OSError("full")]),
            mock.patch.object(job.os, "close") as close,
        ):
            with self.assertRaises(OSError):
                root.save("finished", {"accepted": False})
            close.assert_called_once_with(14)

    def test_input_observation_uses_readonly_nofollow_and_detects_changes(self):
        for after in [self.info(), self.info(st_ino=7), self.info(st_ctime_ns=9)]:
            with (
                self.subTest(after=after),
                mock.patch.object(job, "open_directory", return_value=13),
                mock.patch.object(job.os, "getuid", return_value=1000),
                mock.patch.object(job.os, "open", return_value=14) as opened,
                mock.patch.object(job.os, "fstat", side_effect=[self.info(), after]),
                mock.patch.object(job.os, "read", side_effect=[b"abc", b""]),
                mock.patch.object(job.time, "monotonic", return_value=0),
                mock.patch.object(job.os, "close"),
            ):
                if after.st_ino == 2 and after.st_ctime_ns == 4:
                    self.assertEqual(
                        job.observe_input("/private/input", limit=3, deadline=1),
                        job.hashlib.sha256(b"abc").hexdigest(),
                    )
                else:
                    with self.assertRaises(ValueError):
                        job.observe_input("/private/input", limit=3, deadline=1)
                flags = opened.call_args.args[1]
                self.assertTrue(flags & job.os.O_NOFOLLOW)
                self.assertFalse(
                    flags & (job.os.O_WRONLY | job.os.O_RDWR | job.os.O_CREAT)
                )

    def test_input_special_setid_writable_foreign_empty_and_large_files_refuse(self):
        for info in [
            self.info(st_mode=0o10600),
            self.info(st_mode=0o104600),
            self.info(st_mode=0o100622),
            self.info(st_uid=2000),
            self.info(st_size=0),
            self.info(st_size=11),
        ]:
            with (
                self.subTest(info=info),
                mock.patch.object(job, "open_directory", return_value=13),
                mock.patch.object(job.os, "getuid", return_value=1000),
                mock.patch.object(job.os, "open", return_value=14),
                mock.patch.object(job.os, "fstat", return_value=info),
                mock.patch.object(job.os, "read") as read,
                mock.patch.object(job.os, "close"),
            ):
                with self.assertRaises(ValueError):
                    job.observe_input("/private/input", limit=10, deadline=1)
                read.assert_not_called()

    def test_input_timeout_refuses_before_read(self):
        with (
            mock.patch.object(job, "open_directory", return_value=13),
            mock.patch.object(job.os, "getuid", return_value=1000),
            mock.patch.object(job.os, "open", return_value=14),
            mock.patch.object(job.os, "fstat", return_value=self.info()),
            mock.patch.object(job.time, "monotonic", return_value=2),
            mock.patch.object(job.os, "read") as read,
            mock.patch.object(job.os, "close"),
        ):
            with self.assertRaises(TimeoutError):
                job.observe_input("/private/input", limit=10, deadline=1)
            read.assert_not_called()


class Task3BuildTests(unittest.TestCase):
    def test_c15_started_receipt_precedes_constructor_and_failure_is_retained(self):
        calls = []
        context = SimpleNamespace(
            start=lambda: calls.append("started"),
            failed=lambda error: calls.append(("failed", type(error).__name__)),
            close=lambda: calls.append("closed"),
        )

        def factory(_):
            calls.append("constructor")
            raise RuntimeError("constructor failure")

        with self.assertRaisesRegex(RuntimeError, "constructor failure"):
            job.build_task3(
                "/private/build", _context=lambda _: context, _factory=factory
            )
        self.assertEqual(
            calls, ["started", "constructor", ("failed", "RuntimeError"), "closed"]
        )

    def test_c16_frozen_pins_cannot_refresh_changed_inputs(self):
        files = {"source": b"original", "dependency": b"library"}
        pins = job.FrozenPins(files, reader=files.__getitem__)
        original = dict(pins.hashes)
        files["source"] = b"changed"
        with self.assertRaisesRegex(RuntimeError, "changed"):
            pins.check()
        self.assertEqual(pins.hashes, original)
        with self.assertRaises(ValueError):
            pins.add("source")

    def test_c17_exact_suite_no_vacuous_or_skipped_success(self):
        job.check_suite(("one", "two"), ("one", "two"), success=True, skipped=0)
        for actual, success, skipped in [
            ((), True, 0),
            (("one",), True, 0),
            (("one", "one"), True, 0),
            (("one", "wrong"), True, 0),
            (("one", "two"), False, 0),
            (("one", "two"), True, 1),
        ]:
            with (
                self.subTest(actual=actual, success=success, skipped=skipped),
                self.assertRaises(RuntimeError),
            ):
                job.check_suite(
                    ("one", "two"), actual, success=success, skipped=skipped
                )
        with self.assertRaises(RuntimeError):
            job.check_controls({})
        controls = {
            name: {"status": 1, "expected": list(diagnostics)}
            for name, diagnostics in job.EXPECTED_CONTROLS.items()
        }
        job.check_controls(controls)
        controls["active_lint_negative"]["expected"] = []
        with self.assertRaises(RuntimeError):
            job.check_controls(controls)

    def test_c18_native_product_cannot_enter_execution_allowlist(self):
        allowed = job.ExecutionAllowlist()
        allowed.add("/owned/unit", "pure", "a" * 64)
        allowed.check("/owned/unit", "a" * 64)
        for path, digest in [("/owned/native", "a" * 64), ("/owned/unit", "b" * 64)]:
            with self.assertRaises(ValueError):
                allowed.check(path, digest)
        with self.assertRaises(ValueError):
            allowed.add("/owned/native", "native", "a" * 64)
        with self.assertRaises(ValueError):
            allowed.add(Path("/owned/unit"), "pure", "b" * 64)
        ir = """define void @task3_native_root(ptr %input) {
call void @_ZN13native_driver3sys3run(ptr %input)
}
call i64 @syscall(i64 noundef 435, ptr %args, i64 noundef 88)
call i32 @clock_gettime(i32 noundef 7, ptr %value)
call i32 @waitid(i32 %kind, i32 %id, ptr %info, i32 %options)
store i64 8589938688, ptr %args
cgroup.kill
"""
        job.check_native_codegen(
            ir, "kernel.rs sys.rs driver.rs", ("kernel.rs", "sys.rs", "driver.rs")
        )
        for broken in (
            ir.replace("define void", "declare void"),
            ir.replace("call", "declare"),
            ir.replace("435", "0"),
        ):
            with self.assertRaises(RuntimeError):
                job.check_native_codegen(
                    broken, "kernel.rs sys.rs driver.rs", ("sys.rs",)
                )


class Task3CompilerTests(unittest.TestCase):
    def command(self, *, cancellation=False, data=b"", wait_error=None):
        handlers = {}
        process = mock.Mock(
            pid=91, returncode=None, stdout=mock.Mock(), stderr=mock.Mock()
        )
        process.stdout.fileno.return_value = 31
        process.stderr.fileno.return_value = 32
        process.wait.return_value = 0
        if wait_error is not None:
            process.wait.side_effect = wait_error
        selector = mock.Mock()
        selector.select.return_value = [
            (SimpleNamespace(fd=31), 1),
            (SimpleNamespace(fd=32), 1),
        ]
        emitted = []

        def spawn(owner, *args, **kwargs):
            self.assertNotIn("preexec_fn", kwargs)
            self.assertTrue(kwargs["start_new_session"])
            owner.process = process
            owner.construction = "returned"
            owner.no_child = False
            if cancellation:
                handlers[job.signal.SIGTERM](job.signal.SIGTERM, None)
            return process

        patches = [
            mock.patch.object(job, "create_owned_compiler", side_effect=spawn),
            mock.patch.object(job.signal, "getsignal", return_value=0),
            mock.patch.object(
                job.signal,
                "signal",
                side_effect=lambda n, handler: handlers.__setitem__(n, handler),
            ),
            mock.patch.object(job.selectors, "DefaultSelector", return_value=selector),
            mock.patch.object(job.os, "set_blocking"),
            mock.patch.object(job.os, "read", side_effect=[data, b""]),
            mock.patch.object(
                job.os, "waitid", return_value=SimpleNamespace(si_pid=91, si_code=1)
            ),
            mock.patch.object(job.os, "killpg"),
            mock.patch.object(job.time, "monotonic", return_value=0),
        ]
        return process, emitted, patches

    def test_c15_compiler_is_owned_before_deferred_cancellation_and_reaped(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command(cancellation=True)
        with ExitStack() as stack:
            entered = [stack.enter_context(patch) for patch in patches]
            with self.assertRaises(job.BuildCancelled):
                job.CompilerCommand(
                    "cancel-test", 20, lambda *args: emitted.append(args)
                ).run(["compiler"], {})
            entered[7].assert_called_once_with(91, job.signal.SIGKILL)
            process.wait.assert_called_once()
        self.assertNotIn("cancel-test", job.COMPILER_OWNERS)
        self.assertTrue(emitted)

    def test_c15_output_cap_failure_retains_partial_output(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command(data=b"oversized")
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaisesRegex(RuntimeError, "output cap"):
                job.CompilerCommand(
                    "cap-test", 20, lambda *args: emitted.append(args), limit=4
                ).run(["compiler"], {})
            process.wait.assert_called_once()
        self.assertTrue(emitted)
        self.assertNotIn("cap-test", job.COMPILER_OWNERS)

    def test_c15_failed_reap_retains_named_owner(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command(wait_error=RuntimeError("wait failed"))
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaisesRegex(RuntimeError, "wait failed"):
                job.CompilerCommand(
                    "retained-test", 20, lambda *args: emitted.append(args)
                ).run(["compiler"], {})
        self.assertIs(job.COMPILER_OWNERS["retained-test"].process, process)
        job.COMPILER_OWNERS.pop("retained-test")  # Fake owner only, no OS resource.
        for operation in ("kill", "identity"):
            process, emitted, patches = self.command()
            with ExitStack() as stack:
                entered = [stack.enter_context(patch) for patch in patches]
                target = entered[7] if operation == "kill" else entered[6]
                target.side_effect = OSError("unproved " + operation)
                with self.assertRaises(OSError):
                    job.CompilerCommand(
                        "unproved-" + operation,
                        20,
                        lambda *args, emitted=emitted: emitted.append(args),
                    ).run(["compiler"], {})
                process.wait.assert_not_called()
            self.assertIs(
                job.COMPILER_OWNERS.pop("unproved-" + operation).process, process
            )
        process, emitted, patches = self.command()
        with ExitStack() as stack:
            entered = [stack.enter_context(patch) for patch in patches]
            entered[8].side_effect = [0, 181, 181]
            with self.assertRaisesRegex(TimeoutError, "command deadline"):
                job.CompilerCommand(
                    "timeout-test", 900, lambda *args: emitted.append(args)
                ).run(["compiler"], {})
            process.wait.assert_called_once()
        self.assertNotIn("timeout-test", job.COMPILER_OWNERS)


class Task6GateTests(unittest.TestCase):
    def test_default_output_respects_standard_private_temp_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(tempfile, "tempdir", directory),
            ):
                output = select_output()
            self.assertEqual(output.parent.parent, Path(directory).resolve())
            self.assertEqual(output.name, "run")
            self.assertFalse(output.exists())
            self.assertEqual(output.parent.stat().st_mode & 0o077, 0)

    def test_explicit_output_precedes_environment_and_rejects_empty(self):
        with mock.patch.dict(
            os.environ, {"IRLUME_JOB_OUTPUT": "/private/from-environment"}
        ):
            self.assertEqual(select_output(), Path("/private/from-environment"))
            self.assertEqual(
                select_output("/private/explicit"), Path("/private/explicit")
            )
            with self.assertRaises(ValueError):
                select_output("")

    def test_completion_requires_exact_fresh_inventory_and_typed_success(self):
        run_id = "a" * 32
        ids = expected_inventory("portable")
        text = completion_text("portable", ids, run_id)
        self.assertEqual(
            parse_completion(text, "portable", run_id)["tests"], sorted(ids)
        )
        row = json.loads(text[len(COMPLETION_PREFIX) :])
        for field, value in [
            ("run_id", "b" * 32),
            ("suite", "controller"),
            ("tests", []),
            ("tests", list(ids) + [ids[0]]),
            ("passed", True),
            ("schema", True),
            ("complete", 1),
            ("skipped", 1),
            ("expected_failures", 1),
            ("native_authorized", True),
            ("full_contract_proven", True),
        ]:
            bad = dict(row, **{field: value})
            with (
                self.subTest(field=field, value=value),
                self.assertRaises((ValueError, RuntimeError)),
            ):
                parse_completion(
                    COMPLETION_PREFIX + json.dumps(bad) + "\n", "portable", run_id
                )

    def test_empty_truncated_duplicate_and_surplus_completion_refuse(self):
        text = completion_text("portable", expected_inventory("portable"), "a" * 32)
        for bad in ["", text[:-1], text + text, "noise\n" + text, text + "noise\n"]:
            with (
                self.subTest(bad=bad[:30]),
                self.assertRaises((ValueError, RuntimeError)),
            ):
                parse_completion(bad, "portable", "a" * 32)

    def fake_receipt_runner(self, mode):
        saved, invoked = {}, []
        output = mock.Mock()
        output.save.side_effect = lambda label, value: saved.__setitem__(label, value)

        def factory(label, deadline, emit, **kwargs):
            self.assertEqual(kwargs["limit"], 1024 * 1024)

            def run(argv, environment, **options):
                invoked.append(label)
                if mode == "cancel":
                    raise KeyboardInterrupt("test cancellation")
                value = (
                    ""
                    if mode == "empty"
                    else completion_text(
                        label,
                        expected_inventory(label),
                        environment["IRLUME_JOB_SUITE_RUN"],
                    )
                )
                status = 4 if mode == "nonzero" else 0
                emit(label, {"reaped": True, "returncode": status}, value.encode(), b"")
                return SimpleNamespace(returncode=status, stdout=value, stderr="")

            return SimpleNamespace(run=run)

        return saved, invoked, output, factory

    def test_portable_parent_requires_completion_even_after_zero_exit(self):
        for mode in ["empty", "nonzero", "cancel"]:
            saved, invoked, output, factory = self.fake_receipt_runner(mode)
            with (
                self.subTest(mode=mode),
                mock.patch.object(job.OwnedOutput, "create", return_value=output),
                mock.patch.object(job, "FrozenPins"),
                mock.patch.object(job, "CompilerCommand", side_effect=factory),
                self.assertRaises((RuntimeError, ValueError, KeyboardInterrupt)),
            ):
                run_portable_receipts("/private/output")
            self.assertEqual(invoked, ["portable"])
            self.assertIn("started", saved)
            self.assertIn("failed", saved)
            self.assertNotIn("finished", saved)
            output.close.assert_called_once()

    def test_portable_parent_records_both_suites_and_propagates_close_failure(self):
        for close_fails in [False, True]:
            saved, invoked, output, factory = self.fake_receipt_runner("valid")
            if close_fails:
                output.close.side_effect = OSError("output close")
            with (
                self.subTest(close_fails=close_fails),
                mock.patch.object(job.OwnedOutput, "create", return_value=output),
                mock.patch.object(job, "FrozenPins"),
                mock.patch.object(job, "CompilerCommand", side_effect=factory),
            ):
                if close_fails:
                    with self.assertRaises(OSError):
                        run_portable_receipts("/private/output")
                else:
                    run_portable_receipts("/private/output")
            self.assertEqual(invoked, ["portable", "controller"])
            self.assertTrue(saved["finished"]["complete"])
            output.close.assert_called_once()

    def test_portable_parent_rejects_late_completion_and_source_drift(self):
        for mode in ["late", "drift"]:
            saved, invoked, output, factory = self.fake_receipt_runner("valid")
            pins = mock.Mock()
            if mode == "drift":
                pins.check.side_effect = [None, RuntimeError("source changed")]
            clock = [0, 301] if mode == "late" else [0]
            with (
                self.subTest(mode=mode),
                mock.patch.object(job.OwnedOutput, "create", return_value=output),
                mock.patch.object(job, "FrozenPins", return_value=pins),
                mock.patch.object(job, "CompilerCommand", side_effect=factory),
                mock.patch.object(time, "monotonic", side_effect=clock),
                self.assertRaises((RuntimeError, TimeoutError)),
            ):
                run_portable_receipts("/private/output")
            self.assertIn("failed", saved)
            self.assertNotIn("finished", saved)
            self.assertEqual(
                invoked, ["portable", "controller"] if mode == "late" else ["portable"]
            )
            output.close.assert_called_once()

    def test_portable_parent_preserves_primary_cancellation_when_close_fails(self):
        saved, _, output, factory = self.fake_receipt_runner("cancel")
        output.close.side_effect = OSError("secondary close")
        with (
            mock.patch.object(job.OwnedOutput, "create", return_value=output),
            mock.patch.object(job, "FrozenPins"),
            mock.patch.object(job, "CompilerCommand", side_effect=factory),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            run_portable_receipts("/private/output")
        self.assertIn("failed", saved)
        self.assertTrue(
            any("secondary close" in note for note in raised.exception.__notes__)
        )
        output.close.assert_called_once()

    def test_portable_parent_owns_output_before_run_identity_generation(self):
        saved, _, output, factory = self.fake_receipt_runner("valid")
        with (
            mock.patch.object(job.OwnedOutput, "create", return_value=output),
            mock.patch.object(uuid, "uuid4", side_effect=OSError("identity failed")),
            mock.patch.object(job, "CompilerCommand", side_effect=factory) as commands,
            self.assertRaises(OSError),
        ):
            run_portable_receipts("/private/output")
        commands.assert_not_called()
        self.assertIn("failed", saved)
        output.close.assert_called_once()

    def test_terminal_receipt_and_close_overruns_are_not_success(self):
        for stage in ["finished", "close"]:
            saved, _, output, factory = self.fake_receipt_runner("valid")
            clock = [0]
            closed = [False]

            def save(
                label, value, *, stage=stage, clock=clock, saved=saved, closed=closed
            ):
                self.assertFalse(closed[0], "receipt write after output close")
                saved[label] = value
                if label == "finished" and stage == "finished":
                    clock[0] = 301

            def close(*, stage=stage, clock=clock, closed=closed):
                self.assertFalse(closed[0], "output closed twice")
                closed[0] = True
                if stage == "close":
                    clock[0] = 301

            output.save.side_effect = save
            output.close.side_effect = close
            with (
                self.subTest(stage=stage),
                mock.patch.object(job.OwnedOutput, "create", return_value=output),
                mock.patch.object(job, "FrozenPins"),
                mock.patch.object(job, "CompilerCommand", side_effect=factory),
                mock.patch.object(
                    time, "monotonic", side_effect=lambda clock=clock: clock[0]
                ),
                self.assertRaises(TimeoutError),
            ):
                run_portable_receipts("/private/output")
            output.close.assert_called_once()
            self.assertEqual("failed" in saved, stage == "finished")


class Task6WrapperTests(unittest.TestCase):
    wrapper = Path(__file__).resolve().parents[1] / "test-measurement-job.sh"

    def invoke_stub(self, arguments):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "called.json"
            python = root / "python3"
            python.write_text(
                f"#!{sys.executable}\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['WRAPPER_LOG']).write_text(json.dumps(sys.argv[1:]))\nsys.exit(71)\n"
            )
            python.chmod(0o700)
            env = dict(
                os.environ,
                PATH=str(root) + os.pathsep + os.environ["PATH"],
                WRAPPER_LOG=str(log),
            )
            result = subprocess.run(
                ["bash", str(self.wrapper), *arguments],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result, json.loads(log.read_text()) if log.exists() else None

    def test_wrapper_routes_only_declared_modes_and_preserves_arguments(self):
        driver = str(Path(__file__).resolve())
        for arguments, expected in [
            ([], [driver, "--portable"]),
            (["--build"], [driver, "--build"]),
            (
                ["--build", "/private/path with spaces"],
                [driver, "--build", "/private/path with spaces"],
            ),
        ]:
            result, called = self.invoke_stub(arguments)
            self.assertEqual(result.returncode, 71, result.stderr)
            self.assertEqual(called, expected)
        result, called = self.invoke_stub(
            [
                "--kernel",
                "--execute-disposable-vm",
                "--profile",
                "/private/profile with spaces.json",
            ]
        )
        if os.geteuid() == 0:
            self.assertEqual(result.returncode, 2)
            self.assertIsNone(called)
        else:
            self.assertEqual(result.returncode, 71)
            self.assertEqual(
                called,
                [
                    str(Path(__file__).with_name("measurement-job-vm.py").resolve()),
                    "--execute-disposable-vm",
                    "--profile",
                    "/private/profile with spaces.json",
                ],
            )

    def test_wrapper_rejects_unknown_incomplete_and_mixed_modes_before_backend(self):
        for arguments in [
            ["--unknown"],
            ["--kernel"],
            ["--kernel", "--profile", "x"],
            ["--build", "--kernel"],
            ["--build", ""],
            ["--build", "x", "y"],
            ["--kernel", "--execute-disposable-vm", "--profile", ""],
            ["--kernel", "--execute-disposable-vm", "--profile", "x", "--build"],
        ]:
            with self.subTest(arguments=arguments):
                result, called = self.invoke_stub(arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIsNone(called)
        result, called = self.invoke_stub(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(called)

    def test_fully_flagged_kernel_route_remains_inactive(self):
        result = subprocess.run(
            [
                "bash",
                str(self.wrapper),
                "--kernel",
                "--execute-disposable-vm",
                "--profile",
                "/nonexistent/qualification.json",
            ],
            env=dict(os.environ, IRLUME_JOB_RUN="1"),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            result.returncode, 2 if os.geteuid() == 0 else 77, result.stderr
        )
        self.assertEqual(result.stdout, "")

    def test_controller_inventory_is_independent_and_exact(self):
        suite, expected = controller_suite()
        self.assertEqual(suite.countTestCases(), 43)
        self.assertEqual(len(expected), 43)
        for value in [CONTROLLER_TESTS[:-1], CONTROLLER_TESTS + (CONTROLLER_TESTS[0],)]:
            with (
                mock.patch.dict(globals(), CONTROLLER_TESTS=value),
                self.assertRaises(RuntimeError),
            ):
                controller_suite()

    def workflow(self):
        import yaml

        return yaml.safe_load(
            (
                Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
            ).read_text()
        )

    def assert_workflow(self, document):
        check = document["jobs"]["check"]
        self.assertEqual(check["runs-on"], "ubuntu-24.04")
        self.assertFalse(check.get("continue-on-error", False))
        steps = check["steps"]

        def one(name):
            matches = [s for s in steps if s.get("name") == name]
            self.assertEqual(len(matches), 1, name)
            return matches[0]

        portable = one("Contained-job portable contracts")
        build = one("Contained-job static build (no native execution)")
        upload = one("Retain contained-job receipts")
        for step, command, output in [
            (portable, "bash scripts/test-measurement-job.sh", "portable"),
            (build, "bash scripts/test-measurement-job.sh --build", "build"),
        ]:
            self.assertEqual(step["run"].strip(), command)
            self.assertNotIn("if", step)
            self.assertFalse(step.get("continue-on-error", False))
            self.assertNotIn("working-directory", step)
            self.assertEqual(
                step["env"]["IRLUME_JOB_OUTPUT"],
                "${{ runner.temp }}/irlume-job-" + output,
            )
        self.assertLess(steps.index(portable), steps.index(build))
        self.assertLess(steps.index(build), steps.index(upload))
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(
            upload["uses"], one("Upload evidence-build compiler receipts")["uses"]
        )
        self.assertEqual(
            upload["with"]["path"].splitlines(),
            [
                "${{ runner.temp }}/irlume-job-portable/*.json",
                "${{ runner.temp }}/irlume-job-build/*.json",
            ],
        )
        self.assertEqual(upload["with"]["retention-days"], 3)
        self.assertFalse(upload["with"].get("include-hidden-files", False))

    def test_workflow_enforces_both_modes_and_bounded_receipt_paths(self):
        self.assert_workflow(self.workflow())

    def test_workflow_contract_rejects_disabled_gate_and_expanded_upload(self):
        original = self.workflow()
        for target, key, value in [
            ("Contained-job portable contracts", "if", "false"),
            (
                "Contained-job static build (no native execution)",
                "continue-on-error",
                True,
            ),
            (
                "Contained-job static build (no native execution)",
                "run",
                "bash scripts/test-measurement-job.sh --kernel",
            ),
        ]:
            document = copy.deepcopy(original)
            matches = [
                s for s in document["jobs"]["check"]["steps"] if s.get("name") == target
            ]
            self.assertEqual(len(matches), 1)
            matches[0][key] = value
            with (
                self.subTest(target=target, key=key),
                self.assertRaises(AssertionError),
            ):
                self.assert_workflow(document)
        document = copy.deepcopy(original)
        upload = next(
            s
            for s in document["jobs"]["check"]["steps"]
            if s.get("name") == "Retain contained-job receipts"
        )
        upload["with"]["path"] += "\n${{ runner.temp }}/**"
        with self.assertRaises(AssertionError):
            self.assert_workflow(document)


class Task5BuildTests(unittest.TestCase):
    def test_bounds_codegen_requires_sentinel_operations_and_data(self):
        parts = ("call i32 @memfd_create(", "call i32 @fcntl(", "irlume-job-custody-v1")
        job.check_bounds_codegen("\n".join(parts))
        for removed in parts:
            with self.subTest(removed=removed), self.assertRaises(RuntimeError):
                job.check_bounds_codegen("\n".join(p for p in parts if p != removed))
        with self.assertRaises(RuntimeError):
            job.check_bounds_codegen("\n".join(parts).replace("call", "declare"))


class Task4BuildTests(unittest.TestCase):
    def test_child_codegen_rejects_absent_calls_and_declarations_only(self):
        calls = (
            "call i64 @recvmsg(",
            "call i64 @sendmsg(",
            "call i32 @setsid(",
            "call i64 @syscall(i64 noundef 424,",
            "store i64 4096,",
            "memory.events.local",
        )
        job.check_child_codegen("\n".join(calls))
        for omitted in calls:
            with self.subTest(omitted=omitted), self.assertRaises(RuntimeError):
                job.check_child_codegen("\n".join(c for c in calls if c != omitted))
        with self.assertRaises(RuntimeError):
            job.check_child_codegen("\n".join(calls).replace("call", "declare"))


class Task3CorrectionTests(unittest.TestCase):
    command = Task3CompilerTests.command

    def test_c15_partial_constructor_missing_group_keeps_leader_unreaped(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command()
        label = "partial-group-missing"
        self.addCleanup(job.COMPILER_OWNERS.pop, label, None)

        class PartialPopen:
            def __init__(partial, *args, **kwargs):
                partial.pid, partial.returncode = 91, None
                partial.stdout, partial.stderr = process.stdout, process.stderr
                partial.wait = process.wait
                raise OSError("constructor interrupted before group readiness")

        with ExitStack() as stack:
            entered = [stack.enter_context(patch) for patch in patches[1:]]
            stack.enter_context(
                mock.patch.object(job.subprocess, "Popen", PartialPopen)
            )
            entered[6].side_effect = ProcessLookupError("setsid not yet complete")
            with self.assertRaisesRegex(OSError, "constructor interrupted"):
                job.CompilerCommand(label, 20, lambda *args: emitted.append(args)).run(
                    ["compiler"], {}
                )
        record = emitted[0][1]
        self.assertFalse(record["reaped"])
        self.assertFalse(record["group_stopped_before_reap"])
        self.assertTrue(record["owner_retained"])
        process.wait.assert_not_called()
        self.assertIn(label, job.COMPILER_OWNERS)

    def test_c15_unpublished_constructor_pid_retains_unknown_owner(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command()
        label = "unpublished-constructor"
        self.addCleanup(job.COMPILER_OWNERS.pop, label, None)

        class UnpublishedPopen:
            def __init__(partial, *args, **kwargs):
                partial.pid, partial.returncode = None, None
                partial.stdout, partial.stderr = process.stdout, process.stderr
                raise OSError("birth publication unknown")

        with ExitStack() as stack:
            entered = [stack.enter_context(patch) for patch in patches[1:]]
            stack.enter_context(
                mock.patch.object(job.subprocess, "Popen", UnpublishedPopen)
            )
            with self.assertRaisesRegex(OSError, "birth publication unknown"):
                job.CompilerCommand(label, 20, lambda *args: emitted.append(args)).run(
                    ["compiler"], {}
                )
        record = emitted[0][1]
        self.assertFalse(record["no_child"])
        self.assertFalse(record["reaped"])
        self.assertTrue(record["owner_retained"])
        entered[5].assert_not_called()
        entered[6].assert_not_called()
        process.wait.assert_not_called()

    def test_c15_preallocation_failure_records_no_child_without_pid_operations(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command()
        label = "preallocation-failure"
        self.addCleanup(job.COMPILER_OWNERS.pop, label, None)

        class UnallocatedPopen:
            def __new__(cls, *args, **kwargs):
                raise OSError("allocation refused before initialization")

        with ExitStack() as stack:
            entered = [stack.enter_context(patch) for patch in patches[1:]]
            stack.enter_context(
                mock.patch.object(job.subprocess, "Popen", UnallocatedPopen)
            )
            with self.assertRaisesRegex(OSError, "allocation refused"):
                job.CompilerCommand(label, 20, lambda *args: emitted.append(args)).run(
                    ["compiler"], {}
                )
        record = emitted[0][1]
        self.assertTrue(record["no_child"])
        self.assertFalse(record["reaped"])
        self.assertFalse(record["owner_retained"])
        entered[5].assert_not_called()
        entered[6].assert_not_called()
        process.wait.assert_not_called()

    def test_c16_compiler_uses_frozen_path_after_selector_changes(self):
        session = job.BuildSession("/private/build")
        session.deadline = 20
        session.environment = {}
        session.rustup, session.cargo = "/selector", "/cargo-proxy"
        session.tool_paths = {
            "rustc": "/pinned/rustc",
            "clippy-driver": "/pinned/clippy-driver",
            "rustdoc": "/pinned/rustdoc",
            "cargo": "/pinned/cargo",
        }
        session.pins = job.FrozenPins({}, reader=lambda _: b"")
        session.output = mock.Mock()
        result = job.subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(job.time, "monotonic", return_value=0),
            mock.patch.object(
                job.CompilerCommand, "run", return_value=result
            ) as execute,
            mock.patch.object(
                job.shutil, "which", return_value="/redirected"
            ) as selector,
        ):
            for tool in ("rustc", "clippy-driver", "rustdoc"):
                session.command(
                    "pinned-compiler", ["/selector", "run", "1.88.0", tool, "--version"]
                )
                self.assertEqual(
                    execute.call_args.args[0], [session.tool_paths[tool], "--version"]
                )
            session.command("pinned-cargo", ["/cargo-proxy", "+1.88.0", "build"])
            self.assertEqual(execute.call_args.args[0], ["/pinned/cargo", "build"])
            selector.assert_not_called()
            with self.assertRaises(ValueError):
                session.command(
                    "unknown", ["/selector", "run", "1.88.0", "unknown-tool"]
                )

    def test_c15_late_reap_records_fact_but_refuses_success(self):
        from contextlib import ExitStack

        for finished in (20, 21):
            with self.subTest(finished=finished):
                process, emitted, patches = self.command()
                now = [0]

                def late_wait(now=now, finished=finished, **_):
                    now[0] = finished
                    return 0

                process.wait.side_effect = late_wait
                with ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    stack.enter_context(
                        mock.patch.object(
                            job.time, "monotonic", side_effect=lambda now=now: now[0]
                        )
                    )
                    with self.assertRaises(TimeoutError):
                        job.CompilerCommand(
                            "late-reap",
                            20,
                            lambda *args, emitted=emitted: emitted.append(args),
                        ).run(["compiler"], {})
                self.assertEqual(len(emitted), 1)
                record = emitted[0][1]
                self.assertTrue(record["reaped"])
                self.assertEqual(record["returncode"], 0)
                self.assertFalse(record["owner_retained"])
                self.assertTrue(
                    any("deadline" in error for error in record["secondary"])
                )
                self.assertNotIn("late-reap", job.COMPILER_OWNERS)
                process.stdout.close.assert_called_once()
                process.stderr.close.assert_called_once()

    def test_c15_restore_failure_attempts_all_and_finalizes_receipt(self):
        from contextlib import ExitStack

        process, emitted, patches = self.command()
        restores = []

        def restore(number, handler):
            if handler == 0:
                restores.append(number)
                raise OSError("restore failed: " + str(number))

        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(job.signal, "signal", side_effect=restore)
            )
            with self.assertRaisesRegex(OSError, "restore failed") as raised:
                job.CompilerCommand(
                    "restore-failure", 20, lambda *args: emitted.append(args)
                ).run(["compiler"], {})
        self.assertEqual(restores, [job.signal.SIGINT, job.signal.SIGTERM])
        self.assertEqual(len(emitted), 1)
        record = emitted[0][1]
        self.assertTrue(record["reaped"])
        self.assertFalse(record["owner_retained"])
        self.assertEqual(len(record["secondary"]), 2)
        self.assertTrue(all("restore failed" in error for error in record["secondary"]))
        self.assertNotIn("restore-failure", job.COMPILER_OWNERS)
        self.assertTrue(
            any(str(job.signal.SIGTERM) in note for note in raised.exception.__notes__)
        )
        process.wait.assert_called_once()

    def test_c15_primary_failure_survives_restore_and_emit_errors(self):
        from contextlib import ExitStack

        _, emitted, patches = self.command(cancellation=True)
        restore_attempts = []

        def restore(number, handler):
            if handler == 0:
                restore_attempts.append(number)
                raise OSError("restore failed")

        def emit(*args):
            emitted.append(args)
            raise OSError("emit failed")

        with ExitStack() as stack:
            entered = [stack.enter_context(patch) for patch in patches]
            original_signal = entered[2].side_effect

            def install_or_restore(number, handler):
                original_signal(number, handler)
                restore(number, handler)

            entered[2].side_effect = install_or_restore
            with self.assertRaises(BaseException) as raised:
                job.CompilerCommand("primary-failure", 20, emit).run(["compiler"], {})
        self.assertIsInstance(raised.exception, job.BuildCancelled)
        self.assertEqual(restore_attempts, [job.signal.SIGINT, job.signal.SIGTERM])
        self.assertEqual(len(emitted), 1)
        self.assertTrue(emitted[0][1]["reaped"])
        self.assertIn("BuildCancelled", emitted[0][1]["first"])
        self.assertTrue(
            any("restore failed" in note for note in raised.exception.__notes__)
        )
        self.assertTrue(
            any("emit failed" in note for note in raised.exception.__notes__)
        )
        self.assertNotIn("primary-failure", job.COMPILER_OWNERS)

    def test_c15_partial_constructor_retains_exact_child_and_stale_pid_is_never_killed(
        self,
    ):
        from contextlib import ExitStack

        for state in (
            "unreaped",
            "reaped",
            "unpublished",
            "unknown",
            "unknown-reap",
            "echild",
        ):
            with self.subTest(state=state):
                process, emitted, patches = self.command()
                label = "constructor-" + state
                adopted = []

                class PartialPopen:
                    def __init__(
                        partial,
                        *args,
                        adopted=adopted,
                        label=label,
                        state=state,
                        process=process,
                        **kwargs,
                    ):
                        adopted.append(job.COMPILER_OWNERS[label].process is partial)
                        partial.pid = None if state == "unpublished" else 91
                        partial.returncode = 127 if state == "reaped" else None
                        if state == "unknown":
                            partial.pid = "unknown"
                        if state == "unknown-reap":
                            partial.returncode = sys.maxsize
                        partial.stdout, partial.stderr = process.stdout, process.stderr
                        partial.wait = process.wait
                        raise OSError("constructor failure after possible birth")

                with ExitStack() as stack:
                    # Do not run any real Popen or its initializer.
                    entered = [stack.enter_context(patch) for patch in patches[1:]]
                    if state == "echild":
                        entered[5].side_effect = ChildProcessError("ownership unknown")
                    stack.enter_context(
                        mock.patch.object(job.subprocess, "Popen", PartialPopen)
                    )
                    with self.assertRaisesRegex(OSError, "constructor failure"):
                        job.CompilerCommand(
                            label,
                            20,
                            lambda *args, emitted=emitted: emitted.append(args),
                        ).run(["compiler"], {})
                self.assertEqual(adopted, [True])
                self.assertEqual(len(emitted), 1)
                record = emitted[0][1]
                self.assertEqual(record["reaped"], state in ("unreaped", "reaped"))
                if state == "unreaped":
                    entered[6].assert_called_once_with(91, job.signal.SIGKILL)
                    process.wait.assert_called_once()
                else:
                    if state != "echild":
                        entered[5].assert_not_called()
                    entered[6].assert_not_called()
                    process.wait.assert_not_called()
                unknown = state in ("unpublished", "unknown", "unknown-reap", "echild")
                self.assertEqual(label in job.COMPILER_OWNERS, unknown)
                if unknown:
                    job.COMPILER_OWNERS.pop(label)  # Only the fake is retained.
                self.assertFalse(record["no_child"])

    def test_c15_successful_collection_preserves_wait_and_receipt_failures(self):
        from contextlib import ExitStack

        _, emitted, patches = self.command(wait_error=OSError("wait failed"))

        def emit(*args):
            emitted.append(args)
            raise RuntimeError("receipt failed")

        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaisesRegex(OSError, "wait failed") as raised:
                job.CompilerCommand("wait-and-receipt", 20, emit).run(["compiler"], {})
        self.assertTrue(
            any(
                "receipt failed" in note
                for note in getattr(raised.exception, "__notes__", ())
            )
        )
        self.assertFalse(emitted[0][1]["reaped"])
        self.assertIn("wait-and-receipt", job.COMPILER_OWNERS)
        job.COMPILER_OWNERS.pop("wait-and-receipt")

    def test_c16_orchestration_rechecks_transitive_members_and_sources(self):
        for stage in ("pre", "post", "final"):
            for mutation in (
                "source",
                "transitive",
                "new-member",
                "deleted-member",
                "config",
            ):
                with self.subTest(stage=stage, mutation=mutation):
                    files = {"source": b"source"}
                    members = {"libdigest.rlib": "original"}
                    config_data = {}
                    session = job.BuildSession("/private/build")
                    session.deadline = 20
                    session.environment = {}
                    session.rustup, session.cargo = "/rustup", "/cargo"
                    session.tool_paths = {
                        "rustc": "/pinned/rustc",
                        "cargo": "/pinned/cargo",
                    }
                    session.output = mock.Mock()
                    session.pins = job.FrozenPins(files, reader=files.__getitem__)
                    session.dependency_inputs = job.FrozenDirectories(
                        ("/private/deps",),
                        inventory=lambda _, members=members: dict(members),
                    )
                    session.config_inputs = job.CargoConfigurations(
                        Path("/work"),
                        {"CARGO_HOME": "/cargo"},
                        reader=lambda path, config_data=config_data: config_data.get(
                            str(path)
                        ),
                    )

                    def change(
                        mutation=mutation,
                        files=files,
                        members=members,
                        config_data=config_data,
                    ):
                        if mutation == "source":
                            files["source"] = b"changed"
                        elif mutation == "transitive":
                            members["libdigest.rlib"] = "changed"
                        elif mutation == "new-member":
                            members["libextra.rlib"] = "new"
                        elif mutation == "deleted-member":
                            del members["libdigest.rlib"]
                        else:
                            config_data["/cargo/config"] = b"# newly present"

                    def command(*args, stage=stage, change=change, **kwargs):
                        if stage == "post":
                            change()
                        return job.subprocess.CompletedProcess([], 0, "", "")

                    if stage != "post":
                        change()
                    with (
                        mock.patch.object(job.time, "monotonic", return_value=0),
                        mock.patch.object(
                            job.CompilerCommand, "run", side_effect=command
                        ) as execute,
                    ):
                        with self.assertRaisesRegex(RuntimeError, "changed"):
                            if stage == "final":
                                session.finish(
                                    SimpleNamespace(
                                        record={
                                            "controls": {
                                                name: {
                                                    "status": 1,
                                                    "expected": list(messages),
                                                }
                                                for name, messages in job.EXPECTED_CONTROLS.items()
                                            }
                                        },
                                        bootstrap=SimpleNamespace(FLAGS=(), LINTS=()),
                                    )
                                )
                            else:
                                session.command(
                                    "probe",
                                    ["/rustup", "run", "1.88.0", "rustc", "--version"],
                                )
                        self.assertEqual(execute.call_count, int(stage == "post"))

    def test_c16_cargo_configuration_absence_and_contents_are_frozen(self):
        data = {}
        config = job.CargoConfigurations(
            Path("/work/tree"),
            {"CARGO_HOME": "/cargo-home"},
            reader=lambda path: data.get(str(path)),
        )
        self.assertIn("/work/tree/.cargo/config", config.hashes)
        self.assertIn("/.cargo/config.toml", config.hashes)
        self.assertIn("/cargo-home/config.toml", config.hashes)
        for path in config.hashes:
            data[path] = b"# newly present\n"
            with self.assertRaisesRegex(RuntimeError, "changed"):
                config.check()
            del data[path]
        data["/work/tree/.cargo/config.toml"] = b'[build]\nrustc-wrapper="unapproved"\n'
        with self.assertRaisesRegex(RuntimeError, "configuration"):
            job.CargoConfigurations(
                Path("/work/tree"),
                {"CARGO_HOME": "/cargo-home"},
                reader=lambda path: data.get(str(path)),
            )

    def test_c16_cargo_command_binds_compiler_and_clears_wrappers(self):
        session = job.BuildSession("/private/build")
        session.deadline = 20
        session.environment = {"HOME": "/private/home"}
        session.rustup, session.cargo = "/rustup", "/cargo"
        session.tool_paths = {
            "rustc": "/pinned/rustc",
            "rustdoc": "/pinned/rustdoc",
            "cargo": "/pinned/cargo",
        }
        session.pins = job.FrozenPins({}, reader=lambda _: b"")
        session.output = mock.Mock()
        result = job.subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(job.time, "monotonic", return_value=0),
            mock.patch.object(
                job.CompilerCommand, "run", return_value=result
            ) as execute,
        ):
            session.command(
                "compile",
                ["/cargo", "+1.88.0", "build"],
                env={
                    **session.environment,
                    "RUSTC_WRAPPER": "/bad",
                    "RUSTC_WORKSPACE_WRAPPER": "/bad",
                },
            )
            effective = execute.call_args.args[1]
            self.assertEqual(effective["RUSTC"], "/pinned/rustc")
            self.assertEqual(effective["RUSTDOC"], "/pinned/rustdoc")
            self.assertEqual(effective["RUSTC_WRAPPER"], "")
            self.assertEqual(effective["RUSTC_WORKSPACE_WRAPPER"], "")
            self.assertEqual(effective["CARGO_BUILD_JOBS"], "4")
            with self.assertRaisesRegex(RuntimeError, "changed build environment"):
                session.command(
                    "compile",
                    ["/cargo", "+1.88.0", "build"],
                    env={"HOME": "/elsewhere"},
                )

    def test_c17_expected_failure_cannot_pass_actual_suite_guard(self):
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_failure(self):
                self.fail("expected failures are not successful evidence")

        case = ExpectedFailure("test_failure")
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            run_portable_suite(unittest.TestSuite([case]), (case.id(),))


PORTABLE_TESTS = {
    Task6WrapperTests: [
        "test_wrapper_routes_only_declared_modes_and_preserves_arguments",
        "test_wrapper_rejects_unknown_incomplete_and_mixed_modes_before_backend",
        "test_fully_flagged_kernel_route_remains_inactive",
        "test_controller_inventory_is_independent_and_exact",
        "test_workflow_enforces_both_modes_and_bounded_receipt_paths",
        "test_workflow_contract_rejects_disabled_gate_and_expanded_upload",
    ],
    Task6GateTests: [
        "test_default_output_respects_standard_private_temp_directory",
        "test_explicit_output_precedes_environment_and_rejects_empty",
        "test_completion_requires_exact_fresh_inventory_and_typed_success",
        "test_empty_truncated_duplicate_and_surplus_completion_refuse",
        "test_portable_parent_requires_completion_even_after_zero_exit",
        "test_portable_parent_records_both_suites_and_propagates_close_failure",
        "test_portable_parent_rejects_late_completion_and_source_drift",
        "test_portable_parent_preserves_primary_cancellation_when_close_fails",
        "test_portable_parent_owns_output_before_run_identity_generation",
        "test_terminal_receipt_and_close_overruns_are_not_success",
    ],
    InputTests: [
        "test_exact_separately_supplied_expectations",
        "test_self_selected_hash_cannot_replace_trusted_pin",
        "test_unknown_duplicate_and_nonfinite_json",
        "test_invalid_identity_types_counts_and_fixed_budgets",
        "test_hash_and_path_grammar_and_no_optional_attachments",
        "test_untrusted_and_trusted_input_sizes_are_bounded",
    ],
    EvidenceTests: [
        "test_complete_model_is_not_native_authorization",
        "test_every_binding_and_nonexact_scalar_is_checked",
        "test_missing_duplicate_stale_conflicting_or_unreached_cases_refuse",
        "test_cleanup_and_lease_assertions_are_not_optional",
        "test_duplicate_nested_keys_and_oversized_evidence_refuse",
        "test_incomplete_cleanup_retains_custody_in_negative_model",
        "test_evidence_does_not_mutate_trusted_expectations",
    ],
    FilesystemTests: [
        "test_fresh_directory_refuses_existing_or_symlink_without_writing",
        "test_receipt_is_exclusive_nofollow_and_bounded",
        "test_directory_walk_rejects_symlinks_and_foreign_writable_ancestors",
        "test_foreign_output_parent_never_calls_mkdir",
        "test_new_output_is_private_and_anchored_to_parent_fd",
        "test_new_output_fd_closes_when_validation_raises",
        "test_new_output_fd_closes_if_parent_close_prevents_transfer",
        "test_directory_transfer_guards_child_before_closing_old_fd",
        "test_input_transfer_guards_file_before_closing_parent_fd",
        "test_partial_receipt_write_is_retained_and_never_replaced",
        "test_input_observation_uses_readonly_nofollow_and_detects_changes",
        "test_input_special_setid_writable_foreign_empty_and_large_files_refuse",
        "test_input_timeout_refuses_before_read",
    ],
    Task3BuildTests: [
        "test_c15_started_receipt_precedes_constructor_and_failure_is_retained",
        "test_c16_frozen_pins_cannot_refresh_changed_inputs",
        "test_c17_exact_suite_no_vacuous_or_skipped_success",
        "test_c18_native_product_cannot_enter_execution_allowlist",
    ],
    Task3CompilerTests: [
        "test_c15_compiler_is_owned_before_deferred_cancellation_and_reaped",
        "test_c15_output_cap_failure_retains_partial_output",
        "test_c15_failed_reap_retains_named_owner",
    ],
    Task5BuildTests: ["test_bounds_codegen_requires_sentinel_operations_and_data"],
    Task4BuildTests: [
        "test_child_codegen_rejects_absent_calls_and_declarations_only",
    ],
    Task3CorrectionTests: [
        "test_c15_partial_constructor_missing_group_keeps_leader_unreaped",
        "test_c15_unpublished_constructor_pid_retains_unknown_owner",
        "test_c15_preallocation_failure_records_no_child_without_pid_operations",
        "test_c16_compiler_uses_frozen_path_after_selector_changes",
        "test_c15_late_reap_records_fact_but_refuses_success",
        "test_c15_restore_failure_attempts_all_and_finalizes_receipt",
        "test_c15_primary_failure_survives_restore_and_emit_errors",
        "test_c15_partial_constructor_retains_exact_child_and_stale_pid_is_never_killed",
        "test_c15_successful_collection_preserves_wait_and_receipt_failures",
        "test_c16_orchestration_rechecks_transitive_members_and_sources",
        "test_c16_cargo_configuration_absence_and_contents_are_frozen",
        "test_c16_cargo_command_binds_compiler_and_clears_wrappers",
        "test_c17_expected_failure_cannot_pass_actual_suite_guard",
    ],
}


CONTROLLER_TESTS = (
    "ControllerTests.test_no_real_runtime_can_be_enabled_by_profile_or_tool_availability",
    "ControllerTests.test_model_success_is_explicitly_partial_and_readonly",
    "ControllerTests.test_root_setid_missing_kvm_tools_or_scratch_never_spawns",
    "ControllerTests.test_missing_or_changed_observations_never_spawn",
    "ControllerTests.test_unsafe_output_never_gets_failure_write",
    "ControllerTests.test_profile_refusal_has_started_and_failure_receipts",
    "ControllerTests.test_missing_host_loss_handling_is_not_a_success_flag",
    "ControllerTests.test_prepare_failure_keeps_its_receipt_without_launch",
    "ControllerTests.test_spawn_failure_does_not_claim_reaping",
    "ControllerTests.test_early_nonzero_or_signal_exit_never_accepts_recovered_success",
    "ControllerTests.test_timeout_kills_only_owned_handle_and_reaps_with_finite_budget",
    "ControllerTests.test_failed_reaping_retains_exact_handle_and_skips_recovery",
    "ControllerTests.test_kill_failure_does_not_skip_bounded_wait_or_erase_primary_failure",
    "ControllerTests.test_cancellation_is_recorded_and_owned_process_is_reaped",
    "ControllerTests.test_invalid_or_missing_recovery_is_retained_but_never_accepted",
    "ControllerTests.test_oversized_serial_or_recovery_never_validates",
    "ControllerTests.test_late_zero_exit_is_not_timely_success",
    "ControllerTests.test_late_prepare_and_recovery_cannot_extend_deadlines",
    "ControllerTests.test_changed_validator_after_launch_refuses_even_complete_evidence",
    "ControllerTests.test_prepare_and_reap_results_require_exact_bounded_scalars",
    "ControllerTests.test_interrupted_recovery_retains_non_success_receipt",
    "ControllerTests.test_unrelated_handle_is_not_touched_during_cleanup",
    "ControllerTests.test_unexpected_model_exception_reaps_and_records_before_propagating",
    "ControllerTests.test_observation_recheck_precedes_spawn",
    "ControllerTests.test_model_marker_is_not_read_from_json",
    "ControllerTests.test_unexpected_kill_still_waits_finalizes_and_preserves_primary_cause",
    "ControllerTests.test_unexpected_recovery_still_finalizes_before_reraise",
    "ControllerTests.test_recovery_uses_only_positive_budget_remaining_after_inspection",
    "ControllerTests.test_late_stop_wait_keeps_reap_fact_but_records_deadline_failure",
    "ControllerTests.test_unexpected_stop_wait_retains_ownership_and_finalizes",
    "ControllerTests.test_cancellation_and_secondary_unexpected_failure_are_preserved",
    "ControllerTests.test_secondary_recovery_failure_does_not_replace_initial_failure",
    "ControllerTests.test_finished_receipt_failure_preserves_pending_error_and_closes",
    "ControllerTests.test_operational_finished_receipt_error_is_not_returned_as_success",
    "ControllerTests.test_unexpected_receipt_and_close_errors_both_propagate",
    "ControllerTests.test_kill_spending_entire_stop_budget_never_starts_wait_or_recovery",
    "ControllerTests.test_expected_context_survives_prepare_recovery_and_reap_failures",
    "ControllerTests.test_profile_edits_cannot_change_retained_trusted_context",
    "ControllerTests.test_different_case_and_payload_expectations_remain_distinguishable",
    "ControllerTests.test_invalid_or_empty_expected_data_is_refused_before_any_output",
    "CommandTests.test_import_never_starts_build_process_or_output_transaction",
    "CommandTests.test_fixed_argv_no_network_monitor_shares_or_device_passthrough",
    "CommandTests.test_guest_entry_has_no_activation_switch_or_old_executor",
)
COMPLETION_PREFIX = "IRLUME_JOB_SUITE "
COMPLETION_LIMIT = 65536


def select_output(explicit=None):
    selected = explicit if explicit is not None else os.environ.get("IRLUME_JOB_OUTPUT")
    if selected is not None:
        return Path(job.safe_path(selected))
    parent = Path(tempfile.mkdtemp(prefix="irlume-job-")).resolve()
    return Path(job.safe_path(str(parent / "run")))


def expected_inventory(suite):
    if suite == "portable":
        return tuple(
            f"{cls.__name__}.{name}"
            for cls, names in PORTABLE_TESTS.items()
            for name in names
        )
    if suite == "controller":
        return CONTROLLER_TESTS
    raise ValueError("unknown portable suite")


def completion_text(suite, ids, run_id):
    tests = sorted(".".join(name.split(".")[-2:]) for name in ids)
    row = {
        "schema": 1,
        "suite": suite,
        "run_id": run_id,
        "tests": tests,
        "passed": len(tests),
        "skipped": 0,
        "expected_failures": 0,
        "complete": True,
        "native_authorized": False,
        "full_contract_proven": False,
    }
    return COMPLETION_PREFIX + json.dumps(row, sort_keys=True) + "\n"


def parse_completion(text, suite, run_id):
    if (
        not isinstance(text, str)
        or not text.endswith("\n")
        or len(text.encode()) > COMPLETION_LIMIT
    ):
        raise ValueError("missing or oversized suite completion")
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].startswith(COMPLETION_PREFIX):
        raise ValueError("ambiguous suite completion")
    row = job.strict_json(lines[0][len(COMPLETION_PREFIX) :].encode(), COMPLETION_LIMIT)
    job.fields(
        row,
        (
            "schema",
            "suite",
            "run_id",
            "tests",
            "passed",
            "skipped",
            "expected_failures",
            "complete",
            "native_authorized",
            "full_contract_proven",
        ),
    )
    want = expected_inventory(suite)
    job.integer(row["schema"], 1, 1)
    job.integer(row["passed"], len(want), len(want))
    job.integer(row["skipped"], 0, 0)
    job.integer(row["expected_failures"], 0, 0)
    if (
        row["suite"] != suite
        or row["run_id"] != run_id
        or row["native_authorized"] is not False
        or row["full_contract_proven"] is not False
    ):
        raise ValueError("foreign suite completion")
    if type(row["tests"]) is not list or any(
        type(name) is not str for name in row["tests"]
    ):
        raise ValueError("invalid completed test inventory")
    job.check_suite(
        want,
        row["tests"],
        success=row["complete"],
        skipped=row["skipped"],
        expected_failures=row["expected_failures"],
    )
    return row


def run_portable_receipts(output):
    deadline = time.monotonic() + 300
    root = job.OwnedOutput.create(str(output))
    try:
        run_id = uuid.uuid4().hex
        root.save(
            "started",
            {
                "mode": "portable",
                "run_id": run_id,
                "complete": False,
                "native_authorized": False,
                "full_contract_proven": False,
            },
        )
        here = Path(__file__).resolve().parent
        repository = here.parents[1]
        interpreter = str(Path(sys.executable).resolve())
        pins = job.FrozenPins(
            [
                interpreter,
                __file__,
                here / "measurement-job.py",
                here / "measurement-job-vm.py",
                here / "test-measurement-job-vm.py",
                repository / "scripts/test-measurement-job.sh",
                repository / ".github/workflows/ci.yml",
            ]
        )
        root.save("inputs", pins.hashes)
        environment = dict(
            os.environ, PYTHONDONTWRITEBYTECODE="1", IRLUME_JOB_SUITE_RUN=run_id
        )
        records = []

        def emit(label, record, stdout, stderr):
            root.save(label, record)
            root.save_blob(label + "-stdout", stdout)
            root.save_blob(label + "-stderr", stderr)

        for suite, arguments in [("portable", []), ("controller", ["--controller"])]:
            pins.check()
            result = job.CompilerCommand(suite, deadline, emit, limit=1024 * 1024).run(
                [interpreter, str(Path(__file__).resolve()), *arguments],
                environment,
                cwd=str(repository),
            )
            pins.check()
            if result.returncode != 0:
                raise RuntimeError(suite + " suite failed")
            records.append(parse_completion(result.stdout, suite, run_id))
            root.save(suite + "-completion", records[-1])
        pins.check()
        if time.monotonic() >= deadline:
            raise TimeoutError("portable aggregate deadline")
        root.save(
            "finished",
            {
                "mode": "portable",
                "complete": True,
                "run_id": run_id,
                "suites": records,
                "native_authorized": False,
                "full_contract_proven": False,
            },
        )
        if time.monotonic() >= deadline:
            raise TimeoutError("portable aggregate deadline after receipt")
    except BaseException as error:
        try:
            root.save(
                "failed",
                {
                    "mode": "portable",
                    "complete": False,
                    "error": f"{type(error).__name__}: {error}"[:2000],
                    "native_authorized": False,
                    "full_contract_proven": False,
                },
            )
        except job.FINALIZATION_FAILURES as secondary:
            error.add_note(f"failure receipt: {type(secondary).__name__}: {secondary}")
        try:
            root.close()
        except job.FINALIZATION_FAILURES as secondary:
            error.add_note(f"output close: {type(secondary).__name__}: {secondary}")
        raise
    else:
        root.close()
        # The descriptor is consumed: an overrun must not retry receipt I/O or close.
        if time.monotonic() >= deadline:
            raise TimeoutError("portable aggregate deadline after close")
    return records


def run_portable_suite(suite, expected_ids):
    actual = tuple(test.id() for test in suite)
    job.check_suite(expected_ids, actual, success=True, skipped=0)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    job.check_suite(
        expected_ids,
        actual[: result.testsRun],
        success=result.wasSuccessful(),
        skipped=len(result.skipped),
        expected_failures=len(result.expectedFailures),
    )
    return actual


def controller_suite():
    spec = importlib.util.spec_from_file_location(
        "job_controller_tests", Path(__file__).with_name("test-measurement-job-vm.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def flatten(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            else:
                yield test

    tests = tuple(flatten(unittest.defaultTestLoader.loadTestsFromModule(module)))
    expected = tuple(f"job_controller_tests.{name}" for name in CONTROLLER_TESTS)
    job.check_suite(
        expected, tuple(test.id() for test in tests), success=True, skipped=0
    )
    return unittest.TestSuite(tests), expected


if __name__ == "__main__":
    if sys.argv[1:2] == ["--build"]:
        if len(sys.argv) > 3:
            raise SystemExit("usage: test-measurement-job.py --build [fresh-output]")
        output = select_output(sys.argv[2] if len(sys.argv) == 3 else None)
        print("Contained-job build-only output:", output, flush=True)
        job.build_task3(str(output))
    elif sys.argv[1:2] == ["--portable"]:
        if len(sys.argv) > 3:
            raise SystemExit("usage: test-measurement-job.py --portable [fresh-output]")
        output = select_output(sys.argv[2] if len(sys.argv) == 3 else None)
        print("Contained-job portable receipts:", output, flush=True)
        records = run_portable_receipts(output)
        print(
            "Validated portable suites:",
            ", ".join(f"{r['suite']}={r['passed']}" for r in records),
        )
    elif sys.argv[1:] == ["--controller"]:
        suite, expected_ids = controller_suite()
        actual = run_portable_suite(suite, expected_ids)
        sys.stdout.write(
            completion_text(
                "controller", actual, os.environ.get("IRLUME_JOB_SUITE_RUN", "")
            )
        )
    elif sys.argv[1:]:
        # Focused selection only contains pure/mock classes; no build setUpClass.
        unittest.main()
    else:
        discovered = tuple(
            f"__main__.{cls.__name__}.{name}"
            for cls in PORTABLE_TESTS
            for name in unittest.defaultTestLoader.getTestCaseNames(cls)
        )
        suite = unittest.TestSuite(
            cls(name) for cls, names in PORTABLE_TESTS.items() for name in names
        )
        actual = tuple(test.id() for test in suite)
        expected_ids = tuple(
            f"__main__.{cls.__name__}.{name}"
            for cls, names in PORTABLE_TESTS.items()
            for name in names
        )
        job.check_suite(expected_ids, actual, success=True, skipped=0)
        job.check_suite(expected_ids, discovered, success=True, skipped=0)
        actual = run_portable_suite(suite, expected_ids)
        sys.stdout.write(
            completion_text(
                "portable", actual, os.environ.get("IRLUME_JOB_SUITE_RUN", "")
            )
        )
