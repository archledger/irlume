import json
import sys
import tempfile
import unittest
from pathlib import Path

import harness


class TraceTests(unittest.TestCase):
    def test_rate_fill_failures_remain_non_granting_and_payload_free(self):
        labels = [
            "io_permission_denied", "io_invalid_argument", "io_device", "io_no_space",
            "io_timeout", "io_other", "buffer_timestamp", "buffer_clock", "buffer_source",
            "buffer_layout", "timestamp_non_increasing", "timestamp_clock",
            "timestamp_source", "timestamp_epoch", "sequence", "rate_window", "other",
            "privacy_boundary", "privacy_engaged", "privacy_read_permission_denied",
            "privacy_read_device", "privacy_read_timeout", "privacy_read_busy",
            "privacy_read_other", "lease_boundary", "stream_state", "continuity_alignment",
            "continuity_accounting", "incomplete_window", "missing_stream", "stopped_stream",
        ]
        base = {
            "schema": 1,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "camera_hardware_failed",
            "elapsed_ms": 12,
            "capture_ms": 11,
            "detection_ms": None,
            "pad_ms": None,
            "identity_ms": None,
        }
        for label in labels:
            record = dict(base, category="camera_rate_fill_" + label)
            try:
                accepted = harness.checked_report(record)
            except ValueError as error:
                self.fail(str(error))
            self.assertEqual(accepted, record)
            for invalid in [
                dict(record, authentication_granted=True),
                dict(record, raw_error="private driver payload"),
                dict(record, category=record["category"] + "_errno_5"),
            ]:
                with self.assertRaises(ValueError):
                    harness.checked_report(invalid)

    def test_rate_fill_category_keeps_all_prior_schema_contracts(self):
        stage_names = [
            "open", "session_setup", "buffers", "metadata", "emitter", "warmup",
            "rate_fill", "frames", "session_release", "image_stop", "metadata_streamoff",
            "metadata_buffers", "metadata_format", "metadata_close", "emitter_restore",
        ]
        for version in (1, 2, 3, 4):
            record = {
                "schema": version,
                "operation": "ir_only_evaluation",
                "authentication_granted": False,
                "category": "camera_rate_fill_timestamp_non_increasing",
                "elapsed_ms": 12,
                "capture_ms": 11,
                "detection_ms": None,
                "pad_ms": None,
                "identity_ms": None,
            }
            if version >= 2:
                record["capture_stages_ms"] = dict.fromkeys(
                    stage_names[:9] if version == 2 else stage_names
                )
            if version == 4:
                record["identity_acceptance"] = None
            self.assertEqual(harness.checked_report(record), record)
            for old in ["camera_hardware_failed", "cancelled", "deadline_expired"]:
                legacy = dict(record, category=old)
                self.assertEqual(harness.checked_report(legacy), legacy)
            if version == 4:
                with self.assertRaises(ValueError):
                    harness.checked_report(dict(record, identity_acceptance="both"))

    def test_ioctl_metadata_is_numeric_and_payload_free(self):
        line = "123.456 ioctl(0x4, 0x40045613, 0xdeadbeef) = 0 <0.933001>"
        self.assertEqual(
            harness.ioctl_event(line, {4: "/dev/video2"}),
            {
                "timestamp": 123.456,
                "device": "/dev/video2",
                "fd": 4,
                "request": 0x40045613,
                "result": 0,
                "duration_us": 933001,
            },
        )
        self.assertIsNone(harness.ioctl_event(line, {}))
        for invalid in [
            line.replace("<0.933001>", ""),
            line.replace("0x40045613", "VIDIOC_STREAMOFF"),
            line.replace("<0.933001>", "<121.000000>"),
            line.replace("0xdeadbeef", "{private_payload}"),
        ]:
            with self.assertRaises(ValueError):
                harness.ioctl_event(invalid, {4: "/dev/video2"})

    def test_ioctl_trace_handles_resumption_and_fd_reuse_without_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracer = Path(tmp) / "tracer.py"
            lines = [
                '9 123.000 openat(AT_FDCWD, "/dev/video2", O_RDWR) = 4</dev/video2>',
                "9 123.100 ioctl(0x4, 0x40045613, 0xdeadbeef <unfinished ...>",
                "9 124.033 <... ioctl resumed>) = 0 <0.933000>",
                "9 124.034 close(4</dev/video2>) = 0",
                "9 124.035 ioctl(0x4, 0x40045613, 0xdeadbeef) = -1 ENOTTY (message) <0.000001>",
            ]
            tracer.write_text(
                "#!"
                + sys.executable
                + "\nimport sys\n"
                + "assert '-T' in sys.argv and 'raw=ioctl' in sys.argv\n"
                + "print("
                + repr("\n".join(lines))
                + ",file=sys.stderr)\n"
            )
            tracer.chmod(0o700)
            got = harness.run_traced(
                ["unused"], timeout=5, tracer=str(tracer), trace_ioctl=True
            )
            self.assertFalse(got["trace_error"])
            self.assertEqual(len(got["video_ioctl_events"]), 1)
            self.assertEqual(got["video_ioctl_events"][0]["duration_us"], 933000)
            self.assertNotIn("deadbeef", json.dumps(got))
            self.assertNotIn("message", json.dumps(got))

    def test_close_during_pending_ioctl_invalidates_measurement(self):
        for reopen in [False, True]:
            with self.subTest(reopen=reopen), tempfile.TemporaryDirectory() as tmp:
                lines = [
                    '9 123.000 openat(AT_FDCWD, "/dev/video2", O_RDWR) = 4</dev/video2>',
                    "9 123.100 ioctl(0x4, 0x40045613, 0xdeadbeef <unfinished ...>",
                    "10 123.200 close(4</dev/video2>) = 0",
                ]
                if reopen:
                    lines.append(
                        '10 123.300 openat(AT_FDCWD, "/dev/video3", O_RDWR) = 4</dev/video3>'
                    )
                lines.append("9 124.033 <... ioctl resumed>) = 0 <0.933000>")
                tracer = Path(tmp) / "tracer.py"
                tracer.write_text(
                    "#!"
                    + sys.executable
                    + "\nimport sys\nprint("
                    + repr("\n".join(lines))
                    + ",file=sys.stderr)\n"
                )
                tracer.chmod(0o700)
                got = harness.run_traced(
                    ["unused"], timeout=5, tracer=str(tracer), trace_ioctl=True
                )
                self.assertTrue(got["trace_error"])

    def test_pending_nonvideo_ioctl_cannot_become_video_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = [
                '9 123.000 openat(AT_FDCWD, "/dev/null", O_RDWR) = 4</dev/null>',
                "9 123.100 ioctl(0x4, 0x40045613, 0xdeadbeef <unfinished ...>",
                "10 123.200 close(4</dev/null>) = 0",
                '10 123.300 openat(AT_FDCWD, "/dev/video2", O_RDWR) = 4</dev/video2>',
                "9 124.033 <... ioctl resumed>) = 0 <0.933000>",
                "9 124.034 close(4</dev/video2>) = 0",
            ]
            tracer = Path(tmp) / "tracer.py"
            tracer.write_text(
                "#!"
                + sys.executable
                + "\nimport sys\nprint("
                + repr("\n".join(lines))
                + ",file=sys.stderr)\n"
            )
            tracer.chmod(0o700)
            got = harness.run_traced(
                ["unused"], timeout=5, tracer=str(tracer), trace_ioctl=True
            )
            self.assertTrue(got["trace_error"])

    def test_version_three_requires_all_teardown_timings_and_rejects_payloads(self):
        stages = dict.fromkeys(
            [
                "open",
                "session_setup",
                "buffers",
                "metadata",
                "emitter",
                "warmup",
                "rate_fill",
                "frames",
                "session_release",
                "image_stop",
                "metadata_streamoff",
                "metadata_buffers",
                "metadata_format",
                "metadata_close",
                "emitter_restore",
            ]
        )
        stages.update(image_stop=950, metadata_close=0)
        record = {
            "schema": 3,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "deadline_expired",
            "elapsed_ms": 5700,
            "capture_ms": 5699,
            "detection_ms": None,
            "pad_ms": None,
            "identity_ms": None,
            "capture_stages_ms": stages,
        }
        self.assertEqual(harness.checked_report(record), record)
        for values in [
            dict(stages, metadata_close=True),
            dict(stages, image_stop=-1),
            dict(stages, emitter_restore="private error"),
            dict(stages, image_stop=3600001),
            dict(stages, score=0.99),
            {k: v for k, v in stages.items() if k != "image_stop"},
        ]:
            with self.assertRaises(ValueError):
                harness.checked_report(dict(record, capture_stages_ms=values))
        for version in [1, 2, 4]:
            with self.assertRaises(ValueError):
                harness.checked_report(dict(record, schema=version))

    def test_version_four_requires_bounded_identity_acceptance_evidence(self):
        stages = dict.fromkeys(
            [
                "open",
                "session_setup",
                "buffers",
                "metadata",
                "emitter",
                "warmup",
                "rate_fill",
                "frames",
                "session_release",
                "image_stop",
                "metadata_streamoff",
                "metadata_buffers",
                "metadata_format",
                "metadata_close",
                "emitter_restore",
            ]
        )
        base = {
            "schema": 4,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "candidate_match",
            "identity_acceptance": "centroid",
            "elapsed_ms": 5700,
            "capture_ms": 5699,
            "detection_ms": 0,
            "pad_ms": 0,
            "identity_ms": 1,
            "capture_stages_ms": stages,
        }
        for acceptance in ["best_template", "centroid", "both"]:
            record = dict(base, identity_acceptance=acceptance)
            self.assertEqual(harness.checked_report(record), record)
        for invalid in [None, "unknown", True, 1, [], {}]:
            with self.assertRaises(ValueError):
                harness.checked_report(dict(base, identity_acceptance=invalid))
        with self.assertRaises(ValueError):
            harness.checked_report(dict(base, category="identity_mismatch"))
        refusal = dict(base, category="cancelled", identity_acceptance=None)
        self.assertEqual(harness.checked_report(refusal), refusal)
        for invalid in [
            {key: value for key, value in base.items() if key != "identity_acceptance"},
            dict(base, private_score=0.9),
        ]:
            with self.assertRaises(ValueError):
                harness.checked_report(invalid)

    def test_version_two_capture_timings_are_exact_and_bounded(self):
        stages = dict.fromkeys(
            [
                "open",
                "session_setup",
                "buffers",
                "metadata",
                "emitter",
                "warmup",
                "rate_fill",
                "frames",
                "session_release",
            ]
        )
        stages.update(open=120, session_setup=5500, warmup=4200)
        record = {
            "schema": 2,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "deadline_expired",
            "elapsed_ms": 5650,
            "capture_ms": 5648,
            "detection_ms": None,
            "pad_ms": None,
            "identity_ms": None,
            "capture_stages_ms": stages,
        }
        self.assertEqual(harness.checked_report(record), record)
        for invalid in [
            dict(stages, private_score=1),
            {"open": 1},
            dict(stages, open=True),
            dict(stages, open=-1),
            dict(stages, open=3_600_001),
            dict(stages, open="120"),
        ]:
            with self.assertRaises(ValueError):
                harness.checked_report(dict(record, capture_stages_ms=invalid))
        for invalid in [
            dict(record, schema=1),
            dict(record, schema=3),
            dict(record, authentication_granted=True),
        ]:
            with self.assertRaises(ValueError):
                harness.checked_report(invalid)

    def test_capture_failure_categories_accept_only_fixed_metadata(self):
        for category in [
            "camera_busy",
            "camera_rate_refused",
            "camera_lease_timeout",
            "camera_lease_refused",
            "camera_io_failed",
            "camera_hardware_failed",
            "camera_authorization_refused",
            "camera_policy_refused",
            "camera_capture_failed",
        ]:
            record = {
                "schema": 1,
                "operation": "ir_only_evaluation",
                "authentication_granted": False,
                "category": category,
                "elapsed_ms": 100,
                "capture_ms": 99,
                "detection_ms": None,
                "pad_ms": None,
                "identity_ms": None,
            }
            self.assertEqual(harness.checked_report(record), record)
            for extra in [
                dict(record, message="private"),
                dict(record, rate_evidence={}),
                dict(record, category="private error text"),
                dict(record, authentication_granted=True),
            ]:
                with self.assertRaises(ValueError):
                    harness.checked_report(extra)

    def test_records_successful_ir_open_and_close_without_other_paths(self):
        lines = [
            '123.000 openat(AT_FDCWD, "/dev/video2", O_RDWR) = 7</dev/video2>',
            "123.250 close(7</dev/video2>) = 0",
            '123.300 openat(AT_FDCWD, "/private/profile.json", O_RDONLY) = 4</private/profile.json>',
        ]
        events = [event for line in lines if (event := harness.video_event(line))]
        self.assertEqual(
            [(e["operation"], e["device"], e["result"]) for e in events],
            [("open", "/dev/video2", 7), ("close", "/dev/video2", 0)],
        )
        self.assertEqual(events[1]["timestamp"] - events[0]["timestamp"], 0.25)

    def test_character_device_annotations_from_yy_are_recognized(self):
        for line in [
            "[pid 200] 123.6 close(6</dev/video2<char 81:2>>) = 0",
            "[pid 200] 123.6 <... openat resumed>) = 6</dev/video2<char 81:2>>",
        ]:
            event = harness.video_event(line)
            self.assertIsNotNone(event)
            self.assertEqual(event["device"], "/dev/video2")

    def test_failed_rgb_attempt_remains_visible(self):
        event = harness.video_event(
            '[pid 200] 123.5 openat(AT_FDCWD, "/dev/video0", O_RDWR) = -1 EBUSY (Device or resource busy)'
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["result"], -1)

    def test_unfinished_and_resumed_calls_keep_evidence(self):
        event = harness.video_event(
            '[pid 200] 123.5 openat(AT_FDCWD, "/dev/video2", O_RDWR <unfinished ...>'
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["operation"], "open")
        self.assertEqual(
            harness.video_event(
                "[pid 200] 123.6 <... openat resumed>) = 6</dev/video2>"
            )["result"],
            6,
        )

    def test_rejects_nonvideo_and_path_prefix_lookalikes(self):
        for line in [
            '123 openat(AT_FDCWD, "/dev/video2-secret", O_RDONLY) = 4',
            "123 close(4</tmp/video2>) = 0",
            '123 read(4</dev/video2>, "private", 4) = 4',
        ]:
            self.assertIsNone(harness.video_event(line))

    def test_output_allows_only_categories_and_bounded_timings(self):
        record = {
            "schema": 1,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "candidate_match",
            "elapsed_ms": 123,
            "capture_ms": 20,
            "detection_ms": 30,
            "pad_ms": 40,
            "identity_ms": None,
        }
        self.assertEqual(harness.checked_report(record), record)
        for changed in [
            dict(record, authentication_granted=True),
            dict(record, embedding=[0.1]),
            dict(record, category="match Alice"),
            dict(record, elapsed_ms=-1),
            dict(record, pad_ms=float("nan")),
        ]:
            with self.assertRaises(ValueError):
                harness.checked_report(changed)


class ProcessTests(unittest.TestCase):
    def test_real_trace_omits_nonvideo_paths_and_stderr_content(self):
        record = {
            "schema": 1,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "ready",
            "elapsed_ms": 1,
            "capture_ms": None,
            "detection_ms": None,
            "pad_ms": None,
            "identity_ms": None,
        }
        code = (
            "import json,sys; open('/dev/null').close(); print('do not persist me',file=sys.stderr); print("
            + repr(json.dumps(record))
            + ")"
        )
        got = harness.run_traced([sys.executable, "-c", code], timeout=5)
        self.assertEqual(got["returncode"], 0)
        self.assertEqual(got["report"], record)
        self.assertEqual(got["video_events"], [])
        self.assertNotIn("do not persist me", json.dumps(got))

    def test_cooperative_stdin_cancellation_is_observed(self):
        record = {
            "schema": 1,
            "operation": "ir_only_evaluation",
            "authentication_granted": False,
            "category": "cancelled",
            "elapsed_ms": 1,
            "capture_ms": None,
            "detection_ms": None,
            "pad_ms": None,
            "identity_ms": None,
        }
        code = (
            "import sys; sys.stdin.buffer.read(1); print("
            + repr(json.dumps(record))
            + ")"
        )
        got = harness.run_traced(
            [sys.executable, "-c", code], cancel_after_ms=30, timeout=5
        )
        self.assertTrue(got["cancellation_sent"])
        self.assertFalse(got["watchdog_fired"])
        self.assertEqual(got["report"]["category"], "cancelled")

    def test_early_tracer_exit_cleans_descendant_held_pipes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracer = Path(tmp) / "tracer.py"
            tracer.write_text(
                "#!"
                + sys.executable
                + '\nimport subprocess,sys\nsubprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"])\n'
            )
            tracer.chmod(0o700)
            got = harness.run_traced(
                [sys.executable, "-c", "pass"], timeout=2, tracer=str(tracer)
            )
            self.assertTrue(got["early_tracer_exit"])
            self.assertTrue(got["readers_completed"])
            self.assertLess(got["wall_elapsed_ms"], 1500)

    def test_watchdog_reaps_stuck_child(self):
        got = harness.run_traced(
            [sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1
        )
        self.assertTrue(got["watchdog_fired"])
        self.assertIsNotNone(got["returncode"])
        self.assertIsNone(got["report"])


class TrialGateTests(unittest.TestCase):
    def result(self):
        return {
            "output_valid": True,
            "readers_completed": True,
            "watchdog_fired": False,
            "early_tracer_exit": False,
            "trace_error": False,
            "trace_overflow": False,
            "output_overflow": False,
            "installed_unchanged": True,
            "returncode": 0,
            "cancellation_sent": False,
            "report": {"category": "candidate_match"},
            "video_events": [
                {
                    "device": "/dev/video2",
                    "operation": "open",
                    "result": 6,
                    "fd": 6,
                    "timestamp": 1.0,
                },
                {
                    "device": "/dev/video2",
                    "operation": "close",
                    "result": 0,
                    "fd": 6,
                    "timestamp": 1.1,
                },
            ],
        }

    def test_only_complete_camera_trial_passes(self):
        result = self.result()
        self.assertTrue(harness.trial_checks(result, "genuine"))
        for bad in [
            dict(result, returncode=-6),
            dict(result, video_events=[]),
            dict(result, installed_unchanged=False),
            dict(result, early_tracer_exit=True),
        ]:
            self.assertFalse(harness.trial_checks(bad, "genuine"))
        result["video_events"].append(
            {
                "device": "/dev/video0",
                "operation": "open",
                "result": -1,
                "timestamp": 1.1,
            }
        )
        self.assertFalse(harness.trial_checks(result, "genuine"))

    def test_metadata_is_allowed_and_cancel_requires_cancelled_result(self):
        result = self.result()
        result["video_events"].extend(
            [
                {
                    "device": "/dev/video3",
                    "operation": "open",
                    "result": 7,
                    "fd": 7,
                    "timestamp": 1.1,
                },
                {
                    "device": "/dev/video3",
                    "operation": "close",
                    "result": 0,
                    "fd": 7,
                    "timestamp": 1.2,
                },
            ]
        )
        self.assertTrue(harness.trial_checks(result, "genuine"))
        self.assertFalse(harness.trial_checks(result, "cancel"))
        result.update(cancellation_sent=True, report={"category": "cancelled"})
        self.assertTrue(harness.trial_checks(result, "cancel"))

    def test_preflight_requires_ready_and_no_camera_opens(self):
        result = self.result()
        self.assertFalse(harness.trial_checks(result, "preflight"))
        result.update(video_events=[], report={"category": "ready"})
        self.assertTrue(harness.trial_checks(result, "preflight"))
        result["report"]["category"] = "enrollment_unavailable"
        self.assertFalse(harness.trial_checks(result, "preflight"))


if __name__ == "__main__":
    unittest.main()


class PortableRegressionTests(unittest.TestCase):
    def test_missing_stage_fields_is_not_valid_evidence(self):
        with self.assertRaises(ValueError):
            harness.checked_report(
                {
                    "schema": 1,
                    "operation": "ir_only_evaluation",
                    "authentication_granted": False,
                    "category": "ready",
                    "elapsed_ms": 1,
                }
            )

    def test_one_close_cannot_release_two_open_descriptors(self):
        result = TrialGateTests().result()
        result["video_events"].insert(
            1,
            {
                "device": "/dev/video2",
                "operation": "open",
                "result": 7,
                "fd": 7,
                "timestamp": 1.05,
            },
        )
        self.assertFalse(harness.trial_checks(result, "genuine"))


class StrictTraceTests(unittest.TestCase):
    def test_duplicate_output_keys_are_rejected_without_raw_output(self):
        raw = '{"schema":1,"operation":"ir_only_evaluation","authentication_granted":true,"authentication_granted":false,"category":"ready","elapsed_ms":1,"capture_ms":null,"detection_ms":null,"pad_ms":null,"identity_ms":null}'
        got = harness.run_traced(
            [sys.executable, "-c", "print(" + repr(raw) + ")"], timeout=5
        )
        self.assertFalse(got["output_valid"])
        self.assertIsNone(got["report"])

    def test_shared_fd_lifetimes_are_paired_and_never_reused(self):
        lines = [
            '[pid 200] 123.1 openat(AT_FDCWD, "/dev/video10", O_RDWR) = 6</dev/video10<char 81:10>>',
            "[pid 201] 123.2 close(6</dev/video10<char 81:10>>) = 0",
        ]
        events = [harness.video_event(line) for line in lines]
        self.assertTrue(harness.release_checks(events, "/dev/video10", "/dev/video11"))
        for tail in [[dict(events[1], fd=7)], [events[1], events[1]], []]:
            self.assertFalse(
                harness.release_checks(
                    [events[0], *tail], "/dev/video10", "/dev/video11"
                )
            )

    def test_real_fork_invalidates_shared_fd_assumption(self):
        code = (
            "import os; pid=os.fork(); os._exit(0) if pid == 0 else os.waitpid(pid,0)"
        )
        got = harness.run_traced([sys.executable, "-c", code], timeout=5)
        self.assertTrue(got["trace_error"])


class ResumedTraceTests(unittest.TestCase):
    def test_unfinished_calls_preserve_original_fd_and_thread_flags(self):
        lines = [
            "[pid 200] 123.0 clone(child_stack=NULL, flags=CLONE_FILES|CLONE_THREAD <unfinished ...>",
            "[pid 200] 123.1 <... clone resumed>) = 201",
            '[pid 201] 123.2 openat(AT_FDCWD, "/dev/video10", O_RDWR <unfinished ...>',
            "[pid 201] 123.3 <... openat resumed>) = 6</dev/video10<char 81:10>>",
            "[pid 201] 123.4 close(6</dev/video10<char 81:10>> <unfinished ...>",
            "[pid 201] 123.5 <... close resumed>) = 0",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            tracer = Path(tmp) / "tracer.py"
            tracer.write_text(
                "#!"
                + sys.executable
                + "\nimport sys\nfor line in "
                + repr(lines)
                + ": print(line,file=sys.stderr)\n"
            )
            tracer.chmod(0o700)
            got = harness.run_traced(["/unused"], timeout=5, tracer=str(tracer))
        self.assertFalse(got["trace_error"])
        self.assertTrue(
            harness.release_checks(got["video_events"], "/dev/video10", "/dev/video11")
        )
        self.assertEqual(len(got["video_events"]), 2)


class CleanupTests(unittest.TestCase):
    def test_selector_setup_interrupt_reaps_already_started_child(self):
        import subprocess
        from unittest.mock import patch

        children = []
        original = subprocess.Popen

        def spawned(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with (
            patch("harness.subprocess.Popen", side_effect=spawned),
            patch("harness.selectors.DefaultSelector", side_effect=KeyboardInterrupt()),
            self.assertRaises(KeyboardInterrupt),
        ):
            harness.run_traced(
                [sys.executable, "-c", "import time; time.sleep(10)"], timeout=5
            )
        self.assertIsNotNone(children[0].poll())


class DescriptorTableTests(unittest.TestCase):
    def test_unsharing_fd_table_invalidates_release_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracer = Path(tmp) / "tracer.py"
            tracer.write_text(
                "#!"
                + sys.executable
                + '\nimport sys\nprint("[pid 200] 123.0 unshare(CLONE_FILES) = 0",file=sys.stderr)\n'
            )
            tracer.chmod(0o700)
            got = harness.run_traced(["/unused"], timeout=5, tracer=str(tracer))
        self.assertTrue(got["trace_error"])
