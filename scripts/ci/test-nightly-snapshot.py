#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Nightly candidate contracts; no network, builds or hardware access."""

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import nightly_snapshot_github as github
import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "nightly_snapshot", HERE / "nightly-snapshot.py"
)
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class WorkflowContractTests(unittest.TestCase):
    def workflow(self, name):
        path = HERE.parents[1] / ".github" / "workflows" / name
        return yaml.load(path.read_text(), Loader=yaml.BaseLoader)

    def test_nightly_suite_runs_unconditionally_in_required_check(self):
        check = self.workflow("ci.yml")["jobs"]["check"]
        self.assertEqual(check["name"], "fmt · clippy · build · test")
        self.assertEqual(check["runs-on"], "ubuntu-24.04")
        steps = check["steps"]
        command = "python3 -B scripts/ci/test-nightly-snapshot.py"
        matching = [step for step in steps if step.get("run") == command]
        self.assertEqual(len(matching), 1)
        self.assertNotIn("if", matching[0])
        self.assertNotIn("continue-on-error", matching[0])
        index = steps.index(matching[0])
        self.assertTrue(
            any("python3-jsonschema" in step.get("run", "") for step in steps[:index])
        )
        model_step = next(
            i
            for i, step in enumerate(steps)
            if step.get("name") == "Cache model weights"
        )
        self.assertLess(index, model_step)

    def test_audit_observes_every_push_without_path_filtering(self):
        events = self.workflow("workflow-audit.yml")["on"]
        self.assertEqual(events["push"], {"branches": ["**"]})
        self.assertIn("workflow_dispatch", events)
        self.assertEqual(events["schedule"], [{"cron": "20 6 * * 2"}])

    def test_audit_gates_remain_read_only_unconditional_and_hosted(self):
        workflow = self.workflow("workflow-audit.yml")
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        names = set()
        for job in workflow["jobs"].values():
            self.assertEqual(job["runs-on"], "ubuntu-24.04")
            self.assertNotIn("if", job)
            self.assertNotIn("continue-on-error", job)
            self.assertNotIn("permissions", job)
            names.add(job["name"])
        self.assertEqual(
            names,
            {
                name
                for name, file in snapshot.CHECKS.items()
                if file == "workflow-audit.yml"
            },
        )


def observation():
    sha = "a" * 40
    return {
        "repository": snapshot.REPOSITORY,
        "ref": snapshot.REF,
        "commit": sha,
        "tree": "b" * 40,
        "main_after": sha,
        "slot": "2026-10-25",
        "observed_at": "2026-10-25T03:10:00Z",
        "required_checks": sorted(snapshot.REQUIRED),
        "inputs": [
            {"path": path, "blob": "c" * 40, "sha256": "d" * 64}
            for path in snapshot.INPUTS
        ],
        "checks": [
            {
                "name": name,
                "workflow": workflow,
                "commit": sha,
                "app_id": snapshot.ACTIONS_APP,
                "workflow_id": 100
                + list(dict.fromkeys(snapshot.CHECKS.values())).index(workflow),
                "run_id": 200
                + list(dict.fromkeys(snapshot.CHECKS.values())).index(workflow),
                "attempt": 1,
                "job_id": 300 + index,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-10-25T02:00:00Z",
            }
            for index, (name, workflow) in enumerate(snapshot.CHECKS.items())
        ],
    }


class DecisionTests(unittest.TestCase):
    def test_exact_complete_observation_selects_a_candidate_not_a_release(self):
        result = snapshot.decide(observation())
        self.assertEqual(result["outcome"], "selected")
        candidate = result["candidate"]
        self.assertEqual(candidate["kind"], "nightly-candidate")
        self.assertEqual(candidate["evidence_origin"], "fixture")
        self.assertEqual(candidate["commit"], "a" * 40)
        self.assertEqual(candidate["policy_version"], 1)
        snapshot.validate_candidate(candidate)

    def test_each_non_successful_required_check_holds(self):
        for name in snapshot.CHECKS:
            for conclusion in ["failure", "cancelled", "skipped", None]:
                with self.subTest(name=name, conclusion=conclusion):
                    data = observation()
                    next(c for c in data["checks"] if c["name"] == name)[
                        "conclusion"
                    ] = conclusion
                    self.assertEqual(snapshot.decide(data)["outcome"], "hold")

    def test_changed_main_or_required_policy_holds(self):
        for key, value in [("main_after", "f" * 40), ("required_checks", [])]:
            data = observation()
            data[key] = value
            self.assertEqual(snapshot.decide(data)["outcome"], "hold")

    def test_previous_identity_is_unchanged_but_new_same_slot_source_holds(self):
        previous = snapshot.decide(observation())["candidate"]
        self.assertEqual(
            snapshot.decide(observation(), previous)["outcome"], "unchanged"
        )
        data = observation()
        data["commit"] = data["main_after"] = "f" * 40
        for check in data["checks"]:
            check["commit"] = data["commit"]
        self.assertEqual(snapshot.decide(data, previous)["reason"], "slot-conflict")

    def test_missing_or_duplicate_checks_never_select(self):
        for checks in [observation()["checks"][:-1], observation()["checks"] * 2]:
            data = observation()
            data["checks"] = checks
            self.assertEqual(snapshot.decide(data)["outcome"], "hold")

    def test_spoofed_check_identity_never_selects(self):
        for field, value in [
            ("app_id", 1),
            ("commit", "f" * 40),
            ("workflow", "evil.yml"),
        ]:
            data = observation()
            data["checks"][0][field] = value
            self.assertEqual(snapshot.decide(data)["outcome"], "hold")

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            snapshot.load_json(b'{"commit": "a", "commit": "b"}')

    def test_input_inventory_and_candidate_schema_are_strict(self):
        data = observation()
        data["inputs"].pop()
        with self.assertRaises(ValueError):
            snapshot.decide(data)
        candidate = snapshot.decide(observation())["candidate"]
        altered = copy.deepcopy(candidate)
        altered["published"] = True
        with self.assertRaises(ValueError):
            snapshot.validate_candidate(altered)

    def test_fractional_utc_times_and_integer_identifiers(self):
        data = observation()
        data["checks"][0]["completed_at"] = "2026-10-25T02:00:00.123Z"
        self.assertEqual(snapshot.decide(data)["outcome"], "selected")
        data["checks"][0]["attempt"] = True
        with self.assertRaises(ValueError):
            snapshot.decide(data)

    def test_previous_candidate_cannot_change_evidence_origin(self):
        previous = snapshot.decide(observation())["candidate"]
        with self.assertRaisesRegex(ValueError, "origin"):
            snapshot.decide(observation(), previous, origin="github-api")

    def test_previous_slot_order_and_changed_source_on_next_day(self):
        previous = snapshot.decide(observation())["candidate"]
        data = observation()
        data.update(slot="2026-10-26", observed_at="2026-10-26T03:10:00Z")
        self.assertEqual(snapshot.decide(data, previous)["outcome"], "unchanged")
        data["commit"] = data["main_after"] = "f" * 40
        for check in data["checks"]:
            check["commit"] = data["commit"]
        selected = snapshot.decide(data, previous)
        self.assertEqual(selected["outcome"], "selected")
        self.assertEqual(
            snapshot.decide(observation(), selected["candidate"])["reason"],
            "slot-regression",
        )

    def test_bad_dates_inputs_and_json_are_rejected(self):
        for payload in [
            b'{"n":NaN}',
            b'{"n":Infinity}',
            b"\xff",
            b"[" * 2000,
            b" " * (snapshot.LIMIT + 1),
        ]:
            with self.subTest(payload=payload[:20]), self.assertRaises(ValueError):
                snapshot.load_json(payload)
        for field, value in [
            ("repository", "other/irlume"),
            ("commit", "a" * 12),
            ("slot", "2026-02-30"),
            ("slot", "2026-10-26"),
            ("observed_at", "2026-10-25T03:10:00+00:00"),
        ]:
            data = observation()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                snapshot.decide(data)
        data = observation()
        data["inputs"][0]["sha256"] = "invalid"
        with self.assertRaises(ValueError):
            snapshot.decide(data)

    def test_future_check_and_mixed_attempts_hold(self):
        data = observation()
        data["checks"][0]["completed_at"] = "2026-10-25T04:00:00Z"
        self.assertEqual(snapshot.decide(data)["reason"], "future-check")
        data = observation()
        data["checks"][0]["attempt"] = 2
        self.assertEqual(snapshot.decide(data)["reason"], "mixed-workflow-attempts")


class FakeGithub(github.Github):
    def __init__(self):
        self.calls = []
        self.heads = ["a" * 40, "a" * 40]
        self.routes = {}
        base = github.BASE
        self.routes[base + "/git/commits/" + "a" * 40] = {
            "sha": "a" * 40,
            "tree": {"sha": "b" * 40},
        }
        self.routes[base + "/branches/main/protection/required_status_checks"] = {
            "strict": True,
            "contexts": sorted(snapshot.REQUIRED),
            "checks": [
                {"context": n, "app_id": snapshot.ACTIONS_APP}
                for n in snapshot.REQUIRED
            ],
        }
        self.routes[base + "/rules/branches/main"] = [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": snapshot.REQUIRED[0]}]
                },
            }
        ]
        data = observation()
        for workflow in set(snapshot.CHECKS.values()):
            checks = [c for c in data["checks"] if c["workflow"] == workflow]
            first = checks[0]
            run_id = first["run_id"]
            path = ".github/workflows/" + workflow
            self.routes[base + "/actions/workflows/" + workflow] = {
                "id": first["workflow_id"],
                "path": path,
                "state": "active",
            }
            self.routes[base + "/actions/workflows/" + workflow + "/runs"] = {
                "total_count": 1,
                "workflow_runs": [
                    {
                        "id": run_id,
                        "workflow_id": first["workflow_id"],
                        "path": path,
                        "run_number": 1,
                        "run_attempt": 1,
                        "check_suite_id": run_id + 1000,
                        "event": "push",
                        "head_branch": "main",
                        "head_sha": "a" * 40,
                        "repository": {"full_name": snapshot.REPOSITORY},
                        "head_repository": {"full_name": snapshot.REPOSITORY},
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            }
            jobs = []
            for check in checks:
                job = {
                    "id": check["job_id"],
                    "name": check["name"],
                    "run_id": run_id,
                    "run_attempt": 1,
                    "head_sha": "a" * 40,
                    "status": "completed",
                    "conclusion": "success",
                    "completed_at": check["completed_at"],
                    "check_run_url": github.API
                    + base
                    + "/check-runs/"
                    + str(check["job_id"]),
                }
                jobs.append(job)
                self.routes[base + "/check-runs/" + str(check["job_id"])] = {
                    "id": check["job_id"],
                    "name": check["name"],
                    "head_sha": "a" * 40,
                    "app": {"id": snapshot.ACTIONS_APP},
                    "check_suite": {"id": run_id + 1000},
                    "status": "completed",
                    "conclusion": "success",
                }
            self.routes[base + f"/actions/runs/{run_id}/attempts/1/jobs"] = {
                "total_count": len(jobs),
                "jobs": jobs,
            }
        for path in snapshot.INPUTS:
            content = path.encode()
            blob = hashlib.sha1(
                b"blob " + str(len(content)).encode() + b"\0" + content,
                usedforsecurity=False,
            ).hexdigest()
            self.routes[base + "/contents/" + path] = {
                "type": "file",
                "path": path,
                "sha": blob,
                "size": len(content),
                "encoding": "base64",
                "content": base64.b64encode(content).decode(),
            }

    def get(self, path, query=None):
        self.calls.append((path, query))
        if path == github.BASE + "/git/ref/heads/main":
            return {
                "ref": snapshot.REF,
                "object": {"type": "commit", "sha": self.heads.pop(0)},
            }
        return copy.deepcopy(self.routes[path])


class CollectorTests(unittest.TestCase):
    def collect(self, api):
        return github.collect(
            api, snapshot.POLICY, "2026-10-25", "2026-10-25T03:10:00Z"
        )

    def test_real_collection_shape_selects_and_never_uses_a_mutating_endpoint(self):
        api = FakeGithub()
        data = self.collect(api)
        self.assertEqual(
            snapshot.decide(data, origin="github-api")["outcome"], "selected"
        )
        self.assertTrue(
            all(path.startswith(github.BASE + "/") for path, _ in api.calls)
        )

    def test_newer_pending_run_cannot_fall_back_to_an_older_success(self):
        api = FakeGithub()
        page = api.routes[github.BASE + "/actions/workflows/ci.yml/runs"]
        newer = copy.deepcopy(page["workflow_runs"][0])
        newer.update(id=999, run_number=2, status="in_progress", conclusion=None)
        page["workflow_runs"].append(newer)
        page["total_count"] = 2
        with self.assertRaises(github.Hold):
            self.collect(api)

    def test_check_app_and_commit_must_match_job_and_run(self):
        for field, value in [("app", {"id": 9}), ("head_sha", "f" * 40)]:
            api = FakeGithub()
            api.routes[github.BASE + "/check-runs/300"][field] = value
            with self.assertRaises(github.Hold):
                self.collect(api)

    def test_changed_head_and_changed_required_policy_hold(self):
        api = FakeGithub()
        api.heads[-1] = "f" * 40
        data = self.collect(api)
        self.assertEqual(snapshot.decide(data)["reason"], "main-moved")
        api = FakeGithub()
        api.routes[github.BASE + "/rules/branches/main"][0]["parameters"][
            "required_status_checks"
        ].append({"context": "new gate"})
        with self.assertRaises(github.Hold):
            self.collect(api)

    def test_corrupt_source_blob_is_rejected(self):
        api = FakeGithub()
        api.routes[github.BASE + "/contents/Cargo.lock"]["sha"] = "f" * 40
        with self.assertRaises(ValueError):
            self.collect(api)

    def test_incomplete_or_duplicate_pages_fail_instead_of_truncating(self):
        api = FakeGithub()
        path = github.BASE + "/actions/workflows/ci.yml/runs"
        api.routes[path]["total_count"] = 2
        with self.assertRaises(ValueError):
            api.pages(path, "workflow_runs")

    def test_run_attempt_change_during_collection_holds(self):
        api = FakeGithub()
        original = api.get
        calls = 0

        def changed(path, query=None):
            nonlocal calls
            result = original(path, query)
            if path.endswith("/ci.yml/runs"):
                calls += 1
                if calls == 2:
                    result["workflow_runs"][0]["run_attempt"] = 2
            return result

        api.get = changed
        with self.assertRaisesRegex(github.Hold, "changed"):
            self.collect(api)

    def test_api_rejects_off_host_paths_before_any_request(self):
        api = github.Github(snapshot.load_json)
        for path in [
            "https://evil.test/token",
            "/repos/other/repo/runs",
            github.BASE + "/../secret",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                api.get(path)

    def test_pagination_full_final_page_and_boundary(self):
        api = github.Github(snapshot.load_json)
        api.get = Mock(
            side_effect=[
                {"total_count": 101, "jobs": [{"id": i} for i in range(1, 101)]},
                {"total_count": 101, "jobs": [{"id": 101}]},
            ]
        )
        self.assertEqual(len(api.pages(github.BASE + "/jobs", "jobs")), 101)
        self.assertEqual(api.get.call_args.args[1]["page"], 2)
        for count, rows in [
            (1000, []),
            (1, []),
            (0, [{"id": 1}]),
            (2, [{"id": 1}, {"id": 1}]),
            (True, [{"id": 1}]),
        ]:
            api.get = Mock(return_value={"total_count": count, "jobs": rows})
            with self.subTest(count=count), self.assertRaises(ValueError):
                api.pages(github.BASE + "/jobs", "jobs")
        api.get = Mock(
            side_effect=[
                {"total_count": 101, "jobs": [{"id": i} for i in range(1, 101)]},
                {"total_count": 102, "jobs": [{"id": 101}, {"id": 102}]},
            ]
        )
        with self.assertRaises(ValueError):
            api.pages(github.BASE + "/jobs", "jobs")

    def test_api_get_is_bounded_and_does_not_expose_tokens(self):
        api = github.Github(snapshot.load_json)
        api.opener = Mock()
        api.opener.open.return_value = io.BytesIO(b'{"ok":true}')
        with patch.dict(os.environ, {"GH_TOKEN": "synthetic-test-token"}):
            self.assertEqual(api.get(github.BASE + "/jobs"), {"ok": True})
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.assertNotIn("synthetic-test-token", request.full_url)
        self.assertLessEqual(api.opener.open.call_args.kwargs["timeout"], 20)
        api.requests = 80
        with self.assertRaisesRegex(ValueError, "budget"):
            api.get(github.BASE + "/jobs")
        api.requests = 0
        api.deadline = 0
        with self.assertRaisesRegex(ValueError, "budget"):
            api.get(github.BASE + "/jobs")

    def test_api_size_timeout_and_error_bodies_fail_closed(self):
        for body in [b" " * (github.LIMIT + 1), b'{"x":1,"x":2}', b"not-json"]:
            api = github.Github(snapshot.load_json)
            api.opener = Mock()
            api.opener.open.return_value = io.BytesIO(body)
            with self.subTest(body=body[:20]), self.assertRaises(ValueError):
                api.get(github.BASE + "/jobs")
        for error in [
            TimeoutError("private detail"),
            urllib.error.URLError("private detail"),
            urllib.error.HTTPError("private url", 403, "private detail", {}, None),
        ]:
            api = github.Github(snapshot.load_json)
            api.opener = Mock()
            api.opener.open.side_effect = error
            with (
                self.subTest(error=type(error).__name__),
                self.assertRaises(ValueError) as raised,
            ):
                api.get(github.BASE + "/jobs")
            self.assertNotIn("private", str(raised.exception))
        with self.assertRaisesRegex(ValueError, "redirect"):
            github.NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://other.test"
            )

    def test_missing_wrong_or_ambiguous_runs_hold(self):
        path = github.BASE + "/actions/workflows/ci.yml/runs"
        for field, value in [
            ("head_sha", "f" * 40),
            ("event", "pull_request"),
            ("repository", {"full_name": "other/irlume"}),
            ("conclusion", "cancelled"),
        ]:
            api = FakeGithub()
            api.routes[path]["workflow_runs"][0][field] = value
            with self.subTest(field=field), self.assertRaises(github.Hold):
                self.collect(api)
        api = FakeGithub()
        api.routes[path] = {"total_count": 0, "workflow_runs": []}
        with self.assertRaises(github.Hold):
            self.collect(api)
        api = FakeGithub()
        other = copy.deepcopy(api.routes[path]["workflow_runs"][0])
        other["id"] = 999
        api.routes[path]["workflow_runs"].append(other)
        api.routes[path]["total_count"] = 2
        with self.assertRaises(github.Hold):
            self.collect(api)

    def test_jobs_cannot_mix_attempts_suites_or_response_urls(self):
        path = github.BASE + "/actions/runs/200/attempts/1/jobs"
        for field, value in [
            ("run_id", 999),
            ("run_attempt", 2),
            ("run_attempt", True),
            ("conclusion", "skipped"),
            ("check_run_url", "https://other.test/token"),
        ]:
            api = FakeGithub()
            api.routes[path]["jobs"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.collect(api)
        api = FakeGithub()
        api.routes[github.BASE + "/check-runs/300"]["check_suite"] = {"id": 999}
        with self.assertRaises(github.Hold):
            self.collect(api)
        api = FakeGithub()
        for job in api.routes[path]["jobs"]:
            del job["run_attempt"]
        self.assertEqual(snapshot.decide(self.collect(api))["outcome"], "selected")

    def test_classic_app_binding_cannot_be_removed(self):
        api = FakeGithub()
        path = github.BASE + "/branches/main/protection/required_status_checks"
        api.routes[path]["checks"][0]["app_id"] = None
        with self.assertRaises(github.Hold):
            self.collect(api)

    def test_source_queries_are_pinned_and_verify_both_hashes(self):
        api = FakeGithub()
        data = self.collect(api)
        for path, query in api.calls:
            if "/contents/" in path:
                self.assertEqual(query, {"ref": "a" * 40})
        for item in data["inputs"]:
            self.assertEqual(
                item["sha256"], hashlib.sha256(item["path"].encode()).hexdigest()
            )
        for field, value in [
            ("encoding", "none"),
            ("content", "!invalid!"),
            ("size", 999),
            ("type", "dir"),
        ]:
            api = FakeGithub()
            api.routes[github.BASE + "/contents/Cargo.lock"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.collect(api)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nightly snapshot ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = snapshot.decide(observation())["candidate"]

    def test_candidate_output_is_private_and_idempotent(self):
        path = self.root / "candidate.json"
        snapshot.write_candidate(path, self.candidate)
        original = path.read_bytes()
        later = copy.deepcopy(self.candidate)
        later["observed_at"] = "2026-10-25T03:20:00Z"
        self.assertEqual(snapshot.write_candidate(path, later), self.candidate)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_conflicting_or_symlink_output_is_not_overwritten(self):
        path = self.root / "candidate.json"
        path.write_text("preserve me")
        with self.assertRaises(ValueError):
            snapshot.write_candidate(path, self.candidate)
        self.assertEqual(path.read_text(), "preserve me")
        alias = self.root / "alias"
        alias.symlink_to(path)
        with self.assertRaises((ValueError, OSError)):
            snapshot.write_candidate(alias, self.candidate)
        self.assertEqual(path.read_text(), "preserve me")

    def test_failed_publication_leaves_no_partial_candidate(self):
        path = self.root / "candidate.json"
        with (
            patch.object(snapshot.os, "link", side_effect=OSError("synthetic")),
            self.assertRaises(OSError),
        ):
            snapshot.write_candidate(path, self.candidate)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_fsync_preserves_existing_file_and_cleans_temporary(self):
        path = self.root / "candidate.json"
        path.write_bytes(b"existing complete record")
        with (
            patch.object(snapshot.os, "fsync", side_effect=OSError("synthetic")),
            self.assertRaises(OSError),
        ):
            snapshot.write_candidate(path, self.candidate)
        self.assertEqual(path.read_bytes(), b"existing complete record")
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_same_slot_different_source_is_never_overwritten(self):
        path = self.root / "candidate.json"
        snapshot.write_candidate(path, self.candidate)
        original = path.read_bytes()
        other = copy.deepcopy(self.candidate)
        other["tree"] = "e" * 40
        with self.assertRaisesRegex(ValueError, "conflict"):
            snapshot.write_candidate(path, other)
        self.assertEqual(path.read_bytes(), original)

    def test_writable_output_directory_is_refused(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "directory"):
            snapshot.write_candidate(self.root / "candidate.json", self.candidate)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_previous_is_rejected_before_collection(self):
        previous = self.root / "previous.json"
        previous.write_text("{}")
        with (
            patch.object(
                github, "collect", side_effect=github.Hold("missing-workflow-run")
            ) as collect,
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(
                snapshot.main(["--collect", "--previous", str(previous)]), 2
            )
        collect.assert_not_called()

    def test_live_cli_output_and_fixture_provenance_cannot_be_overridden(self):
        path = self.root / "candidate.json"
        now = snapshot.timestamp("2026-10-25T03:10:00Z")
        with (
            patch.object(github, "collect", return_value=observation()),
            patch.object(snapshot, "datetime", wraps=snapshot.datetime) as clock,
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            clock.now.return_value = now
            self.assertEqual(snapshot.main(["--collect", "--output", str(path)]), 0)
        candidate = json.loads(output.getvalue())["candidate"]
        self.assertEqual(candidate["evidence_origin"], "github-api")
        self.assertEqual(json.loads(path.read_text()), candidate)
        data = observation()
        data["evidence_origin"] = "github-api"
        with self.assertRaises(ValueError):
            snapshot.decide(data)

    def test_malformed_check_exits_two_regardless_of_failed_check_order(self):
        fixture = self.root / "observation.json"
        for reverse in (False, True):
            data = observation()
            data["checks"][0]["conclusion"] = "failure"
            data["checks"][1]["unexpected"] = "not allowed"
            if reverse:
                data["checks"].reverse()
            fixture.write_text(json.dumps(data))
            with (
                self.subTest(reverse=reverse),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(snapshot.main(["--fixture", str(fixture)]), 2)

    def test_failed_or_incomplete_checks_preserve_previous_output(self):
        previous = self.root / "candidate.json"
        fixture = self.root / "observation.json"
        snapshot.write_candidate(previous, self.candidate)
        saved = previous.read_bytes()
        for failure in ("failed", "incomplete"):
            data = observation()
            if failure == "failed":
                data["checks"][0]["conclusion"] = "failure"
            else:
                data["checks"].pop()
            fixture.write_text(json.dumps(data))
            with (
                self.subTest(failure=failure),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                self.assertEqual(
                    snapshot.main(
                        [
                            "--fixture",
                            str(fixture),
                            "--previous",
                            str(previous),
                            "--output",
                            str(previous),
                        ]
                    ),
                    0,
                )
            self.assertEqual(json.loads(output.getvalue())["outcome"], "hold")
            self.assertEqual(previous.read_bytes(), saved)

    def test_cli_selected_hold_and_invalid_input(self):
        fixture = self.root / "observation.json"
        output = self.root / "candidate.json"

        def run(value):
            fixture.write_text(json.dumps(value))
            return subprocess.run(
                [
                    sys.executable,
                    str(HERE / "nightly-snapshot.py"),
                    "--fixture",
                    str(fixture),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        data = observation()
        data["checks"].pop()
        held = run(data)
        self.assertEqual(held.returncode, 0, held.stderr)
        self.assertEqual(json.loads(held.stdout)["outcome"], "hold")
        self.assertFalse(output.exists())
        selected = run(observation())
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(
            json.loads(selected.stdout)["candidate"]["evidence_origin"], "fixture"
        )
        saved = output.read_bytes()
        bad = run({"secret": "must-not-appear"})
        self.assertNotEqual(bad.returncode, 0)
        self.assertNotIn("must-not-appear", bad.stdout + bad.stderr)
        self.assertEqual(output.read_bytes(), saved)

    def test_fixture_fifo_is_refused_without_blocking(self):
        path = self.root / "pipe"
        os.mkfifo(path)
        result = subprocess.run(
            [sys.executable, str(HERE / "nightly-snapshot.py"), "--fixture", str(path)],
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
