"""Keep the manually registered preview workflow within its reviewed scope."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml


WORKFLOWS = Path(__file__).resolve().parents[3] / ".github/workflows"
PREVIEW = WORKFLOWS / "litert-preview-build.yml"
ENV = {
    "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "REF_PROTECTED",
    "RUNNER_NAME", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH",
}


class PreviewWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(PREVIEW.read_text(), Loader=yaml.BaseLoader)
        self.jobs = self.workflow["jobs"]

    def bootstrap(self, role):
        script = self.jobs[role]["steps"][0]["run"]
        delimiter = "exec /usr/bin/python3 -I -S -B - <<'PY'\n"
        self.assertIn(delimiter, script)
        code = script.split(delimiter, 1)[1].removesuffix("PY\n")
        namespace = {"__name__": "preview_workflow_fixture"}
        exec(compile(code, str(PREVIEW), "exec"), namespace)
        return namespace

    def test_registration_is_manual_build_only_and_jobs_are_ordered(self):
        self.assertEqual(self.workflow["on"], {"workflow_dispatch": ""})
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(set(self.jobs), {"runtime", "assembly"})
        self.assertNotIn("needs", self.jobs["runtime"])
        self.assertEqual(self.jobs["assembly"]["needs"], "runtime")
        self.assertRegex(self.workflow["env"]["PREVIEW_BRIDGE_SHA256"], r"^[a-f0-9]{64}$")
        for role, job, step in (("runtime", 70, 68), ("assembly", 10, 7)):
            current = self.jobs[role]
            self.assertEqual(current["runs-on"], ["self-hosted", "Linux", "X64", "n100"])
            self.assertNotIn("permissions", current)
            self.assertEqual(" ".join(current["if"].split()), (
                "github.repository == 'archledger/irlume' && "
                "github.repository_id == '1286828818' && github.repository_owner_id == '276915572' && "
                "github.ref == 'refs/heads/main' && github.ref_protected && "
                "github.event_name == 'workflow_dispatch' && github.run_attempt == 1"
            ))
            self.assertEqual(current["timeout-minutes"], str(job))
            self.assertEqual(len(current["steps"]), 1)
            build = current["steps"][0]
            self.assertEqual(build["timeout-minutes"], str(step))
            self.assertEqual(build["env"], {"REF_PROTECTED": "${{ github.ref_protected }}", "PREVIEW_ROLE": role})
            self.assertNotIn("uses", build)
            self.assertNotIn("${{", build["run"])
        self.assertEqual(self.jobs["runtime"]["steps"][0]["run"], self.jobs["assembly"]["steps"][0]["run"])
        self.assertEqual(set(self.bootstrap("runtime")["PASSTHROUGH"]), ENV)

    def test_wrong_runner_is_rejected_before_bridge_access_in_both_jobs(self):
        for role in self.jobs:
            script = self.jobs[role]["steps"][0]["run"]
            for wrong in ({"RUNNER_NAME": "archhost"}, {"RUNNER_ENVIRONMENT": "github-hosted"}):
                with self.subTest(role=role, wrong=wrong):
                    env = {
                        "RUNNER_NAME": "minihost", "RUNNER_ENVIRONMENT": "self-hosted",
                        "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "PREVIEW_ROLE": role,
                    } | wrong
                    result = subprocess.run(["/usr/bin/bash", "-ec", script], env=env,
                                            capture_output=True, text=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("requires the Minihost runner", result.stderr)

    def test_verified_copy_is_sealed_and_independent_of_its_source(self):
        make_bridge = self.bootstrap("runtime")["verified_bridge"]
        body = b'printf "%s\\n" "$1:$2:$3"\n'
        with TemporaryDirectory() as root:
            source = Path(root) / "bridge"
            source.write_bytes(body)
            sealed = make_bridge(source, hashlib.sha256(body).hexdigest())
            self.addCleanup(os.close, sealed)
            source.write_bytes(b"# different bytes\n")
            with self.assertRaises(OSError) as raised:
                os.write(sealed, b"x")
            self.assertEqual(raised.exception.errno, errno.EPERM)
            result = subprocess.run(["/usr/bin/bash", f"/proc/self/fd/{sealed}", "assembly", "head", "123"],
                                    pass_fds=(sealed,), capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(result.stdout, "assembly:head:123\n")

    def test_dispatch_executes_only_the_pinned_descriptor_with_clean_environment(self):
        for role in self.jobs:
            with self.subTest(role=role):
                code = self.bootstrap(role)
                code["verified_bridge"] = Mock(return_value=7)
                env = dict.fromkeys(ENV, "fixture") | {
                    "RUNNER_NAME": "minihost", "RUNNER_ENVIRONMENT": "self-hosted",
                    "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "PREVIEW_ROLE": role,
                    "PREVIEW_BRIDGE_SHA256": "a" * 64, "GITHUB_SHA": "b" * 40, "GITHUB_RUN_ID": "123",
                    "GITHUB_TOKEN": "fixture-must-not-pass",
                }
                with (patch.dict(os.environ, env, clear=True),
                      patch.object(os, "uname", return_value=SimpleNamespace(nodename="minihost")),
                      patch.object(os, "geteuid", return_value=1000),
                      patch.object(os, "set_inheritable") as inherit,
                      patch.object(os, "execve") as launch):
                    code["main"]()
                self.assertEqual(code["verified_bridge"].call_args.args[1], "a" * 64)
                inherit.assert_called_once_with(7, True)
                launch.assert_called_once_with(
                    "/usr/bin/bash", ["/usr/bin/bash", "/proc/self/fd/7", role, "b" * 40, "123"],
                    {name: env[name] for name in ENV} |
                    {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PREVIEW_BRIDGE_FD": "7"},
                )

    def test_refuses_unreviewed_oversize_or_nonregular_bridge(self):
        make_bridge = self.bootstrap("assembly")["verified_bridge"]
        with TemporaryDirectory() as root:
            source = Path(root) / "bridge"
            source.write_bytes(b"unreviewed")
            with self.assertRaisesRegex(ValueError, "digest"):
                make_bridge(source, hashlib.sha256(b"reviewed").hexdigest())
            source.write_bytes(b"x" * (65 * 1024))
            with self.assertRaisesRegex(ValueError, "size"):
                make_bridge(source, hashlib.sha256(source.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError, "regular"):
                make_bridge(Path(root), "b" * 64)
