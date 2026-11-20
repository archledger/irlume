"""Keep registration limited to one unsigned, manually dispatched job."""
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import unittest

import yaml

from routing import JOBS


TOOLS = Path(__file__).resolve().parent
WORKFLOW = TOOLS.parents[2] / ".github/workflows/litert-runtime-provenance.yml"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        self.rebuild = self.workflow["jobs"]["rebuild"]

    def test_only_manual_unsigned_rebuild_is_registered(self):
        self.assertEqual(self.workflow["on"], {"workflow_dispatch": ""})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(self.workflow["jobs"]), {"rebuild"})
        self.assertEqual(JOBS, {"Rebuild on minihost"})
        self.assertEqual(self.rebuild["name"], "Rebuild on minihost")
        self.assertNotIn("permissions", self.rebuild)
        self.assertNotIn("outputs", self.rebuild)
        self.assertEqual(self.rebuild["runs-on"], ["self-hosted", "Linux", "X64", "n100"])
        actions = [step for step in self.rebuild["steps"] if "uses" in step]
        self.assertEqual(len(actions), 1)
        self.assertRegex(actions[0]["uses"], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertEqual(actions[0]["with"], {
            "ref": "${{ github.sha }}", "persist-credentials": "false",
        })

    def test_runner_and_protected_ref_are_checked_before_checkout(self):
        self.assertEqual(" ".join(self.rebuild["if"].split()), (
            "github.repository == 'archledger/irlume' && "
            "github.repository_id == '1286828818' && "
            "github.ref == 'refs/heads/main' && github.ref_protected"
        ))
        guard = self.rebuild["steps"][0]
        self.assertIn("run", guard)
        self.assertNotIn("uses", guard)
        env = {
            "GITHUB_REPOSITORY": "archledger/irlume", "GITHUB_REPOSITORY_ID": "1286828818",
            "GITHUB_REF": "refs/heads/main", "REF_PROTECTED": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "RUNNER_NAME": "minihost", "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
        }
        argv = ["/bin/bash", "-c", guard["run"]]
        self.assertEqual(subprocess.run(argv, env=env, timeout=5).returncode, 0)
        for key, wrong in (("GITHUB_EVENT_NAME", "pull_request"), ("RUNNER_NAME", "archhost"),
                           ("GITHUB_REF", "refs/heads/other"), ("REF_PROTECTED", "false")):
            with self.subTest(key=key):
                self.assertNotEqual(subprocess.run(argv, env=env | {key: wrong}, timeout=5).returncode, 0)

    def test_reviewed_scope_and_actual_invocation(self):
        build = self.rebuild["steps"][-1]
        self.assertEqual(self.rebuild["timeout-minutes"], "70")
        self.assertEqual(build["timeout-minutes"], "68")
        self.assertIn('[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]]', build["run"])
        self.assertIn("scripts/ci/litert-provenance", build["run"])
        self.assertIn('"$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"', build["run"])
        self.assertNotIn("RUNNER_TEMP", build["run"])
        for step in self.rebuild["steps"]:
            self.assertNotIn("${{", step.get("run", ""))
        bridge = (TOOLS / "run-minihost-workflow.sh").read_text()
        for reviewed in ("RuntimeMaxSec=3900s", "CPUQuota=200%", "MemoryMax=3500M",
                         "MemorySwapMax=0", "minihost-platform.sha256", "staged-bounded-v2"):
            self.assertIn(reviewed, bridge)

    def test_build_log_and_validated_handoff_stay_in_private_run_directory(self):
        bridge = (TOOLS / "run-minihost-workflow.sh").read_text()
        self.assertIn('root=$t/github-replay-$2-$3', bridge)
        self.assertIn('> "$root/rebuild.log" 2>&1', bridge)
        self.assertIn('check-handoff "$root/handoff" "$1" "$2" "$3"', bridge)
        self.assertNotIn("runner_temp", bridge)

    def test_verifier_fixtures_are_run_in_the_hosted_ci_check(self):
        ci = yaml.load(WORKFLOW.with_name("ci.yml").read_text(), Loader=yaml.BaseLoader)
        check = ci["jobs"]["check"]
        self.assertEqual(check["runs-on"], "ubuntu-24.04")
        command = "python3 -E -B -m unittest discover -s scripts/ci/litert-provenance -p 'test_*.py' -v"
        self.assertTrue(any(step.get("run") == command and "if" not in step
                            for step in check["steps"]), "missing hosted LiteRT contract check")

    def test_scope_guard_accepts_nested_systemd_user_manager_path(self):
        lines = (TOOLS / "run-minihost-workflow.sh").read_text().splitlines()
        stop = lines.index('        || fail "controlled build scope missing"')
        guard = "\n".join(lines[stop - 1:stop + 1])
        check = ('fail() { exit 78; }\nscope=$1\n' + guard
                 + '\nprintf "%s" "${BASH_REMATCH[1]}"')
        path = "/user.slice/user-1000.slice/user@1000.service/app.slice/" \
               "irlume-litert-unsigned-bounded-build-247.scope"
        argv = ["/bin/bash", "-ec", check, "test"]
        valid = subprocess.run(argv + ["0::" + path], capture_output=True, text=True, timeout=5)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(valid.stdout, path)
        for wrong in (path.replace("/user.slice/", "/system.slice/", 1),
                      path.replace("bounded-build-247", "unrelated-247"), path + "/child"):
            with self.subTest(path=wrong):
                result = subprocess.run(argv + ["0::" + wrong], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 78, result.stderr)

    def test_scope_collection_waits_for_removal_but_refuses_an_error_or_stuck_unit(self):
        bridge = (TOOLS / "run-minihost-workflow.sh").read_text()
        fail = re.search(r"^fail\(\) .+$", bridge, re.M)
        wait = re.search(r"^wait_for_scope_collection\(\) \{\n.*?^\}", bridge, re.M | re.S)
        self.assertIsNotNone(wait)
        self.assertIn('wait_for_scope_collection "${user_bus[@]}" systemctl --user list-units', bridge)
        fixture = """
            timeout() { shift; "$@"; }
            sleep() {
                if [[ $1 != 0.1 ]]; then exit 2; fi
                SECONDS=$((SECONDS + 1))
            }
            inventory() {
                case $mode in
                    failed) return 7 ;;
                    stuck) printf 'still loaded\\n' ;;
                    settling)
                        if [[ ! -e $marker ]]; then
                            : > "$marker"
                            printf 'still loaded\\n'
                        fi
                        ;;
                esac
            }
            mode=$1 marker=$2
            wait_for_scope_collection inventory
        """
        with TemporaryDirectory() as tmp:
            script = "\n".join((fail[0], wait[0], fixture))
            for mode, status in (("settling", 0), ("failed", 78), ("stuck", 78)):
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        ["/bin/bash", "-ec", script, "test", mode, f"{tmp}/marker"],
                        capture_output=True, text=True, timeout=4,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)

    def test_unprovisioned_or_unreviewed_materials_refuse_before_rebuild(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "no-rebuild"
            argv = ["bash", str(TOOLS / "run-unsigned.sh"), str(root), str(out)]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 78)
            self.assertFalse(out.exists())
            (root / "bundle").mkdir()
            (root / "packages").mkdir()
            (root / "storage.conf").touch()
            (root / "bundle/REVIEW-SHA256SUMS").write_text("stale\n")
            result = subprocess.run(argv, capture_output=True, text=True, timeout=8)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest pin mismatch", result.stderr)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
