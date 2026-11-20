"""Synthetic records check the required same-run GitHub routing policy."""

from copy import deepcopy
import unittest

from routing import JOBS, verify_routing


SHA = "a" * 40
RUN = "12345"
ATTEMPT = "2"


def fixtures():
    run = {
        "id": int(RUN), "run_attempt": int(ATTEMPT), "event": "workflow_dispatch",
        "head_branch": "main", "head_sha": SHA, "path": ".github/workflows/litert-runtime-provenance.yml",
        "status": "completed", "conclusion": "success",
        "repository": {"id": 1286828818, "full_name": "archledger/irlume", "owner": {"id": 276915572}},
    }
    jobs = {"total_count": len(JOBS), "jobs": [
        {"id": index, "name": name, "runner_id": 22, "runner_name": "minihost",
         "run_id": int(RUN), "run_attempt": int(ATTEMPT), "head_sha": SHA,
         "status": "completed", "conclusion": "success"}
        for index, name in enumerate(sorted(JOBS), 100)
    ]}
    return run, jobs


class RoutingTests(unittest.TestCase):
    def test_exact_unsigned_job_on_registered_minihost(self):
        verify_routing(*fixtures(), SHA, RUN, ATTEMPT)

    def test_wrong_runner_ref_attempt_or_job_cannot_pass(self):
        run, jobs = fixtures()
        for name, wrong in (
            ("runner_id", 24), ("runner_name", "archhost"), ("runner_id", "22"),
            ("run_attempt", 1), ("run_id", 54321), ("head_sha", "b" * 40),
            ("conclusion", "skipped"), ("status", "queued"), ("name", "Unrelated job"),
        ):
            candidate = deepcopy(jobs)
            candidate["jobs"][0][name] = wrong
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify_routing(run, candidate, SHA, RUN, ATTEMPT)
        for name, wrong in (("head_branch", "other"), ("event", "push"),
                            ("path", "other.yml"), ("run_attempt", 1)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify_routing(run | {name: wrong}, jobs, SHA, RUN, ATTEMPT)

    def test_unrelated_repo_and_incomplete_or_duplicate_jobs_refused(self):
        run, jobs = fixtures()
        wrong_repo = deepcopy(run)
        wrong_repo["repository"]["id"] += 1
        with self.assertRaises(ValueError):
            verify_routing(wrong_repo, jobs, SHA, RUN, ATTEMPT)
        for rows in ([], jobs["jobs"] * 2, jobs["jobs"] + [jobs["jobs"][0] | {"name": "Attest"}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                verify_routing(run, {"total_count": len(rows), "jobs": rows}, SHA, RUN, ATTEMPT)


if __name__ == "__main__":
    unittest.main()
