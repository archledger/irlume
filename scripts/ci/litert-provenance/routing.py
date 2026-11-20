"""Cross-check GitHub API routing records; this does not verify an attestation."""

from argparse import ArgumentParser
from pathlib import Path

from provenance import OWNER_ID, REPO, REPO_ID, WORKFLOW, expected_predicate, json_file, require


RUNNER = "minihost"
RUNNER_ID = 22
JOBS = {"Rebuild on minihost"}


def verify_routing(run, jobs, source_sha, run_id, attempt):
    """Check content from independently fetched, authenticated GitHub API responses."""
    expected_predicate(source_sha, run_id, attempt)
    identity = {"run_attempt": int(attempt), "head_sha": source_sha,
                "status": "completed", "conclusion": "success"}
    run_fields = identity | {
        "id": int(run_id), "event": "workflow_dispatch", "head_branch": "main", "path": WORKFLOW,
    }
    require(isinstance(run, dict) and all(
        type(run.get(key)) is type(value) and run[key] == value for key, value in run_fields.items()
    ), "wrong GitHub run, workflow, commit, attempt or result")
    repo = run.get("repository")
    require(isinstance(repo, dict) and repo.get("id") == int(REPO_ID) and repo.get("full_name") == REPO
            and isinstance(repo.get("owner"), dict) and repo["owner"].get("id") == int(OWNER_ID),
            "wrong GitHub repository or owner")
    require(isinstance(jobs, dict) and jobs.get("total_count") == len(JOBS)
            and isinstance(jobs.get("jobs"), list) and len(jobs["jobs"]) == len(JOBS),
            "minihost routing requires one completed unsigned job; no extra jobs")
    job_fields = identity | {"runner_id": RUNNER_ID, "runner_name": RUNNER, "run_id": int(run_id)}
    found = set()
    ids = set()
    for job in jobs["jobs"]:
        require(isinstance(job, dict) and isinstance(job.get("name"), str)
                and job["name"] in JOBS and job["name"] not in found
                and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids
                and all(type(job.get(key)) is type(value) and job[key] == value
                        for key, value in job_fields.items()),
                "wrong registered runner, job, commit, attempt or result")
        found.add(job["name"])
        ids.add(job["id"])


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("run_record", type=Path)
    parser.add_argument("jobs_record", type=Path)
    parser.add_argument("source_sha")
    parser.add_argument("run")
    parser.add_argument("attempt")
    args = parser.parse_args()
    try:
        verify_routing(json_file(args.run_record), json_file(args.jobs_record),
                       args.source_sha, args.run, args.attempt)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Routing records refused: {error}\n")
    print("MINIHOST_ROUTING_RECORD_MATCH (routing only; not a build attestation)")


if __name__ == "__main__":
    main()
