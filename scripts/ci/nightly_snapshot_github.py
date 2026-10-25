# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Bounded GET-only GitHub observations. This module has no publication API."""

import base64
import hashlib
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
BASE = "/repos/archledger/irlume"
LIMIT = 1024 * 1024


class Hold(ValueError):
    """Valid observations which do not qualify a new source selection."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("api-redirect-refused")


class Github:
    """Never follows response-provided URLs or sends a mutation request."""

    def __init__(self, decoder):
        self.decoder = decoder
        self.deadline = time.monotonic() + 180
        self.requests = 0
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, path, query=None):
        if (
            not path.startswith(BASE + "/")
            or ".." in path
            or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
        ):
            raise ValueError("api-path-refused")
        self.requests += 1
        remaining = self.deadline - time.monotonic()
        if self.requests > 80 or remaining <= 0:
            raise ValueError("api-budget-exceeded")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "irlume-nightly-snapshot",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            if not token.isascii() or any(c.isspace() for c in token):
                raise ValueError("invalid-api-token-format")
            headers["Authorization"] = "Bearer " + token
        url = API + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self.opener.open(request, timeout=min(20, remaining)) as response:
                data = bytearray()
                while True:
                    if time.monotonic() >= self.deadline:
                        raise ValueError("api-budget-exceeded")
                    chunk = response.read1(min(65536, LIMIT + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > LIMIT:
                        raise ValueError("api-response-too-large")
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            raise ValueError(f"api-http-{code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ValueError("api-unavailable") from None
        return self.decoder(bytes(data))

    def pages(self, path, key, query=None):
        result = []
        total = None
        for page in range(1, 11):
            value = self.get(path, dict(query or {}, per_page=100, page=page))
            count = positive(value.get("total_count"), allow_zero=True)
            rows = value.get(key)
            if (
                not isinstance(rows, list)
                or count >= 1000
                or (total is not None and total != count)
            ):
                raise ValueError("incomplete-api-pages")
            total = count
            if len(rows) != min(100, count - len(result)):
                raise ValueError("incomplete-api-pages")
            result.extend(rows)
            ids = [positive(row.get("id")) for row in result]
            if len(set(ids)) != len(ids):
                raise ValueError("duplicate-api-record")
            if len(result) == total:
                return result
        raise ValueError("api-page-limit")


def positive(value, *, allow_zero=False):
    if type(value) is not int or value < (0 if allow_zero else 1):
        raise ValueError("invalid-api-identifier")
    return value


def head(api):
    value = api.get(BASE + "/git/ref/heads/main")
    if value.get("ref") != "refs/heads/main" or value["object"].get("type") != "commit":
        raise ValueError("invalid-main-ref")
    sha = value["object"].get("sha")
    if not isinstance(sha, str) or not re.fullmatch("[0-9a-f]{40}", sha):
        raise ValueError("invalid-main-commit")
    return sha


def required_policy(api, policy):
    classic = api.get(BASE + "/branches/main/protection/required_status_checks")
    rules = api.get(BASE + "/rules/branches/main")
    if classic.get("strict") is not True or not isinstance(rules, list):
        raise Hold("required-policy-drift")
    checks = classic["checks"]
    if set(classic["contexts"]) != {item["context"] for item in checks}:
        raise Hold("required-policy-drift")
    entries = [(item["context"], item.get("app_id")) for item in checks]
    if any(app != policy["app_id"] for _, app in entries):
        raise Hold("required-app-drift")
    for rule in rules:
        if rule["type"] == "required_status_checks":
            entries.extend(
                (item["context"], item.get("integration_id"))
                for item in rule["parameters"]["required_status_checks"]
            )
        elif rule["type"] == "workflows":
            raise Hold("unsupported-required-workflow-rule")
    if {name for name, _ in entries} != set(policy["required"]):
        raise Hold("required-policy-drift")
    if any(app not in (None, policy["app_id"]) for _, app in entries):
        raise Hold("required-app-drift")
    return sorted({name for name, _ in entries})


def latest_run(api, workflow, metadata, sha, repository):
    runs = api.pages(
        BASE + f"/actions/workflows/{workflow}/runs",
        "workflow_runs",
        {
            "branch": "main",
            "event": "push",
            "head_sha": sha,
            "exclude_pull_requests": "true",
        },
    )
    if not runs:
        raise Hold("missing-workflow-run")
    for run in runs:
        if (
            run["repository"]["full_name"] != repository
            or run["head_repository"]["full_name"] != repository
            or run["head_sha"] != sha
            or run["head_branch"] != "main"
            or run["event"] != "push"
            or run["workflow_id"] != metadata["id"]
            or run["path"] != metadata["path"]
        ):
            raise Hold("wrong-workflow-run")
        positive(run["run_number"])
        positive(run["run_attempt"])
        positive(run["check_suite_id"])
    last = max(run["run_number"] for run in runs)
    selected = [run for run in runs if run["run_number"] == last]
    if len(selected) != 1:
        raise Hold("ambiguous-workflow-run")
    run = selected[0]
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise Hold("workflow-not-successful")
    return run


def workflow_checks(api, workflow, metadata, run, sha, policy):
    jobs = api.pages(
        BASE + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs"
    )
    result = []
    for name, filename in policy["checks"].items():
        if filename != workflow:
            continue
        selected = [job for job in jobs if job["name"] == name]
        if len(selected) != 1:
            raise Hold("missing-or-duplicate-job")
        job = selected[0]
        # The attempt-specific endpoint binds jobs even on API versions that
        # omit run_attempt from job objects. If present, it must agree.
        if "run_attempt" in job:
            positive(job["run_attempt"])
        if (
            job["run_id"] != run["id"]
            or job["head_sha"] != sha
            or job.get("run_attempt", run["run_attempt"]) != run["run_attempt"]
        ):
            raise Hold("wrong-job-identity")
        if job["status"] != "completed" or job["conclusion"] != "success":
            raise Hold("job-not-successful")
        url = job["check_run_url"]
        match = re.fullmatch(
            re.escape(API + BASE + "/check-runs/") + r"([1-9][0-9]*)", url
        )
        if not match:
            raise Hold("wrong-check-url")
        check = api.get(BASE + "/check-runs/" + match[1])
        if (
            check["id"] != int(match[1])
            or check["head_sha"] != sha
            or check["name"] != name
            or check["app"]["id"] != policy["app_id"]
            or check["check_suite"]["id"] != run["check_suite_id"]
            or check["status"] != "completed"
            or check["conclusion"] != "success"
        ):
            raise Hold("wrong-check-identity")
        result.append(
            {
                "name": name,
                "workflow": workflow,
                "commit": sha,
                "app_id": check["app"]["id"],
                "workflow_id": metadata["id"],
                "run_id": run["id"],
                "attempt": run["run_attempt"],
                "job_id": job["id"],
                "status": job["status"],
                "conclusion": job["conclusion"],
                "completed_at": job["completed_at"],
            }
        )
    return result


def source_inputs(api, paths, sha):
    result = []
    for path in paths:
        value = api.get(BASE + "/contents/" + path, {"ref": sha})
        if (
            value["type"] != "file"
            or value["path"] != path
            or value["encoding"] != "base64"
        ):
            raise ValueError("invalid-source-file")
        content = base64.b64decode("".join(value["content"].split()), validate=True)
        if len(content) > LIMIT or positive(value["size"], allow_zero=True) != len(
            content
        ):
            raise ValueError("invalid-source-size")
        blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content,
            usedforsecurity=False,
        ).hexdigest()
        if blob != value["sha"]:
            raise ValueError("source-blob-mismatch")
        result.append(
            {"path": path, "blob": blob, "sha256": hashlib.sha256(content).hexdigest()}
        )
    return result


def collect(api, policy, slot, observed_at):
    sha = head(api)
    commit = api.get(BASE + "/git/commits/" + sha)
    if commit["sha"] != sha:
        raise ValueError("wrong-commit-response")
    required = required_policy(api, policy)
    checks, selected_runs = [], []
    for workflow in dict.fromkeys(policy["checks"].values()):
        metadata = api.get(BASE + "/actions/workflows/" + workflow)
        positive(metadata["id"])
        if (
            metadata["path"] != ".github/workflows/" + workflow
            or metadata["state"] != "active"
        ):
            raise Hold("wrong-workflow-identity")
        run = latest_run(api, workflow, metadata, sha, policy["repository"])
        checks.extend(workflow_checks(api, workflow, metadata, run, sha, policy))
        selected_runs.append((workflow, metadata, run))
    inputs = source_inputs(api, policy["inputs"], sha)
    for workflow, metadata, run in selected_runs:
        current = latest_run(api, workflow, metadata, sha, policy["repository"])
        if (current["id"], current["run_attempt"]) != (run["id"], run["run_attempt"]):
            raise Hold("workflow-changed-during-collection")
    if required_policy(api, policy) != required:
        raise Hold("policy-changed-during-collection")
    return {
        "repository": policy["repository"],
        "ref": policy["ref"],
        "commit": sha,
        "tree": commit["tree"]["sha"],
        "main_after": head(api),
        "slot": slot,
        "observed_at": observed_at,
        "required_checks": required,
        "inputs": inputs,
        "checks": checks,
    }
