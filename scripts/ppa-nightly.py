#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Upload main to ppa:archledger/irlume-nightly (ADR-0037 section 3).

Run once a day by a user timer on minihost (packaging/ppa/nightly/). Each run:

1. updates a dedicated clone and derives the nightly version from main:
   `git describe` v0.15.0-139-g3c162b83 gives 0.15.0+git139.g3c162b83, so a
   release tag on an already uploaded commit is a new input too;
2. reads its state and Launchpad's public API, and decides (decide()):
   nothing to do, wait, record a publication, or upload;
3. to upload: builds the source package in the release's Ubuntu container
   (packaging/ppa/container-build.sh, from a git archive of the commit),
   signs it in a second container that reaches the key only through
   gpg-agent's extra socket, and uploads it with dput from a third; then
   records the upload and polls Launchpad for a while.

The trust boundary: this script is installed from a reviewed checkout and is
not run from the clone it updates. Code from main (the build scripts,
`cargo vendor`, the model fetch) runs only inside the build container, which
never sees the key; the signing and upload containers run fixed commands on
the built files.

Launchpad accepts a version once per PPA, also after a deletion, and dput's
success means only that the files arrived, so the state follows Launchpad:
an upload counts as accepted once its source publication appears, a version
whose source publication has not appeared a day later was rejected, and a
rejected upload or a failed build is retried with the next PPA revision only
while the derived version is unchanged.

  python3 ppa-nightly.py                # what the timer runs
  python3 ppa-nightly.py --no-upload    # build and sign, never dput (a dry run)
  python3 ppa-nightly.py --no-upload --repo-url <repo> --ref <branch>
                                        # a dry run of another branch, as for
                                        # testing a change to the build itself

Exit codes: 0 nothing to do, waiting, or uploaded; 1 a step failed (logged,
state unchanged); 2 usage, or Launchpad could not be reached.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_URL = "https://github.com/archledger/irlume.git"
OWNER = "archledger"
PPA = "irlume-nightly"
SERIES = "resolute"
# The key Launchpad has for ~archledger (ADR-0037 section 3).
KEY = "F35053398E3C80FE20891B82C10B8492BD7F30C6"
# The release build's image (packaging/ppa/build-ppa-container.sh's BASE);
# test-ppa-nightly.py checks the two agree.
BASE = (
    "docker.io/library/ubuntu:26.04"
    "@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb"
)
# An upload whose source publication has not appeared after this was rejected.
REJECTED_AFTER = 24 * 3600
# Retries of one derived version before waiting for main to move.
MAX_PPAREV = 5
# After an upload, how long to poll Launchpad before leaving it to the next run.
POLL_FOR = 4 * 3600
POLL_EVERY = 600

HOME = Path.home()
DEFAULT_CLONE = HOME / ".local" / "share" / "irlume-nightly" / "irlume"
# A dry run of another repository or branch gets a clone of its own.
DRY_RUN_CLONE = DEFAULT_CLONE.with_name("irlume-dry-run")
DEFAULT_STATE = HOME / ".local" / "state" / "irlume-nightly" / "ppa.json"
# On disk: a build needs a few GB, more than a tmpfs /tmp may have.
DEFAULT_WORK = HOME / ".cache" / "irlume-nightly"


def log(message: str) -> None:
    print(f"ppa-nightly: {message}", flush=True)


# --- versions -------------------------------------------------------------------


def nightly_version(describe: str) -> str:
    """`git describe --long --tags` of main as the nightly upstream version:
    v0.15.0-139-g3c162b83 -> 0.15.0+git139.g3c162b83 (ADR-0037 section 2)."""
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)-(\d+)-g([0-9a-f]+)", describe.strip())
    if not match:
        raise ValueError(f"not a release-tag describe: {describe!r}")
    tag, commits, commit = match.groups()
    return f"{tag}+git{commits}.g{commit}"


def debian_version(upstream: str, pparev: int, series: str = SERIES) -> str:
    """The Debian version of an upload: 0.15.0+git139.g3c162b83-0ppa1~resolute1."""
    return f"{upstream}-0ppa{pparev}~{series}1"


# --- the decision ---------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Nothing:
    reason: str


@dataclasses.dataclass(frozen=True)
class Wait:
    reason: str


@dataclasses.dataclass(frozen=True)
class Published:
    upstream: str


@dataclasses.dataclass(frozen=True)
class Upload:
    upstream: str
    pparev: int
    reason: str


def decide(state: dict, upstream: str, now: float, status) -> object:
    """What this run does, from the recorded state, the derived version and
    Launchpad. `status(debian_version)` is "ok" (binary published), "pending"
    (accepted: source published, building), "failed" (a build failed) or
    "absent" (no source publication)."""
    if state.get("published") == upstream:
        return Nothing(f"{upstream} is already published")
    pending = state.get("pending")
    if pending and pending.get("upstream") == upstream:
        rev = int(pending["pparev"])
        seen = status(debian_version(upstream, rev))
        if seen == "ok":
            return Published(upstream)
        if seen == "pending":
            return Wait(f"{debian_version(upstream, rev)} is accepted and building")
        if seen == "failed":
            return retry(upstream, rev, "its build failed")
        if now - float(pending.get("uploaded_at", 0)) > REJECTED_AFTER:
            return retry(upstream, rev, "Launchpad never published its source (rejected)")
        return Wait(f"{debian_version(upstream, rev)} was uploaded and is not accepted yet")
    failed = state.get("failed")
    if failed and failed.get("upstream") == upstream:
        return retry(upstream, int(failed["pparev"]), "an earlier attempt failed")
    # A new version: main moved, or a release tag landed. A failed or pending
    # older version is dropped, so a fix on main is never held up by retries
    # of the commit it fixed.
    return Upload(upstream, 1, "main moved")


def retry(upstream: str, rev: int, why: str) -> object:
    if rev >= MAX_PPAREV:
        return Wait(f"{upstream}: {why} at -0ppa{rev}; waiting for main to move")
    return Upload(upstream, rev + 1, f"{why} at -0ppa{rev}")


def after_upload(state: dict, action: Upload, now: float) -> dict:
    """The state once dput has run, whether it succeeded or not: a lost
    connection after the last byte fails dput while Launchpad accepts the
    upload, so the version is pending and Launchpad's source publication
    decides. The failed record is dropped."""
    return {
        "published": state.get("published"),
        "pending": {"upstream": action.upstream, "pparev": action.pparev, "uploaded_at": now},
    }


def after_failure(state: dict, upstream: str, pparev: int) -> dict:
    """The state once Launchpad refused or failed a pending upload."""
    return {"published": state.get("published"), "failed": {"upstream": upstream, "pparev": pparev}}


def after_publish(state: dict, upstream: str) -> dict:
    return {"published": upstream}


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


# --- Launchpad ------------------------------------------------------------------


def launchpad(script_dir: Path):
    """verify-ppa-publish.py's queries for the nightly PPA: a status function."""
    os.environ["PPA_OWNER"] = OWNER
    os.environ["PPA_NAME"] = PPA
    spec = importlib.util.spec_from_file_location("verify_ppa_publish", script_dir / "verify-ppa-publish.py")
    verify = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verify)

    def status(debver: str) -> str:
        if verify.source_publication(debver) is None:
            return "absent"
        verdict, _ = verify.check(debver, verbose=False)
        return {"ok": "ok", "failed": "failed"}.get(verdict, "pending")

    return status


# --- the clone, the build, the signature, the upload -----------------------------


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, **kwargs)


def update_clone(clone: Path, url: str = REPO_URL, ref: str = "main") -> tuple[str, str, int]:
    """Fetch `ref` and exactly `url`'s tags; the commit, its describe and its
    commit time. The tags come through an explicit refspec with --prune, so a
    tag the repository does not have (one a dry run of another repository
    left) is deleted before git describe can derive a version from it."""
    if not (clone / ".git").is_dir():
        clone.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "--quiet", str(clone)])
    run([
        # --update-shallow: a dry run's local checkout may itself be shallow.
        "git", "-C", str(clone), "fetch", "--quiet", "--force", "--prune", "--no-tags", "--update-shallow", url,
        f"+refs/heads/{ref}:refs/nightly/head", "+refs/tags/*:refs/tags/*",
    ])
    git = lambda *args: run(["git", "-C", str(clone), *args], capture_output=True, text=True).stdout.strip()
    commit = git("rev-parse", "refs/nightly/head^{commit}")
    describe = git("describe", "--long", "--tags", "--match", "v[0-9]*", commit)
    when = int(git("log", "-1", "--format=%ct", commit))
    return commit, describe, when


def engine() -> str:
    found = os.environ.get("CONTAINER") or shutil.which("docker") or shutil.which("podman")
    if not found:
        raise RuntimeError("need docker or podman")
    return found


def owner() -> str | None:
    """The uid:gid a container hands its files back to, as
    packaging/ppa/build-ppa-container.sh does: docker runs them as the real
    root, while rootless podman's root already is this user, where a chown to
    this uid would map to a subuid instead."""
    return f"{os.getuid()}:{os.getgid()}" if Path(engine()).name == "docker" else None


def build(clone: Path, work: Path, commit: str, when: int, upstream: str, pparev: int) -> Path:
    """The unsigned source package of `commit`, built in the release container."""
    shutil.rmtree(work, ignore_errors=True)
    tree = work / "tree"
    tree.mkdir(parents=True)
    archive = subprocess.Popen(["git", "-C", str(clone), "archive", "--format=tar", commit], stdout=subprocess.PIPE)
    run(["tar", "-x", "-C", str(tree)], stdin=archive.stdout)
    if archive.wait() != 0:
        raise RuntimeError("git archive failed")
    changelog = f"Nightly build of irlume main at {commit[:12]} (ADR-0037); not a release."
    env = [
        "-e", f"SOURCE_DATE_EPOCH={when}",
        "-e", f"SERIES={SERIES}",
        "-e", f"PPAREV=0ppa{pparev}",
        "-e", f"PPA_VERSION={upstream}",
        "-e", f"PPA_CHANGELOG={changelog}",
        "-e", f"PPA_NAME={PPA}",
    ]
    if own := owner():
        uid, gid = own.split(":")
        env += ["-e", f"HOST_UID={uid}", "-e", f"HOST_GID={gid}"]
    run([engine(), "run", "--rm", "-v", f"{tree}:/work", *env, BASE, "bash", "/work/packaging/ppa/container-build.sh"])
    return collect(tree / "ppa-build", work / "out", upstream, debian_version(upstream, pparev))


def artifacts(upstream: str, debver: str) -> list[str]:
    """The files a source upload is made of, the .changes last."""
    return [
        f"irlume_{upstream}.orig.tar.gz",
        f"irlume_{debver}.debian.tar.xz",
        f"irlume_{debver}.dsc",
        f"irlume_{debver}_source.buildinfo",
        f"irlume_{debver}_source.changes",
    ]


def collect(built: Path, out: Path, upstream: str, debver: str) -> Path:
    """Move the upload's files out of the tree the build container wrote into
    `out`, a directory only this script writes, and return the .changes.
    Code from main ran in that container, so the tree is not trusted: only
    regular files under the expected names move (a symlink there could
    otherwise point a later host write anywhere), and signing and the upload
    work on `out` alone."""
    if built.is_symlink() or not built.is_dir():
        raise RuntimeError(f"the build left no {built.name} directory")
    out.mkdir()
    for name in artifacts(upstream, debver):
        source = built / name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"the build left no regular {name}")
        source.rename(out / name)
    return out / artifacts(upstream, debver)[-1]


def export_key(directory: Path) -> Path:
    """The public key, for the containers to check signatures with, in a
    directory of its own that they get read-only."""
    directory.mkdir()
    public = directory / "signing-key.asc"
    public.write_bytes(run(["gpg", "--export", "--armor", KEY], capture_output=True).stdout)
    return directory


def sign(changes: Path, key: Path) -> None:
    """debsign in a container that reaches the key only through gpg-agent's
    extra socket ("signing ... without exposing the private keys")."""
    socket = run(["gpgconf", "--list-dirs", "agent-extra-socket"], capture_output=True, text=True).stdout.strip()
    script = (
        "export DEBIAN_FRONTEND=noninteractive GNUPGHOME=/gnupg; "
        "apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends devscripts gnupg >/dev/null; "
        "chmod 700 /gnupg; gpg --batch --import /key/signing-key.asc 2>/dev/null; "
        f"debsign --no-re-sign -k{KEY} /pkg/{changes.name}"
    )
    if own := owner():
        # Regular files only: chown follows a symlink.
        script += f"; find /pkg -maxdepth 1 -type f -exec chown {own} {{}} +"
    run([
        engine(), "run", "--rm", "--network=host",
        "-v", f"{changes.parent}:/pkg",
        "-v", f"{key}:/key:ro",
        "-v", f"{socket}:/gnupg/S.gpg-agent",
        BASE, "bash", "-euc", script,
    ])
    # The signature is checked on the host, against the key itself.
    run(["gpg", "--batch", "--verify", str(changes)], capture_output=True)


# The upload container's exit when its own setup failed, before dput ran;
# docker's own failures to start a container are 125 to 127.
BEFORE_DPUT = 87


class NotUploaded(RuntimeError):
    """The upload failed before dput ran: nothing reached Launchpad."""


def upload(changes: Path, key: Path) -> None:
    """dput in a container. Raises NotUploaded when the container failed
    before dput started, CalledProcessError when dput itself failed."""
    script = (
        "export DEBIAN_FRONTEND=noninteractive; "
        "{ apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends "
        "dput-ng python3-distro-info gnupg ca-certificates >/dev/null "
        f"&& gpg --batch --import /key/signing-key.asc 2>/dev/null; }} || exit {BEFORE_DPUT}; "
        f"cd /pkg && exec dput ppa:{OWNER}/{PPA} {changes.name}"
    )
    try:
        run([
            engine(), "run", "--rm", "--network=host",
            "-v", f"{changes.parent}:/pkg", "-v", f"{key}:/key:ro",
            BASE, "bash", "-euc", script,
        ])
    except subprocess.CalledProcessError as error:
        if error.returncode in (BEFORE_DPUT, 125, 126, 127):
            raise NotUploaded(f"the upload container failed before dput (exit {error.returncode})") from error
        raise


def attempt_upload(state: dict, action: Upload, now: float, push) -> tuple[dict | None, bool, str]:
    """Run `push` (the upload) and say what to record: (the state to save,
    or None for nothing; whether it uploaded; a log line). Once dput has run
    the version is pending, whether dput succeeded or not: a connection lost
    after the last byte fails dput while Launchpad accepts the upload, so the
    source publication decides. A failure before dput records nothing."""
    try:
        push()
    except NotUploaded as error:
        return None, False, f"not uploaded ({error}); nothing recorded"
    except (subprocess.CalledProcessError, RuntimeError) as error:
        return after_upload(state, action, now), False, (
            f"dput failed ({error}); recorded as uploaded, since Launchpad may have it, "
            "so the next run reads its source publication instead of uploading it again"
        )
    return after_upload(state, action, now), True, "uploaded; waiting for Launchpad"


# --- a run ---------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload main to the nightly PPA (ADR-0037).")
    parser.add_argument("--clone", type=Path, default=DEFAULT_CLONE)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--no-upload", action="store_true", help="build and sign, never dput or record")
    parser.add_argument("--repo-url", default=REPO_URL, help="with --no-upload: another repository")
    parser.add_argument("--ref", default="main", help="with --no-upload: another branch")
    args = parser.parse_args()
    if (args.repo_url != REPO_URL or args.ref != "main") and not args.no_upload:
        parser.error("--repo-url and --ref are for dry runs: only main is ever uploaded")
    if (args.repo_url != REPO_URL or args.ref != "main") and args.clone == DEFAULT_CLONE:
        # Another repository's refs never enter the clone the timer uploads from.
        args.clone = DRY_RUN_CLONE

    commit, describe, when = update_clone(args.clone, args.repo_url, args.ref)
    upstream = nightly_version(describe)
    log(f"main is {commit[:12]} ({describe}), nightly version {upstream}")
    status = launchpad(Path(__file__).resolve().parent)
    state = load_state(args.state)
    action = decide(state, upstream, time.time(), status)

    if isinstance(action, (Nothing, Wait)):
        log(action.reason)
        return 0
    if isinstance(action, Published):
        save_state(args.state, after_publish(state, action.upstream))
        log(f"{action.upstream} is published")
        return 0

    pending = state.get("pending")
    if pending and pending.get("upstream") == action.upstream:
        # Launchpad refused or failed the pending revision: record it before
        # the retry, so a failure of the retry itself still retries upward.
        state = after_failure(state, action.upstream, int(pending["pparev"]))
        if not args.no_upload:
            save_state(args.state, state)
    debver = debian_version(action.upstream, action.pparev)
    log(f"building {debver} to upload: {action.reason}")
    try:
        changes = build(args.clone, args.work, commit, when, action.upstream, action.pparev)
        key = export_key(args.work / "key")
        sign(changes, key)
    except (subprocess.CalledProcessError, RuntimeError) as error:
        # Before dput: nothing reached Launchpad, so nothing is recorded.
        log(f"{debver} was not uploaded: {error}")
        return 1
    if args.no_upload:
        log(f"built and signed {changes}; not uploaded (--no-upload)")
        return 0
    recorded, uploaded, message = attempt_upload(state, action, time.time(), lambda: upload(changes, key))
    if recorded is not None:
        state = recorded
        save_state(args.state, state)
    log(f"{debver}: {message}")
    if not uploaded:
        return 1

    deadline = time.time() + POLL_FOR
    while time.time() < deadline:
        time.sleep(POLL_EVERY)
        seen = status(debver)
        if seen == "ok":
            save_state(args.state, after_publish(state, action.upstream))
            log(f"{debver} is published")
            return 0
        if seen == "failed":
            save_state(args.state, after_failure(state, action.upstream, action.pparev))
            log(f"{debver} failed to build; the next run retries with the next PPA revision")
            return 1
    log(f"{debver} is not published yet; the next run checks again")
    return 0


if __name__ == "__main__":
    sys.exit(main())
