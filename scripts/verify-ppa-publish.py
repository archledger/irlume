#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Wait until a PPA upload is actually installable, and fail loudly if it is not.

`dput` printing "Successfully uploaded packages." means Launchpad accepted the
*upload*. Three things have to happen after that before `apt install irlume`
works on a user's machine, and all three are silent:

    upload accepted  ->  source published  ->  build succeeds  ->  binary published

0.6.1-0ppa1~resolute1 was uploaded on 2026-07-24 and accepted. Its amd64 build
then failed after about three minutes, so no binary was ever published and PPA
users stayed on 0.6.0 for four days. Nobody noticed, because from the
maintainer's side a green `dput` and a broken package look identical.

Every other lane fails in your face: Copr reports `state: failed`, the AUR
breaks at `makepkg`, a bad universal .deb trips the release asset check. This
script gives the PPA lane the same property.

The live check is release-time tooling: it needs a real upload to exist, so there
is nothing for it to look at on a pull request. Run it after `dput`, from the
release process, and treat a non-zero exit as "Ubuntu users did not get this
release". Its verdict logic is what CI runs, via --self-test.

    python3 scripts/verify-ppa-publish.py                # version from Cargo.toml
    python3 scripts/verify-ppa-publish.py 0.7.0          # explicit upstream version
    python3 scripts/verify-ppa-publish.py --no-wait      # report now, do not poll
    python3 scripts/verify-ppa-publish.py --self-test    # fixtures only, no network

Exit codes: 0 installable, 1 failed or timed out, 2 usage/transport error.

The Launchpad API is public and needs no authentication.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.launchpad.net/1.0"
OWNER = os.environ.get("PPA_OWNER", "archledger")
PPA = os.environ.get("PPA_NAME", "irlume")
SOURCE = os.environ.get("PPA_SOURCE_PACKAGE", "irlume")
# Binary package name from packaging/ppa/debian/control (Package:). Used only to
# keep the binary query small; the actual join is on source_package_version, so
# a binary whose version differs from its source's still matches.
BINARY = os.environ.get("PPA_BINARY_PACKAGE", "irlume")

# The authoritative build_state vocabulary, from the `build_state` query
# parameter in Launchpad's own WADL (api.launchpad.net/1.0/ with
# Accept: application/vd.sun.wadl+xml). Do not write this list from memory:
# "Gathering build output" is a real transient state and treating it as
# unrecognised would make this script flap in the middle of a healthy build.
PENDING = {
    "Needs building",
    "Currently building",
    "Uploading build",
    "Gathering build output",
}
SUCCESS = "Successfully built"
FAILED = {
    "Failed to build",
    "Failed to upload",
    "Chroot problem",
    # MANUALDEPWAIT. The build is parked until a human intervenes, so for a
    # release check it is a failure now, not something to wait out.
    "Dependency wait",
    "Cancelling build",
    "Cancelled build",
    "Build for superseded Source",
}


def get(url, params=None):
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        die(f"Launchpad returned HTTP {e.code} for {url}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        die(f"could not reach Launchpad ({e}); this is not a verdict on the upload")


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def upstream_version(repo):
    """Read the crate version the same way scripts/build-ppa-source.sh does."""
    cargo = os.path.join(repo, "Cargo.toml")
    try:
        with open(cargo, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^version *= *"([^"]+)"', line)
                if m:
                    return m.group(1)
    except OSError as e:
        die(f"cannot read {cargo} ({e}); pass the version explicitly")
    die(f"no version field in {cargo}; pass the version explicitly")


def source_publication(debver):
    """The source publication for exactly this Debian version, or None.

    Status is deliberately not filtered. A publication is Superseded as soon as
    the next release lands, and 0.6.1 was Superseded *and* broken -- so status
    says nothing about whether this version ever reached anyone.
    """
    d = get(
        f"{API}/~{OWNER}/+archive/ubuntu/{PPA}",
        {
            "ws.op": "getPublishedSources",
            "source_name": SOURCE,
            "exact_match": "true",
            "version": debver,
        },
    )
    entries = d.get("entries") or []
    return entries[0] if entries else None


def builds(publication):
    d = get(publication["self_link"], {"ws.op": "getBuilds"})
    return d.get("entries") or []


def published_binaries(debver):
    """Binaries built from this source version that have actually been published.

    Status is *not* filtered to Published. A binary goes Superseded the moment
    the next release lands, so filtering on Published would answer "is this the
    newest version" instead of "did this version ever reach users" -- and would
    report a false failure for every release but the current one. That matters
    beyond tidiness: a release check that cries wolf stops being read, which is
    how 0.6.1 went unnoticed in the first place.

    Only Pending is excluded, because that one genuinely means "not yet". The
    statuses are Pending/Published/Superseded/Deleted/Obsolete (Launchpad WADL).

    The join is on source_package_version, not on the binary's own version, so
    this stays correct if a binary is ever versioned differently from its source.
    """
    d = get(
        f"{API}/~{OWNER}/+archive/ubuntu/{PPA}",
        {
            "ws.op": "getPublishedBinaries",
            "binary_name": BINARY,
            "exact_match": "true",
        },
    )
    return binaries_for_source(d.get("entries") or [], debver)


def binaries_for_source(entries, debver):
    """Pure half of published_binaries, so --self-test can pin the Pending rule."""
    return [
        e
        for e in entries
        if e.get("source_package_version") == debver and e.get("status") != "Pending"
    ]


def classify(debver, pub, bs, bins):
    """The whole verdict, as a pure function of what Launchpad said.

    Kept free of I/O so --self-test can drive the states that cannot be
    conjured from the live archive on demand: a build mid-flight, a Pending
    binary, an unrecognised state. Those are precisely the branches where
    getting the vocabulary wrong would make the check useless rather than noisy.

    Returns (verdict, detail) with verdict in ok/pending/failed.
    `bins` is only consulted once every build has succeeded, so callers may pass
    None to mean "not fetched yet".
    """
    if pub is None:
        return "pending", f"no source publication for {debver} yet"
    if not bs:
        return "pending", "source published, no build records yet"

    bad = [b for b in bs if b["buildstate"] in FAILED]
    if bad:
        lines = []
        for b in bad:
            lines.append(f"{b['arch_tag']} {b['buildstate']}")
            lines.append(f"      build page: {b['web_link']}")
            # Grab the log URL while it exists. Launchpad had already dropped
            # 0.6.1's by the time anyone looked, so the cause was unrecoverable.
            log = b.get("build_log_url")
            lines.append(f"      build log:  {log if log else 'none retained by Launchpad'}")
        return "failed", "\n    ".join(lines)

    waiting = [b for b in bs if b["buildstate"] in PENDING]
    unknown = [b for b in bs if b["buildstate"] not in PENDING and b["buildstate"] != SUCCESS]
    if unknown:
        # Not treated as failure: an unrecognised state means this script's
        # vocabulary is stale, not necessarily that the build is broken. Keep
        # waiting and let the timeout be the verdict, with the state named.
        states = ", ".join(sorted({b["buildstate"] for b in unknown}))
        return "pending", f"unrecognised build state ({states}); waiting, check the build page"
    if waiting:
        return "pending", "building"

    if not bins:
        # The gap that matters: 0.7.0's source published at 06:27 and its binary
        # at 06:49. A successful build is not yet an installable package.
        return "pending", "build succeeded, binary not published yet"

    # Name the status rather than just saying "published": a Superseded pass
    # means "this shipped, and something newer has since replaced it", which is
    # a different fact from a freshly published upload.
    where = ", ".join(
        sorted(
            f"{b['distro_arch_series_link'].rsplit('/', 1)[-1]} {b['status']}" for b in bins
        )
    )
    return "ok", f"binary published ({where})"


def check(debver, verbose=True):
    """Fetch one pass' worth of state from Launchpad and classify it."""
    pub = source_publication(debver)
    bs = builds(pub) if pub is not None else []
    if verbose:
        for b in bs:
            print(f"    {b['arch_tag']:8} {b['buildstate']}")
    # Only worth a second request once the builds are all green; classify()
    # never reads bins before that point.
    all_built = bool(bs) and all(b["buildstate"] == SUCCESS for b in bs)
    bins = published_binaries(debver) if all_built else None
    return classify(debver, pub, bs, bins)


# Every value Launchpad's WADL lists for the `build_state` query parameter, as
# of 2026-07-28. Written out literally so --self-test can prove the sets above
# still partition it: a state in none of them means this script has gone stale
# against Launchpad, which is the failure that turns a check into a rubber stamp.
WADL_BUILD_STATES = (
    "Needs building",
    "Successfully built",
    "Failed to build",
    "Dependency wait",
    "Chroot problem",
    "Build for superseded Source",
    "Currently building",
    "Failed to upload",
    "Uploading build",
    "Cancelling build",
    "Cancelled build",
    "Gathering build output",
)

V = "1.2.3-0ppa1~resolute1"


def _build(state, arch="amd64"):
    return {
        "buildstate": state,
        "arch_tag": arch,
        "web_link": "https://launchpad.net/build/1",
        "build_log_url": None,
    }


def _binary(status, arch="amd64", src=V):
    return {
        "status": status,
        "source_package_version": src,
        "distro_arch_series_link": f"https://api.launchpad.net/1.0/ubuntu/resolute/{arch}",
    }


def self_test():
    """Canary the verdict logic both ways, without touching the network."""
    pub = {"self_link": "https://api.launchpad.net/1.0/x"}
    ok_build = [_build("Successfully built")]
    cases = [
        ("no upload at all", (None, [], None), "pending"),
        ("source published, no builds yet", (pub, [], None), "pending"),
        ("build not yet started", (pub, [_build("Needs building")], None), "pending"),
        ("build running", (pub, [_build("Currently building")], None), "pending"),
        ("build uploading", (pub, [_build("Uploading build")], None), "pending"),
        # The state a from-memory vocabulary omits; it must not read as failure.
        ("gathering output", (pub, [_build("Gathering build output")], None), "pending"),
        ("build failed", (pub, [_build("Failed to build")], None), "failed"),
        ("dependency wait", (pub, [_build("Dependency wait")], None), "failed"),
        ("chroot problem", (pub, [_build("Chroot problem")], None), "failed"),
        ("upload failed", (pub, [_build("Failed to upload")], None), "failed"),
        ("cancelled", (pub, [_build("Cancelled build")], None), "failed"),
        ("superseded source", (pub, [_build("Build for superseded Source")], None), "failed"),
        # One good arch must not mask a broken one.
        (
            "one arch failed",
            (pub, [_build("Successfully built"), _build("Failed to build", "arm64")], None),
            "failed",
        ),
        # A state this script has never heard of: wait and name it, do not
        # invent a verdict either way.
        ("unknown state", (pub, [_build("Teleporting")], None), "pending"),
        ("built, binaries not fetched", (pub, ok_build, None), "pending"),
        ("built, nothing published yet", (pub, ok_build, []), "pending"),
        ("built and published", (pub, ok_build, [_binary("Published")]), "ok"),
        # 0.6.0 really did reach users; filtering on Published alone called this
        # a failure, which is the regression this case exists to catch.
        ("shipped, since superseded", (pub, ok_build, [_binary("Superseded")]), "ok"),
        ("shipped, later deleted", (pub, ok_build, [_binary("Deleted")]), "ok"),
    ]

    failures = 0
    for name, (pub_, bs, bins), want in cases:
        got, detail = classify(V, pub_, bs, bins)
        mark = "ok  " if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {mark} {name}: want {want}, got {got} ({detail.splitlines()[0]})")

    print("\n  == binary filter ==")
    filter_cases = [
        ("Pending binary is not published", [_binary("Pending")], 0),
        ("Published binary counts", [_binary("Published")], 1),
        ("Superseded binary counts", [_binary("Superseded")], 1),
        ("other source's binary ignored", [_binary("Published", src="9.9.9-0ppa1~resolute1")], 0),
    ]
    for name, entries, want in filter_cases:
        got = len(binaries_for_source(entries, V))
        mark = "ok  " if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {mark} {name}: want {want}, got {got}")

    print("\n  == build state vocabulary vs Launchpad's WADL ==")
    # Behavioural, and deliberately not phrased in terms of the sets above: run
    # every real state through classify() and require a definite answer. The
    # set-difference check below can be defeated by editing a state out of both
    # PENDING and WADL_BUILD_STATES at once; this cannot, because a state that
    # falls out of the sets starts reporting itself as unrecognised.
    for state in WADL_BUILD_STATES:
        _, detail = classify(V, pub, [_build(state)], [_binary("Published")])
        if "unrecognised" in detail:
            failures += 1
            print(f"  FAIL {state}: classified as unrecognised")
    print(f"  ok   all {len(WADL_BUILD_STATES)} real states get a definite verdict")

    known = PENDING | FAILED | {SUCCESS}
    unhandled = [s for s in WADL_BUILD_STATES if s not in known]
    invented = sorted(known - set(WADL_BUILD_STATES))
    for label, bad in (("unhandled", unhandled), ("not in the WADL", invented)):
        if bad:
            failures += 1
            print(f"  FAIL {label}: {', '.join(bad)}")
        else:
            print(f"  ok   no states {label}")

    print(f"\n{'FAIL' if failures else 'PASS'}: {failures} failing case(s)")
    return 1 if failures else 0


def main():
    p = argparse.ArgumentParser(
        description="Verify a PPA upload reached 'binary published', not just 'upload accepted'."
    )
    p.add_argument("version", nargs="?", help="upstream version (default: from Cargo.toml)")
    p.add_argument("--series", default=os.environ.get("SERIES", "resolute"))
    p.add_argument("--pparev", default=os.environ.get("PPAREV", "0ppa1"))
    p.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("PPA_VERIFY_TIMEOUT", "5400")),
        help="seconds to wait for the build (default 5400; 0.7.0 took ~22 min)",
    )
    p.add_argument(
        "--interval", type=int, default=int(os.environ.get("PPA_VERIFY_INTERVAL", "60"))
    )
    p.add_argument("--no-wait", action="store_true", help="single pass, do not poll")
    p.add_argument(
        "--self-test",
        action="store_true",
        help="check the verdict logic against fixtures, no network, no upload needed",
    )
    args = p.parse_args()

    if args.self_test:
        print("== verify-ppa-publish self-test ==")
        return self_test()

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    version = args.version or upstream_version(repo)
    debver = f"{version}-{args.pparev}~{args.series}1"

    print(f"== PPA lane: ppa:{OWNER}/{PPA}  {SOURCE} {debver}")
    print(f"   https://launchpad.net/~{OWNER}/+archive/ubuntu/{PPA}")

    deadline = time.monotonic() + (0 if args.no_wait else args.timeout)
    while True:
        verdict, detail = check(debver)
        # stdout is block-buffered into a pipe while stderr is not, so without
        # this the verdict lands above the context it refers to in a release log.
        sys.stdout.flush()
        if verdict == "ok":
            print(f"\nPASS: {debver} is installable -- {detail}")
            return 0
        if verdict == "failed":
            print(f"\nFAIL: {debver} did not publish\n    {detail}", file=sys.stderr)
            print(
                "\nUbuntu users are still on the previous version. Fix and upload a\n"
                "new PPA revision (bump PPAREV); Launchpad will not rebuild the same one.",
                file=sys.stderr,
            )
            return 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(f"\nFAIL: timed out waiting -- {detail}", file=sys.stderr)
            print(
                "Not proof anything is broken -- a slow builder queue looks the same.\n"
                f"Check https://launchpad.net/~{OWNER}/+archive/ubuntu/{PPA}/+packages"
                " before re-uploading.",
                file=sys.stderr,
            )
            return 1
        left = f"{int(remaining / 60)} min" if remaining >= 60 else f"{int(remaining)}s"
        print(f"   {detail}; {left} left, retrying in {args.interval}s")
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted; the upload's state on Launchpad is unchanged", file=sys.stderr)
        sys.exit(2)
