"""One attended, non-granting IR experiment. See README.md before root execution."""

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import resource
import signal
import sys
import tempfile
from pathlib import Path

import harness
import host

MODES = ["preflight", "genuine", "impostor", "attack", "empty", "cancel"]


def attend(mode):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    print(
        f"Prepare the scheduled {mode} presentation in normal lighting; close other camera apps."
    )
    print(
        "Type READY now only if the participant is ready for this one scan: ",
        end="",
        flush=True,
    )
    if sys.stdin.readline().strip() != "READY":
        return False
    print("START: hold the scheduled position until FINISHED.", flush=True)
    return True


def diagnostic_command(config, binary, operation):
    assets = config["assets"]
    command = [
        str(binary),
        "--" + operation,
        pwd.getpwuid(config["subject_uid"]).pw_name,
        *[assets[key]["path"] for key in ["detector", "recognizer", "flir"]],
        "--budget-ms",
        str(config["budget_ms"]),
        "--cancel-on-stdin",
    ]
    if "adapter" in assets:
        command += ["--adapter", assets["adapter"]["path"]]
    return command


def execute(config, directory, label, mode, campaign, binary, *, trace_ioctl=False):
    ledger = host.Ledger(directory)
    attempt = ledger.reserve(
        label, mode, campaign, config["assets"]["binary"]["sha256"]
    )
    result = {
        "schema": 1,
        "status": "stopped",
        "stop_required": True,
        "mode": mode,
        "campaign": campaign,
        "budget_ms": config["budget_ms"],
        "watchdog_seconds": config["watchdog_seconds"],
        "asset_sha256": {k: v["sha256"] for k, v in config["assets"].items()},
        "preflight": None,
        "evaluation": None,
        "preservation_verified": False,
        "failure": None,
    }
    before = None
    env = dict(
        host.ENV,
        ORT_DYLIB_PATH=config["assets"]["ort"]["path"],
        IRLUME_RGB_DEVICE=config["cameras"]["rgb"],
        IRLUME_IR_DEVICE=config["cameras"]["ir"],
    )
    try:
        before = host.snapshot(config)
        preflight = harness.run_traced(
            diagnostic_command(config, binary, "preflight"),
            env=env,
            timeout=config["watchdog_seconds"],
            trace_ioctl=trace_ioctl,
        )
        result["preflight"] = preflight
        preflight["installed_unchanged"] = host.snapshot(config) == before
        if not harness.trial_checks(
            preflight,
            "preflight",
            config["cameras"]["ir"],
            config["cameras"]["metadata"],
        ):
            result["failure"] = "preflight_failed"
        elif mode == "preflight":
            result.update(status="complete", stop_required=False)
        elif not attend(mode):
            result["failure"] = "readiness_declined"
        elif host.snapshot(config) != before:
            result["failure"] = "host_changed_before_capture"
        else:
            trial = harness.run_traced(
                diagnostic_command(config, binary, "evaluate"),
                env=env,
                timeout=config["watchdog_seconds"],
                trace_ioctl=trace_ioctl,
                cancel_on_ir_open=config["cameras"]["ir"] if mode == "cancel" else None,
            )
            result["evaluation"] = trial
            trial["installed_unchanged"] = host.snapshot(config) == before
            safe = harness.trial_checks(
                trial, mode, config["cameras"]["ir"], config["cameras"]["metadata"]
            )
            candidate = (
                trial["report"] is not None
                and trial["report"]["category"] == "candidate_match"
            )
            if safe and not (mode in {"attack", "impostor", "empty"} and candidate):
                result.update(status="complete", stop_required=False)
            else:
                result["failure"] = "trial_requires_review"
    except KeyboardInterrupt:
        result["failure"] = "interrupted"
    except Exception:  # noqa: BLE001 — sanitize all library failures at the report boundary
        # Never stringify raw exceptions: paths, account names and third-party
        # error payloads may occur even before diagnostic stderr suppression.
        result["failure"] = "execution_failed"
    finally:
        try:
            result["preservation_verified"] = (
                before is not None and host.snapshot(config) == before
            )
        except Exception:  # noqa: BLE001 — sanitize all library failures at the report boundary
            result["preservation_verified"] = False
        if result["failure"] is not None or not result["preservation_verified"]:
            result.update(status="stopped", stop_required=True)
        ledger.finish(attempt, result)
        if mode != "preflight":
            print("FINISHED: you may leave the test position.", flush=True)
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "invalid_arguments: see --help\n")


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument("--config", required=True, help="root-owned private host JSON")
    parser.add_argument(
        "--output", required=True, help="existing root-owned private campaign directory"
    )
    parser.add_argument("--attempt", required=True, help="anonymous unique schedule ID")
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument(
        "--campaign", required=True, choices=["development", "pilot", "qualification"]
    )
    parser.add_argument(
        "--trace-ioctl",
        action="store_true",
        help="record numeric video ioctl durations; no payloads",
    )
    args = parser.parse_args()
    if os.getuid() != 0 or os.geteuid() != 0:
        print("root_required", file=sys.stderr)
        return 2
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    # Handle normal terminal/service interruption through cleanup and the ledger.
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        for name in ["runner.py", "host.py", "harness.py"]:
            host.trusted_path(Path(__file__).resolve().parent / name)
        config_path = host.trusted_path(args.config)
        output = host.trusted_path(args.output)
        if (
            not output.is_dir()
            or output.stat().st_mode & 0o077
            or config_path.stat().st_mode & 0o077
            or config_path.stat().st_size > 65536
        ):
            raise ValueError("private_paths_required")
        config = host.validate_config(host.strict_json(config_path.read_text()))
        for program in ["/usr/bin/strace", "/usr/bin/fuser", "/usr/bin/systemctl"]:
            host.trusted_path(program)
        # One host-wide lock, independent of campaign output path.
        lock = os.open(
            "/run/irlume-ir-evaluation.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(lock, "w") as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError("untrusted_lock")
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            identity = host.file_identity(config["assets"]["binary"]["path"])
            if identity[-1] != config["assets"]["binary"]["sha256"]:
                raise ValueError("binary_hash_mismatch")
            with tempfile.TemporaryDirectory(
                prefix="irlume-ir-evaluation-", dir="/run"
            ) as stage:
                binary = Path(stage) / "diagnostic"
                # Execute the checked bytes, never a path replaceable by a user.
                data = Path(config["assets"]["binary"]["path"]).read_bytes()
                if hashlib.sha256(data).hexdigest() != identity[-1]:
                    raise ValueError("binary_changed")
                binary.write_bytes(data)
                binary.chmod(0o500)
                result = execute(
                    config,
                    output,
                    args.attempt,
                    args.mode,
                    args.campaign,
                    binary,
                    trace_ioctl=args.trace_ioctl,
                )
                print(
                    json.dumps(
                        {
                            "status": result["status"],
                            "stop_required": result["stop_required"],
                        }
                    )
                )
                return 1 if result["stop_required"] else 0
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 — never print private exception payloads
        print(
            "setup_or_ledger_failed: inspect the private campaign ledger before any retry",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
