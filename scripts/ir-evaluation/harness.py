"""Attended diagnostic runner; persist categories/timings and video-open metadata only."""

import os
import re
import selectors
import signal
import subprocess
import time

from host import strict_json

CATEGORIES = frozenset(
    {
        "ready",
        "candidate_match",
        "identity_mismatch",
        "no_face",
        "liveness_refused",
        "pad_unavailable",
        "pad_invalid",
        "pad_refused",
        "incompatible_enrollment",
        "enrollment_unavailable",
        "models_unavailable",
        "camera_unavailable",
        "invalid_frame",
        "cancelled",
        "deadline_expired",
        "invalid_request",
        "root_required",
        "inference_failed",
        "camera_busy",
        "camera_rate_refused",
        "camera_lease_timeout",
        "camera_lease_refused",
        "camera_io_failed",
        "camera_hardware_failed",
        "camera_rate_fill_io_permission_denied",
        "camera_rate_fill_io_invalid_argument",
        "camera_rate_fill_io_device",
        "camera_rate_fill_io_no_space",
        "camera_rate_fill_io_timeout",
        "camera_rate_fill_io_other",
        "camera_rate_fill_buffer_timestamp",
        "camera_rate_fill_buffer_clock",
        "camera_rate_fill_buffer_source",
        "camera_rate_fill_buffer_layout",
        "camera_rate_fill_timestamp_non_increasing",
        "camera_rate_fill_timestamp_clock",
        "camera_rate_fill_timestamp_source",
        "camera_rate_fill_timestamp_epoch",
        "camera_rate_fill_sequence",
        "camera_rate_fill_rate_window",
        "camera_rate_fill_privacy_boundary",
        "camera_rate_fill_privacy_engaged",
        "camera_rate_fill_privacy_read_permission_denied",
        "camera_rate_fill_privacy_read_device",
        "camera_rate_fill_privacy_read_timeout",
        "camera_rate_fill_privacy_read_busy",
        "camera_rate_fill_privacy_read_other",
        "camera_rate_fill_lease_boundary",
        "camera_rate_fill_stream_state",
        "camera_rate_fill_continuity_alignment",
        "camera_rate_fill_continuity_accounting",
        "camera_rate_fill_incomplete_window",
        "camera_rate_fill_missing_stream",
        "camera_rate_fill_stopped_stream",
        "camera_rate_fill_other",
        "camera_authorization_refused",
        "camera_policy_refused",
        "camera_capture_failed",
    }
)
TIMINGS = frozenset(
    {"elapsed_ms", "capture_ms", "detection_ms", "pad_ms", "identity_ms"}
)


def video_event(line):
    # Only trace open/close metadata. No other paths or syscall payload survive.
    match = re.search(
        r"(?:\b(openat2|openat|open|close)\(|<\.\.\. (openat2|openat|open|close) resumed>)",
        line,
    )
    device = re.search(r'["<](/dev/video[0-9]+)["><]', line)
    timestamp = re.search(r"(?:^|\s)([0-9]+\.[0-9]+)\s", line)
    if not match or not device or not timestamp:
        return None
    result = re.search(r"\s=\s(-?[0-9]+)", line)
    operation = match.group(1) or match.group(2)
    return {
        "timestamp": float(timestamp.group(1)),
        "operation": "close" if operation == "close" else "open",
        "device": device.group(1),
        "fd": (
            int(result.group(1))
            if result and operation != "close"
            else int(re.search(r"close\(([0-9]+)", line).group(1))
            if re.search(r"close\(([0-9]+)", line)
            else None
        ),
        "result": int(result.group(1)) if result else None,
    }


def ioctl_event(line, live):
    """Decode raw ioctl syntax; retain only metadata for a known video fd."""
    match = re.search(r"\bioctl\((0x[0-9a-f]+|0),", line)
    if not match:
        if "ioctl(" in line:
            raise ValueError("unexpected ioctl syntax")
        return None
    fd = int(match.group(1), 16)
    if fd not in live:
        return None
    fields = re.search(
        r"ioctl\((0x[0-9a-f]+|0), (0x[0-9a-f]+|0), (?:0x[0-9a-f]+|0)\s*\)"
        r"\s+=\s+(-1|0x[0-9a-f]+|0)(?: [^<>]*)? <([0-9]+)\.([0-9]{6})>$",
        line.strip(),
    )
    timestamp = re.search(r"(?:^|\s)([0-9]+\.[0-9]+)\s", line)
    if fields is None or timestamp is None:
        raise ValueError("unexpected video ioctl syntax")
    duration = int(fields.group(4)) * 1_000_000 + int(fields.group(5))
    request = int(fields.group(2), 16)
    if duration > 120_000_000 or request > 0xFFFFFFFF:
        raise ValueError("invalid ioctl metadata")
    return {
        "timestamp": float(timestamp.group(1)),
        "device": live[fd],
        "fd": fd,
        "request": request,
        "result": int(fields.group(3), 16),
        "duration_us": duration,
    }


def checked_report(record):
    required = {
        "schema",
        "operation",
        "authentication_granted",
        "category",
        "elapsed_ms",
    }
    if not isinstance(record, dict) or "schema" not in record:
        raise ValueError("unexpected diagnostic output schema")
    version = record.get("schema")
    extra = set()
    if type(version) is int and version in (2, 3, 4):
        extra.add("capture_stages_ms")
    if version == 4:
        extra.add("identity_acceptance")
    if record.keys() != required | TIMINGS | extra:
        raise ValueError("unexpected diagnostic output schema")
    if (
        type(record["schema"]) is not int
        or record["schema"] not in (1, 2, 3, 4)
        or record["operation"] != "ir_only_evaluation"
        or record["authentication_granted"] is not False
    ):
        raise ValueError("not a non-granting diagnostic result")
    if not isinstance(record["category"], str) or record["category"] not in CATEGORIES:
        raise ValueError("unknown result category")
    if version == 4:
        acceptance = record["identity_acceptance"]
        if record["category"] == "candidate_match":
            if type(acceptance) is not str or acceptance not in {
                "best_template",
                "centroid",
                "both",
            }:
                raise ValueError("invalid identity acceptance evidence")
        elif acceptance is not None:
            raise ValueError("identity acceptance contradicts result category")
    for key in TIMINGS & record.keys():
        value = record[key]
        if value is None and key != "elapsed_ms":
            continue
        if type(value) is not int or not 0 <= value <= 3_600_000:
            raise ValueError("invalid stage timing")
    if version in (2, 3, 4):
        stages = record["capture_stages_ms"]
        labels = {
            "open",
            "session_setup",
            "buffers",
            "metadata",
            "emitter",
            "warmup",
            "rate_fill",
            "frames",
            "session_release",
        }
        if version in (3, 4):
            labels |= {
                "image_stop",
                "metadata_streamoff",
                "metadata_buffers",
                "metadata_format",
                "metadata_close",
                "emitter_restore",
            }
        if not isinstance(stages, dict) or stages.keys() != labels:
            raise ValueError("unexpected capture timing schema")
        if any(
            value is not None
            and (type(value) is not int or not 0 <= value <= 3_600_000)
            for value in stages.values()
        ):
            raise ValueError("invalid capture timing")
    return record


def run_traced(
    command,
    *,
    env=None,
    cancel_after_ms=None,
    cancel_on_ir_open=None,
    timeout=45,
    tracer="/usr/bin/strace",
    trace_ioctl=False,
):
    """One fixed diagnostic invocation; no raw stderr is retained.

    A selector drains pipes without blocking reader threads. A dead tracer,
    watchdog, or exception triggers process-group cleanup before returning.
    `tracer` exists for harmless real-process failure tests; trials use strace.
    """
    if timeout <= 0 or timeout > 120:
        raise ValueError("watchdog must be within (0,120] seconds")
    events, output, trace_buffer = [], bytearray(), bytearray()
    flags = {"trace_error": False, "output_overflow": False, "trace_overflow": False}
    ioctl_events, live = [], {}
    ir_open = False
    started = time.monotonic()
    proc = None
    selector = None
    cancelled, watchdog, early_exit = False, False, False
    exited_at = None
    stopping_at = None
    killed = False

    def signal_group(sig):
        try:
            if proc is not None:
                os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass

    pending = {}

    def consume_trace(raw):
        nonlocal ir_open
        line = raw.decode("utf-8", errors="replace")
        if line.startswith("strace:") and "Process " not in line:
            flags["trace_error"] = True
        prefix = re.match(r"^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?\d+\.\d+\s+", line)
        thread = (prefix.group(1) or prefix.group(2) or "main") if prefix else None
        resumed = re.search(r"<\.\.\. (\w+) resumed>", line)
        if "<unfinished ...>" in line:
            if (
                thread is None
                or thread in pending
                or len(pending) >= 1024
                or len(line) > 4096
            ):
                flags["trace_error"] = True
            else:
                pending[thread] = line.split("<unfinished ...>", 1)[0]
            return
        if resumed:
            original = pending.pop(thread, None)
            if original is None or not re.search(
                r"\b" + resumed.group(1) + r"\(", original
            ):
                flags["trace_error"] = True
                return
            line = original + line[resumed.end() :]
        # Only a single process with shared thread descriptors is supported.
        # A successful process fork, descriptor duplication, or bulk close
        # makes per-fd release evidence ambiguous: fail conservatively.
        successful = re.search(r"\s=\s([0-9]+)", line)
        if successful:
            if re.search(
                r"\b(clone3?|fork|vfork)\(|<\.\.\. (clone3?|fork|vfork) resumed>", line
            ) and not ("CLONE_THREAD" in line and "CLONE_FILES" in line):
                flags["trace_error"] = True
            if re.search(r"\b(close_range|unshare)\(", line):
                flags["trace_error"] = True
            if "/dev/video" in line and re.search(r"\b(dup[23]?|fcntl)\(", line):
                flags["trace_error"] = True
        if trace_ioctl:
            try:
                measured = ioctl_event(line, live)
            except ValueError:
                flags["trace_error"] = True
            else:
                if measured:
                    if len(ioctl_events) < 10000:
                        ioctl_events.append(measured)
                    else:
                        flags["trace_overflow"] = True
        event = video_event(line)
        if event:
            if event["result"] is not None and event["result"] >= 0:
                if trace_ioctl:
                    for entry in pending.values():
                        inflight = re.search(r"\bioctl\((0x[0-9a-f]+|0),", entry)
                        if inflight and int(inflight.group(1), 16) == event["fd"]:
                            flags["trace_error"] = True
                if event["operation"] == "open":
                    if event["fd"] in live:
                        flags["trace_error"] = True
                    live[event["fd"]] = event["device"]
                elif event["result"] == 0:
                    live.pop(event["fd"], None)
            if len(events) < 10000:
                events.append(event)
            else:
                flags["trace_overflow"] = True
            if (
                event["device"] == cancel_on_ir_open
                and event["operation"] == "open"
                and event["result"] is not None
                and event["result"] >= 0
            ):
                ir_open = True

    try:
        proc = subprocess.Popen(
            [
                tracer,
                "-q",
                "-f",
                "-ttt",
                "-yy",
                "-e",
                "trace=open,openat,openat2,close,clone,clone3,fork,vfork,dup,dup2,dup3,fcntl,close_range,unshare"
                + (",ioctl" if trace_ioctl else ""),
                *(["-T", "-e", "raw=ioctl"] if trace_ioctl else []),
                "--",
                *command,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        for pipe, name in [(proc.stdout, "output"), (proc.stderr, "trace")]:
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() or proc.poll() is None:
            now = time.monotonic()
            elapsed = now - started
            if proc.poll() is not None and exited_at is None:
                exited_at = now
            if stopping_at is None:
                due = (
                    cancel_after_ms is not None and elapsed * 1000 >= cancel_after_ms
                ) or ir_open
                if due and not cancelled and proc.poll() is None:
                    try:
                        proc.stdin.write(b"x")
                        proc.stdin.flush()
                        cancelled = True
                    except BrokenPipeError:
                        pass
                if elapsed >= timeout:
                    watchdog = True
                    stopping_at = now
                elif (
                    exited_at is not None
                    and selector.get_map()
                    and now - exited_at >= 0.2
                ):
                    early_exit = True
                    stopping_at = now
                if stopping_at is not None:
                    signal_group(signal.SIGTERM)
            if stopping_at is not None:
                if not killed and now - stopping_at >= 0.2:
                    signal_group(signal.SIGKILL)
                    killed = True
                if now - stopping_at >= 1:
                    break
            for key, _ in selector.select(0.01):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "output":
                    if len(output) + len(chunk) <= 16384:
                        output.extend(chunk)
                    else:
                        flags["output_overflow"] = True
                else:
                    trace_buffer.extend(chunk)
                    while b"\n" in trace_buffer:
                        raw, _, rest = trace_buffer.partition(b"\n")
                        trace_buffer[:] = rest
                        consume_trace(raw)
                    if len(trace_buffer) > 65536:
                        trace_buffer.clear()
                        flags["trace_overflow"] = True
        if trace_buffer:
            consume_trace(trace_buffer)
        if pending:
            flags["trace_error"] = True
        complete = not selector.get_map()
    finally:
        # Even a tracer that has already exited may have left children alive.
        signal_group(signal.SIGKILL)
        try:
            if proc is not None:
                proc.wait(timeout=3)
        finally:
            if selector is not None:
                selector.close()
            if proc is not None:
                for pipe in (proc.stdin, proc.stdout, proc.stderr):
                    pipe.close()
    report = None
    output_valid = False
    if not flags["output_overflow"]:
        try:
            report = checked_report(strict_json(output))
            output_valid = True
        except (ValueError, TypeError):
            pass
    return {
        "returncode": proc.returncode,
        "report": report,
        "output_valid": output_valid,
        "video_events": events,
        **({"video_ioctl_events": ioctl_events} if trace_ioctl else {}),
        "cancellation_sent": cancelled,
        "watchdog_fired": watchdog,
        "early_tracer_exit": early_exit,
        "wall_elapsed_ms": round((time.monotonic() - started) * 1000),
        "readers_completed": complete,
        **flags,
    }


def release_checks(events, ir_device, metadata_device, *, preflight=False):
    """Pair each descriptor lifetime once; ambiguous/incomplete traces fail."""
    live = {}
    saw_image = False
    for event in events:
        if preflight:
            return False
        if event["device"] not in {ir_device, metadata_device}:
            return False
        fd, result = event.get("fd"), event["result"]
        if result is None or fd is None:
            return False
        if event["operation"] == "open":
            if result < 0:
                continue
            if fd in live:
                return False
            live[fd] = event
            saw_image |= event["device"] == ir_device
        else:
            opened = live.pop(fd, None)
            if (
                result != 0
                or opened is None
                or opened["device"] != event["device"]
                or event["timestamp"] < opened["timestamp"]
            ):
                return False
    return not live and (preflight or saw_image)


def trial_checks(result, mode, ir_device="/dev/video2", metadata_device="/dev/video3"):
    if (
        result["returncode"] != 0
        or not result["output_valid"]
        or not result["readers_completed"]
        or not result["installed_unchanged"]
    ):
        return False
    if any(
        result[k]
        for k in [
            "watchdog_fired",
            "early_tracer_exit",
            "trace_error",
            "trace_overflow",
            "output_overflow",
        ]
    ):
        return False
    if not release_checks(
        result["video_events"],
        ir_device,
        metadata_device,
        preflight=mode == "preflight",
    ):
        return False
    if mode == "preflight":
        return result["report"]["category"] == "ready"
    if mode == "cancel":
        return (
            result["cancellation_sent"] and result["report"]["category"] == "cancelled"
        )
    return result["report"]["category"] != "ready"
