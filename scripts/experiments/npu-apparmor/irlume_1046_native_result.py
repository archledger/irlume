"""Acceptance of one completed strict synthetic native test, not certification."""

import json
import math
import re


def require_single_test(output, exit_code):
    summaries = [
        line.strip()
        for line in output.splitlines()
        if line.lstrip().startswith("test result:")
    ]
    pattern = r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in \d+(?:\.\d+)?s"
    if exit_code != 0 or len(summaries) != 1 or not re.fullmatch(pattern, summaries[0]):
        raise ValueError("native test did not complete exactly once")


def parse_native_result(output, exit_code, case):
    require_single_test(output, exit_code)
    lines = [
        line.split("NATIVE_AA_RESULT ", 1)[1]
        for line in output.splitlines()
        if "NATIVE_AA_RESULT " in line
    ]
    if len(lines) != 1:
        raise ValueError("missing or duplicate native result")
    value = json.loads(lines[0])
    executables = {
        "bin-native": "/usr/bin/irlumed",
        "local-native": "/usr/local/bin/irlumed",
    }
    fixed = {
        "case": case,
        "scope": "test-only-native",
        "executable": executables.get(case),
        "label": "irlumed (enforce)",
        "pci_id": "8086:643e",
        "library": "/usr/lib64/libopenvino_c.so.2621",
        "execution_device": "NPU",
        "native_inferences": 6,
        "markers_absent": True,
        "model_sha256": "a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60",
    }
    if case not in executables or any(
        type(value.get(k)) is not type(expected) or value[k] != expected
        for k, expected in fixed.items()
    ):
        raise ValueError("native result disagrees with the case")
    if type(value.get("pid")) is not int or value["pid"] <= 0:
        raise ValueError("missing process identity")
    firmware = value.get("firmware")
    if (
        not isinstance(firmware, str)
        or not firmware.strip()
        or "unverified" in firmware.lower()
    ):
        raise ValueError("missing real firmware identity")
    for name in ("identity_digest", "execution_digest", "cpu_reference_digest"):
        if not re.fullmatch("[0-9a-f]{64}", str(value.get(name, ""))):
            raise ValueError("missing identity digest")
    digests = value.get("raw_output_digests")
    if (
        not isinstance(digests, list)
        or len(digests) != 3
        or any(
            not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v)
            for v in digests
        )
    ):
        raise ValueError("missing native output digests")
    distances = value.get("synthetic_distances")
    if (
        not isinstance(distances, list)
        or len(distances) != 6
        or any(
            type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 0.01
            for v in distances
        )
    ):
        raise ValueError("synthetic CPU comparison failed")
    return value
