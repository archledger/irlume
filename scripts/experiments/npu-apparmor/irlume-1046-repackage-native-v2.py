"""Repackage corrected guest helpers without changing the prior frozen payload."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("/home/wisbfime/archledger-gp/experiments/irlume-1046-native-20261028")
OLD = Path("/tmp/opencode/irlume-1046-native-payload")
revision = sys.argv[1] if len(sys.argv) == 2 else "2"
if revision not in ("2", "3", "4", "5"):
    raise SystemExit("unsupported payload revision")
NEW = Path("/tmp/opencode/irlume-1046-native-payload-v" + revision)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


inputs = json.loads((ROOT / "inputs.json").read_text())
assert inputs["uuid"] == "fc178b75-d12b-4fe8-9296-e6b60ec0341a"
assert (
    sha(ROOT / "domain.xml")
    == inputs["xml_sha256"]
    == "5e82467e0240b1f2be3f02a85db63e4e367f857a3c1f4780888e4fb30550aa60"
)
assert sha(ROOT / "seed.iso") == inputs["seed_sha256"]
manifest = json.loads((OLD / "manifest.json").read_text())
for relative, digest in manifest["files"].items():
    assert sha(OLD / relative) == digest, relative
assert not NEW.exists()
shutil.copytree(
    OLD,
    NEW,
    symlinks=True,
    copy_function=os.link,
    ignore=lambda directory, names: (
        {"helpers", "runner.py", "manifest.json"} if Path(directory) == OLD else set()
    ),
)
(NEW / "helpers").mkdir()
shutil.copyfile("/tmp/opencode/irlume-1046-native-guest.py", NEW / "runner.py")
for name in (
    "irlume_1046_native_preflight.py",
    "irlume_1046_native_result.py",
    "irlume_1046_native_audit.py",
):
    shutil.copyfile(Path("/tmp/opencode") / name, NEW / "helpers" / name)
staging = json.loads((ROOT / "native-library-staging.json").read_text())
manifest["native_lookups"] = [
    {"lookup": lookup, "canonical": row["canonical"]}
    for row in staging["files"]
    for lookup in (row["selected"], Path(row["selected"]).name)
]
manifest["files"] = {
    str(path.relative_to(NEW)): sha(path)
    for path in NEW.rglob("*")
    if path.is_file() and not path.is_symlink()
}
(NEW / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
iso = Path("/tmp/opencode/irlume-1046-native-payload-v" + revision + ".iso")
assert not iso.exists()
subprocess.run(
    [
        "xorriso",
        "-as",
        "mkisofs",
        "-quiet",
        "-o",
        str(iso),
        "-V",
        "IRLUME_PAYLOAD",
        "-r",
        "-J",
        "-uid",
        "0",
        "-gid",
        "0",
        str(NEW),
    ],
    check=True,
    capture_output=True,
)
inputs["payload"] = {"path": str(iso), "sha256": sha(iso), "bytes": iso.stat().st_size}
inputs["revision"] = int(revision)
with (ROOT / ("inputs-v" + revision + ".json")).open("x") as output:
    json.dump(inputs, output, indent=2)
    output.write("\n")
with (ROOT / ("native-payload-manifest-v" + revision + ".json")).open("x") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
print(json.dumps(inputs, indent=2))
