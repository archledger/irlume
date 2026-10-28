"""One fresh attempt with the corrected, hash-pinned native controller."""

import hashlib
import importlib.machinery
import importlib.util
import os
import signal
import sys
from pathlib import Path


class PinnedSourceLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, name, path, verified_source):
        super().__init__(name, str(path))
        self.verified_source = verified_source

    def get_code(self, fullname):
        # Compile only the bytes already verified below, never a cached .pyc.
        if fullname != self.name:
            raise ImportError('unexpected pinned module name')
        return self.source_to_code(self.verified_source, self.path)


def load_source(name, path, expected):
    with Path(path).open("rb") as stream:
        data = stream.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise RuntimeError("controller source exceeds the fixed bound")
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("reviewed controller source changed")
    loader = PinnedSourceLoader(name, path, data)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


if __name__ == "__main__":
    for key in ("PYTHONPATH", "PYTHONHOME"):
        os.environ.pop(key, None)
    os.environ["PYTHONNOUSERSITE"] = "1"
    os.environ["PATH"] = "/usr/bin:/bin"
    load_source(
        "irlume_1046_native_protocol",
        "/tmp/opencode/irlume_1046_native_protocol.py",
        "a52533d9cc6076bbbd6046e477c77bf9ca3cceeaa02254778a1beaa1c991579c",
    )
    controller = load_source(
        "_irlume_native_attempt4",
        "/tmp/opencode/irlume-1046-native-host-v4.py",
        "275ea02ce5fa51b1b6d49ec8ef70b340fe69e7a84d33f62e39b4c113d5f8f5d7",
    )
    controller.ROOT = Path(
        "/home/wisbfime/archledger-gp/experiments/irlume-1046-native-20261028/attempt4"
    )
    controller.UUID = "3b452049-c1f1-446d-8c56-7a8ae7d4c06d"
    controller.NAME = "irlume-aa-native-a4"
    controller.XML = "/var/lib/libvirt/images/irlume-1046-native-20261028-a4/domain.xml"
    controller.XML_SHA = (
        "41264f0c458cc55ca0f21f4d3ccbc778086554fc74ffd5afe54f9866f44658e2"
    )
    controller.CLIENT = "irlume-1046-native-client-a4"
    controller.TIMER = "irlume-1046-native-stop-a4"
    controller.INHIBITOR = "irlume-1046-native-inhibit-a4"
    # The controller's read-only query subprocess re-enters this pinned wrapper.
    controller.__file__ = __file__
    signal.signal(signal.SIGTERM, controller.interrupted)
    signal.signal(signal.SIGINT, controller.interrupted)
    if sys.argv[1:] == ["query"]:
        controller.query_restored()
    elif not sys.argv[1:]:
        controller.start()
    else:
        raise SystemExit("unknown operation")
