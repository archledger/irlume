import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "attempt4_loader", Path(__file__).with_name("irlume-1046-native-attempt4.py")
)
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)


class SourceLoadingTests(unittest.TestCase):
    def test_hash_mismatch_refuses_before_source_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.py"
            path.write_text('raise AssertionError("must not run")\n')
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                loader.load_source("_a2_test_bad", path, "0" * 64)

    def test_exact_source_loads_without_import_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.py"
            data = b"answer = 42\n"
            path.write_bytes(data)
            module = loader.load_source(
                "_a2_test_good", path, hashlib.sha256(data).hexdigest()
            )
            self.assertEqual(module.answer, 42)


if __name__ == "__main__":
    unittest.main()
