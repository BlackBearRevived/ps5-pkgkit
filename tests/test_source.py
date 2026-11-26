"""Exercise source inventory, path validation, and the JSON CLI."""

import hashlib
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from ps5_pkgkit import SourceError, inspect_source
from ps5_pkgkit.cli import main


PARAM = {
    "titleId": "PPSA99771",
    "contentId": "UP9000-PPSA99771_00-PKGHELLOWORLD001",
    "contentVersion": "01.000.000",
    "applicationCategoryType": 0,
    "applicationDrmType": "free",
}


def make_source(root: Path) -> None:
    """Create the minimum staged-title fixture under an existing root.

    Args:
        root: Temporary directory in which to create the executable and
            metadata.
    """
    (root / "sce_sys").mkdir()
    (root / "eboot.bin").write_bytes(b"ELF fixture")
    (root / "sce_sys" / "param.json").write_text(json.dumps(PARAM), encoding="utf-8")


class SourceTests(unittest.TestCase):
    """Build small staged folders to exercise inspection errors and reports."""
    def test_inspect_source_and_cli_json(self):
        """Compare source inventory and JSON output for a Unicode path."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_source(root)
            (root / "assets").mkdir()
            (root / "assets" / "café.txt").write_text("hello", encoding="utf-8")
            report = inspect_source(root)
            self.assertEqual(report.title_id, PARAM["titleId"])
            self.assertEqual(len(report.files), 3)
            self.assertEqual(report.files[0].path, "assets/café.txt")
            manifest = "".join(f"{item.sha256}  ./{item.path}\n" for item in report.files)
            self.assertEqual(report.manifest_sha256, hashlib.sha256(manifest.encode()).hexdigest())
            self.assertEqual(inspect_source(root), report)
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["inspect-source", str(root), "--json"])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["manifest_sha256"], report.manifest_sha256)

    def test_missing_executable_and_invalid_metadata(self):
        """Report a missing executable and malformed metadata separately."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_source(root)
            (root / "eboot.bin").unlink()
            with self.assertRaisesRegex(SourceError, "missing root eboot.bin"):
                inspect_source(root)
            (root / "eboot.bin").write_bytes(b"ELF fixture")
            (root / "sce_sys" / "param.json").write_text("{bad", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "invalid sce_sys/param.json"):
                inspect_source(root)

    def test_reject_case_collision(self):
        """Reject directory names that differ only by case when supported."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_source(root)
            (root / "ASSETS").mkdir()
            if (root / "assets").exists():
                self.skipTest("filesystem is case insensitive")
            (root / "assets").mkdir()
            with self.assertRaisesRegex(SourceError, "collision"):
                inspect_source(root)

    def test_reject_link(self):
        """Reject a link even when it points inside the staged title."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_source(root)
            try:
                (root / "link").symlink_to(root / "eboot.bin")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(SourceError, "links"):
                inspect_source(root)


class HelloWorldSourceTests(unittest.TestCase):
    """Compare inventory facts against the captured staged title."""
    def test_reference_source_manifest(self):
        """Confirm the canonical manifest digest, file count, and title ID."""
        default = Path(__file__).resolve().parents[1] / ".artifacts" / "hello-world"
        root = Path(os.environ.get("PS5_PKGKIT_REFERENCE", default)) / "PPSA99771"
        if not root.is_dir():
            self.skipTest("local Hello World staged folder unavailable")
        report = inspect_source(root)
        self.assertEqual(report.manifest_sha256, "faf30c49f4f06010340ed7f0596149c7f21dd923293787c6bd6cc0b5412cac4e")
        self.assertEqual(len(report.files), 8)
        self.assertEqual(report.title_id, "PPSA99771")


if __name__ == "__main__":
    unittest.main()
