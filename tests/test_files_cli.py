"""No-follow input/output faults and private-path fixed diagnostics."""

from contextlib import redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from yara_rule_draft_review.cli import main
from yara_rule_draft_review.files import KEYS, read_local
from yara_rule_draft_review.model import Issue
from yara_rule_draft_review.output import write_draft

RAW = b"DEMO_MARKER_ALPHA_0239\0DEMO_MARKER_BETA_1648"
GOOD = b"DEMO_MARKER_BENIGN_9538"
SOURCE = "rule harmless_draft { condition: false }\n"


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name).resolve()
        self.target = self.folder / "private-target.dat"
        self.benign = self.folder / "private-benign.dat"
        self.target.write_bytes(RAW)
        self.benign.write_bytes(GOOD)
        self.output = self.folder / "drafts"
        self.output.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def assert_issue(self, path, code=None):
        with self.assertRaises(Issue) as raised:
            read_local(path)
        if code:
            self.assertEqual(raised.exception.code, code)

    def cli(self, args):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(args)
        return status, json.loads(output.getvalue())

    def test_exact_read_and_unchanged(self):
        before = self.target.stat()
        self.assertEqual(read_local(str(self.target)), RAW)
        after = self.target.stat()
        self.assertEqual(self.target.read_bytes(), RAW)
        for key in KEYS:
            self.assertEqual(getattr(before, key), getattr(after, key))

    def test_bad_paths(self):
        for path in (
            "",
            ".",
            "..",
            "x/../y",
            "x//y",
            "x/./y",
            str(self.target) + "/",
            "file\0secret",
            "\ud800",
            "x" * 8193,
            None,
            self.folder,
        ):
            self.assert_issue(path)

    def test_special_symlink_and_component(self):
        link = self.folder / "link"
        link.symlink_to(self.target)
        self.assert_issue(str(link))
        directory_link = self.folder / "folder-link"
        directory_link.symlink_to(self.output, target_is_directory=True)
        (self.output / "one").write_bytes(RAW)
        self.assert_issue(str(directory_link / "one"))
        fifo = self.folder / "pipe"
        os.mkfifo(fifo)
        self.assert_issue(str(fifo), "file_not_regular_or_byte_budget")
        self.assert_issue(str(self.output), "file_not_regular_or_byte_budget")

    def test_missing_platform_capabilities(self):
        for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"):
            original = getattr(os, flag)
            delattr(os, flag)
            try:
                self.assert_issue(str(self.target), "safe_file_platform_not_supported")
            finally:
                setattr(os, flag, original)
        with patch.object(os, "supports_dir_fd", set()):
            self.assert_issue(str(self.target), "safe_file_platform_not_supported")
        with patch.object(os, "supports_follow_symlinks", set()):
            self.assert_issue(str(self.target), "safe_file_platform_not_supported")

    def test_controlled_short_read_and_identity(self):
        with patch("yara_rule_draft_review.files.os.read", return_value=b""):
            self.assert_issue(str(self.target), "file_changed_or_short_read")
        before = self.target.stat()
        for key in KEYS:
            values = {k: getattr(before, k) for k in KEYS}
            values[key] += 1
            values["st_mode"] = before.st_mode
            changed = SimpleNamespace(**values)
            with patch("yara_rule_draft_review.files.os.fstat", side_effect=[before, changed]):
                self.assert_issue(str(self.target), "file_changed_or_short_read")
        values = {k: getattr(before, k) for k in KEYS}
        values["st_mode"] = stat.S_IFDIR
        with patch(
            "yara_rule_draft_review.files.os.fstat", side_effect=[before, SimpleNamespace(**values)]
        ):
            self.assert_issue(str(self.target), "file_changed_or_short_read")

    def test_output_fresh_hash_mode_and_no_overwrite(self):
        result = write_draft(SOURCE, str(self.output), [str(self.target)])
        self.assertEqual(result["status"], "PASS")
        name = "draft-" + sha256(SOURCE.encode()).hexdigest() + ".yar"
        created = self.output / name
        self.assertEqual(result["name"], name)
        self.assertEqual(created.read_text(), SOURCE)
        self.assertEqual(stat.S_IMODE(created.stat().st_mode) & 0o077, 0)
        before = created.stat()
        repeated = write_draft(SOURCE, str(self.output))
        self.assertEqual(repeated["status"], "OPEN")
        self.assertTrue(repeated["may_exist"])
        self.assertEqual(created.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(created.read_text(), SOURCE)

    def test_output_independence_and_symlinks(self):
        self.assertEqual(
            write_draft(SOURCE, str(self.folder), [str(self.target)])["issue"],
            "output_directory_not_independent",
        )
        link = self.folder / "dir-link"
        link.symlink_to(self.output, target_is_directory=True)
        self.assertEqual(write_draft(SOURCE, str(link))["status"], "OPEN")
        name = "draft-" + sha256(SOURCE.encode()).hexdigest() + ".yar"
        (self.output / name).symlink_to(self.target)
        self.assertEqual(write_draft(SOURCE, str(self.output))["status"], "OPEN")
        self.assertEqual(self.target.read_bytes(), RAW)
        self.assertTrue((self.output / name).is_symlink())

    def test_failed_write_retains_partial_and_never_unlinks(self):
        native_write = os.write
        count = 0

        def failing(fd, data):
            nonlocal count
            count += 1
            if count == 1:
                return native_write(fd, data[:7])
            raise OSError("PRIVATE_SOURCE_PATH")

        with patch("yara_rule_draft_review.output.os.write", side_effect=failing):
            result = write_draft(SOURCE, str(self.output))
        self.assertEqual(result["status"], "OPEN")
        self.assertTrue(result["may_exist"])
        self.assertEqual((self.output / result["name"]).read_bytes(), SOURCE.encode()[:7])
        self.assertNotIn("PRIVATE_SOURCE_PATH", json.dumps(result))

    def test_replacement_failure_never_deletes_replacement(self):
        native_fsync = os.fsync
        name = "draft-" + sha256(SOURCE.encode()).hexdigest() + ".yar"
        replacement = b"REPLACEMENT_PRIVATE"

        def replace_file(fd):
            native_fsync(fd)
            (self.output / name).unlink()
            (self.output / name).write_bytes(replacement)

        with patch("yara_rule_draft_review.output.os.fsync", side_effect=replace_file):
            result = write_draft(SOURCE, str(self.output))
        self.assertEqual(result["status"], "OPEN")
        self.assertEqual(result["issue"], "output_identity")
        self.assertEqual((self.output / name).read_bytes(), replacement)

    def test_output_bad_types_and_paths(self):
        for directory in (None, self.output, "x/../y", "\ud800", "bad\0path"):
            self.assertEqual(write_draft(SOURCE, directory)["status"], "OPEN")
        for source in (b"RAW", "", "\u4e2d", "x" * (256 * 1024 + 1)):
            self.assertEqual(write_draft(source, str(self.output))["status"], "OPEN")

    def test_cli_redacted_and_explicit_output(self):
        args = ["--target", str(self.target), "--benign", str(self.benign)]
        status, report = self.cli(args)
        self.assertEqual(status, 0)
        self.assertIsNone(report["rule_source"])
        encoded = json.dumps(report)
        self.assertNotIn("private-target", encoded)
        self.assertNotIn("DEMO_MARKER_", encoded)
        status, output = self.cli(args + ["--output-dir", str(self.output)])
        self.assertEqual(status, 0)
        self.assertIsNone(output["rule_source"])
        self.assertTrue((self.output / output["output"]["name"]).exists())
        status, failed = self.cli(args + ["--output-dir", str(self.output)])
        self.assertEqual(status, 2)
        self.assertEqual(failed["status"], "OPEN")
        self.assertEqual(self.target.read_bytes(), RAW)

    def test_cli_reveal_and_errors_never_echo(self):
        status, report = self.cli(
            ["--target", str(self.target), "--benign", str(self.benign), "--reveal-rules"]
        )
        self.assertEqual(status, 0)
        self.assertIn("DEMO_MARKER_", report["rule_source"])
        for args in (
            ["--PRIVATE_SECRET"],
            ["--target", "PRIVATE_SOURCE_PATH", "--benign", str(self.benign)],
            ["--target", str(self.target)],
            [
                "--target",
                str(self.target),
                "--benign",
                str(self.benign),
                "--negative",
                "PRIVATE_SOURCE_PATH",
            ],
        ):
            status, error = self.cli(args)
            self.assertEqual(status, 2)
            encoded = json.dumps(error)
            self.assertNotIn("PRIVATE", encoded)
            self.assertNotIn("private-", encoded)
            self.assertIsNone(error["evidence"])

    def test_cli_count_rejected_before_read(self):
        with patch(
            "yara_rule_draft_review.cli.read_local", side_effect=AssertionError("must not read")
        ):
            status, report = self.cli(["--target", "PRIVATE"] * 17 + ["--benign", "PRIVATE"])
        self.assertEqual(status, 2)
        self.assertEqual(report["issues"][0]["code"], "corpus_type_or_count")


if __name__ == "__main__":
    unittest.main()
