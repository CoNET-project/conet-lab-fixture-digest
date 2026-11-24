#!/usr/bin/python3 -IB
"""Synthetic-only tests for the archive-only read path."""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve()
PACKAGE = HERE.parents[1]
ARCHIVE_HELPER = PACKAGE / "assets" / "lab-g3-fixture-archive-summary.py"
ARCHIVE_SPEC = importlib.util.spec_from_file_location("archive_summary_under_test", ARCHIVE_HELPER)
ARCHIVE = importlib.util.module_from_spec(ARCHIVE_SPEC)
ARCHIVE_SPEC.loader.exec_module(ARCHIVE)

# Use the reviewed source helper, not the older copy packaged in fault-guards.
SOURCE_HELPER = PACKAGE / "assets" / "lab-g3-fixture-summary.py"
with SOURCE_HELPER.open("rb") as source_file:
    SOURCE = source_file.read()
if hashlib.sha256(SOURCE).hexdigest() != ARCHIVE.ENGINE_SHA256:
    raise RuntimeError("reviewed source helper hash mismatch")
ENGINE = types.ModuleType("fixture_summary_engine_under_test")
exec(compile(SOURCE, str(SOURCE_HELPER), "exec", dont_inherit=True), ENGINE.__dict__)
if not sys.platform.startswith("linux"):
    ENGINE._mount_id = lambda _fd: 41

SUPPORT_PATH = HERE.with_name("test_fixture_summary.py")
SUPPORT_SPEC = importlib.util.spec_from_file_location("fixture_summary_support", SUPPORT_PATH)
SUPPORT = importlib.util.module_from_spec(SUPPORT_SPEC)
SUPPORT_SPEC.loader.exec_module(SUPPORT)


class ArchiveSummaryTests(unittest.TestCase):
    def setUp(self):
        temp_root = pathlib.Path(tempfile.gettempdir()).resolve()
        self.tmp = tempfile.TemporaryDirectory(prefix="lab-g3-archive-synth-", dir=str(temp_root))
        self.root, self.policy = SUPPORT.make_fixture(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def summarize(self, after_first_pass=None):
        return ARCHIVE.summarize_archive_for_test(
            ENGINE, str(self.root), self.policy, after_first_pass=after_first_pass)

    def test_archive_is_independent_of_active_v2_or_v3_wal(self):
        before = self.summarize()
        state = self.root / "state" / "payout-state.v2"
        manifest = json.loads((state / "manifest.json").read_text())
        manifest["version"] = 3
        manifest["walFormat"] = 1
        (state / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
        (state / "wal").mkdir()
        (state / "wal" / "wal-0000000000000001.log").write_bytes(b"synthetic active v3 wal\n")
        after = self.summarize()
        self.assertEqual(before["archive"], after["archive"])

    def test_pinned_engine_hash_required_before_compile(self):
        loaded = ARCHIVE._compile_engine(SOURCE, hashlib.sha256(SOURCE).hexdigest())
        self.assertTrue(callable(loaded._archive_summary))
        self.assertEqual(loaded.CONFIG_PATH, "/etc/lab-fixture-digest/g3.json")
        self.assertEqual(ARCHIVE.ENGINE_PATH, "/usr/local/sbin/lab-fixture-digest")
        with self.assertRaises(ARCHIVE.Refusal) as ctx:
            ARCHIVE._compile_engine(SOURCE, "0" * 64)
        self.assertEqual(ctx.exception.category, "ENGINE_HASH_MISMATCH")

    def test_accept_matching_historical_generation_directories(self):
        name = "gen-20000101T000300Z-123456abcdef"
        for state_name in ("state-v3-attempt8", "state-v3-attempt8-live"):
            SUPPORT.write(self.root / ENGINE.ARCHIVE / state_name / name / "historical.jsonl",
                          b"synthetic historical generation\n")
        result = self.summarize()
        self.assertEqual(result["archive"]["historical_generations"], sorted([
            "state-v3-attempt8/" + name,
            "state-v3-attempt8-live/" + name,
        ]))

    def test_reject_generation_named_regular_file(self):
        name = "gen-20000101T000300Z-123456abcdef"
        target = self.root / ENGINE.ARCHIVE / "state-v3-attempt8" / name
        target.write_bytes(b"not a generation directory\n")
        with self.assertRaises(ENGINE.Refusal) as ctx:
            self.summarize()
        self.assertEqual(ctx.exception.category, "ARCHIVE_V3_HISTORICAL_GENERATION_INVALID")

    def test_reject_different_archived_v3_copies(self):
        target = (self.root / ENGINE.ARCHIVE / "state-v3-attempt8" /
                  "gen-20000101T000200Z-abcdef123456" / "pending-000000.jsonl")
        target.write_bytes(b"different synthetic v3 copy\n")
        with self.assertRaises(ENGINE.Refusal) as ctx:
            self.summarize()
        self.assertEqual(ctx.exception.category, "ARCHIVE_V3_COPIES_DIFFER")

    def test_success_prints_archive_files_and_directories_without_bodies(self):
        result = self.summarize()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ARCHIVE._print_archive("a" * 64, result, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
        text = out.getvalue()
        self.assertIn("STATUS=PASS", text)
        self.assertIn("ARCHIVE_DIR type=directory", text)
        self.assertIn("ARCHIVE_FILE type=file", text)
        self.assertNotIn("synthetic", text)

    def test_reject_archive_entry_change_between_passes(self):
        target = self.root / ENGINE.ARCHIVE / "window-attempt8" / "g3-cutover.log"
        with self.assertRaises(ARCHIVE.Refusal) as ctx:
            self.summarize(after_first_pass=lambda: target.write_bytes(b"changed synthetic entry\n"))
        self.assertEqual(ctx.exception.category, "SNAPSHOT_DRIFT")

    def test_reject_unexpected_archive_root_entry(self):
        (self.root / ENGINE.ARCHIVE / "unexpected-synthetic-entry").write_bytes(b"x")
        with self.assertRaises(ENGINE.Refusal) as ctx:
            self.summarize()
        self.assertEqual(ctx.exception.category, "ARCHIVE_ENTRY_SET")

    def test_reject_archive_symlink(self):
        target = self.root / ENGINE.ARCHIVE / "systemctl.calls-attempt8"
        target.unlink()
        target.symlink_to(self.root / "deny.json")
        with self.assertRaises(ENGINE.Refusal) as ctx:
            self.summarize()
        self.assertEqual(ctx.exception.category, "SYMLINK_REFUSED")

    def test_reject_archive_hardlink(self):
        source = self.root / ENGINE.ARCHIVE / "window-attempt8" / "g3-cutover.log"
        alias = source.with_name("g3-cutover.hardlink")
        os.link(source, alias)
        with self.assertRaises(ENGINE.Refusal) as ctx:
            self.summarize()
        self.assertEqual(ctx.exception.category, "HARDLINK_REFUSED")

    def test_reject_cross_mount_using_mount_id_test_double(self):
        original = ENGINE._mount_id
        calls = 0

        def mount_id(fd):
            nonlocal calls
            calls += 1
            if calls <= 2:
                return original(fd)
            return 987654321

        with mock.patch.object(ENGINE, "_mount_id", mount_id):
            with self.assertRaises(ENGINE.Refusal) as ctx:
                self.summarize()
        self.assertEqual(ctx.exception.category, "MOUNT_BOUNDARY")

    def test_reject_additional_wal_file_in_archived_v3(self):
        wal = self.root / ENGINE.ARCHIVE / "state-v3-attempt8" / "wal" / "wal-extra.log"
        wal.write_bytes(b"synthetic extra wal\n")
        with self.assertRaises(ENGINE.Refusal) as ctx:
            self.summarize()
        self.assertEqual(ctx.exception.category, "ARCHIVE_V3_WAL_FILE_SET")

    def test_expired_config_fails_before_archive_output(self):
        original = ENGINE._load_private_config
        expired = dict(self.policy, valid_until_epoch=10)
        ENGINE._load_private_config = lambda: (expired, "b" * 64, (1, 2, 3))
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = ARCHIVE._run(lambda: ENGINE, now_epoch=10)
        finally:
            ENGINE._load_private_config = original
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue().strip(), "STATUS=FAIL CATEGORY=CONFIG_EXPIRED")

    def test_production_entry_rejects_arguments(self):
        old_argv = sys.argv
        old_env = os.environ.copy()
        out = io.StringIO()
        try:
            sys.argv = [str(ARCHIVE_HELPER), "unexpected-path"]
            with contextlib.redirect_stdout(out):
                rc = ARCHIVE.main()
        finally:
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(rc, 2)
        self.assertEqual(out.getvalue().strip(), "STATUS=FAIL CATEGORY=ARGUMENTS")


if __name__ == "__main__":
    unittest.main()
