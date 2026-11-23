#!/usr/bin/python3 -IB
"""Synthetic-only tests for the fixed-path summary helper."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
HELPER = pathlib.Path(__file__).resolve().parents[1] / "assets" / "lab-g3-fixture-summary.py"
SPEC = importlib.util.spec_from_file_location("fixture_summary_under_test", HELPER)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
# Linux production uses /proc/self/fdinfo mnt_id. Only non-Linux local unit tests
# substitute a stable mount identity; Linux tests use the real kernel value.
if not sys.platform.startswith("linux"):
    MOD._mount_id = lambda _fd: 41


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def selected_tree_hash(state, generation, previous):
    files = ["manifest.json"]
    for root in (generation, previous):
        for path in (state / root).rglob("*"):
            if path.is_file() and not path.is_symlink():
                files.append(path.relative_to(state).as_posix())
    lines = []
    for rel in sorted(files, key=lambda s: s.encode("ascii")):
        lines.append(sha((state / rel).read_bytes()) + "  " + rel + "\n")
    return sha("".join(lines).encode("ascii"))


def make_fixture(base):
    root = pathlib.Path(base)
    gen = "gen-20000101T000000Z-aabbccddeeff"
    prev = "gen-19991231T235900Z-112233445566"
    state = root / "state" / "payout-state.v2"
    manifest = json.dumps({"version": 2, "generation": gen, "previousGeneration": prev,
                           "pending": {"count": 1}, "consumed": {"lines": 1},
                           "scalars": {"settledBatchCount": 1}}, sort_keys=True,
                          separators=(",", ":")).encode()
    write(state / "manifest.json", manifest)
    write(state / gen / "pending-000000.jsonl", b"synthetic pending secret marker\n")
    write(state / gen / "consumed.jsonl", b"synthetic consumed marker\n")
    write(state / prev / "exited.jsonl", b"")
    input_bytes = {
        "site.env": b"synthetic site secret marker\n",
        "env/env0": b"synthetic env0\n",
        "env/d6.env": b"synthetic d6\n",
        "deny.json": b"synthetic deny marker\n",
    }
    for rel, data in input_bytes.items():
        write(root / rel, data)

    archive = root / MOD.ARCHIVE
    for d in ("control-attempt8", "cp-mount-empty-attempt8", "dropins-attempt8"):
        (archive / d).mkdir(parents=True)
    files = {
        "dispatcher.calls-attempt8": b"synthetic call log\n",
        "dispatcher.denied-attempt8": b"synthetic deny log\n",
        "root-dispatcher-positive-attempt8.py": b"synthetic dispatcher marker\n",
        "startup-journal-attempt8.log": b"synthetic startup marker\n",
        "systemctl-positive-attempt8": b"synthetic unit marker\n",
        "systemctl.calls-attempt8": b"synthetic systemctl calls\n",
        "systemctl.mutations-attempt8": b"synthetic mutation log\n",
    }
    for rel, data in files.items():
        write(archive / rel, data)
    window = archive / "window-attempt8"
    for rel in MOD.ARCHIVE_REQUIRED_WINDOW:
        write(window / rel, ("synthetic " + rel + "\n").encode())

    archive_manifest = json.dumps({"version": 3, "walFormat": 1,
                                   "generation": "gen-20000101T000200Z-abcdef123456",
                                   "previousGeneration": "gen-20000101T000100Z-abcdef123456"},
                                  sort_keys=True, separators=(",", ":")).encode()
    wal_blob = b"synthetic wal marker\n"
    for state_name in ("state-v3-attempt8", "state-v3-attempt8-live"):
        st = archive / state_name
        write(st / "manifest.json", archive_manifest)
        write(st / "wal" / "wal-0000000000000001.log", wal_blob)
        write(st / "gen-20000101T000200Z-abcdef123456" / "pending-000000.jsonl", b"synthetic v3 pending\n")
        write(st / "gen-20000101T000100Z-abcdef123456" / "consumed.jsonl", b"synthetic v3 consumed\n")
    policy = {
        "fixture_root": str(root),
        "v2_manifest_sha256": sha(manifest),
        "v2_selected_tree_sha256": selected_tree_hash(state, gen, prev),
        "v2_generation": gen,
        "v2_previous_generation": prev,
        "archive_manifest_sha256": sha(archive_manifest),
        "archive_wal_sha256": sha(wal_blob),
    }
    return root, policy


class FixtureSummaryTests(unittest.TestCase):
    def setUp(self):
        parent = pathlib.Path(tempfile.gettempdir()).resolve()
        self.tmp = tempfile.TemporaryDirectory(prefix="lab-g3-summary-synth-", dir=parent)
        self.root, self.policy = make_fixture(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def expect_category(self, category):
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD.summarize_for_test(str(self.root), self.policy)
        self.assertEqual(ctx.exception.category, category)

    def test_positive_and_no_sensitive_body(self):
        result = MOD.summarize_for_test(str(self.root), self.policy)
        self.assertEqual(result["v2"]["selected_tree_sha256"], self.policy["v2_selected_tree_sha256"])
        self.assertEqual(set(result["inputs"]), set(MOD.INPUTS))
        self.assertEqual(result["archive"]["file_count"], 7 + len(MOD.ARCHIVE_REQUIRED_WINDOW) + 2 * 4)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            MOD._print_summary("0" * 64, result, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
        body = out.getvalue()
        for marker in ("site secret marker", "pending secret marker", "deny marker"):
            self.assertNotIn(marker, body)
        self.assertIn("STATUS=PASS", body)
        self.assertIn("site.env", body)
        self.assertIn("INPUT type=file", body)
        self.assertIn("ARCHIVE type=directory", body)
        self.assertIn("ARCHIVE_FILE type=file", body)

    def test_reject_symlink_input(self):
        (self.root / "site.env").unlink()
        (self.root / "site.env").symlink_to(self.root / "deny.json")
        self.expect_category("SYMLINK_REFUSED")

    def test_reject_symlink_fixture_root(self):
        alias = pathlib.Path(self.tmp.name).parent / (pathlib.Path(self.tmp.name).name + "-alias")
        alias.symlink_to(self.root, target_is_directory=True)
        try:
            with self.assertRaises(MOD.Refusal) as ctx:
                MOD.summarize_for_test(str(alias), self.policy)
            self.assertEqual(ctx.exception.category, "PATH_REFUSED")
        finally:
            alias.unlink()

    def test_reject_hardlink_input(self):
        os.link(self.root / "site.env", self.root / "site.env.link")
        self.expect_category("HARDLINK_REFUSED")

    def test_reject_special_input(self):
        (self.root / "deny.json").unlink()
        os.mkfifo(self.root / "deny.json")
        self.expect_category("NODE_TYPE")

    def test_reject_wal_path(self):
        (self.root / "state" / "payout-state.v2" / "wal").mkdir()
        self.expect_category("WAL_PRESENT")

    def test_reject_unexpected_archive_entry(self):
        write(self.root / MOD.ARCHIVE / "unexpected", b"not emitted")
        self.expect_category("ARCHIVE_ENTRY_SET")

    def test_reject_archive_symlink(self):
        p = self.root / MOD.ARCHIVE / "systemctl.calls-attempt8"
        p.unlink()
        p.symlink_to(self.root / "deny.json")
        self.expect_category("SYMLINK_REFUSED")

    def test_reject_snapshot_drift_between_passes(self):
        def change():
            (self.root / "env" / "d6.env").write_bytes(b"different synthetic input\n")
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD.summarize_for_test(str(self.root), self.policy, after_first_pass=change)
        self.assertEqual(ctx.exception.category, "SNAPSHOT_DRIFT")

    def test_reject_directory_replacement_between_passes(self):
        def replace_env_dir():
            old = self.root / "env.saved"
            (self.root / "env").rename(old)
            new = self.root / "env"
            new.mkdir()
            (new / "env0").write_bytes((old / "env0").read_bytes())
            (new / "d6.env").write_bytes((old / "d6.env").read_bytes())
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD.summarize_for_test(str(self.root), self.policy, after_first_pass=replace_env_dir)
        self.assertEqual(ctx.exception.category, "SNAPSHOT_DRIFT")

    def test_reject_v2_selected_tree_change(self):
        gen = self.policy["v2_generation"]
        def change_selected_tree():
            (self.root / "state" / "payout-state.v2" / gen / "consumed.jsonl").write_bytes(b"changed synthetic tree\n")
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD.summarize_for_test(str(self.root), self.policy, after_first_pass=change_selected_tree)
        self.assertEqual(ctx.exception.category, "V2_ANCHOR_MISMATCH")

    def test_config_schema_and_fixture_scope(self):
        valid = {
            "schema_version": 1,
            "fixture_root": "/var/tmp/lab-g3-synth-test-abcdef",
            "v2_manifest_sha256": "1" * 64,
            "v2_selected_tree_sha256": "2" * 64,
            "v2_generation": "gen-20000101T000000Z-aabbccddeeff",
            "v2_previous_generation": "gen-19991231T235900Z-112233445566",
            "archive_manifest_sha256": "3" * 64,
            "archive_wal_sha256": "4" * 64,
            "valid_until_epoch": 2000000000,
        }
        self.assertEqual(MOD._strict_config_blob(json.dumps(valid).encode()), valid)
        bad = dict(valid, fixture_root="/var/tmp/other-path")
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD._strict_config_blob(json.dumps(bad).encode())
        self.assertEqual(ctx.exception.category, "CONFIG_INVALID")
        bad = dict(valid, valid_until_epoch=True)
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD._strict_config_blob(json.dumps(bad).encode())
        self.assertEqual(ctx.exception.category, "CONFIG_INVALID")
        MOD._check_expiry(valid, 1999999999)
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD._check_expiry(valid, 2000000000)
        self.assertEqual(ctx.exception.category, "CONFIG_EXPIRED")
        bad = dict(valid, schema_version=True)
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD._strict_config_blob(json.dumps(bad).encode())
        self.assertEqual(ctx.exception.category, "CONFIG_INVALID")
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD._strict_config_blob(b'{"schema_version":1,"schema_version":1}')
        self.assertEqual(ctx.exception.category, "CONFIG_INVALID")
        bad = dict(valid, extra="rejected")
        with self.assertRaises(MOD.Refusal) as ctx:
            MOD._strict_config_blob(json.dumps(bad).encode())
        self.assertEqual(ctx.exception.category, "CONFIG_INVALID")

    def test_production_entry_rejects_all_arguments(self):
        old_argv = sys.argv
        old_env = os.environ.copy()
        out = io.StringIO()
        try:
            sys.argv = [str(HELPER), "unexpected"]
            with contextlib.redirect_stdout(out):
                rc = MOD.main()
            self.assertEqual(rc, 2)
            self.assertEqual(out.getvalue().strip(), "STATUS=FAIL CATEGORY=ARGUMENTS")
        finally:
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)

    def test_production_entry_rejects_expired_configuration_before_reading_fixture(self):
        out = io.StringIO()
        config = {"valid_until_epoch": 1}
        with patch.object(sys, "argv", [str(HELPER)]), patch.dict(os.environ), \
                patch.object(MOD, "_load_private_config", return_value=(config, "unused", ())), \
                patch.object(MOD, "_summary_pass") as summary, contextlib.redirect_stdout(out):
            self.assertEqual(MOD.main(), 1)
        summary.assert_not_called()
        self.assertEqual(out.getvalue().strip(), "STATUS=FAIL CATEGORY=CONFIG_EXPIRED")

    def test_config_owner_mode_gate(self):
        root_ok = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
        MOD._check_config_stat(root_ok)
        for bad in (
            SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0, st_nlink=1),
            SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=501, st_gid=0, st_nlink=1),
            SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=2),
        ):
            with self.assertRaises(MOD.Refusal) as ctx:
                MOD._check_config_stat(bad)
            self.assertEqual(ctx.exception.category, "CONFIG_PERMISSIONS")
        MOD._check_config_dir_stat(SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0))
        for bad_dir in (
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=501, st_gid=0),
        ):
            with self.assertRaises(MOD.Refusal) as ctx:
                MOD._check_config_dir_stat(bad_dir)
            self.assertEqual(ctx.exception.category, "CONFIG_DIRECTORY_PERMISSIONS")


if __name__ == "__main__":
    unittest.main()
