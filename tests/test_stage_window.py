"""Pure synthetic tests for the short-lived A-window controller."""
import hashlib
import contextlib
import importlib.util
import io
import json
import pathlib
import re
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve()
MODULE_PATH = HERE.parents[1] / "ops" / "lab-g3-archive-a" / "stage-window.py"
SPEC = importlib.util.spec_from_file_location("lab_g3_archive_a_stage", MODULE_PATH)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
ROOT_ENTRY_PATH = HERE.parents[1] / "ops" / "lab-g3-archive-a" / "root-entry.py"
ROOT_SPEC = importlib.util.spec_from_file_location("lab_g3_archive_a_root_entry", ROOT_ENTRY_PATH)
ROOT = importlib.util.module_from_spec(ROOT_SPEC)
ROOT_SPEC.loader.exec_module(ROOT)
INSTALL_PATH = HERE.parents[1] / "ops" / "lab-g3-archive-a" / "root-install.py"
INSTALL_SPEC = importlib.util.spec_from_file_location("lab_g3_archive_a_root_install", INSTALL_PATH)
INSTALL = importlib.util.module_from_spec(INSTALL_SPEC)
INSTALL_SPEC.loader.exec_module(INSTALL)


def synthetic_bootstrap():
    return {
        "schema_version": 1,
        "operator": "synthetic_operator",
        "source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
        "source_commit": "a" * 40,
        "input_sha256": {name: str(i) * 64 for i, name in enumerate(
            ("site.env", "env/env0", "env/d6.env", "deny.json"), start=1)},
        "stage_script_sha256": "b" * 64,
        "valid_until_epoch": 9000,
        "fixture_root": "/var/tmp/lab-g3-synth-20261123T000000Z-abcdef",
        "v2_manifest_sha256": "c" * 64,
        "v2_selected_tree_sha256": "d" * 64,
        "v2_generation": "gen-20261123T000001Z-123456abcdef",
        "v2_previous_generation": "gen-20261123T000000Z-abcdef123456",
        "archive_manifest_sha256": "e" * 64,
        "archive_wal_sha256": "f" * 64,
        "root_entry_path": "/run/lab-g3-archive-a-loader-123456abcdef.py",
        "root_entry_sha256": "9" * 64,
    }


def terminal_record():
    run_name = "lab-g3-archive-a-20261124T010000Z-abcdef123456"
    return {
        "schema_version": 1, "run_name": run_name,
        "run_dir": "/run/" + run_name,
        "terminal_dir": "/run/lab-g3-archive-a-terminal/" + run_name + ".journal",
        "operation": "running", "state": "RUNNING", "phase": "RUNNING", "revision": 0,
        "source_checkout": "/var/tmp/lab-archive-a-src.Synth001", "source_commit": "a" * 40,
        "operator_uid": 1001, "deadline": 9999999999,
        "stage_script_sha256": "b" * 64,
        "root_entry_path": "/run/lab-g3-archive-a-loader-abcdef123456.py",
        "root_entry_sha256": "c" * 64,
        "sudoers_path": "/etc/sudoers.d/" + run_name, "sudoers_sha256": "d" * 64,
        "active_sha256": "e" * 64, "meta_sha256": "f" * 64,
        "bootstrap_sha256": "1" * 64,
        "host_snapshots": {path: str(i) * 64 for i, path in enumerate(
            ("/usr/local/sbin", "/etc/sudoers.d", "/run/systemd", "/run/dbus"), start=1)},
        "host_mnt_ns": "mnt:[10]", "host_net_ns": "net:[11]",
        "field_completed": False, "review_completed": False,
    }


def anchor_lines(generation="gen-20261123T000001Z-123456abcdef",
                 previous="gen-20261123T000000Z-abcdef123456", wal="ABSENT"):
    return ("STATUS=PASS\n"
            "START_UTC=2026-11-23T00:00:00Z\n"
            "END_UTC=2026-11-23T00:00:01Z\n"
            "CONFIG=PASS sha256=" + "1" * 64 + "\n"
            "V2_BEFORE_AFTER=IDENTICAL version=2 generation=" + generation +
            " previous=" + previous + " manifest_sha256=" + "2" * 64 +
            " selected_tree_sha256=" + "3" * 64 + " files=7 WAL=" + wal + "\n"
            "INPUT type=file path=site.env sha256=" + "4" * 64 + " size=10 uid=0 gid=0 mode=0600\n"
            "INPUT type=file path=env/env0 sha256=" + "5" * 64 + " size=10 uid=0 gid=0 mode=0600\n"
            "INPUT type=file path=env/d6.env sha256=" + "6" * 64 + " size=10 uid=0 gid=0 mode=0600\n"
            "INPUT type=file path=deny.json sha256=" + "7" * 64 + " size=10 uid=0 gid=0 mode=0600\n"
            "ARCHIVE type=directory path=attempt8-pre-fault-replay-archive sha256=-\n"
            "ARCHIVE_FILE type=file path=placeholder sha256=" + "8" * 64 + "\n")


def valid_entry_output():
    source = [line for line in anchor_lines().splitlines()
              if line.startswith(("STATUS=", "START_UTC=", "END_UTC=", "CONFIG=", "V2_BEFORE_AFTER=", "INPUT "))]
    archive = ("STATUS=PASS\n"
               "START_UTC=2026-11-23T00:00:00Z\n"
               "END_UTC=2026-11-23T00:00:01Z\n"
               "CONFIG=PASS sha256=" + "1" * 64 + "\n"
               "ARCHIVE type=directory path=attempt8-pre-fault-replay-archive sha256=- uid=0 gid=0 mode=0700 top_level_exact=PASS files=1 entries=1 aggregate_sha256=" + "9" * 64 + "\n")
    return ("STATUS=PASS\nBEGIN_PRE_ANCHOR\n" + "\n".join(source) +
            "\nEND_PRE_ANCHOR\nBEGIN_ARCHIVE_ONLY\n" + archive +
            "END_ARCHIVE_ONLY\nBEGIN_POST_ANCHOR\n" + "\n".join(source) +
            "\nEND_POST_ANCHOR\n")


class StageWindowTests(unittest.TestCase):
    def test_prepare_blocks_unconsumed_root_install_spec_before_session_creation(self):
        with mock.patch.object(MOD, "_check_root"), \
                mock.patch.object(MOD, "_host_preflight"), \
                mock.patch.object(MOD.os.path, "lexists",
                                  side_effect=lambda path: path == MOD.INSTALL_SPEC), \
                mock.patch.object(MOD, "_terminal_preflight") as terminal_preflight:
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._prepare()
        self.assertEqual(caught.exception.category, "INSTALL_SPEC_PENDING")
        terminal_preflight.assert_not_called()

    def test_prepare_checks_pending_terminal_journal_before_reading_bootstrap(self):
        with mock.patch.object(MOD, "_check_root"), \
                mock.patch.object(MOD, "_host_preflight"), \
                mock.patch.object(MOD, "_terminal_preflight", side_effect=MOD.Refusal("TERMINAL_PENDING")), \
                mock.patch.object(MOD, "_read_regular") as read_regular:
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._prepare()
        self.assertEqual(caught.exception.category, "TERMINAL_PENDING")
        read_regular.assert_not_called()

    def test_terminal_preflight_blocks_unread_terminal_and_allows_readback_done(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp).resolve() / "terminal"
            base.mkdir(mode=0o700)
            name = terminal_record()["run_name"] + ".journal"
            (base / name).mkdir(mode=0o700)
            record = terminal_record()
            with mock.patch.object(MOD, "TERMINAL_BASE", str(base)), \
                    mock.patch.object(MOD, "TERMINAL_UID", MOD.os.getuid()), \
                    mock.patch.object(MOD, "TERMINAL_GID", base.stat().st_gid), \
                    mock.patch.object(MOD, "_terminal_read", return_value=(record, b"{}")):
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._terminal_preflight()
                self.assertEqual(caught.exception.category, "TERMINAL_PENDING")
                record["phase"] = "READBACK_DONE"
                record["state"] = "COMPLETE"
                MOD._terminal_preflight()

    def test_terminal_create_rolls_back_only_its_partial_nodes(self):
        source = pathlib.Path(MOD.SCRIPT)
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        run_name = "lab-g3-archive-a-20261124T010000Z-abcdef123456"
        host = {p: str(i) * 64 for i, p in enumerate(
            ("/usr/local/sbin", "/etc/sudoers.d", "/run/systemd", "/run/dbus"), start=1)}
        active = {"run_name": run_name, "run_dir": "/run/" + run_name,
                  "sudoers_path": "/etc/sudoers.d/" + run_name, "sudoers_sha256": "d" * 64}
        meta = {"source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "a" * 40, "operator_uid": 1001, "deadline": 9999999999,
                "stage_script_sha256": source_sha,
                "root_entry_path": "/run/lab-g3-archive-a-loader-123456abcdef.py",
                "root_entry_sha256": "c" * 64, "bootstrap_sha256": "1" * 64,
                "host_snapshots": host, "host_mnt_ns": "mnt:[10]", "host_net_ns": "net:[11]"}

        for fail_after in (1, 2, 3):
            with self.subTest(fail_after=fail_after), tempfile.TemporaryDirectory() as temp:
                base = pathlib.Path(temp).resolve() / "terminal"
                calls = {"count": 0}
                real_write_new = MOD._write_new

                def fail_after_write(path, content, mode=0o600, created=None):
                    result = real_write_new(path, content, mode, created=created)
                    calls["count"] += 1
                    if calls["count"] == fail_after:
                        raise RuntimeError("synthetic interruption after durable file")
                    return result

                with mock.patch.object(MOD, "TERMINAL_BASE", str(base)), \
                        mock.patch.object(MOD, "RUN_BASE", "/run"), \
                        mock.patch.object(MOD, "SUDOERS_DIR", "/etc/sudoers.d"), \
                        mock.patch.object(MOD, "TERMINAL_UID", MOD.os.getuid()), \
                        mock.patch.object(MOD, "TERMINAL_GID", base.parent.stat().st_gid), \
                        mock.patch.object(MOD, "_terminal_preflight"), \
                        mock.patch.object(MOD, "_terminal_read", side_effect=lambda _p: (None, b"")), \
                        mock.patch.object(MOD.os, "chown"), \
                        mock.patch.object(MOD.os, "fchown"), \
                        mock.patch.object(MOD, "_write_new", side_effect=fail_after_write):
                    with self.assertRaises(RuntimeError):
                        MOD._terminal_create(active, meta, "e" * 64, "f" * 64)
                self.assertFalse(base.exists(), "only this invocation's empty journal tree is removed")

    def test_terminal_create_cleans_its_partial_write_by_recorded_inode(self):
        source = pathlib.Path(MOD.SCRIPT)
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        run_name = "lab-g3-archive-a-20261124T010002Z-abcdef123456"
        active = {"run_name": run_name, "run_dir": "/run/" + run_name,
                  "sudoers_path": "/etc/sudoers.d/" + run_name, "sudoers_sha256": "d" * 64}
        meta = {"source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "a" * 40, "operator_uid": 1001, "deadline": 9999999999,
                "stage_script_sha256": source_sha,
                "root_entry_path": "/run/lab-g3-archive-a-loader-123456abcdef.py",
                "root_entry_sha256": "c" * 64, "bootstrap_sha256": "1" * 64,
                "host_snapshots": {p: str(i) * 64 for i, p in enumerate(
                    ("/usr/local/sbin", "/etc/sudoers.d", "/run/systemd", "/run/dbus"), start=1)},
                "host_mnt_ns": "mnt:[10]", "host_net_ns": "net:[11]"}
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp).resolve() / "terminal"
            real_write = MOD.os.write
            writes = {"count": 0}
            def partial_then_fail(fd, data):
                writes["count"] += 1
                if writes["count"] == 1:
                    return real_write(fd, data[:1])
                raise OSError("synthetic short-write interruption")
            with mock.patch.object(MOD, "TERMINAL_BASE", str(base)), \
                    mock.patch.object(MOD, "TERMINAL_UID", MOD.os.getuid()), \
                    mock.patch.object(MOD, "TERMINAL_GID", base.parent.stat().st_gid), \
                    mock.patch.object(MOD, "_terminal_preflight"), \
                    mock.patch.object(MOD.os, "chown"), \
                    mock.patch.object(MOD.os, "fchown"), \
                    mock.patch.object(MOD.os, "write", side_effect=partial_then_fail):
                with self.assertRaises(OSError):
                    MOD._terminal_create(active, meta, "e" * 64, "f" * 64)
            self.assertFalse(base.exists())

    def test_terminal_create_leaves_unrecognized_node_for_fail_closed_review(self):
        source = pathlib.Path(MOD.SCRIPT)
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        run_name = "lab-g3-archive-a-20261124T010001Z-abcdef123456"
        active = {"run_name": run_name, "run_dir": "/run/" + run_name,
                  "sudoers_path": "/etc/sudoers.d/" + run_name, "sudoers_sha256": "d" * 64}
        meta = {"source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "a" * 40, "operator_uid": 1001, "deadline": 9999999999,
                "stage_script_sha256": source_sha,
                "root_entry_path": "/run/lab-g3-archive-a-loader-123456abcdef.py",
                "root_entry_sha256": "c" * 64, "bootstrap_sha256": "1" * 64,
                "host_snapshots": {p: str(i) * 64 for i, p in enumerate(
                    ("/usr/local/sbin", "/etc/sudoers.d", "/run/systemd", "/run/dbus"), start=1)},
                "host_mnt_ns": "mnt:[10]", "host_net_ns": "net:[11]"}
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp).resolve() / "terminal"
            real_write_new = MOD._write_new
            def add_unrecognized(path, content, mode=0o600, created=None):
                result = real_write_new(path, content, mode, created=created)
                if pathlib.Path(path).name == "control.lock":
                    (pathlib.Path(path).parent / "unknown").write_text("keep", encoding="ascii")
                    raise RuntimeError("synthetic interruption with foreign entry")
                return result
            with mock.patch.object(MOD, "TERMINAL_BASE", str(base)), \
                    mock.patch.object(MOD, "TERMINAL_UID", MOD.os.getuid()), \
                    mock.patch.object(MOD, "TERMINAL_GID", base.parent.stat().st_gid), \
                    mock.patch.object(MOD, "_terminal_preflight"), \
                    mock.patch.object(MOD.os, "chown"), \
                    mock.patch.object(MOD.os, "fchown"), \
                    mock.patch.object(MOD, "_write_new", side_effect=add_unrecognized):
                with self.assertRaises(RuntimeError):
                    MOD._terminal_create(active, meta, "e" * 64, "f" * 64)
            terminal_dir = base / (run_name + ".journal")
            self.assertTrue((terminal_dir / "unknown").exists())
            self.assertTrue((terminal_dir / "control.lock").exists())
            with mock.patch.object(MOD, "_terminal_read", side_effect=MOD.Refusal("TERMINAL_ENTRY_SET")), \
                    mock.patch.object(MOD, "TERMINAL_BASE", str(base)), \
                    mock.patch.object(MOD, "TERMINAL_UID", MOD.os.getuid()), \
                    mock.patch.object(MOD, "TERMINAL_GID", base.stat().st_gid):
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._terminal_preflight()
                self.assertEqual(caught.exception.category, "TERMINAL_ENTRY_SET")

    def test_terminal_sudoers_and_baseline_failures_preserve_resume_phase(self):
        record = terminal_record()
        record.update({"operation": "abort", "state": "ABORTING", "phase": "RULE_INTENT", "revision": 2})
        binding = {"path": record["root_entry_path"], "sha256": record["root_entry_sha256"],
                   "verb": "readback", "terminal_dir": record["terminal_dir"], "terminal_phase": "RULE_INTENT"}
        with mock.patch.object(MOD, "_terminal_lock", return_value=93), \
                mock.patch.object(MOD, "_terminal_read", return_value=(record, b"{}")), \
                mock.patch.object(MOD.os, "close"), \
                mock.patch.object(MOD, "_sudoers_remove", side_effect=MOD.Refusal("SUDOERS_ENTRY_DRIFT")) as remove, \
                mock.patch.object(MOD, "ROOT_ENTRY_BINDING", binding):
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._terminal_finish(record["terminal_dir"])
        self.assertEqual(caught.exception.category, "SUDOERS_ENTRY_DRIFT")
        self.assertEqual(record["phase"], "RULE_INTENT")
        remove.assert_called_once()

        record = terminal_record()
        record.update({"operation": "abort", "state": "ABORTING", "phase": "CHECKOUT_DONE", "revision": 18})
        wrong = dict(record["host_snapshots"])
        wrong["/usr/local/sbin"] = "0" * 64
        with mock.patch.object(MOD, "_terminal_lock", return_value=94), \
                mock.patch.object(MOD, "_terminal_read", return_value=(record, b"{}")), \
                mock.patch.object(MOD.os.path, "lexists", return_value=False), \
                mock.patch.object(MOD, "_host_snapshots", return_value=wrong), \
                mock.patch.object(MOD, "_sudoers_global_check"), \
                mock.patch.object(MOD.os, "close"):
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._terminal_finish(record["terminal_dir"])
        self.assertEqual(caught.exception.category, "TERMINAL_HOST_POSTCHECK")
        self.assertEqual(record["phase"], "CHECKOUT_DONE")

    def test_terminal_transitions_bind_operation_and_allow_only_readback_after_complete(self):
        record = terminal_record()
        closing = MOD._terminal_next(record, operation="close", state="CLOSING",
                                     field_completed=True, review_completed=True)
        self.assertEqual(closing["phase"], "INTENT")
        self.assertEqual(closing["operation"], "close")
        rule_intent = MOD._terminal_next(closing, phase="RULE_INTENT")
        self.assertEqual(rule_intent["phase"], "RULE_INTENT")
        changed = dict(rule_intent)
        changed["source_commit"] = "9" * 40
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._terminal_check_transition(rule_intent, changed)
        self.assertEqual(caught.exception.category, "TERMINAL_BINDING")
        done = dict(rule_intent, phase="COMPLETE", state="COMPLETE",
                    revision=rule_intent["revision"] + 1)
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._terminal_check_transition(rule_intent, done)
        self.assertEqual(caught.exception.category, "TERMINAL_TRANSITION")
        complete = dict(rule_intent, phase="POSTCHECK_PASS", revision=rule_intent["revision"] + 1)
        complete = MOD._terminal_next(complete, phase="COMPLETE", state="COMPLETE")
        readback = MOD._terminal_next(complete, phase="READBACK_DONE")
        self.assertEqual(readback["state"], "COMPLETE")
        self.assertEqual(readback["phase"], "READBACK_DONE")

    def test_terminal_cleanup_resumes_each_delete_boundary_and_readback_is_idempotent(self):
        failures = ("rule", "watchdog", "bootstrap", "active", "run", "checkout")
        for fail_at in failures:
            with self.subTest(fail_at=fail_at):
                record = terminal_record()
                record["host_mnt_ns"] = "mnt:[10]"
                record["host_net_ns"] = "net:[11]"
                record["bootstrap_sha256"] = hashlib.sha256(b"synthetic bootstrap").hexdigest()
                record["active_sha256"] = hashlib.sha256(b"synthetic active").hexdigest()
                entry_path = record["root_entry_path"]
                present = {MOD.BOOTSTRAP, MOD.ACTIVE, record["run_dir"],
                           record["source_checkout"], record["sudoers_path"],
                           record["run_dir"] + "/watchdog.pid", entry_path}
                fired = set()
                removed = {"rule": 0, "watchdog": 0, "bootstrap": 0, "active": 0, "run": 0, "checkout": 0}

                def maybe_fail(name):
                    removed[name] += 1
                    if name == fail_at and name not in fired:
                        fired.add(name)
                        raise RuntimeError("synthetic interruption")

                def advance(_path, *, phase=None, operation=None, state=None, **updates):
                    nonlocal record
                    record = MOD._terminal_next(record, phase=phase, operation=operation, state=state, **updates)
                    return record

                def lexists(path):
                    return path in present

                def isdir(path):
                    return path == record["run_dir"] and path in present

                def read_regular(path, owner, mode, limit=65536):
                    raw = b"synthetic bootstrap" if path == MOD.BOOTSTRAP else b"synthetic active"
                    return raw, None

                def unlink(path):
                    present.discard(path)
                    if path == MOD.BOOTSTRAP:
                        maybe_fail("bootstrap")
                    elif path == MOD.ACTIVE:
                        maybe_fail("active")

                def remove_rule(_active):
                    present.discard(record["sudoers_path"])
                    maybe_fail("rule")
                    return "REMOVED_AND_VALIDATED"

                def stop_watchdog(_run, allow_absent=False):
                    present.discard(record["run_dir"] + "/watchdog.pid")
                    maybe_fail("watchdog")
                    return "STOPPED"

                def remove_run(*args, **kwargs):
                    present.discard(record["run_dir"])
                    maybe_fail("run")

                def remove_checkout(*args, **kwargs):
                    present.discard(record["source_checkout"])
                    maybe_fail("checkout")
                    return "REMOVED"

                binding = {"path": entry_path, "sha256": record["root_entry_sha256"],
                           "verb": "readback", "terminal_dir": record["terminal_dir"],
                           "terminal_phase": "COMPLETE"}
                patches = [
                    mock.patch.object(MOD, "_terminal_lock", return_value=99),
                    mock.patch.object(MOD, "_terminal_read", side_effect=lambda _p: (record, b"{}")),
                    mock.patch.object(MOD, "_terminal_advance", side_effect=advance),
                    mock.patch.object(MOD, "_terminal_publish_complete"),
                    mock.patch.object(MOD.os, "close"),
                    mock.patch.object(MOD.os.path, "lexists", side_effect=lexists),
                    mock.patch.object(MOD.os.path, "isdir", side_effect=isdir),
                    mock.patch.object(MOD, "_sudoers_remove", side_effect=remove_rule),
                    mock.patch.object(MOD, "_sudoers_global_check"),
                    mock.patch.object(MOD, "_stop_watchdog", side_effect=stop_watchdog),
                    mock.patch.object(MOD, "_assert_no_window_processes"),
                    mock.patch.object(MOD, "_mounts_for_run", return_value=False),
                    mock.patch.object(MOD, "_check_run_tree"),
                    mock.patch.object(MOD, "_read_regular", side_effect=read_regular),
                    mock.patch.object(MOD.os, "unlink", side_effect=unlink),
                    mock.patch.object(MOD, "_safe_remove_tree", side_effect=remove_run),
                    mock.patch.object(MOD, "_validate_checkout_for_cleanup"),
                    mock.patch.object(MOD, "_remove_checkout", side_effect=remove_checkout),
                    mock.patch.object(MOD, "_host_snapshots", return_value=record["host_snapshots"]),
                    mock.patch.object(MOD.os, "readlink", side_effect=lambda path: {
                        "/proc/self/ns/mnt": "mnt:[10]", "/proc/self/ns/net": "net:[11]"}.get(path)),
                    mock.patch.object(MOD, "_remove_root_entry", side_effect=lambda p, _sha: present.discard(p)),
                    mock.patch.object(MOD, "ROOT_ENTRY_BINDING", binding),
                ]
                with contextlib.ExitStack() as stack:
                    for patcher in patches:
                        stack.enter_context(patcher)
                    with self.assertRaises(RuntimeError):
                        MOD._terminal_finish(record["terminal_dir"], "close", True, True)
                    self.assertEqual(record["phase"], {
                        "rule": "RULE_INTENT", "watchdog": "WATCHDOG_INTENT",
                        "bootstrap": "BOOTSTRAP_INTENT", "active": "ACTIVE_INTENT",
                        "run": "RUN_INTENT", "checkout": "CHECKOUT_INTENT",
                    }[fail_at])
                    self.assertEqual(MOD._terminal_finish(record["terminal_dir"]), 0)
                    self.assertEqual(record["phase"], "COMPLETE")
                    self.assertNotIn(MOD.BOOTSTRAP, present)
                    self.assertNotIn(MOD.ACTIVE, present)
                    self.assertNotIn(record["sudoers_path"], present)
                    self.assertNotIn(record["run_dir"], present)
                    self.assertNotIn(record["source_checkout"], present)
                    self.assertEqual(MOD._terminal_verify_and_mark_readback(record["terminal_dir"], record), 0)
                    self.assertEqual(record["phase"], "READBACK_DONE")
                    self.assertNotIn(entry_path, present)
                    self.assertEqual(MOD._terminal_verify_and_mark_readback(record["terminal_dir"], record), 0)
                    self.assertEqual(record["phase"], "READBACK_DONE")

    def test_root_installer_same_bytes_install_and_independent_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            dest = root / "lab-g3-archive-a-loader-123456abcdef.py"
            data = b"trusted synthetic root entry\n"
            uid, gid = MOD.os.getuid(), MOD.os.getgid()
            MOD.os.chown(root, uid, gid)
            spec = {
                "schema_version": 1,
                "source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "a" * 40,
                "source_uid": uid,
                "source_gid": gid,
                "entry_sha256": hashlib.sha256(data).hexdigest(),
                "destination": str(dest),
                "valid_until_epoch": 9999999999,
            }
            with mock.patch.object(INSTALL, "ROOT_UID", MOD.os.getuid()), \
                    mock.patch.object(INSTALL, "ROOT_GID", MOD.os.getgid()), \
                    mock.patch.object(INSTALL, "RUN_DIR", str(root)), \
                    mock.patch.object(INSTALL.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=gid)), \
                    mock.patch.object(INSTALL, "ENTRY_PATH", re.compile(
                        r"^" + re.escape(str(root)) + r"/lab-g3-archive-a-loader-[0-9a-f]{12}\.py$")):
                checked, same_bytes = INSTALL.install_from_bytes(
                    json.dumps(spec, sort_keys=True, separators=(",", ":")).encode(),
                    read_source=lambda *_args: data, now=1)
                spec_raw = (json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n").encode()
                receipt_sha = INSTALL._install(checked, same_bytes, hashlib.sha256(spec_raw).hexdigest())
                installed, installed_st = INSTALL._read_fixed_root_file(str(dest), 0o500, 4096)
                receipt_path = pathlib.Path(str(dest)[:-3] + ".install.json")
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(installed, data)
            self.assertEqual(installed_st.st_nlink, 1)
            self.assertEqual(stat.S_IMODE(installed_st.st_mode), 0o500)
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(receipt["readback"], "PASS")
            self.assertEqual(receipt["entry_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(receipt["spec_sha256"], hashlib.sha256(spec_raw).hexdigest())
            self.assertEqual(receipt_sha, hashlib.sha256(receipt_path.read_bytes()).hexdigest())

    def test_root_installer_resumes_partial_loader_and_receipt_idempotently(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            dest = root / "lab-g3-archive-a-loader-123456abcdef.py"
            data = b"synthetic pinned loader bytes\n"
            uid, gid = MOD.os.getuid(), MOD.os.getgid()
            MOD.os.chown(root, uid, gid)
            spec = {
                "schema_version": 1,
                "source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "a" * 40,
                "source_uid": uid, "source_gid": gid,
                "entry_sha256": hashlib.sha256(data).hexdigest(),
                "destination": str(dest), "valid_until_epoch": 9999999999,
            }
            spec_raw = (json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n").encode()
            receipt = {
                "schema_version": 2,
                "source_commit": spec["source_commit"],
                "entry_sha256": spec["entry_sha256"],
                "destination": spec["destination"],
                "spec_sha256": hashlib.sha256(spec_raw).hexdigest(),
                "readback": "PASS",
            }
            receipt_raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
            receipt_path = pathlib.Path(str(dest)[:-3] + ".install.json")
            dest.write_bytes(data[:9])
            dest.chmod(0o600)
            receipt_path.write_bytes(receipt_raw[:17])
            receipt_path.chmod(0o600)
            with mock.patch.object(INSTALL, "ROOT_UID", uid), \
                    mock.patch.object(INSTALL, "ROOT_GID", gid), \
                    mock.patch.object(INSTALL, "RUN_DIR", str(root)), \
                    mock.patch.object(INSTALL.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=gid)), \
                    mock.patch.object(INSTALL, "ENTRY_PATH", re.compile(
                        r"^" + re.escape(str(root)) + r"/lab-g3-archive-a-loader-[0-9a-f]{12}\.py$")):
                checked, same_bytes = INSTALL.install_from_bytes(
                    spec_raw, read_source=lambda *_args: data, now=1)
                first_sha = INSTALL._install(checked, same_bytes, hashlib.sha256(spec_raw).hexdigest())
                second_sha = INSTALL._install(checked, same_bytes, hashlib.sha256(spec_raw).hexdigest())
                installed, installed_st = INSTALL._read_fixed_root_file(str(dest), 0o500, 4096)
                saved_receipt, saved_st = INSTALL._read_fixed_root_file(str(receipt_path), 0o600, 4096)
            self.assertEqual(installed, data)
            self.assertEqual(saved_receipt, receipt_raw)
            self.assertEqual(installed_st.st_nlink, 1)
            self.assertEqual(saved_st.st_nlink, 1)
            self.assertEqual(first_sha, second_sha)

    def test_root_installer_refuses_nonprefix_partial_artifact_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            artifact = root / "lab-g3-archive-a-loader-123456abcdef.py"
            artifact.write_bytes(b"foreign")
            artifact.chmod(0o600)
            uid, gid = MOD.os.getuid(), MOD.os.getgid()
            MOD.os.chown(root, uid, gid)
            MOD.os.chown(artifact, uid, gid)
            original = artifact.read_bytes()
            with mock.patch.object(INSTALL, "ROOT_UID", uid), \
                    mock.patch.object(INSTALL, "ROOT_GID", gid), \
                    mock.patch.object(INSTALL, "RUN_DIR", str(root)):
                with self.assertRaises(INSTALL.Refusal) as caught:
                    INSTALL._write_install_artifact(artifact.name, b"trusted expected bytes", 0o500, 4096)
            self.assertEqual(caught.exception.category, "INSTALL_ARTIFACT_CONTENT")
            self.assertEqual(artifact.read_bytes(), original)

    def test_root_installer_consumes_only_exact_unchanged_spec(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            spec_path = root / "lab-g3-archive-a-install.json"
            raw = b"synthetic spec bytes\n"
            spec_path.write_bytes(raw)
            spec_path.chmod(0o600)
            uid, gid = MOD.os.getuid(), MOD.os.getgid()
            os_chown = INSTALL.os.chown
            os_chown(root, uid, gid)
            os_chown(spec_path, uid, gid)
            with mock.patch.object(INSTALL, "ROOT_UID", uid), \
                    mock.patch.object(INSTALL, "ROOT_GID", gid), \
                    mock.patch.object(INSTALL, "RUN_DIR", str(root)), \
                    mock.patch.object(INSTALL, "SPEC_PATH", str(spec_path)):
                snapshot = INSTALL.os.stat(spec_path, follow_symlinks=False)
                INSTALL._consume_spec(raw, snapshot)
                self.assertFalse(spec_path.exists())
                spec_path.write_bytes(raw)
                spec_path.chmod(0o600)
                os_chown(spec_path, uid, gid)
                changed = b"changed spec bytes\n"
                spec_path.write_bytes(changed)
                spec_path.chmod(0o600)
                changed_stat = INSTALL.os.stat(spec_path, follow_symlinks=False)
                with self.assertRaises(INSTALL.Refusal) as caught:
                    INSTALL._consume_spec(raw, changed_stat)
            self.assertEqual(caught.exception.category, "SPEC_REMOVE_DRIFT")
            self.assertEqual(spec_path.read_bytes(), changed)

    def test_root_installer_rejects_wrong_pin_and_source_link_without_installing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            checkout = root / "lab-archive-a-src.Synth001"
            (checkout / "ops" / "lab-g3-archive-a").mkdir(parents=True)
            checkout.chmod(0o700)
            source = checkout / "ops" / "lab-g3-archive-a" / "root-entry.py"
            source.write_bytes(b"synthetic entry\n")
            source.chmod(0o644)
            uid, gid = MOD.os.getuid(), MOD.os.getgid()
            MOD.os.chown(checkout, uid, gid)
            with mock.patch.object(INSTALL, "SOURCE_PATH", re.compile(r"^" + re.escape(str(checkout)) + r"$")), \
                    mock.patch.object(INSTALL, "SOURCE_REL", ("ops", "lab-g3-archive-a", "root-entry.py")):
                good = hashlib.sha256(source.read_bytes()).hexdigest()
                self.assertEqual(INSTALL._read_source_entry(str(checkout), uid, gid, good), b"synthetic entry\n")
                with self.assertRaises(INSTALL.Refusal) as caught:
                    INSTALL._read_source_entry(str(checkout), uid, gid, "0" * 64)
                self.assertEqual(caught.exception.category, "SOURCE_HASH")
                source.unlink()
                source.symlink_to(checkout / "missing-target")
                with self.assertRaises(INSTALL.Refusal):
                    INSTALL._read_source_entry(str(checkout), uid, gid, good)
            self.assertEqual(sorted(p.name for p in root.iterdir()), [checkout.name])

    def test_root_installer_readback_mismatch_fails_before_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            dest = root / "lab-g3-archive-a-loader-123456abcdef.py"
            data = b"synthetic pinned loader\n"
            uid, gid = MOD.os.getuid(), MOD.os.getgid()
            MOD.os.chown(root, uid, gid)
            spec = {
                "schema_version": 1,
                "source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "a" * 40,
                "source_uid": uid,
                "source_gid": gid,
                "entry_sha256": hashlib.sha256(data).hexdigest(),
                "destination": str(dest),
                "valid_until_epoch": 9999999999,
            }
            with mock.patch.object(INSTALL, "ROOT_UID", uid), \
                    mock.patch.object(INSTALL, "ROOT_GID", gid), \
                    mock.patch.object(INSTALL, "RUN_DIR", str(root)), \
                    mock.patch.object(INSTALL.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=gid)), \
                    mock.patch.object(INSTALL, "ENTRY_PATH", re.compile(
                        r"^" + re.escape(str(root)) + r"/lab-g3-archive-a-loader-[0-9a-f]{12}\.py$")):
                checked, same_bytes = INSTALL.install_from_bytes(
                    json.dumps(spec, sort_keys=True, separators=(",", ":")).encode(),
                    read_source=lambda *_args: data, now=1)
                readback = INSTALL._read_fixed_root_file

                def altered_readback(path, mode, limit):
                    blob, st = readback(path, mode, limit)
                    if path == str(dest):
                        return b"different bytes", st
                    return blob, st

                with mock.patch.object(INSTALL, "_read_fixed_root_file", side_effect=altered_readback):
                    with self.assertRaises(INSTALL.Refusal) as caught:
                        INSTALL._install(checked, same_bytes)
            self.assertEqual(caught.exception.category, "INSTALL_READBACK")
            self.assertTrue(dest.exists())
            self.assertFalse(root.joinpath("lab-g3-archive-a-loader-123456abcdef.install.json").exists())

    def test_close_reloads_active_under_run_lock_before_mutating(self):
        observed = {"run_dir": "/run/lab-g3-archive-a-20261124T000000Z-abcdef123456"}
        changed = {"run_dir": "/run/lab-g3-archive-a-20261124T000001Z-123456abcdef"}
        with mock.patch.object(MOD, "_check_root"), \
                mock.patch.object(MOD, "_active_read", return_value=observed), \
                mock.patch.object(MOD, "_locked", return_value=91) as locked, \
                mock.patch.object(MOD, "_active_meta_digests", return_value=(changed, b"", "a" * 64, "b" * 64)), \
                mock.patch.object(MOD, "_close_locked") as close_locked, \
                mock.patch.object(MOD.os, "close") as close_fd:
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._close()
        self.assertEqual(caught.exception.category, "ACTIVE_CHANGED")
        locked.assert_called_once_with(observed["run_dir"])
        close_locked.assert_not_called()
        close_fd.assert_called_once_with(91)

    def test_expiry_reloads_active_under_run_lock_before_revoking(self):
        observed = {"run_dir": "/run/lab-g3-archive-a-20261124T000000Z-abcdef123456"}
        changed = {"run_dir": "/run/lab-g3-archive-a-20261124T000001Z-123456abcdef"}
        with mock.patch.object(MOD, "_check_root"), \
                mock.patch.object(MOD, "_active_read", return_value=observed), \
                mock.patch.object(MOD, "_locked", return_value=92) as locked, \
                mock.patch.object(MOD, "_active_meta_digests", return_value=(changed, b"", "a" * 64, "b" * 64)), \
                mock.patch.object(MOD, "_sudoers_remove") as remove_rule, \
                mock.patch.object(MOD.os, "close") as close_fd:
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._expire_window()
        self.assertEqual(caught.exception.category, "ACTIVE_CHANGED")
        locked.assert_called_once_with(observed["run_dir"])
        remove_rule.assert_not_called()
        close_fd.assert_called_once_with(92)

    def test_root_entry_rejects_extra_arguments(self):
        with mock.patch.object(ROOT, "run") as run:
            self.assertEqual(ROOT.main(["abort", "extra"]), 2)
            run.assert_not_called()

    def test_root_loader_hashes_and_returns_exact_fd_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve() / "checkout"
            (root / "ops" / "lab-g3-archive-a").mkdir(parents=True)
            source = root / "ops" / "lab-g3-archive-a" / "stage-window.py"
            original = b"VALUE='verified bytes'\n"
            source.write_bytes(original)
            source.chmod(0o600)
            root.chmod(0o700)
            uid = MOD.os.getuid()
            gid = MOD.pwd.getpwuid(uid).pw_gid
            MOD.os.chown(root, uid, gid)
            with mock.patch.object(ROOT, "SOURCE_PATH", re.compile(r"^" + re.escape(str(root)) + r"$")):
                path, loaded = ROOT._read_controller(str(root), uid, hashlib.sha256(original).hexdigest())
                self.assertEqual(path, str(source))
                self.assertEqual(loaded, original)
                source.write_bytes(b"VALUE='changed after verified read'\n")
                namespace = {"__name__": "synthetic", "__file__": path}
                exec(compile(loaded, path, "exec", dont_inherit=True), namespace, namespace)
                self.assertEqual(namespace["VALUE"], "verified bytes")
                self.assertEqual(ROOT.pwd.getpwuid(uid).pw_gid, gid)

    def test_root_loader_rejects_controller_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve() / "checkout"
            source_dir = root / "ops" / "lab-g3-archive-a"
            source_dir.mkdir(parents=True)
            target = pathlib.Path(temp) / "outside.py"
            target.write_text("pass\n", encoding="utf-8")
            (source_dir / "stage-window.py").symlink_to(target)
            root.chmod(0o700)
            uid = MOD.os.getuid()
            MOD.os.chown(root, uid, MOD.pwd.getpwuid(uid).pw_gid)
            with mock.patch.object(ROOT, "SOURCE_PATH", re.compile(r"^" + re.escape(str(root)) + r"$")):
                with self.assertRaises(ROOT.Refusal) as caught:
                    ROOT._read_controller(str(root), uid, hashlib.sha256(b"pass\n").hexdigest())
            self.assertEqual(caught.exception.category, "SOURCE_FILE")

    @staticmethod
    def network_rows():
        return {
            ("link", "show"): [{"ifname": "lo", "flags": ["LOOPBACK", "UP"]}],
            ("-4", "address", "show"): [{"ifname": "lo", "addr_info": [
                {"family": "inet", "local": "127.0.0.1"}]}],
            ("-6", "address", "show"): [{"ifname": "lo", "addr_info": [
                {"family": "inet6", "local": "::1"}]}],
            ("-4", "route", "show", "table", "all"): [],
            ("-6", "route", "show", "table", "all"): [],
        }

    def test_network_gate_uses_current_namespace_json_and_allows_empty_route_data(self):
        rows = self.network_rows()
        calls = []

        def read(args):
            calls.append(tuple(args))
            return rows[tuple(args)]

        with mock.patch.object(MOD, "_ip_json", side_effect=read):
            MOD._check_network_isolation()
        self.assertEqual(calls, list(rows))
        self.assertEqual(MOD._network_routes([], 4), "no_route_rows")
        self.assertEqual(MOD._network_routes([], 6), "no_route_rows")

    def test_network_gate_accepts_no_address_for_either_family_when_link_is_lo(self):
        rows = self.network_rows()
        rows[("-4", "address", "show")] = []
        rows[("-6", "address", "show")] = []
        with mock.patch.object(MOD, "_ip_json", side_effect=lambda args: rows[tuple(args)]):
            MOD._check_network_isolation()

    def test_network_gate_distinguishes_explicit_ipv6_unreachable_sentinel(self):
        self.assertEqual(MOD._network_routes(
            [{"type": "unreachable", "dst": "default"}], 6), "explicit_nonforwarding")
        self.assertEqual(MOD._network_routes([], 6), "no_route_rows")
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._network_routes(
                [{"type": "unreachable", "dst": "default", "gateway": "2001:db8::1"}], 6)
        self.assertEqual(caught.exception.category, "NETWORK_NAMESPACE_NOT_ISOLATED")
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._network_routes([{"type": "unreachable", "gateway": None}], 6)
        self.assertEqual(caught.exception.category, "NETWORK_STATE_UNAVAILABLE")

    def test_network_gate_rejects_nonloopback_link_address_and_dual_stack_route(self):
        cases = []
        rows = self.network_rows()
        rows[("link", "show")] = [
            {"ifname": "lo", "flags": ["LOOPBACK"]},
            {"ifname": "eth0", "flags": ["BROADCAST", "UP"]},
        ]
        cases.append((rows, "NETWORK_NAMESPACE_NOT_ISOLATED"))
        rows = self.network_rows()
        rows[("-4", "address", "show")] = [{"ifname": "lo", "addr_info": [
            {"family": "inet", "local": "192.0.2.5"}]}]
        cases.append((rows, "NETWORK_NAMESPACE_NOT_ISOLATED"))
        rows = self.network_rows()
        rows[("-4", "route", "show", "table", "all")] = [
            {"dst": "default", "gateway": "192.0.2.1", "dev": "lo"}]
        cases.append((rows, "NETWORK_ROUTE_PRESENT"))
        rows = self.network_rows()
        rows[("-6", "route", "show", "table", "all")] = [
            {"dst": "2001:db8::/32", "gateway": "2001:db8::1", "dev": "lo"}]
        cases.append((rows, "NETWORK_ROUTE_PRESENT"))

        for index, (sample, expected_category) in enumerate(cases):
            def read(args, sample=sample):
                return sample[tuple(args)]
            with self.subTest(case=index), mock.patch.object(MOD, "_ip_json", side_effect=read):
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._check_network_isolation()
                self.assertEqual(caught.exception.category, expected_category)

    def test_network_gate_rejects_missing_or_malformed_family_data(self):
        rows = self.network_rows()
        rows[("-6", "address", "show")] = [{"ifname": "lo"}]
        with mock.patch.object(MOD, "_ip_json", side_effect=lambda args: rows[tuple(args)]):
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._check_network_isolation()
        self.assertEqual(caught.exception.category, "NETWORK_STATE_UNAVAILABLE")

    def test_ip_json_distinguishes_empty_result_from_missing_or_failed_data(self):
        empty = SimpleNamespace(returncode=0, stdout=b"[]\n")
        with mock.patch.object(MOD.subprocess, "run", return_value=empty):
            self.assertEqual(MOD._ip_json(["-6", "route", "show"]), [])
        for result in (
            SimpleNamespace(returncode=0, stdout=b""),
            SimpleNamespace(returncode=2, stdout=b"[]\n"),
            SimpleNamespace(returncode=0, stdout=b"{\"routes\": []}\n"),
            SimpleNamespace(returncode=0, stdout=b"not-json\n"),
        ):
            with self.subTest(result=result), mock.patch.object(MOD.subprocess, "run", return_value=result):
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._ip_json(["-6", "route", "show"])
                self.assertEqual(caught.exception.category, "NETWORK_STATE_UNAVAILABLE")
        for failure in (FileNotFoundError(), MOD.subprocess.TimeoutExpired([MOD.IPROUTE2], 4)):
            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(MOD.subprocess, "run", side_effect=failure):
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._ip_json(["-6", "route", "show"])
                self.assertEqual(caught.exception.category, "NETWORK_STATE_UNAVAILABLE")

    def test_watchdog_exec_and_close_identity_are_exact(self):
        run_dir = "/run/lab-g3-archive-a-20261124T040000Z-abcdef123456"
        source_checkout = "/var/tmp/lab-archive-a-src.Synth001"
        script = (run_dir + "/stage-window.py").encode()
        self.assertEqual(MOD._watchdog_exec_argv(run_dir),
                         ["/usr/bin/python3", "-IB", run_dir + "/stage-window.py", "watchdog"])
        self.assertTrue(MOD._watchdog_identity_matches(
            [b"/usr/bin/python3", b"-IB", script, b"watchdog"], source_checkout,
            run_dir, source_checkout))
        self.assertFalse(MOD._watchdog_identity_matches(
            [b"/usr/bin/python3", b"-IB", script, b"prepare"], source_checkout,
            run_dir, source_checkout))
        self.assertFalse(MOD._watchdog_identity_matches(
            [b"/usr/bin/python3", b"-IB", script, b"watchdog"], "/wrong/cwd",
            run_dir, source_checkout))

    def test_readback_is_dispatched_without_running_host_checks(self):
        with mock.patch.dict(MOD.os.environ, {"KEEP_FOR_TEST": "yes"}, clear=True):
            with mock.patch.object(MOD, "_readback", return_value=23) as readback:
                self.assertEqual(MOD.main(["readback"]), 23)
            readback.assert_called_once_with()

    def test_abort_markers_block_unentered_seats(self):
        with tempfile.TemporaryDirectory() as temp:
            run_base = pathlib.Path(temp).resolve()
            run_name = "lab-g3-archive-a-20261124T000000Z-abcdef123456"
            run_dir = str(run_base / run_name)
            pathlib.Path(run_dir).mkdir(mode=0o700)
            with mock.patch.object(MOD, "RUN_BASE", str(run_base)):
                paths = MOD._abort_record_paths(run_dir)
                self.assertFalse(MOD._is_aborting(run_dir))
                pathlib.Path(paths["intent"]).write_text("synthetic\n", encoding="ascii")
                self.assertTrue(MOD._is_aborting(run_dir))
                pathlib.Path(paths["intent"]).unlink()
                pathlib.Path(paths["receipt"]).write_text("synthetic\n", encoding="ascii")
                self.assertTrue(MOD._is_aborting(run_dir))
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._reject_aborting(run_dir)
                self.assertEqual(caught.exception.category, "WINDOW_ABORTING")

    def test_entry_checks_aborting_under_shared_lock_before_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = pathlib.Path(temp).resolve() / "lab-g3-archive-a-20261124T000000Z-abcdef123456"
            run_dir.mkdir(mode=0o700)
            script = run_dir / "stage-window.py"
            script.write_text("# synthetic\n", encoding="ascii")
            events = []
            active = {"run_dir": str(run_dir), "run_name": run_dir.name}
            meta = {"deadline": 9000}

            def locked(_path):
                events.append("lock")
                return MOD.os.open(MOD.os.devnull, MOD.os.O_RDONLY)

            def aborting(_path):
                events.append("aborting-check")
                raise MOD.Refusal("WINDOW_ABORTING")

            with mock.patch.object(MOD, "__file__", str(script)), \
                    mock.patch.object(MOD, "RUN_BASE", str(run_dir.parent)), \
                    mock.patch.object(MOD, "_check_root"), \
                    mock.patch.object(MOD, "_locked", side_effect=locked), \
                    mock.patch.object(MOD, "_active_read", return_value=active), \
                    mock.patch.object(MOD, "_load_meta", return_value=meta), \
                    mock.patch.object(MOD, "_check_active_meta"), \
                    mock.patch.object(MOD, "_reject_aborting", side_effect=aborting), \
                    mock.patch.object(MOD, "_write_new") as write_new, \
                    mock.patch.object(MOD.subprocess, "Popen") as popen:
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._entry("field")
            self.assertEqual(caught.exception.category, "WINDOW_ABORTING")
            self.assertEqual(events, ["lock", "aborting-check"])
            write_new.assert_not_called()
            popen.assert_not_called()

    def test_inner_refuses_aborting_before_enter_marker_or_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = pathlib.Path(temp).resolve() / "lab-g3-archive-a-20261124T000000Z-abcdef123456"
            run_dir.mkdir(mode=0o700)
            script = run_dir / "stage-window.py"
            script.write_text("# synthetic\n", encoding="ascii")
            active = {"run_dir": str(run_dir), "run_name": run_dir.name}
            meta = {"deadline": 9999999999}
            fd = MOD.os.open(MOD.os.devnull, MOD.os.O_RDONLY)
            with mock.patch.object(MOD, "__file__", str(script)), \
                    mock.patch.object(MOD, "RUN_BASE", str(run_dir.parent)), \
                    mock.patch.object(MOD, "_check_root"), \
                    mock.patch.object(MOD, "_locked", return_value=fd), \
                    mock.patch.object(MOD, "_active_read", return_value=active), \
                    mock.patch.object(MOD, "_load_meta", return_value=meta), \
                    mock.patch.object(MOD, "_check_active_meta"), \
                    mock.patch.object(MOD, "_reject_aborting", side_effect=MOD.Refusal("WINDOW_ABORTING")), \
                    mock.patch.object(MOD, "_write_new") as write_new, \
                    mock.patch.object(MOD, "_check_network_isolation") as network:
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._inner("review")
            self.assertEqual(caught.exception.category, "WINDOW_ABORTING")
            write_new.assert_not_called()
            network.assert_not_called()

    def test_entry_launch_record_binds_unshare_pid_while_lock_is_held(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = pathlib.Path(temp).resolve() / "lab-g3-archive-a-20261124T000000Z-abcdef123456"
            run_dir.mkdir(mode=0o700)
            script = run_dir / "stage-window.py"
            script.write_text("# synthetic\n", encoding="ascii")
            active = {"run_dir": str(run_dir), "run_name": run_dir.name}
            meta = {"deadline": int(MOD.time.time()) + 60}
            events = []
            lock_fds = iter([101, 102])
            writes = []

            class Child:
                pid = 5678
                returncode = 0

                @staticmethod
                def communicate(timeout=None):
                    return valid_entry_output().encode("utf-8"), b""

            def locked(_path):
                events.append("lock")
                return next(lock_fds)

            def write_new(path, content, mode=0o600):
                events.append("write")
                writes.append((path, content))

            def popen(*args, **kwargs):
                events.append("popen")
                self.assertEqual(events, ["lock", "write", "popen"])
                return Child()

            real_close = MOD.os.close
            def close_fd(fd):
                events.append("unlock")
                if fd not in (101, 102):
                    real_close(fd)

            with mock.patch.object(MOD, "__file__", str(script)), \
                    mock.patch.object(MOD, "RUN_BASE", str(run_dir.parent)), \
                    mock.patch.object(MOD, "_check_root"), \
                    mock.patch.object(MOD, "_locked", side_effect=locked), \
                    mock.patch.object(MOD, "_active_read", return_value=active), \
                    mock.patch.object(MOD, "_load_meta", return_value=meta), \
                    mock.patch.object(MOD, "_check_active_meta"), \
                    mock.patch.object(MOD, "_reject_aborting"), \
                    mock.patch.object(MOD, "_process_starttime", return_value=4321), \
                    mock.patch.object(MOD, "_validate_entry_output"), \
                    mock.patch.object(MOD, "_write_new", side_effect=write_new), \
                    mock.patch.object(MOD.subprocess, "Popen", side_effect=popen), \
                    mock.patch.object(MOD.os, "close", side_effect=close_fd):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(MOD._entry("field"), 0)
            entry_path = str(run_dir / "entry.field.json")
            launch_raw = next(content for path, content in writes if path == entry_path)
            launch = json.loads(launch_raw)
            self.assertEqual(launch["entry_pid"], 5678)
            self.assertEqual(launch["entry_starttime"], 4321)
            self.assertEqual(events.count("unlock"), 2)
            self.assertLess(events.index("popen"), events.index("unlock"))

    def test_abort_requires_exact_live_sudoers_rule_before_intent(self):
        with tempfile.TemporaryDirectory() as temp:
            run_base = pathlib.Path(temp).resolve()
            run_name = "lab-g3-archive-a-20261124T000000Z-abcdef123456"
            run_dir = run_base / run_name
            run_dir.mkdir(mode=0o700)
            lock_path = run_dir / "control.lock"
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
            active_path = run_base / "active.json"
            active = {"run_dir": str(run_dir), "run_name": run_name,
                      "terminal_dir": "/run/lab-g3-archive-a-terminal/" + run_name + ".journal",
                      "sudoers_path": str(run_base / "sudoers" / run_name),
                      "sudoers_sha256": "c" * 64}
            lockfd = MOD.os.open(str(lock_path), MOD.os.O_RDWR)
            with mock.patch.object(MOD, "RUN_BASE", str(run_base)), \
                    mock.patch.object(MOD, "ACTIVE", str(active_path)), \
                    mock.patch.object(MOD, "SUDOERS_DIR", str(run_base / "sudoers")), \
                    mock.patch.object(MOD, "_check_root"), \
                    mock.patch.object(MOD, "_active_read", return_value=active), \
                    mock.patch.object(MOD, "_locked", return_value=lockfd), \
                    mock.patch.object(MOD, "_active_meta_digests", return_value=(active, b"{}", "a" * 64, "b" * 64)), \
                    mock.patch.object(MOD, "_load_meta", return_value={"deadline": 9000}), \
                    mock.patch.object(MOD, "_check_active_meta"), \
                    mock.patch.object(MOD, "_terminal_read", return_value=({"phase": "RUNNING"}, b"{}")), \
                    mock.patch.object(MOD, "_sudoers_entry_present", return_value=False), \
                    mock.patch.object(MOD, "_write_new") as write_new, \
                    mock.patch.object(MOD, "_sudoers_remove") as remove:
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._abort()
                self.assertEqual(caught.exception.category, "ABORT_RULE_ABSENT")
                write_new.assert_not_called()
                remove.assert_not_called()
                self.assertTrue(lockfd >= 0)

    def test_abort_revoked_receipt_binds_the_same_intent_but_changes_state(self):
        active = {"run_name": "lab-g3-archive-a-20261124T000000Z-abcdef123456",
                  "run_dir": "/run/lab-g3-archive-a-20261124T000000Z-abcdef123456",
                  "sudoers_path": "/etc/sudoers.d/lab-g3-archive-a-20261124T000000Z-abcdef123456",
                  "sudoers_sha256": "a" * 64}
        meta = {"source_checkout": "/var/tmp/lab-archive-a-src.Synth001",
                "source_commit": "b" * 40, "operator_uid": 1001, "deadline": 9000,
                "stage_script_sha256": "c" * 64, "root_entry_path": "/run/lab-g3-archive-a-loader-123456abcdef.py",
                "root_entry_sha256": "d" * 64}
        intent = MOD._abort_bindings(active, meta, "e" * 64, "f" * 64)
        intent.update({"state": "ABORTING", "requested_utc": "2026-11-24T00:00:00Z"})
        revoked = dict(intent)
        revoked.update({"state": "REVOKED", "rule_absent": True, "visudo": "PASS",
                        "verified_utc": "2026-11-24T00:00:01Z"})
        raw = (json.dumps(revoked, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with mock.patch.object(MOD, "_read_regular", return_value=(raw, None)):
            accepted, accepted_raw = MOD._read_abort_revoked(active["run_dir"], intent)
        self.assertEqual(accepted["state"], "REVOKED")
        self.assertEqual(accepted_raw, raw)
        revoked["root_entry_sha256"] = "0" * 64
        bad = (json.dumps(revoked, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with mock.patch.object(MOD, "_read_regular", return_value=(bad, None)):
            with self.assertRaises(MOD.Refusal) as caught:
                MOD._read_abort_revoked(active["run_dir"], intent)
        self.assertEqual(caught.exception.category, "ABORT_BINDING_MISMATCH")

    def test_watchdog_stop_uses_bound_pidfd_and_refuses_reused_pid(self):
        with tempfile.TemporaryDirectory() as run_dir:
            watchdog_path = pathlib.Path(run_dir) / "watchdog.pid"
            watchdog_path.write_text("synthetic\n", encoding="ascii")
            watchdog_path.chmod(0o600)
            record = {"pid": 987654, "starttime": 321,
                      "cwd": "/var/tmp/lab-archive-a-src.Synth001",
                      "argv_sha256": hashlib.sha256("\0".join(
                          MOD._watchdog_exec_argv(run_dir)).encode()).hexdigest()}
            poller = mock.MagicMock()
            poller.poll.side_effect = [[], [(7, 1)]]
            real_close = MOD.os.close
            with mock.patch.object(MOD, "_require_pidfd_support"), \
                    mock.patch.object(MOD, "_watchdog_record", return_value=record), \
                    mock.patch.object(MOD, "_process_starttime", return_value=321), \
                    mock.patch.object(MOD, "_proc_command_and_cwd", return_value=(
                        [b"/usr/bin/python3", b"-IB", (run_dir + "/stage-window.py").encode(), b"watchdog"],
                        record["cwd"])), \
                    mock.patch.object(MOD, "_watchdog_identity_matches", return_value=True), \
                    mock.patch.object(MOD.os, "pidfd_open", return_value=77, create=True), \
                    mock.patch.object(MOD.signal, "pidfd_send_signal", create=True) as send, \
                    mock.patch.object(MOD.select, "poll", return_value=poller), \
                    mock.patch.object(MOD.os, "kill") as numeric_kill, \
                    mock.patch.object(MOD.os, "close", side_effect=lambda fd: None if fd == 77 else real_close(fd)):
                self.assertEqual(MOD._stop_watchdog(run_dir), "STOPPED")
                send.assert_called_once_with(77, MOD.signal.SIGTERM)
                numeric_kill.assert_not_called()

            with mock.patch.object(MOD, "_require_pidfd_support"), \
                    mock.patch.object(MOD, "_watchdog_record", return_value=record), \
                    mock.patch.object(MOD, "_process_starttime", return_value=999), \
                    mock.patch.object(MOD, "_proc_command_and_cwd", return_value=([], "wrong")), \
                    mock.patch.object(MOD, "_watchdog_identity_matches", return_value=False), \
                    mock.patch.object(MOD.os, "pidfd_open", return_value=77, create=True), \
                    mock.patch.object(MOD.signal, "pidfd_send_signal", create=True) as send, \
                    mock.patch.object(MOD.os, "close", side_effect=lambda fd: None if fd == 77 else real_close(fd)):
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._stop_watchdog(run_dir)
                self.assertEqual(caught.exception.category, "WATCHDOG_IDENTITY_MISMATCH")
                send.assert_not_called()

    def test_watchdog_pidfd_uncertainty_preserves_state_without_numeric_kill(self):
        original = MOD.WATCHDOG_START_UNCERTAIN
        MOD.WATCHDOG_START_UNCERTAIN = False
        with mock.patch.object(MOD, "_require_pidfd_support"), \
                mock.patch.object(MOD.os, "pidfd_open", side_effect=[77, PermissionError("synthetic")], create=True), \
                mock.patch.object(MOD.os, "fork", return_value=56789), \
                mock.patch.object(MOD.os, "close"), \
                mock.patch.object(MOD.os, "kill", create=True) as numeric_kill:
            try:
                with self.assertRaises(MOD.Refusal) as caught:
                    MOD._start_watchdog("/run/lab-g3-archive-a-20261124T000000Z-abcdef123456", 9999999999)
                self.assertEqual(caught.exception.category, "PIDFD_UNAVAILABLE")
                self.assertTrue(MOD.WATCHDOG_START_UNCERTAIN)
                numeric_kill.assert_not_called()
            finally:
                MOD.WATCHDOG_START_UNCERTAIN = original


    def test_entry_only_relays_fixed_inner_failure_categories(self):
        self.assertEqual(MOD._fixed_failure_category(b"STATUS=FAIL CATEGORY=ANCHOR_CHANGED\n"),
                         "ANCHOR_CHANGED")
        self.assertEqual(MOD._fixed_failure_category(b"STATUS=FAIL CATEGORY=INTERNAL\n"), "INTERNAL")
        for output in (b"secret site value\n", b"STATUS=FAIL CATEGORY=ANCHOR_CHANGED\nSECRET\n",
                       b"STATUS=FAIL CATEGORY=lowercase\n", b"STATUS=FAIL CATEGORY=BAD\nDETAIL=private\n",
                       b"STATUS=FAIL CATEGORY=" + b"A" * 65 + b"\n", b"x" * 129):
            with self.subTest(output=output[:32]):
                self.assertIsNone(MOD._fixed_failure_category(output))

    def test_git_identity_is_owner_only_for_root_and_owner_callers(self):
        self.assertEqual(MOD._git_identity(1001, 1001, [1001, 1002, 1001], 0),
                         {"user": 1001, "group": 1001, "extra_groups": [1001, 1002]})
        self.assertEqual(MOD._git_identity(1001, 1001, [1001, 1002], 1001), {})
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._git_identity(1001, 1001, [1001, 1002], 1002)
        self.assertEqual(caught.exception.category, "SOURCE_GIT_IDENTITY")

    def test_git_identity_rejects_invalid_identity_and_query(self):
        for uid, gid, groups, euid in (
            (0, 0, [0], 0),
            (1001, -1, [1001], 0),
            (1001, 1001, ["1001"], 0),
        ):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(MOD.Refusal):
                MOD._git_identity(uid, gid, groups, euid)
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._git_read("/var/tmp/lab-archive-a-src.Synth001", ["config", "--list"], 1001)
        self.assertEqual(caught.exception.category, "SOURCE_GIT_QUERY")

    def test_root_git_read_drops_to_verified_checkout_owner(self):
        uid = MOD.os.getuid()
        owner = MOD.pwd.getpwuid(uid)
        fake = SimpleNamespace(returncode=0, stdout=b"synthetic\n")
        with mock.patch.object(MOD.os, "geteuid", return_value=0), \
             mock.patch.object(MOD.subprocess, "run", return_value=fake) as run_git:
            self.assertEqual(MOD._git_read("/var/tmp/lab-archive-a-src.Synth001",
                                           ["rev-parse", "HEAD"], uid), "synthetic")
        kwargs = run_git.call_args.kwargs
        self.assertEqual(kwargs["user"], uid)
        self.assertEqual(kwargs["group"], owner.pw_gid)
        self.assertEqual(kwargs["extra_groups"], sorted(set(MOD.os.getgrouplist(owner.pw_name, owner.pw_gid))))
        self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertNotIn("safe.directory", kwargs["env"])

    def test_owner_git_read_keeps_owner_identity(self):
        uid = MOD.os.getuid()
        fake = SimpleNamespace(returncode=0, stdout=b"\n")
        with mock.patch.object(MOD.os, "geteuid", return_value=uid), \
             mock.patch.object(MOD.subprocess, "run", return_value=fake) as run_git:
            self.assertEqual(MOD._git_read("/var/tmp/lab-archive-a-src.Synth001",
                                           ["status", "--porcelain=v1", "--untracked-files=all"], uid), "")
        self.assertNotIn("user", run_git.call_args.kwargs)
        self.assertNotIn("group", run_git.call_args.kwargs)

    def test_two_seat_completion_state_machine(self):
        stamp = b"ROLE=field\nDONE_UTC=2026-11-23T00:00:00Z\nOUTPUT_SHA256=" + b"a" * 64 + b"\n"
        self.assertTrue(MOD._seat_marker_state(b"started\n", stamp, "field"))
        self.assertEqual(MOD._close_seat_status(True, True, False), "COMPLETE")
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._close_seat_status(True, False, False)
        self.assertEqual(caught.exception.category, "SEATS_INCOMPLETE")
        self.assertEqual(MOD._close_seat_status(True, False, True), "INCOMPLETE")
        self.assertFalse(MOD._seat_marker_state(b"started\n", None, "field"))
        with self.assertRaises(MOD.Refusal):
            MOD._seat_marker_state(b"started\n", stamp, "field", deadline=1763856000)

    def test_expired_close_records_bad_seat_as_incomplete(self):
        def malformed():
            raise MOD.Refusal("SEAT_MARKER_INVALID")
        self.assertFalse(MOD._close_seat_state(malformed, expired=True))
        with self.assertRaises(MOD.Refusal) as caught:
            MOD._close_seat_state(malformed, expired=False)
        self.assertEqual(caught.exception.category, "SEAT_MARKER_INVALID")
        self.assertEqual(MOD._close_seat_status(False, False, True), "INCOMPLETE")

    def test_seat_markers_reject_forged_or_malformed_completion(self):
        good = b"ROLE=review\nDONE_UTC=2026-11-23T00:00:00Z\nOUTPUT_SHA256=" + b"b" * 64 + b"\n"
        for started, done, role in (
            (None, good, "review"),
            (b"started\n", good.replace(b"ROLE=review", b"ROLE=field"), "review"),
            (b"started\n", good.replace(b"2026-11-23", b"2026-13-23"), "review"),
            (b"started\n", good.replace(b"b" * 64, b"not-a-digest"), "review"),
            (b"started\n", good + b"EXTRA=bad\n", "review"),
        ):
            with self.subTest(role=role, done=done[-20:]), self.assertRaises(MOD.Refusal):
                MOD._seat_marker_state(started, done, role)

    def test_entry_completion_requires_all_three_parsed_sections(self):
        meta = {"config_sha256": "1" * 64,
                "input_sha256": {"site.env": "4" * 64, "env/env0": "5" * 64,
                                 "env/d6.env": "6" * 64, "deny.json": "7" * 64}}
        output = valid_entry_output()
        MOD._validate_entry_output(output, meta)
        for invalid in (output.replace("STATUS=PASS\nBEGIN_PRE_ANCHOR", "STATUS=PASS\nSTATUS=FAIL\nBEGIN_PRE_ANCHOR"),
                        output.replace("END_PRE_ANCHOR\nBEGIN_ARCHIVE_ONLY", "END_PRE_ANCHOR\nEXTRA=bad\nBEGIN_ARCHIVE_ONLY"),
                        output.replace("END_POST_ANCHOR\n", "END_POST_ANCHOR\nEXTRA=bad\n")):
            with self.subTest(invalid_hash=hashlib.sha256(invalid.encode()).hexdigest()), self.assertRaises(MOD.Refusal):
                MOD._validate_entry_output(invalid, meta)

    def test_valid_private_bootstrap_is_bounded_to_window(self):
        self.assertEqual(MOD.validate_bootstrap(synthetic_bootstrap(), now=8100), 900)

    def test_reject_expired_or_overlong_window(self):
        for deadline in (8000, 10000):
            obj = synthetic_bootstrap()
            obj["valid_until_epoch"] = deadline
            with self.subTest(deadline=deadline), self.assertRaises(MOD.Refusal):
                MOD.validate_bootstrap(obj, now=8100)

    def test_reject_extra_or_missing_bootstrap_fields(self):
        obj = synthetic_bootstrap()
        obj["unexpected"] = "synthetic"
        with self.assertRaises(MOD.Refusal):
            MOD._json_exact(json.dumps(obj).encode(), MOD.BOOTSTRAP_KEYS, "BOOTSTRAP_SCHEMA")
        obj = synthetic_bootstrap()
        obj["input_sha256"] = "9" * 64
        with self.assertRaises(MOD.Refusal):
            MOD.validate_bootstrap(obj, now=8100)
        obj = synthetic_bootstrap()
        del obj["archive_wal_sha256"]
        with self.assertRaises(MOD.Refusal):
            MOD._json_exact(json.dumps(obj).encode(), MOD.BOOTSTRAP_KEYS, "BOOTSTRAP_SCHEMA")

    def test_reject_path_traversal_and_bad_generation(self):
        obj = synthetic_bootstrap()
        obj["source_checkout"] = "/var/tmp/lab-archive-a-src.Synthetic1/../other"
        with self.assertRaises(MOD.Refusal):
            MOD.validate_bootstrap(obj, now=8100)
        obj = synthetic_bootstrap()
        obj["v2_generation"] = obj["v2_previous_generation"]
        with self.assertRaises(MOD.Refusal):
            MOD.validate_bootstrap(obj, now=8100)

    def test_exact_sudoers_and_no_argument_wrappers(self):
        text = MOD._sudoers_text("synthetic_operator", "/run/lab-g3-archive-a-20261123T000000Z-abcdef123456")
        self.assertEqual(text, 'synthetic_operator ALL=(root) NOPASSWD: /run/lab-g3-archive-a-20261123T000000Z-abcdef123456/field "", /run/lab-g3-archive-a-20261123T000000Z-abcdef123456/review ""\n')
        for role in ("field", "review"):
            wrapper = MOD._entry_wrapper("/run/lab-g3-archive-a-20261123T000000Z-abcdef123456", role)
            self.assertIn('[ "$#" -eq 0 ] || exit 2', wrapper)
            self.assertNotIn("unshare", wrapper)
            self.assertIn(" entry " + role, wrapper)

    def test_anchor_semantics_accept_v2_and_exact_four_inputs(self):
        selected, lines = MOD._extract_anchor(anchor_lines().encode())
        self.assertEqual(len(selected), 7)
        self.assertEqual(sum(line.startswith("INPUT ") for line in lines), 4)

    def test_anchor_rejects_wrong_version_or_wal_present(self):
        bad_version = anchor_lines().replace("version=2", "version=3").encode()
        bad_wal = anchor_lines(wal="PRESENT").encode()
        for raw in (bad_version, bad_wal):
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()), self.assertRaises(MOD.Refusal):
                MOD._extract_anchor(raw)

    def test_anchor_rejects_equal_generation_and_bad_input_set(self):
        same = anchor_lines(previous="gen-20261123T000001Z-123456abcdef").encode()
        missing = anchor_lines().replace("INPUT type=file path=deny.json", "INPUT type=file path=other.json").encode()
        for raw in (same, missing):
            with self.assertRaises(MOD.Refusal):
                MOD._extract_anchor(raw)

    def test_anchor_input_hashes_bind_each_fixed_input(self):
        selected, _ = MOD._extract_anchor(anchor_lines().encode())
        expected = {"site.env": "4" * 64, "env/env0": "5" * 64,
                    "env/d6.env": "6" * 64, "deny.json": "7" * 64}
        MOD._check_anchor_input_hashes(selected, expected)
        expected["deny.json"] = "0" * 64
        with self.assertRaises(MOD.Refusal):
            MOD._check_anchor_input_hashes(selected, expected)

    def test_anchor_rejects_unknown_output_lines(self):
        raw = (anchor_lines() + "SECRET_BODY=synthetic\n").encode()
        with self.assertRaises(MOD.Refusal):
            MOD._extract_anchor(raw)

    def test_source_constants_are_public_pins_only(self):
        source = MODULE_PATH.read_bytes()
        text = source.decode("utf-8")
        self.assertNotIn("/var/tmp/lab-g3-synth-20261123", text)
        self.assertNotIn("d00a55f892852152", text)
        self.assertNotIn("70.35.205.77", text)
        self.assertNotIn("safe.directory", text)
        self.assertIn(MOD.ENGINE_SHA256, text)
        self.assertIn(MOD.ARCHIVE_SHA256, text)


if __name__ == "__main__":
    unittest.main()
