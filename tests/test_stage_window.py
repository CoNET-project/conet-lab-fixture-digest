"""Pure synthetic tests for the short-lived A-window controller."""
import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve()
MODULE_PATH = HERE.parents[1] / "ops" / "lab-g3-archive-a" / "stage-window.py"
SPEC = importlib.util.spec_from_file_location("lab_g3_archive_a_stage", MODULE_PATH)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


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
