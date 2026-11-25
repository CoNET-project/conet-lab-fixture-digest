#!/usr/bin/python3 -IB
"""Fixed root entry for the short-lived Lab A read-only staging controller."""
import hashlib
import json
import os
import pwd
import re
import stat
import sys
import time

BOOTSTRAP = "/run/lab-g3-archive-a-bootstrap.json"
ACTIVE = "/run/lab-g3-archive-a-active.json"
RUN_BASE = "/run"
CONTROLLER_REL = ("ops", "lab-g3-archive-a", "stage-window.py")
SOURCE_PATH = re.compile(r"^/var/tmp/lab-archive-a-src\.[A-Za-z0-9]{8}$")
LOADER_PATH = re.compile(r"^/run/lab-g3-archive-a-loader-[0-9a-f]{12}\.py$")
RUN_NAME = re.compile(r"^lab-g3-archive-a-\d{8}T\d{6}Z-[a-f0-9]{12}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BOOT_KEYS = {
    "schema_version", "operator", "source_checkout", "source_commit",
    "stage_script_sha256", "input_sha256", "valid_until_epoch", "fixture_root",
    "v2_manifest_sha256", "v2_selected_tree_sha256", "v2_generation",
    "v2_previous_generation", "archive_manifest_sha256", "archive_wal_sha256",
    "root_entry_path", "root_entry_sha256",
}
ACTIVE_KEYS = {
    "run_dir", "run_name", "terminal_dir", "source_checkout", "deadline", "sudoers_path",
    "sudoers_sha256", "source_commit", "stage_script_sha256", "operator_uid",
    "root_entry_path", "root_entry_sha256",
}
TERMINAL_BASE = "/run/lab-g3-archive-a-terminal"
TERMINAL_NAME = re.compile(r"^lab-g3-archive-a-\d{8}T\d{6}Z-[a-f0-9]{12}\.journal$")
TERMINAL_KEYS = {
    "schema_version", "run_name", "run_dir", "terminal_dir", "operation", "state", "phase", "revision",
    "source_checkout", "source_commit", "operator_uid", "deadline", "stage_script_sha256",
    "root_entry_path", "root_entry_sha256", "sudoers_path", "sudoers_sha256", "active_sha256",
    "meta_sha256", "bootstrap_sha256", "host_snapshots", "host_mnt_ns", "host_net_ns",
    "field_completed", "review_completed",
}
CLOSED_KEYS = {
    "schema_version", "run_name", "run_dir", "source_checkout", "source_commit",
    "operator_uid", "host_mnt_ns", "host_net_ns", "stage_script_sha256", "sudoers_path",
    "sudoers_sha256", "deadline", "root_entry_path", "root_entry_sha256", "host_snapshots",
    "sudoers_status", "bootstrap_status", "host_config_absent", "host_snapshot_status",
    "automatic_expiry", "field_completed", "review_completed", "seat_status",
}
ABORTED_KEYS = {
    "schema_version", "state", "run_name", "run_dir", "active_sha256", "meta_sha256",
    "source_checkout", "source_commit", "operator_uid", "deadline", "stage_script_sha256",
    "root_entry_path", "root_entry_sha256", "sudoers_path", "sudoers_sha256",
    "abort_intent_sha256", "abort_revoked_sha256", "host_snapshots", "host_config_absent",
    "field_completed", "review_completed", "seat_status", "aborted_utc",
}
ALLOWED = {"prepare", "close", "readback", "abort"}
MAX_META = 65536
MAX_CODE = 1024 * 1024
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refusal(Exception):
    def __init__(self, category):
        self.category = category


def refuse(category):
    raise Refusal(category)


def _json(blob, keys, category):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                refuse(category)
            obj[key] = value
        return obj
    try:
        value = json.loads(blob.decode("utf-8"), object_pairs_hook=unique)
    except Refusal:
        raise
    except Exception:
        refuse(category)
    if not isinstance(value, dict) or set(value) != keys:
        refuse(category)
    return value


def _open_run_dir():
    fd = os.open(RUN_BASE, O_DIR)
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0:
        os.close(fd)
        refuse("RUN_DIRECTORY")
    return fd


def _read_run_file(name, mode, limit):
    if "/" in name or name in ("", ".", ".."):
        refuse("RUN_PATH")
    dfd = _open_run_dir()
    try:
        before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or
                stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1 or before.st_size > limit):
            refuse("RUN_FILE")
        fd = os.open(name, O_FILE, dir_fd=dfd)
        try:
            opened = os.fstat(fd)
            if _identity(before) != _identity(opened):
                refuse("RUN_DRIFT")
            chunks, size = [], 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                size += len(block)
                if size > limit:
                    refuse("RUN_SIZE")
                chunks.append(block)
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if _identity(opened) != _identity(after) or _identity(after) != _identity(current):
                refuse("RUN_DRIFT")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except FileNotFoundError:
        refuse("RUN_FILE_MISSING")
    except Refusal:
        raise
    except OSError:
        refuse("RUN_FILE_UNAVAILABLE")
    finally:
        os.close(dfd)


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _read_terminal_record(terminal_dir):
    if (not isinstance(terminal_dir, str) or
            terminal_dir != os.path.join(TERMINAL_BASE, os.path.basename(terminal_dir)) or
            not TERMINAL_NAME.fullmatch(os.path.basename(terminal_dir))):
        refuse("TERMINAL_PATH")
    try:
        base_st = os.lstat(TERMINAL_BASE)
        if (not stat.S_ISDIR(base_st.st_mode) or stat.S_ISLNK(base_st.st_mode) or
                base_st.st_uid != 0 or base_st.st_gid != 0 or stat.S_IMODE(base_st.st_mode) != 0o700 or
                os.path.realpath(TERMINAL_BASE) != TERMINAL_BASE):
            refuse("TERMINAL_DIRECTORY")
        dfd = os.open(terminal_dir, O_DIR)
    except OSError:
        refuse("TERMINAL_DIRECTORY")
    try:
        ds = os.fstat(dfd)
        if (not stat.S_ISDIR(ds.st_mode) or ds.st_uid != 0 or ds.st_gid != 0 or
                stat.S_IMODE(ds.st_mode) != 0o700):
            refuse("TERMINAL_DIRECTORY")
        names = set(os.listdir(dfd))
        if names not in ({"control.lock", "controller.py", "journal.json"},
                         {"control.lock", "controller.py", "journal.json", "journal.next"}):
            refuse("TERMINAL_ENTRY_SET")
        lock_st = os.stat("control.lock", dir_fd=dfd, follow_symlinks=False)
        if (not stat.S_ISREG(lock_st.st_mode) or lock_st.st_uid != 0 or lock_st.st_gid != 0 or
                stat.S_IMODE(lock_st.st_mode) != 0o600 or lock_st.st_nlink != 1):
            refuse("TERMINAL_LOCK")
        before = os.stat("journal.json", dir_fd=dfd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 16384):
            refuse("TERMINAL_JOURNAL")
        fd = os.open("journal.json", O_FILE, dir_fd=dfd)
        try:
            opened = os.fstat(fd)
            if _identity(before) != _identity(opened):
                refuse("TERMINAL_DRIFT")
            data = bytearray()
            while True:
                block = os.read(fd, 4096)
                if not block:
                    break
                data.extend(block)
                if len(data) > 16384:
                    refuse("TERMINAL_SIZE")
            after = os.fstat(fd)
            current = os.stat("journal.json", dir_fd=dfd, follow_symlinks=False)
            if _identity(opened) != _identity(after) or _identity(after) != _identity(current):
                refuse("TERMINAL_DRIFT")
        finally:
            os.close(fd)
        record = _json(bytes(data), TERMINAL_KEYS, "TERMINAL_SCHEMA")
        run_name = os.path.basename(terminal_dir)[:-len(".journal")]
        if (record.get("schema_version") != 1 or record.get("run_name") != run_name or
                record.get("run_dir") != os.path.join(RUN_BASE, run_name) or
                record.get("terminal_dir") != terminal_dir or
                record.get("phase") not in ("RUNNING", "INTENT", "RULE_INTENT", "RULE_DONE", "WATCHDOG_INTENT",
                    "WATCHDOG_DONE", "QUIESCENCE_DONE", "BOOTSTRAP_INTENT", "BOOTSTRAP_DONE", "ACTIVE_INTENT",
                    "ACTIVE_DONE", "RUN_INTENT", "RUN_DONE", "CHECKOUT_INTENT", "CHECKOUT_DONE",
                    "POSTCHECK_PASS", "COMPLETE", "READBACK_DONE") or
                record.get("operation") not in ("running", "close", "abort", "expire") or
                record.get("state") not in ("RUNNING", "CLOSING", "ABORTING", "EXPIRING", "COMPLETE") or
                not isinstance(record.get("root_entry_path"), str) or
                record["root_entry_path"] != os.path.realpath(__file__) or
                not HEX64.fullmatch(str(record.get("root_entry_sha256", ""))) or
                not isinstance(record.get("stage_script_sha256"), str) or
                not HEX64.fullmatch(str(record.get("stage_script_sha256")))):
            refuse("TERMINAL_BINDING")
        return record
    finally:
        os.close(dfd)


def _terminal_controller(terminal_dir, expected_sha):
    record = _read_terminal_record(terminal_dir)
    try:
        dfd = os.open(terminal_dir, O_DIR)
        try:
            before = os.stat("controller.py", dir_fd=dfd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or
                    stat.S_IMODE(before.st_mode) != 0o500 or before.st_nlink != 1 or before.st_size > MAX_CODE):
                refuse("TERMINAL_CONTROLLER")
            fd = os.open("controller.py", O_FILE, dir_fd=dfd)
            try:
                opened = os.fstat(fd)
                if _identity(before) != _identity(opened):
                    refuse("TERMINAL_CONTROLLER_DRIFT")
                data = bytearray()
                while True:
                    block = os.read(fd, 65536)
                    if not block:
                        break
                    data.extend(block)
                    if len(data) > MAX_CODE:
                        refuse("TERMINAL_CONTROLLER_SIZE")
                after = os.fstat(fd)
                current = os.stat("controller.py", dir_fd=dfd, follow_symlinks=False)
                if _identity(opened) != _identity(after) or _identity(after) != _identity(current):
                    refuse("TERMINAL_CONTROLLER_DRIFT")
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
    except OSError:
        refuse("TERMINAL_CONTROLLER")
    if hashlib.sha256(data).hexdigest() != expected_sha or expected_sha != record["stage_script_sha256"]:
        refuse("TERMINAL_CONTROLLER_HASH")
    return os.path.join(terminal_dir, "controller.py"), bytes(data), record


def _read_entry_binding(verb):
    if verb == "prepare":
        raw = _read_run_file(os.path.basename(BOOTSTRAP), 0o600, MAX_META)
        obj = _json(raw, BOOT_KEYS, "BOOTSTRAP_SCHEMA")
        if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
            refuse("BOOTSTRAP_SCHEMA")
        if type(obj["valid_until_epoch"]) is not int or obj["valid_until_epoch"] <= int(time.time()):
            refuse("WINDOW_EXPIRED")
        try:
            operator = pwd.getpwnam(obj["operator"])
        except Exception:
            refuse("OPERATOR_UNKNOWN")
        binding = {
            "source_checkout": obj["source_checkout"],
            "source_commit": obj["source_commit"],
            "stage_script_sha256": obj["stage_script_sha256"],
            "operator_uid": operator.pw_uid,
            "root_entry_path": obj["root_entry_path"],
            "root_entry_sha256": obj["root_entry_sha256"],
            "deadline": obj["valid_until_epoch"],
        }
    else:
        try:
            raw = _read_run_file(os.path.basename(ACTIVE), 0o600, 8192)
        except Refusal as exc:
            if verb != "readback" or exc.category != "RUN_FILE_MISSING":
                raise
            try:
                names = os.listdir(TERMINAL_BASE)
            except OSError:
                refuse("TERMINAL_DIRECTORY")
            matches = []
            for name in names:
                if not TERMINAL_NAME.fullmatch(name):
                    refuse("TERMINAL_ENTRY_SET")
                terminal_dir = os.path.join(TERMINAL_BASE, name)
                record = _read_terminal_record(terminal_dir)
                if (record["root_entry_path"] == os.path.realpath(__file__) and
                        record["root_entry_sha256"] == hashlib.sha256(_read_run_file(
                            os.path.basename(os.path.realpath(__file__)), 0o500, MAX_CODE)).hexdigest() and
                        record["phase"] != "RUNNING"):
                    matches.append((terminal_dir, record))
            if len(matches) != 1:
                refuse("TERMINAL_RECORD_COUNT")
            terminal_dir, record = matches[0]
            binding = {key: record[key] for key in (
                "source_checkout", "source_commit", "stage_script_sha256", "operator_uid",
                "root_entry_path", "root_entry_sha256", "deadline")}
            binding["terminal_dir"] = terminal_dir
        else:
            obj = _json(raw, ACTIVE_KEYS, "ACTIVE_SCHEMA")
            if (not isinstance(obj["run_name"], str) or not RUN_NAME.fullmatch(obj["run_name"]) or
                    obj["run_dir"] != os.path.join(RUN_BASE, obj["run_name"]) or
                    obj["terminal_dir"] != os.path.join(TERMINAL_BASE, obj["run_name"] + ".journal") or
                    obj["sudoers_path"] != os.path.join("/etc/sudoers.d", obj["run_name"])):
                refuse("ACTIVE_SCHEMA")
            record = _read_terminal_record(obj["terminal_dir"])
            if (record["run_name"] != obj["run_name"] or
                    record["root_entry_path"] != obj["root_entry_path"] or
                    record["root_entry_sha256"] != obj["root_entry_sha256"]):
                refuse("TERMINAL_BINDING")
            binding = {key: obj[key] for key in (
                "source_checkout", "source_commit", "stage_script_sha256", "operator_uid",
                "root_entry_path", "root_entry_sha256", "deadline")}
            binding["terminal_dir"] = obj["terminal_dir"]
    _validate_binding(binding, verb)
    return binding
def _validate_binding(binding, verb):
    if (not isinstance(binding.get("source_checkout"), str) or
            not SOURCE_PATH.fullmatch(binding["source_checkout"]) or
            not isinstance(binding.get("source_commit"), str) or
            not re.fullmatch(r"[0-9a-f]{40}", binding["source_commit"]) or
            type(binding.get("operator_uid")) is not int or binding["operator_uid"] <= 0 or
            not isinstance(binding.get("stage_script_sha256"), str) or
            not HEX64.fullmatch(binding["stage_script_sha256"]) or
            not isinstance(binding.get("root_entry_path"), str) or
            not LOADER_PATH.fullmatch(binding["root_entry_path"]) or
            not isinstance(binding.get("root_entry_sha256"), str) or
            not HEX64.fullmatch(binding["root_entry_sha256"])):
        refuse("BINDING_SCHEMA")
    if "deadline" in binding and (type(binding["deadline"]) is not int or binding["deadline"] <= 0):
        refuse("BINDING_SCHEMA")
    if verb == "prepare" and int(time.time()) >= binding["deadline"]:
        refuse("WINDOW_EXPIRED")
    if binding["root_entry_path"] != os.path.realpath(__file__):
        refuse("ROOT_ENTRY_PATH")
    raw = _read_run_file(os.path.basename(binding["root_entry_path"]), 0o500, MAX_CODE)
    if hashlib.sha256(raw).hexdigest() != binding["root_entry_sha256"]:
        refuse("ROOT_ENTRY_HASH")


def _open_dir_chain(path):
    if not path.startswith("/") or path == "/":
        refuse("SOURCE_PATH")
    fd = os.open("/", O_DIR)
    try:
        for component in path.strip("/").split("/"):
            if component in ("", ".", ".."):
                refuse("SOURCE_PATH")
            nxt = os.open(component, O_DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_controller(checkout, expected_uid, expected_sha):
    if not SOURCE_PATH.fullmatch(checkout):
        refuse("SOURCE_PATH")
    rootfd = _open_dir_chain(checkout)
    try:
        rootst = os.fstat(rootfd)
        owner = pwd.getpwuid(expected_uid)
        if (not stat.S_ISDIR(rootst.st_mode) or rootst.st_uid != expected_uid or
                rootst.st_gid != owner.pw_gid or stat.S_IMODE(rootst.st_mode) != 0o700):
            refuse("SOURCE_DIRECTORY")
        dfd = os.dup(rootfd)
        try:
            for component in CONTROLLER_REL[:-1]:
                nxt = os.open(component, O_DIR, dir_fd=dfd)
                os.close(dfd)
                dfd = nxt
            name = CONTROLLER_REL[-1]
            before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or
                    before.st_nlink != 1 or before.st_size > MAX_CODE or
                    (stat.S_IMODE(before.st_mode) & 0o022)):
                refuse("SOURCE_FILE")
            fd = os.open(name, O_FILE, dir_fd=dfd)
            try:
                opened = os.fstat(fd)
                if _identity(before) != _identity(opened):
                    refuse("SOURCE_DRIFT")
                chunks, size = [], 0
                while True:
                    block = os.read(fd, 65536)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_CODE:
                        refuse("SOURCE_SIZE")
                    chunks.append(block)
                data = b"".join(chunks)
                after = os.fstat(fd)
                current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                if _identity(opened) != _identity(after) or _identity(after) != _identity(current):
                    refuse("SOURCE_DRIFT")
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
    finally:
        os.close(rootfd)
    if hashlib.sha256(data).hexdigest() != expected_sha:
        refuse("SOURCE_HASH")
    return os.path.join(checkout, *CONTROLLER_REL), data


def run(verb):
    if os.geteuid() != 0:
        refuse("ROOT_REQUIRED")
    binding = _read_entry_binding(verb)
    if "terminal_dir" in binding:
        script_path, source, terminal_record = _terminal_controller(
            binding["terminal_dir"], binding["stage_script_sha256"])
    else:
        script_path, source = _read_controller(
            binding["source_checkout"], binding["operator_uid"], binding["stage_script_sha256"])
        terminal_record = None
    namespace = {
        "__name__": "__main__",
        "__file__": script_path,
        "__package__": None,
        "__cached__": None,
        "__builtins__": __builtins__,
        "ROOT_ENTRY_BINDING": {
            "path": binding["root_entry_path"],
            "sha256": binding["root_entry_sha256"],
            "verb": verb,
            "terminal_dir": binding.get("terminal_dir"),
            "terminal_phase": terminal_record["phase"] if terminal_record else None,
        },
    }
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                       "PYTHONDONTWRITEBYTECODE": "1"})
    sys.dont_write_bytecode = True
    sys.argv[:] = [script_path, verb]
    code = compile(source, script_path, "exec", dont_inherit=True)
    exec(code, namespace, namespace)
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 1 or argv[0] not in ALLOWED:
        print("STATUS=FAIL CATEGORY=ARGUMENTS")
        return 2
    try:
        return run(argv[0])
    except Refusal as exc:
        print("STATUS=FAIL CATEGORY=ROOT_ENTRY_" + exc.category)
        return 1
    except Exception:
        print("STATUS=FAIL CATEGORY=ROOT_ENTRY_INTERNAL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
