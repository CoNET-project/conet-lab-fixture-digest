#!/usr/bin/python3 -IB
"""Short-lived, fixed-purpose Lab G3 archive summary staging controller.

This tool is an administrative workflow helper, not a privilege reduction.
It accepts no caller-supplied paths or hashes for the read entries. Private
per-window values are supplied only by a root-owned bootstrap file.
"""
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

BOOTSTRAP = "/run/lab-g3-archive-a-bootstrap.json"
ACTIVE = "/run/lab-g3-archive-a-active.json"
SUDOERS_DIR = "/etc/sudoers.d"
ENGINE_REL = "assets/lab-g3-fixture-summary.py"
ARCHIVE_REL = "assets/lab-g3-fixture-archive-summary.py"
ENGINE_SHA256 = "5e63f874d0a55e3192ec576a4ba100969ef959511970028939e368db641cfe0e"
ARCHIVE_SHA256 = "a5f55b5647c2439a52157b348d3f4693647c4b4986c41d88f52cce73eee30a4e"
BOOTSTRAP_KEYS = {
    "schema_version", "operator", "source_checkout", "source_commit",
    "stage_script_sha256", "input_sha256",
    "valid_until_epoch", "fixture_root", "v2_manifest_sha256",
    "v2_selected_tree_sha256", "v2_generation", "v2_previous_generation",
    "archive_manifest_sha256", "archive_wal_sha256",
}
CONFIG_KEYS = {
    "schema_version", "fixture_root", "v2_manifest_sha256",
    "v2_selected_tree_sha256", "v2_generation", "v2_previous_generation",
    "archive_manifest_sha256", "archive_wal_sha256", "valid_until_epoch",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GEN = re.compile(r"^gen-\d{8}T\d{6}Z-[0-9a-f]{12}$")
FIXTURE = re.compile(r"^/var/tmp/lab-g3-synth-[A-Za-z0-9T-]+-[a-f0-9]{6}$")
SOURCE_PATH = re.compile(r"^/var/tmp/lab-archive-a-src\.[A-Za-z0-9]{8}$")
RUN_NAME = re.compile(r"^lab-g3-archive-a-\d{8}T\d{6}Z-[a-f0-9]{12}$")
RUN_BASE = "/run"
MAX_WINDOW_SECONDS = 900
MIN_WINDOW_SECONDS = 60
MAX_HELPER_OUTPUT = 8 * 1024 * 1024
IPROUTE2 = "/usr/sbin/ip"
MAX_NETWORK_OUTPUT = 1024 * 1024
SCRIPT = os.path.realpath(__file__)


class Refusal(Exception):
    def __init__(self, category):
        self.category = category


def fail(category):
    raise Refusal(category)


def _meta(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _check_root():
    if os.geteuid() != 0:
        fail("ROOT_REQUIRED")


def _read_regular(path, owner, mode, limit=65536):
    parent, name = os.path.split(path)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC |
                  getattr(os, "O_NOATIME", 0))
    try:
        before = os.stat(name, dir_fd=pfd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_gid != 0 or
                stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1 or before.st_size > limit):
            fail("INPUT_PERMISSIONS")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC |
                     getattr(os, "O_NOATIME", 0), dir_fd=pfd)
        try:
            opened = os.fstat(fd)
            if _meta(before) != _meta(opened):
                fail("INPUT_DRIFT")
            chunks, total = [], 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                total += len(block)
                if total > limit:
                    fail("INPUT_SIZE")
                chunks.append(block)
            after = os.fstat(fd)
            path_after = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            if _meta(opened) != _meta(after) or _meta(after) != _meta(path_after):
                fail("INPUT_DRIFT")
            return b"".join(chunks), _meta(after)
        finally:
            os.close(fd)
    except Refusal:
        raise
    except OSError:
        fail("INPUT_UNAVAILABLE")
    finally:
        os.close(pfd)


def _json_exact(blob, keys, category):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail(category)
            result[key] = value
        return result
    try:
        obj = json.loads(blob.decode("utf-8"), object_pairs_hook=unique)
    except Refusal:
        raise
    except Exception:
        fail(category)
    if not isinstance(obj, dict) or set(obj) != keys:
        fail(category)
    return obj


def validate_bootstrap(obj, now=None):
    if type(obj.get("schema_version")) is not int or obj["schema_version"] != 1:
        fail("BOOTSTRAP_SCHEMA")
    operator = obj.get("operator")
    if not isinstance(operator, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", operator):
        fail("BOOTSTRAP_SCHEMA")
    if not isinstance(obj.get("source_checkout"), str) or not SOURCE_PATH.fullmatch(obj["source_checkout"]):
        fail("SOURCE_PATH_POLICY")
    if not isinstance(obj.get("source_commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", obj["source_commit"]):
        fail("BOOTSTRAP_SCHEMA")
    if not isinstance(obj.get("stage_script_sha256"), str) or not HEX64.fullmatch(obj["stage_script_sha256"]):
        fail("BOOTSTRAP_SCHEMA")
    until = obj.get("valid_until_epoch")
    if type(until) is not int:
        fail("BOOTSTRAP_SCHEMA")
    if now is None:
        now = int(time.time())
    remaining = until - now
    if remaining < MIN_WINDOW_SECONDS or remaining > MAX_WINDOW_SECONDS:
        fail("WINDOW_DEADLINE")
    if not isinstance(obj.get("fixture_root"), str) or not FIXTURE.fullmatch(obj["fixture_root"]):
        fail("BOOTSTRAP_SCHEMA")
    for key in ("v2_manifest_sha256", "v2_selected_tree_sha256", "archive_manifest_sha256", "archive_wal_sha256"):
        if not isinstance(obj.get(key), str) or not HEX64.fullmatch(obj[key]):
            fail("BOOTSTRAP_SCHEMA")
    for key in ("v2_generation", "v2_previous_generation"):
        if not isinstance(obj.get(key), str) or not GEN.fullmatch(obj[key]):
            fail("BOOTSTRAP_SCHEMA")
    if obj["v2_generation"] == obj["v2_previous_generation"]:
        fail("BOOTSTRAP_SCHEMA")
    input_hashes = obj.get("input_sha256")
    if not isinstance(input_hashes, dict) or set(input_hashes) != {"site.env", "env/env0", "env/d6.env", "deny.json"}:
        fail("BOOTSTRAP_SCHEMA")
    if any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in input_hashes.values()):
        fail("BOOTSTRAP_SCHEMA")
    return remaining


def _git_identity(expected_uid, expected_gid, supplementary_groups, current_euid):
    if type(expected_uid) is not int or expected_uid <= 0 or type(expected_gid) is not int or expected_gid < 0:
        fail("SOURCE_GIT_IDENTITY")
    if (not isinstance(supplementary_groups, list) or
            any(type(group) is not int or group < 0 for group in supplementary_groups)):
        fail("SOURCE_GIT_IDENTITY")
    if current_euid == 0:
        return {"user": expected_uid, "group": expected_gid,
                "extra_groups": sorted(set(supplementary_groups))}
    if current_euid == expected_uid:
        return {}
    fail("SOURCE_GIT_IDENTITY")


def _git_read(checkout, args, expected_uid):
    if args not in (["rev-parse", "HEAD"],
                    ["status", "--porcelain=v1", "--untracked-files=all"]):
        fail("SOURCE_GIT_QUERY")
    try:
        owner = pwd.getpwuid(expected_uid)
        groups = os.getgrouplist(owner.pw_name, owner.pw_gid)
        identity = _git_identity(expected_uid, owner.pw_gid, groups, os.geteuid())
    except Refusal:
        raise
    except Exception:
        fail("SOURCE_GIT_IDENTITY")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": "/nonexistent",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"}
    try:
        result = subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                                 "-c", "core.fsmonitor=false", "-C", checkout, *args],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, timeout=8, check=False,
                                **identity)
    except Exception:
        fail("SOURCE_GIT_UNAVAILABLE")
    if result.returncode:
        fail("SOURCE_GIT_UNAVAILABLE")
    return result.stdout.decode("ascii", "strict").strip()


def verify_source(checkout, expected_commit, expected_uid):
    if not os.path.isabs(checkout) or not SOURCE_PATH.fullmatch(checkout):
        fail("SOURCE_PATH_POLICY")
    st = os.lstat(checkout)
    try:
        owner = pwd.getpwuid(expected_uid)
    except KeyError:
        fail("SOURCE_DIRECTORY")
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or
            os.path.realpath(checkout) != checkout or st.st_uid != expected_uid or st.st_gid != owner.pw_gid or
            stat.S_IMODE(st.st_mode) != 0o700):
        fail("SOURCE_DIRECTORY")
    if _git_read(checkout, ["rev-parse", "HEAD"], expected_uid) != expected_commit:
        fail("SOURCE_COMMIT_MISMATCH")
    if _git_read(checkout, ["status", "--porcelain=v1", "--untracked-files=all"], expected_uid):
        fail("SOURCE_DIRTY")
    expected_script = os.path.join(checkout, "ops", "lab-g3-archive-a", "stage-window.py")
    if SCRIPT != expected_script or _file_sha256(SCRIPT) != _file_sha256(expected_script):
        fail("STAGE_SCRIPT_SOURCE_MISMATCH")
    for rel, expected in ((ENGINE_REL, ENGINE_SHA256), (ARCHIVE_REL, ARCHIVE_SHA256)):
        path = os.path.join(checkout, rel)
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
            fail("SOURCE_FILE_TYPE")
        if _file_sha256(path) != expected:
            fail("SOURCE_HASH_MISMATCH")
    return True


def _g3_config(bootstrap):
    return {key: bootstrap[key] for key in CONFIG_KEYS}


def _sudoers_text(operator, run_dir):
    return (operator + " ALL=(root) NOPASSWD: " + run_dir + "/field \"\", " +
            run_dir + "/review \"\"\n")


def _entry_wrapper(run_dir, role):
    return ("#!/bin/sh\n"
            "set -eu\n"
            "[ \"$#\" -eq 0 ] || exit 2\n"
            "exec /usr/bin/python3 -IB " + run_dir + "/stage-window.py entry " + role + "\n")


def _write_new(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        data = content if isinstance(content, bytes) else content.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new_from_file(src, dst, expected_sha, mode=0o555):
    fd_in = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC |
                    getattr(os, "O_NOATIME", 0))
    try:
        st = os.fstat(fd_in)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            fail("SOURCE_FILE_TYPE")
        data = bytearray()
        h = hashlib.sha256()
        while True:
            block = os.read(fd_in, 65536)
            if not block:
                break
            h.update(block)
            data.extend(block)
        if h.hexdigest() != expected_sha or _meta(st) != _meta(os.fstat(fd_in)):
            fail("SOURCE_HASH_MISMATCH")
    finally:
        os.close(fd_in)
    _write_new(dst, bytes(data), mode)


def _sudoers_check(path):
    try:
        result = subprocess.run(["/usr/sbin/visudo", "-cf", path], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                timeout=8, check=False)
    except Exception:
        fail("VISUDO_UNAVAILABLE")
    if result.returncode:
        fail("SUDOERS_INVALID")


def _new_id(now=None):
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    return "lab-g3-archive-a-" + now.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]


def _host_preflight():
    run_st = os.lstat(RUN_BASE)
    if (not stat.S_ISDIR(run_st.st_mode) or stat.S_ISLNK(run_st.st_mode) or
            os.path.realpath(RUN_BASE) != RUN_BASE or run_st.st_uid != 0 or run_st.st_gid != 0):
        fail("RUN_DIRECTORY")
    if (not os.path.isdir(SUDOERS_DIR) or os.path.islink(SUDOERS_DIR) or
            os.path.realpath(SUDOERS_DIR) != SUDOERS_DIR):
        fail("SUDOERS_DIRECTORY")
    sst = os.stat(SUDOERS_DIR, follow_symlinks=False)
    if sst.st_uid != 0 or sst.st_gid != 0 or stat.S_IMODE(sst.st_mode) != 0o755:
        fail("SUDOERS_DIRECTORY")
    if os.path.lexists("/etc/lab-fixture-digest"):
        fail("HOST_CONFIG_PATH_PRESENT")
    if os.path.lexists(ACTIVE):
        fail("WINDOW_ALREADY_ACTIVE")
    if os.path.lexists(BOOTSTRAP) is False:
        fail("BOOTSTRAP_MISSING")


def _directory_fingerprint(path):
    try:
        root = os.lstat(path)
    except OSError:
        fail("HOST_PATH_UNAVAILABLE")
    if not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode) or os.path.realpath(path) != path:
        fail("HOST_PATH_TYPE")
    entries = []
    try:
        dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC |
                      getattr(os, "O_NOATIME", 0))
    except OSError:
        fail("HOST_PATH_UNAVAILABLE")
    try:
        for name in os.listdir(dfd):
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                entries.append((name, st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
                                st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
    except OSError:
        fail("HOST_PATH_UNAVAILABLE")
    finally:
        os.close(dfd)
    root_identity = (root.st_dev, root.st_ino, root.st_mode, root.st_nlink, root.st_uid, root.st_gid)
    material = repr((root_identity, sorted(entries, key=lambda row: os.fsencode(row[0])))).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _directory_identity(path):
    try:
        st = os.lstat(path)
    except OSError:
        fail("HOST_PATH_UNAVAILABLE")
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or os.path.realpath(path) != path:
        fail("HOST_PATH_TYPE")
    material = repr((st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid)).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _host_snapshots():
    return {
        "/usr/local/sbin": _directory_fingerprint("/usr/local/sbin"),
        "/etc/sudoers.d": _directory_fingerprint("/etc/sudoers.d"),
        "/run/systemd": _directory_identity("/run/systemd"),
        "/run/dbus": _directory_identity("/run/dbus"),
    }


def _prepare():
    _check_root()
    _host_preflight()
    raw, bootstrap_meta = _read_regular(BOOTSTRAP, 0, 0o600, 65536)
    bootstrap = _json_exact(raw, BOOTSTRAP_KEYS, "BOOTSTRAP_SCHEMA")
    ttl = validate_bootstrap(bootstrap)
    if _file_sha256(SCRIPT) != bootstrap["stage_script_sha256"]:
        fail("STAGE_SCRIPT_HASH_MISMATCH")
    operator = bootstrap["operator"]
    try:
        pw = pwd.getpwnam(operator)
    except KeyError:
        fail("OPERATOR_UNKNOWN")
    if pw.pw_uid == 0:
        fail("OPERATOR_UNKNOWN")
    verify_source(bootstrap["source_checkout"], bootstrap["source_commit"], pw.pw_uid)
    host_snapshots = _host_snapshots()
    os.chdir(bootstrap["source_checkout"])
    run_name = _new_id()
    run_dir = os.path.join(RUN_BASE, run_name)
    if not RUN_NAME.fullmatch(run_name) or os.path.lexists(run_dir):
        fail("RUN_PATH_COLLISION")
    sudoers_path = os.path.join(SUDOERS_DIR, run_name)
    if os.path.lexists(sudoers_path):
        fail("SUDOERS_PATH_COLLISION")
    os.mkdir(run_dir, 0o700)
    os.chown(run_dir, 0, 0)
    os.chmod(run_dir, 0o700)
    sudoers_created = False
    active_created = False
    watchdog_started = False
    rule_sha = None
    try:
        payload = os.path.join(run_dir, "payload")
        os.mkdir(payload, 0o700)
        os.chown(payload, 0, 0)
        os.chmod(payload, 0o700)
        _write_new_from_file(os.path.join(bootstrap["source_checkout"], ENGINE_REL),
                             os.path.join(payload, "engine.py"), ENGINE_SHA256)
        _write_new_from_file(os.path.join(bootstrap["source_checkout"], ARCHIVE_REL),
                             os.path.join(payload, "archive.py"), ARCHIVE_SHA256)
        _write_new_from_file(SCRIPT, os.path.join(run_dir, "stage-window.py"),
                             bootstrap["stage_script_sha256"], 0o500)
        config_blob = (json.dumps(_g3_config(bootstrap), sort_keys=True, separators=(",", ":")) + "\n").encode()
        _write_new(os.path.join(run_dir, "g3.json"), config_blob, 0o600)
        for role in ("field", "review"):
            wrapper = os.path.join(run_dir, role)
            _write_new(wrapper, _entry_wrapper(run_dir, role), 0o500)
        nsdir = os.path.join(run_dir, "ns")
        os.mkdir(nsdir, 0o700)
        os.chown(nsdir, 0, 0)
        os.chmod(nsdir, 0o700)
        _write_new(os.path.join(run_dir, "control.lock"), b"", 0o600)
        rule = _sudoers_text(operator, run_dir)
        temp_rule = os.path.join(run_dir, "sudoers.check")
        _write_new(temp_rule, rule, 0o440)
        _sudoers_check(temp_rule)
        os.unlink(temp_rule)
        rule_sha = hashlib.sha256(rule.encode("utf-8")).hexdigest()
        meta = {
            "schema_version": 1, "run_dir": run_dir, "run_name": run_name,
            "source_checkout": bootstrap["source_checkout"], "source_commit": bootstrap["source_commit"],
            "operator_uid": pw.pw_uid, "deadline": bootstrap["valid_until_epoch"],
            "input_sha256": bootstrap["input_sha256"],
            "sudoers_path": sudoers_path, "sudoers_sha256": rule_sha,
            "config_sha256": hashlib.sha256(config_blob).hexdigest(),
            "engine_sha256": ENGINE_SHA256, "archive_sha256": ARCHIVE_SHA256,
            "bootstrap_meta": list(bootstrap_meta), "host_mnt_ns": os.readlink("/proc/self/ns/mnt"),
            "host_net_ns": os.readlink("/proc/self/ns/net"),
            "stage_script_sha256": bootstrap["stage_script_sha256"], "bootstrap_sha256": hashlib.sha256(raw).hexdigest(),
            "host_snapshots": host_snapshots,
        }
        _write_new(os.path.join(run_dir, "meta.json"), json.dumps(meta, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
        _write_new(ACTIVE, json.dumps({"run_dir": run_dir, "run_name": run_name,
                                       "source_checkout": bootstrap["source_checkout"],
                                       "deadline": bootstrap["valid_until_epoch"],
                                       "sudoers_path": sudoers_path,
                                       "sudoers_sha256": rule_sha}, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
        active_created = True
        _start_watchdog(run_dir, bootstrap["valid_until_epoch"])
        watchdog_started = True
        _write_new(sudoers_path, rule, 0o440)
        sudoers_created = True
        result = subprocess.run(["/usr/sbin/visudo", "-c", "-q"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                timeout=8, check=False)
        if result.returncode:
            fail("SUDOERS_INVALID")
        if _file_sha256(sudoers_path) != rule_sha:
            fail("SUDOERS_READBACK_FAILED")
        # The bootstrap is a one-window input. Remove it only after every
        # staged object and the auto-expiry process have been verified.
        os.unlink(BOOTSTRAP)
        print("STATUS=STAGED")
        print("ENTRY_FIELD=" + run_dir + "/field")
        print("ENTRY_REVIEW=" + run_dir + "/review")
        print("CLOSE=sudo -n /usr/bin/python3 -IB " + bootstrap["source_checkout"] + "/ops/lab-g3-archive-a/stage-window.py close")
        print("READBACK=sudo -n /usr/bin/python3 -IB " + bootstrap["source_checkout"] + "/ops/lab-g3-archive-a/stage-window.py readback")
        print("DEADLINE_EPOCH=" + str(bootstrap["valid_until_epoch"]))
        print("SOURCE_COMMIT=" + bootstrap["source_commit"])
        print("CONFIG_SHA256=" + meta["config_sha256"])
        print("SUDOERS_SHA256=" + rule_sha)
        print("TRUST_MODEL=existing administrator permissions unchanged; exact temporary entries are workflow restrictions")
        return 0
    except Exception:
        if sudoers_created and rule_sha and os.path.lexists(sudoers_path):
            try:
                if _file_sha256(sudoers_path) == rule_sha:
                    os.unlink(sudoers_path)
            except Exception:
                pass
        if watchdog_started:
            _best_effort_stop_watchdog(run_dir)
        if active_created:
            _best_effort_remove(ACTIVE)
        _best_effort_remove_tree(run_dir)
        raise


def _file_sha256(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC |
                 getattr(os, "O_NOATIME", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail("FILE_TYPE")
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            h.update(b)
    finally:
        os.close(fd)
    return h.hexdigest()


def _entry(role):
    _check_root()
    if role not in ("field", "review"):
        fail("ENTRY_ROLE")
    run_dir = os.path.dirname(os.path.realpath(__file__))
    run_name = os.path.basename(run_dir)
    if not RUN_NAME.fullmatch(run_name) or not os.path.realpath(run_dir) == run_dir:
        fail("RUN_PATH_POLICY")
    meta = _load_meta(run_dir)
    if int(time.time()) >= meta["deadline"]:
        fail("WINDOW_EXPIRED")
    marker = os.path.join(run_dir, "seat." + role)
    try:
        _write_new(marker, "started\n", 0o600)
    except FileExistsError:
        fail("SEAT_ALREADY_USED")
    # The only privileged command exposed by sudoers is this fixed no-argument
    # wrapper. The wrapper starts a fresh private mount and network namespace.
    try:
        result = subprocess.run(["/usr/bin/unshare", "--mount", "--net", "--propagation", "private", "--",
                                 "/usr/bin/python3", "-IB", os.path.join(run_dir, "stage-window.py"),
                                 "inner", role], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                                     "PYTHONDONTWRITEBYTECODE": "1"},
                                timeout=max(1, meta["deadline"] - int(time.time())), check=False)
    except subprocess.TimeoutExpired:
        print("STATUS=FAIL CATEGORY=WINDOW_EXPIRED")
        return 1
    except Exception:
        fail("NAMESPACE_UNAVAILABLE")
    if result.returncode != 0:
        # Do not echo arbitrary subprocess output on failure.
        category = _fixed_failure_category(result.stdout)
        print("STATUS=FAIL CATEGORY=" + (category or "READ_ENTRY_FAILED"))
        return 1
    output = result.stdout.decode("utf-8", "strict")
    if len(result.stdout) > MAX_HELPER_OUTPUT:
        print("STATUS=FAIL CATEGORY=READ_OUTPUT_INVALID")
        return 1
    _validate_entry_output(output, meta)
    if int(time.time()) >= meta["deadline"]:
        fail("WINDOW_EXPIRED")
    sys.stdout.write(output)
    sys.stdout.flush()
    completed = ("ROLE=" + role + "\nDONE_UTC=" +
                 datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") +
                 "\nOUTPUT_SHA256=" + hashlib.sha256(result.stdout).hexdigest() + "\n")
    try:
        _write_new(os.path.join(run_dir, "seat." + role + ".done"), completed, 0o600)
    except FileExistsError:
        fail("SEAT_COMPLETION_ALREADY_RECORDED")
    return 0


def _fixed_failure_category(output):
    if not isinstance(output, bytes) or len(output) > 128:
        return None
    match = re.fullmatch(rb"STATUS=FAIL CATEGORY=([A-Z][A-Z0-9_]{0,63})\n", output)
    return match.group(1).decode("ascii") if match else None


def _watchdog_exec_argv(run_dir):
    return ["/usr/bin/python3", "-IB", os.path.join(run_dir, "stage-window.py"), "watchdog"]


def _validate_entry_output(output, meta):
    lines = output.splitlines()
    if not lines or lines[0] != "STATUS=PASS" or not output.endswith("\n"):
        fail("READ_OUTPUT_INVALID")
    sections = ("BEGIN_PRE_ANCHOR", "END_PRE_ANCHOR", "BEGIN_ARCHIVE_ONLY",
                "END_ARCHIVE_ONLY", "BEGIN_POST_ANCHOR", "END_POST_ANCHOR")
    positions = []
    for marker in sections:
        if lines.count(marker) != 1:
            fail("READ_OUTPUT_INVALID")
        positions.append(lines.index(marker))
    if (positions != sorted(positions) or positions[0] != 1 or
            positions[2] != positions[1] + 1 or positions[4] != positions[3] + 1 or
            positions[-1] != len(lines) - 1):
        fail("READ_OUTPUT_INVALID")
    pre_raw = ("\n".join(lines[positions[0] + 1:positions[1]]) + "\n").encode("utf-8")
    archive_lines = lines[positions[2] + 1:positions[3]]
    archive_raw = ("\n".join(archive_lines) + "\n").encode("utf-8")
    post_raw = ("\n".join(lines[positions[4] + 1:positions[5]]) + "\n").encode("utf-8")
    pre_selected, _ = _extract_anchor(pre_raw)
    post_selected, _ = _extract_anchor(post_raw)
    expected_config = "CONFIG=PASS sha256=" + meta["config_sha256"]
    if (pre_selected != post_selected or pre_selected[1] != expected_config or
            post_selected[1] != expected_config):
        fail("READ_OUTPUT_INVALID")
    _check_anchor_input_hashes(pre_selected, meta["input_sha256"])
    _validate_archive_output(archive_raw.decode("utf-8", "strict"), meta["config_sha256"])


def _seat_marker_state(started, done, role, deadline=None):
    if started is None and done is None:
        return False
    if started != b"started\n":
        fail("SEAT_MARKER_INVALID")
    if done is None:
        return False
    try:
        text = done.decode("ascii")
    except Exception:
        fail("SEAT_MARKER_INVALID")
    match = re.fullmatch(
        r"ROLE=" + re.escape(role) +
        r"\nDONE_UTC=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\nOUTPUT_SHA256=([0-9a-f]{64})\n",
        text)
    if not match:
        fail("SEAT_MARKER_INVALID")
    try:
        parsed = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%SZ")
        if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != match.group(1):
            fail("SEAT_MARKER_INVALID")
        if deadline is not None and int(parsed.replace(tzinfo=datetime.timezone.utc).timestamp()) > deadline:
            fail("SEAT_MARKER_INVALID")
    except Exception:
        fail("SEAT_MARKER_INVALID")
    return True


def _seat_state(run_dir, role, deadline=None, allow_malformed=False):
    values = []
    for suffix in ("", ".done"):
        path = os.path.join(run_dir, "seat." + role + suffix)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            values.append(None)
            continue
        if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or
                st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
            fail("SEAT_MARKER_UNSAFE")
        blob, _ = _read_regular(path, 0, 0o600, 256)
        values.append(blob)
    try:
        return _seat_marker_state(values[0], values[1], role, deadline)
    except Refusal:
        if allow_malformed:
            return False
        raise


def _close_seat_state(read_state, expired):
    try:
        return read_state()
    except Refusal as exc:
        if expired and exc.category == "SEAT_MARKER_INVALID":
            return False
        raise


def _close_seat_status(field_complete, review_complete, expired):
    if not expired and not (field_complete and review_complete):
        fail("SEATS_INCOMPLETE")
    return "COMPLETE" if field_complete and review_complete else "INCOMPLETE"


def _load_meta(run_dir):
    raw, _ = _read_regular(os.path.join(run_dir, "meta.json"), 0, 0o600, 65536)
    obj = _json_exact(raw, {
        "schema_version", "run_dir", "run_name", "source_checkout", "source_commit",
        "operator_uid", "deadline", "sudoers_path", "sudoers_sha256", "config_sha256",
        "engine_sha256", "archive_sha256", "bootstrap_meta", "host_mnt_ns", "stage_script_sha256",
        "bootstrap_sha256", "host_net_ns", "host_snapshots", "input_sha256",
    }, "META_INVALID")
    if obj["schema_version"] != 1 or obj["run_dir"] != run_dir or obj["run_name"] != os.path.basename(run_dir):
        fail("META_INVALID")
    if _file_sha256(os.path.join(run_dir, "stage-window.py")) != obj["stage_script_sha256"]:
        fail("STAGE_SCRIPT_HASH")
    return obj


def _mount(args):
    try:
        result = subprocess.run(["/usr/bin/mount", *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                timeout=8, check=False)
    except Exception:
        fail("PRIVATE_MOUNT_FAILED")
    if result.returncode:
        fail("PRIVATE_MOUNT_FAILED")


def _mount_type(target):
    try:
        with open("/proc/self/mountinfo", "rt", encoding="ascii") as stream:
            rows = stream.readlines()
    except OSError:
        fail("MOUNTINFO_UNAVAILABLE")
    for row in rows:
        parts = row.rstrip("\n").split(" ")
        if len(parts) >= 10 and parts[4].replace("\\040", " ") == target:
            try:
                separator = parts.index("-")
            except ValueError:
                continue
            if len(parts) > separator + 1:
                return parts[separator + 1]
    return None


def _ip_json(args):
    """Read network state from the current process network namespace."""
    try:
        result = subprocess.run([IPROUTE2, "-j", *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                timeout=4, check=False)
    except Exception:
        fail("NETWORK_STATE_UNAVAILABLE")
    if result.returncode != 0 or len(result.stdout) > MAX_NETWORK_OUTPUT:
        fail("NETWORK_STATE_UNAVAILABLE")
    try:
        value = json.loads(result.stdout.decode("utf-8", "strict"))
    except Exception:
        fail("NETWORK_STATE_UNAVAILABLE")
    if not isinstance(value, list):
        fail("NETWORK_STATE_UNAVAILABLE")
    return value


def _network_address_rows(rows, family):
    if not isinstance(rows, list):
        fail("NETWORK_STATE_UNAVAILABLE")
    # iproute2 filters out links without an address in the requested family;
    # a successful JSON [] is valid absence, unlike missing or malformed data.
    if not rows:
        return
    if len(rows) != 1:
        fail("NETWORK_STATE_UNAVAILABLE")
    for interface in rows:
        if not isinstance(interface, dict) or interface.get("ifname") != "lo":
            fail("NETWORK_NAMESPACE_NOT_ISOLATED")
        addresses = interface.get("addr_info")
        if not isinstance(addresses, list):
            fail("NETWORK_STATE_UNAVAILABLE")
        for item in addresses:
            if not isinstance(item, dict) or item.get("family") != family:
                fail("NETWORK_STATE_UNAVAILABLE")
            local = item.get("local")
            if not isinstance(local, str):
                fail("NETWORK_STATE_UNAVAILABLE")
            try:
                address = ipaddress.ip_address(local.split("%", 1)[0])
            except ValueError:
                fail("NETWORK_STATE_UNAVAILABLE")
            if address.version != (4 if family == "inet" else 6):
                fail("NETWORK_STATE_UNAVAILABLE")
            if not address.is_loopback:
                fail("NETWORK_NAMESPACE_NOT_ISOLATED")


def _network_routes(rows, family):
    if not isinstance(rows, list):
        fail("NETWORK_STATE_UNAVAILABLE")
    loopback = ipaddress.ip_network("127.0.0.0/8" if family == 4 else "::1/128")
    nonforwarding = {"unreachable", "blackhole", "prohibit"}
    sentinel_count = 0
    for route in rows:
        if not isinstance(route, dict):
            fail("NETWORK_STATE_UNAVAILABLE")
        route_type = route.get("type", "unicast")
        if not isinstance(route_type, str):
            fail("NETWORK_STATE_UNAVAILABLE")
        dst = route.get("dst")
        if not isinstance(dst, str):
            fail("NETWORK_STATE_UNAVAILABLE")
        if dst == "default":
            network = ipaddress.ip_network("0.0.0.0/0" if family == 4 else "::/0")
        else:
            try:
                network = ipaddress.ip_network(dst, strict=False)
            except ValueError:
                fail("NETWORK_STATE_UNAVAILABLE")
        if network.version != family:
            fail("NETWORK_STATE_UNAVAILABLE")
        dev = route.get("dev")
        gateway = route.get("gateway")
        if route_type in nonforwarding:
            # An explicit non-forwarding route is not missing data. It is safe
            # only when no device or gateway can turn it into an egress path.
            if dev not in (None, "lo") or gateway is not None:
                fail("NETWORK_NAMESPACE_NOT_ISOLATED")
            sentinel_count += 1
            continue
        if route_type not in ("local", "broadcast", "multicast", "unicast"):
            fail("NETWORK_STATE_UNAVAILABLE")
        if dev != "lo" or gateway is not None:
            fail("NETWORK_ROUTE_PRESENT")
        if dst == "default":
            fail("NETWORK_ROUTE_PRESENT")
        if not network.subnet_of(loopback):
            fail("NETWORK_ROUTE_PRESENT")
    return "explicit_nonforwarding" if sentinel_count else "no_route_rows"


def _check_network_isolation():
    """Fail closed unless the current netns has loopback only and no egress route."""
    links = _ip_json(["link", "show"])
    if len(links) != 1 or not isinstance(links[0], dict):
        fail("NETWORK_NAMESPACE_NOT_ISOLATED")
    flags = links[0].get("flags")
    if not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags):
        fail("NETWORK_STATE_UNAVAILABLE")
    if links[0].get("ifname") != "lo" or "LOOPBACK" not in flags:
        fail("NETWORK_NAMESPACE_NOT_ISOLATED")
    v4_addrs = _ip_json(["-4", "address", "show"])
    v6_addrs = _ip_json(["-6", "address", "show"])
    _network_address_rows(v4_addrs, "inet")
    _network_address_rows(v6_addrs, "inet6")
    v4_routes = _ip_json(["-4", "route", "show", "table", "all"])
    v6_routes = _ip_json(["-6", "route", "show", "table", "all"])
    _network_routes(v4_routes, 4)
    _network_routes(v6_routes, 6)


def _check_staged_file(path, expected_sha):
    try:
        st = os.lstat(path)
    except OSError:
        fail("STAGED_FILE_MISSING")
    if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or
            st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o555 or st.st_nlink != 1):
        fail("STAGED_FILE_PERMISSIONS")
    if _file_sha256(path) != expected_sha:
        fail("STAGED_FILE_HASH")


def _extract_anchor(stdout):
    if len(stdout) > MAX_HELPER_OUTPUT:
        fail("ANCHOR_OUTPUT_SIZE")
    try:
        lines = stdout.decode("utf-8", "strict").splitlines()
    except Exception:
        fail("ANCHOR_OUTPUT_INVALID")
    status = [x for x in lines if x.startswith("STATUS=")]
    starts = [x for x in lines if x.startswith("START_UTC=")]
    ends = [x for x in lines if x.startswith("END_UTC=")]
    config = [x for x in lines if x.startswith("CONFIG=")]
    v2 = [x for x in lines if x.startswith("V2_BEFORE_AFTER=")]
    inputs = [x for x in lines if x.startswith("INPUT ")]
    if (status != ["STATUS=PASS"] or len(starts) != 1 or len(ends) != 1 or
            not re.fullmatch(r"START_UTC=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", starts[0]) or
            not re.fullmatch(r"END_UTC=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ends[0]) or
            len(config) != 1 or not re.fullmatch(r"CONFIG=PASS sha256=[0-9a-f]{64}", config[0])):
        fail("ANCHOR_OUTPUT_INVALID")
    if len(v2) != 1 or not re.fullmatch(
        r"V2_BEFORE_AFTER=IDENTICAL version=2 generation=gen-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12} "
        r"previous=gen-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12} manifest_sha256=[0-9a-f]{64} "
        r"selected_tree_sha256=[0-9a-f]{64} files=[1-9][0-9]* WAL=ABSENT", v2[0]):
        fail("ANCHOR_OUTPUT_INVALID")
    v2_match = re.fullmatch(
        r"V2_BEFORE_AFTER=IDENTICAL version=2 generation=(gen-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}) "
        r"previous=(gen-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}) manifest_sha256=[0-9a-f]{64} "
        r"selected_tree_sha256=[0-9a-f]{64} files=[1-9][0-9]* WAL=ABSENT", v2[0])
    if not v2_match or v2_match.group(1) == v2_match.group(2):
        fail("ANCHOR_OUTPUT_INVALID")
    if len(inputs) != 4:
        fail("ANCHOR_OUTPUT_INVALID")
    expected = ("site.env", "env/env0", "env/d6.env", "deny.json")
    for line, rel in zip(inputs, expected):
        if not re.fullmatch(r"INPUT type=file path=" + re.escape(rel) +
                            r" sha256=[0-9a-f]{64} size=[0-9]+ uid=[0-9]+ gid=[0-9]+ mode=[0-7]{4}", line):
            fail("ANCHOR_OUTPUT_INVALID")
    allowed = tuple(("STATUS=", "START_UTC=", "END_UTC=", "CONFIG=", "V2_BEFORE_AFTER=", "INPUT ",
                     "ARCHIVE type=", "ARCHIVE_V3_HISTORICAL_GENERATION ", "ARCHIVE_FILE "))
    if any(not line.startswith(allowed) for line in lines):
        fail("ANCHOR_OUTPUT_INVALID")
    selected = [status[0], config[0], v2[0], *inputs]
    return tuple(selected), lines


def _run_helper(argv, timeout):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                                     "PYTHONDONTWRITEBYTECODE": "1"},
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        fail("HELPER_TIMEOUT")
    except Exception:
        fail("HELPER_UNAVAILABLE")
    if result.returncode != 0 or len(result.stdout) > MAX_HELPER_OUTPUT:
        fail("HELPER_REJECTED")
    return result.stdout


def _inner(role):
    _check_root()
    if role not in ("field", "review"):
        fail("ENTRY_ROLE")
    run_dir = os.path.dirname(os.path.realpath(__file__))
    meta = _load_meta(run_dir)
    if int(time.time()) >= meta["deadline"]:
        fail("WINDOW_EXPIRED")
    if os.readlink("/proc/self/ns/mnt") == meta["host_mnt_ns"]:
        fail("MOUNT_NAMESPACE_NOT_PRIVATE")
    if os.readlink("/proc/self/ns/net") == meta["host_net_ns"]:
        fail("NETWORK_NAMESPACE_NOT_PRIVATE")
    _check_network_isolation()
    os.makedirs(os.path.join(run_dir, "ns"), mode=0o700, exist_ok=True)
    _mount(["--make-rprivate", "/"])
    _mount(["-t", "tmpfs", "-o", "size=64m,mode=0700,nosuid,nodev", "tmpfs", os.path.join(run_dir, "ns")])
    nsdir = os.path.join(run_dir, "ns")
    os.mkdir(os.path.join(nsdir, "upper"), 0o700)
    os.mkdir(os.path.join(nsdir, "work"), 0o700)
    _mount(["-t", "overlay", "overlay", "-o", "lowerdir=/etc,upperdir=" + nsdir + "/upper,workdir=" + nsdir + "/work", "/etc"])
    if _mount_type("/etc") != "overlay":
        fail("PRIVATE_CONFIG_VIEW")
    try:
        os.mkdir("/etc/lab-fixture-digest", 0o700)
    except FileExistsError:
        fail("PRIVATE_CONFIG_VIEW")
    shutil.copyfile(os.path.join(run_dir, "g3.json"), "/etc/lab-fixture-digest/g3.json", follow_symlinks=False)
    os.chown("/etc/lab-fixture-digest", 0, 0)
    os.chmod("/etc/lab-fixture-digest", 0o700)
    os.chown("/etc/lab-fixture-digest/g3.json", 0, 0)
    os.chmod("/etc/lab-fixture-digest/g3.json", 0o600)
    # Mask, never write, the host helper directory and system service buses.
    for path in ("/usr/local/sbin", "/run/systemd", "/run/dbus"):
        if not os.path.isdir(path) or os.path.islink(path):
            fail("PRIVATE_MASK_PATH")
    sbin_tmp = os.path.join(nsdir, "sbin")
    os.mkdir(sbin_tmp, 0o755)
    _mount(["-t", "tmpfs", "-o", "size=16m,mode=0755,nosuid,nodev", "tmpfs", "/usr/local/sbin"])
    if _mount_type("/usr/local/sbin") != "tmpfs":
        fail("PRIVATE_HELPER_VIEW")
    shutil.copyfile(os.path.join(run_dir, "payload", "engine.py"), "/usr/local/sbin/lab-fixture-digest", follow_symlinks=False)
    os.chown("/usr/local/sbin/lab-fixture-digest", 0, 0)
    os.chmod("/usr/local/sbin/lab-fixture-digest", 0o555)
    for path in ("/run/systemd", "/run/dbus"):
        masked = os.path.join(nsdir, "mask-" + os.path.basename(path))
        os.mkdir(masked, 0o755)
        _mount(["-t", "tmpfs", "-o", "size=1m,mode=0755,nosuid,nodev", "tmpfs", path])
        if _mount_type(path) != "tmpfs":
            fail("SERVICE_BUS_NOT_MASKED")
        if os.listdir(path):
            fail("SERVICE_BUS_NOT_MASKED")
    _check_staged_file("/usr/local/sbin/lab-fixture-digest", meta["engine_sha256"])
    _check_staged_file(os.path.join(run_dir, "payload", "archive.py"), meta["archive_sha256"])
    if _file_sha256("/etc/lab-fixture-digest/g3.json") != meta["config_sha256"]:
        fail("CONFIG_BINDING_MISMATCH")
    remaining = max(1, meta["deadline"] - int(time.time()))
    pre = _run_helper(["/usr/bin/python3", "-IB", "/usr/local/sbin/lab-fixture-digest"], remaining)
    pre_selected, pre_lines = _extract_anchor(pre)
    if pre_selected[1] != "CONFIG=PASS sha256=" + meta["config_sha256"]:
        fail("CONFIG_BINDING_MISMATCH")
    _check_anchor_input_hashes(pre_selected, meta["input_sha256"])
    remaining = max(1, meta["deadline"] - int(time.time()))
    archive = _run_helper(["/usr/bin/python3", "-IB", os.path.join(run_dir, "payload", "archive.py")], remaining)
    archive_text = archive.decode("utf-8", "strict")
    _validate_archive_output(archive_text, meta["config_sha256"])
    remaining = max(1, meta["deadline"] - int(time.time()))
    post = _run_helper(["/usr/bin/python3", "-IB", "/usr/local/sbin/lab-fixture-digest"], remaining)
    post_selected, post_lines = _extract_anchor(post)
    if post_selected[1] != "CONFIG=PASS sha256=" + meta["config_sha256"]:
        fail("CONFIG_BINDING_MISMATCH")
    _check_anchor_input_hashes(post_selected, meta["input_sha256"])
    if pre_selected != post_selected:
        fail("ANCHOR_CHANGED")
    if int(time.time()) >= meta["deadline"]:
        fail("WINDOW_EXPIRED")
    print("STATUS=PASS")
    print("BEGIN_PRE_ANCHOR")
    sys.stdout.write("\n".join([line for line in pre_lines if line.startswith(("STATUS=", "START_UTC=", "END_UTC=", "CONFIG=", "V2_BEFORE_AFTER=", "INPUT "))]) + "\n")
    print("END_PRE_ANCHOR")
    print("BEGIN_ARCHIVE_ONLY")
    sys.stdout.write(archive_text if archive_text.endswith("\n") else archive_text + "\n")
    print("END_ARCHIVE_ONLY")
    print("BEGIN_POST_ANCHOR")
    sys.stdout.write("\n".join([line for line in post_lines if line.startswith(("STATUS=", "START_UTC=", "END_UTC=", "CONFIG=", "V2_BEFORE_AFTER=", "INPUT "))]) + "\n")
    print("END_POST_ANCHOR")
    return 0


def _validate_archive_output(text, config_sha):
    lines = text.splitlines()
    statuses = [line for line in lines if line.startswith("STATUS=")]
    configs = [line for line in lines if line.startswith("CONFIG=")]
    roots = [line for line in lines if line.startswith("ARCHIVE type=directory ")]
    if statuses != ["STATUS=PASS"] or configs != ["CONFIG=PASS sha256=" + config_sha] or len(roots) != 1:
        fail("ARCHIVE_OUTPUT_INVALID")
    if sum(line.startswith("START_UTC=") for line in lines) != 1 or sum(line.startswith("END_UTC=") for line in lines) != 1:
        fail("ARCHIVE_OUTPUT_INVALID")
    patterns = (
        re.compile(r"START_UTC=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"),
        re.compile(r"END_UTC=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"),
        re.compile(r"CONFIG=PASS sha256=[0-9a-f]{64}"),
        re.compile(r"ARCHIVE type=directory path=attempt8-pre-fault-replay-archive sha256=- uid=[0-9]+ gid=[0-9]+ mode=[0-7]{4} top_level_exact=PASS files=[0-9]+ entries=[0-9]+ aggregate_sha256=[0-9a-f]{64}"),
        re.compile(r"ARCHIVE_DIR type=directory path=[A-Za-z0-9._/-]+ sha256=- uid=[0-9]+ gid=[0-9]+ mode=[0-7]{4}"),
        re.compile(r"ARCHIVE_FILE type=file path=[A-Za-z0-9._/-]+ sha256=[0-9a-f]{64} size=[0-9]+ uid=[0-9]+ gid=[0-9]+ mode=[0-7]{4}"),
    )
    for line in lines:
        if line == "STATUS=PASS":
            continue
        if not any(pattern.fullmatch(line) for pattern in patterns):
            fail("ARCHIVE_OUTPUT_INVALID")


def _check_anchor_input_hashes(selected, expected):
    names = {"site.env", "env/env0", "env/d6.env", "deny.json"}
    if not isinstance(expected, dict) or set(expected) != names:
        fail("META_INVALID")
    for line in selected[3:]:
        match = re.fullmatch(r"INPUT type=file path=(site\.env|env/env0|env/d6\.env|deny\.json) sha256=([0-9a-f]{64}) size=[0-9]+ uid=[0-9]+ gid=[0-9]+ mode=[0-7]{4}", line)
        if not match or expected.get(match.group(1)) != match.group(2):
            fail("INPUT_ANCHOR_MISMATCH")


def _active_read():
    raw, _ = _read_regular(ACTIVE, 0, 0o600, 8192)
    obj = _json_exact(raw, {"run_dir", "run_name", "source_checkout", "deadline", "sudoers_path", "sudoers_sha256"}, "ACTIVE_INVALID")
    if (not isinstance(obj["run_name"], str) or not RUN_NAME.fullmatch(obj["run_name"]) or
            obj["run_dir"] != os.path.join(RUN_BASE, obj["run_name"]) or
            obj["sudoers_path"] != os.path.join(SUDOERS_DIR, obj["run_name"]) or
            not SOURCE_PATH.fullmatch(obj["source_checkout"])):
        fail("ACTIVE_INVALID")
    return obj


def _start_watchdog(run_dir, deadline):
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            if devnull > 2:
                os.close(devnull)
            meta = _load_meta(run_dir)
            if meta["deadline"] != deadline:
                os._exit(1)
            os.chdir(meta["source_checkout"])
            argv = _watchdog_exec_argv(run_dir)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                   "PYTHONDONTWRITEBYTECODE": "1"}
            os.execve(argv[0], argv, env)
        except BaseException:
            os._exit(1)
    ready = os.path.join(run_dir, "watchdog.pid")
    for _ in range(100):
        if os.path.exists(ready):
            return
        time.sleep(0.01)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    fail("WATCHDOG_START_FAILED")


def _sudoers_remove(active):
    path = active["sudoers_path"]
    status = "REMOVED_AND_VALIDATED"
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        status = "ALREADY_ABSENT"
    else:
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o440 or st.st_nlink != 1:
            fail("SUDOERS_ENTRY_DRIFT")
        if _file_sha256(path) != active["sudoers_sha256"]:
            fail("SUDOERS_ENTRY_DRIFT")
        os.unlink(path)
    try:
        result = subprocess.run(["/usr/sbin/visudo", "-c", "-q"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                timeout=8, check=False)
    except Exception:
        fail("VISUDO_UNAVAILABLE")
    if result.returncode:
        fail("SUDOERS_READBACK_FAILED")
    if os.path.lexists(path):
        fail("SUDOERS_READBACK_FAILED")
    return status


def _locked(run_dir):
    lockfd = os.open(os.path.join(run_dir, "control.lock"), os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    fcntl.flock(lockfd, fcntl.LOCK_EX)
    return lockfd


def _expire_window():
    _check_root()
    active = _active_read()
    lockfd = _locked(active["run_dir"])
    try:
        status = _sudoers_remove(active)
        receipt = "STATUS=EXPIRED\nSUDOERS=" + status + "\nDEADLINE_EPOCH=" + str(active["deadline"]) + "\n"
        closed = os.path.join(RUN_BASE, active["run_name"] + ".closed")
        if not os.path.lexists(closed):
            _write_new(closed, receipt, 0o600)
    finally:
        os.close(lockfd)


def _safe_remove_tree(path, expected_name, allow_incomplete=False):
    if path != os.path.join(RUN_BASE, expected_name) or not RUN_NAME.fullmatch(expected_name):
        fail("CLEANUP_PATH_POLICY")
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        fail("CLEANUP_PATH_POLICY")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        fail("SAFE_RMTREE_UNAVAILABLE")
    _check_run_tree(path, allow_incomplete=allow_incomplete)
    shutil.rmtree(path)
    if os.path.lexists(path):
        fail("CLEANUP_READBACK_FAILED")


def _check_run_tree(path, allow_incomplete=False):
    required = {"payload", "stage-window.py", "g3.json", "field", "review", "ns", "control.lock", "meta.json", "watchdog.pid"}
    allowed = required | {"seat.field", "seat.review", "seat.field.done", "seat.review.done"}
    names = set(os.listdir(path))
    if not required.issubset(names) or names - allowed:
        fail("CLEANUP_ENTRY_SET")
    for name in ("payload", "ns"):
        st = os.lstat(os.path.join(path, name))
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
            fail("CLEANUP_NODE_TYPE")
    payload = os.path.join(path, "payload")
    if set(os.listdir(payload)) != {"engine.py", "archive.py"}:
        fail("CLEANUP_ENTRY_SET")
    if os.listdir(os.path.join(path, "ns")):
        fail("CLEANUP_ENTRY_SET")
    for name in names - {"payload", "ns"}:
        st = os.lstat(os.path.join(path, name))
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1:
            fail("CLEANUP_NODE_TYPE")
    for role in ("field", "review"):
        _seat_state(path, role, allow_malformed=allow_incomplete)


def _remove_checkout(path, expected_commit, expected_uid):
    if not SOURCE_PATH.fullmatch(path):
        fail("SOURCE_PATH_POLICY")
    if not os.path.lexists(path):
        return "ALREADY_ABSENT"
    st = os.lstat(path)
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or
            st.st_uid != expected_uid or stat.S_IMODE(st.st_mode) != 0o700 or
            os.path.realpath(path) != path):
        fail("CHECKOUT_CLEANUP_REFUSED")
    if (_git_read(path, ["rev-parse", "HEAD"], expected_uid) != expected_commit or
            _git_read(path, ["status", "--porcelain=v1", "--untracked-files=all"], expected_uid)):
        fail("CHECKOUT_CLEANUP_REFUSED")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        fail("SAFE_RMTREE_UNAVAILABLE")
    shutil.rmtree(path)
    if os.path.lexists(path):
        fail("CLEANUP_READBACK_FAILED")
    return "REMOVED"


def _close():
    _check_root()
    active = _active_read()
    run_dir = active["run_dir"]
    meta = _load_meta(run_dir)
    if meta["sudoers_sha256"] != active["sudoers_sha256"]:
        fail("ACTIVE_BINDING_MISMATCH")
    lockfd = _locked(run_dir)
    try:
        _close_locked(active, meta, run_dir)
    finally:
        os.close(lockfd)


def _close_locked(active, meta, run_dir):
    expired = int(time.time()) >= meta["deadline"]
    expired_receipt = os.path.join(RUN_BASE, active["run_name"] + ".closed")
    if os.path.lexists(expired_receipt):
        raw_expired, _ = _read_regular(expired_receipt, 0, 0o600, 2048)
        if not raw_expired.startswith(b"STATUS=EXPIRED\n"):
            fail("EXPIRY_RECEIPT_INVALID")
        expired = True
    field_complete = _close_seat_state(
        lambda: _seat_state(run_dir, "field", meta["deadline"], allow_malformed=expired), expired)
    review_complete = _close_seat_state(
        lambda: _seat_state(run_dir, "review", meta["deadline"], allow_malformed=expired), expired)
    seat_status = _close_seat_status(field_complete, review_complete, expired)
    # Stop only this window's watchdog. It is never a service and is never
    # allowed to survive this exact staging session.
    watchdog_path = os.path.join(run_dir, "watchdog.pid")
    if os.path.exists(watchdog_path):
        raw, _ = _read_regular(watchdog_path, 0, 0o600, 64)
        try:
            watchdog_pid = int(raw.decode("ascii").strip())
        except Exception:
            fail("WATCHDOG_RECORD_INVALID")
        if watchdog_pid != os.getpid():
            try:
                proc_stat = open("/proc/" + str(watchdog_pid) + "/stat", "rt", encoding="ascii").read()
                state = proc_stat.rsplit(") ", 1)[1].split(" ", 1)[0]
                if state == "Z":
                    cmd, cwd = None, None
                else:
                    cmd = open("/proc/" + str(watchdog_pid) + "/cmdline", "rb").read().split(b"\0")
                    cwd = os.readlink("/proc/" + str(watchdog_pid) + "/cwd")
            except FileNotFoundError:
                cmd, cwd = None, None
            except OSError:
                fail("WATCHDOG_IDENTITY_MISMATCH")
            if cmd is not None:
                if not _watchdog_identity_matches(cmd, cwd, run_dir, meta["source_checkout"]):
                    fail("WATCHDOG_IDENTITY_MISMATCH")
                try:
                    os.kill(watchdog_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError:
                    fail("WATCHDOG_STOP_FAILED")
                for _ in range(100):
                    try:
                        os.kill(watchdog_pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    fail("WATCHDOG_STOP_FAILED")
    _assert_no_window_processes(run_dir, os.getpid())
    sudo_status = _sudoers_remove(active)
    expiry_seen = "NO"
    if os.path.lexists(expired_receipt):
        raw_expired, _ = _read_regular(expired_receipt, 0, 0o600, 2048)
        expiry_seen = "YES" if raw_expired.startswith(b"STATUS=EXPIRED\n") else "NO"
    bootstrap_status = "ABSENT"
    if os.path.lexists(BOOTSTRAP):
        bootstrap_raw, _ = _read_regular(BOOTSTRAP, 0, 0o600, 65536)
        if hashlib.sha256(bootstrap_raw).hexdigest() != meta["bootstrap_sha256"]:
            fail("BOOTSTRAP_DRIFT")
        os.unlink(BOOTSTRAP)
        bootstrap_status = "REMOVED"
    host_config_absent = not os.path.lexists("/etc/lab-fixture-digest")
    host_snapshots = _host_snapshots()
    snapshot_status = "UNCHANGED" if host_snapshots == meta["host_snapshots"] else "DRIFT"
    closed_path = os.path.join(RUN_BASE, active["run_name"] + ".closed.json")
    closed = {
        "schema_version": 1, "run_name": active["run_name"], "run_dir": run_dir,
        "source_checkout": meta["source_checkout"], "source_commit": meta["source_commit"],
        "operator_uid": meta["operator_uid"],
        "host_mnt_ns": meta["host_mnt_ns"], "host_net_ns": meta["host_net_ns"],
        "stage_script_sha256": meta["stage_script_sha256"],
        "sudoers_path": active["sudoers_path"], "sudoers_sha256": active["sudoers_sha256"],
        "deadline": meta["deadline"], "host_snapshots": meta["host_snapshots"],
        "sudoers_status": sudo_status, "bootstrap_status": bootstrap_status,
        "host_config_absent": host_config_absent, "host_snapshot_status": snapshot_status,
        "automatic_expiry": expiry_seen, "field_completed": field_complete,
        "review_completed": review_complete, "seat_status": seat_status,
    }
    _write_new(closed_path, json.dumps(closed, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    os.unlink(ACTIVE)
    _safe_remove_tree(run_dir, active["run_name"], allow_incomplete=expired)
    _best_effort_remove(expired_receipt)
    print("STATUS=CLOSED")
    print("SUDOERS=" + sudo_status)
    print("BOOTSTRAP=" + bootstrap_status)
    print("HOST_CONFIG_PATH=" + ("ABSENT" if host_config_absent else "PRESENT"))
    print("HOST_DIRECTORY_BASELINES=" + snapshot_status)
    print("SEATS=" + seat_status)
    print("RUN_DIRECTORY=ABSENT")
    print("ACTIVE_POINTER=ABSENT")
    print("INDEPENDENT_READBACK=REQUIRED path=" + closed_path)
    return 0


def _assert_no_window_processes(run_dir, self_pid):
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == self_pid:
            continue
        base = "/proc/" + name
        try:
            raw = open(base + "/cmdline", "rb").read()
            cwd = os.readlink(base + "/cwd")
        except OSError:
            continue
        if run_dir.encode() in raw or cwd == run_dir or cwd.startswith(run_dir + "/"):
            # The watchdog is stopped before this check. Any other process
            # still rooted in the temporary session blocks removal.
            fail("WINDOW_PROCESS_ACTIVE")


def _watchdog_identity_matches(cmd, cwd, run_dir, source_checkout):
    expected = [b"/usr/bin/python3", b"-IB",
                os.path.join(run_dir, "stage-window.py").encode("utf-8"), b"watchdog"]
    return cmd == expected and cwd == source_checkout


def _readback():
    _check_root()
    run_st = os.lstat(RUN_BASE)
    if not stat.S_ISDIR(run_st.st_mode) or stat.S_ISLNK(run_st.st_mode) or os.path.realpath(RUN_BASE) != RUN_BASE or run_st.st_uid != 0:
        fail("RUN_DIRECTORY")
    candidates = sorted(name for name in os.listdir(RUN_BASE)
                        if RUN_NAME.fullmatch(name[:-12]) and name.endswith(".closed.json"))
    if len(candidates) != 1:
        fail("CLOSED_RECEIPT_COUNT")
    path = os.path.join(RUN_BASE, candidates[0])
    blob, _ = _read_regular(path, 0, 0o600, 16384)
    closed = _json_exact(blob, {"schema_version", "run_name", "run_dir", "source_checkout", "source_commit",
        "operator_uid", "host_mnt_ns", "host_net_ns", "stage_script_sha256", "sudoers_path", "sudoers_sha256", "deadline",
                                "host_snapshots", "sudoers_status", "bootstrap_status", "host_config_absent",
                                "host_snapshot_status", "automatic_expiry", "field_completed",
                                "review_completed", "seat_status"}, "CLOSED_RECORD_INVALID")
    if (closed["schema_version"] != 1 or not RUN_NAME.fullmatch(closed["run_name"]) or
            closed["run_dir"] != os.path.join(RUN_BASE, closed["run_name"]) or
            closed["sudoers_path"] != os.path.join(SUDOERS_DIR, closed["run_name"]) or
            not SOURCE_PATH.fullmatch(closed["source_checkout"])):
        fail("CLOSED_RECORD_INVALID")
    if candidates[0] != closed["run_name"] + ".closed.json":
        fail("CLOSED_RECORD_INVALID")
    if (type(closed["field_completed"]) is not bool or type(closed["review_completed"]) is not bool or
            closed["seat_status"] not in ("COMPLETE", "INCOMPLETE") or
            closed["seat_status"] != ("COMPLETE" if closed["field_completed"] and closed["review_completed"] else "INCOMPLETE")):
        fail("CLOSED_RECORD_INVALID")
    if (not isinstance(closed["host_snapshots"], dict) or
            set(closed["host_snapshots"]) != {"/usr/local/sbin", "/etc/sudoers.d", "/run/systemd", "/run/dbus"} or
            any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in closed["host_snapshots"].values()) or
            type(closed["operator_uid"]) is not int or closed["operator_uid"] <= 0):
        fail("CLOSED_RECORD_INVALID")
    if (os.readlink("/proc/self/ns/mnt") != closed["host_mnt_ns"] or
            os.readlink("/proc/self/ns/net") != closed["host_net_ns"]):
        fail("READBACK_NAMESPACE")
    if os.path.lexists(ACTIVE) or os.path.lexists(BOOTSTRAP):
        fail("CLOSE_READBACK_FAILED")
    if os.path.lexists(closed["run_dir"]):
        _safe_remove_tree(closed["run_dir"], closed["run_name"])
    if os.path.lexists(closed["run_dir"]):
        fail("CLOSE_READBACK_FAILED")
    if os.path.lexists(closed["sudoers_path"]):
        fail("CLOSE_READBACK_FAILED")
    if os.path.lexists("/etc/lab-fixture-digest"):
        fail("CLOSE_READBACK_FAILED")
    if _host_snapshots() != closed["host_snapshots"] or closed["host_snapshot_status"] != "UNCHANGED":
        fail("HOST_PATH_DRIFT")
    if not closed["host_config_absent"] or closed["bootstrap_status"] != "ABSENT" or closed["sudoers_status"] not in ("REMOVED_AND_VALIDATED", "ALREADY_ABSENT"):
        fail("CLOSE_READBACK_FAILED")
    try:
        result = subprocess.run(["/usr/sbin/visudo", "-c", "-q"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                                timeout=8, check=False)
    except Exception:
        fail("VISUDO_UNAVAILABLE")
    if result.returncode:
        fail("VISUDO_READBACK_FAILED")
    if _mounts_for_run(closed["run_dir"]):
        fail("MOUNT_READBACK_FAILED")
    _assert_no_window_processes(closed["run_dir"], os.getpid())
    verify_source(closed["source_checkout"], closed["source_commit"], closed["operator_uid"])
    expected_stage_script = os.path.join(closed["source_checkout"], "ops", "lab-g3-archive-a", "stage-window.py")
    if SCRIPT != expected_stage_script or _file_sha256(expected_stage_script) != closed["stage_script_sha256"]:
        fail("STAGE_SCRIPT_HASH")
    checkout_status = _remove_checkout(closed["source_checkout"], closed["source_commit"], closed["operator_uid"])
    os.unlink(path)
    readback_status = "READBACK_PASS" if closed["seat_status"] == "COMPLETE" else "READBACK_INCOMPLETE"
    print("STATUS=" + readback_status)
    print("SUDOERS=ABSENT_AND_VISUDO_VALID")
    print("ACTIVE_BOOTSTRAP_STAGE=ABSENT")
    print("HOST_CONFIG_PATH=ABSENT")
    print("HOST_DIRECTORY_BASELINES=UNCHANGED")
    print("MOUNT_NAMESPACE_RESIDUE=ABSENT")
    print("SEATS=" + closed["seat_status"])
    print("CHECKOUT=" + checkout_status)
    print("CLOSED_RECORD=REMOVED")
    return 0 if closed["seat_status"] == "COMPLETE" else 3


def _mounts_for_run(run_dir):
    try:
        with open("/proc/self/mountinfo", "rt", encoding="ascii") as f:
            lines = f.readlines()
    except OSError:
        fail("MOUNTINFO_UNAVAILABLE")
    prefix = run_dir.replace(" ", "\\040")
    return any(len(row.split()) > 4 and (row.split()[4] == prefix or row.split()[4].startswith(prefix + "/"))
               for row in lines)


def _best_effort_remove(path):
    try:
        if os.path.lexists(path) and stat.S_ISREG(os.lstat(path).st_mode):
            os.unlink(path)
    except OSError:
        pass


def _best_effort_stop_watchdog(run_dir):
    try:
        raw, _ = _read_regular(os.path.join(run_dir, "watchdog.pid"), 0, 0o600, 64)
        pid = int(raw.decode("ascii").strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
    except Exception:
        pass


def _best_effort_remove_tree(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
    except OSError:
        pass


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                       "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        if argv == ["prepare"]:
            return _prepare()
        if len(argv) == 2 and argv[0] == "entry":
            return _entry(argv[1])
        if len(argv) == 2 and argv[0] == "inner":
            return _inner(argv[1])
        if argv == ["watchdog"]:
            return _watchdog()
        if argv == ["close"]:
            return _close()
        if argv == ["readback"]:
            return _readback()
        print("STATUS=FAIL CATEGORY=ARGUMENTS")
        return 2
    except Refusal as exc:
        print("STATUS=FAIL CATEGORY=" + exc.category)
        return 1
    except Exception:
        print("STATUS=FAIL CATEGORY=INTERNAL")
        return 1


def _watchdog():
    _check_root()
    active = _active_read()
    run_dir = active["run_dir"]
    if os.getcwd() != active["source_checkout"]:
        fail("WATCHDOG_IDENTITY_MISMATCH")
    watchdog_path = os.path.join(run_dir, "watchdog.pid")
    if os.path.lexists(watchdog_path):
        fail("WATCHDOG_RECORD_EXISTS")
    _write_new(watchdog_path, str(os.getpid()) + "\n", 0o600)
    while int(time.time()) < active["deadline"]:
        time.sleep(min(1.0, max(0.05, active["deadline"] - time.time())))
    _expire_window()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
