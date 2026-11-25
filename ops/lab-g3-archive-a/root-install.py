#!/usr/bin/python3 -IB
"""One-shot root-only installer for the A-window entry loader.

The caller must itself be a separately approved, hash-pinned root control
plane. This file is treated as data by that control plane, never executed
from the peter-owned checkout path.
"""
import hashlib
import json
import os
import pwd
import re
import stat
import time

SPEC_PATH = "/run/lab-g3-archive-a-install.json"
RUN_DIR = "/run"
SOURCE_PATH = re.compile(r"^/var/tmp/lab-archive-a-src\.[A-Za-z0-9]{8}$")
ENTRY_PATH = re.compile(r"^/run/lab-g3-archive-a-loader-[0-9a-f]{12}\.py$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SOURCE_REL = ("ops", "lab-g3-archive-a", "root-entry.py")
MAX_SPEC = 8192
MAX_ENTRY = 1024 * 1024
MAX_RECEIPT = 4096
ROOT_UID = 0
ROOT_GID = 0
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refusal(Exception):
    def __init__(self, category):
        self.category = category


def refuse(category):
    raise Refusal(category)


def _json_exact(blob, keys, category):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                refuse(category)
            result[key] = value
        return result
    try:
        value = json.loads(blob.decode("utf-8"), object_pairs_hook=unique)
    except Refusal:
        raise
    except Exception:
        refuse(category)
    if not isinstance(value, dict) or set(value) != keys:
        refuse(category)
    return value


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _read_fd(fd, limit, category):
    chunks = []
    size = 0
    while True:
        part = os.read(fd, 65536)
        if not part:
            return b"".join(chunks)
        size += len(part)
        if size > limit:
            refuse(category)
        chunks.append(part)


def _read_fixed_root_file(path, mode, limit):
    fd = os.open(path, O_FILE | getattr(os, "O_NOATIME", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != ROOT_UID or
                before.st_gid != ROOT_GID or stat.S_IMODE(before.st_mode) != mode or
                before.st_nlink != 1 or before.st_size > limit):
            refuse("SPEC_METADATA")
        blob = _read_fd(fd, limit, "SPEC_SIZE")
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(current):
            refuse("SPEC_DRIFT")
        return blob, before
    finally:
        os.close(fd)


def _write_install_artifact(name, data, final_mode, limit):
    """Create or resume an exact artifact; only an exact byte prefix is resumable."""
    if (not isinstance(name, str) or "/" in name or name in ("", ".", "..") or
            not isinstance(data, bytes) or not data or len(data) > limit):
        refuse("INSTALL_ARTIFACT_PATH")
    parent = _open_absolute_directory(RUN_DIR)
    fd = None
    try:
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is None:
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                             os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=parent)
            except FileExistsError:
                refuse("INSTALL_ARTIFACT_RACE")
            os.fchown(fd, ROOT_UID, ROOT_GID)
            os.fchmod(fd, 0o600)
            current = os.fstat(fd)
            if (not stat.S_ISREG(current.st_mode) or current.st_uid != ROOT_UID or
                    current.st_gid != ROOT_GID or current.st_nlink != 1 or
                    stat.S_IMODE(current.st_mode) != 0o600):
                refuse("INSTALL_ARTIFACT_METADATA")
            existing = b""
        else:
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != ROOT_UID or
                    before.st_gid != ROOT_GID or stat.S_IMODE(before.st_mode) not in (0o600, final_mode) or
                    before.st_nlink != 1 or before.st_size > len(data)):
                refuse("INSTALL_ARTIFACT_METADATA")
            fd = os.open(name, os.O_RDONLY | O_FILE, dir_fd=parent)
            opened = os.fstat(fd)
            if _identity(before) != _identity(opened):
                refuse("INSTALL_ARTIFACT_DRIFT")
            existing = _read_fd(fd, limit, "INSTALL_ARTIFACT_SIZE")
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(opened) != _identity(after) or _identity(after) != _identity(current):
                refuse("INSTALL_ARTIFACT_DRIFT")
            if not data.startswith(existing):
                refuse("INSTALL_ARTIFACT_CONTENT")
            if existing == data and stat.S_IMODE(after.st_mode) == final_mode:
                os.fsync(parent)
                return hashlib.sha256(data).hexdigest()
            if stat.S_IMODE(after.st_mode) != 0o600:
                refuse("INSTALL_ARTIFACT_MODE")
            os.close(fd)
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            if _identity(after) != _identity(os.fstat(fd)):
                refuse("INSTALL_ARTIFACT_DRIFT")
        os.lseek(fd, len(existing), os.SEEK_SET)
        view = memoryview(data[len(existing):])
        while view:
            written = os.write(fd, view)
            if written <= 0:
                refuse("INSTALL_ARTIFACT_WRITE")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, final_mode)
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        result = _read_fd(fd, limit, "INSTALL_ARTIFACT_SIZE")
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (result != data or after.st_uid != ROOT_UID or after.st_gid != ROOT_GID or
                stat.S_IMODE(after.st_mode) != final_mode or after.st_nlink != 1 or
                _identity(after) != _identity(current)):
            refuse("INSTALL_ARTIFACT_READBACK")
        os.fsync(parent)
        return hashlib.sha256(result).hexdigest()
    except Refusal:
        raise
    except OSError:
        refuse("INSTALL_ARTIFACT_WRITE")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _consume_spec(raw, original_stat):
    parent = _open_absolute_directory(RUN_DIR)
    name = os.path.basename(SPEC_PATH)
    try:
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            refuse("SPEC_REMOVE_MISSING")
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != ROOT_UID or
                before.st_gid != ROOT_GID or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_nlink != 1 or _identity(before) != _identity(original_stat)):
            refuse("SPEC_REMOVE_DRIFT")
        fd = os.open(name, O_FILE | getattr(os, "O_NOATIME", 0), dir_fd=parent)
        try:
            opened = os.fstat(fd)
            data = _read_fd(fd, MAX_SPEC, "SPEC_SIZE")
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (_identity(before) != _identity(opened) or _identity(opened) != _identity(after) or
                    _identity(after) != _identity(current) or data != raw):
                refuse("SPEC_REMOVE_DRIFT")
        finally:
            os.close(fd)
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
        if os.path.lexists(SPEC_PATH):
            refuse("SPEC_REMOVE_READBACK")
    except Refusal:
        raise
    except OSError:
        refuse("SPEC_REMOVE")
    finally:
        os.close(parent)


def _open_absolute_directory(path):
    if not isinstance(path, str) or not path.startswith("/") or path == "/":
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


def _read_source_entry(checkout, uid, gid, expected_sha):
    if not SOURCE_PATH.fullmatch(checkout) or not HEX64.fullmatch(expected_sha):
        refuse("SOURCE_BINDING")
    rootfd = _open_absolute_directory(checkout)
    try:
        root = os.fstat(rootfd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != uid or root.st_gid != gid or
                stat.S_IMODE(root.st_mode) != 0o700):
            refuse("SOURCE_DIRECTORY")
        dfd = os.dup(rootfd)
        try:
            for component in SOURCE_REL[:-1]:
                child = os.open(component, O_DIR, dir_fd=dfd)
                os.close(dfd)
                dfd = child
            name = SOURCE_REL[-1]
            before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                    before.st_nlink != 1 or before.st_size <= 0 or before.st_size > MAX_ENTRY or
                    stat.S_IMODE(before.st_mode) & 0o022):
                refuse("SOURCE_FILE")
            fd = os.open(name, O_FILE | getattr(os, "O_NOATIME", 0), dir_fd=dfd)
            try:
                opened = os.fstat(fd)
                if _identity(before) != _identity(opened):
                    refuse("SOURCE_DRIFT")
                data = _read_fd(fd, MAX_ENTRY, "SOURCE_SIZE")
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
    return data


def _validate_spec(raw):
    keys = {"schema_version", "source_checkout", "source_commit", "source_uid",
            "source_gid", "entry_sha256", "destination", "valid_until_epoch"}
    obj = _json_exact(raw, keys, "SPEC_SCHEMA")
    if (type(obj["schema_version"]) is not int or obj["schema_version"] != 1 or
            not isinstance(obj["source_checkout"], str) or not SOURCE_PATH.fullmatch(obj["source_checkout"]) or
            not isinstance(obj["source_commit"], str) or not COMMIT.fullmatch(obj["source_commit"]) or
            type(obj["source_uid"]) is not int or obj["source_uid"] <= 0 or
            type(obj["source_gid"]) is not int or obj["source_gid"] < 0 or
            not isinstance(obj["entry_sha256"], str) or not HEX64.fullmatch(obj["entry_sha256"]) or
            not isinstance(obj["destination"], str) or not ENTRY_PATH.fullmatch(obj["destination"]) or
            type(obj["valid_until_epoch"]) is not int or obj["valid_until_epoch"] <= int(time.time())):
        refuse("SPEC_SCHEMA")
    try:
        owner = pwd.getpwuid(obj["source_uid"])
    except KeyError:
        refuse("SOURCE_OWNER")
    if owner.pw_gid != obj["source_gid"]:
        refuse("SOURCE_OWNER")
    return obj


def install_from_bytes(spec_raw, *, read_source=_read_source_entry, now=None):
    """Install from a separately verified root-owned spec; injectable in tests."""
    if now is None:
        now = int(time.time())
    spec = _validate_spec(spec_raw)
    if now >= spec["valid_until_epoch"]:
        refuse("WINDOW_EXPIRED")
    data = read_source(spec["source_checkout"], spec["source_uid"],
                       spec["source_gid"], spec["entry_sha256"])
    if hashlib.sha256(data).hexdigest() != spec["entry_sha256"]:
        refuse("SOURCE_HASH")
    return spec, data


def _install(spec, data, spec_sha256=None):
    if spec_sha256 is None:
        spec_sha256 = hashlib.sha256(
            (json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
    if not HEX64.fullmatch(spec_sha256):
        refuse("INSTALL_SPEC_HASH")
    dest_name = os.path.basename(spec["destination"])
    _write_install_artifact(dest_name, data, 0o500, MAX_ENTRY)
    blob, st = _read_fixed_root_file(spec["destination"], 0o500, MAX_ENTRY)
    if (hashlib.sha256(blob).hexdigest() != spec["entry_sha256"] or blob != data or
            st.st_uid != ROOT_UID or st.st_gid != ROOT_GID or st.st_nlink != 1):
        refuse("INSTALL_READBACK")
    receipt = {
        "schema_version": 2,
        "source_commit": spec["source_commit"],
        "entry_sha256": spec["entry_sha256"],
        "destination": spec["destination"],
        "spec_sha256": spec_sha256,
        "readback": "PASS",
    }
    receipt_path = spec["destination"][:-3] + ".install.json"
    raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _write_install_artifact(os.path.basename(receipt_path), raw, 0o600, MAX_RECEIPT)
    receipt_back, receipt_st = _read_fixed_root_file(receipt_path, 0o600, 4096)
    if (receipt_back != raw or receipt_st.st_nlink != 1 or
            hashlib.sha256(receipt_back).hexdigest() != hashlib.sha256(raw).hexdigest()):
        refuse("INSTALL_RECEIPT_READBACK")
    return hashlib.sha256(raw).hexdigest()


def main(argv=None):
    if argv is None:
        argv = os.sys.argv[1:]
    if os.geteuid() != ROOT_UID:
        print("STATUS=FAIL CATEGORY=ROOT_REQUIRED")
        return 1
    if argv != ["install"]:
        print("STATUS=FAIL CATEGORY=ARGUMENTS")
        return 2
    try:
        raw, spec_stat = _read_fixed_root_file(SPEC_PATH, 0o600, MAX_SPEC)
        spec, data = install_from_bytes(raw)
        receipt_sha = _install(spec, data, hashlib.sha256(raw).hexdigest())
        _consume_spec(raw, spec_stat)
        print("STATUS=ROOT_ENTRY_INSTALLED")
        print("ENTRY_SHA256=" + spec["entry_sha256"])
        print("READBACK=PASS")
        print("INSTALL_RECEIPT_SHA256=" + receipt_sha)
        return 0
    except Refusal as exc:
        print("STATUS=FAIL CATEGORY=" + exc.category)
        return 1
    except Exception:
        print("STATUS=FAIL CATEGORY=INSTALL_INTERNAL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
