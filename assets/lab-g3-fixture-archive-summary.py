#!/usr/bin/python3 -IB
"""Fixed-path, read-only archive-only Lab G3 summary; Linux only."""
import datetime
import hashlib
import os
import re
import stat
import sys
import types

ENGINE_PATH = "/usr/local/sbin/lab-fixture-digest"
ENGINE_SHA256 = "5e63f874d0a55e3192ec576a4ba100969ef959511970028939e368db641cfe0e"
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_ENGINE_SIZE = 2 * 1024 * 1024


class Refusal(Exception):
    def __init__(self, category):
        self.category = category


def _fail(category):
    raise Refusal(category)


def _meta(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _open_abs_dir(path):
    if not path.startswith("/") or ".." in path.split("/"):
        _fail("ENGINE_PATH_REFUSED")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("/", flags)
    try:
        for name in (part for part in path.split("/") if part):
            if name in (".", "..") or not SAFE_NAME.fullmatch(name):
                _fail("ENGINE_PATH_REFUSED")
            nxt = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            _fail("ENGINE_PATH_REFUSED")
        return fd
    except Refusal:
        os.close(fd)
        raise
    except OSError:
        os.close(fd)
        _fail("ENGINE_PATH_REFUSED")


def _compile_engine(source, digest):
    if digest != ENGINE_SHA256:
        _fail("ENGINE_HASH_MISMATCH")
    engine = types.ModuleType("_lab_g3_pinned_fixture_summary")
    engine.__file__ = ENGINE_PATH
    exec(compile(source, ENGINE_PATH, "exec", dont_inherit=True), engine.__dict__)
    return engine


def _load_engine():
    if not sys.platform.startswith("linux"):
        _fail("PLATFORM_UNSUPPORTED")
    parent_path, name = os.path.split(ENGINE_PATH)
    parent = _open_abs_dir(parent_path)
    try:
        pst = os.fstat(parent)
        if (pst.st_uid != 0 or pst.st_gid != 0 or stat.S_IMODE(pst.st_mode) & 0o022):
            _fail("ENGINE_PERMISSIONS")
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError:
            _fail("ENGINE_PATH_REFUSED")
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022):
            _fail("ENGINE_PERMISSIONS")
        flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOATIME", 0))
        try:
            fd = os.open(name, flags, dir_fd=parent)
        except OSError:
            _fail("ENGINE_PATH_REFUSED")
        try:
            opened = os.fstat(fd)
            if _meta(before) != _meta(opened) or opened.st_size > MAX_ENGINE_SIZE:
                _fail("ENGINE_DRIFT")
            chunks = []
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ENGINE_SIZE:
                    _fail("ENGINE_SIZE")
                digest.update(chunk)
                chunks.append(chunk)
            after = os.fstat(fd)
            try:
                path_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError:
                _fail("ENGINE_DRIFT")
            if _meta(opened) != _meta(after) or _meta(after) != _meta(path_after) or total != after.st_size:
                _fail("ENGINE_DRIFT")
            parent_now = _open_abs_dir(parent_path)
            try:
                if _meta(pst) != _meta(os.fstat(parent_now)):
                    _fail("ENGINE_DRIFT")
            finally:
                os.close(parent_now)
            source = b"".join(chunks)
            return _compile_engine(source, digest.hexdigest())
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _archive_pass(engine, fixture_path, policy):
    root_fd = engine._open_abs_dir(fixture_path)
    try:
        root_meta = engine._meta(os.fstat(root_fd))
        root_mount = engine._mount_id(root_fd)
        archive = engine._archive_summary(root_fd, policy)
        current = engine._open_abs_dir(fixture_path)
        try:
            if (engine._meta(os.fstat(current)) != root_meta or
                    engine._mount_id(current) != root_mount):
                engine._fail("PATH_DRIFT")
        finally:
            os.close(current)
        return {"root_meta": root_meta, "root_mount_id": root_mount, "archive": archive}
    finally:
        os.close(root_fd)


def summarize_archive_for_test(engine, fixture_path, policy, after_first_pass=None):
    """Synthetic-only injection point. Production CLI accepts no paths or policy."""
    first = _archive_pass(engine, fixture_path, policy)
    if after_first_pass is not None:
        after_first_pass()
    second = _archive_pass(engine, fixture_path, policy)
    if first != second:
        _fail("SNAPSHOT_DRIFT")
    return second


def _print_archive(config_sha, result, started, ended):
    archive = result["archive"]
    root = archive["root_meta"]
    print("STATUS=PASS")
    print("START_UTC=" + started)
    print("END_UTC=" + ended)
    print("CONFIG=PASS sha256=" + config_sha)
    print("ARCHIVE type=directory path=attempt8-pre-fault-replay-archive sha256=- uid=%d gid=%d mode=%04o top_level_exact=PASS files=%d entries=%d aggregate_sha256=%s" % (
        root[4], root[5], stat.S_IMODE(root[2]), archive["file_count"], archive["entry_count"], archive["aggregate_sha256"]))
    for rel in sorted(archive["dirs"], key=lambda value: value.encode("ascii")):
        rec = archive["dirs"][rel]
        print("ARCHIVE_DIR type=directory path=%s sha256=- uid=%d gid=%d mode=%04o" % (
            rel, rec["uid"], rec["gid"], rec["mode"]))
    for rel in sorted(archive["files"], key=lambda value: value.encode("ascii")):
        rec = archive["files"][rel]
        print("ARCHIVE_FILE type=file path=%s sha256=%s size=%d uid=%d gid=%d mode=%04o" % (
            rel, rec["sha256"], rec["size"], rec["uid"], rec["gid"], rec["mode"]))


def _run(engine_loader, now_epoch=None):
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        engine = engine_loader()
        config, config_sha, config_meta = engine._load_private_config()
        engine._check_expiry(config, now_epoch)
        first = _archive_pass(engine, config["fixture_root"], config)
        config2, config_sha2, config_meta2 = engine._load_private_config()
        engine._check_expiry(config2, now_epoch)
        second = _archive_pass(engine, config2["fixture_root"], config2)
        if config != config2 or config_sha != config_sha2 or config_meta != config_meta2:
            engine._fail("CONFIG_DRIFT")
        if first != second:
            engine._fail("SNAPSHOT_DRIFT")
        ended = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        engine._check_expiry(config2, now_epoch)
        _print_archive(config_sha2, second, started, ended)
        return 0
    except Exception as exc:
        category = getattr(exc, "category", None)
        if not isinstance(category, str) or not re.fullmatch(r"[A-Z0-9_]{1,64}", category):
            category = "INTERNAL"
        print("STATUS=FAIL CATEGORY=" + category)
        return 1


def main():
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                       "PYTHONDONTWRITEBYTECODE": "1"})
    if len(sys.argv) != 1:
        print("STATUS=FAIL CATEGORY=ARGUMENTS")
        return 2
    return _run(_load_engine)


if __name__ == "__main__":
    raise SystemExit(main())
