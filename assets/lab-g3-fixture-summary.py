#!/usr/bin/python3 -IB
"""Fixed-path, read-only Lab G3 synthetic fixture summary; Linux only."""
import datetime
import hashlib
import json
import os
import re
import stat
import sys

CONFIG_PATH = "/etc/lab-fixture-digest/g3.json"
CONFIG_DIR, CONFIG_NAME = os.path.split(CONFIG_PATH)
FIXTURE_ROOT_RE = re.compile(r"^/var/tmp/lab-g3-synth-[A-Za-z0-9T-]+-[a-f0-9]{6}$")
INPUTS = ("site.env", "env/env0", "env/d6.env", "deny.json")
ARCHIVE = "attempt8-pre-fault-replay-archive"
ARCHIVE_ROOT_SET = {
    "control-attempt8", "cp-mount-empty-attempt8", "dispatcher.calls-attempt8",
    "dispatcher.denied-attempt8", "dropins-attempt8", "root-dispatcher-positive-attempt8.py",
    "startup-journal-attempt8.log", "state-v3-attempt8", "state-v3-attempt8-live",
    "systemctl-positive-attempt8", "systemctl.calls-attempt8", "systemctl.mutations-attempt8",
    "window-attempt8",
}
ARCHIVE_REQUIRED_WINDOW = {
    "S1-DATA.env", "S1-OK", "g3-cutover.log", "stop-fingerprint.txt", "m_pre.json",
    "m_stop.json", "full-stop.stdout", "full-swap-start.stdout", "pre-wal-copy.sha256",
    "pre-wal-source.sha256", "digests-copy.txt",
}
CONFIG_KEYS = {
    "schema_version", "fixture_root", "v2_manifest_sha256", "v2_selected_tree_sha256",
    "v2_generation", "v2_previous_generation", "archive_manifest_sha256", "archive_wal_sha256",
    "valid_until_epoch",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENERATION = re.compile(r"^gen-\d{8}T\d{6}Z-[0-9a-f]{12}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class Refusal(Exception):
    def __init__(self, category):
        self.category = category


def _fail(category):
    raise Refusal(category)


def _meta(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _mount_id(fd):
    """Linux mount ID from this process's own fdinfo; no pathname traversal."""
    try:
        with open("/proc/self/fdinfo/" + str(fd), "rb", buffering=0) as f:
            for line in f:
                if line.startswith(b"mnt_id:"):
                    return int(line.split(b":", 1)[1].strip())
    except (OSError, ValueError):
        pass
    _fail("MOUNT_ID_UNAVAILABLE")


def _dir_flags():
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags():
    return (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) |
            (getattr(os, "O_NOATIME", 0) if sys.platform.startswith("linux") else 0))


def _open_abs_dir(path):
    if not path.startswith("/") or ".." in path.split("/"):
        _fail("PATH_POLICY")
    fd = os.open("/", _dir_flags())
    try:
        for component in (p for p in path.split("/") if p):
            if component in (".", "..") or not SAFE_NAME.fullmatch(component):
                _fail("PATH_POLICY")
            nxt = os.open(component, _dir_flags(), dir_fd=fd)
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            _fail("NODE_TYPE")
        return fd
    except Refusal:
        os.close(fd)
        raise
    except OSError:
        os.close(fd)
        _fail("PATH_REFUSED")
    except Exception:
        os.close(fd)
        raise


def _open_dir(parent_fd, name, base_mnt=None):
    if not SAFE_NAME.fullmatch(name) or name in (".", ".."):
        _fail("PATH_POLICY")
    _safe_stat_at(parent_fd, name)
    try:
        fd = os.open(name, _dir_flags() | getattr(os, "O_NOATIME", 0), dir_fd=parent_fd)
    except OSError:
        _fail("PATH_REFUSED")
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        os.close(fd)
        _fail("NODE_TYPE")
    mid = _mount_id(fd)
    if base_mnt is not None and mid != base_mnt:
        os.close(fd)
        _fail("MOUNT_BOUNDARY")
    return fd


def _open_rel_dir(root_fd, rel, base_mnt):
    fd = os.dup(root_fd)
    try:
        for name in rel.split("/"):
            nxt = _open_dir(fd, name, base_mnt)
            os.close(fd)
            fd = nxt
        return fd
    except Exception:
        os.close(fd)
        raise


def _verify_named_dir(root_fd, rel, expected_fd, base_mnt):
    current = _open_rel_dir(root_fd, rel, base_mnt)
    try:
        if _meta(os.fstat(current)) != _meta(os.fstat(expected_fd)):
            _fail("PATH_DRIFT")
        if _mount_id(current) != base_mnt:
            _fail("MOUNT_BOUNDARY")
    finally:
        os.close(current)


def _safe_stat_at(dir_fd, name):
    if not SAFE_NAME.fullmatch(name) or name in (".", ".."):
        _fail("PATH_POLICY")
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        _fail("FIXED_PATH_MISSING")
    if stat.S_ISLNK(st.st_mode):
        _fail("SYMLINK_REFUSED")
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        _fail("NODE_TYPE")
    if st.st_nlink != 1 and stat.S_ISREG(st.st_mode):
        _fail("HARDLINK_REFUSED")
    return st


def _read_file(dir_fd, name, base_mnt):
    st0 = _safe_stat_at(dir_fd, name)
    if not stat.S_ISREG(st0.st_mode):
        _fail("NODE_TYPE")
    try:
        fd = os.open(name, _file_flags(), dir_fd=dir_fd)
    except OSError:
        _fail("PATH_REFUSED")
    try:
        st1 = os.fstat(fd)
        if _meta(st0) != _meta(st1):
            _fail("PATH_DRIFT")
        if _mount_id(fd) != base_mnt:
            _fail("MOUNT_BOUNDARY")
        h = hashlib.sha256()
        chunks = []
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
            total += len(block)
            if name == "manifest.json" and total <= 1024 * 1024:
                chunks.append(block)
        st2 = os.fstat(fd)
        if _meta(st1) != _meta(st2) or total != st2.st_size:
            _fail("FILE_DRIFT")
        return {"sha256": h.hexdigest(), "size": total, "uid": st2.st_uid,
                "gid": st2.st_gid, "mode": stat.S_IMODE(st2.st_mode),
                "meta": _meta(st2), "bytes": b"".join(chunks) if name == "manifest.json" else None}
    finally:
        os.close(fd)


def _manifest(blob):
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                _fail("MANIFEST_INVALID")
            out[key] = value
        return out
    try:
        value = json.loads(blob.decode("utf-8"), object_pairs_hook=no_duplicates)
    except Refusal:
        raise
    except Exception:
        _fail("MANIFEST_INVALID")
    if not isinstance(value, dict):
        _fail("MANIFEST_INVALID")
    return value


def _safe_entries(fd):
    try:
        names = os.listdir(fd)
    except OSError:
        _fail("DIRECTORY_READ_FAILED")
    encoded = []
    for name in names:
        if not SAFE_NAME.fullmatch(name) or name in (".", ".."):
            _fail("PATH_POLICY")
        encoded.append(name)
    return sorted(encoded, key=lambda s: s.encode("ascii"))


def _walk(fd, prefix, base_mnt):
    files, dirs, entries = {}, {}, {}
    before = os.fstat(fd)
    for name in _safe_entries(fd):
        st = _safe_stat_at(fd, name)
        rel = name if not prefix else prefix + "/" + name
        if stat.S_ISDIR(st.st_mode):
            child = _open_dir(fd, name, base_mnt)
            try:
                cfiles, cdirs, centries = _walk(child, rel, base_mnt)
                dirs.update(cdirs)
                files.update(cfiles)
                entries.update(centries)
                dstat = os.fstat(child)
                if _meta(dstat) != _meta(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                    _fail("PATH_DRIFT")
                dirs[rel] = {"uid": dstat.st_uid, "gid": dstat.st_gid,
                             "mode": stat.S_IMODE(dstat.st_mode), "meta": _meta(dstat)}
                entries[rel] = "dir"
            finally:
                os.close(child)
        elif stat.S_ISREG(st.st_mode):
            rec = _read_file(fd, name, base_mnt)
            files[rel] = rec
            entries[rel] = "file"
        else:
            _fail("NODE_TYPE")
    after = os.fstat(fd)
    if _meta(before) != _meta(after):
        _fail("DIRECTORY_DRIFT")
    return files, dirs, entries


def _tree_digest(files):
    h = hashlib.sha256()
    for rel in sorted(files, key=lambda s: s.encode("ascii")):
        h.update(files[rel]["sha256"].encode("ascii") + b"  " + rel.encode("ascii") + b"\n")
    return h.hexdigest()


def _archive_digest(files, dirs):
    h = hashlib.sha256()
    names = sorted(set(files) | set(dirs), key=lambda s: s.encode("ascii"))
    for rel in names:
        if rel in dirs:
            h.update(b"D  " + rel.encode("ascii") + b"\n")
        else:
            h.update(b"F " + files[rel]["sha256"].encode("ascii") + b"  " + rel.encode("ascii") + b"\n")
    return h.hexdigest()


def _v2_snapshot(fixture_fd, policy):
    base_mnt = _mount_id(fixture_fd)
    state_fd = _open_rel_dir(fixture_fd, "state/payout-state.v2", base_mnt)
    try:
        state_before = os.fstat(state_fd)
        names = set(_safe_entries(state_fd))
        manifest_rec = _read_file(state_fd, "manifest.json", base_mnt)
        manifest = _manifest(manifest_rec["bytes"])
        generation = manifest.get("generation")
        previous = manifest.get("previousGeneration")
        if (manifest.get("version") != 2 or generation != policy["v2_generation"] or
                previous != policy["v2_previous_generation"] or
                not isinstance(generation, str) or not GENERATION.fullmatch(generation) or
                not isinstance(previous, str) or not GENERATION.fullmatch(previous) or generation == previous):
            _fail("V2_ANCHOR_MISMATCH")
        if manifest_rec["sha256"] != policy["v2_manifest_sha256"]:
            _fail("V2_ANCHOR_MISMATCH")
        try:
            os.stat("wal", dir_fd=state_fd, follow_symlinks=False)
            _fail("WAL_PRESENT")
        except FileNotFoundError:
            pass
        if names != {"manifest.json", generation, previous}:
            _fail("V2_SELECTED_SET_MISMATCH")
        files = {"manifest.json": manifest_rec}
        for dname in (generation, previous):
            dfd = _open_dir(state_fd, dname, base_mnt)
            try:
                found, _dirs, _entries = _walk(dfd, dname, base_mnt)
                files.update(found)
            finally:
                os.close(dfd)
        digest = _tree_digest(files)
        if digest != policy["v2_selected_tree_sha256"]:
            _fail("V2_ANCHOR_MISMATCH")
        if _meta(state_before) != _meta(os.fstat(state_fd)):
            _fail("V2_DRIFT")
        _verify_named_dir(fixture_fd, "state/payout-state.v2", state_fd, base_mnt)
        return {"manifest_sha256": manifest_rec["sha256"], "selected_tree_sha256": digest,
                "generation": generation, "previous_generation": previous, "file_count": len(files)}
    finally:
        os.close(state_fd)


def _fixed_input_records(fixture_fd, base_mnt):
    records = {}
    for rel in INPUTS:
        if "/" in rel:
            parent, name = rel.split("/", 1)
            pfd = _open_rel_dir(fixture_fd, parent, base_mnt)
        else:
            pfd, name = fixture_fd, rel
        try:
            dir_before = os.fstat(pfd) if pfd != fixture_fd else None
            rec = _read_file(pfd, name, base_mnt)
            records[rel] = {k: rec[k] for k in ("sha256", "size", "uid", "gid", "mode", "meta")}
            if pfd != fixture_fd:
                if _meta(dir_before) != _meta(os.fstat(pfd)):
                    _fail("INPUT_DIRECTORY_DRIFT")
                _verify_named_dir(fixture_fd, parent, pfd, base_mnt)
        finally:
            if pfd != fixture_fd:
                os.close(pfd)
    return records


def _archive_summary(fixture_fd, policy):
    base_mnt = _mount_id(fixture_fd)
    archive_fd = _open_dir(fixture_fd, ARCHIVE, base_mnt)
    try:
        archive_before = os.fstat(archive_fd)
        top_names = set(_safe_entries(archive_fd))
        if top_names != ARCHIVE_ROOT_SET:
            _fail("ARCHIVE_ENTRY_SET")
        files, dirs, entries = _walk(archive_fd, "", base_mnt)
        window_prefix = "window-attempt8/"
        window_names = {p[len(window_prefix):] for p in entries if p.startswith(window_prefix)}
        if not ARCHIVE_REQUIRED_WINDOW.issubset(window_names):
            _fail("ARCHIVE_REQUIRED_EVIDENCE_MISSING")
        pair_maps = []
        historical_generations = []
        for label in ("state-v3-attempt8", "state-v3-attempt8-live"):
            mpath = label + "/manifest.json"
            wpath = label + "/wal/wal-0000000000000001.log"
            if mpath not in files or wpath not in files:
                _fail("ARCHIVE_V3_STATE_INVALID")
            if files[mpath]["sha256"] != policy["archive_manifest_sha256"]:
                _fail("ARCHIVE_V3_STATE_INVALID")
            if files[wpath]["sha256"] != policy["archive_wal_sha256"]:
                _fail("ARCHIVE_V3_STATE_INVALID")
            wm = _manifest(files[mpath]["bytes"])
            if wm.get("version") != 3 or wm.get("walFormat") != 1:
                _fail("ARCHIVE_V3_STATE_INVALID")
            gen, prev = wm.get("generation"), wm.get("previousGeneration")
            if not isinstance(gen, str) or not GENERATION.fullmatch(gen):
                _fail("ARCHIVE_V3_STATE_INVALID")
            expected_direct = {"manifest.json", "wal"}
            if isinstance(prev, str) and GENERATION.fullmatch(prev) and prev != gen:
                expected_direct.update((gen, prev))
            else:
                _fail("ARCHIVE_V3_STATE_INVALID")
            actual_direct = {p[len(label) + 1:].split("/", 1)[0] for p in entries
                             if p.startswith(label + "/")}
            if not expected_direct.issubset(actual_direct):
                _fail("ARCHIVE_V3_STATE_INVALID")
            for name in ("wal", gen, prev):
                if entries.get(label + "/" + name) != "dir":
                    _fail("ARCHIVE_V3_STATE_INVALID")
            extras = actual_direct - expected_direct
            for name in extras:
                rel = label + "/" + name
                if not GENERATION.fullmatch(name):
                    _fail("ARCHIVE_V3_STATE_ENTRY_SET")
                if entries.get(rel) != "dir":
                    _fail("ARCHIVE_V3_HISTORICAL_GENERATION_INVALID")
                historical_generations.append(rel)
            _wal_dir_entries = {p for p in entries if p.startswith(label + "/wal/")}
            if _wal_dir_entries != {wpath}:
                _fail("ARCHIVE_V3_WAL_FILE_SET")
            subfiles = {p[len(label) + 1:]: rec["sha256"] for p, rec in files.items() if p.startswith(label + "/")}
            subdirs = {p[len(label) + 1:] for p in dirs if p.startswith(label + "/")}
            pair_maps.append((subfiles, subdirs))
        if pair_maps[0] != pair_maps[1]:
            _fail("ARCHIVE_V3_COPIES_DIFFER")
        if _meta(archive_before) != _meta(os.fstat(archive_fd)):
            _fail("ARCHIVE_DRIFT")
        _verify_named_dir(fixture_fd, ARCHIVE, archive_fd, base_mnt)
        aggregate = _archive_digest(files, dirs)
        return {"files": files, "dirs": dirs, "historical_generations": sorted(historical_generations),
                "aggregate_sha256": aggregate,
                "file_count": len(files), "entry_count": len(entries),
                "root_meta": _meta(archive_before)}
    finally:
        os.close(archive_fd)


def _strict_config_blob(config_blob):
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                _fail("CONFIG_INVALID")
            out[key] = value
        return out
    try:
        config = json.loads(config_blob.decode("utf-8"), object_pairs_hook=no_duplicates)
    except Refusal:
        raise
    except Exception:
        _fail("CONFIG_INVALID")
    if (not isinstance(config, dict) or set(config) != CONFIG_KEYS or
            type(config.get("schema_version")) is not int or config.get("schema_version") != 1):
        _fail("CONFIG_INVALID")
    if type(config.get("valid_until_epoch")) is not int or config["valid_until_epoch"] <= 0:
        _fail("CONFIG_INVALID")
    fixture = config.get("fixture_root")
    if not isinstance(fixture, str) or not FIXTURE_ROOT_RE.fullmatch(fixture):
        _fail("CONFIG_INVALID")
    for key in ("v2_manifest_sha256", "v2_selected_tree_sha256", "archive_manifest_sha256", "archive_wal_sha256"):
        if not isinstance(config.get(key), str) or not HEX64.fullmatch(config[key]):
            _fail("CONFIG_INVALID")
    for key in ("v2_generation", "v2_previous_generation"):
        if not isinstance(config.get(key), str) or not GENERATION.fullmatch(config[key]):
            _fail("CONFIG_INVALID")
    return config


def _check_config_stat(st):
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or
            stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
        _fail("CONFIG_PERMISSIONS")


def _check_config_dir_stat(st):
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        _fail("CONFIG_DIRECTORY_PERMISSIONS")


def _check_expiry(config, now_epoch=None):
    if now_epoch is None:
        now_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if type(config.get("valid_until_epoch")) is not int or now_epoch >= config["valid_until_epoch"]:
        _fail("CONFIG_EXPIRED")


def _load_private_config():
    if not sys.platform.startswith("linux"):
        _fail("PLATFORM_UNSUPPORTED")
    parent = _open_abs_dir(CONFIG_DIR)
    try:
        parent_stat = os.fstat(parent)
        _check_config_dir_stat(parent_stat)
        st_path = _safe_stat_at(parent, CONFIG_NAME)
        _check_config_stat(st_path)
        fd = os.open(CONFIG_NAME, _file_flags(), dir_fd=parent)
        try:
            st1 = os.fstat(fd)
            _check_config_stat(st1)
            if _meta(st_path) != _meta(st1):
                _fail("CONFIG_DRIFT")
            if st1.st_size > 65536:
                _fail("CONFIG_INVALID")
            h = hashlib.sha256()
            parts = []
            config_total = 0
            while True:
                b = os.read(fd, 65536)
                if not b:
                    break
                config_total += len(b)
                if config_total > 65536:
                    _fail("CONFIG_INVALID")
                h.update(b)
                parts.append(b)
            st2 = os.fstat(fd)
            try:
                st_path_after = os.stat(CONFIG_NAME, dir_fd=parent, follow_symlinks=False)
            except OSError:
                _fail("CONFIG_DRIFT")
            if _meta(st1) != _meta(st2) or _meta(st2) != _meta(st_path_after):
                _fail("CONFIG_DRIFT")
            parent_now = _open_abs_dir(CONFIG_DIR)
            try:
                if _meta(parent_stat) != _meta(os.fstat(parent_now)):
                    _fail("CONFIG_DRIFT")
            finally:
                os.close(parent_now)
            blob = b"".join(parts)
            return _strict_config_blob(blob), h.hexdigest(), _meta(st2)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _summary_pass(fixture_path, policy):
    root_fd = _open_abs_dir(fixture_path)
    try:
        root_stat = os.fstat(root_fd)
        root_mnt = _mount_id(root_fd)
        v2_before = _v2_snapshot(root_fd, policy)
        inputs = _fixed_input_records(root_fd, root_mnt)
        archive = _archive_summary(root_fd, policy)
        v2_after = _v2_snapshot(root_fd, policy)
        if v2_before != v2_after or _meta(root_stat) != _meta(os.fstat(root_fd)):
            _fail("V2_DRIFT")
        current_root = _open_abs_dir(fixture_path)
        try:
            if _meta(root_stat) != _meta(os.fstat(current_root)) or _mount_id(current_root) != root_mnt:
                _fail("PATH_DRIFT")
        finally:
            os.close(current_root)
        return {"v2": v2_after, "inputs": inputs, "archive": archive,
                "root_meta": _meta(root_stat), "root_mount_id": root_mnt}
    finally:
        os.close(root_fd)


def summarize_for_test(fixture_path, policy, after_first_pass=None):
    """Test-only injection point; production CLI never accepts paths or policy."""
    first = _summary_pass(fixture_path, policy)
    if after_first_pass is not None:
        after_first_pass()
    second = _summary_pass(fixture_path, policy)
    if first != second:
        _fail("SNAPSHOT_DRIFT")
    return second


def _print_summary(config_sha, result, started_utc, ended_utc):
    print("STATUS=PASS")
    print("START_UTC=" + started_utc)
    print("END_UTC=" + ended_utc)
    print("CONFIG=PASS sha256=" + config_sha)
    v2 = result["v2"]
    print("V2_BEFORE_AFTER=IDENTICAL version=2 generation=%s previous=%s manifest_sha256=%s selected_tree_sha256=%s files=%d WAL=ABSENT" % (
        v2["generation"], v2["previous_generation"], v2["manifest_sha256"], v2["selected_tree_sha256"], v2["file_count"]))
    for rel in INPUTS:
        rec = result["inputs"][rel]
        print("INPUT type=file path=%s sha256=%s size=%d uid=%d gid=%d mode=%04o" % (
            rel, rec["sha256"], rec["size"], rec["uid"], rec["gid"], rec["mode"]))
    arc = result["archive"]
    am = arc["root_meta"]
    print("ARCHIVE type=directory path=" + ARCHIVE + " sha256=- uid=%d gid=%d mode=%04o top_level_exact=PASS files=%d entries=%d aggregate_sha256=%s" % (
        am[4], am[5], stat.S_IMODE(am[2]), arc["file_count"], arc["entry_count"], arc["aggregate_sha256"]))
    for rel in arc["historical_generations"]:
        print("ARCHIVE_V3_HISTORICAL_GENERATION type=directory path=%s" % rel)
    for rel in sorted(arc["files"], key=lambda s: s.encode("ascii")):
        rec = arc["files"][rel]
        print("ARCHIVE_FILE type=file path=%s sha256=%s size=%d uid=%d gid=%d mode=%04o" % (
            rel, rec["sha256"], rec["size"], rec["uid"], rec["gid"], rec["mode"]))


def main():
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"})
    if len(sys.argv) != 1:
        print("STATUS=FAIL CATEGORY=ARGUMENTS")
        return 2
    config = None
    config_sha = None
    try:
        started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        config, config_sha, config_meta = _load_private_config()
        _check_expiry(config)
        first = _summary_pass(config["fixture_root"], config)
        second_config, second_config_sha, second_config_meta = _load_private_config()
        _check_expiry(second_config)
        second = _summary_pass(second_config["fixture_root"], second_config)
        if config_sha != second_config_sha or config_meta != second_config_meta or config != second_config:
            _fail("CONFIG_DRIFT")
        if first != second:
            _fail("SNAPSHOT_DRIFT")
        ended = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _check_expiry(second_config)
        _print_summary(config_sha, second, started, ended)
        return 0
    except Refusal as exc:
        print("STATUS=FAIL CATEGORY=" + exc.category)
        return 1
    except Exception:
        print("STATUS=FAIL CATEGORY=INTERNAL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
