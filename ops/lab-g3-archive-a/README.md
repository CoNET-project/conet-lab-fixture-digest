# Lab G3 archive A short window

This is a temporary, read-only staging controller. It does not run the
candidate, fault runners, reset scripts, or service commands. The operator
workflow relies on the existing administrator identity; the exact temporary
sudoers entries are a workflow restriction and do not reduce that identity's
other permissions.

## Inputs

`prepare` accepts no command-line data. It reads only the root-owned mode-0600
bootstrap at `/run/lab-g3-archive-a-bootstrap.json`. The bootstrap schema is
implemented in `stage-window.py`; it binds the GitHub checkout commit, this
script's SHA256, the two published helper pins, a root-owned operator name,
the V2 and archived V3/WAL anchors, a fixed synthetic fixture root, the four
input SHA256 values from the currently approved dual-read baseline, and a
`valid_until_epoch` no more than 900 seconds away. The four hashes remain in
the root-only bootstrap and session metadata; they are not added to the
published helper's strict configuration schema.

## Staging and read entries

The administrator runs `stage-window.py prepare` from the clean GitHub
checkout matching the bootstrap commit. It verifies the two helper hashes,
checkout ownership and state (fixed read-only Git queries run as the verified
checkout owner with a clean environment, without `safe.directory`), private
bootstrap metadata, absent host config path, and
sudoers directory before creating anything. It creates one uniquely named
root-owned `/run/lab-g3-archive-a-*` tree and one exact sudoers drop-in for
the no-argument `field` and `review` entrypoints. The entrypoints are
one-shot, each with a distinct exclusive marker.

Each entrypoint uses a fresh private mount and network namespace. It overlays
`/etc` with a private upper layer under a namespace-local tmpfs, so the helper
config is never created in the host `/etc`; it masks `/usr/local/sbin`,
`/run/systemd`, and `/run/dbus` inside that namespace. The network namespace
has no external interface or default route. It executes, in order, the
pinned source summary, the pinned archive-only summary, and the source
summary again. Only V2 plus the four fixed input metadata/hash rows are
retained from each source summary, and the two selected anchor sets must be
identical. The archive-only output is kept in its own marked section for the
control-plane comparator. Any failed stage returns a fixed category without
printing helper stderr or configuration contents.

Each seat is one-shot. A successful entry writes a root-owned mode-0600
completion marker only after the full pre-anchor/archive/post-anchor output has
passed parsing and has been flushed. Normal close requires valid started and
completion markers for both `field` and `review`; it refuses an early close if
either seat is missing or failed. After expiry, close may revoke the rule and
clean the session despite absent or malformed marker contents, but unsafe
marker node metadata still blocks cleanup. It records `SEATS=INCOMPLETE`;
independent readback reports `READBACK_INCOMPLETE` with a nonzero status. The
two SSH seats capture their own
output once. The control-plane comparator
must receive only the `BEGIN_ARCHIVE_ONLY` section; it separately compares
the pre/post source anchor sections to the signed current baseline. The
archive helper does not attest the V2 or four input rows.

## Deadline and close

The helper and entry wrapper check the fixed expiry. A root watchdog removes
the exact sudoers drop-in at expiry. The watchdog is exec'd as the fixed
`stage-window.py watchdog` command from the verified checkout directory, so
its recorded process identity matches the close check. A failed read entry
may relay only one strict fixed-format `STATUS=FAIL CATEGORY=...` token from
the inner controller; arbitrary helper output is discarded. `close` stops that watchdog, verifies
and removes only the exact installed rule, validates sudoers, removes only
the temporary staging tree, and leaves a small root-only close record plus
the clean GitHub checkout for independent review. A second administrator
invokes `readback`; it independently checks the exact rule is absent,
`visudo` remains valid, the bootstrap/active/staging paths are absent, the
host config path is absent, mountinfo has no staging residue, and the host
helper/sudoers/systemd/dbus directory baselines match. Only after that
check does it remove the close record and the exact clean checkout.

If the host reboots during the window, `/run` disappears and the exact
sudoers command path becomes unavailable; the sudoers line itself may remain
until an administrator performs the exact close/readback cleanup. This
controller does not claim persistent reboot-time cleanup.

No production source, service, ledger, socket, or RPC is part of this window.
The local synthetic suite covers schema/deadline/path validation, exact
no-argument rules, anchor semantics, and rejection cases. Namespace/mount,
sudoers installation, and cleanup must be reviewed against the host gate
before a real staging window is opened.
