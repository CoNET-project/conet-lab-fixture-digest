# Lab G3 archive A short window

This is a temporary, read-only staging controller. It does not run the
candidate, fault runners, reset scripts, or service commands. The operator
workflow relies on the existing administrator identity; the exact temporary
sudoers entries are a workflow restriction and do not reduce that identity's
other permissions.

## Privileged trust chain

`root-install.py` is not a trust root and must never be executed directly from
the operator-owned checkout merely because the checkout was fetched from
GitHub. Before the first install, a separately approved root deployment
mechanism must verify the exact release commit and `root-install.py` SHA256
against an independently reviewed release record, open that file without
following links, hash the bytes read from that same file descriptor, and
execute those same bytes. That external mechanism is outside this repository
and must retain its own install/readback receipt. The installer then accepts
only its root-owned, mode-0600, unexpired fixed-path spec; it reads the pinned
`root-entry.py` from the clean, owner-checked checkout through directory file
descriptors, writes the entry at a unique `/run` path with exclusive creation,
and independently verifies the installed bytes, owner, mode, and link count.
This repository does not provide or pin the external first-install executor;
without a separately reviewed exact executor path, argv, source hash, and
same-file-descriptor read/verify/execute receipt, the installer is not
authorized to run.

The installer uses `/run/lab-g3-archive-a-install.json` as a one-window spec.
It consumes that exact unchanged spec only after the installed entry and its
receipt both pass readback. If interrupted before that point, retrying the
same installer with the still-present exact spec resumes only when any
existing loader or receipt is a root-owned regular file whose bytes are an
exact prefix of the expected artifact; mismatched or unsafe objects are
preserved and fail closed. The completed `<loader>.install.json` receipt is a
deterministic binding of source commit, spec digest, destination, and loader
digest. It is intentionally retained as a per-loader `/run` audit record
until reboot; it does not block a later installation because each loader path
is unique. A leftover fixed spec blocks `prepare` until the installer has
successfully resumed and consumed it. `/run` records and this retention rule
are same-boot only.

Every privileged `root-entry.py` invocation reads the installed root-owned
entry and controller from fixed paths, hashes bytes from the opened file
descriptor, and compiles/executes those same bytes. The bootstrap and source
checkout are inputs, never trust anchors. If the separately approved initial
root deployment mechanism and its verification receipt are unavailable, this
controller must not be installed or run.

## Inputs

`prepare` accepts no command-line data. It reads only the root-owned mode-0600
bootstrap at `/run/lab-g3-archive-a-bootstrap.json`. The bootstrap schema is
implemented in `stage-window.py`; it binds the GitHub checkout commit, this
script's SHA256, the two published helper pins, a root-owned operator name,
the V2 and archived V3/WAL anchors, a fixed synthetic fixture root, the four
input SHA256 values from the currently approved dual-read baseline, and a
`valid_until_epoch` no more than 900 seconds away. The four hashes remain in
the root-only bootstrap and session metadata; they are not added to the
published helper's strict configuration schema. It also binds a separately
installed root-owned `root-entry.py` path and SHA256. That fixed entry accepts
only one verb (`prepare`, `close`, `abort`, or `readback`) and no extra
arguments. It opens the pinned controller through directory file descriptors
with `O_NOFOLLOW`, hashes the bytes read from that open file, and compiles and
executes those same bytes. Calling `stage-window.py` directly cannot satisfy
the root-entry binding for privileged lifecycle verbs.

## Staging and read entries

The administrator invokes the pinned root entry with `prepare`; the entry
loads `stage-window.py` from the clean GitHub checkout matching the bootstrap
commit. It verifies the two helper hashes,
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

The two seats and lifecycle operations share `control.lock`. A seat records
its start under the lock and starts the namespace child before releasing the
lock; the child must acquire the same lock and record its process identity
before reading. The start record binds the actual child PID and `/proc` start
time. If abort has begun, a seat not yet entered is rejected before it can
read. Each seat is one-shot. A successful entry writes a root-owned mode-0600
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

## Deadline, abort, and close

The helper and entry wrapper check the fixed expiry. A root watchdog removes
the exact sudoers drop-in at expiry. Its record binds PID, `/proc` start time,
working directory, and exact argv hash. Close and abort address it only with a
pidfd after rechecking that identity; if the identity cannot be confirmed,
they preserve the run state instead of signaling a numeric PID. The watchdog is exec'd as the fixed
`stage-window.py watchdog` command from the verified checkout directory, so
its recorded process identity matches the close check. A failed read entry
may relay only one strict fixed-format `STATUS=FAIL CATEGORY=...` token from
the inner controller; arbitrary helper output is discarded. `close` requires
both seats to have completed unless the deadline has expired. It records
cleanup intent in the independent terminal journal, removes only the exact
installed rule, validates sudoers, stops the identity-bound watchdog, checks
for remaining processes and mounts, then removes bootstrap, ACTIVE, run tree,
and checkout in separately journaled steps. A second administrator invokes
`readback`; it independently checks the exact rule is absent, `visudo` remains
valid, the bootstrap/active/staging paths are absent, the host config path is
absent, mountinfo has no staging residue, and host helper/sudoers/systemd/dbus
directory baselines match. It marks the journal `READBACK_DONE` before
removing the exact root entry; the terminal journal/controller remains as a
small root-only record during this boot.

`abort` is the immediate failure path. Under the same lock it verifies the
current ACTIVE/meta digests and exact installed sudoers file, then persists an
`ABORTING` journal intent bound to the run, source, deadline, and rule hash.
It removes only that exact rule, requires `visudo` to pass and the path to be
absent, and advances the journal after each verified cleanup step. Missing or
changed rules fail before the first intent. If interrupted after intent, a
retry proceeds only from the same validated journal and phase; a reappeared
or altered rule is a hard stop. If an entry process is still active, abort
keeps the incomplete state for a later retry rather than deleting files that
process may use. Readback verifies the terminal journal, rule absence, host
baselines, processes, mounts, and pinned checkout. It reports
`READBACK_INCOMPLETE` with a nonzero status when either seat did not complete.

Close, abort, and expiry use a root-owned terminal journal and controller
stored separately from ACTIVE, bootstrap, the temporary run tree, checkout,
and installed entry. The journal records intent before each destructive
phase and a completed phase only after readback; a retry resumes from the
last durable phase under the terminal lock. A pending journal blocks another
prepare. After all removals and host baseline checks pass, readback records
`READBACK_DONE`, removes the root entry last, and retains this root-only
readback record. It is intentionally stored under `/run`: recovery and this
retained record are valid only during the same host boot. A reboot clears the
journal; the design does not claim reboot-persistent recovery.

If the host reboots during the window, `/run` disappears and the exact
sudoers command path becomes unavailable; the sudoers line itself may remain
until an administrator performs the exact close/readback cleanup. This
controller does not claim persistent reboot-time cleanup.

No production source, service, ledger, socket, or RPC is part of this window.
The local synthetic suite covers schema/deadline/path validation, exact
no-argument rules, anchor semantics, installer/root-loader byte pins and
readback, seat launch/abort ordering, terminal-journal creation failures,
per-phase cleanup interruption/resume/repeat, sudoers/baseline drift, abort
binding, and pidfd refusal/identity checks. It does not verify the external
first-install trust mechanism, real sudoers installation, a live Linux pidfd,
namespace/mount, watchdog, or host cleanup. Those still require a separately
authorized host staging gate; this change alone does not authorize it.
