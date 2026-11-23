# CoNET Lab Fixture Digest

This Linux helper records SHA-256 digests and filesystem metadata from a
synthetic CoNET Lab fixture. It validates the selected V2 ledger generation
before and after collection and emits a receipt only if the two observations
agree. It does not modify the fixture or run a migration.

## Local tests

```sh
python3 -B -m unittest discover -s tests -v
```

The tests create disposable synthetic fixtures. Running the production-layout
command requires separate host authorization.

## Host installation

1. Fetch the reviewed Git commit on the target Linux host and verify its full
   commit ID and the helper's SHA-256. Install `assets/lab-g3-fixture-summary.py` as the
   root-owned `/usr/local/sbin/lab-fixture-digest`. The executable, configuration,
   and their parent directories must not be writable by the invoking accounts.
2. Create the root-owned, mode `0600` configuration at
   `/etc/lab-fixture-digest/g3.json`. Keep the configuration and actual receipts
   outside this repository. The schema contains these fields.

   | Field | Value |
   | --- | --- |
   | `schema_version` | Tool configuration schema revision |
   | `fixture_root` | Approved synthetic fixture directory under `/var/tmp` |
   | `v2_manifest_sha256` | Reviewed SHA-256 of the V2 manifest |
   | `v2_selected_tree_sha256` | Reviewed digest of the selected V2 tree |
   | `v2_generation` | Reviewed current V2 generation |
   | `v2_previous_generation` | Reviewed previous V2 generation |
   | `archive_manifest_sha256` | Reviewed SHA-256 of the archived V3 manifest |
   | `archive_wal_sha256` | Reviewed SHA-256 of the archived V3 WAL |
   | `valid_until_epoch` | Receipt deadline as Unix time in UTC seconds |

3. Authorize only the fixed, argument-free command through the site's existing
   access process. Collect the operator and independent reviewer receipts
   separately and retire the temporary access after collection.

The receipt describes what can be reproduced at collection time. Historical
archive provenance requires an independently recorded historical reference.
