# REUNITE AI

Local Flask/PostgreSQL disaster reunification demonstration. Similarity scores and image descriptions are review aids only; an authorized human must verify evidence and confirm an actual reunion.

## Local Windows Setup

1. Copy `.env.example` to `.env` and configure PostgreSQL credentials, `SECRET_KEY`, and officer/manager credentials.
2. Create the environment and install dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

3. Initialize the additive PostgreSQL schema and then run the app:

   ```powershell
   .\.venv\Scripts\python.exe database.py init
   .\.venv\Scripts\python.exe app.py
   ```

4. Browse to the local URL printed by Flask. Health checks are available at `/api/health` and `/api/v1/health`.

The current local `.env` enables `LOCAL_DEMO_MODE=true` for the fictional camp accounts. `camp1`, `camp2`, and `camp3` use password `123`, are stored as password hashes, and are provisioned only in this mode. The application refuses to start with demo mode enabled if `HOST` is not loopback. Set demo mode to `false` and use manager-provisioned strong accounts outside a local demonstration. Set `COOKIE_SECURE=true` behind HTTPS.

## PostgreSQL Backups

Before schema changes, create a custom-format backup and verify that the file is non-empty:

```powershell
New-Item -ItemType Directory -Force .\instance\backups
$env:PGPASSWORD = "<database password>"
pg_dump --format=custom --no-owner --no-acl --host localhost --port 5432 --username postgres --dbname reunite_ai --file .\instance\backups\reunite_ai.dump
Remove-Item Env:PGPASSWORD
```

Keep backups encrypted and access-controlled. No restore drill or retention/deletion policy is configured by this local demo.

### Non-destructive restore check

Restore into a separate scratch database first; do not use `--clean` against the live database:

```powershell
createdb --host localhost --port 5432 --username postgres reunite_ai_restore_check
pg_restore --no-owner --no-acl --host localhost --port 5432 --username postgres --dbname reunite_ai_restore_check .\instance\backups\reunite_ai.dump
```

Verify the scratch database counts before considering any rollback. A live rollback is an operator decision: stop application writes, retain the current database snapshot, and restore the chosen backup to a separate database before changing the app's `PGDATABASE`. No restore drill was performed for this work.

## Ollama Vision

The photo worker checks Ollama at `OLLAMA_HOST`, detects installed vision-capable models through `/api/tags`, and prefers `qwen2.5vl:3b` when installed. It does not download models. Photos are validated, orientation-corrected, resized, re-encoded to remove metadata, stored under `instance/private_photos`, and served only after role/camp authorization. Ollama jobs are persisted, bounded to one local worker, and retried up to five times. If Ollama is unavailable, the photo record remains saved and the analysis job retries.

## Registered Photo Lookup

Use **Find registered person by photo** to compare an uploaded/captured image against retained photo fingerprints in PostgreSQL. Searching does not require selecting a case. An exact source SHA-256 or EXIF-normalized pixel match to one linked photo retrieves that existing person record and any associated case; if there is no case, the response explicitly says so. Exact-image matching does not depend on lifecycle verification status. Multiple exact linked records show reference IDs for review without biodata. Resized/recompressed perceptual-hash results are labeled **Unverified visual candidates** and never return biodata automatically. An unknown image returns **No matching registered photo found**. The lookup is not face recognition, and an image-file match is not independent proof of personal identity.

New photos can only be associated with an existing `VERIFIED` case. The eligible-case list is role/camp scoped. The original filename is sanitized; raw SHA-256, canonical-pixel SHA-256, DCT perceptual hash, camp, access policy, image dimensions, and version are persisted. Repeated same-case uploads are idempotent; cross-case duplicate association is rejected for review. Existing stored photos are fingerprint-backfilled during schema initialization only when their private file exists.

## Implemented and Verified Here

| Area | Status | Evidence |
| --- | --- | --- |
| PostgreSQL 18.6 connectivity and additive schema | PASS | Local DB migration and repeat initialization succeeded; pre-change backups were created. |
| Three camp logins and camp isolation | PASS | Each local account logged in; own-camp reads returned 200, other-camp and global searches returned 403. |
| Explicit reunion closure and audited reopen | PASS | Live flow verified evidence, closed a case, idempotent retry returned 200, active lookup excluded it, and manager reopen was audited. |
| Camp closure outbox | PASS | Two camp tombstones were queued; camp update retrieval and acknowledgement persisted. |
| Stale offline registration | PASS | A new sync event for a closed registration was rejected. |
| Protected photo upload and Ollama description | PASS | A synthetic image uploaded, was processed by `qwen2.5vl:3b`, and its structured description was saved in PostgreSQL. |
| Exact/normalized photo-to-person retrieval | PASS | Live browser upload followed by photo lookup populated the existing synthetic person/case details and protected photo from PostgreSQL. Exact lookups also return records with no case or a non-verified lifecycle status. |
| Photo lookup safety cases | PASS | 16 live PostgreSQL tests cover exact, canonical pixels, resized review-only candidates, ambiguity, no match, corrupt input, duplicates, no-case/non-verified records, closed/revoked cases, camp scope, and protected access audit. |
| CSV preservation | PASS | The configured source parses as 50 records and all 50 `person_id` values are present in PostgreSQL; no re-import was needed. |
| Ollama match explanation | BLOCKED | The local text-generation request timed out after 60 seconds; the API correctly returned a labeled deterministic explanation instead. |
| Protected photo access | PASS | Assigned camp returned 200; another camp returned 403. |
| Browser mobile layout | PASS | 390 px viewport had no horizontal overflow; camp-only navigation remained scoped. |
| Automated tests | PASS | 39 tests pass in the final full-suite run. |
| CLIP photo search | BLOCKED | No `clip` or `open_clip` package/model is installed; no model was downloaded. |
| Three requested demo-photo-to-person associations | BLOCKED | `demo_photos/` is absent; JPEGs are in `demo_folder/`. Their exact hashes match neither of the two existing photo rows, and no approved person-ID mapping is stored. No links were guessed or changed. |
| Camera hardware capture | NOT TESTED | Browser controls are implemented; physical camera permission/device behavior was not exercised. |
| Backup restore, concurrency/load, MFA, lockout/rate limiting, retention cleanup | NOT TESTED | These require additional implementation and operational validation. |

## Important Limitations

- The current party-confirmation inputs are officer-recorded attestations; the application does not independently authenticate either party.
- Camp closure updates use a durable server outbox and explicit acknowledgement. Full offline SQLite tombstone replication and conflict-resolution UI are not implemented.
- CLIP visual search is not installed; modified images use a local DCT perceptual hash only and return non-biometric, unverified suggestions. QR receipts, Tamil translations, OpenAPI docs, full audit filtering, retention workflows, and production deployment automation are not implemented.
- No `VERIFIED` cases existed in the live database during this work. The browser and integration demonstration used one temporary fictional verified case, which was removed afterward. Consequently, the real database currently has no eligible case/photo pair for lookup.
- Ollama runs on the same host in this local setup. Independent camps cannot exchange records while no authorized network path is available.
- No security audit, hardware benchmark, backup restore drill, or production readiness assessment has been performed.

Do not use this demonstration for real disaster-response personal data without independent security review, consent/legal review, encrypted backup and offline-storage design, and operational testing.