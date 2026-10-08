import hmac
import hashlib
import json
import uuid
from functools import wraps

from flask import Blueprint, current_app, jsonify, request, send_file, session
from psycopg.types.json import Jsonb
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import camp_store
import database
import photo_service
from matcher import deterministic_explanation, explain_with_ollama, ollama_available, rank_people


api = Blueprint("versioned_api", __name__)
MATCH_LABEL = "Potential Match — Human Verification Required"


def _role():
    return session.get("role") or ("officer" if session.get("officer") else None)


def _csrf_valid():
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _error(message, status):
    return jsonify({"error": message}), status


def _roles(*allowed):
    def decorator(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            role = _role()
            if not role:
                return _error("Authentication required.", 401)
            if role not in allowed:
                return _error("This role is not authorized for the requested action.", 403)
            return handler(*args, **kwargs)
        return wrapped
    return decorator


def _camp_access(camp_id, allow_inactive=False):
    role = _role()
    if role == "camp_operator" and str(session.get("camp_id")) != str(camp_id):
        return None, _error("This account is assigned to a different camp.", 403)
    with database.get_connection() as connection:
        camp = connection.execute("SELECT * FROM camps WHERE id = %s", (camp_id,)).fetchone()
    if not camp:
        return None, _error("Camp not found.", 404)
    if camp["status"] == "archived" or (camp["status"] != "active" and not allow_inactive):
        return None, _error("Camp is not active.", 409)
    return camp, None


def _audit(connection, action, object_type, object_id=None, details=None):
    connection.execute(
        "INSERT INTO audit_logs (actor_id, actor_username, action, object_type, object_id, details) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            session.get("staff_user_id"),
            session.get("username") or session.get("officer", "unknown"),
            action,
            object_type,
            str(object_id) if object_id is not None else None,
            Jsonb(details or {}),
        ),
    )


def _validate_name(value):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 120:
        raise ValueError("full_name must be 1 to 120 characters.")
    return value.strip()


def _photo_person_access(person_id):
    with database.get_connection() as connection:
        person = connection.execute(
            "SELECT people.id, people.camp_id, people.full_name, cases.id AS case_id, cases.status AS case_status "
            "FROM people LEFT JOIN reunification_cases cases ON cases.missing_person_id = people.id "
            "WHERE people.id = %s",
            (person_id,),
        ).fetchone()
    if not person:
        return None, _error("Person record not found.", 404)
    if _role() == "camp_operator" and str(person["camp_id"]) != str(session.get("camp_id")):
        return None, _error("This account is assigned to a different camp.", 403)
    return person, None


def _photo_case_details(connection, person_id):
    return connection.execute(
        "SELECT cases.id AS case_id, cases.status AS case_status, cases.revision AS case_revision, "
        "cases.updated_at AS case_updated_at, cases.closed_at, people.id AS person_record_number, "
        "people.person_id AS registration_id, people.seed_key, people.family_id, people.family_uuid, "
        "people.full_name, people.alternate_name, people.age, people.date_of_birth, people.gender, "
        "people.family_head, people.relationship_to_head, people.father_or_guardian_name, people.mother_name, "
        "people.primary_language, people.house_number, people.street, people.area, people.village_or_town, "
        "people.district, people.state, people.postal_code, people.full_address, people.emergency_contact_name, "
        "people.emergency_contact_phone_demo, people.known_relative_name, people.known_relative_relationship, "
        "people.last_known_location, people.registered_camp, people.disaster_status, people.assistance_needed, "
        "people.registration_date, people.record_source, people.identity_verification_status, people.notes, "
        "people.camp_id, people.camp_name, people.status AS registration_status, people.address, people.created_at, "
        "COALESCE(families.household_address, people.full_address, people.address) AS household_address "
        "FROM people LEFT JOIN reunification_cases cases ON cases.missing_person_id = people.id "
        "LEFT JOIN families ON families.id = people.family_uuid WHERE people.id = %s",
        (person_id,),
    ).fetchone()


def _photo_match_candidate(photo_row, match_type):
    return {
        "case_id": str(photo_row["case_id"]) if photo_row["case_id"] else None,
        "person_id": photo_row.get("registration_id"),
        "person_record_number": photo_row["person_id"],
        "camp_name": photo_row["camp_name"],
        "case_status": photo_row["case_status"] or "No case associated with this record.",
        "match_type": match_type,
    }


@api.post("/api/v1/auth/login")
def versioned_login():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.", 400)
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return _error("Username and password are required.", 400)
    if username.strip() in {"camp1", "camp2", "camp3"}:
        remote = (request.remote_addr or "").strip().lower()
        if not database.local_demo_mode_enabled() or remote not in {"127.0.0.1", "::1", "localhost"}:
            return _error("Local demonstration camp accounts are disabled outside LOCAL_DEMO_MODE on localhost.", 403)
    try:
        user = database.get_staff_user(username.strip())
    except Exception:
        current_app.logger.exception("Staff login lookup failed")
        return _error("Authentication database is unavailable. Initialize schema and manager credentials.", 503)
    if not user or not check_password_hash(user["password_hash"], password):
        return _error("Invalid credentials.", 401)
    session.clear()
    session.update({
        "staff_user_id": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "camp_id": str(user["camp_id"]) if user["camp_id"] else None,
        "csrf_token": uuid.uuid4().hex + uuid.uuid4().hex,
        "officer": user["username"],
    })
    session.permanent = True
    return jsonify({"authenticated": True, "username": user["username"], "role": user["role"], "camp_id": session["camp_id"], "csrf_token": session["csrf_token"]})


@api.post("/api/v1/auth/logout")
@_roles("manager", "officer", "camp_operator")
def versioned_logout():
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    session.clear()
    return jsonify({"authenticated": False})


@api.get("/api/v1/health")
def versioned_health():
    try:
        with database.get_connection() as connection:
            connection.execute("SELECT 1")
        return jsonify({"status": "ok", "database": "connected"})
    except Exception:
        return jsonify({"status": "error", "database": "unavailable"}), 503


@api.get("/api/v1/camps")
@_roles("manager", "officer", "camp_operator")
def list_camps():
    try:
        query = "SELECT id, name, description, status, coordination_channel, created_at, updated_at, archived_at FROM camps"
        params = []
        if _role() == "camp_operator":
            query += " WHERE id = %s"
            params.append(session.get("camp_id"))
        elif request.args.get("include_archived") != "true":
            query += " WHERE status <> 'archived'"
        query += " ORDER BY name"
        with database.get_connection() as connection:
            camps = connection.execute(query, params).fetchall()
        return jsonify({"camps": camps, "count": len(camps)})
    except Exception:
        current_app.logger.exception("Camp list failed")
        return _error("Unable to retrieve camps.", 503)


@api.post("/api/v1/camps")
@_roles("manager")
def create_camp():
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("name"), str) or not body["name"].strip():
        return _error("Camp name is required.", 400)
    name = body["name"].strip()
    if len(name) > 120:
        return _error("Camp name must be at most 120 characters.", 400)
    try:
        with database.get_connection() as connection:
            camp = connection.execute(
                "INSERT INTO camps (name, description, coordination_channel) VALUES (%s, %s, %s) "
                "RETURNING id, name, description, status, coordination_channel, created_at",
                (name, body.get("description"), body.get("coordination_channel")),
            ).fetchone()
            _audit(connection, "camp_created", "camp", camp["id"], {"name": name})
        camp_store.connect_camp(camp["id"]).close()
        return jsonify({"camp": camp}), 201
    except Exception as error:
        if "unique" in str(error).lower():
            return _error("A camp with this name already exists.", 409)
        current_app.logger.exception("Camp creation failed")
        return _error("Unable to create camp.", 503)


@api.patch("/api/v1/camps/<uuid:camp_id>")
@_roles("manager")
def update_camp(camp_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body:
        return _error("Provide at least one camp field to update.", 400)
    allowed = {"name", "description", "coordination_channel", "status"}
    if set(body) - allowed:
        return _error("Unsupported camp field.", 400)
    if body.get("status") not in (None, "active", "inactive"):
        return _error("Use the archive endpoint to archive a camp.", 400)
    if "name" in body and (not isinstance(body["name"], str) or not body["name"].strip() or len(body["name"].strip()) > 120):
        return _error("Camp name must be 1 to 120 characters.", 400)
    fields = []
    values = []
    for key in sorted(body):
        fields.append(f"{key} = %s")
        value = body[key].strip() if isinstance(body[key], str) else body[key]
        values.append(value or None if isinstance(value, str) else value)
    fields.append("updated_at = CURRENT_TIMESTAMP")
    values.append(camp_id)
    try:
        with database.get_connection() as connection:
            camp = connection.execute(
                f"UPDATE camps SET {', '.join(fields)} WHERE id = %s AND status <> 'archived' "
                "RETURNING id, name, description, status, coordination_channel, updated_at",
                values,
            ).fetchone()
            if not camp:
                return _error("Camp not found or already archived.", 404)
            _audit(connection, "camp_updated", "camp", camp_id, {"fields": sorted(body)})
        return jsonify({"camp": camp})
    except Exception:
        current_app.logger.exception("Camp update failed")
        return _error("Unable to update camp.", 503)


@api.post("/api/v1/camps/<uuid:camp_id>/archive")
@_roles("manager")
def archive_camp(camp_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    try:
        with database.get_connection() as connection:
            camp = connection.execute(
                "UPDATE camps SET status = 'archived', archived_at = CURRENT_TIMESTAMP, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = %s AND status <> 'archived' "
                "RETURNING id, name, status, archived_at",
                (camp_id,),
            ).fetchone()
            if not camp:
                return _error("Camp not found or already archived.", 404)
            _audit(connection, "camp_archived", "camp", camp_id, {"name": camp["name"]})
        return jsonify({"camp": camp, "message": "Camp archived; linked records remain available."})
    except Exception:
        current_app.logger.exception("Camp archive failed")
        return _error("Unable to archive camp.", 503)


def _sync_one(camp, event):
    event_id = uuid.UUID(event["event_id"])
    payload = event["payload"]
    record_type = "missing" if event["event_type"] == "missing" else "survivor"
    name = _validate_name(payload.get("full_name"))
    age = payload.get("age")
    if age not in (None, ""):
        if isinstance(age, bool) or not str(age).isdigit() or not 0 <= int(age) <= 120:
            raise ValueError("age must be an integer from 0 to 120.")
        age = int(age)
    else:
        age = None
    family_id = payload.get("family_id")
    if family_id is not None and (not isinstance(family_id, str) or len(family_id) > 100):
        raise ValueError("family_id must be text up to 100 characters.")
    address = payload.get("full_address") or payload.get("address")
    relative_name = payload.get("known_relative_name") or payload.get("relative_name") or payload.get("family_head")
    person_id = payload.get("person_id") or f"SYNC-{event_id}"
    status = "missing" if record_type == "missing" else "survivor"
    with database.get_connection() as connection:
        previous = connection.execute("SELECT id FROM camp_records WHERE id = %s", (event_id,)).fetchone()
        if previous:
            connection.execute(
                "INSERT INTO sync_events (event_id, camp_id, event_type, payload, status, attempts, synced_at) "
                "VALUES (%s, %s, %s, %s, 'synced', %s, CURRENT_TIMESTAMP) "
                "ON CONFLICT (event_id) DO UPDATE SET status = 'synced', attempts = sync_events.attempts + 1, "
                "last_error = NULL, synced_at = CURRENT_TIMESTAMP",
                (event_id, camp["id"], record_type, Jsonb(payload), max(1, event.get("attempts", 0) + 1)),
            )
            return previous["id"]

        closed_case = connection.execute(
            "SELECT cases.id FROM people "
            "JOIN reunification_cases cases ON cases.missing_person_id = people.id "
            "WHERE people.person_id = %s AND cases.status = 'CLOSED'",
            (person_id,),
        ).fetchone()
        if closed_case:
            raise ValueError("This case is closed and cannot be reopened by offline synchronization.")

        family_uuid = None
        if family_id:
            family = connection.execute(
                "INSERT INTO families (family_id, family_head, household_address) VALUES (%s, %s, %s) "
                "ON CONFLICT (family_id) DO UPDATE SET family_head = COALESCE(families.family_head, EXCLUDED.family_head), "
                "household_address = COALESCE(families.household_address, EXCLUDED.household_address) RETURNING id",
                (family_id, payload.get("family_head"), address),
            ).fetchone()
            family_uuid = family["id"]
        person = connection.execute(
            "INSERT INTO people (person_id, family_id, family_uuid, camp_id, full_name, alternate_name, age, gender, "
            "family_head, relationship_to_head, father_or_guardian_name, mother_name, known_relative_name, "
            "known_relative_relationship, emergency_contact_name, emergency_contact_phone_demo, last_known_location, "
            "registered_camp, disaster_status, assistance_needed, record_source, notes, relative_name, camp_name, "
            "address, full_address, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (person_id) DO UPDATE SET camp_id = EXCLUDED.camp_id, "
            "full_name = EXCLUDED.full_name, alternate_name = EXCLUDED.alternate_name, age = EXCLUDED.age, "
            "family_id = EXCLUDED.family_id, family_uuid = EXCLUDED.family_uuid, address = EXCLUDED.address, "
            "full_address = EXCLUDED.full_address, status = EXCLUDED.status RETURNING id",
            (
                person_id, family_id, family_uuid, camp["id"], name, payload.get("alternate_name"), age,
                payload.get("gender"), payload.get("family_head"), payload.get("relationship_to_head"),
                payload.get("father_or_guardian_name"), payload.get("mother_name"),
                payload.get("known_relative_name"), payload.get("known_relative_relationship"),
                payload.get("emergency_contact_name"), payload.get("emergency_contact_phone_demo"),
                payload.get("last_known_location"), camp["name"], record_type.title(),
                payload.get("assistance_needed"), "camp offline registration", payload.get("notes"),
                relative_name, camp["name"], address, address, status,
            ),
        ).fetchone()
        if record_type == "missing":
            connection.execute(
                "INSERT INTO reunification_cases (missing_person_id) VALUES (%s) "
                "ON CONFLICT (missing_person_id) DO NOTHING",
                (person["id"],),
            )
        connection.execute(
            "INSERT INTO camp_records (id, camp_id, record_type, person_id, payload) "
            "VALUES (%s, %s, %s, %s, %s)",
            (event_id, camp["id"], record_type, person["id"], Jsonb(payload)),
        )
        record_table = "missing_reports" if record_type == "missing" else "survivor_registrations"
        connection.execute(
            f"INSERT INTO {record_table} (record_id, camp_id, person_id, payload) VALUES (%s, %s, %s, %s)",
            (event_id, camp["id"], person["id"], Jsonb(payload)),
        )
        connection.execute(
            "INSERT INTO sync_events (event_id, camp_id, event_type, payload, status, attempts, synced_at) "
            "VALUES (%s, %s, %s, %s, 'synced', %s, CURRENT_TIMESTAMP) "
            "ON CONFLICT (event_id) DO UPDATE SET status = 'synced', attempts = sync_events.attempts + 1, "
            "last_error = NULL, synced_at = CURRENT_TIMESTAMP",
            (event_id, camp["id"], record_type, Jsonb(payload), max(1, event.get("attempts", 0) + 1)),
        )
        _audit(connection, "camp_record_synced", "camp_record", event_id, {"camp_id": str(camp["id"]), "record_type": record_type})
    return event_id


def _sync_camp(camp):
    synced = []
    failed = []
    for event in camp_store.pending_events(camp["id"]):
        try:
            _sync_one(camp, event)
            camp_store.mark_synced(camp["id"], event["event_id"])
            synced.append(event["event_id"])
        except Exception as error:
            camp_store.mark_failed(camp["id"], event["event_id"], error)
            failed.append({"event_id": event["event_id"], "error": str(error)[:200]})
    with database.get_connection() as connection:
        connection.execute(
            "UPDATE notifications SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP "
            "WHERE camp_id = %s AND status = 'pending'",
            (camp["id"],),
        )
    return {"synced": synced, "failed": failed, "queue": camp_store.queue_status(camp["id"])}


@api.get("/api/v1/vision/status")
@_roles("manager", "officer")
def vision_status():
    return jsonify(photo_service.vision_model_status())


@api.get("/api/v1/photo-persons")
@_roles("manager", "officer", "camp_operator")
def photo_persons():
    limit = min(max(request.args.get("limit", 200, type=int), 1), 200)
    query = (
        "SELECT people.id AS person_record_number, people.person_id, cases.id AS case_id, "
        "people.full_name, people.family_id, "
        "people.camp_id, people.camp_name, cases.status AS case_status "
        "FROM people LEFT JOIN reunification_cases cases ON cases.missing_person_id = people.id "
        "WHERE cases.status IS DISTINCT FROM 'CLOSED'"
    )
    params = []
    if _role() == "camp_operator":
        query += " AND people.camp_id = %s"
        params.append(session.get("camp_id"))
    query += " ORDER BY cases.updated_at DESC LIMIT %s"
    params.append(limit)
    with database.get_connection() as connection:
        people = connection.execute(query, params).fetchall()
        _audit(connection, "photo_person_index_viewed", "photo_person_index", None, {"count": len(people)})
    return jsonify({"people": people, "count": len(people)})


@api.post("/api/v1/people/<int:person_id>/photos")
@_roles("manager", "officer", "camp_operator")
def upload_person_photo(person_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    person, error = _photo_person_access(person_id)
    if error:
        return error
    if person["case_status"] == "CLOSED":
        return _error("Photos cannot be added to a closed case.", 409)
    upload = request.files.get("photo")
    if upload is None:
        return _error("Choose a photo file.", 400)
    content = upload.read(photo_service.MAX_UPLOAD_BYTES + 1)
    try:
        sanitized, mimetype, width, height, suffix = photo_service.sanitize_image(content, upload.mimetype)
        fingerprints = photo_service.image_fingerprints(content)
    except photo_service.PhotoValidationError as error:
        return _error(str(error), 400)
    filename = secure_filename(upload.filename or "")[:255] or f"uploaded-image{suffix}"
    storage_key = f"{uuid.uuid4().hex}{suffix}"
    path = photo_service._safe_photo_path(storage_key)
    try:
        with database.get_connection() as connection:
            locked_case = connection.execute(
                "SELECT people.id AS person_id, people.camp_id FROM people WHERE people.id = %s FOR UPDATE",
                (person_id,),
            ).fetchone()
            if not locked_case:
                return _error("Photo registration requires an existing person record.", 409)
            if _role() == "camp_operator" and str(locked_case["camp_id"]) != str(session.get("camp_id")):
                return _error("This account is assigned to a different camp.", 403)
            linked_case = connection.execute(
                "SELECT id, status FROM reunification_cases WHERE missing_person_id = %s FOR UPDATE",
                (person_id,),
            ).fetchone()
            if linked_case and linked_case["status"] == "CLOSED":
                return _error("Photos cannot be added to a closed case.", 409)
            lock_key = int(fingerprints["normalized_sha256"][:16], 16)
            if lock_key >= 2**63:
                lock_key -= 2**64
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (lock_key,))
            duplicate_rows = connection.execute(
                "SELECT id, person_id FROM person_photos WHERE retained = TRUE AND "
                "(sha256 = %s OR normalized_sha256 = %s)",
                (fingerprints["sha256"], fingerprints["normalized_sha256"]),
            ).fetchall()
            if duplicate_rows:
                person_ids = {row["person_id"] for row in duplicate_rows}
                if person_ids == {person_id}:
                    _audit(connection, "person_photo_duplicate_upload", "person_photo", duplicate_rows[0]["id"], {"person_id": person_id})
                    return jsonify({"photo_id": str(duplicate_rows[0]["id"]), "status": "already_registered", "duplicate": True, "message": "This image is already linked to this case."}), 200
                _audit(connection, "photo_duplicate_association_blocked", "person_record", person_id, {"photo_sha256": fingerprints["sha256"]})
                return _error("This image is already associated with another record. Use photo lookup and review the match before proceeding.", 409)
            with path.open("xb") as output:
                output.write(sanitized)
            photo = connection.execute(
                "INSERT INTO person_photos (person_id, camp_id, storage_key, original_filename, mime_type, sha256, "
                "normalized_sha256, perceptual_hash, access_policy, byte_size, width, height, created_by) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'role_and_camp', %s, %s, %s, %s) "
                "RETURNING id, camp_id, original_filename, mime_type, sha256, normalized_sha256, perceptual_hash, "
                "byte_size, width, height, version, created_at",
                (person_id, locked_case["camp_id"], storage_key, filename, mimetype, fingerprints["sha256"],
                 fingerprints["normalized_sha256"], fingerprints["perceptual_hash"], len(sanitized), width, height,
                 session.get("staff_user_id")),
            ).fetchone()
            job = connection.execute(
                "INSERT INTO photo_ai_jobs (photo_id) VALUES (%s) RETURNING id, status, attempts",
                (photo["id"],),
            ).fetchone()
            _audit(connection, "person_photo_uploaded", "person_photo", photo["id"], {"person_id": person_id, "camp_id": str(locked_case["camp_id"]), "mime_type": mimetype, "byte_size": len(sanitized), "source_sha256": fingerprints["sha256"]})
    except Exception as error:
        path.unlink(missing_ok=True)
        if isinstance(error, ValueError):
            return _error(str(error), 404)
        current_app.logger.exception("Secure photo upload failed")
        return _error("Unable to save this photo securely.", 503)
    return jsonify({"photo": photo, "analysis": {"job_id": str(job["id"]), "status": job["status"], "attempts": job["attempts"]}}), 202


@api.post("/api/v1/photos/lookup")
@_roles("manager", "officer", "camp_operator")
def lookup_photo():
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    upload = request.files.get("photo")
    if upload is None:
        return _error("Choose a photo to search registered records.", 400)
    content = upload.read(photo_service.MAX_UPLOAD_BYTES + 1)
    try:
        _, _, query_width, query_height, _ = photo_service.sanitize_image(content, upload.mimetype)
        fingerprints = photo_service.image_fingerprints(content)
    except photo_service.PhotoValidationError as error:
        return _error(str(error), 400)
    lookup_id = uuid.uuid4()
    camp_filter = session.get("camp_id") if _role() == "camp_operator" else None
    try:
        with database.get_connection() as connection:
            exact_query = (
                "SELECT photos.id AS photo_id, photos.person_id, photos.sha256, photos.normalized_sha256, "
                "photos.perceptual_hash, photos.camp_id, people.person_id AS registration_id, people.camp_name, "
                "cases.id AS case_id, cases.status AS case_status "
                "FROM person_photos photos JOIN people ON people.id = photos.person_id "
                "LEFT JOIN reunification_cases cases ON cases.missing_person_id = people.id "
                "WHERE photos.retained = TRUE AND (photos.sha256 = %s OR photos.normalized_sha256 = %s)"
            )
            exact_params = [fingerprints["sha256"], fingerprints["normalized_sha256"]]
            if camp_filter:
                exact_query += " AND photos.camp_id = %s"
                exact_params.append(camp_filter)
            exact_rows = connection.execute(exact_query, exact_params).fetchall()
            exact_matches = []
            match_priorities = {"exact_sha256": 0, "normalized_pixels": 1, "reencoded_image_copy": 2}
            for row in exact_rows:
                match_type = "exact_sha256" if row["sha256"] == fingerprints["sha256"] else "normalized_pixels"
                exact_matches.append({**row, "match_type": match_type})

            perceptual_rows = None
            if not exact_matches:
                perceptual_query = (
                    "SELECT photos.id AS photo_id, photos.person_id, people.person_id AS registration_id, "
                    "photos.perceptual_hash, photos.storage_key, photos.sha256, photos.width, photos.height, "
                    "photos.camp_id, people.camp_name, cases.id AS case_id, cases.status AS case_status "
                    "FROM person_photos photos JOIN people ON people.id = photos.person_id "
                    "LEFT JOIN reunification_cases cases ON cases.missing_person_id = people.id "
                    "WHERE photos.retained = TRUE AND photos.perceptual_hash IS NOT NULL"
                )
                perceptual_params = []
                if camp_filter:
                    perceptual_query += " AND photos.camp_id = %s"
                    perceptual_params.append(camp_filter)
                perceptual_query += " ORDER BY photos.created_at DESC LIMIT 5001"
                perceptual_rows = connection.execute(perceptual_query, perceptual_params).fetchall()
                if len(perceptual_rows) > 5000:
                    _audit(connection, "photo_lookup_search_limited", "photo_lookup", lookup_id, {"rows_scanned": 5000})
                    return jsonify({"lookup_id": str(lookup_id), "status": "search_limited", "message": "The registered photo index is too large for this local lookup. Narrow the camp scope or ask an administrator."}), 503
                for row in perceptual_rows:
                    if photo_service.perceptual_distance(fingerprints["perceptual_hash"], row["perceptual_hash"]) != 0:
                        continue
                    if (row["width"], row["height"]) != (query_width, query_height):
                        continue
                    stored_path = photo_service._safe_photo_path(row["storage_key"])
                    if not stored_path.is_file():
                        continue
                    stored_content = stored_path.read_bytes()
                    if hashlib.sha256(stored_content).hexdigest() != row["sha256"]:
                        _audit(connection, "registered_photo_integrity_mismatch", "person_photo", row["photo_id"], {"lookup_id": str(lookup_id)})
                        continue
                    pixel_error = photo_service.reencoded_image_copy_mae(content, stored_content)
                    if pixel_error is not None and pixel_error <= photo_service.MAX_REENCODED_COPY_MAE:
                        exact_matches.append({**row, "match_type": "reencoded_image_copy", "pixel_error": pixel_error})

            if exact_matches:
                by_person = {}
                for candidate in exact_matches:
                    current = by_person.get(candidate["person_id"])
                    if current is None or match_priorities[candidate["match_type"]] < match_priorities[current["match_type"]]:
                        by_person[candidate["person_id"]] = candidate
                candidates = [_photo_match_candidate(candidate, candidate["match_type"]) for candidate in by_person.values()]
                if len(by_person) > 1:
                    _audit(connection, "photo_lookup_ambiguous", "photo_lookup", lookup_id, {"match_type": "exact", "candidate_count": len(by_person)})
                    return jsonify({"lookup_id": str(lookup_id), "status": "ambiguous", "match_type": "exact", "candidates": candidates, "message": "Multiple registered cases share this image. An officer must review the associations."}), 200
                matched = next(iter(by_person.values()))
                record = _photo_case_details(connection, matched["person_id"])
                if not record:
                    _audit(connection, "photo_lookup_record_missing", "photo_lookup", lookup_id, {"photo_id": str(matched["photo_id"]), "person_id": matched["person_id"]})
                    return _error("The registered image record is unavailable. No biodata was returned.", 404)
                photo = connection.execute(
                    "SELECT id, original_filename, mime_type, created_at, version FROM person_photos "
                    "WHERE id = %s AND retained = TRUE",
                    (matched["photo_id"],),
                ).fetchone()
                _audit(connection, "photo_lookup_record_retrieved", "reunification_case", record["case_id"], {"lookup_id": str(lookup_id), "photo_id": str(matched["photo_id"]), "match_type": matched["match_type"]})
                lifecycle_status = record["case_status"] or "No case associated with this record."
                verification_status = record["identity_verification_status"] or "Not recorded"
                authorized_biodata = {key: value for key, value in record.items()}
                return jsonify({
                    "lookup_id": str(lookup_id),
                    "status": "matched",
                    "match_type": matched["match_type"],
                    "message": "Retrieved from existing database record.",
                    "person_id": record["registration_id"] or str(record["person_record_number"]),
                    "case_id": str(record["case_id"]) if record["case_id"] else None,
                    "camp_id": str(record["camp_id"]) if record["camp_id"] else None,
                    "authorized_biodata": authorized_biodata,
                    "photo_reference": {"photo_id": str(photo["id"]), "original_filename": photo["original_filename"], "file_url": f"/api/v1/photos/{photo['id']}/file"},
                    "lifecycle_status": lifecycle_status,
                    "verification_status": verification_status,
                    "source_case_id": str(record["case_id"]) if record["case_id"] else None,
                    "case": record,
                    "photo": {**photo, "file_url": f"/api/v1/photos/{photo['id']}/file"},
                    "identity_warning": "The image match identifies a stored image association, not independent proof of the person's identity.",
                }), 200

            rows = perceptual_rows or []
            near_matches = []
            for row in rows:
                distance = photo_service.perceptual_distance(fingerprints["perceptual_hash"], row["perceptual_hash"])
                if distance <= 4:
                    near_matches.append({**row, "distance": distance})
            if near_matches:
                near_matches.sort(key=lambda candidate: candidate["distance"])
                by_person = {}
                for candidate in near_matches:
                    by_person.setdefault(candidate["person_id"], candidate)
                candidates = [
                    {**_photo_match_candidate(candidate, "perceptual_similarity"), "distance": candidate["distance"]}
                    for candidate in by_person.values()
                ]
                status = "ambiguous" if len(candidates) > 1 else "review_required"
                _audit(connection, "photo_lookup_perceptual_candidates", "photo_lookup", lookup_id, {"candidate_count": len(candidates), "max_hamming_distance": 4})
                return jsonify({"lookup_id": str(lookup_id), "status": status, "match_type": "perceptual_similarity", "candidates": candidates, "label": "Unverified visual candidates", "message": "Perceptual similarity is not identity evidence. Verify against independent case and family information."}), 200

            _audit(connection, "photo_lookup_no_match", "photo_lookup", lookup_id, {"source_sha256": fingerprints["sha256"]})
            return jsonify({"lookup_id": str(lookup_id), "status": "no_match", "message": "No matching registered photo found. No identity or biodata was inferred from the image.", "clip_search_available": False}), 200
    except Exception:
        current_app.logger.exception("Registered photo lookup failed")
        return _error("Photo lookup is temporarily unavailable. Your image was not registered.", 503)


@api.get("/api/v1/people/<int:person_id>/photos")
@_roles("manager", "officer", "camp_operator")
def list_person_photos(person_id):
    person, error = _photo_person_access(person_id)
    if error:
        return error
    with database.get_connection() as connection:
        _audit(connection, "person_photo_list_viewed", "person_record", person_id, {"photo_count_query": True})
        photos = connection.execute(
            "SELECT photos.id, photos.original_filename, photos.mime_type, photos.byte_size, photos.width, photos.height, photos.version, photos.created_at, "
            "descriptions.description, descriptions.source, descriptions.model_name, descriptions.review_status, descriptions.analyzed_at, "
            "jobs.status AS analysis_status, jobs.attempts, jobs.last_error "
            "FROM person_photos photos LEFT JOIN photo_descriptions descriptions ON descriptions.photo_id = photos.id "
            "LEFT JOIN LATERAL (SELECT status, attempts, last_error FROM photo_ai_jobs "
            "WHERE photo_id = photos.id ORDER BY created_at DESC LIMIT 1) jobs ON TRUE "
            "WHERE photos.person_id = %s AND photos.retained = TRUE ORDER BY photos.created_at DESC",
            (person_id,),
        ).fetchall()
    result = []
    for photo in photos:
        result.append({**photo, "file_url": f"/api/v1/photos/{photo['id']}/file"})
    return jsonify({"photos": result, "count": len(result)})


@api.get("/api/v1/photos/<uuid:photo_id>/file")
@_roles("manager", "officer", "camp_operator")
def protected_photo_file(photo_id):
    with database.get_connection() as connection:
        photo = connection.execute(
            "SELECT photos.storage_key, photos.mime_type, people.id AS person_id, "
            "COALESCE(photos.camp_id, people.camp_id) AS camp_id "
            "FROM person_photos photos JOIN people ON people.id = photos.person_id "
            "WHERE photos.id = %s AND photos.retained = TRUE",
            (photo_id,),
        ).fetchone()
        if not photo:
            return _error("Photo not found.", 404)
        if _role() == "camp_operator" and str(photo["camp_id"]) != str(session.get("camp_id")):
            _audit(connection, "protected_photo_access_denied", "person_photo", photo_id, {"person_id": photo["person_id"]})
            return _error("This account is assigned to a different camp.", 403)
        _audit(connection, "protected_photo_viewed", "person_photo", photo_id, {"person_id": photo["person_id"]})
    try:
        path = photo_service._safe_photo_path(photo["storage_key"])
        if not path.is_file():
            return _error("Photo file is unavailable.", 404)
        response = send_file(path, mimetype=photo["mime_type"], conditional=True, max_age=0)
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    except (OSError, ValueError):
        current_app.logger.exception("Protected photo could not be opened")
        return _error("Photo file is unavailable.", 404)


@api.post("/api/v1/photos/<uuid:photo_id>/retry")
@_roles("manager", "officer", "camp_operator")
def retry_photo_analysis(photo_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    with database.get_connection() as connection:
        photo = connection.execute(
            "SELECT photos.person_id, people.camp_id, photos.retained FROM person_photos photos "
            "JOIN people ON people.id = photos.person_id WHERE photos.id = %s FOR UPDATE OF photos",
            (photo_id,),
        ).fetchone()
        if not photo or not photo["retained"]:
            return _error("Photo not found.", 404)
        if _role() == "camp_operator" and str(photo["camp_id"]) != str(session.get("camp_id")):
            return _error("This account is assigned to a different camp.", 403)
        active = connection.execute(
            "SELECT id, status, attempts FROM photo_ai_jobs WHERE photo_id = %s "
            "AND status IN ('queued', 'processing', 'retry_wait') ORDER BY created_at DESC LIMIT 1",
            (photo_id,),
        ).fetchone()
        if active:
            return jsonify({"job": active, "idempotent": True}), 202
        job = connection.execute(
            "INSERT INTO photo_ai_jobs (photo_id) VALUES (%s) RETURNING id, status, attempts",
            (photo_id,),
        ).fetchone()
        _audit(connection, "photo_analysis_retried", "person_photo", photo_id, {"job_id": str(job["id"])})
    return jsonify({"job": job, "idempotent": False}), 202


@api.post("/api/v1/photos/<uuid:photo_id>/description")
@_roles("manager", "officer", "camp_operator")
def correct_photo_description(photo_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("description"), dict):
        return _error("Provide a structured description object.", 400)
    description = body["description"]
    if set(description) != set(photo_service.DESCRIPTION_FIELDS) or any(
        not isinstance(description.get(field), str) or len(description[field]) > 500
        for field in photo_service.DESCRIPTION_FIELDS
    ):
        return _error("Description fields do not match the supported observable-feature schema.", 400)
    with database.get_connection() as connection:
        photo = connection.execute(
            "SELECT people.camp_id FROM person_photos JOIN people ON people.id = person_photos.person_id "
            "WHERE person_photos.id = %s AND person_photos.retained = TRUE",
            (photo_id,),
        ).fetchone()
        if not photo:
            return _error("Photo not found.", 404)
        if _role() == "camp_operator" and str(photo["camp_id"]) != str(session.get("camp_id")):
            return _error("This account is assigned to a different camp.", 403)
        saved = connection.execute(
            "INSERT INTO photo_descriptions (photo_id, description, source, model_name, review_status, updated_by) "
            "VALUES (%s, %s, 'officer', NULL, 'corrected', %s) ON CONFLICT (photo_id) DO UPDATE SET "
            "description = EXCLUDED.description, source = 'officer', model_name = NULL, review_status = 'corrected', "
            "analyzed_at = CURRENT_TIMESTAMP, updated_by = EXCLUDED.updated_by RETURNING photo_id, source, review_status, analyzed_at",
            (photo_id, Jsonb(description), session.get("staff_user_id")),
        ).fetchone()
        _audit(connection, "photo_description_corrected", "person_photo", photo_id, {"source": "officer"})
    return jsonify({"description": saved, "message": "Officer correction saved and attributed."})


@api.post("/api/v1/camps/<uuid:camp_id>/offline")
@_roles("manager", "officer", "camp_operator")
def set_camp_connectivity(camp_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    camp, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("online"), bool):
        return _error("online must be a boolean.", 400)
    camp_store.set_online(camp_id, body["online"])
    sync_result = _sync_camp(camp) if body["online"] else None
    return jsonify({"camp_id": str(camp_id), "connectivity": "online" if body["online"] else "offline", "sync": sync_result, "queue": camp_store.queue_status(camp_id)})


@api.post("/api/v1/camps/<uuid:camp_id>/<record_type>")
@_roles("manager", "officer", "camp_operator")
def register_camp_record(camp_id, record_type):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    if record_type not in {"missing", "survivors"}:
        return _error("Record type must be missing or survivors.", 404)
    camp, error = _camp_access(camp_id)
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.", 400)
    try:
        _validate_name(body.get("full_name"))
        event_id = request.headers.get("Idempotency-Key")
        if event_id:
            event_id = str(uuid.UUID(event_id))
        event = camp_store.queue_event(camp_id, "missing" if record_type == "missing" else "survivor", body, event_id)
        if not camp_store.is_online(camp_id):
            return jsonify({"event_id": event["event_id"], "status": "pending", "message": "Saved to this camp's isolated offline queue."}), 202
        result = _sync_camp(camp)
        if event["event_id"] in result["synced"]:
            return jsonify({"event_id": event["event_id"], "status": "synced", "message": "Registration synchronized."}), 201
        return jsonify({"event_id": event["event_id"], "status": "failed", "sync": result}), 503
    except (ValueError, TypeError) as error:
        return _error(str(error), 400)
    except Exception:
        current_app.logger.exception("Camp registration failed")
        return _error("Unable to register this record.", 503)


@api.get("/api/v1/camps/<uuid:camp_id>/records")
@_roles("manager", "officer", "camp_operator")
def list_camp_records(camp_id):
    camp, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    with database.get_connection() as connection:
        records = connection.execute(
            "SELECT id, record_type, person_id, payload, status, created_at FROM camp_records "
            "WHERE camp_id = %s AND status <> 'archived' ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (camp["id"], limit, offset),
        ).fetchall()
    pending = camp_store.pending_events(camp_id)
    local_records = [{"id": event["event_id"], "record_type": event["event_type"], "payload": event["payload"], "status": event["status"], "local": True} for event in pending]
    return jsonify({"records": local_records + records, "count": len(local_records) + len(records), "limit": limit, "offset": offset})


@api.delete("/api/v1/camps/<uuid:camp_id>/records/<uuid:record_id>")
@_roles("manager", "officer", "camp_operator")
def archive_camp_record(camp_id, record_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)

    camp, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error

    try:
        with database.get_connection() as connection:
            record = connection.execute(
                "SELECT id, record_type, status "
                "FROM camp_records "
                "WHERE id = %s AND camp_id = %s FOR UPDATE",
                (record_id, camp["id"]),
            ).fetchone()

            if not record:
                return _error("Record not found in this camp.", 404)

            if record["status"] == "archived":
                return _error("Record already archived.", 409)

            connection.execute(
                "UPDATE camp_records "
                "SET status = 'archived', "
                "updated_at = CURRENT_TIMESTAMP "
                "WHERE id = %s AND camp_id = %s",
                (record_id, camp["id"]),
            )

            _audit(
                connection,
                "camp_record_archived",
                "camp_record",
                record_id,
                {
                    "camp_id": str(camp_id),
                    "record_type": record["record_type"],
                },
            )

        return jsonify({
            "message": "Camp record archived.",
            "record_id": str(record_id),
        })

    except Exception:
        current_app.logger.exception("Camp record archive failed")
        return _error("Unable to archive camp record.", 503)

@api.get("/api/v1/camps/<uuid:camp_id>/<record_type>")
@_roles("manager", "officer", "camp_operator")
def list_camp_record_type(camp_id, record_type):
    if record_type not in {"missing", "survivors"}:
        return _error("Record type must be missing or survivors.", 404)
    camp, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    normalized_type = "survivor" if record_type == "survivors" else "missing"
    with database.get_connection() as connection:
        records = connection.execute(
            "SELECT id, record_type, person_id, payload, status, created_at FROM camp_records "
            "WHERE camp_id = %s AND record_type = %s ORDER BY created_at DESC LIMIT 200",
            (camp["id"], normalized_type),
        ).fetchall()
    local_records = [
        {"id": event["event_id"], "record_type": event["event_type"], "payload": event["payload"], "status": event["status"], "local": True}
        for event in camp_store.pending_events(camp_id) if event["event_type"] == normalized_type
    ]
    return jsonify({"records": local_records + records, "count": len(local_records) + len(records)})


@api.post("/api/v1/camps/<uuid:camp_id>/sync")
@_roles("manager", "officer", "camp_operator")
def sync_camp(camp_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    camp, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    camp_store.set_online(camp_id, True)
    return jsonify(_sync_camp(camp))


@api.get("/api/v1/camps/<uuid:camp_id>/sync")
@_roles("manager", "officer", "camp_operator")
def camp_sync_status(camp_id):
    _, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    return jsonify({"camp_id": str(camp_id), "connectivity": "online" if camp_store.is_online(camp_id) else "offline", "queue": camp_store.queue_status(camp_id)})


@api.post("/api/v1/matches/run")
@_roles("manager", "officer")
def run_matches():
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True) or {}
    source = None
    if body.get("person_id") is not None:
        try:
            source_id = int(body["person_id"])
        except (TypeError, ValueError):
            return _error("person_id must be a positive integer.", 400)
        with database.get_connection() as connection:
            source = connection.execute(
                "SELECT * FROM people WHERE id = %s AND NOT EXISTS ("
                "SELECT 1 FROM reunification_cases cases WHERE cases.missing_person_id = people.id "
                "AND cases.status = 'CLOSED')",
                (source_id,),
            ).fetchone()
        if not source:
            return _error("Source record not found.", 404)
        name = source["full_name"]
        age = source["age"]
        relative = source.get("relative_name") or source.get("known_relative_name") or source.get("family_head")
        family_id = source.get("family_id")
        address = source.get("address") or source.get("full_address")
    else:
        name = body.get("name")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
            return _error("Provide a name or person_id.", 400)
        name = name.strip()
        age = body.get("age")
        relative = body.get("relative_name")
        family_id = body.get("family_id")
        address = body.get("address")
        source_id = None
    try:
        results = rank_people(
            {"name": name, "age": age, "relative_name": relative, "family_id": family_id,
             "address": address, "person_id": source_id},
            database.fetch_people(),
            limit=100000,
        )
        if source:
            results = [result for result in results if result["person"].get("camp_id") != source.get("camp_id")][:5]
            with database.get_connection() as connection:
                for result in results:
                    candidate = result["person"]
                    connection.execute(
                        "INSERT INTO candidate_matches (source_person_id, candidate_person_id, clue_scores, combined_score) "
                        "VALUES (%s, %s, %s, %s) ON CONFLICT (source_person_id, candidate_person_id) "
                        "DO UPDATE SET clue_scores = EXCLUDED.clue_scores, combined_score = EXCLUDED.combined_score, "
                        "status = 'candidate_found', is_active = TRUE, "
                        "explanation = NULL, explanation_ready = FALSE, updated_at = CURRENT_TIMESTAMP "
                        "WHERE candidate_matches.status NOT IN ('approved', 'rejected')",
                        (source_id, candidate["id"], Jsonb(result["clue_scores"]), result["combined_score"]),
                    )
                    for person_id in (source_id, candidate["id"]):
                        connection.execute(
                            "UPDATE reunification_cases SET status = 'POTENTIAL_MATCH', updated_at = CURRENT_TIMESTAMP "
                            "WHERE missing_person_id = %s AND status <> 'CLOSED'",
                            (person_id,),
                        )
        else:
            results = results[:5]
        return jsonify({
            "matches": results,
            "count": len(results),
            "label": MATCH_LABEL,
            "notice": "A similarity score is not identity proof. Human verification is mandatory.",
            "workflow_progress_label": "WORKFLOW progress",
        })
    except Exception:
        current_app.logger.exception("Versioned matching failed")
        return _error("Unable to run matching.", 503)


@api.get("/api/v1/matches")
@_roles("manager", "officer")
def list_matches():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    query = (
        "SELECT cm.*, source.full_name AS source_name, source.camp_name AS source_camp, "
        "candidate.full_name AS candidate_name, candidate.camp_name AS candidate_camp "
        "FROM candidate_matches cm JOIN people source ON source.id = cm.source_person_id "
        "JOIN people candidate ON candidate.id = cm.candidate_person_id"
    )
    query += " WHERE cm.is_active = TRUE"
    params = []
    if request.args.get("status"):
        query += " AND cm.status = %s"
        params.append(request.args["status"])
    query += " ORDER BY cm.updated_at DESC LIMIT %s OFFSET %s"
    params.extend((limit, offset))
    with database.get_connection() as connection:
        matches = connection.execute(query, params).fetchall()
    return jsonify({"matches": matches, "count": len(matches), "limit": limit, "offset": offset})


@api.get("/api/v1/matches/<uuid:match_id>/explanation")
@_roles("manager", "officer")
def match_explanation(match_id):
    with database.get_connection() as connection:
        match = connection.execute(
            "SELECT cm.clue_scores, cm.combined_score, cm.explanation, cm.explanation_ready, cm.is_active, candidate.full_name, candidate.camp_name "
            "FROM candidate_matches cm JOIN people candidate ON candidate.id = cm.candidate_person_id WHERE cm.id = %s",
            (match_id,),
        ).fetchone()
    if not match:
        return _error("Candidate match not found.", 404)
    if not match["is_active"]:
        return _error("This candidate link is no longer active.", 409)
    result = [{"person": {"full_name": match["full_name"], "camp_name": match["camp_name"]}, "combined_score": float(match["combined_score"]), "clue_scores": match["clue_scores"]}]
    model_available = ollama_available()
    explanation = match["explanation"] or explain_with_ollama(result)
    fallback = not model_available or explanation == deterministic_explanation(result)
    if explanation and not match["explanation_ready"]:
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE candidate_matches SET explanation = %s, explanation_ready = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (Jsonb(explanation), match_id),
            )
    return jsonify({"explanation": explanation, "fallback": fallback, "source": "deterministic" if fallback else "ollama", "label": MATCH_LABEL})


@api.post("/api/v1/manager/matches/<uuid:match_id>/verify")
@_roles("manager", "officer")
def verify_match(match_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("evidence"), dict):
        return _error("Provide an evidence object for human verification.", 400)
    evidence = body["evidence"]
    if not any(value not in (None, "", [], {}) for value in evidence.values()):
        return _error("At least one verification evidence item is req" \
        "uired.", 400)
    note = body.get("note", "")
    if not isinstance(note, str) or len(note) > 2000:
        return _error("note must be text up to 2000 characters.", 400)
    with database.get_connection() as connection:
        match = connection.execute("SELECT id, status, is_active FROM candidate_matches WHERE id = %s FOR UPDATE", (match_id,)).fetchone()
        if not match:
            return _error("Candidate match not found.", 404)
        if not match["is_active"]:
            return _error("This candidate link is no longer active.", 409)
        if match["status"] in {"approved", "rejected"}:
            return _error("This match is already closed.", 409)
        review = connection.execute(
            "INSERT INTO verification_reviews (candidate_match_id, reviewer_id, reviewer_username, action, evidence, note) "
            "VALUES (%s, %s, %s, 'evidence_recorded', %s, %s) RETURNING id, action, evidence, note, created_at",
            (match_id, session.get("staff_user_id"), session.get("username"), Jsonb(evidence), note),
        ).fetchone()
        connection.execute("UPDATE candidate_matches SET status = 'verified', updated_at = CURRENT_TIMESTAMP WHERE id = %s", (match_id,))
        connection.execute(
            "UPDATE reunification_cases SET status = 'VERIFIED', updated_at = CURRENT_TIMESTAMP "
            "WHERE missing_person_id IN (SELECT source_person_id FROM candidate_matches WHERE id = %s "
            "UNION SELECT candidate_person_id FROM candidate_matches WHERE id = %s) AND status <> 'CLOSED'",
            (match_id, match_id),
        )
        _audit(connection, "match_verified_by_human", "candidate_match", match_id, {"review_id": str(review["id"])})
    return jsonify({"review": review, "status": "verified", "message": "Evidence recorded by an authorized manager. Approval remains a separate decision."}), 201


def _close_match(match_id, decision):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True) or {}
    note = body.get("note", "")
    if not isinstance(note, str) or len(note) > 2000:
        return _error("note must be text up to 2000 characters.", 400)
    with database.get_connection() as connection:
        match = connection.execute(
            "SELECT cm.*, source.camp_id AS source_camp_id, source.full_name AS source_name, "
            "candidate.camp_id AS candidate_camp_id, candidate.full_name AS candidate_name "
            "FROM candidate_matches cm JOIN people source ON source.id = cm.source_person_id "
            "JOIN people candidate ON candidate.id = cm.candidate_person_id WHERE cm.id = %s FOR UPDATE OF cm",
            (match_id,),
        ).fetchone()
        if not match:
            return _error("Candidate match not found.", 404)
        if not match["is_active"]:
            return _error("This candidate link is no longer active.", 409)
        if match["status"] in {"approved", "rejected"}:
            return _error("This match is already closed.", 409)
        if decision == "approved" and match["status"] != "verified":
            return _error("Record human verification evidence before approval.", 409)
        evidence = {}
        latest = connection.execute(
            "SELECT evidence FROM verification_reviews WHERE candidate_match_id = %s "
            "AND action = 'evidence_recorded' ORDER BY created_at DESC LIMIT 1",
            (match_id,),
        ).fetchone()
        if decision == "approved" and (not latest or not latest["evidence"]):
            return _error("Verification evidence is required before approval.", 409)
        evidence["manager_note"] = note
        connection.execute("UPDATE candidate_matches SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (decision, match_id))
        connection.execute(
            "INSERT INTO verification_reviews (candidate_match_id, reviewer_id, reviewer_username, action, evidence, note) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (match_id, session.get("staff_user_id"), session.get("username"), decision, Jsonb(evidence), note),
        )
        if decision == "approved":
            connection.execute(
                "UPDATE reunification_cases SET status = 'REUNIFICATION_PENDING', updated_at = CURRENT_TIMESTAMP "
                "WHERE missing_person_id IN (SELECT source_person_id FROM candidate_matches WHERE id = %s "
                "UNION SELECT candidate_person_id FROM candidate_matches WHERE id = %s) AND status <> 'CLOSED'",
                (match_id, match_id),
            )
            camp_ids = {camp for camp in (match["source_camp_id"], match["candidate_camp_id"]) if camp}
            for camp_id in camp_ids:
                camp_online = camp_store.is_online(camp_id)
                payload = {
                    "case_id": str(match_id),
                    "review_status": "manager-approved after human verification",
                    "relationship": latest["evidence"].get("verified_relationship"),
                    "other_camp_name": match["candidate_name"] if camp_id == match["source_camp_id"] else match["source_name"],
                    "approved_at": None,
                }
                connection.execute(
                    "INSERT INTO notifications (camp_id, candidate_match_id, payload, status, delivered_at) "
                    "VALUES (%s, %s, %s, %s, CASE WHEN %s = 'delivered' THEN CURRENT_TIMESTAMP END) "
                    "ON CONFLICT (camp_id, candidate_match_id, recipient_id) DO NOTHING",
                    (camp_id, match_id, Jsonb(payload), "delivered" if camp_online else "pending", "delivered" if camp_online else "pending"),
                )
        _audit(connection, f"match_{decision}", "candidate_match", match_id, {"note": note})
    return jsonify({"status": decision, "message": "Manager decision recorded after human verification. Similarity scores did not establish identity."})


@api.post("/api/v1/manager/matches/<uuid:match_id>/approve")
@_roles("manager")
def approve_match(match_id):
    return _close_match(match_id, "approved")


@api.post("/api/v1/manager/matches/<uuid:match_id>/reject")
@_roles("manager")
def reject_match(match_id):
    return _close_match(match_id, "rejected")


def _event_uuid(body):
    event_id = request.headers.get("Idempotency-Key") or body.get("event_id")
    try:
        return uuid.UUID(str(event_id))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Provide a valid UUID in Idempotency-Key or event_id.")


@api.post("/api/v1/matches/<uuid:match_id>/reunite")
@_roles("manager", "officer")
def confirm_reunion(match_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.", 400)
    evidence_note = body.get("evidence_note")
    if not isinstance(evidence_note, str) or not 10 <= len(evidence_note.strip()) <= 2000:
        return _error("evidence_note must contain 10 to 2000 characters.", 400)
    if body.get("missing_person_confirmed") is not True or body.get("other_party_confirmed") is not True:
        return _error("Both the missing person and the other party must confirm the reunion.", 400)
    try:
        event_id = _event_uuid(body)
    except ValueError as error:
        return _error(str(error), 400)

    evidence = {
        "note": evidence_note.strip(),
        "missing_person_confirmed": True,
        "other_party_confirmed": True,
    }
    with database.get_connection() as connection:
        previous = connection.execute(
            "SELECT case_id, candidate_match_id, action FROM reunification_events WHERE event_id = %s",
            (event_id,),
        ).fetchone()
        if previous:
            if previous["candidate_match_id"] != match_id or previous["action"] != "reunion_confirmed":
                return _error("This idempotency key was already used for a different event.", 409)
            return jsonify({"event_id": str(event_id), "case_id": str(previous["case_id"]), "status": "CLOSED", "idempotent": True})

        match = connection.execute(
            "SELECT cm.id, cm.status, cm.is_active, source.id AS source_id, source.status AS source_status, "
            "source.camp_id AS source_camp_id, candidate.id AS candidate_id, candidate.status AS candidate_status, "
            "candidate.camp_id AS candidate_camp_id "
            "FROM candidate_matches cm JOIN people source ON source.id = cm.source_person_id "
            "JOIN people candidate ON candidate.id = cm.candidate_person_id "
            "WHERE cm.id = %s FOR UPDATE OF cm, source, candidate",
            (match_id,),
        ).fetchone()
        if not match:
            return _error("Candidate match not found.", 404)
        previous = connection.execute(
            "SELECT case_id, candidate_match_id, action FROM reunification_events WHERE event_id = %s",
            (event_id,),
        ).fetchone()
        if previous:
            if previous["candidate_match_id"] != match_id or previous["action"] != "reunion_confirmed":
                return _error("This idempotency key was already used for a different event.", 409)
            return jsonify({"event_id": str(event_id), "case_id": str(previous["case_id"]), "status": "CLOSED", "idempotent": True})
        if not match["is_active"]:
            return _error("This candidate link is no longer active.", 409)
        if match["status"] not in {"verified", "approved"}:
            return _error("Verify the candidate match before confirming an actual reunion.", 409)
        people_by_status = {match["source_status"]: match["source_id"], match["candidate_status"]: match["candidate_id"]}
        if "missing" not in people_by_status or "survivor" not in people_by_status:
            return _error("Reunion confirmation requires one missing-person record and one survivor record.", 409)
        missing_person_id = people_by_status["missing"]
        case = connection.execute(
            "SELECT id, status, revision FROM reunification_cases WHERE missing_person_id = %s FOR UPDATE",
            (missing_person_id,),
        ).fetchone()
        if not case:
            return _error("The missing-person case was not found.", 404)
        if case["status"] == "CLOSED":
            return _error("This case is already closed.", 409)

        closed_case = connection.execute(
            "UPDATE reunification_cases SET status = 'CLOSED', revision = revision + 1, "
            "closed_at = CURRENT_TIMESTAMP, closed_by = %s, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = %s RETURNING id, revision, closed_at",
            (session.get("staff_user_id"), case["id"]),
        ).fetchone()
        connection.execute(
            "INSERT INTO reunification_events (event_id, case_id, candidate_match_id, action, actor_id, actor_username, evidence) "
            "VALUES (%s, %s, %s, 'reunion_confirmed', %s, %s, %s)",
            (event_id, case["id"], match_id, session.get("staff_user_id"), session.get("username"), Jsonb(evidence)),
        )
        connection.execute(
            "UPDATE candidate_matches SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP "
            "WHERE source_person_id = %s OR candidate_person_id = %s",
            (missing_person_id, missing_person_id),
        )
        camps = {camp for camp in (match["source_camp_id"], match["candidate_camp_id"]) if camp}
        for camp_id in camps:
            payload = {"event_id": str(event_id), "case_id": str(case["id"]), "status": "CLOSED", "revision": closed_case["revision"], "message": "A family reunion has been confirmed."}
            connection.execute(
                "INSERT INTO case_sync_outbox (event_id, camp_id, payload) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (event_id, camp_id, Jsonb(payload)),
            )
            connection.execute(
                "INSERT INTO notifications (camp_id, candidate_match_id, payload, status) VALUES (%s, %s, %s, 'pending') "
                "ON CONFLICT (camp_id, candidate_match_id) WHERE recipient_id IS NULL DO UPDATE SET "
                "payload = EXCLUDED.payload, status = 'pending', delivered_at = NULL, read_at = NULL",
                (camp_id, match_id, Jsonb({"case_id": str(case["id"]), "review_status": "Family reunion confirmed", "event_id": str(event_id)})),
            )
        _audit(connection, "reunion_confirmed_case_closed", "reunification_case", case["id"], {"event_id": str(event_id), "candidate_match_id": str(match_id), "notification_camps": [str(camp) for camp in camps]})
    return jsonify({"event_id": str(event_id), "case_id": str(closed_case["id"]), "status": "CLOSED", "revision": closed_case["revision"], "closed_at": closed_case["closed_at"], "notifications_queued": len(camps), "idempotent": False}), 201


@api.get("/api/v1/cases/closed")
@_roles("manager", "officer")
def closed_cases():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    with database.get_connection() as connection:
        cases = connection.execute(
            "SELECT cases.id AS case_id, cases.status, cases.revision, cases.closed_at, "
            "people.person_id, people.full_name, people.age, people.family_id, people.camp_name "
            "FROM reunification_cases cases JOIN people ON people.id = cases.missing_person_id "
            "WHERE cases.status = 'CLOSED' ORDER BY cases.closed_at DESC LIMIT %s OFFSET %s",
            (limit, offset),
        ).fetchall()
    return jsonify({"cases": cases, "count": len(cases), "limit": limit, "offset": offset})


@api.get("/api/v1/cases/lookup")
@_roles("manager", "officer", "camp_operator")
def lookup_case():
    reference = request.args.get("reference", "").strip()
    if not reference or len(reference) > 160:
        return _error("Provide a case UUID, registration ID, or person record number.", 400)
    try:
        with database.get_connection() as connection:
            case = connection.execute(
                "SELECT cases.id AS case_id, cases.status AS case_status, cases.revision, cases.closed_at, "
                "people.id AS person_record_number, people.person_id AS registration_id, people.full_name, "
                "people.age, people.gender, people.family_id, people.family_head, people.relationship_to_head, "
                "people.known_relative_name, people.camp_id, people.camp_name, people.status AS registration_status, "
                "COALESCE(families.household_address, people.full_address, people.address) AS address "
                "FROM reunification_cases cases JOIN people ON people.id = cases.missing_person_id "
                "LEFT JOIN families ON families.id = people.family_uuid "
                "WHERE cases.id::text = %s OR people.person_id = %s OR people.id::text = %s "
                "ORDER BY cases.created_at DESC LIMIT 1",
                (reference, reference, reference),
            ).fetchone()
            if not case:
                return _error("No case matched that reference.", 404)
            if _role() == "camp_operator" and str(case["camp_id"]) != str(session.get("camp_id")):
                return _error("This account is assigned to a different camp.", 403)
            photos = connection.execute(
                "SELECT id, mime_type, created_at FROM person_photos WHERE person_id = %s AND retained = TRUE ORDER BY created_at DESC",
                (case["person_record_number"],),
            ).fetchall()
            _audit(connection, "case_biodata_retrieved", "reunification_case", case["case_id"], {"reference_type": "case_lookup"})
        return jsonify({"case": case, "photos": [{**photo, "file_url": f"/api/v1/photos/{photo['id']}/file"} for photo in photos], "verified_reference": True})
    except Exception:
        current_app.logger.exception("Case lookup failed")
        return _error("Unable to retrieve this case.", 503)


@api.post("/api/v1/cases/<uuid:case_id>/reopen")
@_roles("manager")
def reopen_case(case_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.", 400)
    justification = body.get("justification")
    if not isinstance(justification, str) or not 20 <= len(justification.strip()) <= 2000:
        return _error("Provide a 20 to 2000 character reopening justification.", 400)
    try:
        event_id = _event_uuid(body)
    except ValueError as error:
        return _error(str(error), 400)
    with database.get_connection() as connection:
        previous = connection.execute("SELECT case_id, action FROM reunification_events WHERE event_id = %s", (event_id,)).fetchone()
        if previous:
            if previous["case_id"] != case_id or previous["action"] != "case_reopened":
                return _error("This idempotency key was already used for a different event.", 409)
            return jsonify({"event_id": str(event_id), "case_id": str(case_id), "status": "OPEN", "idempotent": True})
        case = connection.execute("SELECT id, missing_person_id, status, revision FROM reunification_cases WHERE id = %s FOR UPDATE", (case_id,)).fetchone()
        if not case:
            return _error("Case not found.", 404)
        previous = connection.execute("SELECT case_id, action FROM reunification_events WHERE event_id = %s", (event_id,)).fetchone()
        if previous:
            if previous["case_id"] != case_id or previous["action"] != "case_reopened":
                return _error("This idempotency key was already used for a different event.", 409)
            return jsonify({"event_id": str(event_id), "case_id": str(case_id), "status": "OPEN", "idempotent": True})
        if case["status"] != "CLOSED":
            return _error("Only closed cases can be reopened.", 409)
        reopened = connection.execute(
            "UPDATE reunification_cases SET status = 'OPEN', revision = revision + 1, closed_at = NULL, "
            "closed_by = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = %s RETURNING revision",
            (case_id,),
        ).fetchone()
        connection.execute(
            "INSERT INTO reunification_events (event_id, case_id, action, actor_id, actor_username, evidence) "
            "VALUES (%s, %s, 'case_reopened', %s, %s, %s)",
            (event_id, case_id, session.get("staff_user_id"), session.get("username"), Jsonb({"justification": justification.strip()})),
        )
        connection.execute(
            "UPDATE candidate_matches SET status = 'follow_up', is_active = FALSE, updated_at = CURRENT_TIMESTAMP "
            "WHERE (source_person_id = %s OR candidate_person_id = %s) AND status <> 'rejected'",
            (case["missing_person_id"], case["missing_person_id"]),
        )
        camps = connection.execute(
            "SELECT DISTINCT camp_id FROM people WHERE camp_id IS NOT NULL AND "
            "(id = %s OR id IN (SELECT CASE WHEN source_person_id = %s THEN candidate_person_id ELSE source_person_id END "
            "FROM candidate_matches WHERE source_person_id = %s OR candidate_person_id = %s))",
            (case["missing_person_id"], case["missing_person_id"], case["missing_person_id"], case["missing_person_id"]),
        ).fetchall()
        for row in camps:
            payload = {"event_id": str(event_id), "case_id": str(case_id), "status": "OPEN", "revision": reopened["revision"], "message": "A closed case was reopened by an authorized manager."}
            connection.execute(
                "INSERT INTO case_sync_outbox (event_id, camp_id, payload) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (event_id, row["camp_id"], Jsonb(payload)),
            )
        _audit(connection, "case_reopened", "reunification_case", case_id, {"event_id": str(event_id), "justification": justification.strip(), "notification_camps": [str(row["camp_id"]) for row in camps]})
    return jsonify({"event_id": str(event_id), "case_id": str(case_id), "status": "OPEN", "revision": reopened["revision"], "active_match_links_restored": False}), 200


@api.get("/api/v1/camps/<uuid:camp_id>/case-updates")
@_roles("manager", "officer", "camp_operator")
def camp_case_updates(camp_id):
    _, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    with database.get_connection() as connection:
        updates = connection.execute(
            "SELECT event_id, payload, attempts, created_at FROM case_sync_outbox "
            "WHERE camp_id = %s AND status = 'pending' ORDER BY created_at LIMIT 200",
            (camp_id,),
        ).fetchall()
    return jsonify({"updates": updates, "count": len(updates)})


@api.post("/api/v1/camps/<uuid:camp_id>/case-updates/<uuid:event_id>/ack")
@_roles("manager", "officer", "camp_operator")
def acknowledge_case_update(camp_id, event_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    _, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    with database.get_connection() as connection:
        update = connection.execute(
            "UPDATE case_sync_outbox SET status = 'delivered', attempts = attempts + 1, delivered_at = CURRENT_TIMESTAMP "
            "WHERE event_id = %s AND camp_id = %s RETURNING event_id, status, delivered_at",
            (event_id, camp_id),
        ).fetchone()
    if not update:
        return _error("Case update not found for this camp.", 404)
    return jsonify({"update": update})


@api.get("/api/v1/camps/<uuid:camp_id>/notifications")
@_roles("manager", "officer", "camp_operator")
def camp_notifications(camp_id):
    _, error = _camp_access(camp_id, allow_inactive=True)
    if error:
        return error
    with database.get_connection() as connection:
        rows = connection.execute(
            "SELECT id, payload, status, created_at, delivered_at, read_at FROM notifications "
            "WHERE camp_id = %s ORDER BY created_at DESC LIMIT 200",
            (camp_id,),
        ).fetchall()
    return jsonify({"notifications": rows, "count": len(rows)})


@api.post("/api/v1/notifications/<uuid:notification_id>/read")
@_roles("manager", "officer", "camp_operator")
def mark_notification_read(notification_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    with database.get_connection() as connection:
        query = "UPDATE notifications SET status = 'read', read_at = CURRENT_TIMESTAMP WHERE id = %s"
        params = [notification_id]
        if _role() == "camp_operator":
            query += " AND camp_id = %s"
            params.append(session.get("camp_id"))
        row = connection.execute(query + " RETURNING id, status, read_at", params).fetchone()
    if not row:
        return _error("Notification not found.", 404)
    return jsonify({"notification": row})


@api.get("/api/v1/stats")
@_roles("manager")
def manager_stats():
    with database.get_connection() as connection:
        stats = connection.execute(
            "SELECT (SELECT COUNT(*) FROM camps WHERE status = 'active') AS active_camps, "
            "(SELECT COUNT(*) FROM people) AS registrations, "
            "(SELECT COUNT(*) FROM people WHERE status = 'missing') AS missing_count, "
            "(SELECT COUNT(*) FROM people WHERE status = 'survivor') AS survivor_count, "
            "(SELECT COUNT(*) FROM candidate_matches WHERE status = 'candidate_found') AS pending_verification, "
            "(SELECT COUNT(*) FROM candidate_matches WHERE status = 'approved') AS approvals, "
            "(SELECT COUNT(*) FROM candidate_matches WHERE status = 'rejected') AS rejected, "
            "(SELECT COUNT(*) FROM sync_events WHERE status IN ('pending', 'failed')) AS sync_backlog, "
            "(SELECT COUNT(*) FROM notifications WHERE status = 'pending') AS queued_notifications"
        ).fetchone()
    return jsonify(stats)


@api.get("/api/v1/audit")
@_roles("manager")
def audit_events():
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    with database.get_connection() as connection:
        logs = connection.execute(
            "SELECT actor_username, action, object_type, object_id, details, created_at "
            "FROM audit_logs ORDER BY created_at DESC LIMIT %s",
            (limit,),
        ).fetchall()
    return jsonify({"events": logs, "count": len(logs)})


@api.get("/api/v1/manager/staff")
@_roles("manager")
def list_staff():
    with database.get_connection() as connection:
        staff = connection.execute(
            "SELECT staff.id, staff.username, staff.role, staff.camp_id, camp.name AS camp_name, "
            "staff.active, staff.created_at FROM staff_users staff "
            "LEFT JOIN camps camp ON camp.id = staff.camp_id ORDER BY staff.username"
        ).fetchall()
    return jsonify({"staff": staff, "count": len(staff)})


@api.post("/api/v1/manager/staff")
@_roles("manager")
def create_staff():
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.", 400)
    username = body.get("username")
    password = body.get("password")
    role = body.get("role")
    camp_id = body.get("camp_id")
    if not isinstance(username, str) or not username.strip() or len(username.strip()) > 80:
        return _error("username must be 1 to 80 characters.", 400)
    if not isinstance(password, str) or len(password) < 12:
        return _error("password must contain at least 12 characters.", 400)
    if role not in {"manager", "officer", "camp_operator"}:
        return _error("role must be manager, officer, or camp_operator.", 400)
    if role == "camp_operator" and not camp_id:
        return _error("camp_operator accounts require a camp_id.", 400)
    try:
        with database.get_connection() as connection:
            staff = connection.execute(
                "INSERT INTO staff_users (username, password_hash, role, camp_id) "
                "VALUES (%s, %s, %s, %s) RETURNING id, username, role, camp_id, active, created_at",
                (username.strip(), generate_password_hash(password), role, camp_id),
            ).fetchone()
            _audit(connection, "staff_created", "staff_user", staff["id"], {"role": role, "camp_id": str(camp_id) if camp_id else None})
        return jsonify({"staff": staff}), 201
    except Exception as error:
        if "unique" in str(error).lower():
            return _error("That username already exists.", 409)
        current_app.logger.exception("Staff account creation failed")
        return _error("Unable to create staff account.", 503)


@api.patch("/api/v1/manager/staff/<uuid:staff_id>")
@_roles("manager")
def update_staff(staff_id):
    if not _csrf_valid():
        return _error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) != {"active"} or not isinstance(body["active"], bool):
        return _error("Only the active boolean can be changed through this endpoint.", 400)
    if str(staff_id) == session.get("staff_user_id") and not body["active"]:
        return _error("You cannot deactivate your own manager account.", 409)
    with database.get_connection() as connection:
        staff = connection.execute(
            "UPDATE staff_users SET active = %s WHERE id = %s "
            "RETURNING id, username, role, camp_id, active",
            (body["active"], staff_id),
        ).fetchone()
        if not staff:
            return _error("Staff account not found.", 404)
        _audit(connection, "staff_access_changed", "staff_user", staff_id, {"active": body["active"]})
    return jsonify({"staff": staff})