import hmac
import os
import secrets
import socket
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

import database
from photo_service import start_photo_worker
from matcher import explain_with_ollama, find_matches, normalize_text, ollama_available
from v1_api import api as versioned_api


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(PROJECT_DIR, ".env"))
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=9 * 1024 * 1024,
)
app.register_blueprint(versioned_api)


def _trusted_origins():
    return {
        origin.strip().rstrip("/")
        for origin in os.getenv("TRUSTED_CORS_ORIGINS", "").split(",")
        if origin.strip() and origin.strip() != "*"
    }


@app.before_request
def handle_cors_preflight():
    if request.method != "OPTIONS":
        return None
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin not in _trusted_origins():
        return api_error("Origin is not allowed.", 403)
    return "", 204


@app.after_request
def add_trusted_cors_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin and origin in _trusted_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-Token, Idempotency-Key"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, OPTIONS"
        response.headers.add("Vary", "Origin")
    return response


def officer_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not session.get("officer"):
            return jsonify({"error": "Officer authentication required."}), 401
        if session.get("role") == "camp_operator":
            return jsonify({"error": "This endpoint requires officer-level access."}), 403
        return handler(*args, **kwargs)
    return wrapped


def csrf_required():
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def api_error(message, status):
    return jsonify({"error": message}), status


def valid_text(value, field, maximum, required=False):
    if value is None:
        if required:
            raise ValueError(f"{field} is required.")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text.")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required.")
    if len(value) > maximum:
        raise ValueError(f"{field} must be at most {maximum} characters.")
    return value or None


def _family_groups(people):
    parents = list(range(len(people)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def join(left, right):
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    seen_family = {}
    seen_address = {}
    for index, person in enumerate(people):
        family_key = normalize_text(person.get("family_id"))
        address_key = normalize_text(person.get("address"))
        for key, seen in ((family_key, seen_family), (address_key, seen_address)):
            if key:
                if key in seen:
                    join(index, seen[key])
                else:
                    seen[key] = index

    components = {}
    for index, person in enumerate(people):
        if not normalize_text(person.get("family_id")) and not normalize_text(person.get("address")):
            continue
        components.setdefault(find(index), []).append(person)

    result = []
    for members in components.values():
        if len(members) < 2:
            continue
        family_ids = [normalize_text(person.get("family_id")) for person in members]
        addresses = [normalize_text(person.get("address")) for person in members]
        evidence = []
        if len([value for value in family_ids if value]) != len(set(value for value in family_ids if value)):
            evidence.append("Shared family ID")
        if len([value for value in addresses if value]) != len(set(value for value in addresses if value)):
            evidence.append("Shared address")
        label_key = next((person.get("family_id") for person in members if person.get("family_id")), None)
        if not label_key:
            label_key = next((person.get("address") for person in members if person.get("address")), "Shared household")
        result.append({
            "group_key": label_key,
            "evidence": " + ".join(evidence),
            "label": "Potential Family Connection - Human Verification Required",
            "members": members,
        })
    return sorted(result, key=lambda group: str(group["group_key"]).casefold())


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    try:
        with database.get_connection() as connection:
            connection.execute("SELECT 1")
        return jsonify({"status": "ok", "database": "connected"})
    except Exception:
        return jsonify({"status": "error", "database": "unavailable"}), 503


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    expected_user = os.getenv("OFFICER_USERNAME", "")
    expected_password = os.getenv("OFFICER_PASSWORD", "")
    if not expected_user or not expected_password:
        return api_error("Officer credentials are not configured in .env.", 503)
    if not isinstance(username, str) or not isinstance(password, str):
        return api_error("Username and password must be text.", 400)
    if not (hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_password)):
        return api_error("Invalid officer credentials.", 401)
    session.clear()
    session["officer"] = expected_user
    session["username"] = expected_user
    session["role"] = "officer"
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    return jsonify({"authenticated": True, "csrf_token": session["csrf_token"]})


@app.post("/api/logout")
@officer_required
def logout():
    if not csrf_required():
        return api_error("Invalid CSRF token.", 403)
    session.clear()
    return jsonify({"authenticated": False})


@app.get("/api/me")
@officer_required
def me():
    return jsonify({"authenticated": True, "officer": session["officer"], "role": session.get("role", "officer"), "csrf_token": session["csrf_token"]})


@app.get("/api/people")
@officer_required
def people():
    filters = {
        "name": request.args.get("name", "").strip(),
        "family_id": request.args.get("family_id", "").strip(),
        "address": request.args.get("address", "").strip(),
        "camp": request.args.get("camp", "").strip(),
    }
    try:
        records = database.fetch_people({key: value for key, value in filters.items() if value})
        return jsonify({"people": records, "count": len(records)})
    except Exception:
        app.logger.exception("People lookup failed")
        return api_error("Unable to retrieve people from the database.", 503)


@app.post("/api/people")
@officer_required
def create_person():
    if not csrf_required():
        return api_error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object.", 400)
    try:
        age = body.get("age")
        if age == "":
            age = None
        if age is not None:
            if isinstance(age, bool):
                raise ValueError("age must be an integer from 0 to 120.")
            age = int(age)
            if age < 0 or age > 120:
                raise ValueError("age must be an integer from 0 to 120.")
        status = body.get("status", "registered")
        if status not in {"missing", "survivor", "registered"}:
            raise ValueError("status must be missing, survivor, or registered.")
        person = {
            "full_name": valid_text(body.get("full_name"), "full_name", 120, required=True),
            "alternate_name": valid_text(body.get("alternate_name"), "alternate_name", 120),
            "age": age,
            "gender": valid_text(body.get("gender"), "gender", 40),
            "family_id": valid_text(body.get("family_id"), "family_id", 100),
            "relative_name": valid_text(body.get("relative_name"), "relative_name", 120),
            "camp_name": valid_text(body.get("camp_name"), "camp_name", 120, required=True),
            "address": valid_text(body.get("address"), "address", 250),
            "status": status,
        }
        created = database.insert_person(person)
        return jsonify({"person": created}), 201
    except (ValueError, TypeError) as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Person registration failed")
        return api_error("Unable to register person.", 503)


@app.get("/api/match")
@officer_required
def match():
    name = request.args.get("name", "").strip()
    if not name or len(name) > 120:
        return api_error("Provide a name of 1 to 120 characters.", 400)
    try:
        age = request.args.get("age")
        age = int(age) if age not in (None, "") else None
        if age is not None and not 0 <= age <= 120:
            raise ValueError
        person_id = request.args.get("person_id")
        person_id = int(person_id) if person_id else None
        if person_id is not None and person_id < 1:
            raise ValueError
    except ValueError:
        return api_error("age must be 0-120 and person_id must be a positive integer.", 400)
    try:
        results = find_matches(
            name=name,
            age=age,
            relative_name=request.args.get("relative_name"),
            family_id=request.args.get("family_id"),
            address=request.args.get("address"),
            person_id=person_id,
            limit=5,
        )
        explanation = explain_with_ollama(results)
        return jsonify({
            "query": {"name": name, "age": age},
            "matches": results,
            "count": len(results),
            "ollama_available": ollama_available(),
            "explanation": explanation,
            "notice": "Scores suggest records for review only; they do not confirm identity or family relationships.",
        })
    except Exception:
        app.logger.exception("Matching request failed")
        return api_error("Unable to search for potential matches.", 503)


@app.get("/api/families")
@officer_required
def families():
    try:
        groups = _family_groups(database.fetch_people())
        return jsonify({"families": groups, "count": len(groups)})
    except Exception:
        app.logger.exception("Family grouping failed")
        return api_error("Unable to retrieve potential family connections.", 503)


@app.get("/api/stats")
@officer_required
def stats():
    try:
        return jsonify(database.get_stats())
    except Exception:
        app.logger.exception("Statistics lookup failed")
        return api_error("Unable to retrieve statistics.", 503)


@app.post("/api/reviews")
@officer_required
def review():
    if not csrf_required():
        return api_error("Invalid CSRF token.", 403)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object.", 400)
    try:
        person_id = int(body.get("person_id"))
        candidate_id = int(body.get("candidate_id"))
    except (TypeError, ValueError):
        return api_error("person_id and candidate_id must be integers.", 400)
    if person_id < 1 or candidate_id < 1 or person_id == candidate_id:
        return api_error("Select two different valid person records.", 400)
    action = body.get("action", "reviewed")
    if not isinstance(action, str) or action not in {"reviewed", "follow_up", "not_a_match"}:
        return api_error("Unsupported review action.", 400)
    try:
        if not database.person_exists(person_id) or not database.person_exists(candidate_id):
            return api_error("One or both person records were not found.", 404)
        note = valid_text(body.get("note"), "note", 500)
        review_record = database.record_review(
            person_id, candidate_id, session["officer"], action, note
        )
        return jsonify({
            "review": review_record,
            "message": "Review recorded. No identity or family relationship was confirmed.",
        }), 201
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Review could not be saved")
        return api_error("Unable to save review.", 503)


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if request.path.startswith("/api/"):
        return api_error(error.description, error.code or 500)
    return error


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    app.logger.exception("Unhandled request error")
    if request.path.startswith("/api/"):
        return api_error("An unexpected server error occurred.", 500)
    return "An unexpected server error occurred.", 500


def choose_port():
    configured_port = os.getenv("PORT", "").strip()
    if configured_port:
        try:
            return int(configured_port)
        except ValueError as error:
            raise RuntimeError(f"PORT must be an integer, got: {configured_port!r}") from error

    for port in range(5000, 5101):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free local development port was available in the 5000-5100 range.")


if __name__ == "__main__":
    if not app.secret_key:
        raise SystemExit("Set SECRET_KEY in .env before starting the server.")
    database.validate_local_demo_binding()
    start_photo_worker()
    selected_port = choose_port()
    print(f"REUNITE AI is starting at http://127.0.0.1:{selected_port}")
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=selected_port, debug=False)