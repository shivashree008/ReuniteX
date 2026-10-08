import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row
from werkzeug.security import generate_password_hash


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")


def get_connection():
    """Open a PostgreSQL connection using local environment configuration."""
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url:
        return psycopg.connect(database_url, connect_timeout=5, row_factory=dict_row)

    settings = {
        "host": os.getenv("PGHOST", "").strip() or os.getenv("DB_HOST", "").strip(),
        "port": os.getenv("PGPORT", "").strip() or os.getenv("DB_PORT", "").strip(),
        "dbname": os.getenv("PGDATABASE", "").strip() or os.getenv("DB_NAME", "").strip(),
        "user": os.getenv("PGUSER", "").strip() or os.getenv("DB_USER", "").strip(),
        "password": os.getenv("PGPASSWORD", "").strip() or os.getenv("DB_PASSWORD", "").strip(),
    }
    missing = [key for key, value in settings.items() if not value]
    if missing:
        raise RuntimeError(f"Configure these database settings in .env: {', '.join(missing)} or set DATABASE_URL")

    settings["port"] = int(settings["port"])
    return psycopg.connect(**settings, connect_timeout=5, row_factory=dict_row)


def bootstrap_environment_users():
    configured_users = (
        ("manager", "MANAGER_USERNAME", "MANAGER_PASSWORD"),
        ("officer", "OFFICER_USERNAME", "OFFICER_PASSWORD"),
    )
    with get_connection() as connection:
        for role, username_key, password_key in configured_users:
            username = os.getenv(username_key, "").strip()
            password = os.getenv(password_key, "")
            if not username or not password:
                continue
            connection.execute(
                "INSERT INTO staff_users (username, password_hash, role) VALUES (%s, %s, %s) "
                "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, "
                "role = EXCLUDED.role, active = TRUE",
                (username, generate_password_hash(password), role),
            )


def local_demo_mode_enabled():
    return os.getenv("LOCAL_DEMO_MODE", "").strip().lower() in {"1", "true", "yes"}


def validate_local_demo_binding():
    if not local_demo_mode_enabled():
        return
    host = os.getenv("HOST", "127.0.0.1").strip().lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("LOCAL_DEMO_MODE requires HOST to bind only to localhost.")


def bootstrap_demo_camp_users():
    if not local_demo_mode_enabled():
        return
    validate_local_demo_binding()
    with get_connection() as connection:
        for camp_name, username in (("Camp 1", "camp1"), ("Camp 2", "camp2"), ("Camp 3", "camp3")):
            camp = connection.execute("SELECT id, status FROM camps WHERE name = %s", (camp_name,)).fetchone()
            if not camp:
                camp = connection.execute(
                    "INSERT INTO camps (name) VALUES (%s) RETURNING id, status",
                    (camp_name,),
                ).fetchone()
            if camp["status"] == "archived":
                raise RuntimeError(f"{camp_name} is archived; refusing to provision its demo account.")
            connection.execute(
                "INSERT INTO staff_users (username, password_hash, role, camp_id) "
                "VALUES (%s, %s, 'camp_operator', %s) "
                "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, "
                "role = 'camp_operator', camp_id = EXCLUDED.camp_id, active = TRUE",
                (username, generate_password_hash("123"), camp["id"]),
            )


def _table_exists(connection, table_name):
    return bool(connection.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s)",
        (table_name,),
    ).fetchone()["exists"])


def _migrate_legacy_persons_to_people(connection):
    if not _table_exists(connection, "persons"):
        return
    if not _table_exists(connection, "people"):
        return
    if connection.execute("SELECT COUNT(*) AS count FROM people").fetchone()["count"] > 0:
        return

    rows = connection.execute(
        "SELECT * FROM persons ORDER BY person_id"
    ).fetchall()
    if not rows:
        return

    columns = (
        "person_id", "family_id", "full_name", "alternate_name", "age", "date_of_birth",
        "gender", "family_head", "relationship_to_head", "father_or_guardian_name",
        "mother_name", "primary_language", "house_number", "street", "area",
        "village_or_town", "district", "state", "postal_code", "full_address",
        "emergency_contact_name", "emergency_contact_phone_demo", "known_relative_name",
        "known_relative_relationship", "last_known_location", "registered_camp",
        "disaster_status", "assistance_needed", "registration_date", "record_source",
        "identity_verification_status", "notes", "relative_name", "camp_name", "address",
        "status",
    )
    insert_sql = (
        "INSERT INTO people (" + ", ".join(columns) + ") VALUES (" + ", ".join(["%s"] * len(columns)) + ") "
        "ON CONFLICT (person_id) DO NOTHING"
    )
    values = []
    for row in rows:
        row_dict = dict(row)
        status_value = (row_dict.get("disaster_status") or "registered").strip()
        if status_value.lower().startswith("missing"):
            status_value = "missing"
        elif status_value.lower().startswith("survivor"):
            status_value = "survivor"
        else:
            status_value = "registered"

        full_address = row_dict.get("full_address") or ", ".join(
            value for value in (
                row_dict.get("house_number"), row_dict.get("street"), row_dict.get("area"),
                row_dict.get("village_or_town"), row_dict.get("district"),
                row_dict.get("state"), row_dict.get("postal_code"),
            ) if value
        )
        values.append((
            row_dict.get("person_id"),
            row_dict.get("family_id"),
            row_dict.get("full_name"),
            row_dict.get("alternate_name"),
            row_dict.get("age"),
            row_dict.get("date_of_birth"),
            row_dict.get("gender"),
            row_dict.get("family_head"),
            row_dict.get("relationship_to_head"),
            row_dict.get("father_or_guardian_name"),
            row_dict.get("mother_name"),
            row_dict.get("primary_language"),
            row_dict.get("house_number"),
            row_dict.get("street"),
            row_dict.get("area"),
            row_dict.get("village_or_town"),
            row_dict.get("district"),
            row_dict.get("state"),
            row_dict.get("postal_code"),
            full_address,
            row_dict.get("emergency_contact_name"),
            row_dict.get("emergency_contact_phone_demo"),
            row_dict.get("known_relative_name"),
            row_dict.get("known_relative_relationship"),
            row_dict.get("last_known_location"),
            row_dict.get("registered_camp") or "Not assigned",
            row_dict.get("disaster_status"),
            row_dict.get("assistance_needed"),
            row_dict.get("registration_date"),
            row_dict.get("record_source"),
            row_dict.get("identity_verification_status"),
            row_dict.get("notes"),
            row_dict.get("known_relative_name") or row_dict.get("emergency_contact_name") or row_dict.get("family_head"),
            row_dict.get("registered_camp") or "Not assigned",
            full_address,
            status_value,
        ))

    if values:
        with connection.cursor() as cursor:
            cursor.executemany(insert_sql, values)


def _backfill_photo_fingerprints():
    from photo_service import MAX_UPLOAD_BYTES, _safe_photo_path, image_fingerprints

    with get_connection() as connection:
        photos = connection.execute(
            "SELECT id, storage_key FROM person_photos WHERE retained = TRUE "
            "AND (normalized_sha256 IS NULL OR perceptual_hash IS NULL)"
        ).fetchall()
        for photo in photos:
            try:
                path = _safe_photo_path(photo["storage_key"])
                if not path.is_file() or path.stat().st_size > MAX_UPLOAD_BYTES:
                    continue
                fingerprints = image_fingerprints(path.read_bytes())
            except (OSError, ValueError):
                continue
            connection.execute(
                "UPDATE person_photos SET normalized_sha256 = COALESCE(normalized_sha256, %s), "
                "perceptual_hash = COALESCE(perceptual_hash, %s) WHERE id = %s AND retained = TRUE",
                (fingerprints["normalized_sha256"], fingerprints["perceptual_hash"], photo["id"]),
            )


def initialize_database():
    schema = (PROJECT_DIR / "schema.sql").read_text(encoding="utf-8")
    with get_connection() as connection:
        connection.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        for statement in schema.split(";"):
            if statement.strip():
                connection.execute(statement)
        _migrate_legacy_persons_to_people(connection)
    _backfill_photo_fingerprints()
    bootstrap_environment_users()
    bootstrap_demo_camp_users()


def get_staff_user(username):
    with get_connection() as connection:
        return connection.execute(
            "SELECT id, username, password_hash, role, camp_id, active "
            "FROM staff_users WHERE username = %s AND active = TRUE",
            (username,),
        ).fetchone()


def fetch_people(filters=None):
    filters = filters or {}
    clauses = [
        "NOT EXISTS (SELECT 1 FROM reunification_cases closed_case "
        "WHERE closed_case.missing_person_id = people.id AND closed_case.status = 'CLOSED')"
    ]
    params = []

    if filters.get("name"):
        clauses.append(
            "(full_name ILIKE %s OR alternate_name ILIKE %s OR relative_name ILIKE %s "
            "OR known_relative_name ILIKE %s OR father_or_guardian_name ILIKE %s "
            "OR mother_name ILIKE %s OR emergency_contact_name ILIKE %s)"
        )
        term = f"%{filters['name']}%"
        params.extend((term,) * 7)
    for key, column in (("family_id", "family_id"), ("address", "address"), ("camp", "camp_name")):
        if filters.get(key):
            term = f"%{filters[key]}%"
            if key == "address":
                clauses.append("(address ILIKE %s OR full_address ILIKE %s)")
                params.extend((term, term))
            elif key == "camp":
                clauses.append("(camp_name ILIKE %s OR registered_camp ILIKE %s)")
                params.extend((term, term))
            else:
                clauses.append(f"{column} ILIKE %s")
                params.append(term)

    query = "SELECT * FROM people"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY full_name, id"
    with get_connection() as connection:
        return connection.execute(query, params).fetchall()


def insert_person(person):
    columns = (
        "full_name", "alternate_name", "age", "gender", "family_id",
        "relative_name", "camp_name", "address", "status",
    )
    values = [person.get(column) for column in columns]
    placeholders = ", ".join(["%s"] * len(columns))
    with get_connection() as connection:
        person = connection.execute(
            f"INSERT INTO people ({', '.join(columns)}) VALUES ({placeholders}) RETURNING *",
            values,
        ).fetchone()
        if person["status"] == "missing":
            connection.execute(
                "INSERT INTO reunification_cases (missing_person_id) VALUES (%s) ON CONFLICT (missing_person_id) DO NOTHING",
                (person["id"],),
            )
        return person


def get_stats():
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) AS total FROM people").fetchone()["total"]
        camps = connection.execute(
            "SELECT camp_name, COUNT(*) AS count FROM people "
            "GROUP BY camp_name ORDER BY camp_name"
        ).fetchall()
    return {"total_people": total, "camps": camps}


def record_review(person_id, candidate_id, officer_username, action, note):
    with get_connection() as connection:
        return connection.execute(
            "INSERT INTO match_reviews "
            "(person_id, candidate_id, officer_username, action, note) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING *",
            (person_id, candidate_id, officer_username, action, note),
        ).fetchone()


def person_exists(person_id):
    with get_connection() as connection:
        return connection.execute(
            "SELECT 1 FROM people WHERE id = %s", (person_id,)
        ).fetchone() is not None


def main():
    import sys

    if len(sys.argv) != 2 or sys.argv[1] != "init":
        print("Usage: py database.py init")
        raise SystemExit(2)
    initialize_database()
    print("Database schema initialized.")


if __name__ == "__main__":
    main()