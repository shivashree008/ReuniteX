import csv
import os
import sys
import uuid
from datetime import date
from pathlib import Path

import database
from database import get_connection
from psycopg.types.json import Jsonb


CSV_COLUMNS = (
    "person_id", "family_id", "full_name", "alternate_name", "age", "date_of_birth",
    "gender", "family_head", "relationship_to_head", "father_or_guardian_name",
    "mother_name", "primary_language", "house_number", "street", "area",
    "village_or_town", "district", "state", "postal_code", "full_address",
    "emergency_contact_name", "emergency_contact_phone_demo", "known_relative_name",
    "known_relative_relationship", "last_known_location", "registered_camp",
    "disaster_status", "assistance_needed", "registration_date", "record_source",
    "identity_verification_status", "notes",
)
IMPORT_COLUMNS = CSV_COLUMNS + ("relative_name", "camp_name", "address", "status")


def _json_safe_record(record):
    safe = {}
    for key, value in record.items():
        if isinstance(value, date):
            safe[key] = value.isoformat()
        elif isinstance(value, uuid.UUID):
            safe[key] = str(value)
        else:
            safe[key] = value
    return safe


def default_csv_path():
    configured_path = os.getenv("CSV_PATH", "").strip()
    return Path(configured_path) if configured_path else Path.home() / "Downloads" / "reunite_50_people_detailed.csv"


def read_source_records(source_path=None):
    path = Path(source_path) if source_path else default_csv_path()
    with path.open(encoding="utf-8-sig", newline="") as source_file:
        reader = csv.DictReader(source_file)
        if tuple(reader.fieldnames or ()) != CSV_COLUMNS:
            raise ValueError("CSV headers do not match the expected 32-column source format.")
        raw_records = list(reader)

    if len(raw_records) != 50:
        raise ValueError(f"Expected exactly 50 source records; found {len(raw_records)}.")

    person_ids = [record.get("person_id", "") for record in raw_records]
    if any(not person_id.strip() for person_id in person_ids):
        raise ValueError("Every CSV record must have a person_id.")
    if len(set(person_ids)) != len(person_ids):
        raise ValueError("CSV person_id values must be unique.")

    records = []
    for row in raw_records:
        record = dict(row)
        try:
            record["age"] = int(row["age"]) if row["age"] else None
            if record["age"] is not None and not 0 <= record["age"] <= 120:
                raise ValueError
            for field in ("date_of_birth", "registration_date"):
                record[field] = date.fromisoformat(row[field]) if row[field] else None
        except ValueError as error:
            raise ValueError(f"Invalid age or date in CSV record {row['person_id']}.") from error

        source_status = row["disaster_status"].strip().casefold()
        if source_status.startswith("missing"):
            normalized_status = "missing"
        elif source_status.startswith("survivor"):
            normalized_status = "survivor"
        elif source_status.startswith("registered"):
            normalized_status = "registered"
        else:
            raise ValueError(f"Unsupported disaster_status in CSV record {row['person_id']}.")

        address = row["full_address"] or ", ".join(
            value for value in (row["house_number"], row["street"], row["area"], row["village_or_town"], row["district"], row["state"], row["postal_code"]) if value
        )
        record.update({
            "relative_name": row["known_relative_name"] or row["emergency_contact_name"] or row["family_head"],
            "camp_name": row["registered_camp"] or "Not assigned",
            "address": address,
            "status": normalized_status,
        })
        records.append(record)
    return records


def seed(source_path=None):
    database.initialize_database()
    records = read_source_records(source_path)
    with get_connection() as connection:
        camp_names = sorted({record["registered_camp"] for record in records if record["registered_camp"] and record["registered_camp"] != "Not assigned"})
        for camp_name in camp_names:
            connection.execute(
                "INSERT INTO camps (name) VALUES (%s) ON CONFLICT (name) DO NOTHING",
                (camp_name,),
            )
        family_ids = sorted({record["family_id"] for record in records if record["family_id"]})
        for family_id in family_ids:
            member = next(record for record in records if record["family_id"] == family_id)
            connection.execute(
                "INSERT INTO families (family_id, family_head, household_address) VALUES (%s, %s, %s) "
                "ON CONFLICT (family_id) DO UPDATE SET family_head = EXCLUDED.family_head, "
                "household_address = EXCLUDED.household_address",
                (family_id, member["family_head"], member["address"]),
            )
        camps = connection.execute("SELECT id, name FROM camps").fetchall()
        families = connection.execute("SELECT id, family_id FROM families").fetchall()
        camp_ids = {camp["name"]: camp["id"] for camp in camps}
        family_uuids = {family["family_id"]: family["id"] for family in families}
        columns = IMPORT_COLUMNS + ("camp_id", "family_uuid")
        placeholders = ", ".join(["%s"] * len(columns))
        updates = ", ".join(f"{column} = EXCLUDED.{column}" for column in columns[1:])
        query = (
            f"INSERT INTO people ({', '.join(columns)}) VALUES ({placeholders}) "
            f"ON CONFLICT (person_id) DO UPDATE SET {updates}"
        )
        for record in records:
            record["camp_id"] = camp_ids.get(record["registered_camp"])
            record["family_uuid"] = family_uuids.get(record["family_id"])
        values = [tuple(record[column] for column in columns) for record in records]
        person_ids = [record["person_id"] for record in records]
        count_placeholders = ", ".join(["%s"] * len(person_ids))
        with connection.cursor() as cursor:
            cursor.executemany(query, values)
        people = connection.execute(
            "SELECT id, person_id FROM people WHERE person_id = ANY(%s)",
            (person_ids,),
        ).fetchall()
        internal_ids = {person["person_id"]: person["id"] for person in people}
        for record in records:
            if not record["camp_id"] or record["status"] not in {"missing", "survivor"}:
                continue
            record_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"reunite-ai:csv:{record['person_id']}")
            person_pk = internal_ids[record["person_id"]]
            connection.execute(
                "INSERT INTO camp_records (id, camp_id, record_type, person_id, payload) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET "
                "camp_id = EXCLUDED.camp_id, record_type = EXCLUDED.record_type, "
                "person_id = EXCLUDED.person_id, payload = EXCLUDED.payload",
                (record_uuid, record["camp_id"], record["status"], person_pk, Jsonb(_json_safe_record(record))),
            )
            record_table = "missing_reports" if record["status"] == "missing" else "survivor_registrations"
            connection.execute(
                f"INSERT INTO {record_table} (record_id, camp_id, person_id, payload) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (record_id) DO UPDATE SET camp_id = EXCLUDED.camp_id, "
                "person_id = EXCLUDED.person_id, payload = EXCLUDED.payload",
                (record_uuid, record["camp_id"], person_pk, Jsonb(_json_safe_record(record))),
            )
        database_count = connection.execute(
            f"SELECT COUNT(*) AS count FROM people WHERE person_id IN ({count_placeholders})",
            person_ids,
        ).fetchone()["count"]
    print(f"Imported or updated {len(records)} CSV records; database records for these IDs: {database_count}.")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("Usage: py seed.py [path-to-csv]")
    seed(sys.argv[1] if len(sys.argv) == 2 else None)