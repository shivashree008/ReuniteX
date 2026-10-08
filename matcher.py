import json
import os
import re
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from rapidfuzz import fuzz

from database import fetch_people


WEIGHTS = {
    "name": 0.55,
    "alternate_name": 0.15,
    "relative_name": 0.15,
    "age": 0.05,
    "family_id": 0.05,
    "address": 0.05,
}
MATCH_LABEL = "Potential Match — Human Verification Required"
RELATIVE_FIELDS = (
    "relative_name", "known_relative_name", "father_or_guardian_name",
    "mother_name", "emergency_contact_name", "family_head",
)


def normalize_text(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _similarity(left, right):
    left_normalized = normalize_text(left)
    right_normalized = normalize_text(right)
    if not left_normalized or not right_normalized:
        return None
    return float(fuzz.ratio(left_normalized, right_normalized))


def score_candidate(query, candidate):
    name_score = _similarity(query["name"], candidate.get("full_name"))
    alt_score = _similarity(query["name"], candidate.get("alternate_name"))

    relative_options = [
        _similarity(query["name"], candidate.get(field)) for field in RELATIVE_FIELDS
    ]
    relative_options.extend(
        _similarity(query.get("relative_name"), candidate.get(field))
        for field in ("full_name", *RELATIVE_FIELDS)
    )
    relative_options = [score for score in relative_options if score is not None]
    relative_score = max(relative_options) if relative_options else None

    age_score = None
    if query.get("age") is not None and candidate.get("age") is not None:
        age_score = max(0.0, 100.0 - abs(query["age"] - candidate["age"]) * 20.0)

    family_score = None
    if query.get("family_id"):
        family_score = 100.0 if normalize_text(query["family_id"]) == normalize_text(candidate.get("family_id")) else 0.0

    address_score = None
    if query.get("address"):
        address_score = _similarity(query["address"], candidate.get("address") or candidate.get("full_address"))

    clues = {
        "name": name_score,
        "alternate_name": alt_score,
        "relative_name": relative_score,
        "age": age_score,
        "family_id": family_score,
        "address": address_score,
    }
    available = [(WEIGHTS[key], score) for key, score in clues.items() if score is not None]
    combined = sum(weight * score for weight, score in available) / sum(weight for weight, _ in available)
    return {
        "person": candidate,
        "clue_scores": {key: round(score, 1) if score is not None else None for key, score in clues.items()},
        "combined_score": round(combined, 1),
        "label": MATCH_LABEL,
    }


def rank_people(query, people, limit=5):
    ranked = []
    source_id = query.get("person_id")
    for person in people:
        if source_id is not None and person.get("id") == source_id:
            continue
        ranked.append(score_candidate(query, person))
    ranked.sort(key=lambda item: (item["combined_score"], item["clue_scores"]["name"] or 0), reverse=True)
    return ranked[:limit]


def find_matches(name, age=None, relative_name=None, family_id=None, address=None, person_id=None, limit=5):
    query = {
        "name": name,
        "age": age,
        "relative_name": relative_name,
        "family_id": family_id,
        "address": address,
        "person_id": person_id,
    }
    return rank_people(query, fetch_people(), limit=limit)


def _local_ollama_base_url():
    configured = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    parsed = urlsplit(configured)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return None
    return configured


def ollama_available(model=None):
    base_url = _local_ollama_base_url()
    if not base_url:
        return False
    model = model or os.getenv("OLLAMA_MODEL", "qwen3:4b")
    try:
        with urlopen(f"{base_url}/api/tags", timeout=1.5) as response:
            models = json.loads(response.read().decode("utf-8")).get("models", [])
        return any(item.get("name") == model or item.get("name", "").startswith(f"{model}:") for item in models)
    except (OSError, URLError, ValueError):
        return False


def explain_with_ollama(matches, model=None):
    base_url = _local_ollama_base_url()
    model = model or os.getenv("OLLAMA_MODEL", "qwen3:4b")
    if not matches:
        return None
    if not base_url or not ollama_available(model):
        return deterministic_explanation(matches)
    evidence = [{"score": match["combined_score"], "clues": match["clue_scores"]} for match in matches]
    payload = {
        "model": model,
        "stream": False,
        "prompt": (
            "Return only valid JSON with keys summary, supporting_clues, conflicting_clues, "
            "missing_information, verification_questions. Use short strings and arrays. "
            "Only describe the supplied numeric clues. Do not infer identity or relationships, "
            "invent evidence, or claim certainty. State human verification is mandatory. Evidence: "
            + json.dumps(evidence, ensure_ascii=True)
        ),
        "options": {"temperature": 0},
    }
    request = Request(
        f"{base_url}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
        explanation = json.loads(result.get("response", ""))
        required = ("summary", "supporting_clues", "conflicting_clues", "missing_information", "verification_questions")
        if not isinstance(explanation, dict) or any(key not in explanation for key in required):
            return deterministic_explanation(matches)
        if not isinstance(explanation["summary"], str) or any(
            not isinstance(explanation[key], list) or not all(isinstance(item, str) for item in explanation[key])
            for key in required[1:]
        ):
            return deterministic_explanation(matches)
        explanation["human_verification_required"] = True
        return explanation
    except (OSError, URLError, ValueError, TypeError, AttributeError):
        return deterministic_explanation(matches)


def deterministic_explanation(matches):
    scores = matches[0].get("clue_scores", {})
    supporting = [key.replace("_", " ") for key, value in scores.items() if value is not None and value >= 60]
    conflicting = [key.replace("_", " ") for key, value in scores.items() if value is not None and value < 35]
    missing = [key.replace("_", " ") for key, value in scores.items() if value is None]
    return {
        "summary": "RapidFuzz ranked this candidate from the available comparison clues; no identity or relationship is established.",
        "supporting_clues": supporting,
        "conflicting_clues": conflicting,
        "missing_information": missing,
        "verification_questions": ["Which independent records or interviews support the proposed connection?", "Do any details contradict this candidate?"],
        "human_verification_required": True,
    }


if __name__ == "__main__":
    examples = [
        ("Arunkumar", "Arun Kumar"),
        ("Karthick", "Karthik"),
    ]
    for search, candidate in examples:
        result = score_candidate({"name": search}, {"full_name": candidate})
        print(f"{search} / {candidate}: {result['combined_score']:.1f}")