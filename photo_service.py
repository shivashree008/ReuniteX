import base64
import hashlib
import io
import json
import math
import os
import statistics
import threading
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from PIL import Image, ImageChops, ImageOps, ImageStat, UnidentifiedImageError
from psycopg.types.json import Jsonb

import database


PROJECT_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000
MAX_RETRIES = 5
MAX_REENCODED_COPY_MAE = 1.5
DESCRIPTION_FIELDS = (
    "clothing", "clothing_color", "hairstyle", "hair_color", "glasses",
    "accessories", "carried_objects", "surroundings", "image_quality", "uncertainty",
)
DESCRIPTION_SCHEMA = {
    "type": "object",
    "properties": {field: {"type": "string"} for field in DESCRIPTION_FIELDS},
    "required": list(DESCRIPTION_FIELDS),
    "additionalProperties": False,
}
_worker_lock = threading.Lock()
_worker_started = False
_worker_stop = threading.Event()
_DCT_SIZE = 32
_DCT_HASH_SIZE = 8
_DCT_BASIS = tuple(
    tuple(
        (1 / math.sqrt(_DCT_SIZE) if frequency == 0 else math.sqrt(2 / _DCT_SIZE))
        * math.cos((2 * position + 1) * frequency * math.pi / (2 * _DCT_SIZE))
        for position in range(_DCT_SIZE)
    )
    for frequency in range(_DCT_HASH_SIZE)
)


class PhotoValidationError(ValueError):
    pass


class VisionUnavailable(RuntimeError):
    pass


def storage_root():
    configured = os.getenv("PHOTO_STORAGE_DIR", "").strip()
    root = Path(configured) if configured else PROJECT_DIR / "instance" / "private_photos"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def sanitize_image(content, declared_mimetype=""):
    if not content:
        raise PhotoValidationError("Choose an image to upload.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise PhotoValidationError("Images must be 8 MB or smaller.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(content)) as probe:
                image_format = probe.format
                probe.verify()
            if image_format not in {"JPEG", "PNG", "WEBP"}:
                raise PhotoValidationError("Use a JPEG, PNG, or WebP image.")
            with Image.open(io.BytesIO(content)) as source:
                if source.width * source.height > MAX_IMAGE_PIXELS:
                    raise PhotoValidationError("Image dimensions exceed the 25 megapixel limit.")
                image = ImageOps.exif_transpose(source)
                source_width, source_height = image.size
                image.thumbnail((2048, 2048), Image.Resampling.LANCZOS)
                if image_format == "JPEG":
                    image = image.convert("RGB")
                    output_format, mimetype, suffix = "JPEG", "image/jpeg", ".jpg"
                    save_options = {"quality": 84, "optimize": True, "progressive": True}
                elif image_format == "PNG":
                    output_format, mimetype, suffix = "PNG", "image/png", ".png"
                    save_options = {"optimize": True}
                else:
                    if image.mode not in {"RGB", "RGBA"}:
                        image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                    output_format, mimetype, suffix = "WEBP", "image/webp", ".webp"
                    save_options = {"quality": 84, "method": 5}
                sanitized = io.BytesIO()
                image.save(sanitized, format=output_format, **save_options)
                return sanitized.getvalue(), mimetype, source_width, source_height, suffix
    except PhotoValidationError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise PhotoValidationError("Image dimensions are unsafe to process.") from None
    except (UnidentifiedImageError, OSError, ValueError):
        raise PhotoValidationError("The uploaded file is not a supported, readable image.") from None


def normalized_pixel_hash(content):
    with Image.open(io.BytesIO(content)) as source:
        image = ImageOps.exif_transpose(source).convert("RGBA")
        digest = hashlib.sha256()
        digest.update(image.width.to_bytes(4, "big"))
        digest.update(image.height.to_bytes(4, "big"))
        digest.update(image.tobytes())
    return digest.hexdigest()


def perceptual_hash(content):
    with Image.open(io.BytesIO(content)) as source:
        image = ImageOps.exif_transpose(source).convert("L").resize(
            (_DCT_SIZE, _DCT_SIZE), Image.Resampling.LANCZOS
        )
        pixels = list(image.tobytes())
    horizontal = [
        [sum(pixels[row * _DCT_SIZE + column] * _DCT_BASIS[u][column] for column in range(_DCT_SIZE)) for u in range(_DCT_HASH_SIZE)]
        for row in range(_DCT_SIZE)
    ]
    coefficients = [
        sum(horizontal[row][u] * _DCT_BASIS[v][row] for row in range(_DCT_SIZE))
        for v in range(_DCT_HASH_SIZE)
        for u in range(_DCT_HASH_SIZE)
    ]
    threshold = statistics.median(coefficients[1:])
    value = 0
    for coefficient in coefficients:
        value = (value << 1) | (coefficient > threshold)
    return f"{value:016x}"


def image_fingerprints(content):
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "normalized_sha256": normalized_pixel_hash(content),
        "perceptual_hash": perceptual_hash(content),
    }


def perceptual_distance(left, right):
    if not isinstance(left, str) or not isinstance(right, str) or len(left) != 16 or len(right) != 16:
        return 64
    try:
        return (int(left, 16) ^ int(right, 16)).bit_count()
    except ValueError:
        return 64


def reencoded_image_copy_mae(left_content, right_content):
    try:
        with Image.open(io.BytesIO(left_content)) as left_source, Image.open(io.BytesIO(right_content)) as right_source:
            left_image = ImageOps.exif_transpose(left_source).convert("RGB")
            right_image = ImageOps.exif_transpose(right_source).convert("RGB")
            if left_image.size != right_image.size:
                return None
            channel_errors = ImageStat.Stat(ImageChops.difference(left_image, right_image)).mean
            return sum(channel_errors) / len(channel_errors)
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, UnidentifiedImageError, OSError, ValueError):
        return None


def _ollama_base_url():
    value = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return None
    return value


def vision_model_status():
    base_url = _ollama_base_url()
    if not base_url:
        return {"available": False, "model": None, "error": "Ollama must be configured on localhost."}
    try:
        with urlopen(f"{base_url}/api/tags", timeout=3) as response:
            models = json.loads(response.read().decode("utf-8")).get("models", [])
        vision_models = []
        for item in models:
            capabilities = item.get("capabilities") or []
            if "vision" in capabilities:
                vision_models.append(item.get("name"))
        configured = os.getenv("OLLAMA_MODEL", "").strip()
        preferred = "qwen2.5vl:3b"
        selected = next((name for name in vision_models if name == preferred), None)
        if not selected and configured in vision_models:
            selected = configured
        if not selected:
            selected = next(iter(vision_models), None)
        if not selected:
            return {"available": False, "model": None, "error": "No installed Ollama vision model was found."}
        return {"available": True, "model": selected, "vision_models": vision_models}
    except (OSError, URLError, HTTPError, ValueError, TypeError) as error:
        return {"available": False, "model": None, "error": str(error)[:200]}


def describe_image(content):
    status = vision_model_status()
    if not status["available"]:
        raise VisionUnavailable(status["error"])
    base_url = _ollama_base_url()
    prompt = (
        "Describe only directly observable, non-identifying visual details in this image. "
        "Do not identify the person or infer identity, ethnicity, nationality, health, age, or relationship. "
        "For every field use a concise observation or 'not observable'; include uncertainty when unclear. "
        "Return exactly the required JSON fields."
    )
    payload = {
        "model": status["model"],
        "stream": False,
        "format": DESCRIPTION_SCHEMA,
        "prompt": prompt,
        "images": [base64.b64encode(content).decode("ascii")],
        "options": {"temperature": 0},
    }
    request = Request(
        f"{base_url}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=90) as response:
            result = json.loads(response.read().decode("utf-8"))
        description = json.loads(result.get("response", ""))
        if not isinstance(description, dict) or set(description) != set(DESCRIPTION_FIELDS):
            raise ValueError("Ollama returned an invalid description schema.")
        for field in DESCRIPTION_FIELDS:
            value = description[field]
            if not isinstance(value, str) or len(value) > 500:
                raise ValueError("Ollama returned an invalid description field.")
            description[field] = value.strip()
        return status["model"], description
    except (OSError, URLError, HTTPError, ValueError, TypeError, AttributeError) as error:
        raise VisionUnavailable(str(error)[:300]) from error


def _safe_photo_path(storage_key):
    root = storage_root()
    path = (root / storage_key).resolve()
    if path.parent != root or path.name != storage_key:
        raise ValueError("Invalid private photo reference.")
    return path


def process_next_photo_job():
    with database.get_connection() as connection:
        job = connection.execute(
            "SELECT jobs.id, jobs.photo_id, jobs.attempts, jobs.max_attempts, photos.storage_key "
            "FROM photo_ai_jobs jobs JOIN person_photos photos ON photos.id = jobs.photo_id "
            "WHERE jobs.status IN ('queued', 'retry_wait') AND jobs.next_attempt_at <= CURRENT_TIMESTAMP "
            "AND photos.retained = TRUE ORDER BY jobs.created_at LIMIT 1 "
            "FOR UPDATE OF jobs SKIP LOCKED"
        ).fetchone()
        if not job:
            return False
        attempts = job["attempts"] + 1
        connection.execute(
            "UPDATE photo_ai_jobs SET status = 'processing', attempts = %s, started_at = CURRENT_TIMESTAMP, last_error = NULL WHERE id = %s",
            (attempts, job["id"]),
        )
    try:
        content = _safe_photo_path(job["storage_key"]).read_bytes()
        model_name, description = describe_image(content)
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO photo_descriptions (photo_id, description, source, model_name, review_status) "
                "VALUES (%s, %s, 'ollama', %s, 'pending') ON CONFLICT (photo_id) DO UPDATE SET "
                "description = EXCLUDED.description, source = 'ollama', model_name = EXCLUDED.model_name, "
                "review_status = 'pending', analyzed_at = CURRENT_TIMESTAMP, updated_by = NULL",
                (job["photo_id"], Jsonb(description), model_name),
            )
            connection.execute(
                "UPDATE photo_ai_jobs SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = %s",
                (job["id"],),
            )
    except Exception as error:
        failed = attempts >= job["max_attempts"]
        next_attempt = datetime.now(timezone.utc) + timedelta(seconds=min(900, 5 * (2 ** (attempts - 1))))
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE photo_ai_jobs SET status = %s, next_attempt_at = %s, last_error = %s, "
                "completed_at = CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id = %s",
                ("failed" if failed else "retry_wait", next_attempt, str(error)[:500], failed, job["id"]),
            )
    return True


def _worker_loop():
    while not _worker_stop.is_set():
        try:
            worked = process_next_photo_job()
        except Exception:
            worked = False
        if not worked:
            _worker_stop.wait(2)


def start_photo_worker():
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE photo_ai_jobs SET status = 'retry_wait', next_attempt_at = CURRENT_TIMESTAMP, "
                "last_error = 'Worker restarted during analysis.' WHERE status = 'processing'"
            )
        thread = threading.Thread(target=_worker_loop, name="reunite-photo-ai", daemon=True)
        thread.start()
        _worker_started = True


def stop_photo_worker():
    _worker_stop.set()