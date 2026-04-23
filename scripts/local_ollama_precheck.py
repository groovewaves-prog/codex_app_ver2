from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from secure_review.env_loader import load_dotenv
from secure_review.extractor import extract_text
from secure_review.sanitizer import SensitiveDataSanitizer, choose_local_sanitization_enhancer
from secure_review.sensitivity import choose_sensitivity_classifier


DEFAULT_SAMPLE_TEXT = """customer-name Acme Corp
site-name Tokyo-DC-01
contact Sato
project Backbone renewal
hostname tokyo-rtr-01
password superSecret!
purpose network migration
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify local Ollama / Gemma3-12b sanitization and sensitivity checks.",
    )
    parser.add_argument(
        "--input-file",
        help="Optional file to run through local extraction, sanitization, and sensitivity checks.",
    )
    parser.add_argument(
        "--document-name",
        help="Optional display name when using --input-file.",
    )
    parser.add_argument(
        "--print-preview-chars",
        type=int,
        default=500,
        help="Preview length to print in the console.",
    )
    args = parser.parse_args()

    load_dotenv()

    sanitizer = SensitiveDataSanitizer()
    local_sanitizer = choose_local_sanitization_enhancer()
    sensitivity_classifier = choose_sensitivity_classifier()

    print("== Environment summary ==")
    print(f"LOCAL_SANITIZER_PROVIDER={os.getenv('LOCAL_SANITIZER_PROVIDER', '') or '-'}")
    print(f"LOCAL_SANITIZER_MODEL={os.getenv('LOCAL_SANITIZER_MODEL', '') or '-'}")
    print(f"LOCAL_SENSITIVITY_PROVIDER={os.getenv('LOCAL_SENSITIVITY_PROVIDER', '') or '-'}")
    print(f"LOCAL_SENSITIVITY_MODEL={os.getenv('LOCAL_SENSITIVITY_MODEL', '') or '-'}")
    print()

    if local_sanitizer.name in {"ollama", "local-http"}:
        verify_local_model(
            os.getenv("LOCAL_SANITIZER_API_URL", "").strip() or "http://127.0.0.1:11434/v1/responses",
            os.getenv("LOCAL_SANITIZER_MODEL", "").strip() or "gemma3:12b",
            "local sanitizer",
        )
    if sensitivity_classifier.name in {"ollama", "local-http"}:
        verify_local_model(
            os.getenv("LOCAL_SENSITIVITY_API_URL", "").strip() or "http://127.0.0.1:11434/v1/responses",
            os.getenv("LOCAL_SENSITIVITY_MODEL", "").strip() or "gemma3:12b",
            "local sensitivity gate",
        )

    document_name, extracted_text, extraction_warnings = load_input(args.input_file, args.document_name)
    if extraction_warnings:
        print("== Extraction warnings ==")
        for warning in extraction_warnings:
            print(f"- {warning}")
        print()

    initial = sanitizer.sanitize(document_name, extracted_text)
    enhanced = local_sanitizer.enhance(document_name, extracted_text, initial, sanitizer)
    assessment = sensitivity_classifier.assess(document_name, extracted_text, enhanced)

    print(f"== Document: {document_name} ==")
    print(f"Original chars: {len(extracted_text)}")
    print(f"Initial replacement count: {len(initial.replacements)}")
    print(f"Enhanced replacement count: {len(enhanced.replacements)}")
    print(f"Outbound risk: {enhanced.outbound_risk}")
    print(f"Local sensitivity decision: {assessment.decision}")
    print(f"Local sanitizer provider: {enhanced.local_sanitizer_provider or local_sanitizer.name}")
    print(f"Local sensitivity provider: {assessment.provider}")
    print()

    print("== Findings ==")
    for item in enhanced.findings or ["-"]:
        print(f"- {item}")
    if assessment.reasons:
        print("== Sensitivity reasons ==")
        for reason in assessment.reasons:
            print(f"- {reason}")
    print()

    preview_chars = max(80, args.print_preview_chars)
    print("== Sanitized preview ==")
    print(enhanced.outbound_text[:preview_chars])
    print()

    if assessment.decision == "block":
        print("RESULT: BLOCKED for external transfer. Prepare a more strongly sanitized copy first.")
        return 2

    if assessment.decision == "mask_and_continue":
        print("RESULT: Additional review recommended before external transfer.")
        return 0

    print("RESULT: Local pre-check passed.")
    return 0


def load_input(input_file: str | None, document_name: str | None) -> tuple[str, str, list[str]]:
    if not input_file:
        return "sample.txt", DEFAULT_SAMPLE_TEXT, []

    path = Path(input_file)
    if not path.is_file():
        raise FileNotFoundError(f"Input file was not found: {path}")

    raw = path.read_bytes()
    content = base64.b64encode(raw).decode("ascii")
    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    extracted_text, warnings = extract_text(
        document_name or path.name,
        content,
        content_type,
        "base64",
    )
    return document_name or path.name, extracted_text, warnings


def verify_local_model(api_url: str, expected_model: str, label: str) -> None:
    tags_url = derive_tags_url(api_url)
    print(f"== Checking {label} ==")
    print(f"API: {api_url}")
    print(f"Expected model: {expected_model}")

    try:
        payload = get_json(tags_url)
    except RuntimeError as exc:
        raise RuntimeError(f"Could not connect to local Ollama at {tags_url}: {exc}") from exc

    models = [item.get("name", "") for item in payload.get("models", [])]
    print(f"Available models: {', '.join(models) if models else '(none)'}")

    if expected_model not in models:
        raise RuntimeError(
            f"Model {expected_model!r} was not found in Ollama. Run `ollama pull {expected_model}` first."
        )
    print("PASS")
    print()


def derive_tags_url(api_url: str) -> str:
    parsed = urllib.parse.urlparse(api_url)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError(f"Invalid API URL: {api_url}")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/api/tags", "", "", ""))


def get_json(url: str) -> dict:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON response: {raw[:200]}") from exc


if __name__ == "__main__":
    sys.exit(main())
