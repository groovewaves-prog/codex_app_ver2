#!/usr/bin/env python3
"""Local Ollama pre-check.

Verifies that the locally configured sanitizer/sensitivity endpoints:

1. Point to a loopback address (refuses otherwise; required by R1).
2. Respond to a small synthetic sanitization request.
3. Optionally runs the full pipeline on a user-supplied file so operators
   can validate a real document before the Streamlit workflow.

Usage::

    python scripts/local_ollama_precheck.py
    python scripts/local_ollama_precheck.py --input-file path/to/doc.docx

Environment variables consumed:
    LOCAL_SANITIZER_API_URL
    LOCAL_SANITIZER_MODEL
    LOCAL_SANITIZER_API_KEY (optional)
    LOCAL_SENSITIVITY_API_URL
    LOCAL_SENSITIVITY_MODEL
    LOCAL_SENSITIVITY_API_KEY (optional)
"""

from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import sys
from pathlib import Path

# Allow running from the repository root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secure_review.env_loader import load_dotenv
from secure_review.extractor import extract_text
from secure_review.network_guard import (
    LocalUrlError,
    UpstreamHttpError,
    post_json_safely,
    validate_local_url,
)
from secure_review.sanitizer import SensitiveDataSanitizer, choose_local_sanitization_enhancer
from secure_review.sensitivity import choose_sensitivity_classifier


SAMPLE_TEXT = (
    "customer-name Acme Corp\n"
    "site-name Tokyo-DC-01\n"
    "password superSecret!\n"
    "ip address 10.1.2.3 255.255.255.0"
)


def _check_endpoint(url_env: str, model_env: str, key_env: str, label: str) -> bool:
    url = os.getenv(url_env, "").strip()
    model = os.getenv(model_env, "").strip()
    key = os.getenv(key_env, "").strip()

    print(f"=== {label} ===")
    if not url or not model:
        print(f"  skipped: {url_env} or {model_env} not set.")
        return True  # not configured = not failed

    try:
        validate_local_url(url, label=url_env)
    except LocalUrlError as exc:
        print(f"  FAIL: {exc}")
        return False

    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": "Return a JSON object with a 'sanitized_text' field."},
            {"role": "user", "content": SAMPLE_TEXT},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        response = post_json_safely(url, payload, headers, context_label=label)
    except UpstreamHttpError as exc:
        print(f"  FAIL: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"  FAIL: unexpected error: {exc}")
        return False

    # Minimal shape check — we do not trust the content.
    if isinstance(response, dict) and (
        "output_text" in response or "output" in response or "choices" in response
    ):
        print(f"  OK: {url} (model={model})")
        return True

    print("  WARN: response did not match any known OpenAI-compatible shape.")
    print(f"  First 200 chars: {json.dumps(response, ensure_ascii=False)[:200]}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pre-flight check for the local sanitizer and sensitivity gate."
    )
    parser.add_argument(
        "--input-file",
        help=(
            "Optional path to a real document. If supplied, the full "
            "extract -> sanitize -> sensitivity pipeline is run on the file "
            "and the per-document result is printed."
        ),
    )
    parser.add_argument(
        "--document-name",
        help="Display name for the input file (defaults to the basename).",
    )
    parser.add_argument(
        "--print-preview-chars",
        type=int,
        default=500,
        help="How many characters of the sanitized preview to print.",
    )
    args = parser.parse_args()

    load_dotenv()

    # 1. endpoint checks always run
    endpoint_results = [
        _check_endpoint(
            "LOCAL_SANITIZER_API_URL",
            "LOCAL_SANITIZER_MODEL",
            "LOCAL_SANITIZER_API_KEY",
            "local sanitizer",
        ),
        _check_endpoint(
            "LOCAL_SENSITIVITY_API_URL",
            "LOCAL_SENSITIVITY_MODEL",
            "LOCAL_SENSITIVITY_API_KEY",
            "local sensitivity gate",
        ),
    ]

    # 2. optional full-pipeline check on a user-supplied file
    pipeline_result = True
    if args.input_file:
        pipeline_result = _run_pipeline_on_file(
            Path(args.input_file),
            args.document_name,
            args.print_preview_chars,
        )

    if all(endpoint_results) and pipeline_result:
        print("\nAll configured checks passed.")
        return 0
    print("\nOne or more checks failed. Review the messages above.")
    return 1


def _run_pipeline_on_file(
    path: Path,
    display_name: str | None,
    preview_chars: int,
) -> bool:
    print(f"\n=== pipeline check on {path} ===")
    if not path.is_file():
        print(f"  FAIL: input file not found: {path}")
        return False

    try:
        raw = path.read_bytes()
        content = base64.b64encode(raw).decode("ascii")
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

        name = display_name or path.name
        extracted_text, warnings = extract_text(name, content, content_type, "base64")
        for warning in warnings:
            print(f"  extractor warning: {warning}")

        sanitizer = SensitiveDataSanitizer()
        local_sanitizer = choose_local_sanitization_enhancer()
        gate = choose_sensitivity_classifier()

        sanitized = sanitizer.sanitize(name, extracted_text)
        sanitized = local_sanitizer.enhance(name, extracted_text, sanitized, sanitizer)
        assessment = gate.assess(name, extracted_text, sanitized)

        print(f"  extracted chars : {len(extracted_text)}")
        print(f"  replacements    : {len(sanitized.replacements)}")
        print(f"  outbound risk   : {sanitized.outbound_risk}")
        print(f"  gate decision   : {assessment.decision}")
        print(f"  gate provider   : {assessment.provider}")
        if assessment.reasons:
            print("  gate reasons    :")
            for reason in assessment.reasons:
                print(f"    - {reason}")
        preview = (sanitized.sanitized_excerpt or "")[: max(preview_chars, 0)]
        if preview:
            print(f"  sanitized preview (first {len(preview)} chars):")
            print("    " + preview.replace("\n", "\n    "))

        if assessment.decision == "block":
            print("  RESULT: BLOCKED. Do not transfer externally.")
        elif assessment.decision == "mask_and_continue":
            print("  RESULT: needs explicit confirmation in the UI.")
        else:
            print("  RESULT: safe (sanitized text only).")
        return True
    except LocalUrlError as exc:
        print(f"  FAIL: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"  FAIL: pipeline error: {exc}")
        return False


if __name__ == "__main__":
    sys.exit(main())
