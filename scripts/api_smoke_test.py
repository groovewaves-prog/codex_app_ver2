from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


OPENAI_URL = "https://api.openai.com/v1/responses"
HF_ROUTER_URL = "https://router.huggingface.co/v1/chat/completions"
DEFAULT_GEMMA_MODEL = "google/gemma-4-E4B-it"


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test LLM API access.")
    parser.add_argument(
        "--provider",
        choices=["openai", "gemma", "both"],
        default="both",
        help="Provider to test.",
    )
    parser.add_argument(
        "--gemma-model",
        default=DEFAULT_GEMMA_MODEL,
        help="Gemma model to test via Hugging Face Inference Providers.",
    )
    args = parser.parse_args()

    failures = 0

    if args.provider in {"openai", "both"}:
        failures += run_openai_test()

    if args.provider in {"gemma", "both"}:
        failures += run_gemma_test(args.gemma_model)

    if failures:
        print(f"\nCompleted with {failures} failing test(s).")
        return 1

    print("\nAll requested API smoke tests succeeded.")
    return 0


def run_openai_test() -> int:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        print("[openai] SKIP: OPENAI_API_KEY is not set.")
        return 1

    payload = {
        "model": "gpt-5.4",
        "input": "Reply with exactly: OPENAI_OK",
        "max_output_tokens": 20,
    }

    print("[openai] Testing gpt-5.4 via Responses API...")
    try:
        response = post_json(
            OPENAI_URL,
            payload,
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
    except RuntimeError as exc:
        print(f"[openai] FAIL: {exc}")
        return 1

    output_text = extract_openai_output_text(response)
    print(f"[openai] PASS: response_text={output_text!r}")
    return 0


def run_gemma_test(model: str) -> int:
    hf_token = os.getenv("HF_TOKEN", "").strip()
    if not hf_token:
        print("[gemma] SKIP: HF_TOKEN is not set.")
        return 1

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: GEMMA_OK"}],
        "max_tokens": 20,
        "temperature": 0,
    }

    print(f"[gemma] Testing {model} via Hugging Face router...")
    try:
        response = post_json(
            HF_ROUTER_URL,
            payload,
            {
                "Authorization": f"Bearer {hf_token}",
                "Content-Type": "application/json",
            },
        )
    except RuntimeError as exc:
        print(f"[gemma] FAIL: {exc}")
        return 1

    output_text = extract_chat_output_text(response)
    print(f"[gemma] PASS: response_text={output_text!r}")
    return 0


def post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON response: {raw[:400]}") from exc


def extract_openai_output_text(payload: dict) -> str:
    text = payload.get("output_text")
    if isinstance(text, str) and text:
        return text

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            piece = content.get("text")
            if piece:
                chunks.append(piece)
    return "\n".join(chunks).strip()


def extract_chat_output_text(payload: dict) -> str:
    choices = payload.get("choices", [])
    if not choices:
        return ""
    message = choices[0].get("message", {})
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        chunks = [item.get("text", "") for item in content if isinstance(item, dict)]
        return "\n".join(chunk for chunk in chunks if chunk).strip()
    return ""


if __name__ == "__main__":
    sys.exit(main())
