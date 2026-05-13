from __future__ import annotations

import math
import os
from dataclasses import dataclass

from secure_review.models import SanitizedDocument
from secure_review.reviewer import SYSTEM_PROMPT, build_prompt
from secure_review.rubric import choose_rubric


@dataclass(frozen=True)
class TokenBudgetEstimate:
    provider_mode: str
    review_mode: str
    call_count: int
    body_tokens: int
    total_input_tokens: int
    max_call_input_tokens: int
    max_output_tokens_per_call: int
    estimated_output_token_cap: int
    status: str
    reasons: tuple[str, ...]


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text) / 4))


def estimate_review_token_budget(
    documents: list[SanitizedDocument],
    document_profile_override: str | None = None,
    *,
    provider_mode: str | None = None,
) -> TokenBudgetEstimate:
    provider = (provider_mode or os.getenv("REVIEW_PROVIDER", "mock")).strip().lower()
    external_provider = provider not in {"", "mock"}
    chunked = _uses_chunking(provider, len(documents))
    rubric = choose_rubric(documents, document_profile_override)

    body_tokens = sum(int(getattr(doc, "estimated_input_tokens", 0) or 0) for doc in documents)
    system_tokens = estimate_tokens(SYSTEM_PROMPT)

    if chunked:
        call_inputs = [
            system_tokens + estimate_tokens(build_prompt([doc], rubric))
            for doc in documents
        ]
        review_mode = "chunked"
    else:
        call_inputs = [system_tokens + estimate_tokens(build_prompt(documents, rubric))]
        review_mode = "single_call"

    max_output = _max_output_tokens_for(provider)
    total_input = sum(call_inputs)
    max_call = max(call_inputs, default=0)
    output_cap = max_output * max(1, len(call_inputs))
    status, reasons = _classify_budget(
        call_count=len(call_inputs),
        max_call_input_tokens=max_call,
        total_input_tokens=total_input,
        external_provider=external_provider,
    )

    return TokenBudgetEstimate(
        provider_mode=provider or "mock",
        review_mode=review_mode,
        call_count=len(call_inputs),
        body_tokens=body_tokens,
        total_input_tokens=total_input,
        max_call_input_tokens=max_call,
        max_output_tokens_per_call=max_output,
        estimated_output_token_cap=output_cap,
        status=status,
        reasons=reasons,
    )


def _uses_chunking(provider: str, document_count: int) -> bool:
    if document_count <= 1:
        return False
    if provider not in {"gemma", "gemma4", "gemma-4", "gemini-gemma", "gemma-gemini", "gemini", "gemini-api", "gemini-free", "gemini-free-tier"}:
        return False
    chunking_env = os.getenv("GEMINI_CHUNKING", "true").strip().lower()
    return chunking_env not in {"false", "0", "no", "off"}


def _max_output_tokens_for(provider: str) -> int:
    if provider in {"gemma", "gemma4", "gemma-4", "gemini-gemma", "gemma-gemini", "gemini", "gemini-api", "gemini-free", "gemini-free-tier"}:
        return _env_int("GEMINI_MAX_OUTPUT_TOKENS", 8192)
    return _env_int("LLM_MAX_OUTPUT_TOKENS", 4096)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def _classify_budget(
    *,
    call_count: int,
    max_call_input_tokens: int,
    total_input_tokens: int,
    external_provider: bool,
) -> tuple[str, tuple[str, ...]]:
    if not external_provider:
        return "mock", ("現在のプロバイダは mock のため、外部LLMトークンは消費しません。",)

    reasons: list[str] = []
    status = "safe"

    if max_call_input_tokens > 12000:
        status = "split_recommended"
        reasons.append("1回あたりの入力が大きいため、章単位または文書分割でのレビューを推奨します。")
    elif max_call_input_tokens > 8000:
        status = "caution"
        reasons.append("1回あたりの入力がやや大きく、応答遅延や失敗時の再試行コストが増えます。")

    if total_input_tokens > 50000:
        status = "split_recommended"
        reasons.append("合計入力が大きいため、複数回のAPI呼び出しでトークン消費が増えます。")
    elif total_input_tokens > 25000 and status == "safe":
        status = "caution"
        reasons.append("合計入力がやや大きく、無料枠・レート制限への影響が出やすくなります。")

    if call_count >= 8:
        status = "split_recommended"
        reasons.append("LLM呼び出し回数が多く、無料枠・レート制限・待ち時間への影響が大きくなります。")
    elif call_count >= 4 and status == "safe":
        status = "caution"
        reasons.append("複数文書のためLLM呼び出し回数が増えます。")

    if not reasons:
        reasons.append("通常のレビュー範囲として扱える見込みです。")
    return status, tuple(reasons)
