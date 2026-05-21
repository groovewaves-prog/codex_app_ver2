from __future__ import annotations

import math
import os
from dataclasses import dataclass

from secure_review.models import SanitizedDocument
from secure_review.reviewer import SYSTEM_PROMPT, build_prompt
from secure_review.rubric import choose_rubric


@dataclass(frozen=True)
class DocumentTokenEstimate:
    name: str
    body_tokens: int
    call_input_tokens: int


@dataclass(frozen=True)
class ReviewBatchSuggestion:
    label: str
    document_names: tuple[str, ...]
    call_count: int
    total_input_tokens: int


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
    document_estimates: tuple[DocumentTokenEstimate, ...] = ()
    suggested_batches: tuple[ReviewBatchSuggestion, ...] = ()
    minimum_wait_seconds: int = 0
    throttle_interval_seconds: float = 0.0


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

    document_estimates = tuple(
        DocumentTokenEstimate(
            name=doc.name,
            body_tokens=int(getattr(doc, "estimated_input_tokens", 0) or 0),
            call_input_tokens=system_tokens + estimate_tokens(build_prompt([doc], rubric)),
        )
        for doc in documents
    )

    if chunked:
        call_inputs = [doc_est.call_input_tokens for doc_est in document_estimates]
        review_mode = "chunked"
    else:
        call_inputs = [system_tokens + estimate_tokens(build_prompt(documents, rubric))]
        review_mode = "single_call"

    max_output = _max_output_tokens_for(provider)
    total_input = sum(call_inputs)
    max_call = max(call_inputs, default=0)
    output_cap = max_output * max(1, len(call_inputs))
    throttle_interval = _chunking_interval_seconds(provider) if chunked else 0.0
    minimum_wait_seconds = int(math.ceil(max(0, len(call_inputs) - 1) * throttle_interval))
    status, reasons = _classify_budget(
        call_count=len(call_inputs),
        max_call_input_tokens=max_call,
        total_input_tokens=total_input,
        external_provider=external_provider,
    )
    suggested_batches = _suggest_batches(
        document_estimates,
        enabled=external_provider and len(documents) > 1,
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
        document_estimates=document_estimates,
        suggested_batches=suggested_batches,
        minimum_wait_seconds=minimum_wait_seconds,
        throttle_interval_seconds=throttle_interval,
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


def _chunking_interval_seconds(provider: str) -> float:
    if provider not in {"gemma", "gemma4", "gemma-4", "gemini-gemma", "gemma-gemini", "gemini", "gemini-api", "gemini-free", "gemini-free-tier"}:
        return 0.0
    raw = os.getenv("GEMINI_CHUNKING_INTERVAL", "0").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0


def _suggest_batches(
    document_estimates: tuple[DocumentTokenEstimate, ...],
    *,
    enabled: bool,
    max_calls_per_batch: int = 6,
    max_input_tokens_per_batch: int = 25000,
) -> tuple[ReviewBatchSuggestion, ...]:
    if not enabled or len(document_estimates) <= 1:
        return ()

    batches: list[ReviewBatchSuggestion] = []
    current_names: list[str] = []
    current_tokens = 0

    def flush() -> None:
        nonlocal current_names, current_tokens
        if not current_names:
            return
        batches.append(
            ReviewBatchSuggestion(
                label=f"分割案 {len(batches) + 1}",
                document_names=tuple(current_names),
                call_count=len(current_names),
                total_input_tokens=current_tokens,
            )
        )
        current_names = []
        current_tokens = 0

    for doc_est in document_estimates:
        would_exceed_calls = len(current_names) >= max_calls_per_batch
        would_exceed_tokens = (
            bool(current_names)
            and current_tokens + doc_est.call_input_tokens > max_input_tokens_per_batch
        )
        if would_exceed_calls or would_exceed_tokens:
            flush()
        current_names.append(doc_est.name)
        current_tokens += doc_est.call_input_tokens
    flush()

    if len(batches) <= 1:
        return ()
    return tuple(batches)


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
