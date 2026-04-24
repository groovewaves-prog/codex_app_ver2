from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from secure_review.models import ReviewIssue, ReviewResult, SanitizedDocument
from secure_review.network_guard import UpstreamHttpError, post_json_safely
from secure_review.rubric import ReviewRubric, classify_documents, choose_rubric, render_rubric_for_prompt


LOGGER = logging.getLogger("secure_review.reviewer")


SYSTEM_PROMPT = """You are a senior network, infrastructure, and code review agent.
Review the sanitized artifacts.
Do not ask for original secrets or identities.
Focus on risks, inconsistencies, hardening gaps, operational concerns, and decisive missing content.
Return concise Japanese feedback.

Output format:
SUMMARY: overall summary
ISSUE|severity|title|details|recommendation|source_document
"""


# Gemini free-tier quota messages we want to surface nicely to the user.
_GEMINI_QUOTA_MARKERS = (
    "RESOURCE_EXHAUSTED",
    "quota",
    "rate limit",
    "Resource has been exhausted",
)


class ReviewProvider:
    name = "base"

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
    ) -> ReviewResult:
        raise NotImplementedError


class MockReviewProvider(ReviewProvider):
    name = "mock"

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
    ) -> ReviewResult:
        issues: list[ReviewIssue] = []
        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)

        for document in documents:
            text = document.outbound_text
            lowered = text.lower()
            beginning = lowered[:800]

            if rubric.document_profile == "source_code":
                if _has_hardcoded_secret(lowered):
                    issues.append(
                        ReviewIssue(
                            severity="high",
                            title="ハードコードされた認証情報の疑い",
                            details="コード内にパスワード、トークン、秘密情報を直接埋め込んでいる可能性があります。",
                            recommendation="秘密情報は環境変数や安全なシークレットストアへ移し、コードから除外してください。",
                            source_document=document.name,
                        )
                    )

                if _has_unprotected_command_execution(lowered):
                    issues.append(
                        ReviewIssue(
                            severity="high",
                            title="危険なコマンド実行の可能性",
                            details="外部コマンド実行や評価系処理が入力検証や安全対策なしに使われている可能性があります。",
                            recommendation="引数の固定化、入力検証、シェル経由実行の回避を検討してください。",
                            source_document=document.name,
                        )
                    )

                if _has_bare_except(lowered):
                    issues.append(
                        ReviewIssue(
                            severity="medium",
                            title="例外処理が広すぎる可能性",
                            details="例外を広く握りつぶす記述があり、障害解析や誤動作の原因になり得ます。",
                            recommendation="捕捉対象を明確化し、ログや再送出を追加してください。",
                            source_document=document.name,
                        )
                    )
                continue

            if "telnet" in lowered:
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="Telnet usage detected",
                        details="An unencrypted remote access setting may still be present.",
                        recommendation="Replace Telnet with SSH and disable Telnet-related settings.",
                        source_document=document.name,
                    )
                )

            if "snmp-server community" in lowered:
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="SNMP community string usage",
                        details="Community-based SNMP authentication may still be enabled.",
                        recommendation="Consider migrating to SNMPv3 and restricting source addresses.",
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "design" and "aaa new-model" not in lowered and "aaa authentication" not in lowered:
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="AAA configuration not explicit",
                        details="Authentication, authorization, and accounting settings were not clearly found.",
                        recommendation="Document the AAA policy, identity source, and fallback behavior.",
                        source_document=document.name,
                    )
                )

            if re.search(r"(?im)^interface\s", text) and "description" not in lowered:
                issues.append(
                    ReviewIssue(
                        severity="low",
                        title="Interface descriptions may be missing",
                        details="Interfaces are defined but human-readable descriptions appear to be sparse.",
                        recommendation="Add interface descriptions for peer, purpose, and circuit context.",
                        source_document=document.name,
                    )
                )

            if not _has_purpose_at_beginning(beginning):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="冒頭の目的記載が不明確",
                        details="資料の最初の項目または第1章で、設計または作業の目的が明確に読み取れませんでした。",
                        recommendation="第1章または冒頭に、対象・目的・到達点を簡潔に追記してください。",
                        source_document=document.name,
                    )
                )

            if not _has_configuration_information(lowered):
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="構成情報の存在が確認できない",
                        details="ネットワーク構成図、システム構成図、接続図、機器一覧などの構成情報が文書から確認できませんでした。",
                        recommendation="構成図または同等の構成情報を本文か別紙参照で明記してください。",
                        source_document=document.name,
                    )
                )

            if rubric.document_profile in {"change_runbook", "operations_runbook"} and not _has_timechart_reference(lowered):
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="タイムチャートの記載または別紙参照が不足",
                        details="時系列管理が必要な資料と推定されましたが、タイムチャート本体または『タイムチャートは別紙』の記載が見当たりませんでした。",
                        recommendation="タイムチャートを本文に追加するか、別紙名を明記してください。",
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "operations_runbook" and not _has_operational_handover_signals(lowered):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="運用ハンドオーバー要素の記載が不足",
                        details=(
                            "運用手順書ですが、SLO/SLA、監視→ランブックのリンク、"
                            "オーナーシップ/RACI、エスカレーション先のいずれかに言及が見当たりません。"
                        ),
                        recommendation=(
                            "SLO、監視項目と対応手順のリンク、運用オーナーと"
                            "エスカレーション先を明記してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and _has_irreversible_operation_signals(lowered) and not _has_rollback_signals(lowered):
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="不可逆な作業が含まれる可能性があり、補償処置が不明",
                        details=(
                            "DB破壊的変更、データ削除、設定の上書きなど不可逆と思われる処理が"
                            "記載されている一方、切戻し/補償処置の記述が見当たりません。"
                        ),
                        recommendation=(
                            "可逆/不可逆を区別し、不可逆処理には補償処置や代替手段を明記してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and not _has_environment_distinction(lowered):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="作業対象環境の区別が不明確",
                        details=(
                            "作業計画書ですが、本番・検証・ステージングなど作業対象環境の"
                            "区別が読み取れませんでした。"
                        ),
                        recommendation=(
                            "作業対象環境（本番／検証／ステージング等）を明記してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and not _has_risk_level_with_approval(lowered):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="リスクレベルと承認プロセスの記載が不足",
                        details=(
                            "変更のリスクレベル分類と、それに対応する承認経路（誰の承認が必要か）"
                            "が読み取れませんでした。"
                        ),
                        recommendation=(
                            "リスクレベル（例: 高／中／低）と、各レベルに必要な承認者を明示してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and not _has_document_update_list(lowered):
                issues.append(
                    ReviewIssue(
                        severity="low",
                        title="作業後に修正対象となるドキュメントの事前一覧が無い",
                        details=(
                            "作業後に更新が必要となるドキュメントの事前一覧が見当たりませんでした。"
                        ),
                        recommendation=(
                            "変更対象ドキュメント（設計書、構成管理、運用手順書など）を計画段階で"
                            "リスト化してください。"
                        ),
                        source_document=document.name,
                    )
                )

        if not issues:
            issues.append(
                ReviewIssue(
                    severity="info",
                    title="No major issue found in mock review",
                    details="The mock review did not detect any obvious risk in the provided artifacts.",
                    recommendation="Use a real LLM provider and add more rules for production quality review.",
                    source_document=documents[0].name if documents else "-",
                )
            )

        return _build_review_result(
            summary=f"Reviewed {len(documents)} document(s) and produced {len(issues)} issue(s).",
            issues=issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
        )


class HttpLlmReviewProvider(ReviewProvider):
    name = "http-llm"

    def __init__(self) -> None:
        self.api_url = os.getenv("LLM_API_URL", "").strip()
        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.model = os.getenv("LLM_MODEL", "").strip()

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
    ) -> ReviewResult:
        if not self.api_url or not self.model:
            raise ValueError("LLM_API_URL and LLM_MODEL must be configured.")

        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)
        prompt = build_prompt(documents, rubric)
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        response = post_json_safely(
            self.api_url,
            payload,
            {
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            context_label="HTTP LLM provider",
        )
        content = _extract_openai_like_text(response)
        issues = _parse_issue_blocks(content, documents)
        return _build_review_result(
            summary="Received review result from the configured HTTP LLM provider.",
            issues=issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
            prompt=prompt,
        )


class GeminiApiReviewProvider(ReviewProvider):
    """Gemini / Gemma via Google Generative Language API.

    Stability improvements over the previous version:

    - Retry once on 429 / 5xx with a short backoff (free-tier rate limits
      are short-lived).
    - Convert quota errors into a clearly-labelled ``RuntimeError`` so the UI
      can display "Quota exceeded, please retry later" instead of a raw
      provider message.
    - Default to a Gemini flash model (which is actually on the free tier) if
      the user selects the "gemini-free" provider without overriding model.
    - Never echo the response body into exceptions.
    """

    name = "gemini-api"
    default_model = "gemma-4-31b-it"
    max_retries = 1
    retry_backoff_seconds = 2.0

    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
        self.model = (
            os.getenv("GEMMA_MODEL", "").strip()
            or os.getenv("GEMINI_MODEL", "").strip()
            or self.default_model
        )
        self.max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "2048"))
        self.temperature = float(os.getenv("GEMINI_TEMPERATURE", "0.2"))

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
    ) -> ReviewResult:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY must be configured.")
        if not self.model:
            raise ValueError("GEMMA_MODEL or GEMINI_MODEL must be configured.")

        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)
        prompt = build_prompt(documents, rubric)
        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
            },
        }

        response = self._post_with_retry(payload)
        content = _extract_gemini_text(response)
        if not content.strip():
            finish_reason = _first_finish_reason(response)
            raise RuntimeError(
                f"Gemini returned no text (finish_reason={finish_reason or 'unknown'}). "
                "Consider reducing input size or raising GEMINI_MAX_OUTPUT_TOKENS."
            )
        issues = _parse_issue_blocks(content, documents)
        return _build_review_result(
            summary=f"Received review result from Gemini API model {self.model}.",
            issues=issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
            prompt=prompt,
        )

    def _post_with_retry(self, payload: dict) -> dict:
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return post_json_safely(
                    _build_gemini_endpoint(self.model),
                    payload,
                    {
                        "Content-Type": "application/json",
                        "x-goog-api-key": self.api_key,
                    },
                    context_label=f"Gemini ({self.model})",
                )
            except UpstreamHttpError as exc:
                last_error = exc
                message = str(exc)
                if _looks_like_quota(message):
                    # Quota errors do not help by retrying.
                    raise RuntimeError(
                        "Gemini free-tier quota appears to be exhausted. "
                        "Wait a minute and try again, or switch to a paid tier."
                    ) from None
                if attempt < self.max_retries:
                    LOGGER.info("Gemini call failed (attempt %s); retrying: %s", attempt + 1, exc)
                    time.sleep(self.retry_backoff_seconds)
                    continue
                raise
        # Defensive: loop above always either returns or raises.
        raise last_error or RuntimeError("Gemini call failed with no error captured.")


class GeminiHostedGemmaProvider(GeminiApiReviewProvider):
    name = "gemma-4-gemini-api"
    default_model = "gemma-4-31b-it"


class GeminiFreeTierProvider(GeminiApiReviewProvider):
    """Gemini 2.x flash model variants are the ones that actually hit free-tier.

    If no model is configured, use ``gemini-2.0-flash`` as a saner default
    than the Gemma model the previous code used.
    """

    name = "gemini-free-tier"
    default_model = "gemini-2.0-flash"


def build_prompt(documents: list[SanitizedDocument], rubric: ReviewRubric | None = None) -> str:
    if rubric is None:
        rubric = choose_rubric(documents)

    sections = [
        "The following artifacts have been sanitized.",
        "Review them in Japanese for security, consistency, operations, documentation gaps, decisive missing content, and review blocking issues.",
        "Use the following rubric and clearly distinguish blocking gaps from items that need a little more detail.",
        render_rubric_for_prompt(rubric),
        "Return the result using the required format.",
        "SUMMARY: overall summary",
        "ISSUE|severity|title|details|recommendation|source_document",
    ]

    for document in documents:
        sections.append(f"--- document: {document.name} ---")
        sections.append(document.outbound_text)

    return "\n".join(sections)


def choose_provider() -> ReviewProvider:
    mode = os.getenv("REVIEW_PROVIDER", "mock").strip().lower()
    if mode == "http":
        return HttpLlmReviewProvider()
    if mode in {"gemma", "gemma4", "gemma-4", "gemini-gemma", "gemma-gemini"}:
        return GeminiHostedGemmaProvider()
    if mode in {"gemini", "gemini-api", "gemini-free", "gemini-free-tier"}:
        return GeminiFreeTierProvider()
    return MockReviewProvider()


def _build_review_result(
    summary: str,
    issues: list[ReviewIssue],
    provider: str,
    documents: list[SanitizedDocument],
    rubric: ReviewRubric,
    classification_confidence: str,
    classification_reason: str,
    prompt: str | None = None,
) -> ReviewResult:
    prompt_text = prompt or build_prompt(documents, rubric)
    return ReviewResult(
        summary=summary,
        issues=issues,
        provider=provider,
        prompt_preview=prompt_text[:2000],
        rubric_id=rubric.rubric_id,
        rubric_name=rubric.rubric_name,
        document_profile=rubric.document_profile,
        classification_confidence=classification_confidence,
        classification_reason=classification_reason,
    )


def _build_gemini_endpoint(model: str) -> str:
    return (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{urllib.parse.quote(model, safe='.-')}:generateContent"
    )


# Backwards-compat shim for tests/callers that patched this symbol.
def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    return post_json_safely(url, payload, headers, context_label="LLM provider")


def _extract_openai_like_text(payload: dict) -> str:
    output = payload.get("output_text")
    if isinstance(output, str) and output.strip():
        return output

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if text:
                chunks.append(text)

    for choice in payload.get("choices", []):
        message = choice.get("message") or {}
        text = message.get("content")
        if isinstance(text, str) and text:
            chunks.append(text)

    # Return empty string on no-content rather than the whole payload; the
    # previous behavior allowed provider diagnostics to surface as user text.
    return "\n".join(chunks).strip()


def _extract_gemini_text(payload: dict) -> str:
    chunks: list[str] = []
    for candidate in payload.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            text = part.get("text")
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip()


def _first_finish_reason(payload: dict) -> str | None:
    for candidate in payload.get("candidates", []):
        reason = candidate.get("finishReason")
        if reason:
            return str(reason)
    return None


def _looks_like_quota(message: str) -> bool:
    lower = message.lower()
    return any(marker.lower() in lower for marker in _GEMINI_QUOTA_MARKERS)


def _parse_issue_blocks(content: str, documents: list[SanitizedDocument]) -> list[ReviewIssue]:
    issues: list[ReviewIssue] = []
    default_source = documents[0].name if documents else "-"

    for line in content.splitlines():
        if not line.startswith("ISSUE|"):
            continue
        parts = [item.strip() for item in line.split("|", 5)]
        if len(parts) != 6:
            continue
        _, severity, title, details, recommendation, source_document = parts
        issues.append(
            ReviewIssue(
                severity=severity or "medium",
                title=title or "Review issue",
                details=details or content[:200],
                recommendation=recommendation or "Please confirm the intended configuration.",
                source_document=source_document or default_source,
            )
        )

    if issues:
        return issues

    return [
        ReviewIssue(
            severity="medium",
            title="LLM review response",
            details=content[:500] or "No review text was returned.",
            recommendation="Confirm the provider response format and prompt template.",
            source_document=default_source,
        )
    ]


def _has_purpose_at_beginning(beginning: str) -> bool:
    return any(
        keyword in beginning
        for keyword in ("目的", "本資料は", "本書は", "本手順書は", "対象", "purpose", "objective")
    )


def _has_configuration_information(text: str) -> bool:
    return any(
        keyword in text
        for keyword in (
            "構成図",
            "接続図",
            "ネットワーク構成",
            "システム構成",
            "機器一覧",
            "network diagram",
            "topology",
            "概要図",
            "全体概要",
            "体制図",
        )
    )


def _has_timechart_reference(text: str) -> bool:
    return any(keyword in text for keyword in ("タイムチャート", "time chart", "timeline", "別紙", "スケジュール"))


def _has_operational_handover_signals(text: str) -> bool:
    """SLO/SLA / monitoring-runbook link / ownership のいずれかに言及があるか。"""
    keywords = (
        "slo",
        "sla",
        "service level",
        "サービス目標",
        "稼働率目標",
        "オーナー",
        "owner",
        "raci",
        "責任分担",
        "エスカレーション",
        "escalation",
        "ランブック",
        "runbook",
        "on-call",
        "オンコール",
        "アラート",
        "alert",
    )
    return any(keyword in text for keyword in keywords)


def _has_irreversible_operation_signals(text: str) -> bool:
    """不可逆と推定される作業キーワード。"""
    keywords = (
        "drop table",
        "truncate",
        "rm -rf",
        "delete from",
        "format ",
        "破棄",
        "削除",
        "データ削除",
        "物理削除",
        "上書き",
        "overwrite",
    )
    return any(keyword in text for keyword in keywords)


def _has_rollback_signals(text: str) -> bool:
    keywords = (
        "切戻し",
        "切り戻し",
        "rollback",
        "roll back",
        "backout",
        "補償処置",
        "リカバリ",
        "fallback",
        "代替手段",
    )
    return any(keyword in text for keyword in keywords)


def _has_environment_distinction(text: str) -> bool:
    """作業対象環境の区別が記載されているか（本番/検証/ステージング等）。"""
    keywords = (
        "本番",
        "検証",
        "ステージング",
        "staging",
        "production",
        "prod",
        "preprod",
        "開発環境",
        "qa環境",
        "評価環境",
    )
    return any(keyword in text for keyword in keywords)


def _has_risk_level_with_approval(text: str) -> bool:
    """リスクレベル分類と承認プロセスの両方の言及があるか。"""
    risk_keywords = (
        "リスクレベル",
        "risk level",
        "リスク分類",
        "リスク区分",
    )
    approval_keywords = (
        "承認",
        "approval",
        "approved by",
        "オーソライズ",
        "サインオフ",
        "sign-off",
        "決裁",
    )
    has_risk = any(keyword in text for keyword in risk_keywords)
    has_approval = any(keyword in text for keyword in approval_keywords)
    return has_risk and has_approval


def _has_document_update_list(text: str) -> bool:
    """作業後に修正するドキュメントの事前一覧があるか。"""
    keywords = (
        "変更対象ドキュメント",
        "修正対象ドキュメント",
        "更新対象ドキュメント",
        "改訂対象",
        "documents to update",
        "documents affected",
        "ドキュメント更新計画",
        "ドキュメント修正計画",
    )
    return any(keyword in text for keyword in keywords)


def _has_hardcoded_secret(text: str) -> bool:
    return bool(re.search(r"(?im)(password|passwd|token|secret|apikey|api_key)\s*[:=]\s*['\"][^'\"]+['\"]", text))


def _has_unprotected_command_execution(text: str) -> bool:
    return any(
        keyword in text
        for keyword in ("os.system(", "subprocess.run(", "subprocess.popen(", "invoke-expression", "iex ", "eval(", "exec(")
    )


def _has_bare_except(text: str) -> bool:
    return bool(re.search(r"(?im)^\s*except\s*:\s*$", text))
