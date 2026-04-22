from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from secure_review.models import ReviewIssue, ReviewResult, SanitizedDocument
from secure_review.rubric import ReviewRubric, classify_documents, choose_rubric, render_rubric_for_prompt


SYSTEM_PROMPT = """You are a senior network, infrastructure, and code review agent.
Review the sanitized artifacts.
Do not ask for original secrets or identities.
Focus on risks, inconsistencies, hardening gaps, operational concerns, and decisive missing content.
Return concise Japanese feedback.

Output format:
SUMMARY: overall summary
ISSUE|severity|title|details|recommendation|source_document
"""


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

            if "aaa new-model" not in lowered and "aaa authentication" not in lowered:
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
        response = _post_json(
            self.api_url,
            payload,
            {
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
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
    name = "gemini-api"

    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
        self.model = os.getenv("GEMMA_MODEL", "").strip() or os.getenv("GEMINI_MODEL", "").strip() or "gemma-4-31b-it"
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
        response = _post_json(
            _build_gemini_endpoint(self.model),
            payload,
            {
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
            },
        )
        content = _extract_gemini_text(response)
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


class GeminiHostedGemmaProvider(GeminiApiReviewProvider):
    name = "gemma-4-gemini-api"


class GeminiFreeTierProvider(GeminiApiReviewProvider):
    name = "gemini-free-tier"


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


def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")

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
    return "\n".join(chunks).strip() or json.dumps(payload, ensure_ascii=False)


def _extract_gemini_text(payload: dict) -> str:
    chunks: list[str] = []
    for candidate in payload.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            text = part.get("text")
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip() or json.dumps(payload, ensure_ascii=False)


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
        for keyword in ("構成図", "接続図", "ネットワーク構成", "システム構成", "機器一覧", "network diagram", "topology")
    )


def _has_timechart_reference(text: str) -> bool:
    return any(keyword in text for keyword in ("タイムチャート", "time chart", "timeline", "別紙", "スケジュール"))


def _has_hardcoded_secret(text: str) -> bool:
    return bool(re.search(r"(?im)(password|passwd|token|secret|apikey|api_key)\s*[:=]\s*['\"][^'\"]+['\"]", text))


def _has_unprotected_command_execution(text: str) -> bool:
    return any(
        keyword in text
        for keyword in ("os.system(", "subprocess.run(", "subprocess.popen(", "invoke-expression", "iex ", "eval(", "exec(")
    )


def _has_bare_except(text: str) -> bool:
    return bool(re.search(r"(?im)^\s*except\s*:\s*$", text))
