from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from secure_review.models import ReviewIssue, ReviewResult, SanitizedDocument


SYSTEM_PROMPT = """You are a senior network review agent.
Review the sanitized design and configuration artifacts.
Do not ask for original secrets or identities.
Focus on risks, inconsistencies, hardening gaps, and operational concerns.
Return concise Japanese feedback.

Output format:
SUMMARY: overall summary
ISSUE|severity|title|details|recommendation|source_document
"""


class ReviewProvider:
    name = "base"

    def review(self, documents: list[SanitizedDocument]) -> ReviewResult:
        raise NotImplementedError


class MockReviewProvider(ReviewProvider):
    name = "mock"

    def review(self, documents: list[SanitizedDocument]) -> ReviewResult:
        issues: list[ReviewIssue] = []

        for document in documents:
            text = document.sanitized_excerpt
            lowered = text.lower()

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

        return ReviewResult(
            summary=f"Reviewed {len(documents)} document(s) and produced {len(issues)} issue(s).",
            issues=issues,
            provider=self.name,
            prompt_preview=build_prompt(documents)[:2000],
        )


class HttpLlmReviewProvider(ReviewProvider):
    name = "http-llm"

    def __init__(self) -> None:
        self.api_url = os.getenv("LLM_API_URL", "").strip()
        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.model = os.getenv("LLM_MODEL", "").strip()

    def review(self, documents: list[SanitizedDocument]) -> ReviewResult:
        if not self.api_url or not self.model:
            raise ValueError("LLM_API_URL and LLM_MODEL must be configured.")

        prompt = build_prompt(documents)
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
        return ReviewResult(
            summary="Received review result from the configured HTTP LLM provider.",
            issues=issues,
            provider=self.name,
            prompt_preview=prompt[:2000],
        )


class GeminiFreeTierProvider(ReviewProvider):
    name = "gemini-free-tier"

    def __init__(self) -> None:
        self.api_key = (
            os.getenv("GEMINI_API_KEY", "").strip()
            or os.getenv("GOOGLE_API_KEY", "").strip()
        )
        self.model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

    def review(self, documents: list[SanitizedDocument]) -> ReviewResult:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY must be configured.")
        if not self.model:
            raise ValueError("GEMINI_MODEL must be configured.")

        prompt = build_prompt(documents)
        endpoint = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{urllib.parse.quote(self.model, safe='.-')}:generateContent"
        )
        payload = {
            "system_instruction": {
                "parts": [{"text": SYSTEM_PROMPT}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
            },
        }
        response = _post_json(
            endpoint,
            payload,
            {
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
            },
        )
        content = _extract_gemini_text(response)
        issues = _parse_issue_blocks(content, documents)
        return ReviewResult(
            summary="Received review result from Gemini free tier.",
            issues=issues,
            provider=self.name,
            prompt_preview=prompt[:2000],
        )


def build_prompt(documents: list[SanitizedDocument]) -> str:
    sections = [
        "The following network design and configuration artifacts have been sanitized.",
        "Review them in Japanese for security, consistency, operations, monitoring, and documentation gaps.",
        "Return the result using the required format.",
        "SUMMARY: overall summary",
        "ISSUE|severity|title|details|recommendation|source_document",
    ]

    for document in documents:
        sections.append(f"--- document: {document.name} ---")
        sections.append(document.sanitized_excerpt)

    return "\n".join(sections)


def choose_provider() -> ReviewProvider:
    mode = os.getenv("REVIEW_PROVIDER", "mock").strip().lower()
    if mode == "http":
        return HttpLlmReviewProvider()
    if mode in {"gemini", "gemini-free", "gemini-free-tier"}:
        return GeminiFreeTierProvider()
    return MockReviewProvider()


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
