from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass

from secure_review.models import SanitizationRecord, SanitizedDocument


@dataclass
class SanitizationResult:
    sanitized_text: str
    records: list[SanitizationRecord]
    findings: list[str]
    estimated_input_tokens: int
    outbound_risk: str


@dataclass
class LocalSanitizationResponse:
    sanitized_text: str
    findings: list[str]
    outbound_risk: str


APPROVED_LOCAL_PLACEHOLDERS = [
    "SECRET",
    "IPV4",
    "IPV6",
    "EMAIL",
    "MAC",
    "HOSTNAME",
    "COMPANY",
    "PROJECT",
    "TICKET",
    "PERSON",
    "URL",
    "SITE",
    "DEVICE",
    "GENERIC_IDENTIFIER",
]


LOCAL_SANITIZER_PROMPT = """You are a local data sanitization assistant that runs before any external LLM transfer.
Your only job is to make the text safer for external review while preserving the technical meaning.

Rules:
- Start from the current sanitized text and make the minimum additional changes needed.
- Keep existing placeholders like [SECRET_001] unchanged.
- Preserve the original structure, ordering, indentation, commands, code, and technical meaning.
- Do not summarize, translate, explain, or rewrite generic technical content.
- Replace any remaining customer names, project names, person names, ticket numbers, site names, device names, topology identifiers, credentials, URLs, or other identifying business context with neutral placeholders.
- Use only these placeholder categories:
  [SECRET_001], [IPV4_001], [IPV6_001], [EMAIL_001], [MAC_001], [HOSTNAME_001],
  [COMPANY_001], [PROJECT_001], [TICKET_001], [PERSON_001], [URL_001],
  [SITE_001], [DEVICE_001], [GENERIC_IDENTIFIER_001]
- Reuse the same placeholder consistently when the same sensitive item appears multiple times.
- Do not invent new placeholder formats.
- Do not add explanations into the sanitized text.
- Return JSON only.

Return format:
{
  "sanitized_text": "sanitized text",
  "findings": ["finding 1", "finding 2"],
  "risk": "low | medium | high"
}
"""


class SensitiveDataSanitizer:
    """Redacts likely confidential values before any LLM transfer."""

    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)
        self._seen: dict[tuple[str, str], str] = {}
        self._preview_limit = int(os.getenv("SANITIZED_PREVIEW_CHARS", "1200"))
        self._outbound_limit = int(os.getenv("OUTBOUND_TEXT_CHARS", "12000"))
        self._patterns: list[tuple[str, re.Pattern[str]]] = [
            (
                "secret",
                re.compile(
                    r"(?im)\b(password|secret|community|token|apikey|api_key|key)\b\s*[:= ]+\s*([^\s,;]+)"
                ),
            ),
            ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
            ("ipv6", re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")),
            ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
            ("mac", re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")),
            (
                "hostname",
                re.compile(r"(?im)\b(hostname|device-name|system-name)\b\s*[:= ]+\s*([A-Za-z0-9_.-]+)"),
            ),
            (
                "company",
                re.compile(
                    r"(?im)(?:^|\b)(customer(?:-name)?|client|company(?:-name)?|organization|vendor|"
                    r"顧客名|お客様名|会社名|企業名|ベンダ(?:名)?|委託先)\b\s*[:=： ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            (
                "project",
                re.compile(
                    r"(?im)(?:^|\b)(project(?:-name)?|system(?:-name)?|service(?:-name)?|"
                    r"案件名|プロジェクト名|システム名|サービス名)\b\s*[:=： ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            (
                "ticket",
                re.compile(
                    r"(?im)(?:^|\b)(change-id|change no|ticket|incident|request-id|"
                    r"変更番号|申請番号|案件番号|回線番号|契約番号)\b\s*[:=： ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            (
                "person",
                re.compile(
                    r"(?im)(?:^|\b)(owner|contact|manager|担当者|連絡先|申請者|責任者)\b\s*[:=： ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            ("url", re.compile(r"\bhttps?://[^\s)]+")),
        ]
        self._confidentiality_patterns: list[re.Pattern[str]] = [
            re.compile(r"(?im)\b(confidential|strictly confidential|internal use only|proprietary)\b"),
            re.compile(r"社外秘|部外秘|機密|極秘|取扱注意|社内限定|関係者限り"),
        ]
        self._legal_entity_pattern = re.compile(
            r"株式会社[^\s、,.;:]{1,40}|[^\s、,.;:]{1,40}(?:株式会社|有限会社)|"
            r"\b[A-Z][A-Za-z0-9&.,' -]{1,40}\s(?:Inc\.?|Corp\.?|LLC|Ltd\.?|Co\.?)\b"
        )

    def sanitize(self, name: str, text: str) -> SanitizedDocument:
        result = self.sanitize_text(text)
        outbound_text = result.sanitized_text[: self._outbound_limit]
        findings = list(result.findings)

        if len(result.sanitized_text) > self._outbound_limit:
            findings.append(
                f"Outbound text was truncated to {self._outbound_limit} characters to stay within a conservative review budget."
            )

        return SanitizedDocument(
            name=name,
            original_excerpt=text[: self._preview_limit],
            sanitized_excerpt=outbound_text[: self._preview_limit],
            outbound_text=outbound_text,
            replacements=result.records[:100],
            findings=findings,
            estimated_input_tokens=self._estimate_tokens(outbound_text),
            outbound_risk=result.outbound_risk,
        )

    def sanitize_text(self, text: str) -> SanitizationResult:
        records: list[SanitizationRecord] = []
        findings: list[str] = []
        sanitized = text
        risk_score = 0

        if self._patterns[0][1].search(text):
            findings.append("Credentials-like values were detected and masked.")
            risk_score = max(risk_score, 1)

        for category, pattern in self._patterns:
            sanitized = self._replace_pattern(sanitized, pattern, category, records)

        confidentiality_hits = sum(1 for pattern in self._confidentiality_patterns if pattern.search(text))
        if confidentiality_hits:
            findings.append(
                "Explicit confidentiality markers were detected locally. External transfer should use only the sanitized text."
            )
            risk_score = max(risk_score, 3)

        if any(record.category in {"company", "project", "ticket", "person"} for record in records):
            findings.append("Customer, project, ticket, or contact identifiers were detected and masked where possible.")
            risk_score = max(risk_score, 2)

        if self._legal_entity_pattern.search(text):
            findings.append("Corporate-name markers were detected. Please confirm that no identifying context remains.")
            risk_score = max(risk_score, 2)

        if len(records) >= 25:
            findings.append("A large number of sensitive values were detected. Consider splitting the review into smaller sanitized batches.")
            risk_score = max(risk_score, 2)

        return SanitizationResult(
            sanitized_text=sanitized,
            records=records,
            findings=findings,
            estimated_input_tokens=self._estimate_tokens(sanitized),
            outbound_risk=self._risk_from_score(risk_score),
        )

    def _replace_pattern(
        self,
        text: str,
        pattern: re.Pattern[str],
        category: str,
        records: list[SanitizationRecord],
    ) -> str:
        def replacement(match: re.Match[str]) -> str:
            if match.lastindex and match.lastindex >= 2:
                value = match.group(2)
                placeholder = self._placeholder(category, value)
                self._append_record(records, placeholder, value, category)
                return match.group(0).replace(value, placeholder)

            value = match.group(0)
            placeholder = self._placeholder(category, value)
            self._append_record(records, placeholder, value, category)
            return placeholder

        return pattern.sub(replacement, text)

    def _placeholder(self, category: str, value: str) -> str:
        key = (category, value)
        if key not in self._seen:
            self._counters[category] += 1
            self._seen[key] = f"[{category.upper()}_{self._counters[category]:03d}]"
        return self._seen[key]

    @staticmethod
    def _append_record(
        records: list[SanitizationRecord],
        placeholder: str,
        original: str,
        category: str,
    ) -> None:
        if any(record.placeholder == placeholder for record in records):
            return
        records.append(
            SanitizationRecord(
                placeholder=placeholder,
                original=original,
                category=category,
            )
        )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        if not text:
            return 0
        return max(1, math.ceil(len(text) / 4))

    @staticmethod
    def _risk_from_score(score: int) -> str:
        if score >= 3:
            return "high"
        if score >= 2:
            return "medium"
        return "low"


class LocalSanitizationEnhancer:
    name = "none"

    def enhance(
        self,
        name: str,
        original_text: str,
        sanitized_document: SanitizedDocument,
        sanitizer: SensitiveDataSanitizer,
    ) -> SanitizedDocument:
        return sanitized_document


class LocalHttpSanitizationEnhancer(LocalSanitizationEnhancer):
    name = "local-http"

    def __init__(self) -> None:
        self.api_url = os.getenv("LOCAL_SANITIZER_API_URL", "").strip()
        self.api_key = os.getenv("LOCAL_SANITIZER_API_KEY", "").strip()
        self.model = os.getenv("LOCAL_SANITIZER_MODEL", "").strip()
        self.max_chars = int(os.getenv("LOCAL_SANITIZER_INPUT_CHARS", "12000"))

    def enhance(
        self,
        name: str,
        original_text: str,
        sanitized_document: SanitizedDocument,
        sanitizer: SensitiveDataSanitizer,
    ) -> SanitizedDocument:
        if not self.api_url or not self.model:
            raise ValueError("LOCAL_SANITIZER_API_URL and LOCAL_SANITIZER_MODEL must be configured.")

        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": LOCAL_SANITIZER_PROMPT},
                {
                    "role": "user",
                    "content": _build_local_sanitizer_input(
                        name,
                        original_text[: self.max_chars],
                        sanitized_document,
                    ),
                },
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
        local_response = _parse_local_sanitization_response(content, sanitized_document.outbound_text)
        return _merge_local_sanitization(
            sanitized_document,
            local_response,
            sanitizer,
            original_text,
            self.name,
        )


class OllamaSanitizationEnhancer(LocalHttpSanitizationEnhancer):
    name = "ollama"

    def __init__(self) -> None:
        super().__init__()
        self.api_url = self.api_url or "http://127.0.0.1:11434/v1/responses"
        self.model = self.model or "gemma3:12b"


def choose_local_sanitization_enhancer() -> LocalSanitizationEnhancer:
    mode = os.getenv("LOCAL_SANITIZER_PROVIDER", "none").strip().lower()
    if mode == "ollama":
        return OllamaSanitizationEnhancer()
    if mode in {"http", "local-http", "openai-compatible"}:
        return LocalHttpSanitizationEnhancer()
    return LocalSanitizationEnhancer()


def _build_local_sanitizer_input(
    name: str,
    original_text: str,
    sanitized_document: SanitizedDocument,
) -> str:
    return "\n".join(
        [
            f"document_name: {name}",
            "original_text:",
            original_text,
            "current_sanitized_text:",
            sanitized_document.outbound_text,
            "approved_placeholder_categories:",
            ", ".join(APPROVED_LOCAL_PLACEHOLDERS),
            f"current_outbound_risk: {sanitized_document.outbound_risk}",
            "current_findings:",
            "\n".join(sanitized_document.findings) or "-",
        ]
    )


def _merge_local_sanitization(
    sanitized_document: SanitizedDocument,
    local_response: LocalSanitizationResponse,
    sanitizer: SensitiveDataSanitizer,
    original_text: str,
    provider_name: str,
) -> SanitizedDocument:
    refined = sanitizer.sanitize_text(local_response.sanitized_text)
    final_text = refined.sanitized_text
    outbound_text = final_text[: sanitizer._outbound_limit]
    findings = _merge_findings(
        sanitized_document.findings,
        local_response.findings,
        refined.findings,
    )

    if outbound_text != sanitized_document.outbound_text:
        findings.append("Local LLM applied additional masking before any external transfer.")
    if len(final_text) > sanitizer._outbound_limit:
        findings.append(
            f"Outbound text was truncated to {sanitizer._outbound_limit} characters to stay within a conservative review budget."
        )

    merged_records = _merge_records(sanitized_document.replacements, refined.records)
    outbound_risk = _max_risk(
        sanitized_document.outbound_risk,
        local_response.outbound_risk,
        refined.outbound_risk,
    )

    return SanitizedDocument(
        name=sanitized_document.name,
        original_excerpt=original_text[: sanitizer._preview_limit],
        sanitized_excerpt=outbound_text[: sanitizer._preview_limit],
        outbound_text=outbound_text,
        replacements=merged_records[:100],
        findings=findings,
        estimated_input_tokens=sanitizer._estimate_tokens(outbound_text),
        outbound_risk=outbound_risk,
        local_sanitizer_provider=provider_name,
        local_sensitivity_decision=sanitized_document.local_sensitivity_decision,
        local_sensitivity_reasons=list(sanitized_document.local_sensitivity_reasons),
        local_sensitivity_provider=sanitized_document.local_sensitivity_provider,
    )


def _merge_records(
    base_records: list[SanitizationRecord],
    additional_records: list[SanitizationRecord],
) -> list[SanitizationRecord]:
    merged: list[SanitizationRecord] = []
    seen: set[tuple[str, str, str]] = set()

    for record in [*base_records, *additional_records]:
        key = (record.placeholder, record.original, record.category)
        if key in seen:
            continue
        seen.add(key)
        merged.append(record)

    return merged


def _merge_findings(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for item in group:
            text = str(item).strip()
            if text and text not in merged:
                merged.append(text)
    return merged


def _max_risk(*levels: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    highest = "low"
    for level in levels:
        normalized = _normalize_risk(level)
        if order[normalized] > order[highest]:
            highest = normalized
    return highest


def _normalize_risk(level: str) -> str:
    normalized = str(level or "").strip().lower()
    if normalized in {"low", "medium", "high"}:
        return normalized
    return "medium"


def _normalize_local_placeholders(text: str) -> str:
    for category in APPROVED_LOCAL_PLACEHOLDERS:
        pattern = re.compile(rf"\[{category}_(\d{{1,3}})\]")
        text = pattern.sub(lambda match: f"[{category}_{int(match.group(1)):03d}]", text)
    return text


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


def _parse_local_sanitization_response(
    content: str,
    fallback_text: str,
) -> LocalSanitizationResponse:
    normalized_content = _extract_json_payload(content)
    try:
        payload = json.loads(normalized_content)
    except json.JSONDecodeError:
        return LocalSanitizationResponse(
            sanitized_text=fallback_text,
            findings=["The local sanitizer model did not return valid JSON; regex-only sanitization was kept."],
            outbound_risk="medium",
        )

    sanitized_text = _normalize_local_placeholders(str(payload.get("sanitized_text", fallback_text)))
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = [str(findings)]

    return LocalSanitizationResponse(
        sanitized_text=sanitized_text.strip() or fallback_text,
        findings=[str(item) for item in findings if str(item).strip()],
        outbound_risk=_normalize_risk(str(payload.get("risk", "medium"))),
    )


def _extract_json_payload(content: str) -> str:
    stripped = str(content or "").strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
        return stripped.strip()

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        return stripped[start : end + 1]
    return stripped
