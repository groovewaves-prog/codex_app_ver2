from __future__ import annotations

import math
import os
import re
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
