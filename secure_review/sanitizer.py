from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from secure_review.models import SanitizationRecord, SanitizedDocument


@dataclass
class SanitizationResult:
    sanitized_text: str
    records: list[SanitizationRecord]
    findings: list[str]


class SensitiveDataSanitizer:
    """Redacts likely confidential values before any LLM transfer."""

    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)
        self._seen: dict[tuple[str, str], str] = {}
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
        ]

    def sanitize(self, name: str, text: str) -> SanitizedDocument:
        result = self.sanitize_text(text)
        return SanitizedDocument(
            name=name,
            original_excerpt=text[:1200],
            sanitized_excerpt=result.sanitized_text[:1200],
            replacements=result.records[:100],
            findings=result.findings,
        )

    def sanitize_text(self, text: str) -> SanitizationResult:
        records: list[SanitizationRecord] = []
        findings: list[str] = []
        sanitized = text

        if self._patterns[0][1].search(text):
            findings.append("Credentials-like values were detected and masked.")

        for category, pattern in self._patterns:
            sanitized = self._replace_pattern(sanitized, pattern, category, records)

        return SanitizationResult(
            sanitized_text=sanitized,
            records=records,
            findings=findings,
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
