from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class UploadedDocument:
    name: str
    content: str
    content_type: str = "text/plain"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizationRecord:
    placeholder: str
    original: str
    category: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizedDocument:
    name: str
    original_excerpt: str
    sanitized_excerpt: str
    replacements: list[SanitizationRecord] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["replacements"] = [item.to_dict() for item in self.replacements]
        return payload


@dataclass
class ReviewIssue:
    severity: str
    title: str
    details: str
    recommendation: str
    source_document: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewResult:
    summary: str
    issues: list[ReviewIssue]
    provider: str
    prompt_preview: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "issues": [issue.to_dict() for issue in self.issues],
            "provider": self.provider,
            "prompt_preview": self.prompt_preview,
        }
