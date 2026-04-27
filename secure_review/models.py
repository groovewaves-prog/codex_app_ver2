from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class UploadedDocument:
    name: str
    content: str
    content_type: str = "text/plain"
    transfer_encoding: str = "text"

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
    outbound_text: str
    replacements: list[SanitizationRecord] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    estimated_input_tokens: int = 0
    outbound_risk: str = "low"
    local_sanitizer_provider: str = ""
    local_sensitivity_decision: str = "unknown"
    local_sensitivity_reasons: list[str] = field(default_factory=list)
    local_sensitivity_provider: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "original_excerpt": self.original_excerpt,
            "sanitized_excerpt": self.sanitized_excerpt,
            "replacements": [item.to_dict() for item in self.replacements],
            "findings": list(self.findings),
            "estimated_input_tokens": self.estimated_input_tokens,
            "outbound_risk": self.outbound_risk,
            "local_sanitizer_provider": self.local_sanitizer_provider,
            "local_sensitivity_decision": self.local_sensitivity_decision,
            "local_sensitivity_reasons": list(self.local_sensitivity_reasons),
            "local_sensitivity_provider": self.local_sensitivity_provider,
        }


@dataclass
class SensitivityAssessment:
    decision: str
    reasons: list[str] = field(default_factory=list)
    provider: str = ""
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "provider": self.provider,
            "recommended_actions": list(self.recommended_actions),
        }


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
    rubric_id: str = ""
    rubric_name: str = ""
    document_profile: str = ""
    classification_confidence: str = ""
    classification_reason: str = ""
    raw_response: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "issues": [issue.to_dict() for issue in self.issues],
            "provider": self.provider,
            "prompt_preview": self.prompt_preview,
            "rubric_id": self.rubric_id,
            "rubric_name": self.rubric_name,
            "document_profile": self.document_profile,
            "classification_confidence": self.classification_confidence,
            "classification_reason": self.classification_reason,
            "raw_response": self.raw_response,
        }
