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
class ReviewSummary:
    """Structured summary of a review result.

    Introduced in B0 (R-L preparation) alongside the unstructured ``summary``
    string on ``ReviewResult`` for backward compatibility. Fields are all
    optional so older LLM responses that don't supply this structure still
    parse cleanly.

    Fields:
        purpose: AI-inferred purpose of the document set.
        purpose_section_in_document: If a "目的" / "本書の位置付け" section
            exists in the document, where it is located (e.g. "1.1 本書の位置付け").
            Empty string if not found.
        purpose_divergence: Description of any divergence between the
            document's stated purpose and the AI-inferred purpose. Empty
            string if there's no divergence or no stated purpose.
        content_outline: AI-generated outline of what the document(s) contain.
        overall_evaluation: Overall assessment, equivalent to the legacy
            ``summary`` string but explicitly framed as evaluation rather
            than mixed purpose/content/evaluation prose.
        verdict: Overall verdict - one of "A" (no issues), "B" (minor),
            "C" (significant issues, re-review recommended), "D" (cannot
            release as-is). Empty string if the LLM did not provide one.
    """

    purpose: str = ""
    purpose_section_in_document: str = ""
    purpose_divergence: str = ""
    content_outline: str = ""
    overall_evaluation: str = ""
    verdict: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_empty(self) -> bool:
        """True if no fields are populated (LLM did not return a structured summary)."""
        return not any(
            (
                self.purpose,
                self.purpose_section_in_document,
                self.purpose_divergence,
                self.content_outline,
                self.overall_evaluation,
                self.verdict,
            )
        )


@dataclass
class ReviewIssue:
    severity: str
    title: str
    details: str
    recommendation: str
    source_document: str
    # B0: structured-issue fields. All optional so legacy LLM responses
    # (with only details / recommendation) still parse cleanly. When the LLM
    # returns the new schema, these are populated and ``details`` may be
    # synthesised from current_state + issue + impact for backward-compat
    # display paths.
    issue_id: str = ""
    section: str = ""
    current_state: str = ""
    issue: str = ""
    impact: str = ""
    required_timing: str = ""
    re_review_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def has_structured_fields(self) -> bool:
        """True if at least one B0 structured field is populated."""
        return bool(
            self.issue_id
            or self.section
            or self.current_state
            or self.issue
            or self.impact
            or self.required_timing
            or self.re_review_required
        )


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
    # R-B / R-C (ε): the concrete model identifier (e.g. ``gemma-4-31b-it``)
    # surfaced separately from the internal ``provider`` slug
    # (e.g. ``gemma-4-gemini-api``). Empty for providers that do not have a
    # distinct model concept (mock).
    model: str = ""
    # B0: structured summary (purpose / divergence / outline / evaluation /
    # verdict). The legacy ``summary`` string field above is preserved for
    # backward compatibility - older callers can keep using it. New callers
    # should prefer ``summary_structured`` when populated. Defaults to an
    # empty ReviewSummary, whose ``is_empty()`` returns True.
    summary_structured: ReviewSummary = field(default_factory=ReviewSummary)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "summary_structured": self.summary_structured.to_dict(),
            "issues": [issue.to_dict() for issue in self.issues],
            "provider": self.provider,
            "prompt_preview": self.prompt_preview,
            "rubric_id": self.rubric_id,
            "rubric_name": self.rubric_name,
            "document_profile": self.document_profile,
            "classification_confidence": self.classification_confidence,
            "classification_reason": self.classification_reason,
            "raw_response": self.raw_response,
            "model": self.model,
        }
