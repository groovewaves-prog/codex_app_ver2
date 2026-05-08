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
        purpose_section_in_document: If a "逶ｮ逧・ / "譛ｬ譖ｸ縺ｮ菴咲ｽｮ莉倥￠" section
            exists in the document, where it is located (e.g. "1.1 譛ｬ譖ｸ縺ｮ菴咲ｽｮ莉倥￠").
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


@dataclass(frozen=True)
class ChecklistResult:
    """Phase 5 (2026-05-08): 構造定義書 v0.2 §6 のチェック項目評価結果。

    LLM は文書ごとに、rubric.py の DESIGN_DOC_STRUCTURE_V0_2 にある各項目を
    5 段階で評価し、根拠 (reason) と文書内根拠 (evidence) を返す。

    フィールド:
        item_id: rubric.py の ChapterChecklistItem.item_id と紐づく (例: "1.1")
        item_name: 項目名 (LLM が返す表示用、例: "本書の目的")
        source_document: どの文書を評価したか (例: "基本設計書 1. はじめに.pdf")
        status: 5 段階評価 + 該当なし
            "excellent" / "good" / "acceptable" /
            "needs_improvement" / "unacceptable" / "not_applicable"
        reason: 評価の根拠 (必須、v0.2 §6.2)
        evidence: 文書内の根拠箇所 (例: "1.1 本書の位置付け")
    """
    item_id: str
    item_name: str
    source_document: str
    status: str
    reason: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MissingChapter:
    """Phase 5 (2026-05-08): 構造定義書 v0.2 §7 の欠落章サジェスチョン。

    集約 LLM call (chunking 完了後の 13 番目の call) で、rubric.py の
    DESIGN_DOC_STRUCTURE_V0_2 のうち、提供文書群に欠けている章について
    LLM が verdict と suggested_content を返す。

    フィールド:
        chapter_id: rubric.py の StandardChapter.chapter_id と紐づく (例: "ch9")
        chapter_name: 章名 (LLM が返す表示用、例: "性能設計")
        verdict: 3 段階の判定 (v0.2 §7.2)
            "should_have"  - 本来必要、欠落として指摘すべき
            "recommended"  - あればよい、サジェスチョンとして推奨
            "out_of_scope" - スコープ外として黙認 (UI では非表示)
        justification: なぜその verdict と判定したか
        suggested_content: もし作成するなら、本来書かれるべき内容
    """
    chapter_id: str
    chapter_name: str
    verdict: str
    justification: str
    suggested_content: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    # R-B / R-C (ﾎｵ): the concrete model identifier (e.g. ``gemma-4-31b-it``)
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
    # Phase 5 (2026-05-08): 構造定義書 v0.2 ベースの評価結果。
    # 既存呼び出し側 (テスト等) は、これらのフィールドを意識しなくても済むよう、
    # デフォルト空 tuple とした。新呼び出し側は LLM 出力から populate する。
    # checklist_results: 各文書 chunk call で得た 5 段階評価結果のリスト
    # missing_chapters: 集約 call で得た欠落章サジェスチョンのリスト
    checklist_results: tuple = field(default_factory=tuple)
    missing_chapters: tuple = field(default_factory=tuple)

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
            "checklist_results": [r.to_dict() for r in self.checklist_results],
            "missing_chapters": [m.to_dict() for m in self.missing_chapters],
        }


@dataclass
class NerCandidate:
    """spaCy NER + EntityRuler が抽出したエンティティ候補。

    R-M Phase 1: シード辞書ヒット (source="seed_dict") は confirmed=True、
    統計 NER のみのヒット (source="spacy_ner") は confirmed=False となり
    Phase 2 で gBizINFO 検索 + ユーザ確認に回される。
    """

    text: str
    label: str          # 既存マスクカテゴリ ("COMPANY" / "SITE" / "PERSON")
    spacy_label: str    # 元の spaCy ラベル ("ORG" / "GPE" / "FAC" / "PERSON")
    start: int
    end: int
    source: str         # "seed_dict" | "spacy_ner"
    confirmed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LookupResult:
    """gBizINFO 法人名検索の結果。

    R-M Phase 2: NER で抽出された未確定候補を gBizINFO に問い合わせ、
    ヒット件数と上位法人名を取得する。error が空でない場合は API 呼び出しが
    失敗したことを示し、UI では「検索失敗」として安全側 (マスクする) で扱う。
    """

    candidate_text: str
    hits: int
    top_names: list[str] = field(default_factory=list)
    error: str = ""
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MaskingPipelineState:
    """1 ドキュメント分のマスキングパイプライン中間状態。

    R-M: regex マスキング (sanitized) → NER で確定済み (confirmed_findings) +
    未確定候補 (uncertain_candidates) → 各未確定候補について gBizINFO 検索
    (lookups) までを保持する。最終 outbound_text は apply_user_decisions()
    の戻り値として都度生成される (state は不変に保つ)。
    """

    name: str
    sanitized: SanitizedDocument
    confirmed_findings: list[tuple[str, str]] = field(default_factory=list)
    uncertain_candidates: list[NerCandidate] = field(default_factory=list)
    lookups: dict[str, LookupResult] = field(default_factory=dict)

    @property
    def has_uncertain(self) -> bool:
        return len(self.uncertain_candidates) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sanitized": self.sanitized.to_dict(),
            "confirmed_findings": [list(pair) for pair in self.confirmed_findings],
            "uncertain_candidates": [c.to_dict() for c in self.uncertain_candidates],
            "lookups": {k: v.to_dict() for k, v in self.lookups.items()},
        }
