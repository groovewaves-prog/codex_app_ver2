from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from secure_review.models import SanitizedDocument


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class NextAction:
    title: str
    detail: str
    tone: str = "info"


def document_attention_reasons(
    document: SanitizedDocument,
    *,
    has_uncertain_candidates: bool = False,
) -> tuple[str, ...]:
    """Return short UI reasons explaining why a document needs attention."""
    reasons: list[str] = []
    decision = document.local_sensitivity_decision or "unknown"
    if decision == "block" or document.outbound_risk == "high":
        reasons.append("送信禁止")
    elif decision == "unknown":
        reasons.append("未判定")
    elif decision == "mask_and_continue":
        reasons.append("要確認")
    if has_uncertain_candidates:
        reasons.append("未確定マスク候補あり")
    if document.replacements:
        reasons.append(f"置換 {len(document.replacements)} 件")
    return tuple(reasons)


def sort_documents_by_attention(
    documents: Iterable[SanitizedDocument],
    *,
    names_with_uncertain_candidates: Iterable[str] = (),
) -> list[SanitizedDocument]:
    """Put blocked / uncertain / confirm-needed documents before quiet ones."""
    uncertain_names = set(names_with_uncertain_candidates)

    def key(document: SanitizedDocument) -> tuple[int, int, int, str]:
        decision = document.local_sensitivity_decision or "unknown"
        has_uncertain = document.name in uncertain_names
        if decision == "block" or document.outbound_risk == "high":
            priority = 0
        elif decision == "unknown":
            priority = 1
        elif decision == "mask_and_continue":
            priority = 2
        elif has_uncertain:
            priority = 3
        elif document.replacements:
            priority = 4
        else:
            priority = 5
        return (priority, -len(document.replacements), -document.estimated_input_tokens, document.name)

    return sorted(documents, key=key)


def sort_issues_by_importance(issues: Iterable[object]) -> list[object]:
    return sorted(
        issues,
        key=lambda issue: (
            SEVERITY_ORDER.get(getattr(issue, "severity", ""), 9),
            getattr(issue, "source_document", "") or "",
            getattr(issue, "section", "") or "",
            getattr(issue, "issue_id", "") or "",
            getattr(issue, "title", "") or "",
        ),
    )


def structure_fix_guidance(kind: str, item_name: str = "", chapter_name: str = "") -> str:
    """Return a short author-facing fix suggestion for structure findings."""
    if kind == "missing_chapter":
        target = chapter_name or "不足している観点"
        return f"「{target}」に相当する見出しを追加し、目的・前提・判断基準を本文から追える形にしてください。"
    if kind == "required_item_gap":
        target = item_name or "必須要素"
        return f"既存の章は活かしつつ、「{target}」が読み手に分かる一文または表を追記してください。"
    if kind == "structure_template_suggestion":
        return "まずテンプレート案の見出しだけを入れ、既存の箇条書きを該当見出しへ移動してください。"
    if kind in {"chapter_structure_missing", "structure_organization_suggestion"}:
        target = chapter_name or "混在している内容"
        return f"「{target}」に関係する記述を独立見出しに分け、別観点の説明と混ざらないよう整理してください。"
    return "読み手が確認すべき観点、根拠、対応方針を追えるように見出しと本文を整理してください。"
