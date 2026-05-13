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


def next_action_for_preview(
    *,
    has_preview_docs: bool,
    blocked_count: int,
    confirmation_count: int,
    send_approved: bool,
    review_in_progress: bool,
    review_done: bool,
) -> NextAction:
    if not has_preview_docs:
        return NextAction(
            "次: ファイルをアップロードして匿名化してください",
            "外部LLMへ送る前に、まずローカルでテキスト抽出・匿名化・機密度判定を実行します。",
            "info",
        )
    if blocked_count:
        return NextAction(
            "次: 送信禁止の文書を修正してください",
            f"{blocked_count} 件の文書はこのまま外部レビューへ送信できません。原文側の機密表現を削るか、より厳密に匿名化してください。",
            "block",
        )
    if review_in_progress:
        return NextAction(
            "現在: LLMレビューを実行中です",
            "画面を閉じずに完了を待ってください。複数ファイルでは文書ごとに順次処理されます。",
            "active",
        )
    if review_done:
        return NextAction(
            "次: 重要指摘と深堀候補を確認してください",
            "レビュー結果は章順と重要度順で切り替えできます。必要な章だけ深堀してください。",
            "success",
        )
    if confirmation_count and not send_approved:
        return NextAction(
            "次: 要確認の匿名化結果を確認してください",
            f"{confirmation_count} 件の文書に未判定・要確認・未確定候補があります。内容を確認してから最終承認に進んでください。",
            "warn",
        )
    if not send_approved:
        return NextAction(
            "次: 匿名化結果を確認して最終承認してください",
            "送信対象は匿名化済みテキストのみです。内容に問題がなければチェックボックスをオンにしてください。",
            "info",
        )
    return NextAction(
        "次: レビューに送信できます",
        "送信ボタンを押すと、設定された外部LLMに匿名化済みテキストだけが送信されます。",
        "success",
    )


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
