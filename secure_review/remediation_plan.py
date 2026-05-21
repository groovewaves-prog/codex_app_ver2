from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Iterable

from secure_review.models import ReviewIssue, ReviewResult
from secure_review.structure_check import StructureCheckResult, StructureFinding
from secure_review.ui_viewmodel import SEVERITY_ORDER, structure_fix_guidance


@dataclass(frozen=True)
class RemediationItem:
    item_id: str
    source_type: str
    severity: str
    title: str
    target_document: str
    target_section: str
    problem: str
    fix_policy: str
    template: str
    re_review_scope: str
    re_review_condition: str
    effort: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ReReviewStep:
    label: str
    detail: str
    trigger: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RemediationPlan:
    headline: str
    summary: str
    items: tuple[RemediationItem, ...]
    re_review_steps: tuple[ReReviewStep, ...]

    @property
    def high_count(self) -> int:
        return sum(1 for item in self.items if item.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for item in self.items if item.severity == "medium")

    def to_dict(self) -> dict:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "items": [item.to_dict() for item in self.items],
            "re_review_steps": [step.to_dict() for step in self.re_review_steps],
        }


def build_remediation_plan(
    review: ReviewResult,
    structure_result: StructureCheckResult | None = None,
    *,
    max_items: int = 12,
) -> RemediationPlan:
    """Build a deterministic post-review action plan.

    The plan deliberately avoids another LLM call. It translates the existing
    review issues and structure-check findings into author-facing next work:
    fix policy, draft snippet, and re-review trigger.
    """
    items: list[RemediationItem] = []
    for issue in review.issues or []:
        if issue.severity not in {"high", "medium", "low"}:
            continue
        items.append(_item_from_issue(issue))

    if structure_result is not None:
        for finding in structure_result.findings or ():
            if finding.severity not in {"high", "medium"}:
                continue
            items.append(_item_from_structure_finding(finding))

    items = sorted(
        _dedupe_items(items),
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 9),
            _source_order(item.source_type),
            item.target_document,
            item.target_section,
            item.item_id,
            item.title,
        ),
    )[:max_items]

    if not items:
        return RemediationPlan(
            headline="大きな修正アクションはありません",
            summary="高・中重要度の指摘や構成不足は検出されていません。必要に応じて低重要度の改善を確認してください。",
            items=(),
            re_review_steps=(
                ReReviewStep(
                    "軽微確認",
                    "文書の誤字、表記ゆれ、参照リンクだけをセルフチェックします。",
                    "低重要度の修正を入れた場合",
                ),
            ),
        )

    high_count = sum(1 for item in items if item.severity == "high")
    medium_count = sum(1 for item in items if item.severity == "medium")
    if high_count:
        headline = "重要指摘から修正計画を作成しました"
        summary = f"高重要度 {high_count} 件を最優先にし、中重要度 {medium_count} 件は次に対応してください。"
    elif medium_count:
        headline = "確認候補の修正計画を作成しました"
        summary = f"中重要度 {medium_count} 件を、章単位または観点単位で順に補強してください。"
    else:
        headline = "軽微な改善計画を作成しました"
        summary = "レビュー指摘のうち、文章品質や補足説明の改善候補を整理しています。"

    return RemediationPlan(
        headline=headline,
        summary=summary,
        items=tuple(items),
        re_review_steps=_build_re_review_steps(items),
    )


def _item_from_issue(issue: ReviewIssue) -> RemediationItem:
    problem = issue.issue or issue.details or issue.title
    fix_policy = issue.recommendation or "指摘箇所に、判断根拠・設計方針・完了条件を追記してください。"
    target_section = issue.section or "該当箇所"
    re_review_condition = _re_review_condition_for_issue(issue, target_section)
    return RemediationItem(
        item_id=issue.issue_id or _fallback_issue_id(issue),
        source_type="review_issue",
        severity=issue.severity or "medium",
        title=issue.title or "レビュー指摘",
        target_document=issue.source_document or "対象文書",
        target_section=target_section,
        problem=problem,
        fix_policy=fix_policy,
        template=_template_for_issue(issue, fix_policy),
        re_review_scope=f"{issue.source_document or '対象文書'} / {target_section}",
        re_review_condition=re_review_condition,
        effort=_effort_for_severity(issue.severity),
    )


def _item_from_structure_finding(finding: StructureFinding) -> RemediationItem:
    title = _structure_title(finding)
    fix_policy = structure_fix_guidance(
        finding.kind,
        item_name=finding.item_name,
        chapter_name=finding.chapter_name,
    )
    target_section = finding.chapter_name or finding.item_name or "文書全体"
    return RemediationItem(
        item_id=finding.item_id or finding.chapter_id or finding.kind,
        source_type="structure_check",
        severity=finding.severity or "medium",
        title=title,
        target_document=finding.source_document or "文書全体",
        target_section=target_section,
        problem=finding.message,
        fix_policy=fix_policy,
        template=_template_for_structure_finding(finding),
        re_review_scope=f"{finding.source_document or '文書全体'} / {target_section}",
        re_review_condition=_re_review_condition_for_structure(finding, target_section),
        effort=_effort_for_severity(finding.severity),
    )


def _re_review_condition_for_issue(issue: ReviewIssue, target_section: str) -> str:
    title = issue.title or "対象指摘"
    if issue.severity == "high":
        return (
            f"「{target_section}」の修正後、この指摘「{title}」に関連する章だけを再アップロードし、"
            "高重要度指摘が解消したか確認してください。"
        )
    if issue.re_review_required:
        return (
            f"「{target_section}」の追記後、該当箇所を再レビューし、"
            f"「{title}」の再指摘が出ないことを確認してください。"
        )
    if issue.severity == "medium":
        return (
            f"「{target_section}」の追記差分を確認し、同じ観点の指摘が残る場合だけ再レビューしてください。"
        )
    return (
        f"「{target_section}」の軽微修正後、表記ゆれや参照漏れがないかセルフチェックしてください。"
    )


def _re_review_condition_for_structure(
    finding: StructureFinding,
    target_section: str,
) -> str:
    if finding.kind == "missing_chapter":
        return (
            f"「{target_section}」相当の見出しを追加した後、文書構成チェックで不足観点が消えるか確認してください。"
        )
    if finding.kind == "required_item_gap":
        item = finding.item_name or "必須要素"
        return (
            f"「{target_section}」に「{item}」を追記した後、該当章の概要レビューで不足が残らないか確認してください。"
        )
    if finding.kind in {"chapter_structure_missing", "structure_organization_suggestion"}:
        return (
            f"「{target_section}」の見出し分割・配置見直し後、章別概要で複数観点が混在していないか確認してください。"
        )
    if finding.kind == "structure_template_suggestion":
        return (
            "テンプレート案に沿って章立てを付け直した後、文書構成チェックで重要不足が減ったか確認してください。"
        )
    return (
        f"「{target_section}」の追記後、文書構成チェックと章別概要レビューを確認してください。"
    )


def _template_for_issue(issue: ReviewIssue, fix_policy: str) -> str:
    section = issue.section or "該当章"
    current_state = issue.current_state or "現状の記載を要約してください。"
    problem = issue.issue or issue.details or "何が不足・不整合なのかを記載してください。"
    impact = issue.impact or "未対応時の影響を記載してください。"
    return "\n".join(
        [
            f"### {section} 追記案",
            "- 現状:",
            f"  - {current_state}",
            "- 問題点:",
            f"  - {problem}",
            "- 修正方針:",
            f"  - {fix_policy}",
            "- 影響と判断基準:",
            f"  - {impact}",
            "- 完了条件:",
            "  - 読み手が設計判断、根拠、運用時の判断基準を追えること。",
        ]
    )


def _template_for_structure_finding(finding: StructureFinding) -> str:
    if finding.suggested_content:
        return finding.suggested_content
    if finding.kind == "missing_chapter":
        title = finding.chapter_name or "不足観点"
        expected = finding.expected_content or "この観点で確認すべき内容"
        return "\n".join(
            [
                f"## {title}",
                "- 目的:",
                f"  - {expected}",
                "- 現状:",
                "  - 現在の設計・運用方針を記載してください。",
                "- 判断基準:",
                "  - 採用理由、代替案、制約条件を記載してください。",
                "- 未決事項:",
                "  - 残課題、確認先、期限を記載してください。",
            ]
        )
    target = finding.item_name or finding.chapter_name or "確認観点"
    expected = finding.expected_content or "必要な内容を具体化してください。"
    return "\n".join(
        [
            f"### {target}",
            "- 追記する内容:",
            f"  - {expected}",
            "- 根拠:",
            "  - 参照資料、設計判断、関係者合意を記載してください。",
            "- 完了条件:",
            "  - 第三者がレビューしても判断に迷わない粒度で記載すること。",
        ]
    )


def _build_re_review_steps(items: Iterable[RemediationItem]) -> tuple[ReReviewStep, ...]:
    item_list = list(items)
    high = [item for item in item_list if item.severity == "high"]
    medium = [item for item in item_list if item.severity == "medium"]
    steps: list[ReReviewStep] = []
    if high:
        steps.append(
            ReReviewStep(
                "必須再レビュー",
                "高重要度の修正後、該当章だけを再アップロードしてレビューします。",
                f"高重要度 {len(high)} 件の修正が完了したとき",
            )
        )
    if medium:
        steps.append(
            ReReviewStep(
                "差分レビュー",
                "中重要度の修正は、追記箇所と関連章だけを確認します。",
                f"中重要度 {len(medium)} 件の修正が完了したとき",
            )
        )
    steps.append(
        ReReviewStep(
            "完了確認",
            "修正後の文書で構成チェック、概要レビュー、深堀候補が矛盾していないか確認します。",
            "リリース前または上長確認前",
        )
    )
    return tuple(steps)


def _dedupe_items(items: Iterable[RemediationItem]) -> list[RemediationItem]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[RemediationItem] = []
    for item in items:
        key = (item.source_type, item.target_document, item.target_section, item.title)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _source_order(source_type: str) -> int:
    return 0 if source_type == "structure_check" else 1


def _structure_title(finding: StructureFinding) -> str:
    if finding.kind == "missing_chapter":
        return f"不足観点: {finding.chapter_name or '未指定'}"
    if finding.kind == "required_item_gap":
        return f"必須要素不足: {finding.item_name or finding.chapter_name or '未指定'}"
    if finding.kind == "structure_template_suggestion":
        return "章立てテンプレート案"
    if finding.kind == "structure_organization_suggestion":
        return f"構成整理: {finding.chapter_name or '関連記述'}"
    return finding.chapter_name or finding.item_name or "構成チェック指摘"


def _fallback_issue_id(issue: ReviewIssue) -> str:
    raw = f"{issue.source_document}|{issue.section}|{issue.title}"
    return "ISSUE-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8].upper()


def _effort_for_severity(severity: str) -> str:
    if severity == "high":
        return "大"
    if severity == "medium":
        return "中"
    return "小"
