from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

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
    origin: str = "initial"

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


@dataclass(frozen=True)
class RemediationComparisonItem:
    item_id: str
    title: str
    severity: str
    target_document: str
    target_section: str
    status: str
    score: float
    matched_terms: tuple[str, ...]
    missing_terms: tuple[str, ...]
    evidence: str
    next_action: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RemediationComparisonReport:
    source_headline: str
    total_count: int
    items: tuple[RemediationComparisonItem, ...]

    @property
    def improved_count(self) -> int:
        return sum(1 for item in self.items if item.status == "improved")

    @property
    def partial_count(self) -> int:
        return sum(1 for item in self.items if item.status == "partial")

    @property
    def not_confirmed_count(self) -> int:
        return sum(1 for item in self.items if item.status == "not_confirmed")

    @property
    def needs_review_count(self) -> int:
        return sum(1 for item in self.items if item.status == "needs_review")

    def to_dict(self) -> dict:
        return {
            "source_headline": self.source_headline,
            "total_count": self.total_count,
            "improved_count": self.improved_count,
            "partial_count": self.partial_count,
            "not_confirmed_count": self.not_confirmed_count,
            "needs_review_count": self.needs_review_count,
            "items": [item.to_dict() for item in self.items],
        }


def remediation_plan_from_dict(data: dict[str, Any]) -> RemediationPlan:
    """Parse a saved remediation-plan JSON into a typed plan.

    The saved JSON is intentionally treated as untrusted user input. Missing
    fields fall back to safe labels so a partially older JSON can still be used
    as a re-review checklist.
    """
    if not isinstance(data, dict):
        raise ValueError("修正計画JSONの形式が不正です。")

    raw_items = data.get("items", [])
    if not isinstance(raw_items, list):
        raise ValueError("修正計画JSONに items 配列がありません。")

    items = tuple(
        _remediation_item_from_dict(raw_item)
        for raw_item in raw_items
        if isinstance(raw_item, dict)
    )
    if not items:
        raise ValueError("修正計画JSONに読み込める指摘項目がありません。")

    raw_steps = data.get("re_review_steps", [])
    steps = tuple(
        _re_review_step_from_dict(raw_step)
        for raw_step in raw_steps
        if isinstance(raw_step, dict)
    )
    if not steps:
        steps = _build_re_review_steps(items)

    return RemediationPlan(
        headline=_coerce_text(data.get("headline")) or "前回の修正計画",
        summary=_coerce_text(data.get("summary")) or "前回保存された修正計画です。",
        items=items,
        re_review_steps=steps,
    )


def compare_remediation_plan_to_documents(
    plan: RemediationPlan,
    documents: Iterable[object],
) -> RemediationComparisonReport:
    """Compare a previous plan with the current sanitized documents.

    This is a deterministic, local comparison. It does not prove that the
    document is correct; it checks whether terms and target sections from the
    previous remediation plan are now visible in the current outbound text.
    """
    doc_texts: dict[str, str] = {}
    all_parts: list[str] = []
    for document in documents:
        name = _coerce_text(getattr(document, "name", ""))
        text = _coerce_text(getattr(document, "outbound_text", ""))
        if name:
            doc_texts[name] = text
        all_parts.append(text)
    all_text = "\n".join(all_parts)

    compared_items = tuple(
        _compare_item_to_text(item, doc_texts, all_text)
        for item in plan.items
    )
    return RemediationComparisonReport(
        source_headline=plan.headline,
        total_count=len(plan.items),
        items=compared_items,
    )


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
        origin=issue.origin or "initial",
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
        origin="initial",
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


_CURRENT_STATE_FALLBACK = (
    "（本文から現状の記載を自動抽出できませんでした。"
    "該当章の元記載を確認の上、現状を簡潔に要約してください。）"
)

_CURRENT_STATE_PATTERNS = (
    re.compile(
        r"【現状】\s*(.+?)(?=(?:\n|\s*)【(?:問題点|影響|推奨対応|詳細|対応)】|\Z)",
        re.DOTALL,
    ),
    re.compile(r"^\s*現状[:：]\s*(.+?)(?=\n|\Z)", re.MULTILINE),
    re.compile(r"^\s*現状の記載[:：]\s*(.+?)(?=\n|\Z)", re.MULTILINE),
)


def _extract_current_state_from_details(details: str | None) -> str | None:
    if not details:
        return None
    for pattern in _CURRENT_STATE_PATTERNS:
        match = pattern.search(details)
        if not match:
            continue
        extracted = re.sub(r"\s+", " ", match.group(1)).strip()
        if extracted:
            return extracted
    return None


def _resolve_current_state(issue: ReviewIssue) -> str:
    if issue.current_state and issue.current_state.strip():
        return issue.current_state.strip()
    extracted = _extract_current_state_from_details(issue.details)
    if extracted:
        return extracted
    return _CURRENT_STATE_FALLBACK


def _template_for_issue(issue: ReviewIssue, fix_policy: str) -> str:
    section = issue.section or "該当章"
    current_state = _resolve_current_state(issue)
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


def _remediation_item_from_dict(data: dict[str, Any]) -> RemediationItem:
    return RemediationItem(
        item_id=_coerce_text(data.get("item_id")) or "PLAN-ITEM",
        source_type=_coerce_text(data.get("source_type")) or "review_issue",
        severity=_coerce_severity(data.get("severity")),
        title=_coerce_text(data.get("title")) or "修正項目",
        target_document=_coerce_text(data.get("target_document")) or "対象文書",
        target_section=_coerce_text(data.get("target_section")) or "該当箇所",
        problem=_coerce_text(data.get("problem")) or "前回レビューで修正対象として検出された項目です。",
        fix_policy=_coerce_text(data.get("fix_policy")) or "前回計画に沿って本文を補強してください。",
        template=_coerce_text(data.get("template")) or "",
        re_review_scope=_coerce_text(data.get("re_review_scope")) or "対象文書 / 該当箇所",
        re_review_condition=_coerce_text(data.get("re_review_condition")) or "修正後に再レビューしてください。",
        effort=_coerce_text(data.get("effort")) or _effort_for_severity(_coerce_severity(data.get("severity"))),
        origin=_coerce_text(data.get("origin")) or "initial",
    )


def _re_review_step_from_dict(data: dict[str, Any]) -> ReReviewStep:
    return ReReviewStep(
        label=_coerce_text(data.get("label")) or "再レビュー",
        detail=_coerce_text(data.get("detail")) or "修正後に該当箇所を確認します。",
        trigger=_coerce_text(data.get("trigger")) or "修正完了時",
    )


def _compare_item_to_text(
    item: RemediationItem,
    doc_texts: dict[str, str],
    all_text: str,
) -> RemediationComparisonItem:
    target_text = doc_texts.get(item.target_document) or all_text
    normalized_text = _normalize_for_match(target_text)
    section_present = bool(
        item.target_section
        and item.target_section not in {"該当箇所", "文書全体"}
        and _normalize_for_match(item.target_section) in normalized_text
    )
    terms = _extract_remediation_terms(item)
    matched = tuple(term for term in terms if _normalize_for_match(term) in normalized_text)
    missing = tuple(term for term in terms if term not in matched)
    score = (len(matched) / len(terms)) if terms else 0.0

    if not terms:
        status = "needs_review"
    elif score >= 0.55 or (section_present and score >= 0.35) or len(matched) >= 5:
        status = "improved"
    elif score >= 0.25 or len(matched) >= 2:
        status = "partial"
    else:
        status = "not_confirmed"

    evidence_parts = [f"確認できた要素: {len(matched)}/{len(terms)}"]
    if section_present:
        evidence_parts.append(f"対象箇所「{item.target_section}」に相当する記述を確認")
    if matched:
        evidence_parts.append("確認語: " + "、".join(matched[:6]))
    else:
        evidence_parts.append("前回計画に対応する主要語はまだ確認できません")

    return RemediationComparisonItem(
        item_id=item.item_id,
        title=item.title,
        severity=item.severity,
        target_document=item.target_document,
        target_section=item.target_section,
        status=status,
        score=round(score, 3),
        matched_terms=matched[:10],
        missing_terms=missing[:10],
        evidence=" / ".join(evidence_parts),
        next_action=_comparison_next_action(status, item),
    )


def _extract_remediation_terms(item: RemediationItem) -> tuple[str, ...]:
    source = "\n".join(
        (
            item.title,
            item.target_section,
            item.problem,
            item.fix_policy,
            item.template,
            item.re_review_condition,
        )
    )
    source = re.sub(
        r"(および|及び|ならびに|または|について|として|すること|してください|あります|できます)",
        " ",
        source,
    )
    candidates = re.findall(r"[A-Za-z][A-Za-z0-9_-]{1,}|[一-龥ぁ-んァ-ヶー]{2,}", source)
    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        term = candidate.strip(" _-:：・、。,.()（）[]【】「」『』")
        if not _is_useful_term(term):
            continue
        key = _normalize_for_match(term)
        if key in seen:
            continue
        seen.add(key)
        result.append(term)
        if len(result) >= 14:
            break
    return tuple(result)


_TERM_STOPWORDS = {
    "この",
    "その",
    "ため",
    "もの",
    "こと",
    "以下",
    "以上",
    "対象",
    "対象文書",
    "該当",
    "該当箇所",
    "文書",
    "修正",
    "追記",
    "確認",
    "再レビュー",
    "レビュー",
    "計画",
    "方針",
    "内容",
    "現状",
    "問題点",
    "完了条件",
    "判断基準",
    "記載",
    "必要",
    "不足",
}
_TERM_STOPWORD_KEYS = {re.sub(r"\s+", "", value).lower() for value in _TERM_STOPWORDS}


def _is_useful_term(term: str) -> bool:
    if len(term) < 2 or len(term) > 32:
        return False
    if term in _TERM_STOPWORDS:
        return False
    if term.isdigit():
        return False
    if _normalize_for_match(term) in _TERM_STOPWORD_KEYS:
        return False
    return True


def _comparison_next_action(status: str, item: RemediationItem) -> str:
    if status == "improved":
        return f"「{item.target_section}」の追記内容を今回レビュー結果と照合し、解消扱いにできるか確認してください。"
    if status == "partial":
        return f"一部の追記要素は確認できました。残りの不足語や再レビュー条件を見て、追加補強してください。"
    if status == "not_confirmed":
        return f"前回計画に対応する追記が十分には見えません。テンプレート案を再確認してください。"
    return "自動照合だけでは判断できません。対象章を人手で確認してください。"


def _normalize_for_match(value: str) -> str:
    return re.sub(r"\s+", "", _coerce_text(value)).lower()


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _coerce_severity(value: Any) -> str:
    severity = _coerce_text(value).lower()
    return severity if severity in {"high", "medium", "low", "info"} else "medium"
