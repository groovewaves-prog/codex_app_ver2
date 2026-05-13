from __future__ import annotations

import re
from dataclasses import dataclass

from secure_review.models import SanitizedDocument
from secure_review.rubric import (
    ChapterChecklistItem,
    ChapterSection,
    DESIGN_DOC_STRUCTURE_V0_2,
    StandardChapter,
    extract_chapters_from_text,
)


@dataclass(frozen=True)
class StructureFinding:
    """A deterministic document-structure finding shown before LLM summary."""

    kind: str
    severity: str
    message: str
    chapter_id: str = ""
    chapter_name: str = ""
    item_id: str = ""
    item_name: str = ""
    source_document: str = ""
    expected_content: str = ""
    suggested_content: str = ""


@dataclass(frozen=True)
class StructureCheckResult:
    """Review-set level structure check result.

    Multiple uploaded files may form one logical document, so missing chapters
    are evaluated across the whole upload set. Item gaps are tied back to the
    file that contains the relevant chapter.
    """

    document_profile: str
    document_count: int
    detected_chapter_count: int
    findings: tuple[StructureFinding, ...]


CRITICAL_DESIGN_CHAPTER_IDS = {
    "ch1",   # purpose, scope, stakeholders
    "ch2",   # functional / non-functional requirements
    "ch3",   # overall architecture
    "ch8",   # availability / DR
    "ch10",  # security
    "ch11",  # operations
    "ch15",  # risks / assumptions / references
}


DOCUMENT_WIDE_REQUIRED_ITEM_IDS = {
    "1.3",  # stakeholders / responsibility can live in a RACI, appendix, or operations chapter.
    "1.6",  # revision history is often front matter, back matter, or a separate appendix.
}


CRITICAL_ITEM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "1.1": ("目的", "背景", "ねらい", "対象システム", "想定読者", "成果"),
    "1.2": ("スコープ", "対象範囲", "対象外", "範囲", "境界"),
    "1.3": ("関係者", "体制", "責任", "責任分界", "エスカレーション", "ベンダ"),
    "1.6": ("改訂履歴", "変更履歴", "版番号", "改訂日", "承認者"),
    "2.1": ("業務要件", "業務目的", "現状業務", "改善目標"),
    "2.2": ("機能要件", "機能一覧", "ユースケース", "入出力"),
    "2.3": ("非機能", "NFR", "可用性", "性能", "セキュリティ", "コスト"),
    "3.1": ("全体構成", "構成図", "論理構成", "物理構成"),
    "3.2": ("構成要素", "コンポーネント", "役割", "版数"),
    "3.5": ("本番", "検証", "開発", "環境構成", "環境差異"),
    "8.1": ("SLI", "SLO", "SLA", "サービスレベル", "稼働率"),
    "8.3": ("DR", "災害", "RPO", "RTO", "リージョン"),
    "10.1": ("脅威", "STRIDE", "リスク分析", "脅威モデル"),
    "10.4": ("暗号", "KMS", "鍵管理", "at-rest", "in-transit"),
    "10.5": ("監査ログ", "証跡", "改ざん", "ログ保管"),
    "10.6": ("インシデント", "検知", "通報", "復旧"),
    "11.1": ("監視", "メトリクス", "ログ", "ダッシュボード"),
    "11.2": ("アラート", "閾値", "通知", "エスカレーション"),
    "11.4": ("デプロイ", "リリース", "ロールバック"),
    "11.6": ("バックアップ", "保管", "リストア", "復元"),
    "14.3": ("ロールバック", "切戻し", "戻し方", "判定基準"),
    "15.1": ("リスク", "前提", "未決", "課題", "対応方針"),
}


VIEWPOINT_KEYWORDS_BY_CHAPTER: dict[str, tuple[str, ...]] = {
    "ch1": ("目的", "背景", "スコープ", "対象範囲", "対象外", "関係者", "責任分担"),
    "ch2": ("業務要件", "機能要件", "非機能要件", "NFR", "制約条件", "前提条件"),
    "ch3": ("全体構成", "構成図", "構成要素", "コンポーネント", "環境構成"),
    "ch4": ("ネットワーク", "VPC", "サブネット", "IP", "ルーティング", "VPN", "DNS"),
    "ch5": ("認証", "認可", "アカウント", "権限", "MFA", "SSO"),
    "ch8": ("可用性", "冗長", "稼働率", "SLO", "SLA", "DR", "RPO", "RTO"),
    "ch10": ("セキュリティ", "脅威", "脆弱性", "暗号", "KMS", "監査ログ", "インシデント"),
    "ch11": ("運用", "監視", "アラート", "バックアップ", "デプロイ", "リリース", "ロールバック"),
    "ch14": ("移行", "切戻し", "ロールバック", "移行手順", "判定基準"),
    "ch15": ("リスク", "前提", "未決", "課題", "参照文書", "改訂履歴"),
}


DESIGN_PLAIN_TEXT_TEMPLATE = """1. はじめに
- 目的
- 対象範囲 / 対象外範囲
- 想定読者
- 関係者・責任分担

2. システム要件
- 業務要件
- 機能要件
- 非機能要件（可用性、性能、セキュリティ、運用、コスト）
- 前提条件・制約条件

3. システム全体構成
- 全体構成図または構成説明
- 構成要素一覧
- 環境構成（本番 / 検証 / 開発）

4. セキュリティ・可用性・運用
- 認証・認可
- 暗号化・監査ログ
- 冗長化・DR / バックアップ
- 監視・アラート・ロールバック

5. リスク・未決事項・参照文書
- 既知リスクと対応方針
- 未決事項
- 改訂履歴
- 参照文書"""


def build_structure_check_result(
    documents: list[SanitizedDocument],
    document_profile: str,
) -> StructureCheckResult:
    """Build deterministic structure findings for the current review set."""
    if document_profile == "design":
        return _build_design_structure_check(documents)
    return _build_generic_structure_check(documents, document_profile)


def _build_design_structure_check(
    documents: list[SanitizedDocument],
) -> StructureCheckResult:
    combined_text = "\n".join(doc.outbound_text for doc in documents)
    chapters_by_doc: dict[str, tuple[ChapterSection, ...]] = {
        doc.name: extract_chapters_from_text(doc.outbound_text)
        for doc in documents
    }
    all_chapters = [
        (doc_name, chapter)
        for doc_name, chapters in chapters_by_doc.items()
        for chapter in chapters
    ]
    detected_ids = {chapter.chapter_id for _, chapter in all_chapters}
    findings: list[StructureFinding] = []

    if not all_chapters:
        findings.append(
            StructureFinding(
                kind="chapter_structure_missing",
                severity="high",
                message=(
                    "見出し構造を検出できません。レビューは全文を対象に実行できますが、"
                    "設計書としては目的・要件・構成・セキュリティ・運用などの観点を"
                    "見出しで分けて記載することを推奨します。"
                ),
            )
        )
        findings.append(
            StructureFinding(
                kind="structure_template_suggestion",
                severity="info",
                message=(
                    "べた書きや箇条書きだけの文書は、以下の見出し例に沿って整理すると、"
                    "レビュー観点の抜け漏れを確認しやすくなります。"
                ),
                suggested_content=DESIGN_PLAIN_TEXT_TEMPLATE,
            )
        )
        if not _has_purpose_text(combined_text):
            findings.append(
                StructureFinding(
                    kind="required_item_gap",
                    severity="high",
                    chapter_id="ch1",
                    chapter_name="はじめに",
                    item_id="1.1",
                    item_name="本書の目的",
                    message="文書冒頭または「はじめに」相当の見出しに、本書の目的が明確に記載されていません。",
                    expected_content="構築目的、対象システム、想定読者、期待される成果",
                )
            )
        return StructureCheckResult("design", len(documents), 0, tuple(findings))

    organization_suggested_ids: set[str] = set()

    for doc_name, chapter in all_chapters:
        current_standard_chapter = _standard_chapter_for(chapter.chapter_id)
        if current_standard_chapter is None:
            continue
        for standard_chapter in DESIGN_DOC_STRUCTURE_V0_2:
            if standard_chapter.chapter_id in detected_ids:
                continue
            if standard_chapter.chapter_id == current_standard_chapter.chapter_id:
                continue
            if standard_chapter.chapter_id in organization_suggested_ids:
                continue
            if not _has_viewpoint_content(chapter.extracted_text, standard_chapter.chapter_id):
                continue
            findings.append(
                _organization_suggestion_finding(
                    standard_chapter,
                    source_document=doc_name,
                    source_chapter=current_standard_chapter.chapter_name,
                )
            )
            organization_suggested_ids.add(standard_chapter.chapter_id)

    for standard_chapter in DESIGN_DOC_STRUCTURE_V0_2:
        if standard_chapter.chapter_id not in detected_ids:
            if standard_chapter.chapter_id in organization_suggested_ids:
                continue
            if _has_viewpoint_content(combined_text, standard_chapter.chapter_id):
                findings.append(_organization_suggestion_finding(standard_chapter))
                organization_suggested_ids.add(standard_chapter.chapter_id)
                continue
            severity = (
                "high"
                if standard_chapter.chapter_id in CRITICAL_DESIGN_CHAPTER_IDS
                else "medium"
            )
            findings.append(_missing_chapter_finding(standard_chapter, severity))

    for doc_name, chapter in all_chapters:
        standard_chapter = _standard_chapter_for(chapter.chapter_id)
        if standard_chapter is None:
            continue
        for item in standard_chapter.items:
            if item.necessity != "must":
                continue
            if item.item_id not in CRITICAL_ITEM_KEYWORDS:
                continue
            if item.item_id in DOCUMENT_WIDE_REQUIRED_ITEM_IDS:
                continue
            if not _item_is_covered(chapter.extracted_text, item.item_id):
                findings.append(
                    _required_item_gap_finding(
                        standard_chapter,
                        item,
                        source_document=doc_name,
                        scope_name=standard_chapter.chapter_name,
                    )
                )

    for standard_chapter in DESIGN_DOC_STRUCTURE_V0_2:
        for item in standard_chapter.items:
            if item.item_id not in DOCUMENT_WIDE_REQUIRED_ITEM_IDS:
                continue
            if item.item_id not in CRITICAL_ITEM_KEYWORDS:
                continue
            if _item_is_covered(combined_text, item.item_id):
                continue
            findings.append(
                _required_item_gap_finding(
                    standard_chapter,
                    item,
                    scope_name="文書全体",
                    document_wide=True,
                )
            )

    return StructureCheckResult(
        "design",
        len(documents),
        len(all_chapters),
        tuple(findings),
    )


def _required_item_gap_finding(
    standard_chapter: StandardChapter,
    item: ChapterChecklistItem,
    *,
    source_document: str = "",
    scope_name: str = "",
    document_wide: bool = False,
) -> StructureFinding:
    scope = scope_name or standard_chapter.chapter_name
    if document_wide:
        message = (
            f"必須要素「{item.item_name}」が文書全体で明確に見当たりません。"
            "配置は先頭・末尾・別章・付録でも構いませんが、"
            "レビュー時に確認できる形で記載してください。"
        )
        chapter_id = ""
        chapter_name = scope
    else:
        message = (
            f"確認範囲「{scope}」で、"
            f"必須要素「{item.item_name}」が明確に見当たりません。"
        )
        chapter_id = standard_chapter.chapter_id
        chapter_name = standard_chapter.chapter_name
    return StructureFinding(
        kind="required_item_gap",
        severity="high" if item.weight >= 3 else "medium",
        chapter_id=chapter_id,
        chapter_name=chapter_name,
        item_id=item.item_id,
        item_name=item.item_name,
        source_document=source_document,
        expected_content=item.expected_content,
        message=message,
    )


def _build_generic_structure_check(
    documents: list[SanitizedDocument],
    document_profile: str,
) -> StructureCheckResult:
    combined_text = "\n".join(doc.outbound_text for doc in documents)
    findings: list[StructureFinding] = []
    if not _has_purpose_text(combined_text[:2000]):
        findings.append(
            StructureFinding(
                kind="required_item_gap",
                severity="medium",
                item_name="冒頭の目的記載",
                message="文書冒頭に、目的・対象・期待する結果が明確に記載されていません。",
                expected_content="目的、対象、想定読者、到達点",
            )
        )
    return StructureCheckResult(
        document_profile=document_profile,
        document_count=len(documents),
        detected_chapter_count=0,
        findings=tuple(findings),
    )


def _organization_suggestion_finding(
    standard_chapter: StandardChapter,
    source_document: str = "",
    source_chapter: str = "",
) -> StructureFinding:
    location = (
        f"「{source_chapter}」内に"
        if source_chapter
        else "本文中に"
    )
    return StructureFinding(
        kind="structure_organization_suggestion",
        severity="medium",
        chapter_id=standard_chapter.chapter_id,
        chapter_name=standard_chapter.chapter_name,
        source_document=source_document,
        expected_content=standard_chapter.purpose,
        message=(
            f"{location}「{standard_chapter.chapter_name}」に関係する記述がありますが、"
            "独立した見出し・章として整理されていません。"
            "読み手がレビュー観点を追いやすいよう、見出しを分けるか、"
            "該当章へ移動することを推奨します。"
        ),
    )


def _missing_chapter_finding(
    standard_chapter: StandardChapter,
    severity: str,
) -> StructureFinding:
    must_items = [
        item.item_name
        for item in standard_chapter.items
        if item.necessity == "must"
    ]
    item_summary = "、".join(must_items[:4])
    if len(must_items) > 4:
        item_summary += " など"
    return StructureFinding(
        kind="missing_chapter",
        severity=severity,
        chapter_id=standard_chapter.chapter_id,
        chapter_name=standard_chapter.chapter_name,
        expected_content=standard_chapter.purpose,
        message=(
            f"不足観点「{standard_chapter.chapter_name}」が見当たりません。"
            f"この観点では「{standard_chapter.purpose}」を確認します。"
            f"主な必須要素: {item_summary}。"
        ),
    )


def _standard_chapter_for(chapter_id: str) -> StandardChapter | None:
    for chapter in DESIGN_DOC_STRUCTURE_V0_2:
        if chapter.chapter_id == chapter_id:
            return chapter
    return None


def _item_is_covered(text: str, item_id: str) -> bool:
    keywords = CRITICAL_ITEM_KEYWORDS.get(item_id, ())
    return _contains_any(text, keywords)


def _has_purpose_text(text: str) -> bool:
    return _contains_any(text, CRITICAL_ITEM_KEYWORDS["1.1"])


def _has_viewpoint_content(text: str, chapter_id: str) -> bool:
    keywords = VIEWPOINT_KEYWORDS_BY_CHAPTER.get(chapter_id, ())
    hits = _viewpoint_hits(text, keywords)
    return len(hits) >= 2


def _viewpoint_hits(text: str, keywords: tuple[str, ...]) -> tuple[str, ...]:
    normalized = _normalize(text)
    return tuple(
        keyword
        for keyword in keywords
        if _normalize(keyword) in normalized
    )


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    normalized = _normalize(text)
    for keyword in keywords:
        if _normalize(keyword) in normalized:
            return True
    return False


def _normalize(text: str) -> str:
    lowered = (text or "").lower()
    lowered = lowered.translate(str.maketrans("０１２３４５６７８９", "0123456789"))
    return re.sub(r"\s+", "", lowered)
