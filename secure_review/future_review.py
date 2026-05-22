from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Iterable

from secure_review.models import ReviewResult, SanitizedDocument
from secure_review.rubric import ChapterSection, extract_chapters_from_text


@dataclass(frozen=True)
class RequiredEvidence:
    label: str
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class PremortemDefinition:
    scenario_id: str
    title: str
    trigger_keywords: tuple[str, ...]
    required_evidence: tuple[RequiredEvidence, ...]
    failure_path: str
    prevention: str
    high_when_missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class AmbiguousExpressionFinding:
    finding_id: str
    expression: str
    source_document: str
    section: str
    context: str
    missing_elements: tuple[str, ...]
    recommendation: str
    severity: str = "medium"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["missing_elements"] = list(self.missing_elements)
        return data


@dataclass(frozen=True)
class ReaderRiskFinding:
    persona: str
    risk_level: str
    source_document: str
    section: str
    reason: str
    recommendation: str
    signals: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["signals"] = list(self.signals)
        return data


@dataclass(frozen=True)
class PremortemScenario:
    scenario_id: str
    title: str
    risk_level: str
    source_document: str
    section: str
    trigger_source: str
    confirmed_elements: tuple[str, ...]
    missing_elements: tuple[str, ...]
    review_hint: tuple[str, ...]
    evidence: str
    failure_path: str
    prevention: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["confirmed_elements"] = list(self.confirmed_elements)
        data["missing_elements"] = list(self.missing_elements)
        data["review_hint"] = list(self.review_hint)
        return data


@dataclass(frozen=True)
class FutureReviewReport:
    ambiguous_findings: tuple[AmbiguousExpressionFinding, ...]
    reader_risks: tuple[ReaderRiskFinding, ...]
    premortem_scenarios: tuple[PremortemScenario, ...]

    @property
    def ambiguous_count(self) -> int:
        return len(self.ambiguous_findings)

    @property
    def high_reader_risk_count(self) -> int:
        return sum(1 for item in self.reader_risks if item.risk_level == "high")

    @property
    def premortem_high_count(self) -> int:
        return sum(1 for item in self.premortem_scenarios if item.risk_level == "high")

    def to_dict(self) -> dict:
        return {
            "ambiguous_findings": [item.to_dict() for item in self.ambiguous_findings],
            "reader_risks": [item.to_dict() for item in self.reader_risks],
            "premortem_scenarios": [item.to_dict() for item in self.premortem_scenarios],
        }


AMBIGUOUS_PATTERNS: tuple[tuple[str, tuple[RequiredEvidence, ...], str], ...] = (
    (
        "必要に応じて",
        (
            RequiredEvidence("判断条件", ("条件", "基準", "閾値", "しきい値")),
            RequiredEvidence("判断者", ("判断者", "責任者", "承認者", "担当")),
            RequiredEvidence("期限・タイミング", ("期限", "タイミング", "何分", "何時間", "までに")),
        ),
        "発動条件、判断者、期限を明記してください。",
    ),
    (
        "適宜",
        (
            RequiredEvidence("判断条件", ("条件", "基準", "閾値", "しきい値")),
            RequiredEvidence("実施者", ("担当", "責任者", "実施者")),
            RequiredEvidence("実施タイミング", ("タイミング", "時点", "毎", "都度")),
        ),
        "誰が、いつ、どの条件で実施するかを明記してください。",
    ),
    (
        "原則",
        (
            RequiredEvidence("例外条件", ("例外", "ただし", "除く", "対象外")),
            RequiredEvidence("承認条件", ("承認", "判断", "責任者")),
        ),
        "例外条件と例外時の承認者を明記してください。",
    ),
    (
        "可能な限り",
        (
            RequiredEvidence("目標値", ("目標", "KPI", "SLA", "%", "以内")),
            RequiredEvidence("下限条件", ("最低", "下限", "必須", "閾値", "しきい値")),
        ),
        "努力目標ではなく、最低条件または目標値を定義してください。",
    ),
    (
        "片寄せ",
        (
            RequiredEvidence("方式", ("Active-Standby", "Active-Active", "待機系", "現用系")),
            RequiredEvidence("切替条件", ("切替", "フェイルオーバー", "条件", "障害")),
            RequiredEvidence("戻し方", ("切戻", "切り戻", "復旧", "戻し")),
        ),
        "片寄せ方式、切替条件、復旧時の戻し方を明記してください。",
    ),
    (
        "冗長化",
        (
            RequiredEvidence("冗長構成", ("台数", "AZ", "ゾーン", "系", "構成")),
            RequiredEvidence("障害時動作", ("障害", "切替", "フェイルオーバー", "SPOF")),
            RequiredEvidence("検証方法", ("試験", "確認", "訓練", "検証")),
        ),
        "冗長構成、障害時動作、検証方法を具体化してください。",
    ),
    (
        "常時稼働",
        (
            RequiredEvidence("稼働時間", ("24時間", "365日", "稼働時間", "SLA")),
            RequiredEvidence("例外停止", ("メンテナンス", "停止", "例外", "保守")),
        ),
        "稼働時間と例外停止条件を明記してください。",
    ),
)


PREMORTEM_DEFINITIONS: tuple[PremortemDefinition, ...] = (
    PremortemDefinition(
        scenario_id="PM-001",
        title="将来、DR切替時に復旧目標を満たせない",
        trigger_keywords=("DR", "災害", "復旧", "バックアップ", "RTO", "RPO", "切替"),
        required_evidence=(
            RequiredEvidence("RTO/RPO", ("RTO", "RPO", "復旧目標", "目標復旧")),
            RequiredEvidence("切替手順", ("切替手順", "切り替え手順", "切戻", "切り戻")),
            RequiredEvidence("訓練", ("訓練", "演習", "DRテスト", "復旧試験")),
        ),
        high_when_missing=("RTO/RPO",),
        failure_path="復旧目標、切替判断、訓練条件が曖昧なまま運用に入り、実障害時に判断待ちが発生する。",
        prevention="RTO/RPO、切替判断者、切替/切戻し手順、訓練頻度を明記してください。",
    ),
    PremortemDefinition(
        scenario_id="PM-002",
        title="将来、アラート発報後に一次対応者が判断できない",
        trigger_keywords=("監視", "アラート", "障害", "運用"),
        required_evidence=(
            RequiredEvidence("一次対応", ("一次対応", "初動", "対応者")),
            RequiredEvidence("エスカレーション", ("エスカレーション", "連絡", "通知先")),
            RequiredEvidence("判断基準", ("判断基準", "閾値", "条件")),
        ),
        high_when_missing=("一次対応", "判断基準"),
        failure_path="監視イベントは検知されるが、誰が何を判断するかが曖昧で復旧開始が遅れる。",
        prevention="一次対応者、判断基準、連絡先、エスカレーション条件を運用手順に落としてください。",
    ),
    PremortemDefinition(
        scenario_id="PM-003",
        title="将来、認証基盤障害で業務ログインが停止する",
        trigger_keywords=("認証", "SAML", "OIDC", "MFA", "Active Directory", "AD"),
        required_evidence=(
            RequiredEvidence("代替経路", ("代替", "迂回", "非常時", "緊急")),
            RequiredEvidence("冗長/切替", ("冗長", "切替", "フェイルオーバー", "待機系")),
            RequiredEvidence("監視", ("監視", "ヘルスチェック", "アラート")),
        ),
        failure_path="認証経路の障害時動作や代替手段が薄く、SaaS利用者がログインできない状態が長引く。",
        prevention="認証系の冗長方式、代替ログイン、監視項目、緊急時の運用判断を補強してください。",
    ),
    PremortemDefinition(
        scenario_id="PM-004",
        title="将来、通信経路の例外設定が増えセキュリティ境界が曖昧になる",
        trigger_keywords=("VPN", "Firewall", "ファイアウォール", "セキュリティ", "通信", "ネットワーク"),
        required_evidence=(
            RequiredEvidence("通信許可方針", ("許可", "拒否", "最小権限", "ポリシー")),
            RequiredEvidence("暗号化", ("暗号", "TLS", "IPsec")),
            RequiredEvidence("証跡", ("ログ", "監査", "証跡")),
        ),
        failure_path="通信許可の根拠や証跡方針が弱く、例外追加時に境界管理が崩れる。",
        prevention="通信許可基準、暗号化、ログ取得、例外承認フローを追記してください。",
    ),
)


def build_future_review_report(
    documents: Iterable[SanitizedDocument],
    review: ReviewResult | None = None,
) -> FutureReviewReport:
    docs = tuple(documents)
    return FutureReviewReport(
        ambiguous_findings=_detect_ambiguous_expressions(docs),
        reader_risks=_build_reader_risk_map(docs),
        premortem_scenarios=_build_premortem_scenarios(docs, review),
    )


def _detect_ambiguous_expressions(
    documents: tuple[SanitizedDocument, ...],
) -> tuple[AmbiguousExpressionFinding, ...]:
    findings: list[AmbiguousExpressionFinding] = []
    for doc in documents:
        chapters = _chapters_or_whole_document(doc)
        for expression, evidences, recommendation in AMBIGUOUS_PATTERNS:
            for chapter in chapters:
                if expression not in chapter.extracted_text:
                    continue
                missing = tuple(
                    evidence.label
                    for evidence in evidences
                    if not _contains_any(chapter.extracted_text, evidence.keywords)
                )
                if not missing:
                    continue
                findings.append(
                    AmbiguousExpressionFinding(
                        finding_id=f"AF-{len(findings) + 1:03d}",
                        expression=expression,
                        source_document=doc.name,
                        section=chapter.chapter_label,
                        context=_context_for_expression(chapter.extracted_text, expression),
                        missing_elements=missing,
                        recommendation=recommendation,
                        severity="medium" if len(missing) >= 2 else "low",
                    )
                )
                break
    return tuple(findings[:12])


def _build_reader_risk_map(
    documents: tuple[SanitizedDocument, ...],
) -> tuple[ReaderRiskFinding, ...]:
    text = "\n".join(doc.outbound_text for doc in documents)
    source = "レビュー対象全体" if len(documents) != 1 else documents[0].name
    risks = [
        _novice_reader_risk(text, source),
        _secondary_operator_risk(text, source),
        _auditor_risk(text, source),
        _manager_risk(text, source),
    ]
    return tuple(risks)


def _build_premortem_scenarios(
    documents: tuple[SanitizedDocument, ...],
    review: ReviewResult | None,
) -> tuple[PremortemScenario, ...]:
    scenarios: list[PremortemScenario] = []
    document_text = "\n".join(doc.outbound_text for doc in documents)
    issue_text = _review_issue_text(review)

    for definition in PREMORTEM_DEFINITIONS:
        document_triggered = _contains_any(document_text, definition.trigger_keywords)
        issue_triggered = _contains_any(issue_text, definition.trigger_keywords)
        if not (document_triggered or issue_triggered):
            continue

        confirmed, missing = _confirmed_and_missing_labels(
            document_text,
            definition.required_evidence,
        )
        if not missing:
            continue

        review_hint = _review_hints_for_keywords(review, definition.trigger_keywords)
        source, section = _source_for_premortem(
            documents,
            definition,
            review,
            prefer_document=document_triggered,
        )
        trigger_source = _trigger_source(document_triggered, issue_triggered)
        risk_level = (
            "high"
            if any(label in missing for label in definition.high_when_missing)
            or len(missing) >= 2
            else "medium"
        )
        scenarios.append(
            PremortemScenario(
                scenario_id=definition.scenario_id,
                title=definition.title,
                risk_level=risk_level,
                source_document=source,
                section=section,
                trigger_source=trigger_source,
                confirmed_elements=confirmed,
                missing_elements=missing,
                review_hint=review_hint,
                evidence=_premortem_evidence_summary(
                    trigger_source,
                    confirmed,
                    missing,
                    review_hint,
                ),
                failure_path=definition.failure_path,
                prevention=definition.prevention,
            )
        )

    return tuple(scenarios[:4])


def _novice_reader_risk(text: str, source: str) -> ReaderRiskFinding:
    abbreviations = sorted(set(re.findall(r"\b[A-Z][A-Z0-9]{1,}(?:/[A-Z0-9]{2,})?\b", text)))
    level = "high" if len(abbreviations) >= 16 else "medium" if len(abbreviations) >= 8 else "low"
    reason = (
        f"略語・英字専門語が {len(abbreviations)} 種類あります。"
        if abbreviations
        else "略語密度は高くありません。"
    )
    return ReaderRiskFinding(
        persona="初任SE",
        risk_level=level,
        source_document=source,
        section="文書全体",
        reason=reason,
        recommendation="略語表、前提説明、参照先を追加すると読み始めの負荷を下げられます。",
        signals=tuple(abbreviations[:8]),
    )


def _secondary_operator_risk(text: str, source: str) -> ReaderRiskFinding:
    has_ops = _contains_any(text, ("障害", "復旧", "切戻", "切り戻", "監視", "アラート", "運用"))
    missing = _missing_labels(
        text,
        (
            RequiredEvidence("判断基準", ("判断基準", "条件", "閾値", "しきい値")),
            RequiredEvidence("責任者", ("責任者", "担当", "一次対応", "運用者")),
            RequiredEvidence("連絡/エスカレーション", ("連絡", "通知", "エスカレーション")),
        ),
    )
    level = "high" if has_ops and len(missing) >= 2 else "medium" if has_ops and missing else "low"
    return ReaderRiskFinding(
        persona="二次運用者",
        risk_level=level,
        source_document=source,
        section="運用・障害対応観点",
        reason=(
            f"運用時に必要な {', '.join(missing)} が読み取りにくい状態です。"
            if missing and has_ops
            else "運用時の判断に必要な記述は大きくは不足していません。"
        ),
        recommendation="障害時の判断条件、一次対応者、連絡先、切戻し基準を手順化してください。",
        signals=tuple(missing),
    )


def _auditor_risk(text: str, source: str) -> ReaderRiskFinding:
    missing = _missing_labels(
        text,
        (
            RequiredEvidence("承認", ("承認", "承認者", "決裁")),
            RequiredEvidence("証跡", ("証跡", "ログ", "監査")),
            RequiredEvidence("変更履歴", ("改訂履歴", "変更履歴", "版番号")),
        ),
    )
    level = "high" if len(missing) >= 3 else "medium" if missing else "low"
    return ReaderRiskFinding(
        persona="監査人",
        risk_level=level,
        source_document=source,
        section="統制・証跡観点",
        reason=(
            f"監査で確認されやすい {', '.join(missing)} が弱い可能性があります。"
            if missing
            else "承認・証跡・変更履歴の観点は一定確認できます。"
        ),
        recommendation="承認者、変更履歴、証跡取得、ログ保管方針を明示してください。",
        signals=tuple(missing),
    )


def _manager_risk(text: str, source: str) -> ReaderRiskFinding:
    missing = _missing_labels(
        text,
        (
            RequiredEvidence("目的", ("目的", "背景", "狙い")),
            RequiredEvidence("意思決定材料", ("判断", "選定理由", "代替案", "リスク")),
            RequiredEvidence("効果/コスト", ("効果", "費用", "コスト", "KPI")),
        ),
    )
    level = "high" if len(missing) >= 3 else "medium" if missing else "low"
    return ReaderRiskFinding(
        persona="上長・承認者",
        risk_level=level,
        source_document=source,
        section="意思決定観点",
        reason=(
            f"承認判断に必要な {', '.join(missing)} が本文から追いにくい状態です。"
            if missing
            else "目的、判断材料、効果の観点は一定確認できます。"
        ),
        recommendation="目的、主要リスク、判断が必要な論点、期待効果を冒頭に要約してください。",
        signals=tuple(missing),
    )


def _chapters_or_whole_document(doc: SanitizedDocument) -> tuple[ChapterSection, ...]:
    chapters = extract_chapters_from_text(doc.outbound_text)
    if chapters:
        return chapters
    return (
        ChapterSection(
            chapter_id="whole",
            chapter_label="文書全体",
            detected_chapter_num=0,
            text_start=0,
            text_end=len(doc.outbound_text),
            extracted_text=doc.outbound_text,
        ),
    )


def _contains_any(text: str, keywords: Iterable[str]) -> bool:
    return any(_keyword_in_text(text, keyword) for keyword in keywords if keyword)


def _missing_labels(text: str, evidences: tuple[RequiredEvidence, ...]) -> tuple[str, ...]:
    return tuple(
        evidence.label for evidence in evidences
        if not _contains_any(text, evidence.keywords)
    )


def _confirmed_and_missing_labels(
    document_text: str,
    evidences: tuple[RequiredEvidence, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    confirmed: list[str] = []
    missing: list[str] = []
    for evidence in evidences:
        if _contains_any(document_text, evidence.keywords):
            confirmed.append(evidence.label)
        else:
            missing.append(evidence.label)
    return tuple(confirmed), tuple(missing)


def _keyword_in_text(text: str, keyword: str) -> bool:
    if not keyword:
        return False
    prefix = r"(?<![A-Za-z0-9])" if _is_ascii_alnum(keyword[0]) else ""
    suffix = r"(?![A-Za-z0-9])" if _is_ascii_alnum(keyword[-1]) else ""
    return re.search(prefix + re.escape(keyword) + suffix, text, re.IGNORECASE) is not None


def _is_ascii_alnum(value: str) -> bool:
    return bool(value and re.match(r"[A-Za-z0-9]", value))


def _trigger_source(document_triggered: bool, issue_triggered: bool) -> str:
    if document_triggered and issue_triggered:
        return "both"
    if document_triggered:
        return "document"
    return "issue"


def _premortem_evidence_summary(
    trigger_source: str,
    confirmed: tuple[str, ...],
    missing: tuple[str, ...],
    review_hint: tuple[str, ...],
) -> str:
    parts = [f"発火理由: {trigger_source}"]
    parts.append(
        "本文確認済み: " + (", ".join(confirmed) if confirmed else "なし")
    )
    parts.append(
        "本文不足: " + (", ".join(missing) if missing else "なし")
    )
    if review_hint:
        parts.append("レビュー指摘ヒント: " + " / ".join(review_hint))
    return "。".join(parts)


def _source_for_premortem(
    documents: tuple[SanitizedDocument, ...],
    definition: PremortemDefinition,
    review: ReviewResult | None,
    *,
    prefer_document: bool,
) -> tuple[str, str]:
    if prefer_document:
        best = _best_document_chapter_match(
            documents,
            (*definition.trigger_keywords, *tuple(
                keyword
                for evidence in definition.required_evidence
                for keyword in evidence.keywords
            )),
        )
        if best is not None:
            return best
    return _source_from_review_issue(review, definition.trigger_keywords)


def _best_document_chapter_match(
    documents: tuple[SanitizedDocument, ...],
    keywords: tuple[str, ...],
) -> tuple[str, str] | None:
    best_score = 0
    best_source: tuple[str, str] | None = None
    for doc in documents:
        for chapter in _chapters_or_whole_document(doc):
            score = sum(1 for keyword in keywords if _keyword_in_text(chapter.extracted_text, keyword))
            if score > best_score:
                best_score = score
                best_source = (doc.name, chapter.chapter_label)
    return best_source if best_score > 0 else None


def _context_for_expression(text: str, expression: str, radius: int = 58) -> str:
    index = text.find(expression)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(expression) + radius)
    context = re.sub(r"\s+", " ", text[start:end]).strip()
    if start > 0:
        context = "..." + context
    if end < len(text):
        context += "..."
    return context


def _review_issue_text(review: ReviewResult | None) -> str:
    if review is None:
        return ""
    parts: list[str] = []
    for issue in review.issues:
        parts.extend(
            (
                issue.title,
                issue.details,
                issue.current_state,
                issue.issue,
                issue.impact,
                issue.recommendation,
            )
        )
    return "\n".join(part for part in parts if part)


def _review_hints_for_keywords(
    review: ReviewResult | None,
    keywords: tuple[str, ...],
    limit: int = 2,
) -> tuple[str, ...]:
    if review is None:
        return ()
    hints: list[str] = []
    for issue in review.issues:
        issue_text = "\n".join(
            part
            for part in (
                issue.title,
                issue.details,
                issue.current_state,
                issue.issue,
                issue.impact,
                issue.recommendation,
            )
            if part
        )
        if _contains_any(issue_text, keywords):
            hints.append(issue.title or issue.issue or issue.details[:40])
        if len(hints) >= limit:
            break
    return tuple(hints)


def _source_from_review_issue(
    review: ReviewResult | None,
    keywords: tuple[str, ...] = (),
) -> tuple[str, str]:
    if review is None or not review.issues:
        return ("レビュー対象全体", "文書全体")
    if keywords:
        for issue in review.issues:
            issue_text = "\n".join(
                part
                for part in (
                    issue.title,
                    issue.details,
                    issue.current_state,
                    issue.issue,
                    issue.impact,
                    issue.recommendation,
                )
                if part
            )
            if _contains_any(issue_text, keywords):
                return (
                    issue.source_document or "レビュー対象全体",
                    issue.section or "関連章",
                )
    issue = next(
        (item for item in review.issues if item.severity == "high"),
        review.issues[0],
    )
    return (
        issue.source_document or "レビュー対象全体",
        issue.section or "関連章",
    )
