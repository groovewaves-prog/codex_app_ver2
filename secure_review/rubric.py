from __future__ import annotations

import re
from dataclasses import dataclass, field

from secure_review.models import SanitizedDocument
from secure_review.network_config import looks_like_network_config


@dataclass(frozen=True)
class MandatoryCheck:
    id: str
    name: str
    requirement: str
    check_points: tuple[str, ...]
    fail_conditions: tuple[str, ...]
    applies_to: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationAxis:
    id: str
    name: str
    weight: int
    purpose: str
    checkpoints: tuple[str, ...]
    fail_conditions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewRubric:
    rubric_id: str
    rubric_name: str
    document_profile: str
    target_documents: tuple[str, ...]
    mandatory_checks: tuple[MandatoryCheck, ...]
    evaluation_axes: tuple[EvaluationAxis, ...]
    review_policy: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReviewClassification:
    document_profile: str
    confidence: str
    reason: str


COMMON_MANDATORY_CHECKS = (
    MandatoryCheck(
        id="purpose_at_beginning",
        name="冒頭の目的記載",
        requirement="各資料の最初の項目または第1章に、設計または作業の目的を明記すること。",
        check_points=(
            "対象が明記されている",
            "何を行う資料かが分かる",
            "期待する結果または到達点が分かる",
        ),
        fail_conditions=(
            "冒頭に目的の記載がない",
            "目的が抽象的で対象や作業内容が分からない",
        ),
    ),
    MandatoryCheck(
        id="configuration_information",
        name="構成情報の存在",
        requirement="ネットワーク構成図、システム構成図、接続図、機器一覧など対象構成を把握できる情報が存在すること。",
        check_points=(
            "ネットワーク構成図または同等の構成情報がある",
            "対象機器、接続先、主要な通信経路が把握できる",
            "別紙の場合は参照先が明記されている",
        ),
        fail_conditions=(
            "構成情報が存在しない",
            "別紙参照とあるが参照先が不明",
        ),
    ),
    MandatoryCheck(
        id="timechart_information",
        name="タイムチャートの存在",
        requirement="時系列管理が必要な資料では、タイムチャートを記載するか『タイムチャートは別紙』と明記すること。",
        check_points=(
            "時系列の作業順が確認できる",
            "停止、切替、確認、切戻しのタイミングが分かる",
            "別紙の場合はその旨が本文に明記されている",
        ),
        fail_conditions=(
            "時系列管理が必要な資料なのにタイムチャートへの言及がない",
            "別紙運用だが本文に別紙記載がない",
        ),
        applies_to=("build_runbook", "change_runbook", "operations_runbook"),
    ),
    # B1: traceability between requirements and design (R-L)
    MandatoryCheck(
        id="requirement_traceability",
        name="要件とのトレーサビリティ",
        requirement=(
            "企画書または要件定義書の内容が設計書に反映され、各要件に対応する設計項目が"
            "確認できること。要件側の文書が同一レビューに含まれない場合は、本資料側に"
            "前提とする要件・制約条件の参照記述があれば可とする。"
        ),
        check_points=(
            "前提とする要件・要望が冒頭または背景に記載されている",
            "機能要件と設計項目の対応が読み取れる",
            "非機能要件(可用性・性能・セキュリティ等)が設計に落ちている",
            "要件にない構成や機能が混入していない",
        ),
        fail_conditions=(
            "要件への参照がまったくなく、設計判断の根拠が不明",
            "設計書に突然出てくる機能や構成があり、要件との対応が取れない",
        ),
        applies_to=("design", "proposal"),
    ),
    # B1: non-functional requirements coverage (R-L)
    MandatoryCheck(
        id="non_functional_coverage",
        name="非機能要件の網羅",
        requirement=(
            "可用性・性能・拡張性・セキュリティ・運用性・保守性・監査性・DR・"
            "バックアップ・ログ管理 の各観点が設計に反映されていること。すべてを"
            "詳述する必要はないが、各観点に方針または『対象外』の判断理由が記載"
            "されていること。"
        ),
        check_points=(
            "可用性方針(冗長化・SPOF排除等)が記載されている",
            "性能要件または性能目標が記載されている",
            "拡張性方針(スケーリング戦略等)が記載されている",
            "セキュリティ方針(認証・認可・暗号化等)が記載されている",
            "運用性・保守性方針が記載されている",
            "監査ログまたは証跡の取得方針が記載されている",
            "DR / バックアップ / リストア方針が記載されている",
            "ログ管理方針(取得対象・保管期間・アクセス制御)が記載されている",
        ),
        fail_conditions=(
            "可用性・セキュリティ・運用性のいずれかが完全に欠落している",
            "DR や監査要件が必要な案件で関連方針が未記載",
        ),
        applies_to=("design",),
    ),
    # B1: risk and open-issue disclosure (R-L)
    MandatoryCheck(
        id="risk_and_open_issues",
        name="リスク・課題の明示",
        requirement=(
            "未決事項・既知リスク・他社/他部署への作業依存が明示されていること。"
            "課題管理表が別紙の場合は、本文から参照されていること。"
        ),
        check_points=(
            "未決事項または『詳細設計フェーズで決定』等の TBD 項目が一覧化されている",
            "既知リスクと対応方針(緩和策・受容理由)が記載されている",
            "他社・他部署の作業依存(顧客側作業、外部接続等)が明確に切り分けられている",
        ),
        fail_conditions=(
            "未決事項が本文中に散在しており一覧化されていない",
            "他社作業依存があるのに責任分界点が記載されていない",
        ),
        applies_to=("design", "proposal"),
    ),
)


def _select_mandatory_checks(profile: str) -> tuple[MandatoryCheck, ...]:
    """Filter COMMON_MANDATORY_CHECKS by profile applicability.

    Checks with empty ``applies_to`` apply to every profile (backward
    compatible with pre-B1 entries). Checks with a non-empty
    ``applies_to`` are only included when the requested profile is in
    the tuple.
    """
    return tuple(
        check for check in COMMON_MANDATORY_CHECKS
        if not check.applies_to or profile in check.applies_to
    )


# Optional checks are not required; they are only verified when the artifact
# claims the element exists. The review must not demand that operators
# create new WBS / schedule artifacts to pass. This encodes the user
# policy "WBS があれば確認、なければ強要しない".
OPTIONAL_CHECKS = (
    MandatoryCheck(
        id="wbs_consistency_if_present",
        name="WBSの整合性（存在する場合のみ）",
        requirement=(
            "WBSや作業分解構造が資料内または参照先に存在する場合に限り、"
            "本文のタイムチャート・責任分担・開始/終了条件と矛盾がないことを確認する。"
            "WBSが無くても指摘しない。"
        ),
        check_points=(
            "WBSがあればタイムチャートと作業項目粒度が一致する",
            "WBSがあれば責任分担と本文のオーナーシップ記載が一致する",
            "WBSが無ければこの項目はスキップする",
        ),
        fail_conditions=(
            "WBSが存在するのに本文と矛盾している",
        ),
        applies_to=("change_runbook", "operations_runbook"),
    ),
)


# ---------------------------------------------------------------------------
# R-K: filename-first profile detection signals
# ---------------------------------------------------------------------------
# Keywords matched against the document filename (lower-cased). Multi-character
# Japanese keywords are matched as substrings; single short Japanese terms
# (e.g. "設計" alone) are intentionally excluded to avoid spurious hits in
# compound names like "○○運用設計書". English keywords are stored in lower-case.

FILENAME_DESIGN_KEYWORDS: tuple[str, ...] = (
    "設計書",
    "設計仕様書",
    "設計仕様",
    "基本設計",
    "詳細設計",
    "仕様書",
    "design document",
    "design spec",
    "specification",
    "architecture",
)

FILENAME_CHANGE_RUNBOOK_KEYWORDS: tuple[str, ...] = (
    "手順書",
    "作業手順書",
    "作業計画書",
    "変更計画書",
    "切替計画書",
    "切替手順書",
    "移行計画書",
    "移行手順書",
    "切戻し手順書",
    "リリース計画書",
    "runbook",
    "procedure",
    "work plan",
    "change plan",
    "cutover plan",
    "migration plan",
    "release plan",
)

FILENAME_OPERATIONS_RUNBOOK_KEYWORDS: tuple[str, ...] = (
    "運用手順",
    "運用設計",
    "保守手順",
    "監視手順",
    "障害対応手順",
    "運用要領",
    "日次運用",
    "インシデント対応",
    "operations runbook",
    "ops runbook",
    "maintenance procedure",
    "monitoring runbook",
    "incident response",
)

# B1: proposal-document filename signals (R-L)
FILENAME_PROPOSAL_KEYWORDS: tuple[str, ...] = (
    "企画書",
    "提案書",
    "構想書",
    "概要書",
    "企画案",
    "提案資料",
    "proposal",
    "business plan",
    "project charter",
    "business case",
)

# Body-text strong signals: rare in design documents, common in real runbooks.
BODY_CHANGE_RUNBOOK_STRONG_SIGNALS: tuple[str, ...] = (
    "タイムチャート",
    "タイムテーブル",
    "time chart",
    "schedule chart",
    "切戻し",
    "切り戻し",
    "ロールバック",
    "rollback",
    "backout",
    "fallback procedure",
    "go/no-go",
    "go no go",
    "gonogo",
    "進行可否判定",
    "続行判断",
)

BODY_OPERATIONS_STRONG_SIGNALS: tuple[str, ...] = (
    "エスカレーション",
    "on-call",
    "oncall",
)


NETWORK_CONFIG_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".config",
}


SOURCE_CODE_EXTENSIONS = {
    ".py",
    ".ps1",
    ".psm1",
    ".psd1",
    ".sh",
    ".bash",
    ".bsh",
    ".ksh",
    ".zsh",
    ".vbs",
    ".vba",
    ".bas",
    ".cls",
    ".frm",
    ".sql",
    ".psql",
}

DESIGN_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".pdf", ".md", ".txt", ".csv", ".yaml", ".yml", ".json"}


RUBRICS = {
    "design": ReviewRubric(
        rubric_id="network_design_v1",
        rubric_name="ネットワーク・サーバ設計書レビュー基準",
        document_profile="design",
        target_documents=("基本設計書", "詳細設計書"),
        # B1: select MCs by applies_to. For "design" this includes
        # purpose / configuration / requirement_traceability /
        # non_functional_coverage / risk_and_open_issues (5 MCs).
        mandatory_checks=_select_mandatory_checks("design"),
        evaluation_axes=(
            EvaluationAxis(
                id="completeness",
                name="完全性",
                weight=20,
                purpose="必要な情報が不足なく記載されているか",
                checkpoints=(
                    "対象範囲(対象システム / 対象機能 / 対象環境)が明記されている",
                    "対象機器、役割、接続先、外部依存先が分かる",
                    "前提条件、制約条件、対象外範囲が記載されている",
                    "機能一覧と各機能の処理概要・入出力・異常系が確認できる",
                    "詳細設計書では、インターフェース仕様、データ項目、状態遷移、例外処理が確認できる",
                    "移行・切替方式の概要が記載されている(詳細手順は別途で可)",
                    "現状課題や期待効果が背景・目的セクションで把握できる",
                ),
                fail_conditions=(
                    "対象機器が特定できない",
                    "前提条件が未記載",
                    "対象外範囲が示されておらず、設計の境界が不明",
                ),
            ),
            EvaluationAxis(
                id="consistency",
                name="整合性",
                weight=15,
                purpose="資料内および関連資料との矛盾がないか",
                checkpoints=(
                    "構成図と本文の機器名・サービス名が一致する",
                    "IPアドレス、IF名、ホスト名、リージョン名に矛盾がない",
                    "章間の参照(例: 詳細はX章参照)の参照先が実在する",
                    "設計内容と試験観点・運用観点の対応が取れている",
                    "本文の設計説明と、挿入されたコード・SQL・機器Config例が矛盾していない",
                ),
                fail_conditions=(
                    "機器名やIP体系に矛盾がある",
                    "参照先の章・別紙が存在しない、または記載と異なる",
                ),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=25,
                purpose="安全な構成と運用方針が考慮されているか",
                checkpoints=(
                    "認証方式と管理アクセス経路が明記されている",
                    "認証情報・機密情報の保管・受け渡し方式が安全である",
                    "権限管理(最小権限・職務分掌)の考え方がある",
                    "暗号化方針(保管時 / 通信時)が記載されている",
                    "監査ログ・アクセスログ・操作ログの取得方針と保管期間がある",
                    "インシデント対応・漏洩時の緊急対応フローが想定されている",
                    "証跡保全・改ざん検知(整合性検証等)が考慮されている",
                ),
                fail_conditions=(
                    "平文認証や危険な設定を放置している",
                    "特権ID運用や緊急時の権限取り扱いが不明",
                    "認証情報を汎用ストレージで長期保管する等、明らかなリスクが残存",
                ),
            ),
            EvaluationAxis(
                id="operability",
                name="運用保守性",
                weight=20,
                purpose="保守担当が迷わず運用でき、将来変更にも対応できるか",
                checkpoints=(
                    "監視項目・閾値・アラート条件が定義されている",
                    "障害時の一次対応・確認ポイント・エスカレーション先がある",
                    "DR / バックアップ / リストア方針が記載されている",
                    "DR 切替時の責任分界点と作業手順の概要が示されている",
                    "権限棚卸し・証明書/認証情報の有効期限管理の方針がある",
                    "将来の機能追加・変更を阻害しない構造になっている(疎結合・標準化)",
                    "引継ぎ可能な説明粒度になっている(暗黙知に依存しない)",
                ),
                fail_conditions=(
                    "監視項目や障害時対応が一切定義されていない",
                    "DR・バックアップ方針が未定義(該当案件で必要な場合)",
                ),
            ),
            EvaluationAxis(
                id="testability",
                name="試験妥当性",
                weight=20,
                purpose="設計内容が試験で確認できるか",
                checkpoints=(
                    "機能要件に対応する試験項目が想定されている",
                    "非機能要件(可用性・性能・セキュリティ)の確認方法が考えられている",
                    "期待結果が具体的に書かれている、または書ける程度に設計が具体的",
                    "異常系・切替試験・DR切替試験が考慮されている",
                    "詳細設計書では、インターフェース境界値、例外系、状態遷移、データ制約から試験観点を導出できる",
                    "試験環境(本番/検証)の差異が試験計画に反映可能",
                ),
                fail_conditions=(
                    "設計が抽象的すぎて試験項目を導出できない",
                    "異常系・切替試験への言及がない",
                ),
            ),
        ),
        review_policy=(
            "冒頭の目的記載の有無を最優先で確認すること。",
            "構成図などの構成情報が無い場合は高リスクとして扱うこと。",
            "セキュリティ事項(特に認証情報の取り扱い)は他の指摘より重く扱うこと。",
            "未決事項・他社作業依存は『リスク・課題の明示』MC で確認すること。",
            "詳細設計書では、インターフェース仕様、データ項目、例外処理、状態遷移、コード/Config抜粋との整合を確認すること。",
            "文書内のコードや機器Configは概要解析として扱い、正式な静的解析・Config監査と断定しないこと。",
            "指摘は blocking / required / recommended の厳しさを意識して記述すること。",
            "指摘は感情的・主観的表現を避け、事実ベースで客観的に記述すること。",
        ),
    ),
    "proposal": ReviewRubric(
        rubric_id="proposal_v1",
        rubric_name="企画書・提案書レビュー基準",
        document_profile="proposal",
        target_documents=("企画書", "提案書", "構想書", "概要書"),
        # B1: proposal applies the same purpose / configuration /
        # requirement_traceability / risk_and_open_issues MCs.
        # non_functional_coverage is design-only, not required at proposal stage.
        mandatory_checks=_select_mandatory_checks("proposal"),
        evaluation_axes=(
            EvaluationAxis(
                id="business_purpose",
                name="目的・背景の妥当性",
                weight=25,
                purpose="ビジネス上の目的・背景・現状課題が明確で、企画として価値があるか",
                checkpoints=(
                    "ビジネス目的が明確に記載されている",
                    "現状課題・問題点が具体的に分析されている",
                    "導入効果・期待される改善が定量・定性で示されている",
                    "対象ユーザー・関係者・影響範囲が明確",
                ),
                fail_conditions=(
                    "目的が抽象的で『何のためにやるか』が不明",
                    "現状課題の記載がなく、企画の必要性が判断できない",
                ),
            ),
            EvaluationAxis(
                id="alternatives_and_rationale",
                name="代替案・採用理由",
                weight=20,
                purpose="代替案を比較検討した上で採用案が選ばれているか",
                checkpoints=(
                    "複数の代替案が比較されている",
                    "採用案を選んだ理由(コスト・実現性・将来性等)が明確",
                    "棄却した案の棄却理由が記載されている",
                ),
                fail_conditions=(
                    "代替案の検討が一切なく、結論ありきになっている",
                ),
            ),
            EvaluationAxis(
                id="cost_and_schedule",
                name="費用対効果・スケジュール",
                weight=20,
                purpose="費用対効果・スケジュールが現実的に検討されているか",
                checkpoints=(
                    "概算費用(初期費用 / 運用費用)が記載されている",
                    "効果(コスト削減 / 売上増 / リスク削減)が金額または定量指標で示されている",
                    "スケジュールが現実的(主要マイルストーン・前提条件・依存関係)",
                    "投資回収期間または ROI が示されている(該当する場合)",
                ),
                fail_conditions=(
                    "費用見積りが完全に欠落している",
                    "効果が抽象的で意思決定に使えない",
                ),
            ),
            EvaluationAxis(
                id="feasibility",
                name="実現可能性",
                weight=20,
                purpose="技術・体制・リスク面で実現可能か",
                checkpoints=(
                    "技術的実現可能性(既存技術 or 検証要)が判断されている",
                    "実施体制(社内 / 外注 / 顧客側作業の分担)が示されている",
                    "主要リスクが洗い出され、緩和策が示されている",
                    "前提条件・制約条件が明示されている",
                ),
                fail_conditions=(
                    "実施体制が不明で誰がやるか分からない",
                    "リスク分析が一切ない",
                ),
            ),
            EvaluationAxis(
                id="success_criteria",
                name="成功指標",
                weight=15,
                purpose="成功条件・評価指標が定義されているか",
                checkpoints=(
                    "成功条件(KPI / KGI)が具体的に定義されている",
                    "効果測定の方法・タイミングが記載されている",
                    "撤退基準(うまくいかなかった場合の判断基準)がある(該当する場合)",
                ),
                fail_conditions=(
                    "成功条件が定義されておらず、後から成果を判定できない",
                ),
            ),
        ),
        review_policy=(
            "ビジネス目的の明確性を最優先で確認すること。",
            "代替案比較がなく結論ありきの場合は高リスクとして扱うこと。",
            "費用対効果が抽象的な場合は『意思決定に使える形に具体化を』と指摘すること。",
            "指摘は感情的・主観的表現を避け、事実ベースで客観的に記述すること。",
        ),
    ),
    "change_runbook": ReviewRubric(
        rubric_id="change_runbook_v1",
        rubric_name="変更・切替手順書レビュー基準",
        document_profile="change_runbook",
        target_documents=("変更手順書", "切替手順書", "構築手順書"),
        mandatory_checks=_select_mandatory_checks("change_runbook") + (OPTIONAL_CHECKS[0],),
        evaluation_axes=(
            EvaluationAxis(
                id="completeness",
                name="完全性",
                weight=20,
                purpose="実施に必要な情報が不足なく記載されているか",
                checkpoints=(
                    "対象範囲と実施手順が明記されている",
                    "前提条件、開始条件、終了条件がある",
                    "確認手順や証跡取得方針がある",
                    "作業日時・場所・作業対象が具体的に記載されている",
                    "作業対象環境（本番・検証・ステージングなど）が区別されている",
                ),
                fail_conditions=("作業対象が特定できない", "開始条件が未記載", "どの環境への作業か不明"),
            ),
            EvaluationAxis(
                id="change_risk",
                name="変更影響・切戻し",
                weight=30,
                purpose="改修時の事故を防げるか（ITIL change enablement / 可逆性分類）",
                checkpoints=(
                    "影響範囲が明記されている",
                    "切戻し条件と切戻し手順がある",
                    "作業継続/中止の判定ポイント（go/no-go）がある",
                    "可逆アクティビティと不可逆アクティビティが区別できる",
                    "不可逆アクティビティには補償処置または代替手段が記載されている",
                    "リスクレベル分類と、それに対応する承認レベルが明示されている",
                    "既知リスクに加えて、予測できない有事への対策方針がある",
                ),
                fail_conditions=(
                    "切戻し手順がない",
                    "判定ポイントがない",
                    "不可逆アクティビティが明示されないまま手順に埋め込まれている",
                    "承認レベルが不明確",
                ),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=15,
                purpose="作業時の安全性が確保されているか",
                checkpoints=(
                    "管理アクセス経路や認証手段が明記されている",
                    "秘密情報の扱いが明確である",
                    "証跡やログ取得方針がある",
                ),
            ),
            EvaluationAxis(
                id="operability",
                name="運用保守性",
                weight=15,
                purpose="作業後の保守や引継ぎがしやすいか",
                checkpoints=(
                    "連絡体制またはエスカレーションがある",
                    "作業後確認項目が明記されている",
                    "異常時の一次対応方針がある",
                    "作業後のオーナーシップ（誰が保守するか）が引き継がれる",
                    "役割分担（作業者・再鑑者・現地統括など）が明確",
                    "情報共有の経路（エスカレーション／問題発生時展開／通常時共有）が区別されている",
                ),
            ),
            EvaluationAxis(
                id="post_implementation_review",
                name="作業後レビュー・報告",
                weight=10,
                purpose="作業結果が記録され、後続の改善につなげられるか（ITIL Post-Implementation Review）",
                checkpoints=(
                    "作業結果の記録方法または保存先が決まっている",
                    "SLA/SLO への影響が確認される仕組みがある",
                    "学びを次回に反映する手段（事後レビュー会など）が想定されている",
                    "作業後に修正が必要となるドキュメントが事前に一覧化されている",
                    "変更履歴（版数・変更日・変更内容・変更者）が管理されている",
                ),
            ),
            EvaluationAxis(
                id="testability",
                name="試験妥当性",
                weight=10,
                purpose="変更結果を確認できるか",
                checkpoints=(
                    "作業後の確認項目がある",
                    "期待結果が具体的である",
                    "切替後/切戻し後の確認が考慮されている",
                ),
            ),
        ),
        review_policy=(
            "タイムチャートまたは別紙記載の有無を必ず確認すること。",
            "切戻し条件が無い場合は差戻し相当の重大指摘として扱うこと。",
            "決定的に不足している内容と、もう少し必要な内容を区別して記述すること。",
            "WBSが本文または別紙に存在する場合のみ整合性を確認すること。無い場合は指摘しない。",
            "不可逆な作業（DB破壊的変更、データ削除など）は区別されているかを重点的に確認すること。",
            "リスクレベル分類と対応する承認プロセスが不明確な場合は指摘すること。",
            "作業対象環境（本番・検証）が区別されていない場合は指摘すること。",
            "予測できない有事のリスクに対する対策方針があるかを確認すること。",
            "作業後に修正するドキュメントを事前に一覧化しているかを確認すること。",
        ),
    ),
    "operations_runbook": ReviewRubric(
        rubric_id="operations_runbook_v1",
        rubric_name="保守・運用手順書レビュー基準",
        document_profile="operations_runbook",
        target_documents=("保守手順書", "運用手順書", "障害対応手順書"),
        mandatory_checks=_select_mandatory_checks("operations_runbook") + (OPTIONAL_CHECKS[0],),
        evaluation_axes=(
            EvaluationAxis(
                id="completeness",
                name="完全性",
                weight=20,
                purpose="運用担当が対応に必要な情報を不足なく得られるか",
                checkpoints=(
                    "対象と目的が明記されている",
                    "定常運用または障害対応の流れがある",
                    "関連資料や別紙への参照先がある",
                ),
            ),
            EvaluationAxis(
                id="operational_handover",
                name="作業後運用ハンドオーバー",
                weight=20,
                purpose=(
                    "作業完了後、運用担当が単独で持続運用できる体制が整っているか "
                    "（Google SRE PRR / AWS ORR 知見）"
                ),
                checkpoints=(
                    "SLO/SLA またはそれに相当するサービス目標が明記されている",
                    "監視項目から対応手順（ランブック）へのリンクが示されている",
                    "オーナーシップ（誰が責任/対応/相談/連絡先か）が明記されている",
                    "エスカレーション先と発動条件が明記されている",
                    "ハイパーケア期間や立ち合い期間の扱いがある（必要時）",
                ),
                fail_conditions=(
                    "運用ハンドオーバー後のオーナー不在",
                    "監視項目だけ列挙され対応手順との対応がない",
                ),
            ),
            EvaluationAxis(
                id="operability",
                name="運用保守性",
                weight=20,
                purpose="保守担当が迷わず対応できるか",
                checkpoints=(
                    "既知の障害モードと対応が文書化されている",
                    "障害時の切り分け手順がある",
                    "デバッグに使えるログ/コマンド/ダッシュボードが示されている",
                ),
                fail_conditions=("障害時の確認ポイントがない",),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=15,
                purpose="保守作業における安全性が担保されているか",
                checkpoints=(
                    "権限や認証の扱いが明記されている",
                    "秘密情報の取扱いがある",
                    "ログや監査の取得方針がある",
                ),
            ),
            EvaluationAxis(
                id="change_risk",
                name="変更影響・切戻し",
                weight=10,
                purpose="保守作業時の変更リスクを抑制できるか",
                checkpoints=(
                    "作業実施条件がある",
                    "必要に応じて切戻し条件がある",
                    "停止時間や影響範囲が明記されている",
                ),
            ),
            EvaluationAxis(
                id="testability",
                name="試験妥当性",
                weight=15,
                purpose="対応結果を確認できるか",
                checkpoints=(
                    "確認コマンドや確認観点がある",
                    "期待結果が分かる",
                    "記録の残し方が分かる",
                ),
            ),
        ),
        review_policy=(
            "保守担当が初見で迷わない粒度かを重視すること。",
            "タイムチャートが必要な保守作業では、別紙記載の有無も確認すること。",
            "作業完了後に運用担当が単独で持続運用できるか、ハンドオーバー要素を必ず確認すること。",
            "SLO・監視→ランブックのリンク・オーナーシップが示されていなければ重大指摘として扱うこと。",
            "WBSが存在する場合は整合性を確認すること。無くても指摘しない。",
        ),
    ),
    "network_config": ReviewRubric(
        rubric_id="network_config_review_v1",
        rubric_name="ネットワーク機器Config概要レビュー基準",
        document_profile="network_config",
        target_documents=("Cisco IOS / IOS XE Config", "Fortinet FortiGate / FortiOS Config"),
        mandatory_checks=(
            MandatoryCheck(
                id="config_scope",
                name="Configの対象と役割の把握",
                requirement="Configから機器種別、想定役割、対象インターフェース、主要機能を概要把握できること。",
                check_points=(
                    "Cisco IOS/IOS XE または FortiOS などの構文種別が推定できる",
                    "主要インターフェース、ルーティング、ポリシー、VPN、管理系設定の有無が把握できる",
                    "設計書と突き合わせるべき確認観点が整理できる",
                ),
                fail_conditions=("構文種別や主要機能が判別できない",),
            ),
            MandatoryCheck(
                id="config_management_access",
                name="管理アクセスの安全性",
                requirement="管理アクセスが暗号化され、送信元や認証方式が適切に制限されていること。",
                check_points=(
                    "Telnet/HTTP管理が不要に有効化されていない",
                    "SSH/HTTPS/AAA/管理元制限の考え方が確認できる",
                    "特権認証、管理者アカウント、監査ログの扱いが確認できる",
                ),
                fail_conditions=("TelnetやHTTP管理が許可されている", "管理元制限や認証方式が不明"),
            ),
            MandatoryCheck(
                id="config_policy_routing",
                name="通信制御・経路制御の確認",
                requirement="ACL/Firewall Policy/NAT/Route/VPN が最小権限・設計意図に沿っているか確認できること。",
                check_points=(
                    "permit any any / all-to-all 許可など広すぎる通信許可を確認する",
                    "NAT/VIP/VPN/route-map 等の文脈依存設定は断定せず確認観点として扱う",
                    "経路制御やポリシーが設計書の通信要件と整合しているかを確認する",
                ),
                fail_conditions=("広すぎる通信許可が理由なく残っている", "経路やNATの意図が不明"),
            ),
        ),
        evaluation_axes=(
            EvaluationAxis(
                id="overview_accuracy",
                name="概要把握",
                weight=25,
                purpose="Configの役割と主要構成を過不足なく要約できるか",
                checkpoints=(
                    "ベンダ/構文種別を推定できる",
                    "interface、routing、policy、VPN、管理系の有無を整理できる",
                    "Config単体で断定できない点を明示できる",
                ),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=30,
                purpose="管理アクセス、認証、SNMP、広すぎる通信許可などの注意候補を抽出できるか",
                checkpoints=(
                    "Telnet/HTTP/SNMP community などの注意候補を確認する",
                    "Firewall Policy / ACL の広すぎる許可を確認する",
                    "秘密情報らしき値は匿名化済みである前提でも、保存・運用方針を確認する",
                ),
                fail_conditions=("明らかな危険候補を見落としている",),
            ),
            EvaluationAxis(
                id="operability",
                name="運用性",
                weight=20,
                purpose="ログ、NTP、監視、description など運用時に必要な情報が確認できるか",
                checkpoints=(
                    "Syslog/ログ転送、NTP、SNMP/監視設定の有無を確認する",
                    "interface description やポリシー名から運用者が意図を追えるか確認する",
                    "HA/冗長化の有無は要件に応じて確認観点として扱う",
                ),
            ),
            EvaluationAxis(
                id="design_consistency",
                name="設計書との整合",
                weight=25,
                purpose="Config例が設計書本文・構成図・通信要件と矛盾していないか",
                checkpoints=(
                    "設計書内のConfig抜粋であれば、本文の説明と設定例が矛盾していないか確認する",
                    "単体Configであれば、設計書と突き合わせるべきインターフェース、経路、ポリシーを整理する",
                    "画像や構成図の情報がある場合も、OCR/画像理解だけで断定せず確認観点として扱う",
                ),
            ),
        ),
        review_policy=(
            "このプロファイルはConfig監査ではなく、概要解析と確認観点の抽出であることを明示すること。",
            "Cisco IOS/IOS XE と Fortinet FortiOS を主対象とし、それ以外の構文は推定として扱うこと。",
            "ACL、Firewall Policy、NAT、VRF、route-map、VPN は文脈依存が強いため、断定ではなく設計書との突合観点を示すこと。",
            "Telnet、HTTP管理、SNMP community、広すぎる許可、ログ/NTP不足は優先的に確認すること。",
        ),
    ),
    "source_code": ReviewRubric(
        rubric_id="source_code_review_v1",
        rubric_name="ソースコード・スクリプトレビュー基準",
        document_profile="source_code",
        target_documents=("Pythonコード", "VBAコード", "PowerShellスクリプト", "Bash/Bshシェルスクリプト"),
        mandatory_checks=(
            MandatoryCheck(
                id="code_purpose",
                name="コードの目的と対象の明確化",
                requirement="コードやスクリプトの目的、対象処理、前提条件がコメントまたは命名から読み取れること。",
                check_points=(
                    "ファイル名、関数名、コメントから役割が分かる",
                    "対象処理や入力元が推測ではなく把握できる",
                    "単独実行スクリプトでは前提条件が読み取れる",
                ),
                fail_conditions=("何をするコードか判別しづらい", "入力や対象処理が不明で安全に実行できない"),
            ),
            MandatoryCheck(
                id="code_interface",
                name="入力・出力・依存関係の把握可能性",
                requirement="入力、出力、設定値、外部依存がコードから把握できること。",
                check_points=(
                    "設定値や環境依存が分かる",
                    "入出力ファイル、接続先、呼び出し先が把握できる",
                    "実行に必要な前提モジュールや権限が読み取れる",
                ),
                fail_conditions=("外部依存や接続先が把握できない", "危険な副作用がありそうなのに説明がない"),
            ),
        ),
        evaluation_axes=(
            EvaluationAxis(
                id="correctness",
                name="正確性",
                weight=25,
                purpose="ロジック上の誤りや想定漏れがないか",
                checkpoints=(
                    "条件分岐や例外系が妥当である",
                    "入力未設定や空値などの扱いが考慮されている",
                    "処理の前提と結果が矛盾しない",
                ),
                fail_conditions=("例外時に誤動作する", "重要な条件分岐が抜けている"),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=25,
                purpose="秘密情報や危険な実装が含まれていないか",
                checkpoints=(
                    "認証情報の直書きがない",
                    "コマンド実行や外部入力の扱いが危険でない",
                    "権限の強い処理に必要なガードがある",
                ),
                fail_conditions=("認証情報の直書きがある", "危険なコマンド実行が無防備"),
            ),
            EvaluationAxis(
                id="maintainability",
                name="保守性",
                weight=20,
                purpose="読みやすく修正しやすいか",
                checkpoints=(
                    "関数や処理単位が過度に密結合でない",
                    "変数名や関数名の意味が分かる",
                    "必要最小限のコメントやログがある",
                ),
            ),
            EvaluationAxis(
                id="operability",
                name="運用性",
                weight=15,
                purpose="実行時の確認、失敗時の調査、再実行がしやすいか",
                checkpoints=(
                    "ログ、標準出力、エラーメッセージがある",
                    "失敗時の検知や終了コードの扱いがある",
                    "バッチや運用スクリプトなら冪等性や再実行性が意識されている",
                ),
            ),
            EvaluationAxis(
                id="testability",
                name="試験容易性",
                weight=15,
                purpose="レビュー後に確認しやすい構造か",
                checkpoints=(
                    "関数単位または処理単位で確認しやすい",
                    "入力パターンを変えて試しやすい",
                    "副作用の強い処理が分離されている",
                ),
            ),
        ),
        review_policy=(
            "コードレビューとして、バグ、危険な実装、運用事故につながる点を優先して指摘すること。",
            "決定的に不足している内容と、もう少し必要な内容を区別して記述すること。",
            "ハードコードされた秘密情報、無防備な外部コマンド実行、破壊的処理は重大指摘として扱うこと。",
        ),
    ),
}


def choose_rubric(
    documents: list[SanitizedDocument],
    forced_profile: str | None = None,
) -> ReviewRubric:
    return RUBRICS[classify_documents(documents, forced_profile).document_profile]


def classify_documents(
    documents: list[SanitizedDocument],
    forced_profile: str | None = None,
) -> ReviewClassification:
    if forced_profile:
        normalized = forced_profile.strip().lower()
        if normalized in RUBRICS:
            return ReviewClassification(
                document_profile=normalized,
                confidence="forced",
                reason=f"プロファイルを '{normalized}' に明示的に指定しました。",
            )

    return detect_document_profile(documents)


def detect_document_profile(documents: list[SanitizedDocument]) -> ReviewClassification:
    corpus = "\n".join(f"{document.name}\n{document.outbound_text[:1500]}" for document in documents).lower()
    suffixes = {_suffix_of(document.name) for document in documents if document.name}
    code_like_count = sum(1 for document in documents if _looks_like_source_code(document.outbound_text))
    documents_count = max(len(documents), 1)

    # ----- Source code detection (unchanged behaviour, Japanese reasons) -----
    if documents and suffixes and suffixes.issubset(SOURCE_CODE_EXTENSIONS):
        return ReviewClassification(
            document_profile="source_code",
            confidence="high",
            reason="すべてのファイルがソースコードの拡張子を持っています。",
        )

    if any(
        keyword in corpus
        for keyword in (
            "def ",
            "class ",
            "import ",
            "from ",
            "try:",
            "except",
            "function ",
            "param(",
            "set -e",
            "#!/bin/",
            "#!/usr/bin/env",
            "invoke-",
            "write-output",
            "sub ",
            "end sub",
        )
    ):
        confidence = "high" if code_like_count == documents_count else "medium"
        return ReviewClassification(
            document_profile="source_code",
            confidence=confidence,
            reason="本文にソースコード構文 (def / class / import 等) が含まれています。",
        )

    # ----- R-K: filename-first profile detection -----
    name_signals = _collect_filename_signals(documents)
    body_signals = _collect_body_strong_signals(corpus)

    name_profiles_hit = [profile for profile, count in name_signals.items() if count > 0]
    body_profiles_hit = [profile for profile, hit in body_signals.items() if hit]

    # Conflict case 1: multiple distinct profiles hit in filenames.
    if len(name_profiles_hit) >= 2:
        priority = ("design", "proposal", "network_config", "change_runbook", "operations_runbook")
        provisional = max(
            priority,
            key=lambda p: (name_signals[p], -priority.index(p)),
        )
        return ReviewClassification(
            document_profile=provisional,
            confidence="conflict",
            reason=(
                "ファイル名から複数のプロファイル signal が検出されました "
                f"({', '.join(name_profiles_hit)})。"
                f"暫定的に '{provisional}' を選択しています。"
                "サイドバーから手動で選択することを推奨します。"
            ),
        )

    # Conflict case 2: filename signal disagrees with body strong signal.
    if name_profiles_hit and body_profiles_hit:
        name_profile = name_profiles_hit[0]
        body_profile = body_profiles_hit[0]
        if name_profile != body_profile:
            return ReviewClassification(
                document_profile=name_profile,
                confidence="conflict",
                reason=(
                    f"ファイル名は '{name_profile}' を示唆していますが、"
                    f"本文には '{body_profile}' の強い signal "
                    "(Config構文/タイムチャート/切戻し/エスカレーション等) が含まれています。"
                    f"暫定的に '{name_profile}' を選択しています。"
                    "サイドバーから手動で選択することを推奨します。"
                ),
            )

    # Clean classification: filename only.
    if name_profiles_hit:
        profile = name_profiles_hit[0]
        return ReviewClassification(
            document_profile=profile,
            confidence="high",
            reason=f"ファイル名から '{profile}' プロファイルと判定しました。",
        )

    # Clean classification: body strong signal only.
    if body_profiles_hit:
        profile = body_profiles_hit[0]
        return ReviewClassification(
            document_profile=profile,
            confidence="medium",
            reason=(
                f"本文から '{profile}' の強い signal を検出しました "
                "(ファイル名からの判定はできませんでした)。"
            ),
        )

    # ----- Fallback -----
    if documents and suffixes and suffixes.issubset(DESIGN_EXTENSIONS) and code_like_count == 0:
        return ReviewClassification(
            document_profile="design",
            confidence="medium",
            reason="ファイル拡張子が文書系フォーマットと一致しています。",
        )

    return ReviewClassification(
        document_profile="design",
        confidence="low",
        reason="コード・ファイル名・本文のいずれからも強い signal が検出されなかったため、設計書として扱います。",
    )


def render_rubric_for_prompt(rubric: ReviewRubric) -> str:
    lines = [
        f"Rubric ID: {rubric.rubric_id}",
        f"Rubric Name: {rubric.rubric_name}",
        f"Document Profile: {rubric.document_profile}",
        "Mandatory checks:",
    ]

    for check in rubric.mandatory_checks:
        lines.append(f"- {check.name}: {check.requirement}")
        for point in check.check_points:
            lines.append(f"  checkpoint: {point}")
        for fail_condition in check.fail_conditions:
            lines.append(f"  fail_condition: {fail_condition}")

    lines.append("Evaluation axes:")
    for axis in rubric.evaluation_axes:
        lines.append(f"- {axis.name} (weight={axis.weight}): {axis.purpose}")
        for checkpoint in axis.checkpoints:
            lines.append(f"  checkpoint: {checkpoint}")
        for fail_condition in axis.fail_conditions:
            lines.append(f"  fail_condition: {fail_condition}")

    if rubric.review_policy:
        lines.append("Review policy:")
        for policy in rubric.review_policy:
            lines.append(f"- {policy}")

    return "\n".join(lines)


def _normalize_for_signal_match(text: str) -> str:
    """Lower-case the text for case-insensitive keyword matching.

    Japanese keywords are stored in canonical form in the constant
    dictionaries, so no further normalisation (full/half-width, hiragana/
    katakana) is performed here.
    """
    return text.lower()


def _collect_filename_signals(
    documents: list[SanitizedDocument],
) -> dict[str, int]:
    """Count how many documents matched each profile signal by filename.

    Returns a dict with keys "design", "proposal", "network_config", "change_runbook",
    "operations_runbook" and integer counts. Each document contributes to at
    most one profile (first match wins, in priority order: design ->
    proposal -> network_config -> change_runbook -> operations_runbook).
    """
    counts: dict[str, int] = {
        "design": 0,
        "proposal": 0,
        "network_config": 0,
        "change_runbook": 0,
        "operations_runbook": 0,
    }
    for document in documents:
        name = _normalize_for_signal_match(document.name or "")
        if not name:
            continue
        if any(keyword in name for keyword in FILENAME_DESIGN_KEYWORDS):
            counts["design"] += 1
            continue
        if any(keyword in name for keyword in FILENAME_PROPOSAL_KEYWORDS):
            counts["proposal"] += 1
            continue
        if _filename_network_config_hit(name, _suffix_of(document.name or "")):
            counts["network_config"] += 1
            continue
        if any(keyword in name for keyword in FILENAME_CHANGE_RUNBOOK_KEYWORDS):
            counts["change_runbook"] += 1
            continue
        if any(keyword in name for keyword in FILENAME_OPERATIONS_RUNBOOK_KEYWORDS):
            counts["operations_runbook"] += 1
            continue
    return counts


def _collect_body_strong_signals(corpus: str) -> dict[str, bool]:
    """Detect strong body signals in the combined body corpus.

    The corpus is expected to be already lower-cased by the caller.
    Returns a dict like {"network_config": True, "change_runbook": False}.
    """
    return {
        "network_config": looks_like_network_config(corpus),
        "change_runbook": any(
            keyword in corpus for keyword in BODY_CHANGE_RUNBOOK_STRONG_SIGNALS
        ),
        "operations_runbook": any(
            keyword in corpus for keyword in BODY_OPERATIONS_STRONG_SIGNALS
        ),
    }


def _suffix_of(name: str) -> str:
    lower_name = name.lower()
    if "." not in lower_name:
        return ""
    return "." + lower_name.rsplit(".", 1)[1]


def _filename_network_config_hit(name: str, suffix: str) -> bool:
    strong_terms = (
        "running-config",
        "startup-config",
        "show running",
        "show_run",
        "show-run",
        "コンフィグ",
        "機器config",
        "機器設定",
    )
    if any(term in name for term in strong_terms):
        return True

    platform_terms = (
        "cisco",
        "ios",
        "ios-xe",
        "iosxe",
        "fortigate",
        "fortinet",
        "fortios",
        "router",
        "switch",
        "firewall",
        "fw",
    )
    config_terms = ("config", "cfg", "conf", "設定")
    if any(platform in name for platform in platform_terms) and any(
        term in name for term in config_terms
    ):
        return True

    return suffix in NETWORK_CONFIG_EXTENSIONS and any(
        platform in name for platform in platform_terms
    )


def _looks_like_source_code(text: str) -> bool:
    lowered = text.lower()
    signals = (
        "def ",
        "class ",
        "import ",
        "from ",
        "try:",
        "except",
        "finally:",
        "function ",
        "param(",
        "#!/bin/",
        "#!/usr/bin/env",
        "set -e",
        "write-host",
        "write-output",
        "invoke-",
        "sub ",
        "end sub",
        "select case",
        "public function",
        "private sub",
        "createobject(",
        "os.system(",
        "subprocess.",
    )
    signal_hits = sum(1 for signal in signals if signal in lowered)
    punctuation_hits = sum(token in text for token in ("{", "}", ";", "=>"))
    return signal_hits >= 2 or (signal_hits >= 1 and punctuation_hits >= 2)


# ============================================================================
# Phase 4 (2026-05-08): 構造定義書 v0.2 ベースの 15 章構造定義
# ============================================================================
# 構造定義書「設計書 構造定義書 v0.2」(IPA + AWS WAF + ISO/IEC 25010 ベース) の
# §3 (15 章構造) と §4 (各章の必須記載事項) を Python データクラスとして定義。
#
# 既存の MandatoryCheck / EvaluationAxis / ReviewRubric / RUBRICS は変更せず、
# 新しい構造を **追加** する形で共存させる。Phase 5 で LLM プロンプトと統合し、
# checklist_results / missing_chapters の評価に使う。
#
# 必須度 (necessity) と重み (weight) の対応は v0.2 §6.3 に基づく:
#   - "must" (必須):       weight = 3
#   - "recommended" (推奨): weight = 2
#   - "optional" (任意):    weight = 1
#
# related_quality は ISO/IEC 25010 (8 特性) または AWS WAF (5 柱) のタグ。
# 表記:
#   ISO 25010: ISO_FunctionalSuitability, ISO_PerformanceEfficiency,
#              ISO_Compatibility, ISO_Usability, ISO_Reliability,
#              ISO_Security, ISO_Maintainability, ISO_Portability
#   AWS WAF:   WAF_OE (Operational Excellence), WAF_SEC (Security),
#              WAF_REL (Reliability), WAF_PERF (Performance Efficiency),
#              WAF_COST (Cost Optimization)
# ============================================================================


@dataclass(frozen=True)
class ChapterChecklistItem:
    """構造定義書 v0.2 第 4 章のチェック項目 1 件分。

    LLM はこの構造を input として受け取り、各文書がこの項目を満たすかを
    5 段階 (excellent/good/acceptable/needs_improvement/unacceptable) で評価する。
    """
    item_id: str               # 例: "1.1"
    item_name: str             # 例: "本書の目的"
    necessity: str             # "must" / "recommended" / "optional"
    weight: int                # 3 / 2 / 1 (v0.2 §6.3)
    expected_content: str      # 記載内容 (v0.2 §4 各表「記載内容」列)
    fail_conditions: tuple[str, ...]   # 失敗条件 (v0.2 §4 各表「失敗条件」列)
    related_quality: tuple[str, ...] = ()  # ISO 25010 / WAF タグ


@dataclass(frozen=True)
class StandardChapter:
    """15 章構造の 1 章分。

    LLM は文書全体に対して、この章をカバーしているかどうかを判定する
    (Phase 5 の missing_chapters 機能で使用)。
    """
    chapter_id: str                        # 例: "ch1"
    chapter_name: str                      # 例: "はじめに"
    purpose: str                           # 章の主目的 (v0.2 §3 の表より)
    items: tuple[ChapterChecklistItem, ...]


# ----------------------------------------------------------------------------
# 構造定義書 v0.2 §3 + §4 から派生する 15 章構造の完全定義
# ----------------------------------------------------------------------------
DESIGN_DOC_STRUCTURE_V0_2: tuple[StandardChapter, ...] = (
    # ========================================================================
    # 第 1 章 はじめに (v0.2 §4.1)
    # ========================================================================
    StandardChapter(
        chapter_id="ch1",
        chapter_name="はじめに",
        purpose="目的・スコープ・関係者の明示",
        items=(
            ChapterChecklistItem(
                item_id="1.1", item_name="本書の目的", necessity="must", weight=3,
                expected_content="構築目的、対象システム、想定読者、期待される成果",
                fail_conditions=("目的が抽象的", "対象不明"),
                related_quality=("ISO_FunctionalSuitability",),
            ),
            ChapterChecklistItem(
                item_id="1.2", item_name="スコープ", necessity="must", weight=3,
                expected_content="対象範囲・対象外範囲・関連システムとの境界",
                fail_conditions=("スコープ不明", "対象外の言及なし"),
                related_quality=("ISO_FunctionalSuitability",),
            ),
            ChapterChecklistItem(
                item_id="1.3", item_name="関係者・体制", necessity="must", weight=3,
                expected_content="体制図、責任範囲、エスカレーションパス、ベンダー",
                fail_conditions=("体制不明", "責任分界点不明"),
            ),
            ChapterChecklistItem(
                item_id="1.4", item_name="用語定義", necessity="recommended", weight=2,
                expected_content="略語・固有用語・本書独自用語の定義",
                fail_conditions=("主要用語が未定義",),
            ),
            ChapterChecklistItem(
                item_id="1.5", item_name="参照文書", necessity="recommended", weight=2,
                expected_content="関連設計書・規格・既存運用文書の一覧",
                fail_conditions=("参照文書なし", "版番号不明"),
            ),
            ChapterChecklistItem(
                item_id="1.6", item_name="改訂履歴", necessity="must", weight=3,
                expected_content="版番号、改訂日、改訂内容、承認者",
                fail_conditions=("改訂履歴なし", "未管理状態"),
                related_quality=("ISO_Maintainability",),
            ),
        ),
    ),
    # ========================================================================
    # 第 2 章 システム要件 (v0.2 §4.2)
    # ========================================================================
    StandardChapter(
        chapter_id="ch2",
        chapter_name="システム要件",
        purpose="機能要件・非機能要件の整理",
        items=(
            ChapterChecklistItem(
                item_id="2.1", item_name="業務要件", necessity="must", weight=3,
                expected_content="業務目的、現状業務、改善目標",
                fail_conditions=("業務目的不明", "現状把握なし"),
                related_quality=("ISO_FunctionalSuitability",),
            ),
            ChapterChecklistItem(
                item_id="2.2", item_name="機能要件", necessity="must", weight=3,
                expected_content="ユースケース、機能一覧、優先度、入出力",
                fail_conditions=("機能一覧なし", "優先度なし"),
                related_quality=("ISO_FunctionalSuitability",),
            ),
            ChapterChecklistItem(
                item_id="2.3", item_name="非機能要件 (NFR)", necessity="must", weight=3,
                expected_content="WAF 5 柱 (OE/SEC/REL/PERF/COST) について各々定量目標",
                fail_conditions=("WAF 5 柱のいずれかに言及なし", "定量目標なし"),
                related_quality=("WAF_OE", "WAF_SEC", "WAF_REL", "WAF_PERF", "WAF_COST"),
            ),
            ChapterChecklistItem(
                item_id="2.4", item_name="制約条件", necessity="recommended", weight=2,
                expected_content="法令・社内ポリシー・ベンダ依存・予算・スケジュール",
                fail_conditions=("制約事項の記載なし",),
            ),
            ChapterChecklistItem(
                item_id="2.5", item_name="前提条件", necessity="recommended", weight=2,
                expected_content="業務前提、技術前提、環境前提",
                fail_conditions=("前提が暗黙的", "未明示"),
            ),
        ),
    ),
    # ========================================================================
    # 第 3 章 システム全体構成 (v0.2 §4.3)
    # ========================================================================
    StandardChapter(
        chapter_id="ch3",
        chapter_name="システム全体構成",
        purpose="物理・論理の構成、データフロー",
        items=(
            ChapterChecklistItem(
                item_id="3.1", item_name="全体構成図", necessity="must", weight=3,
                expected_content="物理構成 + 論理構成 (両方)、凡例",
                fail_conditions=("構成図なし", "凡例なし"),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="3.2", item_name="構成要素一覧", necessity="must", weight=3,
                expected_content="各コンポーネント、役割、提供元、版数",
                fail_conditions=("コンポーネント一覧なし",),
                related_quality=("ISO_Maintainability",),
            ),
            ChapterChecklistItem(
                item_id="3.3", item_name="データフロー", necessity="recommended", weight=2,
                expected_content="システム間/コンポーネント間のデータの流れ",
                fail_conditions=("データフロー図なし",),
            ),
            ChapterChecklistItem(
                item_id="3.4", item_name="ステークホルダ視点", necessity="recommended", weight=2,
                expected_content="利用者/運用者/監査の各視点での見え方",
                fail_conditions=("単一視点のみ",),
            ),
            ChapterChecklistItem(
                item_id="3.5", item_name="環境構成", necessity="must", weight=3,
                expected_content="本番/検証/開発環境の構成と差異",
                fail_conditions=("環境分離なし", "差異不明"),
                related_quality=("WAF_OE",),
            ),
        ),
    ),
    # ========================================================================
    # 第 4 章 ネットワーク設計 (v0.2 §4.4)
    # ========================================================================
    StandardChapter(
        chapter_id="ch4",
        chapter_name="ネットワーク設計",
        purpose="接続性・帯域・冗長性",
        items=(
            ChapterChecklistItem(
                item_id="4.1", item_name="ネットワーク構成", necessity="must", weight=3,
                expected_content="VPC/サブネット/AZ 構成、IP アドレス体系",
                fail_conditions=("構成図なし", "IP 設計なし"),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="4.2", item_name="接続要件", necessity="must", weight=3,
                expected_content="利用プロトコル、ポート、暗号化要件",
                fail_conditions=("プロトコル不明", "平文通信が暗黙"),
                related_quality=("WAF_SEC",),
            ),
            ChapterChecklistItem(
                item_id="4.3", item_name="経路設計", necessity="must", weight=3,
                expected_content="ルーティング、Direct Connect/VPN、NAT/PAT",
                fail_conditions=("経路設計なし",),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="4.4", item_name="帯域・遅延設計", necessity="recommended", weight=2,
                expected_content="想定帯域、SLA、レイテンシ目標",
                fail_conditions=("帯域見積なし",),
                related_quality=("WAF_PERF", "ISO_PerformanceEfficiency"),
            ),
            ChapterChecklistItem(
                item_id="4.5", item_name="冗長化", necessity="must", weight=3,
                expected_content="SPOF 排除、フェイルオーバ、BGP/HA",
                fail_conditions=("SPOF 残存", "冗長化なし"),
                related_quality=("WAF_REL", "ISO_Reliability"),
            ),
            ChapterChecklistItem(
                item_id="4.6", item_name="DNS 設計", necessity="must", weight=3,
                expected_content="名前解決方針、DNS サーバ、ゾーン設計",
                fail_conditions=("DNS 設計なし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 5 章 アカウント・認可設計 (v0.2 §4.5)
    # ========================================================================
    StandardChapter(
        chapter_id="ch5",
        chapter_name="アカウント・認可設計",
        purpose="認証・認可・権限分離",
        items=(
            ChapterChecklistItem(
                item_id="5.1", item_name="アカウント方針", necessity="must", weight=3,
                expected_content="人/サービスの分類、命名規則、ライフサイクル",
                fail_conditions=("方針なし", "命名不統一"),
                related_quality=("WAF_SEC",),
            ),
            ChapterChecklistItem(
                item_id="5.2", item_name="認証方式", necessity="must", weight=3,
                expected_content="パスワードポリシー、MFA、SSO、フェデレーション",
                fail_conditions=("MFA なし", "ポリシー不明"),
                related_quality=("WAF_SEC", "ISO_Security"),
            ),
            ChapterChecklistItem(
                item_id="5.3", item_name="認可・権限分離", necessity="must", weight=3,
                expected_content="最小権限原則、ロール設計、ABAC/RBAC",
                fail_conditions=("全権限付与", "最小権限なし"),
                related_quality=("WAF_SEC", "ISO_Security"),
            ),
            ChapterChecklistItem(
                item_id="5.4", item_name="職務分掌 (SoD)", necessity="recommended", weight=2,
                expected_content="開発/運用/監査の権限分離",
                fail_conditions=("単一人物が全権限保有",),
                related_quality=("WAF_SEC",),
            ),
            ChapterChecklistItem(
                item_id="5.5", item_name="アカウント棚卸", necessity="recommended", weight=2,
                expected_content="定期見直しサイクル、退職者処理",
                fail_conditions=("棚卸プロセスなし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 6 章 データ設計 (v0.2 §4.6)
    # ========================================================================
    StandardChapter(
        chapter_id="ch6",
        chapter_name="データ設計",
        purpose="データモデル・ストレージ・保護",
        items=(
            ChapterChecklistItem(
                item_id="6.1", item_name="データモデル", necessity="recommended", weight=2,
                expected_content="エンティティ、関連、属性 (アプリ依存)",
                fail_conditions=("アプリ設計に委譲不明",),
            ),
            ChapterChecklistItem(
                item_id="6.2", item_name="ストレージ設計", necessity="must", weight=3,
                expected_content="種別 (DB/オブジェクト/ブロック)、容量、IOPS",
                fail_conditions=("ストレージ未定",),
                related_quality=("WAF_REL", "WAF_PERF"),
            ),
            ChapterChecklistItem(
                item_id="6.3", item_name="データ保護", necessity="must", weight=3,
                expected_content="暗号化 (in-transit, at-rest)、鍵管理",
                fail_conditions=("暗号化なし", "平文保管"),
                related_quality=("WAF_SEC", "ISO_Security"),
            ),
            ChapterChecklistItem(
                item_id="6.4", item_name="バックアップ・リカバリ", necessity="must", weight=3,
                expected_content="RPO/RTO、頻度、保管期間、リストア手順",
                fail_conditions=("RPO/RTO 未定義",),
                related_quality=("WAF_REL", "ISO_Reliability"),
            ),
            ChapterChecklistItem(
                item_id="6.5", item_name="データライフサイクル", necessity="recommended", weight=2,
                expected_content="保存期間、廃棄ポリシー、アーカイブ",
                fail_conditions=("廃棄ポリシーなし",),
            ),
            ChapterChecklistItem(
                item_id="6.6", item_name="ログ保管", necessity="must", weight=3,
                expected_content="監査ログ・アプリログの保管期間と取扱",
                fail_conditions=("ログ保管期間不明",),
                related_quality=("WAF_SEC",),
            ),
        ),
    ),
    # ========================================================================
    # 第 7 章 アプリケーション・サービス設計 (v0.2 §4.7)
    # ========================================================================
    StandardChapter(
        chapter_id="ch7",
        chapter_name="アプリケーション・サービス設計",
        purpose="アプリ構成・連携・メッセージング",
        items=(
            ChapterChecklistItem(
                item_id="7.1", item_name="アプリ構成", necessity="must", weight=3,
                expected_content="コンポーネント構成、デプロイ方式",
                fail_conditions=("構成不明",),
                related_quality=("ISO_FunctionalSuitability",),
            ),
            ChapterChecklistItem(
                item_id="7.2", item_name="外部 IF", necessity="must", weight=3,
                expected_content="API、メッセージング、ファイル連携",
                fail_conditions=("IF 仕様なし",),
                related_quality=("ISO_Compatibility",),
            ),
            ChapterChecklistItem(
                item_id="7.3", item_name="内部連携", necessity="recommended", weight=2,
                expected_content="サービス間通信、認証伝播",
                fail_conditions=("内部認証不明",),
            ),
            ChapterChecklistItem(
                item_id="7.4", item_name="エラーハンドリング", necessity="recommended", weight=2,
                expected_content="異常系設計、リトライ、サーキットブレーカー",
                fail_conditions=("正常系のみ",),
                related_quality=("ISO_Reliability",),
            ),
        ),
    ),
    # ========================================================================
    # 第 8 章 可用性設計 (v0.2 §4.8)
    # ========================================================================
    StandardChapter(
        chapter_id="ch8",
        chapter_name="可用性設計",
        purpose="SLI/SLO/SLA, DR/BCP",
        items=(
            ChapterChecklistItem(
                item_id="8.1", item_name="SLI/SLO/SLA", necessity="must", weight=3,
                expected_content="サービス指標、目標、契約レベル",
                fail_conditions=("SLO 未定義",),
                related_quality=("WAF_REL", "ISO_Reliability"),
            ),
            ChapterChecklistItem(
                item_id="8.2", item_name="単一障害点", necessity="must", weight=3,
                expected_content="SPOF の特定と対策",
                fail_conditions=("SPOF 残存",),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="8.3", item_name="DR (災害対策)", necessity="must", weight=3,
                expected_content="DR 方針、リージョン構成、RPO/RTO",
                fail_conditions=("DR 設計なし",),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="8.4", item_name="BCP (事業継続)", necessity="recommended", weight=2,
                expected_content="業務継続計画、復旧手順",
                fail_conditions=("BCP なし",),
            ),
            ChapterChecklistItem(
                item_id="8.5", item_name="訓練・演習", necessity="recommended", weight=2,
                expected_content="切替訓練、リハーサル計画",
                fail_conditions=("訓練計画なし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 9 章 性能設計 (v0.2 §4.9)
    # ========================================================================
    StandardChapter(
        chapter_id="ch9",
        chapter_name="性能設計",
        purpose="性能目標・スケーラビリティ",
        items=(
            ChapterChecklistItem(
                item_id="9.1", item_name="性能目標", necessity="must", weight=3,
                expected_content="スループット、レスポンスタイム、同時接続数",
                fail_conditions=("性能目標なし",),
                related_quality=("WAF_PERF", "ISO_PerformanceEfficiency"),
            ),
            ChapterChecklistItem(
                item_id="9.2", item_name="容量見積", necessity="must", weight=3,
                expected_content="データ容量、ピーク負荷、伸び率",
                fail_conditions=("容量見積なし",),
                related_quality=("WAF_PERF",),
            ),
            ChapterChecklistItem(
                item_id="9.3", item_name="スケーラビリティ", necessity="must", weight=3,
                expected_content="スケールアウト/アップ方針、自動化",
                fail_conditions=("スケール戦略なし",),
                related_quality=("WAF_PERF",),
            ),
            ChapterChecklistItem(
                item_id="9.4", item_name="ボトルネック分析", necessity="recommended", weight=2,
                expected_content="想定ボトルネック、対策",
                fail_conditions=("分析なし",),
            ),
            ChapterChecklistItem(
                item_id="9.5", item_name="性能試験計画", necessity="recommended", weight=2,
                expected_content="負荷試験のシナリオ、ツール、合格基準",
                fail_conditions=("試験計画なし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 10 章 セキュリティ設計 (v0.2 §4.10)
    # ========================================================================
    StandardChapter(
        chapter_id="ch10",
        chapter_name="セキュリティ設計",
        purpose="脅威モデル・暗号化・監査",
        items=(
            ChapterChecklistItem(
                item_id="10.1", item_name="脅威モデル", necessity="must", weight=3,
                expected_content="STRIDE 等での脅威分析",
                fail_conditions=("脅威分析なし",),
                related_quality=("WAF_SEC", "ISO_Security"),
            ),
            ChapterChecklistItem(
                item_id="10.2", item_name="ネットワーク境界防御", necessity="must", weight=3,
                expected_content="FW、WAF、IDS/IPS",
                fail_conditions=("境界防御なし",),
                related_quality=("WAF_SEC",),
            ),
            ChapterChecklistItem(
                item_id="10.3", item_name="エンドポイント防御", necessity="recommended", weight=2,
                expected_content="アンチウィルス、EDR",
                fail_conditions=("設計なし",),
            ),
            ChapterChecklistItem(
                item_id="10.4", item_name="データ暗号化", necessity="must", weight=3,
                expected_content="in-transit, at-rest、鍵管理 (KMS)",
                fail_conditions=("暗号化なし",),
                related_quality=("WAF_SEC", "ISO_Security"),
            ),
            ChapterChecklistItem(
                item_id="10.5", item_name="監査ログ", necessity="must", weight=3,
                expected_content="取得対象、改ざん防止、保管",
                fail_conditions=("監査ログなし",),
                related_quality=("WAF_SEC",),
            ),
            ChapterChecklistItem(
                item_id="10.6", item_name="インシデント対応", necessity="must", weight=3,
                expected_content="検知/通報/復旧プロセス",
                fail_conditions=("プロセスなし",),
                related_quality=("WAF_SEC",),
            ),
            ChapterChecklistItem(
                item_id="10.7", item_name="脆弱性管理", necessity="recommended", weight=2,
                expected_content="スキャン、パッチ管理",
                fail_conditions=("管理プロセスなし",),
            ),
            ChapterChecklistItem(
                item_id="10.8", item_name="法令・規制対応", necessity="recommended", weight=2,
                expected_content="個人情報保護法、業界規制",
                fail_conditions=("法令言及なし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 11 章 運用設計 (v0.2 §4.11)
    # ========================================================================
    StandardChapter(
        chapter_id="ch11",
        chapter_name="運用設計",
        purpose="監視・アラート・デプロイ・バックアップ",
        items=(
            ChapterChecklistItem(
                item_id="11.1", item_name="監視設計", necessity="must", weight=3,
                expected_content="メトリクス、ログ、トレース、ダッシュボード",
                fail_conditions=("監視設計なし",),
                related_quality=("WAF_OE",),
            ),
            ChapterChecklistItem(
                item_id="11.2", item_name="アラート", necessity="must", weight=3,
                expected_content="閾値、通知先、エスカレーション",
                fail_conditions=("閾値なし", "宛先不明"),
                related_quality=("WAF_OE",),
            ),
            ChapterChecklistItem(
                item_id="11.3", item_name="オンコール体制", necessity="recommended", weight=2,
                expected_content="当番制、シフト、エスカレーションパス",
                fail_conditions=("体制不明",),
            ),
            ChapterChecklistItem(
                item_id="11.4", item_name="デプロイ・リリース", necessity="must", weight=3,
                expected_content="デプロイ方式、ロールバック手順",
                fail_conditions=("手順なし",),
                related_quality=("WAF_OE", "ISO_Maintainability"),
            ),
            ChapterChecklistItem(
                item_id="11.5", item_name="構成管理", necessity="recommended", weight=2,
                expected_content="IaC、変更履歴、承認プロセス",
                fail_conditions=("手作業前提",),
                related_quality=("ISO_Maintainability",),
            ),
            ChapterChecklistItem(
                item_id="11.6", item_name="バックアップ運用", necessity="must", weight=3,
                expected_content="取得頻度、検証、保管",
                fail_conditions=("運用計画なし",),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="11.7", item_name="定期作業", necessity="recommended", weight=2,
                expected_content="パッチ、ローテーション、棚卸",
                fail_conditions=("計画なし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 12 章 コスト設計 (v0.2 §4.12)
    # ========================================================================
    StandardChapter(
        chapter_id="ch12",
        chapter_name="コスト設計",
        purpose="コスト見積・最適化",
        items=(
            ChapterChecklistItem(
                item_id="12.1", item_name="コスト見積", necessity="must", weight=3,
                expected_content="月額/年額、内訳 (リソース別)",
                fail_conditions=("見積なし",),
                related_quality=("WAF_COST",),
            ),
            ChapterChecklistItem(
                item_id="12.2", item_name="コスト最適化", necessity="recommended", weight=2,
                expected_content="リザーブドインスタンス、Spot、Auto Scaling",
                fail_conditions=("最適化施策なし",),
                related_quality=("WAF_COST",),
            ),
            ChapterChecklistItem(
                item_id="12.3", item_name="予算管理", necessity="recommended", weight=2,
                expected_content="予算アラート、承認フロー",
                fail_conditions=("管理プロセスなし",),
            ),
            ChapterChecklistItem(
                item_id="12.4", item_name="コスト削減シナリオ", necessity="optional", weight=1,
                expected_content="スケールダウン手順、廃止計画",
                fail_conditions=(),
            ),
        ),
    ),
    # ========================================================================
    # 第 13 章 拡張性・保守性設計 (v0.2 §4.13)
    # ========================================================================
    StandardChapter(
        chapter_id="ch13",
        chapter_name="拡張性・保守性設計",
        purpose="機能追加・ベンダロックイン回避",
        items=(
            ChapterChecklistItem(
                item_id="13.1", item_name="機能拡張への対応", necessity="recommended", weight=2,
                expected_content="機能追加時のインパクト、拡張ポイント",
                fail_conditions=("拡張不可な硬直設計",),
                related_quality=("ISO_Maintainability",),
            ),
            ChapterChecklistItem(
                item_id="13.2", item_name="ベンダロックイン回避", necessity="recommended", weight=2,
                expected_content="標準準拠、移行可能性",
                fail_conditions=("完全ロックイン",),
                related_quality=("ISO_Portability",),
            ),
            ChapterChecklistItem(
                item_id="13.3", item_name="技術的負債管理", necessity="optional", weight=1,
                expected_content="既知の負債、解消計画",
                fail_conditions=(),
            ),
            ChapterChecklistItem(
                item_id="13.4", item_name="ドキュメント保守", necessity="must", weight=3,
                expected_content="改訂サイクル、責任者",
                fail_conditions=("保守計画なし",),
                related_quality=("ISO_Maintainability",),
            ),
        ),
    ),
    # ========================================================================
    # 第 14 章 移行設計 (v0.2 §4.14)
    # ========================================================================
    StandardChapter(
        chapter_id="ch14",
        chapter_name="移行設計",
        purpose="移行方針・手順・ロールバック",
        items=(
            ChapterChecklistItem(
                item_id="14.1", item_name="移行方針", necessity="must", weight=3,
                expected_content="一括/段階、並行稼働の有無",
                fail_conditions=("方針なし",),
            ),
            ChapterChecklistItem(
                item_id="14.2", item_name="移行手順", necessity="must", weight=3,
                expected_content="切替手順、検証手順",
                fail_conditions=("手順なし",),
            ),
            ChapterChecklistItem(
                item_id="14.3", item_name="ロールバック計画", necessity="must", weight=3,
                expected_content="失敗時の戻し方、判定基準",
                fail_conditions=("ロールバック計画なし",),
                related_quality=("WAF_REL",),
            ),
            ChapterChecklistItem(
                item_id="14.4", item_name="データ移行", necessity="must", weight=3,
                expected_content="データ変換、検証、整合性確認",
                fail_conditions=("データ移行設計なし",),
            ),
            ChapterChecklistItem(
                item_id="14.5", item_name="利用者影響", necessity="recommended", weight=2,
                expected_content="サービス停止時間、利用者通知",
                fail_conditions=("影響評価なし",),
            ),
        ),
    ),
    # ========================================================================
    # 第 15 章 補足 (v0.2 §4.15)
    # ========================================================================
    StandardChapter(
        chapter_id="ch15",
        chapter_name="補足",
        purpose="リスク・前提・改訂履歴・参照文書",
        items=(
            ChapterChecklistItem(
                item_id="15.1", item_name="リスクと前提", necessity="must", weight=3,
                expected_content="リスク一覧、対応方針、未決事項",
                fail_conditions=("リスク管理なし",),
            ),
            ChapterChecklistItem(
                item_id="15.2", item_name="課題管理", necessity="recommended", weight=2,
                expected_content="未決事項一覧、責任者、期限",
                fail_conditions=("課題管理なし",),
            ),
            ChapterChecklistItem(
                item_id="15.3", item_name="別紙・付録", necessity="optional", weight=1,
                expected_content="詳細データ、参考情報",
                fail_conditions=(),
            ),
        ),
    ),
)


def render_chapter_checklist_for_prompt(
    structure: tuple[StandardChapter, ...] = DESIGN_DOC_STRUCTURE_V0_2,
) -> str:
    """構造定義書 v0.2 の 15 章チェックリストを LLM プロンプト用に文字列化。

    Phase 5 で reviewer.py の SYSTEM_PROMPT に埋め込み、LLM が
    各文書のチェック項目を 5 段階で評価できるようにする。

    Returns:
        LLM が読みやすい階層構造のテキスト形式 (各章 + 必須度 + 期待内容)
    """
    lines: list[str] = []
    necessity_label = {
        "must": "[必須]",
        "recommended": "[推奨]",
        "optional": "[任意]",
    }
    for chapter in structure:
        lines.append(
            f"== 第 {chapter.chapter_id[2:]} 章 {chapter.chapter_name} =="
            f" (主目的: {chapter.purpose})"
        )
        for item in chapter.items:
            label = necessity_label.get(item.necessity, "[?]")
            lines.append(
                f"  {item.item_id} {label} {item.item_name} "
                f"(weight={item.weight}): {item.expected_content}"
            )
            if item.fail_conditions:
                fc = "、".join(item.fail_conditions)
                lines.append(f"    失敗条件: {fc}")
        lines.append("")  # 章間の空行
    return "\n".join(lines).rstrip()


def get_chapter_by_id(
    chapter_id: str,
    structure: tuple[StandardChapter, ...] = DESIGN_DOC_STRUCTURE_V0_2,
) -> StandardChapter | None:
    """章 ID (例: 'ch9') から StandardChapter を取得。Phase 5/6 で使用。

    missing_chapters の verdict 判定や UI でのサジェスチョン表示で、
    LLM が返した chapter_id から本来の章定義を引くのに使う。
    """
    for chapter in structure:
        if chapter.chapter_id == chapter_id:
            return chapter
    return None


def get_checklist_item_by_id(
    item_id: str,
    structure: tuple[StandardChapter, ...] = DESIGN_DOC_STRUCTURE_V0_2,
) -> ChapterChecklistItem | None:
    """項目 ID (例: '4.1') から ChapterChecklistItem を取得。Phase 5/6 で使用。

    LLM が返した checklist_results の item_id から本来の項目定義を引くのに使う。
    重み計算や UI でのカテゴリ表示で必要。
    """
    for chapter in structure:
        for item in chapter.items:
            if item.item_id == item_id:
                return item
    return None


# ============================================================================
# Phase 7 段階 2-A (2026-05-08): 章境界検出機能
# ============================================================================
# 1 ファイルに複数章が含まれる場合に、章境界を自動検出して章単位で
# 深堀り評価を可能にする。検出方式は Q34=A: 「第 N 章」+ 「N.」パターン
# (節レベル N.M は採用せず、UI 複雑化を回避)。
#
# 検出失敗時は呼び出し側で fallback (= 1 ファイル全体を深堀り) する設計。
# ============================================================================


@dataclass(frozen=True)
class ChapterSection:
    """1 ファイル内で検出された章の範囲 (Phase 7 段階 2)。

    フィールド:
        chapter_id: 構造定義書 v0.2 の章 ID と紐付け (例: "ch4")。
            検出した章番号が 1〜15 の範囲外なら "ch_unknown"。
        chapter_label: 検出された見出しテキスト (例: "第 4 章 ネットワーク構成")。
            UI 表示用。LLM の章名と異なる場合あり (検出ベース)。
        detected_chapter_num: 検出された章番号 (1〜N、N が 16 以上の場合あり)。
        text_start: 文書内の章開始位置 (0-indexed chars)。
        text_end: 文書内の章終了位置 (排他的、次の章直前 or 文書末尾)。
        extracted_text: 章本文 (この章だけのテキスト)。
            depth-dive call で送信するのはこれ。
    """
    chapter_id: str
    chapter_label: str
    detected_chapter_num: int
    text_start: int
    text_end: int
    extracted_text: str


# 章番号検出の正規表現パターン (Q34=A: 「第 N 章」+ 「N.」)
# - パターン 1: 「第 1 章 はじめに」「第 1章 はじめに」
# - パターン 2: 「1. はじめに」「1.はじめに」(行頭、N は 1〜2 桁)
# 両パターンとも全角スペース・半角スペース両対応。
_CHAPTER_PATTERN_FULL = re.compile(
    r'^[\s\u3000]*第\s*(\d{1,2})\s*章[\s\u3000]+([^\n]+)$',
    re.MULTILINE,
)
_CHAPTER_PATTERN_SHORT = re.compile(
    r'^[\s\u3000]*(\d{1,2})\.\s*([^\n]+)$',
    re.MULTILINE,
)


def extract_chapters_from_text(
    text: str,
    *,
    min_chapters_for_split: int = 3,
) -> tuple[ChapterSection, ...]:
    """文書テキストから章境界を検出する (Phase 7 段階 2-A)。

    Q34=A の方針:
    - パターン 1 「第 N 章」を最優先で試す
    - パターン 1 で 3 章以上検出できれば、それを採用
    - そうでなければパターン 2 「N. 」を試す
    - パターン 2 でも 3 章以上検出できれば採用
    - どちらでも検出失敗 (3 章未満) なら空 tuple (= fallback で 1 文書全体を扱う)

    Q35=A の方針:
    - 3 章以上検出時のみ「複数章ファイル」と判定。
    - 1〜2 章しか検出できなければ、章単位 UI を出さない (空 tuple 返却)。

    Args:
        text: 検出対象の文書テキスト
        min_chapters_for_split: 章単位扱いにする最小章数 (default 3、Q35=A)

    Returns:
        ChapterSection のタプル (検出失敗時は空 tuple)。
        text_start/text_end/extracted_text は文書内の正確な位置を保持。
    """
    # パターン 1 を優先
    matches_full = list(_CHAPTER_PATTERN_FULL.finditer(text))
    if len(matches_full) >= min_chapters_for_split:
        return _build_chapter_sections(text, matches_full, "full")

    # パターン 2 を試す
    matches_short = list(_CHAPTER_PATTERN_SHORT.finditer(text))
    # 注意: パターン 2 は誤検出しやすい (例: "1. はじめに" は章だが
    # "1. 最初に" のような箇条書きも誤マッチする)。検出された章番号が
    # 連番 (1, 2, 3, ...) になっているかを確認して誤検出を排除する。
    if len(matches_short) >= min_chapters_for_split:
        chapter_nums = [int(m.group(1)) for m in matches_short]
        if _is_sequential_chapter_numbers(chapter_nums):
            return _build_chapter_sections(text, matches_short, "short")

    # どちらでも検出失敗
    return ()


def _is_sequential_chapter_numbers(nums: list[int]) -> bool:
    """章番号リストが連番として妥当か判定 (パターン 2 の誤検出排除)。

    妥当な条件:
    - 最初の番号が 1 (0 や 2 から始まる箇条書きを排除)
    - 全章の 80% 以上が diff=1 (連続) であること
      (たまに 1 章スキップしても許容するが、1, 3, 5, 7 のような
      飛び番号パターンは排除する)
    - 最後の番号が 15 以下 (15 章を超える文書はないと仮定)

    例:
    - [1, 2, 3, 4] → True (全て diff=1)
    - [1, 2, 4, 5] → True (3/3 が diff=1〜2 で 80%+)
    - [1, 3, 5, 7] → False (全て diff=2、連続性がない)
    - [3, 4, 5] → False (1 から始まらない)
    - [1, 2, 3, ..., 30] → False (15 章を超える)
    """
    if not nums or nums[0] != 1:
        return False
    if nums[-1] > 15:
        return False
    if len(nums) < 2:
        return True
    # diff の集計
    diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
    # 全 diff が 1〜2 以内であり、かつ diff=1 の割合が 80% 以上
    if any(d < 1 or d > 2 for d in diffs):
        return False
    # diff=1 の割合
    seq_count = sum(1 for d in diffs if d == 1)
    seq_ratio = seq_count / len(diffs)
    return seq_ratio >= 0.8


def _build_chapter_sections(
    text: str,
    matches: list,  # list[re.Match]
    pattern_kind: str,  # "full" or "short"
) -> tuple[ChapterSection, ...]:
    """正規表現マッチ結果から ChapterSection のリストを構築。

    各章の text_start は match.start() (見出し行の先頭)、
    text_end は次の match.start() 直前 (or 文書末尾)。
    """
    sections: list[ChapterSection] = []
    for i, m in enumerate(matches):
        chapter_num = int(m.group(1))
        chapter_title = m.group(2).strip()
        text_start = m.start()
        text_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)

        if pattern_kind == "full":
            chapter_label = f"第 {chapter_num} 章 {chapter_title}"
        else:
            chapter_label = f"{chapter_num}. {chapter_title}"

        # 構造定義書 v0.2 の章 ID と紐付け
        # 検出した章番号が 1〜15 の範囲なら "ch{N}"、範囲外なら "ch_unknown"
        if 1 <= chapter_num <= 15:
            chapter_id = f"ch{chapter_num}"
        else:
            chapter_id = "ch_unknown"

        sections.append(ChapterSection(
            chapter_id=chapter_id,
            chapter_label=chapter_label,
            detected_chapter_num=chapter_num,
            text_start=text_start,
            text_end=text_end,
            extracted_text=text[text_start:text_end].strip(),
        ))
    return tuple(sections)
