from __future__ import annotations

from dataclasses import dataclass, field

from secure_review.models import SanitizedDocument


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
        mandatory_checks=COMMON_MANDATORY_CHECKS[:2],
        evaluation_axes=(
            EvaluationAxis(
                id="completeness",
                name="完全性",
                weight=20,
                purpose="必要な情報が不足なく記載されているか",
                checkpoints=(
                    "対象範囲が明記されている",
                    "対象機器、役割、接続先が分かる",
                    "前提条件、制約条件が記載されている",
                ),
                fail_conditions=("対象機器が特定できない", "前提条件が未記載"),
            ),
            EvaluationAxis(
                id="consistency",
                name="整合性",
                weight=20,
                purpose="資料内および関連資料との矛盾がないか",
                checkpoints=(
                    "構成図と本文の機器名が一致する",
                    "IPアドレス、IF名、ホスト名に矛盾がない",
                    "設計内容と試験観点の対応が取れている",
                ),
                fail_conditions=("機器名やIP体系に矛盾がある",),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=25,
                purpose="安全な構成と運用方針が考慮されているか",
                checkpoints=(
                    "認証方式と管理アクセス経路が明記されている",
                    "不要サービス停止やログ取得方針がある",
                    "権限管理や監査の考え方がある",
                ),
                fail_conditions=("平文認証や危険な設定を放置", "特権ID運用が不明"),
            ),
            EvaluationAxis(
                id="operability",
                name="運用保守性",
                weight=15,
                purpose="保守担当が迷わず運用できるか",
                checkpoints=(
                    "監視項目が定義されている",
                    "障害時の確認ポイントがある",
                    "引継ぎ可能な説明粒度になっている",
                ),
            ),
            EvaluationAxis(
                id="testability",
                name="試験妥当性",
                weight=20,
                purpose="設計内容が試験で確認できるか",
                checkpoints=(
                    "試験項目が設計内容に対応している",
                    "期待結果が具体的に書かれている",
                    "異常系または切替試験が考慮されている",
                ),
            ),
        ),
        review_policy=(
            "冒頭の目的記載の有無を最優先で確認すること。",
            "構成図などの構成情報が無い場合は高リスクとして扱うこと。",
            "指摘は blocking / required / recommended の厳しさを意識して記述すること。",
        ),
    ),
    "change_runbook": ReviewRubric(
        rubric_id="change_runbook_v1",
        rubric_name="変更・切替手順書レビュー基準",
        document_profile="change_runbook",
        target_documents=("変更手順書", "切替手順書", "構築手順書"),
        mandatory_checks=COMMON_MANDATORY_CHECKS + (OPTIONAL_CHECKS[0],),
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
        mandatory_checks=COMMON_MANDATORY_CHECKS + (OPTIONAL_CHECKS[0],),
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
        priority = ("design", "change_runbook", "operations_runbook")
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
                    "(タイムチャート/切戻し/エスカレーション等) が含まれています。"
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

    Returns a dict with keys "design", "change_runbook", "operations_runbook"
    and integer counts. Each document contributes to at most one profile
    (first match wins, in priority order: design -> change_runbook ->
    operations_runbook).
    """
    counts: dict[str, int] = {
        "design": 0,
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
        if any(keyword in name for keyword in FILENAME_CHANGE_RUNBOOK_KEYWORDS):
            counts["change_runbook"] += 1
            continue
        if any(keyword in name for keyword in FILENAME_OPERATIONS_RUNBOOK_KEYWORDS):
            counts["operations_runbook"] += 1
            continue
    return counts


def _collect_body_strong_signals(corpus: str) -> dict[str, bool]:
    """Detect strong runbook signals in the combined body corpus.

    The corpus is expected to be already lower-cased by the caller.
    Returns a dict like {"change_runbook": True, "operations_runbook": False}.
    """
    return {
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
        "set -e",
        "write-host",
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
