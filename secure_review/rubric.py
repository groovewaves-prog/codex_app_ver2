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

DESIGN_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".md", ".txt", ".csv", ".yaml", ".yml", ".json"}


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
        mandatory_checks=COMMON_MANDATORY_CHECKS,
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
                ),
                fail_conditions=("作業対象が特定できない", "開始条件が未記載"),
            ),
            EvaluationAxis(
                id="change_risk",
                name="変更影響・切戻し",
                weight=30,
                purpose="改修時の事故を防げるか",
                checkpoints=(
                    "影響範囲が明記されている",
                    "切戻し条件と切戻し手順がある",
                    "作業継続可否の判定ポイントがある",
                ),
                fail_conditions=("切戻し手順がない", "判定ポイントがない"),
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
                ),
            ),
            EvaluationAxis(
                id="testability",
                name="試験妥当性",
                weight=20,
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
        ),
    ),
    "operations_runbook": ReviewRubric(
        rubric_id="operations_runbook_v1",
        rubric_name="保守・運用手順書レビュー基準",
        document_profile="operations_runbook",
        target_documents=("保守手順書", "運用手順書", "障害対応手順書"),
        mandatory_checks=COMMON_MANDATORY_CHECKS,
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
                id="operability",
                name="運用保守性",
                weight=30,
                purpose="保守担当が迷わず対応できるか",
                checkpoints=(
                    "監視項目と確認ポイントが定義されている",
                    "障害時の切り分け手順がある",
                    "連絡先やエスカレーションがある",
                ),
                fail_conditions=("障害時の確認ポイントがない",),
            ),
            EvaluationAxis(
                id="security",
                name="セキュリティ",
                weight=20,
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
                weight=15,
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
                reason=f"The document profile was explicitly overridden to '{normalized}'.",
            )

    return detect_document_profile(documents)


def detect_document_profile(documents: list[SanitizedDocument]) -> ReviewClassification:
    corpus = "\n".join(f"{document.name}\n{document.outbound_text[:1500]}" for document in documents).lower()
    suffixes = {_suffix_of(document.name) for document in documents if document.name}
    code_like_count = sum(1 for document in documents if _looks_like_source_code(document.outbound_text))
    documents_count = max(len(documents), 1)

    if documents and suffixes and suffixes.issubset(SOURCE_CODE_EXTENSIONS):
        return ReviewClassification(
            document_profile="source_code",
            confidence="high",
            reason="All uploaded files use known source-code extensions.",
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
            reason="The content contains source-code syntax and execution constructs.",
        )

    if any(
        keyword in corpus
        for keyword in (
            "変更",
            "切替",
            "切り替え",
            "rollback",
            "backout",
            "timechart",
            "タイムチャート",
            "change",
            "switchover",
            "cutover",
            "runbook",
        )
    ):
        return ReviewClassification(
            document_profile="change_runbook",
            confidence="medium",
            reason="The content includes change or switchover vocabulary.",
        )

    if any(
        keyword in corpus
        for keyword in ("保守", "運用", "障害", "監視", "エスカレーション", "operations", "monitoring")
    ):
        return ReviewClassification(
            document_profile="operations_runbook",
            confidence="medium",
            reason="The content includes operations or incident-management vocabulary.",
        )

    if documents and suffixes and suffixes.issubset(DESIGN_EXTENSIONS) and code_like_count == 0:
        return ReviewClassification(
            document_profile="design",
            confidence="medium",
            reason="The file extensions match common design or document formats.",
        )

    return ReviewClassification(
        document_profile="design",
        confidence="low",
        reason="No strong code or runbook signals were detected, so the documents were treated as design artifacts.",
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
