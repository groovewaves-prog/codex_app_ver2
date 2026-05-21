from __future__ import annotations

from dataclasses import dataclass

from secure_review.models import SanitizedDocument


@dataclass(frozen=True)
class AgentStage:
    label: str
    state: str
    detail: str
    tone: str = "idle"


@dataclass(frozen=True)
class AgentBrief:
    mode: str
    mission: str
    next_action: str
    risk_summary: str
    stages: tuple[AgentStage, ...]
    monitors: tuple[str, ...]


@dataclass(frozen=True)
class OperationGuide:
    tone: str
    step_label: str
    headline: str
    primary_action: str
    reason: str
    done_when: str
    watch_out: str
    checklist: tuple[str, ...]


def build_operation_guide(
    *,
    upload_count: int,
    has_preview_docs: bool,
    blocked_count: int,
    confirmation_count: int,
    send_approved: bool,
    token_status: str = "unknown",
    review_in_progress: bool = False,
    review_done: bool = False,
    can_regenerate_anonymization: bool = False,
) -> OperationGuide:
    """Build a local, deterministic operation guide for first-time users.

    The guide is intentionally not an autonomous agent. It acts like a
    co-pilot: explains the next safe UI action, why it matters, and what
    success looks like before the user moves to the next step.
    """
    if review_done:
        return OperationGuide(
            tone="success",
            step_label="ステップ 4 / レビュー結果確認",
            headline="レビュー結果を確認できます",
            primary_action="文書構成チェック、概要レビュー、章別レビュー、深堀候補の順に確認してください。",
            reason="全体から詳細へ読むと、重要不足と章別指摘の整合性を確認しやすくなります。",
            done_when="対応すべき指摘、保留する指摘、追加確認する指摘を整理できた状態です。",
            watch_out="深堀はトークンを消費します。まず深堀候補章を優先してください。",
            checklist=(
                "高重要度の指摘を先に確認",
                "構成不足と章別レビューの矛盾がないか確認",
                "必要なら結果ログ(JSON)を保存",
            ),
        )

    if review_in_progress:
        return OperationGuide(
            tone="active",
            step_label="ステップ 3 / レビュー実行中",
            headline="レビュー処理を実行中です",
            primary_action="画面を閉じずに、進捗バーと処理中ファイル名を確認してください。",
            reason="外部LLMの応答待ちです。途中で画面をリロードすると処理状態が分かりにくくなります。",
            done_when="ステータスが「レビュー完了」になり、レビュー結果セクションが表示されます。",
            watch_out="大きい文書束では時間がかかります。エラーが出た場合は表示メッセージを保存してください。",
            checklist=(
                "進捗バーが進んでいるか確認",
                "エラー表示がないか確認",
                "完了後にレビュー結果へ移動",
            ),
        )

    if upload_count <= 0:
        return OperationGuide(
            tone="idle",
            step_label="ステップ 1 / 文書アップロード",
            headline="まずレビュー対象の文書を選択します",
            primary_action="「ファイルを選択」から、同じ種類の文書をアップロードしてください。",
            reason="このツールは複数ファイルを1つのレビュー束として扱えますが、設計書と手順書などの混在は避ける前提です。",
            done_when="ファイル名が画面に表示され、「匿名化してプレビュー」ボタンが押せる状態です。",
            watch_out="社外秘の原文を直接外部LLMへ送ることはありません。まずローカル匿名化を行います。",
            checklist=(
                "同一種類の文書だけを選ぶ",
                "不要な別紙やログを含めない",
                "重複ファイルを避ける",
            ),
        )

    if not has_preview_docs:
        return OperationGuide(
            tone="active",
            step_label="ステップ 1 -> 2 / 匿名化プレビュー作成",
            headline="次は匿名化プレビューを作成します",
            primary_action="「匿名化してプレビュー」ボタンを押してください。",
            reason="外部レビュー前に、ローカルでテキスト抽出、匿名化、機密度判定、トークン概算を実行します。",
            done_when="ステップ2に匿名化結果サマリと文書カードが表示されます。",
            watch_out="処理中はアップロード文書のサイズや形式によって数十秒かかる場合があります。",
            checklist=(
                f"選択済みファイル: {upload_count} 件",
                "匿名化後テキストだけが送信対象",
                "PDF/Officeは抽出結果を必ず確認",
            ),
        )

    if blocked_count > 0:
        return OperationGuide(
            tone="block",
            step_label="ステップ 2 / 送信停止",
            headline="外部レビューへ送信できない文書があります",
            primary_action="送信禁止の文書カードを開き、原文修正、分割、またはアップロード対象からの除外を検討してください。",
            reason="送信禁止や高リスク判定が残っている状態では、最終承認より安全停止を優先します。",
            done_when="匿名化結果サマリの「送信禁止」が0件になります。",
            watch_out="この状態では「レビューに送信」は有効化しない設計です。",
            checklist=(
                f"送信禁止: {blocked_count} 件",
                "機密語、URL、固有名詞、設定値を確認",
                "修正後に再アップロードして再プレビュー",
            ),
        )

    if confirmation_count > 0:
        next_action = "文書カードのマスク候補と匿名化後テキストを確認してください。"
        if can_regenerate_anonymization:
            next_action = "マスク候補を確認し、必要なら「匿名化結果を再生成」を押してください。"
        return OperationGuide(
            tone="warn",
            step_label="ステップ 2 / 匿名化結果確認",
            headline="人間の確認が必要な候補があります",
            primary_action=next_action,
            reason="自動判定しきれない固有名詞や文脈上の機密候補は、送信前に人間が確認する必要があります。",
            done_when="要確認・未判定候補を確認し、送信してよい匿名化済みテキストだと判断できた状態です。",
            watch_out="迷う候補はマスク側に倒すのが安全です。",
            checklist=(
                f"要確認文書: {confirmation_count} 件",
                "マスク候補の採否を確認",
                "送信対象テキストの抜粋を確認",
            ),
        )

    if token_status == "split_recommended":
        return OperationGuide(
            tone="warn",
            step_label="ステップ 2 -> 3 / 送信規模確認",
            headline="分割レビューを推奨する規模です",
            primary_action="レビュー束を分割するか、このまま進める場合は最終承認チェックへ進んでください。",
            reason="大きい文書束はLLMのトークン上限や待ち時間に影響し、指摘品質も粗くなる可能性があります。",
            done_when="分割方針を決め、続行する場合はステップ3の最終承認に進める状態です。",
            watch_out="複数PDFは1つの文書として扱いますが、外部LLM側では複数callになる場合があります。",
            checklist=(
                "本文と別紙の要否を確認",
                "章単位またはファイル単位の分割を検討",
                "続行時は最終承認で明示確認",
            ),
        )

    if not send_approved:
        return OperationGuide(
            tone="active",
            step_label="ステップ 3 / 最終承認",
            headline="送信前の最終承認に進めます",
            primary_action="匿名化結果を確認したうえで、「LLM送信前の最終承認」にチェックしてください。",
            reason="外部LLMへ送るのは匿名化済みテキストのみですが、送信判断は人間が明示的に承認する設計です。",
            done_when="「レビューに送信」ボタンが有効になります。",
            watch_out="チェックは確認済みの意思表示です。迷う場合は匿名化後テキストをもう一度開いてください。",
            checklist=(
                "匿名化結果サマリを確認",
                "送信禁止が0件であることを確認",
                "必要なら結果ログ(JSON)を確認",
            ),
        )

    return OperationGuide(
        tone="active",
        step_label="ステップ 3 / レビュー送信",
        headline="レビュー送信の準備ができています",
        primary_action="「レビューに送信」ボタンを押して、外部LLMレビューを開始してください。",
        reason="承認ゲートを通過しており、送信対象は匿名化済みテキストに限定されています。",
        done_when="ステータスが「レビュー中」に変わり、進捗バーが表示されます。",
        watch_out="送信後は処理完了まで待機してください。大きい文書束では時間がかかります。",
        checklist=(
            "送信準備完了を確認",
            "LLMプロバイダ設定を確認",
            "レビュー完了後に結果を確認",
        ),
    )


def build_review_agent_brief(
    preview_docs: list[SanitizedDocument],
    *,
    blocked_count: int,
    confirmation_count: int,
    send_approved: bool,
    token_status: str = "unknown",
    review_in_progress: bool = False,
    review_done: bool = False,
) -> AgentBrief:
    """Build a deterministic "review command agent" brief for the UI.

    This is intentionally local and rule-based. It gives the interface an
    agent-like control layer without letting the model autonomously send data
    or make final release decisions.
    """
    if not preview_docs:
        return AgentBrief(
            mode="待機",
            mission="レビュー対象の文書をアップロードしてください。",
            next_action="文書をアップロードし、匿名化プレビューを作成します。",
            risk_summary="外部送信はまだ発生していません。",
            stages=(
                AgentStage("取込", "待機", "ファイル未投入", "idle"),
                AgentStage("匿名化", "待機", "抽出前", "idle"),
                AgentStage("送信判断", "待機", "承認前", "idle"),
                AgentStage("レビュー", "待機", "未実行", "idle"),
            ),
            monitors=("外部送信: 未実行", "匿名化: 未実行"),
        )

    excel_docs = sum(1 for doc in preview_docs if "# Excelブック診断" in (doc.outbound_text or ""))
    high_risk_docs = sum(
        1
        for doc in preview_docs
        if doc.outbound_risk == "high" or doc.local_sensitivity_decision == "block"
    )
    total_replacements = sum(len(doc.replacements or []) for doc in preview_docs)
    uncertain_docs = sum(
        1
        for doc in preview_docs
        if doc.local_sensitivity_decision in {"unknown", "mask_and_continue"}
    )

    if blocked_count or high_risk_docs:
        mode = "停止判断"
        mission = "外部送信を止め、機密要素の除去または資料分割を優先します。"
        next_action = "送信禁止または高リスク判定の文書を確認してください。"
        risk_summary = f"送信禁止 {blocked_count} 件 / 高リスク {high_risk_docs} 件を検出しています。"
        decision_stage = AgentStage("送信判断", "停止", "外部送信不可", "block")
    elif confirmation_count or uncertain_docs:
        mode = "確認誘導"
        mission = "未確定候補と匿名化結果を確認し、人間承認に進めます。"
        next_action = "匿名化結果、マスク候補、送信対象ログを確認してください。"
        risk_summary = f"確認が必要な文書 {max(confirmation_count, uncertain_docs)} 件があります。"
        decision_stage = AgentStage("送信判断", "要確認", "人間確認待ち", "warn")
    elif token_status == "split_recommended":
        mode = "分割戦略"
        mission = "長文レビューを分割し、トークン消費と待ち時間を抑えます。"
        next_action = "必要に応じてファイル単位または章単位で分割してください。"
        risk_summary = "送信は可能ですが、分割レビューを推奨します。"
        decision_stage = AgentStage("送信判断", "注意", "分割推奨", "warn")
    elif token_status == "caution":
        mode = "注意監視"
        mission = "送信規模を監視しながら、匿名化済み文書をレビューへ進めます。"
        next_action = "最終承認前に不要な別紙やログが含まれていないか確認してください。"
        risk_summary = "通常より入力規模が大きめです。"
        decision_stage = AgentStage("送信判断", "注意", "送信規模を監視", "warn")
    elif send_approved:
        mode = "実行準備"
        mission = "匿名化済みテキストのみを外部レビューへ送信できます。"
        next_action = "レビュー送信ボタンでLLMレビューを開始します。"
        risk_summary = "送信前ゲートを通過しています。"
        decision_stage = AgentStage("送信判断", "承認済み", "送信準備完了", "done")
    else:
        mode = "安全確認"
        mission = "匿名化済み文書を確認し、外部レビュー前の最終承認に進めます。"
        next_action = "ステップ3で最終承認チェックを入れてください。"
        risk_summary = "送信禁止または追加確認が必要な文書はありません。"
        decision_stage = AgentStage("送信判断", "待機", "最終承認待ち", "active")

    if review_done:
        review_stage = AgentStage("レビュー", "完了", "結果を確認できます", "done")
    elif review_in_progress:
        review_stage = AgentStage("レビュー", "実行中", "LLM応答待ち", "active")
    else:
        review_stage = AgentStage("レビュー", "待機", "未送信", "idle")

    monitors = [
        f"レビュー束: {len(preview_docs)} ファイル",
        f"匿名化置換: {total_replacements} 件",
        f"Excel診断: {excel_docs} 件",
        f"送信規模: {token_status}",
    ]

    return AgentBrief(
        mode=mode,
        mission=mission,
        next_action=next_action,
        risk_summary=risk_summary,
        stages=(
            AgentStage("取込", "完了", "文書を受領", "done"),
            AgentStage("匿名化", "完了", "ローカル抽出と匿名化済み", "done"),
            decision_stage,
            review_stage,
        ),
        monitors=tuple(monitors),
    )
