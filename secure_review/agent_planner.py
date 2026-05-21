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
