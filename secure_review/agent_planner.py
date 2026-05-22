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


@dataclass(frozen=True)
class DisplayPolicy:
    tone: str
    headline: str
    primary_action: str
    reason: str
    show_now: tuple[str, ...]
    keep_collapsed: tuple[str, ...]
    developer_only: tuple[str, ...] = ()
    expand_quality_hints: bool = False
    show_document_details: bool = False
    expand_structure_details: bool = False
    expand_deep_candidates: bool = False


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
            primary_action="まず修正計画カードを確認してください。詳細ログや品質改善ヒントは必要なときだけ開けば十分です。",
            reason="レビュー指摘と構成不足は修正計画へ集約済みです。重複情報を順番に読むより、次に直す内容から確認する方が迷いません。",
            done_when="修正担当に渡す項目、追記する文章案、再レビュー条件を把握できた状態です。",
            watch_out="深堀や詳細表示は補助情報です。通常は赤いカード、黄色いカード、追記テンプレートの順に確認してください。",
            checklist=(
                "修正計画カードを確認",
                "必要なら追記テンプレートを開く",
                "次回比較したい場合だけJSONを保存",
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
                "必要ならレビュー証跡(JSON)を確認",
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


def build_review_display_policy(
    *,
    remediation_count: int,
    high_count: int,
    medium_count: int,
    structure_finding_count: int,
    future_hint_count: int,
    deep_candidate_count: int,
    previous_plan_loaded: bool = False,
    developer_mode: bool = False,
) -> DisplayPolicy:
    """Decide how much review information to surface for the current state.

    This is a deterministic local policy, not an external LLM call.  It keeps
    the UI agent-like while avoiding extra token usage or hidden data transfer.
    """
    base_show = ("修正計画カード", "追記テンプレート", "再レビュー条件")
    json_label = "今回レビュー結果JSON" if not previous_plan_loaded else "今回JSONと前回比較結果"
    base_collapsed = [
        "品質改善ヒント",
        "文書別の元指摘",
        "証跡・エクスポート",
    ]
    if structure_finding_count:
        base_collapsed.append("文書構成チェック詳細")
    if deep_candidate_count:
        base_collapsed.append("章別深堀候補")

    developer_only = (
        ("メタレビュー", "プロンプトプレビュー", "LLM生レスポンス")
        if developer_mode else ()
    )

    if high_count > 0:
        return DisplayPolicy(
            tone="block",
            headline="AI判断: まず高重要度の修正計画に集中してください",
            primary_action="赤い修正計画カードから確認し、担当者・追記内容・再レビュー条件を決めてください。",
            reason="高重要度の指摘があるため、章別詳細や品質改善ヒントを先に読むと判断が散らばります。",
            show_now=(*base_show, json_label),
            keep_collapsed=tuple(base_collapsed),
            developer_only=developer_only,
        )

    if remediation_count > 0 or medium_count > 0:
        return DisplayPolicy(
            tone="warn",
            headline="AI判断: 修正計画だけ見れば次の作業に進めます",
            primary_action="黄色いカードを確認し、必要な追記だけ文書へ反映してください。",
            reason="元レビュー指摘は修正計画に集約済みです。通常は詳細ログを開かなくても対応できます。",
            show_now=(*base_show, json_label),
            keep_collapsed=tuple(base_collapsed),
            developer_only=developer_only,
        )

    if future_hint_count > 0 or deep_candidate_count > 0:
        return DisplayPolicy(
            tone="info",
            headline="AI判断: 大きな修正は少なく、品質改善ヒントが中心です",
            primary_action="必要に応じて品質改善ヒントを開き、曖昧表現や読み手リスクだけ確認してください。",
            reason="重大な修正計画が少ないため、本文品質を上げる補助情報の確認が有効です。",
            show_now=("レビュー結果サマリ", json_label),
            keep_collapsed=tuple(item for item in base_collapsed if item != "品質改善ヒント"),
            developer_only=developer_only,
            expand_quality_hints=True,
            expand_deep_candidates=bool(deep_candidate_count and remediation_count == 0),
        )

    return DisplayPolicy(
        tone="success",
        headline="AI判断: 追加確認は最小限で十分です",
        primary_action="必要なら今回レビュー結果JSONだけ保存し、レビューを完了してください。",
        reason="高重要度・中重要度の修正計画や強い品質改善ヒントは目立っていません。",
        show_now=("レビュー結果サマリ", json_label),
        keep_collapsed=tuple(base_collapsed),
        developer_only=developer_only,
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
