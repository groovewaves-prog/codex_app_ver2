from __future__ import annotations

import json
import logging
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from secure_review.models import (
    ChecklistResult,
    MissingChapter,
    ReviewIssue,
    ReviewResult,
    ReviewSummary,
    SanitizedDocument,
)
from secure_review.network_guard import UpstreamHttpError, post_json_safely
from secure_review.rubric import (
    ChapterSection,
    DESIGN_DOC_STRUCTURE_V0_2,
    ReviewRubric,
    classify_documents,
    choose_rubric,
    get_chapter_by_id,
    render_chapter_checklist_for_prompt,
    render_rubric_for_prompt,
)


LOGGER = logging.getLogger("secure_review.reviewer")


SYSTEM_PROMPT = """あなたは日本のIT業界における設計レビュー担当者です。
匿名化済みの成果物を、設計者の意図と運用観点からレビューしてください。

# 出力形式

JSON オブジェクトのみを返してください。コードブロックや説明文は不要です。

{
  "summary": "全体評価 (3-5 文の日本語、重大な懸念点を含める)",
  "issues": [
    {
      "severity": "high",
      "title": "指摘のタイトル",
      "source_document": "対象文書名",
      "issue": "問題点 (具体的に)",
      "impact": "影響 (運用・セキュリティ・コスト等の観点で)",
      "recommendation": "推奨対応 (含めるべき要素を具体的に列挙)"
    }
  ]
}

# 評価方針

- severity は "high" / "medium" / "low" / "info" のいずれか。
  - high: リリース前に必ず是正すべき重大な不足
  - medium: 詳細設計または運用開始前に対応すべき
  - low: 改善推奨 (次フェーズで可)
  - info: 補足情報・参考事項
- 重大な不足や整合性の問題のみを指摘してください (細かすぎる指摘は不要)。
- recommendation は具体的に記述してください。「対応してください」のような抽象表現は避け、含めるべき要素を列挙すること。
- 指摘がない場合は issues を空配列 [] にしてください。
- 事実ベースで客観的に。「不適切である」より「〜のリスクがある」「〜の改善余地がある」を好む。
"""


# JSON Schema for Gemini API structured output. The schema is enforced
# server-side when the model supports responseSchema. For models that ignore
# it (or for non-Gemini providers), the prompt above still describes the same
# structure, and the parser handles graceful fallback.
#
# B2: schema extended to cover the structured-summary and 6-field issue
# format. All new fields are optional so older prompts/responses still
# validate. ``required`` is kept minimal (severity + title + source_document
# for issues, nothing for summary itself) to avoid the API rejecting valid
# legacy responses.
REVIEW_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "anyOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "properties": {
                        "purpose": {"type": "string"},
                        "purpose_section_in_document": {"type": "string"},
                        "purpose_divergence": {"type": "string"},
                        "content_outline": {"type": "string"},
                        "overall_evaluation": {"type": "string"},
                        "verdict": {"type": "string"},
                    },
                },
            ]
        },
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["high", "medium", "low", "info"],
                    },
                    "title": {"type": "string"},
                    "details": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "source_document": {"type": "string"},
                    "section": {"type": "string"},
                    "current_state": {"type": "string"},
                    "issue": {"type": "string"},
                    "impact": {"type": "string"},
                    "required_timing": {"type": "string"},
                    "re_review_required": {"type": "boolean"},
                },
                "required": [
                    "severity",
                    "title",
                    "source_document",
                ],
            },
        },
        # Phase 5 (2026-05-08): 構造定義書 v0.2 ベースの 5 段階評価結果。
        # 各文書に対して、関連するチェック項目 (rubric.py の DESIGN_DOC_STRUCTURE_V0_2)
        # を 5 段階で評価。Q17=C: 各 chunk call で「関連項目を全て」評価する。
        "checklist_results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "item_id": {"type": "string"},
                    "item_name": {"type": "string"},
                    "source_document": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": [
                            "excellent",
                            "good",
                            "acceptable",
                            "needs_improvement",
                            "unacceptable",
                            "not_applicable",
                        ],
                    },
                    "reason": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["item_id", "status", "reason"],
            },
        },
        # Phase 5 (2026-05-08): 構造定義書 v0.2 §7 の欠落章サジェスチョン。
        # Q18=A: 集約 call (chunking 完了後の 13 番目の call) で判定。
        # 各 chunk call では空配列で返す (LLM への指示で明示)。
        "missing_chapters": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "chapter_id": {"type": "string"},
                    "chapter_name": {"type": "string"},
                    "verdict": {
                        "type": "string",
                        "enum": ["should_have", "recommended", "out_of_scope"],
                    },
                    "justification": {"type": "string"},
                    "suggested_content": {"type": "string"},
                },
                "required": ["chapter_id", "verdict", "justification"],
            },
        },
    },
    "required": ["summary", "issues"],
}


# Set of strings that, if returned by the model as field values, indicate
# the model copied the schema/example placeholders verbatim instead of
# producing real review content. We treat such issues as malformed and drop
# them rather than displaying garbage to the user.
_PLACEHOLDER_TOKENS = {
    "severity",
    "title",
    "details",
    "recommendation",
    "source_document",
    "<severity>",
    "<title>",
    "<details>",
    "<recommendation>",
    "<source_document>",
    "<重大度>",
    "<タイトル>",
    "<詳細>",
    "<推奨対応>",
    "<出典文書名>",
}


_VALID_SEVERITIES = {"high", "medium", "low", "info"}


# Gemini free-tier quota messages we want to surface nicely to the user.
_GEMINI_QUOTA_MARKERS = (
    "RESOURCE_EXHAUSTED",
    "quota",
    "rate limit",
    "Resource has been exhausted",
)


class ReviewProvider:
    name = "base"

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
        *,
        deep_dive_target: str | None = None,
        existing_issues: "list[ReviewIssue] | None" = None,
        chapter: ChapterSection | None = None,
    ) -> ReviewResult:
        """文書群をレビューする。

        Args:
            documents: 匿名化済み文書のリスト
            document_profile_override: ルーブリック上書き (省略可)
            deep_dive_target: R-Y (2026-05-08) 深堀対象の文書名。指定時は
                通常レビューではなく、対象文書 + 既存指摘を入力として
                追加の詳細分析を LLM に依頼する。None なら通常レビュー。
            existing_issues: deep_dive_target 指定時に渡す既存指摘の集合。
                通常レビュー時は無視される。
            chapter: Phase 7 段階 2-B (2026-05-08) 章単位深堀り対象。指定時は
                deep_dive_target も必須で、対象文書の特定章のみを評価する。

        Returns:
            ReviewResult。deep_dive_target 指定時は、target 文書に対する
            追加指摘のみを含む。
        """
        raise NotImplementedError


class MockReviewProvider(ReviewProvider):
    name = "mock"

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
        *,
        deep_dive_target: str | None = None,
        existing_issues: "list[ReviewIssue] | None" = None,
        chapter: ChapterSection | None = None,
    ) -> ReviewResult:
        # R-Y (2026-05-08): Mock は深堀をサポートしない (ヒューリスティクス).
        # Phase 7 段階 2-B: chapter も同様に受け取って無視する。
        # 引数だけ受け取って無視する。
        issues: list[ReviewIssue] = []
        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)

        for document in documents:
            text = document.outbound_text
            lowered = text.lower()
            beginning = lowered[:800]

            if rubric.document_profile == "source_code":
                if _has_hardcoded_secret(lowered):
                    issues.append(
                        ReviewIssue(
                            severity="high",
                            title="ハードコードされた認証情報の疑い",
                            details="コード内にパスワード、トークン、秘密情報を直接埋め込んでいる可能性があります。",
                            recommendation="秘密情報は環境変数や安全なシークレットストアへ移し、コードから除外してください。",
                            source_document=document.name,
                        )
                    )

                if _has_unprotected_command_execution(lowered):
                    issues.append(
                        ReviewIssue(
                            severity="high",
                            title="危険なコマンド実行の可能性",
                            details="外部コマンド実行や評価系処理が入力検証や安全対策なしに使われている可能性があります。",
                            recommendation="引数の固定化、入力検証、シェル経由実行の回避を検討してください。",
                            source_document=document.name,
                        )
                    )

                if _has_bare_except(lowered):
                    issues.append(
                        ReviewIssue(
                            severity="medium",
                            title="例外処理が広すぎる可能性",
                            details="例外を広く握りつぶす記述があり、障害解析や誤動作の原因になり得ます。",
                            recommendation="捕捉対象を明確化し、ログや再送出を追加してください。",
                            source_document=document.name,
                        )
                    )
                continue

            if "telnet" in lowered:
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="Telnet usage detected",
                        details="An unencrypted remote access setting may still be present.",
                        recommendation="Replace Telnet with SSH and disable Telnet-related settings.",
                        source_document=document.name,
                    )
                )

            if "snmp-server community" in lowered:
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="SNMP community string usage",
                        details="Community-based SNMP authentication may still be enabled.",
                        recommendation="Consider migrating to SNMPv3 and restricting source addresses.",
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "design" and "aaa new-model" not in lowered and "aaa authentication" not in lowered:
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="AAA configuration not explicit",
                        details="Authentication, authorization, and accounting settings were not clearly found.",
                        recommendation="Document the AAA policy, identity source, and fallback behavior.",
                        source_document=document.name,
                    )
                )

            if re.search(r"(?im)^interface\s", text) and "description" not in lowered:
                issues.append(
                    ReviewIssue(
                        severity="low",
                        title="Interface descriptions may be missing",
                        details="Interfaces are defined but human-readable descriptions appear to be sparse.",
                        recommendation="Add interface descriptions for peer, purpose, and circuit context.",
                        source_document=document.name,
                    )
                )

            if not _has_purpose_at_beginning(beginning):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="冒頭の目的記載が不明確",
                        details="資料の最初の項目または第1章で、設計または作業の目的が明確に読み取れませんでした。",
                        recommendation="第1章または冒頭に、対象・目的・到達点を簡潔に追記してください。",
                        source_document=document.name,
                    )
                )

            if not _has_configuration_information(lowered):
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="構成情報の存在が確認できない",
                        details="ネットワーク構成図、システム構成図、接続図、機器一覧などの構成情報が文書から確認できませんでした。",
                        recommendation="構成図または同等の構成情報を本文か別紙参照で明記してください。",
                        source_document=document.name,
                    )
                )

            if rubric.document_profile in {"change_runbook", "operations_runbook"} and not _has_timechart_reference(lowered):
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="タイムチャートの記載または別紙参照が不足",
                        details="時系列管理が必要な資料と推定されましたが、タイムチャート本体または『タイムチャートは別紙』の記載が見当たりませんでした。",
                        recommendation="タイムチャートを本文に追加するか、別紙名を明記してください。",
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "operations_runbook" and not _has_operational_handover_signals(lowered):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="運用ハンドオーバー要素の記載が不足",
                        details=(
                            "運用手順書ですが、SLO/SLA、監視→ランブックのリンク、"
                            "オーナーシップ/RACI、エスカレーション先のいずれかに言及が見当たりません。"
                        ),
                        recommendation=(
                            "SLO、監視項目と対応手順のリンク、運用オーナーと"
                            "エスカレーション先を明記してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and _has_irreversible_operation_signals(lowered) and not _has_rollback_signals(lowered):
                issues.append(
                    ReviewIssue(
                        severity="high",
                        title="不可逆な作業が含まれる可能性があり、補償処置が不明",
                        details=(
                            "DB破壊的変更、データ削除、設定の上書きなど不可逆と思われる処理が"
                            "記載されている一方、切戻し/補償処置の記述が見当たりません。"
                        ),
                        recommendation=(
                            "可逆/不可逆を区別し、不可逆処理には補償処置や代替手段を明記してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and not _has_environment_distinction(lowered):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="作業対象環境の区別が不明確",
                        details=(
                            "作業計画書ですが、本番・検証・ステージングなど作業対象環境の"
                            "区別が読み取れませんでした。"
                        ),
                        recommendation=(
                            "作業対象環境（本番／検証／ステージング等）を明記してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and not _has_risk_level_with_approval(lowered):
                issues.append(
                    ReviewIssue(
                        severity="medium",
                        title="リスクレベルと承認プロセスの記載が不足",
                        details=(
                            "変更のリスクレベル分類と、それに対応する承認経路（誰の承認が必要か）"
                            "が読み取れませんでした。"
                        ),
                        recommendation=(
                            "リスクレベル（例: 高／中／低）と、各レベルに必要な承認者を明示してください。"
                        ),
                        source_document=document.name,
                    )
                )

            if rubric.document_profile == "change_runbook" and not _has_document_update_list(lowered):
                issues.append(
                    ReviewIssue(
                        severity="low",
                        title="作業後に修正対象となるドキュメントの事前一覧が無い",
                        details=(
                            "作業後に更新が必要となるドキュメントの事前一覧が見当たりませんでした。"
                        ),
                        recommendation=(
                            "変更対象ドキュメント（設計書、構成管理、運用手順書など）を計画段階で"
                            "リスト化してください。"
                        ),
                        source_document=document.name,
                    )
                )

        if not issues:
            issues.append(
                ReviewIssue(
                    severity="info",
                    title="No major issue found in mock review",
                    details="The mock review did not detect any obvious risk in the provided artifacts.",
                    recommendation="Use a real LLM provider and add more rules for production quality review.",
                    source_document=documents[0].name if documents else "-",
                )
            )

        return _build_review_result(
            summary=f"Reviewed {len(documents)} document(s) and produced {len(issues)} issue(s).",
            issues=issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
        )


class HttpLlmReviewProvider(ReviewProvider):
    name = "http-llm"

    def __init__(self) -> None:
        self.api_url = os.getenv("LLM_API_URL", "").strip()
        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.model = os.getenv("LLM_MODEL", "").strip()

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
        *,
        deep_dive_target: str | None = None,
        existing_issues: "list[ReviewIssue] | None" = None,
        chapter: ChapterSection | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> ReviewResult:
        if not self.api_url or not self.model:
            raise ValueError("LLM_API_URL and LLM_MODEL must be configured.")

        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)
        # R-Y (2026-05-08): deep_dive_target 指定時は深堀プロンプトを生成。
        # Phase 7 段階 2-B (2026-05-08): chapter 指定時は章単位深堀り。
        prompt = build_prompt(
            documents, rubric,
            deep_dive_target=deep_dive_target,
            existing_issues=existing_issues,
            chapter=chapter,
        )
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        response = post_json_safely(
            self.api_url,
            payload,
            {
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            context_label="HTTP LLM provider",
        )
        content = _extract_openai_like_text(response)
        # R-B + R-C: same pattern as the Gemma provider — prefer the model's
        # own summary; fall back to an explicit Japanese notice when absent.
        # B2: extract structured summary too; assign profile-based issue IDs.
        model_summary, summary_struct, issues = _parse_review_payload(content, documents)
        _assign_issue_ids(issues, classification.document_profile)
        # Phase 7 (2026-05-08): 一段目では checklist_results / missing_chapters は
        # 取得しない (一段目シンプル化)。
        # 深堀り call (deep_dive_target 指定時) では取得する:
        # - 章モード (chapter 指定): 該当章の 78 項目サブセットを評価
        # - ファイル全体モード: 全 78 項目を該当性判定
        checklist_results: tuple = ()
        missing_chapters: tuple = ()
        if deep_dive_target is not None:
            # 深堀り call は target 文書名を fallback として渡す
            checklist_results = _parse_checklist_results(content, deep_dive_target)
            # 章モードでは missing_chapters は空配列指示なので取得しない
            # ファイル全体モードでは取得する (LLM が返せば反映)
            if chapter is None:
                missing_chapters = _parse_missing_chapters(content)
        summary = model_summary or "LLM がレビューサマリを返しませんでした。生レスポンスを確認してください。"
        return _build_review_result(
            summary=summary,
            summary_structured=summary_struct,
            issues=issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
            prompt=prompt,
            raw_response=content,
            model=self.model,
            checklist_results=checklist_results,
            missing_chapters=missing_chapters,
        )


class GeminiApiReviewProvider(ReviewProvider):
    """Gemini / Gemma via Google Generative Language API.

    Stability improvements over the previous version:

    - Retry once on 429 / 5xx with a short backoff (free-tier rate limits
      are short-lived).
    - Convert quota errors into a clearly-labelled ``RuntimeError`` so the UI
      can display "Quota exceeded, please retry later" instead of a raw
      provider message.
    - Default to a Gemini flash model (which is actually on the free tier) if
      the user selects the "gemini-free" provider without overriding model.
    - Never echo the response body into exceptions.
    """

    name = "gemini-api"
    default_model = "gemma-4-31b-it"
    # 課題 2 改修 (2026-05-08, レビュー後修正):
    # - max_retries クラス変数のデフォルトは 1 を維持 (既存テスト互換性)
    #   GeminiApiReviewProvider() の通常生成時は __init__ で環境変数を見て上書き。
    #   __new__() で生成するテストではクラス変数 (= 1) が使われ、旧来挙動を保つ。
    # - retry_backoff_base_seconds: 指数バックオフの基準時間
    # - retry_backoff_jitter: バックオフに乱数オフセットを加え、複数クライアントの
    #   同期的リトライを避ける (thundering herd 対策)
    max_retries = 1
    retry_backoff_base_seconds = 1.5
    retry_backoff_jitter = 0.5

    # 課題 2 改修 (2026-05-08):
    # chunking 後の文書間隔。Free tier の RPM (≈10) を超えないように、
    # 各 API call の間に sleep を入れる。
    # デフォルト 0 は本番テスト容易性のため (テストでは時間を浪費しない)。
    # 環境変数 GEMINI_CHUNKING_INTERVAL で 6.0 (= 60s/10req) のような値に設定可。
    chunking_interval_seconds = 0.0

    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
        self.model = (
            os.getenv("GEMMA_MODEL", "").strip()
            or os.getenv("GEMINI_MODEL", "").strip()
            or self.default_model
        )
        # 課題 2 改修 (2026-05-08): デフォルトを 2048 → 8192 に
        # (戦略 B: Gemini 2.5 Flash の出力上限まで使う、応答途切れ防止)
        # 環境変数 GEMINI_MAX_OUTPUT_TOKENS で上書き可能。
        self.max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "8192"))
        self.temperature = float(os.getenv("GEMINI_TEMPERATURE", "0.2"))

        # 課題 2 改修 (2026-05-08, レビュー後修正): max_retries を環境変数で制御
        # (戦略 C: リトライ強化を本番のみに限定、既存テスト互換性を維持)
        # 通常生成時 (= GeminiApiReviewProvider()) はこの __init__ が走り、
        # 環境変数があれば値を上書き。Streamlit Cloud では GEMINI_MAX_RETRIES=3 を推奨。
        # テストの __new__() インスタンスはクラス変数 (max_retries=1) のまま。
        try:
            _retries_env = os.getenv("GEMINI_MAX_RETRIES", "").strip()
            if _retries_env:
                _retries_val = int(_retries_env)
                if 0 <= _retries_val <= 10:
                    self.max_retries = _retries_val
                else:
                    LOGGER.warning(
                        "GEMINI_MAX_RETRIES=%s is out of range [0, 10], using class default (%d)",
                        _retries_env,
                        type(self).max_retries,
                    )
        except ValueError:
            LOGGER.warning(
                "GEMINI_MAX_RETRIES=%r is not an integer, using class default",
                os.getenv("GEMINI_MAX_RETRIES"),
            )

        # 課題 2 改修 (2026-05-08): chunking モードの ON/OFF
        # デフォルト ON (戦略 A: 1 文書 = 1 API call で安定化)
        # 環境変数 GEMINI_CHUNKING で "false" を指定すると旧来の一括送信に戻る (緊急時用)
        chunking_env = os.getenv("GEMINI_CHUNKING", "true").strip().lower()
        self.chunking_enabled = chunking_env not in {"false", "0", "no", "off"}

        # chunking 間隔を環境変数で上書き可能 (Free tier RPM 対策)
        try:
            self.chunking_interval_seconds = float(
                os.getenv("GEMINI_CHUNKING_INTERVAL", "0").strip() or "0"
            )
        except ValueError:
            self.chunking_interval_seconds = 0.0

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
        *,
        deep_dive_target: str | None = None,
        existing_issues: "list[ReviewIssue] | None" = None,
        chapter: ChapterSection | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> ReviewResult:
        """課題 2 改修 (2026-05-08): chunking 対応のレビュー実装。

        chunking_enabled (デフォルト True) の場合:
            各文書を 1 つずつ別の API call で処理し、結果をマージする。
            これにより以下を達成:
            - 各 call の入出力サイズが小さく、503/timeout のリスクが激減
            - 失敗時は文書単位で限定 (リトライ可能)
            - 進捗の可視化 (progress_callback)

        chunking_enabled が False の場合:
            旧来の挙動 (全文書を 1 call で送る)。緊急時の fallback 用。

        deep_dive_target 指定時:
            深堀レビューは元々 1 文書を対象とするので、chunking は適用せず、
            旧来通り 1 call で処理する。
        """
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY must be configured.")
        if not self.model:
            raise ValueError("GEMMA_MODEL or GEMINI_MODEL must be configured.")

        # 課題 2 改修 (2026-05-08): chunking 適用判定
        # 順序が重要:
        #   1. 単一文書 (len <= 1) → chunking 不要 (テストの __new__ インスタンス互換性)
        #   2. 深堀 → 1 文書を対象とするので chunking 不要
        #   3. chunking_enabled が False → 緊急 fallback (旧来挙動)
        # getattr で chunking_enabled を取得することで、テストが手動構築した
        # インスタンス (chunking_enabled 属性なし) でも動作する。
        if (
            len(documents) <= 1
            or deep_dive_target is not None
            or not getattr(self, "chunking_enabled", True)
        ):
            return self._review_single_call(
                documents,
                document_profile_override,
                deep_dive_target=deep_dive_target,
                existing_issues=existing_issues,
                chapter=chapter,
            )

        # ---- chunking フロー ----
        return self._review_chunked(
            documents,
            document_profile_override,
            progress_callback=progress_callback,
        )

    def _review_single_call(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None,
        *,
        deep_dive_target: str | None,
        existing_issues: "list[ReviewIssue] | None",
        chapter: ChapterSection | None = None,
    ) -> ReviewResult:
        """旧来の単一 API call レビュー (深堀および chunking 無効時に使用)。

        Phase 7 段階 2-B: chapter 指定時は章単位深堀り (deep_dive_target も必須)。
        """
        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)
        prompt = build_prompt(
            documents, rubric,
            deep_dive_target=deep_dive_target,
            existing_issues=existing_issues,
            chapter=chapter,
        )
        payload = self._build_payload(prompt)

        response = self._post_with_retry(payload)
        content = _extract_gemini_text(response)
        if not content.strip():
            finish_reason = _first_finish_reason(response)
            raise RuntimeError(
                f"Gemini returned no text (finish_reason={finish_reason or 'unknown'}). "
                "Consider reducing input size or raising GEMINI_MAX_OUTPUT_TOKENS."
            )
        model_summary, summary_struct, issues = _parse_review_payload(content, documents)
        _assign_issue_ids(issues, classification.document_profile)
        # Phase 7 (2026-05-08): 一段目では checklist_results / missing_chapters は
        # 取得しない (一段目シンプル化)。
        # 深堀り call (deep_dive_target 指定時) では取得する:
        # - 章モード (chapter 指定): 該当章の 78 項目サブセットを評価
        # - ファイル全体モード: 全 78 項目を該当性判定
        checklist_results: tuple = ()
        missing_chapters: tuple = ()
        if deep_dive_target is not None:
            # 深堀り call は target 文書名を fallback として渡す
            checklist_results = _parse_checklist_results(content, deep_dive_target)
            # 章モードでは missing_chapters は空配列指示なので取得しない
            # ファイル全体モードでは取得する (LLM が返せば反映)
            if chapter is None:
                missing_chapters = _parse_missing_chapters(content)
        summary = model_summary or "LLM がレビューサマリを返しませんでした。生レスポンスを確認してください。"
        return _build_review_result(
            summary=summary,
            summary_structured=summary_struct,
            issues=issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
            prompt=prompt,
            raw_response=content,
            model=self.model,
            checklist_results=checklist_results,
            missing_chapters=missing_chapters,
        )

    def _review_chunked(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None,
        *,
        progress_callback: Callable[[int, int, str], None] | None,
    ) -> ReviewResult:
        """課題 2 改修 (2026-05-08): chunking 版レビュー (各文書を別 API call で処理)。

        各文書を独立した API call で処理し、結果 (issues) をマージする。
        全体の summary は各文書の結果から構成 (Phase 5 で missing_chapters 統合 call に拡張予定)。

        Free tier の RPM (10/分) を超えないよう、call 間に sleep を入れる
        (chunking_interval_seconds で制御)。
        """
        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)

        all_issues: list[ReviewIssue] = []
        per_doc_summaries: list[str] = []
        per_doc_raw_responses: list[str] = []
        per_doc_prompts: list[str] = []
        # Phase 7 (2026-05-08): 集約 call と checklist 抽出を一段目から削除。
        # checklist_results / missing_chapters は深堀り call で取得する設計に変更。
        failed_docs: list[tuple[str, str]] = []  # (doc_name, error_message)

        total = len(documents)
        for idx, doc in enumerate(documents, start=1):
            doc_name = doc.name

            # 進捗通知 (Streamlit 側で progress bar を更新)
            if progress_callback is not None:
                try:
                    progress_callback(idx, total, doc_name)
                except Exception as cb_exc:  # noqa: BLE001
                    LOGGER.warning("progress_callback raised: %s; continuing", cb_exc)

            # この文書 1 件だけのプロンプトを生成
            single_prompt = build_prompt([doc], rubric)
            payload = self._build_payload(single_prompt)
            per_doc_prompts.append(single_prompt)

            # API call (リトライ機構付き)
            try:
                response = self._post_with_retry(payload)
                content = _extract_gemini_text(response)
                if not content.strip():
                    finish_reason = _first_finish_reason(response)
                    raise RuntimeError(
                        f"Empty response (finish_reason={finish_reason or 'unknown'})"
                    )
                # 1 文書のレビュー結果から issues を抽出
                doc_summary, _struct, doc_issues = _parse_review_payload(content, [doc])
                all_issues.extend(doc_issues)
                if doc_summary:
                    per_doc_summaries.append(f"【{doc_name}】{doc_summary}")
                per_doc_raw_responses.append(f"=== {doc_name} ===\n{content}")
            except RuntimeError as exc:
                # 個別文書の失敗は記録し、他の文書の処理は継続
                err_msg = str(exc)
                LOGGER.warning("Document %s failed: %s", doc_name, err_msg)
                failed_docs.append((doc_name, err_msg))
                per_doc_raw_responses.append(f"=== {doc_name} (FAILED) ===\n{err_msg}")
                if _looks_like_quota(err_msg):
                    # クォータ超過は処理を中断する (続行しても全部失敗するため)
                    raise

            # Free tier RPM 対策の sleep (最後の文書では不要)
            _interval = getattr(self, "chunking_interval_seconds", 0.0)
            if idx < total and _interval > 0:
                time.sleep(_interval)

        # 全件失敗した場合は明確にエラーにする
        if not all_issues and failed_docs and len(failed_docs) == total:
            details = "; ".join(f"{n}: {e}" for n, e in failed_docs[:3])
            raise RuntimeError(
                f"All {total} documents failed during chunked review. First errors: {details}"
            )

        # ID 割り当て (D-001, D-002, ...)
        _assign_issue_ids(all_issues, classification.document_profile)

        # 全体 summary を構成 (Phase 5 で集約 LLM call に置き換え予定)
        summary_lines = []
        if per_doc_summaries:
            summary_lines.append(
                f"全 {total} 文書のレビューを完了 (合計 {len(all_issues)} 件の指摘)。"
            )
            summary_lines.append("")
            summary_lines.extend(per_doc_summaries)
        else:
            summary_lines.append(
                f"全 {total} 文書のレビューを完了 (合計 {len(all_issues)} 件の指摘)。"
            )
        if failed_docs:
            summary_lines.append("")
            summary_lines.append(f"⚠️ 以下 {len(failed_docs)} 件の文書はレビューできませんでした:")
            for n, e in failed_docs:
                summary_lines.append(f"  - {n}: {e[:120]}")
        summary = "\n".join(summary_lines)

        # Phase 7 (2026-05-08): 集約 call (missing_chapters 判定) を削除。
        # 一段目をシンプルにし、深堀り call で missing_chapters を取得する設計に変更。

        # 最終通知 (100% 完了)
        if progress_callback is not None:
            try:
                progress_callback(total, total, "完了")
            except Exception:  # noqa: BLE001
                pass

        return _build_review_result(
            summary=summary,
            summary_structured=None,  # 一段目は per-doc summary から構築
            issues=all_issues,
            provider=self.name,
            documents=documents,
            rubric=rubric,
            classification_confidence=classification.confidence,
            classification_reason=classification.reason,
            prompt="\n\n".join(per_doc_prompts)[:50000],  # 上限 50k chars (UI 表示用、Phase 7-D で拡張予定)
            raw_response="\n\n".join(per_doc_raw_responses)[:50000],
            model=self.model,
        )

    def _build_payload(self, prompt: str) -> dict:
        """Gemini API リクエストペイロードを構築 (共通処理)。"""
        return {
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": REVIEW_RESPONSE_SCHEMA,
            },
        }

    def _post_with_retry(self, payload: dict) -> dict:
        """課題 2 改修 (2026-05-08): リトライ機構強化版。

        変更点:
        - max_retries 1 → 3 (計 4 回試行)
        - 指数バックオフ (1.5s → 3s → 6s) + jitter
        - UpstreamHttpError.retryable で条件分岐 (network_guard.py 改修と連携)
        - 503/timeout は確実にリトライされる
        - クォータ超過 (429 + quota メッセージ) はリトライしない
        """
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return post_json_safely(
                    _build_gemini_endpoint(self.model),
                    payload,
                    {
                        "Content-Type": "application/json",
                        "x-goog-api-key": self.api_key,
                    },
                    context_label=f"Gemini ({self.model})",
                )
            except UpstreamHttpError as exc:
                last_error = exc
                message = str(exc)

                # Quota 超過は即座に諦める (リトライしても回復しない)
                if _looks_like_quota(message):
                    raise RuntimeError(
                        "Gemini free-tier quota appears to be exhausted. "
                        "Wait a minute and try again, or switch to a paid tier."
                    ) from None

                # network_guard.py 改修と連携: retryable=False のエラーは即座に raise
                # (例: HTTP 400 Bad Request, JSON parse error)
                #
                # レビュー後修正 (2026-05-08): デフォルトを True に変更。
                # これは旧 UpstreamHttpError (retryable 属性なしで raise されるもの)
                # を後方互換的にリトライ対象とするため。
                # 既存テスト互換性 (test_retry_once_then_raise_on_transport_error) を保ち、
                # 新しい網羅的な network_guard.py からの raise は明示的に True/False が
                # セットされているので、属性ありの場合はその値が使われる。
                _retryable = getattr(exc, "retryable", True)
                if not _retryable:
                    LOGGER.info(
                        "Gemini call failed with non-retryable error (status=%s); not retrying",
                        getattr(exc, "status_code", None),
                    )
                    raise

                # リトライ可能、かつ残試行回数あり
                if attempt < self.max_retries:
                    # 指数バックオフ + jitter で thundering herd を回避
                    # getattr で属性アクセスを安全に (テスト互換性)
                    _base = getattr(self, "retry_backoff_base_seconds", 1.5)
                    _jitter_max = getattr(self, "retry_backoff_jitter", 0.5)
                    backoff = _base * (2 ** attempt)
                    jitter = random.uniform(0, _jitter_max)
                    delay = backoff + jitter
                    LOGGER.info(
                        "Gemini call failed (attempt %d/%d, status=%s); retrying in %.1fs: %s",
                        attempt + 1,
                        self.max_retries + 1,
                        getattr(exc, "status_code", None),
                        delay,
                        exc,
                    )
                    time.sleep(delay)
                    continue
                # リトライ上限に達した
                LOGGER.warning(
                    "Gemini call exhausted retries (%d/%d); giving up",
                    attempt + 1,
                    self.max_retries + 1,
                )
                raise
        # Defensive: loop above always either returns or raises.
        raise last_error or RuntimeError("Gemini call failed with no error captured.")


class GeminiHostedGemmaProvider(GeminiApiReviewProvider):
    name = "gemma-4-gemini-api"
    default_model = "gemma-4-31b-it"


class GeminiFreeTierProvider(GeminiApiReviewProvider):
    """Gemini 2.x flash model variants are the ones that actually hit free-tier.

    If no model is configured, use ``gemini-2.0-flash`` as a saner default
    than the Gemma model the previous code used.
    """

    name = "gemini-free-tier"
    default_model = "gemini-2.0-flash"


def _build_deep_dive_prompt(
    documents: list[SanitizedDocument],
    rubric: ReviewRubric,
    target_doc_name: str,
    existing_issues: list,
    chapter: ChapterSection | None = None,
) -> str:
    """R-Y (2026-05-08) + Phase 7 段階 2-B (2026-05-08): 深堀レビュー用プロンプトを構築する。

    対象文書 (1 件) + その文書由来の既存指摘群 を入力に、LLM に
    「これらをより詳細に掘り下げ、追加の懸念点や具体的な推奨対応を
    挙げてください」と依頼する。出力 schema は通常レビューと同じ
    (REVIEW_RESPONSE_SCHEMA)。

    周辺文書 (target 以外) はプロンプトから除外する。理由:
    - 既存の総合レビューで既に分析済みのため
    - LLM の入力 token を target 文書の深掘りに集中させたい
    - 文脈が混在すると深堀の焦点がぼやける

    Phase 7 段階 2-B: chapter パラメータが指定された場合、章単位深堀りモード:
    - 評価対象は ChapterSection.extracted_text (1 章分のみ)
    - 78 項目チェックリストの該当章サブセットのみをプロンプトに埋め込み
    - missing_chapters は空配列を返すよう指示 (章単位では判定しない)
    """
    target_doc = next((d for d in documents if d.name == target_doc_name), None)
    if target_doc is None:
        # フォールバック: target が見つからない時は通常プロンプトと同じ動作
        return build_prompt(documents, rubric)

    related_issues = [
        i for i in existing_issues
        if getattr(i, "source_document", "") == target_doc_name
    ]

    # Phase 7 段階 2-B (2026-05-08): 章単位深堀りモード判定
    is_chapter_mode = chapter is not None
    chapter_label = chapter.chapter_label if is_chapter_mode else ""

    if is_chapter_mode:
        sections = [
            "以下は **章単位の深堀レビュー** のリクエストです。",
            f"対象文書: **{target_doc_name}**",
            f"対象章: **{chapter_label}** (章 ID: {chapter.chapter_id})",
            "",
            "この章を、構造定義書 v0.2 の該当チェック項目に基づいて詳細に評価してください。",
            "**章本文は文書全体の一部** ですが、評価はこの章単独の品質を見てください。",
            "(他の章との連携は、ファイル全体の深堀りで別途評価されます。)",
            "",
            render_rubric_for_prompt(rubric),
            "",
            "出力は必ず JSON オブジェクトのみで返してください。",
            "JSON の構造はシステムプロンプトで指定した形式に従ってください。",
            "missing_chapters は **空配列 []** を返してください (章単位では判定不要)。",
            "",
            "## 既存のレビュー指摘 (この文書全体に対するもの、章別ではない)",
            "",
        ]
    else:
        sections = [
            "以下は **深堀レビュー** のリクエストです。",
            f"対象文書: **{target_doc_name}**",
            "",
            "この文書には既に以下のレビュー指摘がされています。これらをさらに掘り下げ、",
            "より具体的な対応手順、関連する追加の懸念点、考慮すべきエッジケースなど、",
            "**新しい視点での詳細な分析** を追加してください。",
            "",
            "なお、既存指摘と完全に同じ内容を再掲する必要はなく、新たな観点 (運用・",
            "セキュリティ・性能・障害復旧・関係者間の合意プロセスなど) からの追加指摘",
            "や、既存指摘の具体化 (代替案・実装手順・前提条件) を中心に提示してください。",
            "",
            render_rubric_for_prompt(rubric),
            "",
            "出力は必ず JSON オブジェクトのみで返してください。",
            "JSON の構造はシステムプロンプトで指定した形式に従ってください。",
            "",
            "## 既存のレビュー指摘",
            "",
        ]

    if not related_issues:
        sections.append("(この文書に対する既存指摘はありません。文書本文から新規指摘のみ提示してください。)")
    else:
        for idx, issue in enumerate(related_issues, 1):
            iid = getattr(issue, "issue_id", "") or f"#{idx}"
            sev = getattr(issue, "severity", "")
            title = getattr(issue, "title", "")
            sections.append(f"### {iid} [{sev.upper()}] {title}")
            for field, label in [
                ("current_state", "現状"),
                ("issue", "問題点"),
                ("impact", "影響"),
                ("recommendation", "推奨対応"),
                ("details", "詳細"),
            ]:
                val = getattr(issue, field, "") or ""
                if val:
                    sections.append(f"- {label}: {val}")
            sections.append("")

    if is_chapter_mode:
        # Phase 7 段階 2-B: 章モード時は章本文のみ + 該当章のチェックリスト
        sections.append(f"## 対象章の本文")
        sections.append("")
        sections.append(f"--- 文書: {target_doc.name} | 章: {chapter_label} ---")
        sections.append(chapter.extracted_text)
        sections.append("")

        # 該当章の 78 項目サブセットを埋め込み (例: ch4 なら 6 項目)
        if rubric.document_profile == "design" and chapter.chapter_id != "ch_unknown":
            std_chapter = get_chapter_by_id(chapter.chapter_id)
            if std_chapter is not None:
                sections.append(f"## この章のチェック項目 ({chapter.chapter_id} {std_chapter.chapter_name})")
                sections.append("")
                sections.append(f"主目的: {std_chapter.purpose}")
                sections.append("")
                sections.append("以下の項目について、この章を 5 段階で評価し、checklist_results 配列に格納してください:")
                sections.append("")
                necessity_label = {"must": "[必須]", "recommended": "[推奨]", "optional": "[任意]"}
                for item in std_chapter.items:
                    label = necessity_label.get(item.necessity, "[?]")
                    sections.append(
                        f"- {item.item_id} {label} {item.item_name} (weight={item.weight}): {item.expected_content}"
                    )
                    if item.fail_conditions:
                        fc = "、".join(item.fail_conditions)
                        sections.append(f"  失敗条件: {fc}")
                sections.append("")
                sections.append(
                    "各 checklist_result には source_document に文書名 ("
                    f"{target_doc.name}) を、item_id / item_name は上記から正確にコピーしてください。"
                )
    else:
        # 従来通り: ファイル全体の深堀り
        sections.append("## 対象文書の本文")
        sections.append("")
        sections.append(f"--- 文書: {target_doc.name} ---")
        sections.append(target_doc.outbound_text)

    return "\n".join(sections)


def build_prompt(
    documents: list[SanitizedDocument],
    rubric: ReviewRubric | None = None,
    *,
    deep_dive_target: str | None = None,
    existing_issues: "list[ReviewIssue] | None" = None,
    chapter: ChapterSection | None = None,
) -> str:
    """LLM 入力プロンプトを構築する。

    R-Y (2026-05-08): ``deep_dive_target`` が指定された場合は、対象文書 +
    既存指摘 + 深堀指示の特殊プロンプトを返す。それ以外は従来通り全文書の
    総合レビュー用プロンプトを返す。

    Phase 7 段階 2-B (2026-05-08): chapter が指定された場合、章単位深堀り
    モードで _build_deep_dive_prompt を呼び出す (deep_dive_target も必須)。
    """
    if rubric is None:
        rubric = choose_rubric(documents)

    if deep_dive_target:
        return _build_deep_dive_prompt(
            documents, rubric, deep_dive_target, existing_issues or [],
            chapter=chapter,
        )

    # Phase 8 段階 8-A (2026-05-11): 一段目は軽量プロンプトに統一。
    # 詳細なルーブリック (78 項目評価等) は深堀り側で展開する設計。
    # rubric の profile_name と短い観点リストだけを埋め込む。
    sections = [
        "以下の成果物は匿名化済みです。日本語でレビューしてください。",
        "",
        f"# 文書プロファイル: {rubric.document_profile} ({rubric.rubric_name})",
        "",
        "# レビュー観点 (簡潔)",
        "- 設計の重大な不足や曖昧さ",
        "- 運用・セキュリティ・コスト観点での実現可能性",
        "- 章間・文書間の整合性",
        "",
        "出力は JSON のみ。詳細はシステムプロンプトの指定に従ってください。",
    ]

    # R-Q-1b (2026-05-06): 全文書数を先頭にサマリ、各文書には「K/N」を付与。
    # これによりモデルは
    #   (a) 全部で何文書を読まされているか
    #   (b) 各文書が何番目か
    # を確実に把握できる。Streamlit Cloud の並列アップロードで
    # `session_state.uploads` の順序が乱れるケースは streamlit_app.py 側で
    # 自然順ソート (``_natural_sort_key``) で吸収しているが、念のため
    # プロンプトでも順序を明示しておく。
    total = len(documents)
    if total > 1:
        sections.append("")
        sections.append(f"(本レビューでは合計 {total} 文書を順に提示します。連番付きファイル名は番号順にソート済みです。)")

    for index, document in enumerate(documents, start=1):
        if total > 1:
            sections.append(f"--- 文書 {index}/{total}: {document.name} ---")
        else:
            sections.append(f"--- 文書: {document.name} ---")
        sections.append(document.outbound_text)

    return "\n".join(sections)


def choose_provider() -> ReviewProvider:
    mode = os.getenv("REVIEW_PROVIDER", "mock").strip().lower()
    if mode == "http":
        return HttpLlmReviewProvider()
    if mode in {"gemma", "gemma4", "gemma-4", "gemini-gemma", "gemma-gemini"}:
        return GeminiHostedGemmaProvider()
    if mode in {"gemini", "gemini-api", "gemini-free", "gemini-free-tier"}:
        return GeminiFreeTierProvider()
    return MockReviewProvider()


def _build_review_result(
    summary: str,
    issues: list[ReviewIssue],
    provider: str,
    documents: list[SanitizedDocument],
    rubric: ReviewRubric,
    classification_confidence: str,
    classification_reason: str,
    prompt: str | None = None,
    raw_response: str = "",
    model: str = "",
    summary_structured: ReviewSummary | None = None,
    checklist_results: tuple = (),
    missing_chapters: tuple = (),
) -> ReviewResult:
    """Phase 5 (2026-05-08): checklist_results と missing_chapters 引数を追加。

    既存呼び出し側 (テスト等) は新引数を渡さなければデフォルト空 tuple のまま。
    """
    prompt_text = prompt or build_prompt(documents, rubric)
    return ReviewResult(
        summary=summary,
        issues=issues,
        provider=provider,
        prompt_preview=prompt_text[:2000],
        rubric_id=rubric.rubric_id,
        rubric_name=rubric.rubric_name,
        document_profile=rubric.document_profile,
        classification_confidence=classification_confidence,
        classification_reason=classification_reason,
        raw_response=raw_response,
        model=model,
        summary_structured=summary_structured or ReviewSummary(),
        checklist_results=checklist_results,
        missing_chapters=missing_chapters,
    )


def _build_gemini_endpoint(model: str) -> str:
    return (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{urllib.parse.quote(model, safe='.-')}:generateContent"
    )


# Backwards-compat shim for tests/callers that patched this symbol.
def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    return post_json_safely(url, payload, headers, context_label="LLM provider")


def _extract_openai_like_text(payload: dict) -> str:
    output = payload.get("output_text")
    if isinstance(output, str) and output.strip():
        return output

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if text:
                chunks.append(text)

    for choice in payload.get("choices", []):
        message = choice.get("message") or {}
        text = message.get("content")
        if isinstance(text, str) and text:
            chunks.append(text)

    # Return empty string on no-content rather than the whole payload; the
    # previous behavior allowed provider diagnostics to surface as user text.
    return "\n".join(chunks).strip()


def _extract_gemini_text(payload: dict) -> str:
    chunks: list[str] = []
    for candidate in payload.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            text = part.get("text")
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip()


def _first_finish_reason(payload: dict) -> str | None:
    for candidate in payload.get("candidates", []):
        reason = candidate.get("finishReason")
        if reason:
            return str(reason)
    return None


def _looks_like_quota(message: str) -> bool:
    lower = message.lower()
    return any(marker.lower() in lower for marker in _GEMINI_QUOTA_MARKERS)


def _parse_review_response(content: str, documents: list[SanitizedDocument]) -> list[ReviewIssue]:
    """Parse a review response, preferring JSON output.

    The Gemini API now returns structured JSON when the schema is enforced.
    For HTTP LLM providers that follow the prompt without server-side schema
    enforcement, JSON is still expected. We fall back to the legacy
    pipe-delimited parser only for backwards compatibility.

    Backwards-compat shim: returns issues only. Callers that also need the
    LLM-supplied summary or the structured ReviewSummary should use
    ``_parse_review_payload`` instead.
    """
    _, _, issues = _parse_review_payload(content, documents)
    return issues


# B2: profile-based prefixes for Python-side issue ID assignment.
# When the LLM does not supply an ID (or when we want consistent prefixes
# regardless of LLM behaviour), callers invoke ``_assign_issue_ids`` after
# parsing.
_PROFILE_ID_PREFIX = {
    "design": "D",
    "proposal": "P",
    "change_runbook": "CR",
    "operations_runbook": "OR",
    "source_code": "SC",
}


def _assign_issue_ids(
    issues: list[ReviewIssue], document_profile: str
) -> list[ReviewIssue]:
    """Assign IDs of the form "{prefix}-{NNN}" to issues that don't have one.

    The prefix is derived from the document profile (e.g. design -> "D-001").
    Issues whose ``issue_id`` is already populated (LLM supplied one) are
    left untouched.
    """
    prefix = _PROFILE_ID_PREFIX.get(document_profile, "I")
    counter = 1
    for issue in issues:
        if not issue.issue_id:
            issue.issue_id = f"{prefix}-{counter:03d}"
        counter += 1
    return issues


def _parse_checklist_results(
    content: str, source_doc_fallback: str = ""
) -> tuple[ChecklistResult, ...]:
    """Phase 5 (2026-05-08): LLM 応答から checklist_results を抽出。

    後方互換性のため、_parse_review_payload とは独立した関数。
    JSON パース失敗時は空 tuple を返す (致命エラーにしない)。

    Args:
        content: LLM の生レスポンス
        source_doc_fallback: LLM が source_document を返さなかった場合の値

    Returns:
        ChecklistResult のタプル (LLM が返さなかった場合は空)
    """
    text = content.strip()
    if not text:
        return ()
    # markdown フェンスを除去
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    if not (text.startswith("{") and text.rstrip().endswith("}")):
        return ()
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ()
    if not isinstance(payload, dict):
        return ()
    raw_list = payload.get("checklist_results", [])
    if not isinstance(raw_list, list):
        return ()
    results: list[ChecklistResult] = []
    valid_status = {
        "excellent", "good", "acceptable",
        "needs_improvement", "unacceptable", "not_applicable",
    }
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        item_id = str(entry.get("item_id") or "").strip()
        status = str(entry.get("status") or "").strip()
        if not item_id or not status:
            continue
        # status が想定外の値ならスキップ (LLM のハルシネーション防止)
        if status not in valid_status:
            LOGGER.info(
                "Skipping checklist_result with invalid status: item_id=%r status=%r",
                item_id, status,
            )
            continue
        results.append(ChecklistResult(
            item_id=item_id,
            item_name=str(entry.get("item_name") or "").strip(),
            source_document=str(entry.get("source_document") or source_doc_fallback).strip(),
            status=status,
            reason=str(entry.get("reason") or "").strip(),
            evidence=str(entry.get("evidence") or "").strip(),
        ))
    return tuple(results)


def _parse_missing_chapters(content: str) -> tuple[MissingChapter, ...]:
    """Phase 5 (2026-05-08): LLM 応答から missing_chapters を抽出。

    集約 call (chunking 完了後) でのみ使う想定。各 chunk call では
    LLM が空配列を返すように指示しており、空 tuple が戻る。

    Args:
        content: LLM の生レスポンス

    Returns:
        MissingChapter のタプル (LLM が返さなかった場合は空)
    """
    text = content.strip()
    if not text:
        return ()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    if not (text.startswith("{") and text.rstrip().endswith("}")):
        return ()
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ()
    if not isinstance(payload, dict):
        return ()
    raw_list = payload.get("missing_chapters", [])
    if not isinstance(raw_list, list):
        return ()
    results: list[MissingChapter] = []
    valid_verdict = {"should_have", "recommended", "out_of_scope"}
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        chapter_id = str(entry.get("chapter_id") or "").strip()
        verdict = str(entry.get("verdict") or "").strip()
        if not chapter_id or not verdict:
            continue
        if verdict not in valid_verdict:
            LOGGER.info(
                "Skipping missing_chapter with invalid verdict: chapter_id=%r verdict=%r",
                chapter_id, verdict,
            )
            continue
        results.append(MissingChapter(
            chapter_id=chapter_id,
            chapter_name=str(entry.get("chapter_name") or "").strip(),
            verdict=verdict,
            justification=str(entry.get("justification") or "").strip(),
            suggested_content=str(entry.get("suggested_content") or "").strip(),
        ))
    return tuple(results)


def _parse_review_payload(
    content: str, documents: list[SanitizedDocument]
) -> tuple[str, ReviewSummary, list[ReviewIssue]]:
    """Parse a review response and return ``(summary_text, summary_struct, issues)``.

    B2: extended to return both the legacy plain-text summary and the new
    structured ``ReviewSummary``. Backward compatibility is preserved:

    - If the LLM returns the legacy schema (summary as string), summary_text
      is populated and summary_struct is empty (``is_empty()`` returns True).
    - If the LLM returns the new schema (summary as object), summary_text is
      synthesised from ``overall_evaluation`` for legacy display paths, and
      summary_struct holds the structured form.
    - If the response is not JSON, falls back to the legacy pipe-format
      parser as before, returning ("", empty_summary, issues).

    Issues parsing also handles both old (title/details/recommendation only)
    and new (current_state/issue/impact/required_timing/re_review_required)
    schemas. Missing new fields default to empty strings / False.
    """
    summary_text, summary_struct, json_issues = _parse_json_payload(content, documents)
    if json_issues is not None:
        return summary_text, summary_struct, json_issues
    return "", ReviewSummary(), _parse_issue_blocks(content, documents)


def _parse_json_payload(
    content: str, documents: list[SanitizedDocument]
) -> tuple[str, ReviewSummary, list[ReviewIssue] | None]:
    """Internal: try to parse JSON and return ``(summary_text, summary_struct, issues_or_None)``.

    Returns ``("", empty_summary, None)`` if the content is not JSON; the
    caller falls back to the legacy parser. Returns
    ``(summary_text, summary_struct, issues)`` (issues possibly empty) when
    JSON parses successfully.
    """
    text = content.strip()
    empty_summary = ReviewSummary()
    if not text:
        return "", empty_summary, None

    # Strip optional markdown fences the model may have added despite the
    # explicit instruction to return JSON only.
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    if not (text.startswith("{") and text.rstrip().endswith("}")):
        return "", empty_summary, None

    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return "", empty_summary, None
    if not isinstance(payload, dict):
        return "", empty_summary, None

    # B2: summary may be either a string (legacy) or an object (new schema).
    summary_raw = payload.get("summary", "")
    summary_text = ""
    summary_struct = ReviewSummary()
    if isinstance(summary_raw, str):
        # Legacy schema: plain text summary.
        summary_text = summary_raw.strip()
    elif isinstance(summary_raw, dict):
        # New schema: structured summary.
        summary_struct = ReviewSummary(
            purpose=str(summary_raw.get("purpose", "")).strip(),
            purpose_section_in_document=str(
                summary_raw.get("purpose_section_in_document", "")
            ).strip(),
            purpose_divergence=str(summary_raw.get("purpose_divergence", "")).strip(),
            content_outline=str(summary_raw.get("content_outline", "")).strip(),
            overall_evaluation=str(summary_raw.get("overall_evaluation", "")).strip(),
            verdict=str(summary_raw.get("verdict", "")).strip(),
        )
        # Synthesise legacy plain-text summary from overall_evaluation so
        # callers that still read ``ReviewResult.summary`` keep working.
        summary_text = summary_struct.overall_evaluation

    raw_issues = payload.get("issues", [])
    if not isinstance(raw_issues, list):
        return summary_text, summary_struct, []

    default_source = documents[0].name if documents else "-"
    parsed: list[ReviewIssue] = []
    for raw in raw_issues:
        if not isinstance(raw, dict):
            continue
        severity = str(raw.get("severity", "")).strip().lower()
        if severity not in _VALID_SEVERITIES:
            continue
        title = str(raw.get("title", "")).strip()
        details = str(raw.get("details", "")).strip()
        recommendation = str(raw.get("recommendation", "")).strip()
        source = str(raw.get("source_document", "")).strip() or default_source

        # B2: new structured fields (all optional).
        section = str(raw.get("section", "")).strip()
        current_state = str(raw.get("current_state", "")).strip()
        issue_text = str(raw.get("issue", "")).strip()
        impact = str(raw.get("impact", "")).strip()
        required_timing = str(raw.get("required_timing", "")).strip()
        re_review_raw = raw.get("re_review_required", False)
        re_review_required = bool(re_review_raw) if isinstance(re_review_raw, bool) else False

        candidate_values = [title.lower(), details.lower(), recommendation.lower()]
        if any(value in _PLACEHOLDER_TOKENS for value in candidate_values):
            continue
        # B2: also reject placeholder values in the new fields.
        new_field_values = [
            current_state.lower(), issue_text.lower(), impact.lower(),
        ]
        if any(value in _PLACEHOLDER_TOKENS for value in new_field_values):
            continue

        # B2: synthesise legacy ``details`` when only the new fields are
        # populated, so backward-compat display paths still have something
        # to show.
        if not details and (current_state or issue_text or impact):
            parts = []
            if current_state:
                parts.append(f"【現状】{current_state}")
            if issue_text:
                parts.append(f"【問題点】{issue_text}")
            if impact:
                parts.append(f"【影響】{impact}")
            details = " ".join(parts)

        if not title and not details:
            continue

        parsed.append(
            ReviewIssue(
                severity=severity,
                title=title or "(無題の指摘)",
                details=details or "(詳細なし)",
                recommendation=recommendation or "(推奨対応の記載なし)",
                source_document=source,
                # B2: structured fields. issue_id is not set here - callers
                # assign it after parsing via _assign_issue_ids().
                section=section,
                current_state=current_state,
                issue=issue_text,
                impact=impact,
                required_timing=required_timing,
                re_review_required=re_review_required,
            )
        )

    return summary_text, summary_struct, parsed


def _parse_json_issues(
    content: str, documents: list[SanitizedDocument]
) -> list[ReviewIssue] | None:
    """Backwards-compat shim. Prefer ``_parse_json_payload``."""
    _, issues = _parse_json_payload(content, documents)
    return issues


def _parse_issue_blocks(content: str, documents: list[SanitizedDocument]) -> list[ReviewIssue]:
    issues: list[ReviewIssue] = []
    default_source = documents[0].name if documents else "-"

    for line in content.splitlines():
        if not line.startswith("ISSUE|"):
            continue
        parts = [item.strip() for item in line.split("|", 5)]
        if len(parts) != 6:
            continue
        _, severity, title, details, recommendation, source_document = parts

        severity_normalized = severity.lower()
        # Reject placeholder-echo lines (e.g. "ISSUE|severity|title|...").
        if severity_normalized not in _VALID_SEVERITIES:
            continue
        if any(
            value.lower() in _PLACEHOLDER_TOKENS
            for value in (title, details, recommendation)
        ):
            continue

        issues.append(
            ReviewIssue(
                severity=severity_normalized,
                title=title or "Review issue",
                details=details or content[:200],
                recommendation=recommendation or "Please confirm the intended configuration.",
                source_document=source_document or default_source,
            )
        )

    if issues:
        return issues

    return [
        ReviewIssue(
            severity="medium",
            title="LLM review response",
            details=content[:500] or "No review text was returned.",
            recommendation="Confirm the provider response format and prompt template.",
            source_document=default_source,
        )
    ]


def _has_purpose_at_beginning(beginning: str) -> bool:
    return any(
        keyword in beginning
        for keyword in ("目的", "本資料は", "本書は", "本手順書は", "対象", "purpose", "objective")
    )


def _has_configuration_information(text: str) -> bool:
    return any(
        keyword in text
        for keyword in (
            "構成図",
            "接続図",
            "ネットワーク構成",
            "システム構成",
            "機器一覧",
            "network diagram",
            "topology",
            "概要図",
            "全体概要",
            "体制図",
        )
    )


def _has_timechart_reference(text: str) -> bool:
    return any(keyword in text for keyword in ("タイムチャート", "time chart", "timeline", "別紙", "スケジュール"))


def _has_operational_handover_signals(text: str) -> bool:
    """SLO/SLA / monitoring-runbook link / ownership のいずれかに言及があるか。"""
    keywords = (
        "slo",
        "sla",
        "service level",
        "サービス目標",
        "稼働率目標",
        "オーナー",
        "owner",
        "raci",
        "責任分担",
        "エスカレーション",
        "escalation",
        "ランブック",
        "runbook",
        "on-call",
        "オンコール",
        "アラート",
        "alert",
    )
    return any(keyword in text for keyword in keywords)


def _has_irreversible_operation_signals(text: str) -> bool:
    """不可逆と推定される作業キーワード。"""
    keywords = (
        "drop table",
        "truncate",
        "rm -rf",
        "delete from",
        "format ",
        "破棄",
        "削除",
        "データ削除",
        "物理削除",
        "上書き",
        "overwrite",
    )
    return any(keyword in text for keyword in keywords)


def _has_rollback_signals(text: str) -> bool:
    keywords = (
        "切戻し",
        "切り戻し",
        "rollback",
        "roll back",
        "backout",
        "補償処置",
        "リカバリ",
        "fallback",
        "代替手段",
    )
    return any(keyword in text for keyword in keywords)


def _has_environment_distinction(text: str) -> bool:
    """作業対象環境の区別が記載されているか（本番/検証/ステージング等）。"""
    keywords = (
        "本番",
        "検証",
        "ステージング",
        "staging",
        "production",
        "prod",
        "preprod",
        "開発環境",
        "qa環境",
        "評価環境",
    )
    return any(keyword in text for keyword in keywords)


def _has_risk_level_with_approval(text: str) -> bool:
    """リスクレベル分類と承認プロセスの両方の言及があるか。"""
    risk_keywords = (
        "リスクレベル",
        "risk level",
        "リスク分類",
        "リスク区分",
    )
    approval_keywords = (
        "承認",
        "approval",
        "approved by",
        "オーソライズ",
        "サインオフ",
        "sign-off",
        "決裁",
    )
    has_risk = any(keyword in text for keyword in risk_keywords)
    has_approval = any(keyword in text for keyword in approval_keywords)
    return has_risk and has_approval


def _has_document_update_list(text: str) -> bool:
    """作業後に修正するドキュメントの事前一覧があるか。"""
    keywords = (
        "変更対象ドキュメント",
        "修正対象ドキュメント",
        "更新対象ドキュメント",
        "改訂対象",
        "documents to update",
        "documents affected",
        "ドキュメント更新計画",
        "ドキュメント修正計画",
    )
    return any(keyword in text for keyword in keywords)


def _has_hardcoded_secret(text: str) -> bool:
    return bool(re.search(r"(?im)(password|passwd|token|secret|apikey|api_key)\s*[:=]\s*['\"][^'\"]+['\"]", text))


def _has_unprotected_command_execution(text: str) -> bool:
    return any(
        keyword in text
        for keyword in ("os.system(", "subprocess.run(", "subprocess.popen(", "invoke-expression", "iex ", "eval(", "exec(")
    )


def _has_bare_except(text: str) -> bool:
    return bool(re.search(r"(?im)^\s*except\s*:\s*$", text))
