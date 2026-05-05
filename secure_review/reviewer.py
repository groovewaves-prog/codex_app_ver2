from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from secure_review.models import ReviewIssue, ReviewResult, ReviewSummary, SanitizedDocument
from secure_review.network_guard import UpstreamHttpError, post_json_safely
from secure_review.rubric import ReviewRubric, classify_documents, choose_rubric, render_rubric_for_prompt


LOGGER = logging.getLogger("secure_review.reviewer")


SYSTEM_PROMPT = """あなたは日本のIT業界における設計レビュー担当者です。
匿名化済みの成果物をレビューしてください。原文の秘密情報や本人特定情報を求めないでください。

# 役割と評価姿勢

- 指摘は感情的・主観的表現を避け、事実ベースで客観的に記述してください。
- 「不適切である」のような断定よりも「〜の改善余地がある」「〜のリスクがある」のような事実ベースの記述を好んでください。
- 設計・構築・運用・セキュリティ・監査・可用性・コストへの影響を意識してください。

# 評価方針 (指摘の構造)

各指摘は必ず以下のフィールドを持つ JSON オブジェクトとして返してください。

- severity: "high" / "medium" / "low" / "info" のいずれか **(必須)**
- title: 指摘のタイトル (日本語、簡潔に) **(必須)**
- source_document: 対象文書のファイル名 **(必須)**
- section: 対象箇所の章番号や見出し (例: "2.4 システム構成図")。特定できない場合は空文字列。
- current_state: ドキュメントに何が書かれているか (現状の事実描写) **(必須・空文字列禁止)**
- issue: なぜそれが問題か (問題の本質) **(必須・空文字列禁止)**
- impact: 放置するとどう影響するか (運用・構築・セキュリティ・監査・コスト等の観点で具体的に列挙) **(必須・空文字列禁止)**
- recommendation: 修正すべき具体項目を列挙形式で記述 (抽象的な「対応してください」ではなく、含めるべき要素を明示) **(必須・空文字列禁止。最低でも 2 つの具体的な対応項目を列挙してください。)**
- required_timing: 以下のいずれか:
  - "リリース前必須": リリース前に必ず是正すべき (高重要度に多い)
  - "詳細設計開始前": 詳細設計フェーズに入る前に解決すべき
  - "運用開始前": 運用開始までに整備すべき
  - "次フェーズで可": 当該フェーズでは見送り可能、次フェーズで対応
- re_review_required: true / false (指摘是正後に再レビューが必要か)
- details: 後方互換のため、現状/問題点/影響を 1-2 文に要約した文 (省略可、空文字列でも可)

# サマリー方針 (4 セクション + 総合判定)

レスポンス全体の summary は文字列ではなく以下の構造のオブジェクトにしてください。

**重要**: summary オブジェクトには以下の **6 つのフィールドすべてを必ず含めてください**。
内容が該当しない場合のみ空文字列 "" を入れてください。フィールド自体を省略することは許容されません。

- purpose: あなたがドキュメントの内容から読み取った、ドキュメント全体の目的を 1-2 文で要約 (日本語)。**これは「ドキュメント本文中に書かれている目的」ではなく、あなたが内容を解釈して導き出した目的です。**
- purpose_section_in_document: ドキュメント内に「目的」「本書の位置付け」「概要」等の冒頭セクションが存在する場合、その章番号や見出しを記載 (例: "1.1 本書の位置付け")。**ドキュメント内に該当セクションが見当たらない場合は、必ず空文字列 "" を返してください**(架空のセクション名を作らないこと)。
- purpose_divergence: ``purpose_section_in_document`` が空でない場合、その目的セクションに記載されている内容と、あなたが ``purpose`` に書いた目的の解釈との間に乖離がないか確認し、**乖離があれば具体的に記述してください**。乖離がない場合、または目的セクションが存在しない場合は空文字列 ""。
- content_outline: ドキュメントの内容要約 (何が書かれているか、3-5 文程度)
- overall_evaluation: 全体評価 (整合性・重大懸念点・全体的な品質、3-5 文)。**これは特に重要なフィールドで、このフィールドの内容がユーザに最初に表示されます。空文字列にせず、必ず実質的な内容を記述してください。**
- verdict: 総合判定。以下のいずれか:
  - "A": 問題なし
  - "B": 軽微な指摘のみ、軽い修正で可
  - "C": 重要指摘あり、修正後に再レビュー推奨
  - "D": 重大指摘あり、現時点ではリリース不可

# 出力形式 (JSON 必須)

必ず以下の構造の JSON オブジェクトのみを返してください。説明文や markdown のコードブロック (```) を付けないでください。

{
  "summary": {
    "purpose": "...",
    "purpose_section_in_document": "...",
    "purpose_divergence": "...",
    "content_outline": "...",
    "overall_evaluation": "...",
    "verdict": "C"
  },
  "issues": [
    {
      "severity": "high",
      "title": "...",
      "source_document": "...",
      "section": "...",
      "current_state": "...",
      "issue": "...",
      "impact": "...",
      "recommendation": "...",
      "required_timing": "リリース前必須",
      "re_review_required": true,
      "details": ""
    }
  ]
}

# 重要な指示

- 重大度の判定基準:
  - high: ブロッキング相当 (リリース前必須是正、安全性・整合性に重大な穴)
  - medium: 必須に近い改善 (詳細設計開始前か運用開始前に対応)
  - low: 改善推奨 (次フェーズで可)
  - info: 補足情報・参考事項
- "title", "current_state", "issue", "impact", "recommendation" には実際のレビュー内容を入れること。フィールド名そのものを値として返さないこと。
- "impact" は箇条書き的に複数の影響観点 (運用・セキュリティ・コスト等) を述べること。単に「影響がある」のような抽象表現は避けること。
- "recommendation" は「〜してください」だけでなく、含めるべき具体項目を列挙すること。
- issues 配列が空でもよい。その場合は overall_evaluation に「重大な指摘なし」等を明記する。
- ルーブリックの mandatory_checks に違反する箇所は high または medium で確実に拾うこと。
- ルーブリックの evaluation_axes の checkpoint / fail_condition と照らして、抜け漏れを確認すること。
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
                    "current_state",
                    "issue",
                    "impact",
                    "recommendation",
                ],
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
    ) -> ReviewResult:
        raise NotImplementedError


class MockReviewProvider(ReviewProvider):
    name = "mock"

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
    ) -> ReviewResult:
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
    ) -> ReviewResult:
        if not self.api_url or not self.model:
            raise ValueError("LLM_API_URL and LLM_MODEL must be configured.")

        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)
        prompt = build_prompt(documents, rubric)
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
    max_retries = 1
    retry_backoff_seconds = 2.0

    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
        self.model = (
            os.getenv("GEMMA_MODEL", "").strip()
            or os.getenv("GEMINI_MODEL", "").strip()
            or self.default_model
        )
        self.max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "2048"))
        self.temperature = float(os.getenv("GEMINI_TEMPERATURE", "0.2"))

    def review(
        self,
        documents: list[SanitizedDocument],
        document_profile_override: str | None = None,
    ) -> ReviewResult:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY must be configured.")
        if not self.model:
            raise ValueError("GEMMA_MODEL or GEMINI_MODEL must be configured.")

        classification = classify_documents(documents, document_profile_override)
        rubric = choose_rubric(documents, document_profile_override)
        prompt = build_prompt(documents, rubric)
        # Force JSON output so the model cannot return literal placeholder
        # strings ("severity", "title", ...) the way it did with the older
        # pipe-delimited template. The schema is enforced on the server side
        # for models that support it; for models that do not, the prompt
        # alone still describes the same JSON shape.
        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": REVIEW_RESPONSE_SCHEMA,
            },
        }

        response = self._post_with_retry(payload)
        content = _extract_gemini_text(response)
        if not content.strip():
            finish_reason = _first_finish_reason(response)
            raise RuntimeError(
                f"Gemini returned no text (finish_reason={finish_reason or 'unknown'}). "
                "Consider reducing input size or raising GEMINI_MAX_OUTPUT_TOKENS."
            )
        # R-B + R-C: surface the model's own summary in the UI. Fall back to
        # an explicit Japanese notice when the model returned no summary, so
        # operators can spot misbehaving responses (choice γ from the design
        # discussion). The English boilerplate previously shown unconditionally
        # is removed.
        # B2: also extract the structured summary and assign issue IDs.
        model_summary, summary_struct, issues = _parse_review_payload(content, documents)
        _assign_issue_ids(issues, classification.document_profile)
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
        )

    def _post_with_retry(self, payload: dict) -> dict:
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
                if _looks_like_quota(message):
                    # Quota errors do not help by retrying.
                    raise RuntimeError(
                        "Gemini free-tier quota appears to be exhausted. "
                        "Wait a minute and try again, or switch to a paid tier."
                    ) from None
                if attempt < self.max_retries:
                    LOGGER.info("Gemini call failed (attempt %s); retrying: %s", attempt + 1, exc)
                    time.sleep(self.retry_backoff_seconds)
                    continue
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


def build_prompt(documents: list[SanitizedDocument], rubric: ReviewRubric | None = None) -> str:
    if rubric is None:
        rubric = choose_rubric(documents)

    multi_file_note = ""
    if len(documents) > 1:
        multi_file_note = (
            "**重要 — 文書構造の解釈方針**: "
            f"以下に {len(documents)} 件のファイルが添付されていますが、"
            "これらは関連する **1 つのドキュメント** (本文と別紙等の補足資料) "
            "を構成していると解釈してください。各ファイルを独立にレビューする"
            "のではなく、全体を統合的に評価してください。具体的には:\n"
            "- 「目的」項目は通常、本文の冒頭部分にのみ記載されます。"
            "全ファイルを横断して探してください。\n"
            "- 構成情報や設定値の詳細が別紙ファイルに分かれている場合、"
            "本文側の不足として誤指摘しないでください。\n"
            "- 本文と別紙の間で記述が矛盾していたり、別紙への参照が"
            "途中で途切れている場合は、重要な指摘として issues に含めてください。\n"
        )

    sections = [
        "以下の成果物は匿名化済みです。",
        "セキュリティ、整合性、運用、文書化の不足、決定的な不足、レビューブロッキング事項の観点から、日本語でレビューしてください。",
        "次のルーブリックを使用し、ブロッキング相当の不足と、もう少し詳細が必要な事項を明確に区別してください。",
        render_rubric_for_prompt(rubric),
        "",
        "出力は必ず JSON オブジェクトのみで返してください。markdown のコードブロックや前置きを付けないこと。",
        "JSON の構造はシステムプロンプトで指定した形式に従ってください。",
    ]

    if multi_file_note:
        sections.insert(0, multi_file_note)
        sections.insert(1, "")

    for document in documents:
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
) -> ReviewResult:
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

        # PR-H: when the LLM omits overall_evaluation (which Gemini does
        # semi-frequently because that field is optional in the JSON
        # schema), build a coherent summary from the other structured
        # fields so the user sees a usable summary instead of the
        # "LLM がレビューサマリを返しませんでした" fallback message.
        # The order here mirrors what a human reviewer would skim first:
        # purpose -> divergence -> outline -> verdict.
        if not summary_text:
            parts: list[str] = []
            if summary_struct.purpose:
                parts.append(f"目的: {summary_struct.purpose}")
            if summary_struct.purpose_divergence:
                parts.append(
                    f"目的との差異: {summary_struct.purpose_divergence}"
                )
            if summary_struct.content_outline:
                parts.append(f"内容概要: {summary_struct.content_outline}")
            if summary_struct.verdict:
                parts.append(f"判定: {summary_struct.verdict}")
            summary_text = " / ".join(parts)

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
