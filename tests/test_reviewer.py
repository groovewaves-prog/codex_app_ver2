import os
import unittest
from unittest.mock import patch

from secure_review.models import ChapterOverview, SanitizedDocument
from secure_review.network_guard import UpstreamHttpError
from secure_review.reviewer import (
    GeminiApiReviewProvider,
    GeminiFreeTierProvider,
    MockReviewProvider,
    _extract_gemini_text,
    _extract_openai_like_text,
    _looks_like_quota,
    choose_provider,
    provider_display_name,
)


def _doc(name="cfg.txt", text="hostname r1\nip address 10.0.0.1"):
    return SanitizedDocument(
        name=name,
        original_excerpt=text[:200],
        sanitized_excerpt=text[:200],
        outbound_text=text,
    )


class MockProviderTests(unittest.TestCase):
    def test_mock_produces_at_least_one_issue(self) -> None:
        provider = MockReviewProvider()
        result = provider.review([_doc(text="telnet allowed\ninterface Gi0/1")])
        self.assertTrue(result.issues)
        self.assertEqual(result.provider, "mock")


class ProviderChoiceTests(unittest.TestCase):
    def test_default_is_mock(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            provider = choose_provider()
        self.assertIsInstance(provider, MockReviewProvider)

    def test_gemini_free_tier_uses_flash_default(self) -> None:
        with patch.dict(
            os.environ,
            {"REVIEW_PROVIDER": "gemini-free", "GEMINI_API_KEY": "dummy"},
            clear=True,
        ):
            provider = choose_provider()
        self.assertIsInstance(provider, GeminiFreeTierProvider)
        self.assertTrue(provider.model.startswith("gemini-"))

    def test_provider_display_name_is_stable_for_gemma_hosted(self) -> None:
        self.assertEqual(
            provider_display_name("gemma-4-gemini-api", "gemma-4-31b-it"),
            "Gemma 4 (Gemini API) / gemma-4-31b-it",
        )


class GeminiExtractorTests(unittest.TestCase):
    def test_extract_gemini_text(self) -> None:
        payload = {
            "candidates": [
                {"content": {"parts": [{"text": "SUMMARY: ok"}, {"text": "more"}]}}
            ]
        }
        self.assertEqual(_extract_gemini_text(payload), "SUMMARY: ok\nmore")

    def test_extract_openai_returns_empty_on_nothing(self) -> None:
        """R4: never use json.dumps(payload) as fallback."""
        self.assertEqual(_extract_openai_like_text({"weird_field": 1}), "")

    def test_extract_openai_from_chat_completions(self) -> None:
        payload = {"choices": [{"message": {"content": "hello"}}]}
        self.assertEqual(_extract_openai_like_text(payload), "hello")


class QuotaDetectionTests(unittest.TestCase):
    def test_quota_markers_are_detected(self) -> None:
        self.assertTrue(_looks_like_quota("Resource has been exhausted (quota)"))
        self.assertTrue(_looks_like_quota("RESOURCE_EXHAUSTED"))
        self.assertTrue(_looks_like_quota("You hit a rate limit, please retry"))
        self.assertFalse(_looks_like_quota("Connection refused"))


class GeminiRetryTests(unittest.TestCase):
    def test_retry_once_then_raise_on_transport_error(self) -> None:
        with patch.dict(
            os.environ,
            {"GEMINI_API_KEY": "dummy", "GEMINI_MODEL": "gemini-2.0-flash"},
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        call_count = {"n": 0}

        def fake_post(*args, **kwargs):
            call_count["n"] += 1
            raise UpstreamHttpError("transport failed.")

        with patch("secure_review.reviewer.post_json_safely", side_effect=fake_post), \
             patch("secure_review.reviewer.time.sleep"):
            with self.assertRaises(UpstreamHttpError):
                provider.review([_doc()])

        # Initial + 1 retry = 2 calls.
        self.assertEqual(call_count["n"], 2)

    def test_gemini_retry_and_timeout_are_configurable(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "dummy",
                "GEMINI_MODEL": "gemma-4-31b-it",
                "GEMINI_MAX_RETRIES": "3",
                "GEMINI_TIMEOUT_SECONDS": "7",
            },
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        captured_timeouts: list[int] = []

        def fake_post(*args, **kwargs):
            captured_timeouts.append(kwargs["timeout"])
            raise UpstreamHttpError("transport failed.")

        with patch("secure_review.reviewer.post_json_safely", side_effect=fake_post), \
             patch("secure_review.reviewer.time.sleep"):
            with self.assertRaises(UpstreamHttpError):
                provider.review([_doc()])

        # Initial + 3 retries = 4 calls.
        self.assertEqual(len(captured_timeouts), 4)
        self.assertEqual(captured_timeouts, [7, 7, 7, 7])

    def test_gemma_model_disables_response_schema_by_default(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "dummy",
                "GEMMA_MODEL": "gemma-4-31b-it",
            },
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        payload = provider._build_payload("Return JSON.")
        generation_config = payload["generationConfig"]
        self.assertEqual(generation_config["responseMimeType"], "application/json")
        self.assertNotIn("responseSchema", generation_config)

    def test_gemini_model_keeps_response_schema_by_default(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "dummy",
                "GEMINI_MODEL": "gemini-2.5-flash",
            },
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        payload = provider._build_payload("Return JSON.")
        self.assertIn("responseSchema", payload["generationConfig"])

    def test_response_schema_can_be_forced_for_gemma_model(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "dummy",
                "GEMMA_MODEL": "gemma-4-31b-it",
                "GEMINI_USE_RESPONSE_SCHEMA": "true",
            },
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        payload = provider._build_payload("Return JSON.")
        self.assertIn("responseSchema", payload["generationConfig"])

    def test_schema_http_500_falls_back_without_response_schema(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "dummy",
                "GEMINI_MODEL": "gemini-2.5-flash",
                "GEMINI_MAX_RETRIES": "0",
            },
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        schema_flags: list[bool] = []

        def fake_post(_url, payload, _headers, **_kwargs):
            schema_flags.append("responseSchema" in payload["generationConfig"])
            if len(schema_flags) == 1:
                raise UpstreamHttpError(
                    "Gemini returned HTTP 500.",
                    status_code=500,
                    retryable=True,
                )
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": '{"summary": "ok", "issues": []}'},
                            ],
                        }
                    }
                ]
            }

        with patch("secure_review.reviewer.post_json_safely", side_effect=fake_post):
            result = provider.review([_doc()])

        self.assertEqual(result.summary, "ok")
        self.assertEqual(schema_flags, [True, False])

    def test_json_mode_http_500_falls_back_to_plain_text(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "dummy",
                "GEMMA_MODEL": "gemma-4-31b-it",
                "GEMINI_MAX_RETRIES": "0",
            },
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        json_mode_flags: list[bool] = []

        def fake_post(_url, payload, _headers, **_kwargs):
            json_mode_flags.append(
                payload["generationConfig"].get("responseMimeType")
                == "application/json"
            )
            if len(json_mode_flags) == 1:
                raise UpstreamHttpError(
                    "Gemini returned HTTP 500.",
                    status_code=500,
                    retryable=True,
                )
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": '{"summary": "ok", "issues": []}'},
                            ],
                        }
                    }
                ]
            }

        with patch("secure_review.reviewer.post_json_safely", side_effect=fake_post):
            result = provider.review([_doc()])

        self.assertEqual(result.summary, "ok")
        self.assertEqual(json_mode_flags, [True, False])

    def test_quota_errors_do_not_retry(self) -> None:
        with patch.dict(
            os.environ,
            {"GEMINI_API_KEY": "dummy", "GEMINI_MODEL": "gemini-2.0-flash"},
            clear=True,
        ):
            provider = GeminiApiReviewProvider()

        call_count = {"n": 0}

        def fake_post(*args, **kwargs):
            call_count["n"] += 1
            raise UpstreamHttpError(
                "Gemini (gemini-2.0-flash) returned HTTP 429. RESOURCE_EXHAUSTED."
            )

        with patch("secure_review.reviewer.post_json_safely", side_effect=fake_post), \
             patch("secure_review.reviewer.time.sleep"):
            with self.assertRaises(RuntimeError) as ctx:
                provider.review([_doc()])

        self.assertEqual(call_count["n"], 1)
        self.assertIn("quota", str(ctx.exception).lower())


    def test_operations_rubric_has_handover_axis(self) -> None:
        """研究知見反映: operations_runbook は運用ハンドオーバー軸を持つ。"""
        from secure_review.rubric import RUBRICS

        rubric = RUBRICS["operations_runbook"]
        axis_ids = {axis.id for axis in rubric.evaluation_axes}
        self.assertIn("operational_handover", axis_ids)

    def test_change_rubric_has_pir_axis(self) -> None:
        """研究知見反映: change_runbook は Post-Implementation Review 軸を持つ。"""
        from secure_review.rubric import RUBRICS

        rubric = RUBRICS["change_runbook"]
        axis_ids = {axis.id for axis in rubric.evaluation_axes}
        self.assertIn("post_implementation_review", axis_ids)

    def test_wbs_check_is_optional_and_applies_to_runbooks(self) -> None:
        """ユーザー指示: WBSは存在すれば確認、無くても指摘しない。"""
        from secure_review.rubric import OPTIONAL_CHECKS, RUBRICS

        wbs_check = OPTIONAL_CHECKS[0]
        self.assertEqual(wbs_check.id, "wbs_consistency_if_present")

        change_check_ids = {check.id for check in RUBRICS["change_runbook"].mandatory_checks}
        ops_check_ids = {check.id for check in RUBRICS["operations_runbook"].mandatory_checks}
        self.assertIn("wbs_consistency_if_present", change_check_ids)
        self.assertIn("wbs_consistency_if_present", ops_check_ids)

        # Design profile does not have WBS check (too early for WBS).
        design_check_ids = {check.id for check in RUBRICS["design"].mandatory_checks}
        self.assertNotIn("wbs_consistency_if_present", design_check_ids)

    def test_mock_detects_missing_operational_handover(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="operations.md",
                text="監視手順\n1. 確認\n2. 別紙スケジュールに従い対応\n目的: 定常運用",
            )],
            document_profile_override="operations_runbook",
        )
        titles = {issue.title for issue in result.issues}
        self.assertIn("運用ハンドオーバー要素の記載が不足", titles)

    def test_mock_detects_irreversible_without_rollback(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="migration.md",
                text=(
                    "目的: DB移行\n"
                    "ネットワーク構成: 別紙\n"
                    "タイムチャート: 別紙\n"
                    "1. DROP TABLE old_table\n"
                    "2. 新テーブル作成"
                ),
            )],
            document_profile_override="change_runbook",
        )
        titles = {issue.title for issue in result.issues}
        self.assertIn("不可逆な作業が含まれる可能性があり、補償処置が不明", titles)

    def test_mock_does_not_warn_when_rollback_present(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="migration.md",
                text=(
                    "目的: DB移行\n"
                    "ネットワーク構成: 別紙\n"
                    "タイムチャート: 別紙\n"
                    "1. DROP TABLE old_table\n"
                    "2. エラー時は切戻し: バックアップから復元"
                ),
            )],
            document_profile_override="change_runbook",
        )
        titles = {issue.title for issue in result.issues}
        self.assertNotIn("不可逆な作業が含まれる可能性があり、補償処置が不明", titles)

    def test_mock_detects_missing_environment_distinction(self) -> None:
        """テンプレート整合: 作業対象環境（本番/検証）の区別が必要。"""
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="change.md",
                text=(
                    "目的: 設定変更\n"
                    "ネットワーク構成: 別紙\n"
                    "タイムチャート: 別紙\n"
                    "リスクレベル: 低、承認: GL\n"
                    "変更対象ドキュメント: 設計書v1.2"
                ),
            )],
            document_profile_override="change_runbook",
        )
        titles = {issue.title for issue in result.issues}
        self.assertIn("作業対象環境の区別が不明確", titles)

    def test_mock_detects_missing_risk_level_and_approval(self) -> None:
        """テンプレート整合: リスクレベル + 承認の組が必要。"""
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="change.md",
                text=(
                    "目的: 本番設定変更\n"
                    "ネットワーク構成: 別紙\n"
                    "タイムチャート: 別紙\n"
                    "変更対象ドキュメント: 設計書v1.2"
                ),
            )],
            document_profile_override="change_runbook",
        )
        titles = {issue.title for issue in result.issues}
        self.assertIn("リスクレベルと承認プロセスの記載が不足", titles)

    def test_mock_detects_missing_document_update_list(self) -> None:
        """テンプレート整合: 作業後に修正するドキュメント一覧が必要。"""
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="change.md",
                text=(
                    "目的: 本番設定変更\n"
                    "ネットワーク構成: 別紙\n"
                    "タイムチャート: 別紙\n"
                    "リスクレベル: 低、承認: GL"
                ),
            )],
            document_profile_override="change_runbook",
        )
        titles = {issue.title for issue in result.issues}
        self.assertIn("作業後に修正対象となるドキュメントの事前一覧が無い", titles)

    def test_mock_passes_fully_compliant_template(self) -> None:
        """テンプレート整合: 作業計画書テンプレートに完全準拠したコンテンツは、
        テンプレート起源の指摘 (環境/リスクレベル/ドキュメント一覧) を受けない。"""
        provider = MockReviewProvider()
        result = provider.review(
            [_doc(
                name="change_plan.md",
                text=(
                    "作業目的: 本番環境への設定反映\n"
                    "全体概要図: 別紙\n"
                    "日時・場所: 2026/05/01 22:00 東京DC\n"
                    "作業対象環境: 本番\n"
                    "作業影響範囲: サービス影響なし\n"
                    "リスクレベル: 中、承認: 部長\n"
                    "作業完了後の正常性確認項目: ping疎通\n"
                    "バックアウト判断基準: エラー継続時は切戻し\n"
                    "タイムチャート: 別紙\n"
                    "リスクと対策: 予測できない有事の対策あり\n"
                    "体制図: 作業者・再鑑者・現地統括、エスカレーション経路\n"
                    "変更対象ドキュメント: 設計書v1.2、運用手順書"
                ),
            )],
            document_profile_override="change_runbook",
        )
        titles = {issue.title for issue in result.issues}
        # Template-originated checks should all pass
        self.assertNotIn("作業対象環境の区別が不明確", titles)
        self.assertNotIn("リスクレベルと承認プロセスの記載が不足", titles)
        self.assertNotIn("作業後に修正対象となるドキュメントの事前一覧が無い", titles)


# ----------------------------------------------------------------------
# R-B + R-C: model summary surfacing and the explicit-Japanese fallback
# when the model returned no summary (choice γ).
# ----------------------------------------------------------------------


class ReviewPayloadParsingTests(unittest.TestCase):
    """R-C: ``_parse_review_payload`` must extract both summary and issues."""

    def test_payload_returns_summary_and_issues_from_json(self) -> None:
        from secure_review.reviewer import _parse_review_payload

        content = (
            '{"summary": "提示された手順書は目的の記載があるが構成図が無い。", '
            '"issues": [{"severity": "high", "title": "構成図の欠落", '
            '"details": "詳細", "recommendation": "追加すること", '
            '"source_document": "doc.md"}]}'
        )
        summary, _, issues = _parse_review_payload(content, [_doc(name="doc.md")])
        self.assertEqual(summary, "提示された手順書は目的の記載があるが構成図が無い。")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, "high")

    def test_payload_returns_empty_summary_when_field_missing(self) -> None:
        """JSON without a summary field: summary is empty, issues still parsed.
        Caller is responsible for filling in a fallback."""
        from secure_review.reviewer import _parse_review_payload

        content = (
            '{"issues": [{"severity": "low", "title": "minor", '
            '"details": "x", "recommendation": "y", "source_document": "doc.md"}]}'
        )
        summary, _, issues = _parse_review_payload(content, [_doc(name="doc.md")])
        self.assertEqual(summary, "")
        self.assertEqual(len(issues), 1)

    def test_payload_handles_legacy_pipe_format_with_empty_summary(self) -> None:
        """Legacy ``ISSUE|...`` format: summary is empty (no JSON to parse),
        issues are parsed by the legacy block parser."""
        from secure_review.reviewer import _parse_review_payload

        content = "ISSUE|high|legacy title|legacy details|legacy reco|doc.md"
        summary, _, issues = _parse_review_payload(content, [_doc(name="doc.md")])
        self.assertEqual(summary, "")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].title, "legacy title")

    def test_payload_extracts_json_from_markdown_or_prefix_text(self) -> None:
        """Gemini can occasionally wrap JSON despite JSON-mode instructions."""
        from secure_review.reviewer import _parse_review_payload

        content = (
            "レビュー結果です。\n```json\n"
            '{"summary": "全体概要", "issues": []}'
            "\n```"
        )
        summary, _, issues = _parse_review_payload(content, [_doc(name="doc.md")])
        self.assertEqual(summary, "全体概要")
        self.assertEqual(issues, [])

    def test_chapter_overviews_are_parsed(self) -> None:
        from secure_review.reviewer import _parse_chapter_overviews

        content = (
            '{"summary": "全体概要", "issues": [], "chapter_overviews": ['
            '{"source_document": "design.docx", "chapter_id": "ch1", '
            '"chapter_label": "第 1 章 はじめに", "summary": "目的と背景", '
            '"review": "目的は読み取れる", "needs_deep_dive": true}'
            ']}'
        )
        overviews = _parse_chapter_overviews(content, [_doc(name="design.docx")])
        self.assertEqual(len(overviews), 1)
        self.assertEqual(overviews[0].chapter_id, "ch1")
        self.assertTrue(overviews[0].needs_deep_dive)


class GeminiSummarySurfacingTests(unittest.TestCase):
    """R-B + R-C: the Gemini provider must surface the model's own summary
    in ``ReviewResult.summary`` (not a fixed English boilerplate), and fall
    back to an explicit Japanese notice when the model did not provide one."""

    def _build_response(self, summary_text: str) -> dict:
        """Build a minimal Gemini API response containing the given summary."""
        import json as _json
        body = _json.dumps(
            {
                "summary": summary_text,
                "issues": [
                    {
                        "severity": "high",
                        "title": "テスト指摘",
                        "details": "詳細",
                        "recommendation": "推奨対応",
                        "source_document": "doc.md",
                    }
                ],
            }
        )
        return {
            "candidates": [
                {
                    "content": {"parts": [{"text": body}]},
                    "finishReason": "STOP",
                }
            ]
        }

    def test_summary_uses_model_text_when_provided(self) -> None:
        """When the model returns a summary, ReviewResult.summary should be
        that exact text — not an English boilerplate."""
        provider = GeminiApiReviewProvider.__new__(GeminiApiReviewProvider)
        provider.name = "gemma-4-gemini-api"
        provider.model = "gemma-4-31b-it"
        provider.api_key = "test-key"
        provider.temperature = 0.1
        provider.max_output_tokens = 8000
        provider.max_retries = 1

        expected_summary = "提示された手順書は構成情報が欠落している。"
        response = self._build_response(expected_summary)

        with patch.object(provider, "_post_with_retry", return_value=response):
            result = provider.review([_doc(name="doc.md", text="some text")])

        self.assertEqual(result.summary, expected_summary)
        self.assertNotIn("Received review result from", result.summary)

    def test_summary_falls_back_to_japanese_notice_when_empty(self) -> None:
        """When the model returns no summary (empty string), the result
        should contain the explicit Japanese fallback message (choice γ)."""
        provider = GeminiApiReviewProvider.__new__(GeminiApiReviewProvider)
        provider.name = "gemma-4-gemini-api"
        provider.model = "gemma-4-31b-it"
        provider.api_key = "test-key"
        provider.temperature = 0.1
        provider.max_output_tokens = 8000
        provider.max_retries = 1

        response = self._build_response("")  # explicit empty summary

        with patch.object(provider, "_post_with_retry", return_value=response):
            result = provider.review([_doc(name="doc.md", text="some text")])

        self.assertIn("LLM がレビューサマリを返しませんでした", result.summary)

    def test_review_result_carries_model_identifier(self) -> None:
        """R-B + R-C (ε): the concrete model identifier must travel with
        the ReviewResult so the UI can display it explicitly."""
        provider = GeminiApiReviewProvider.__new__(GeminiApiReviewProvider)
        provider.name = "gemma-4-gemini-api"
        provider.model = "gemma-4-31b-it"
        provider.api_key = "test-key"
        provider.temperature = 0.1
        provider.max_output_tokens = 8000
        provider.max_retries = 1

        response = self._build_response("test summary")

        with patch.object(provider, "_post_with_retry", return_value=response):
            result = provider.review([_doc(name="doc.md", text="some text")])

        self.assertEqual(result.model, "gemma-4-31b-it")
        # The internal provider slug stays separate.
        self.assertEqual(result.provider, "gemma-4-gemini-api")


# ----------------------------------------------------------------------
# B2 (R-L) tests: structured-summary parsing, 6-field issues, ID assignment
# ----------------------------------------------------------------------


class StructuredSummaryParsingTests(unittest.TestCase):
    """B2: when LLM returns ``summary`` as an object, parser populates
    ReviewSummary; when it returns a string (legacy), it goes into the
    plain-text summary slot and ReviewSummary stays empty."""

    def test_new_schema_object_summary(self) -> None:
        from secure_review.reviewer import _parse_review_payload
        content = (
            '{"summary": {'
            '"purpose": "AWS SES でのメール基盤", '
            '"purpose_section_in_document": "1.1", '
            '"purpose_divergence": "", '
            '"content_outline": "ネットワーク構成と運用方針を記載", '
            '"overall_evaluation": "全体方向性は妥当", '
            '"verdict": "C"}, '
            '"issues": []}'
        )
        text, struct, issues = _parse_review_payload(content, [_doc(name="d.pdf")])
        self.assertFalse(struct.is_empty())
        self.assertEqual(struct.verdict, "C")
        self.assertEqual(struct.purpose, "AWS SES でのメール基盤")
        # plain-text summary is synthesised from overall_evaluation
        self.assertEqual(text, "全体方向性は妥当")

    def test_legacy_string_summary_keeps_struct_empty(self) -> None:
        from secure_review.reviewer import _parse_review_payload
        content = '{"summary": "全体OK", "issues": []}'
        text, struct, issues = _parse_review_payload(content, [_doc(name="d.pdf")])
        self.assertEqual(text, "全体OK")
        self.assertTrue(struct.is_empty())


class StructuredIssueParsingTests(unittest.TestCase):
    """B2: parser extracts 6 new optional fields from issue objects."""

    def test_new_six_field_issue_parses(self) -> None:
        from secure_review.reviewer import _parse_review_payload
        content = (
            '{"summary": {}, "issues": [{'
            '"severity": "high", "title": "認証情報の保管", '
            '"source_document": "design.pdf", "section": "5. メール設計", '
            '"current_state": "GoogleDriveで永久保管", '
            '"issue": "汎用ストレージで機密情報を長期保管", '
            '"impact": "漏洩時影響大、SES制限リスク", '
            '"recommendation": "Secrets Manager移行、ローテーション", '
            '"required_timing": "リリース前必須", '
            '"re_review_required": true}]}'
        )
        _, _, issues = _parse_review_payload(content, [_doc(name="design.pdf")])
        self.assertEqual(len(issues), 1)
        i = issues[0]
        self.assertTrue(i.has_structured_fields())
        self.assertEqual(i.section, "5. メール設計")
        self.assertEqual(i.current_state, "GoogleDriveで永久保管")
        self.assertEqual(i.required_timing, "リリース前必須")
        self.assertTrue(i.re_review_required)

    def test_details_synthesised_from_new_fields(self) -> None:
        """When LLM returns only the new fields (no legacy ``details``),
        the parser synthesises ``details`` from current_state + issue + impact
        for backward-compat display paths."""
        from secure_review.reviewer import _parse_review_payload
        content = (
            '{"summary": {}, "issues": [{'
            '"severity": "low", "title": "x", "source_document": "d.pdf", '
            '"current_state": "状態A", "issue": "問題B", "impact": "影響C", '
            '"recommendation": "対応D"}]}'
        )
        _, _, issues = _parse_review_payload(content, [_doc(name="d.pdf")])
        self.assertEqual(len(issues), 1)
        # The synthesised ``details`` contains all three new-field bracketed
        # sections so legacy display paths can render something readable.
        self.assertIn("【現状】", issues[0].details)
        self.assertIn("【問題点】", issues[0].details)
        self.assertIn("【影響】", issues[0].details)


class IssueIdAssignmentTests(unittest.TestCase):
    """B2: ``_assign_issue_ids`` adds profile-prefixed IDs."""

    def test_design_profile_gets_d_prefix(self) -> None:
        from secure_review.reviewer import _assign_issue_ids
        from secure_review.models import ReviewIssue
        issues = [
            ReviewIssue(severity="high", title="t1", details="d1",
                        recommendation="r1", source_document="x.pdf"),
            ReviewIssue(severity="low", title="t2", details="d2",
                        recommendation="r2", source_document="x.pdf"),
        ]
        _assign_issue_ids(issues, "design")
        self.assertEqual(issues[0].issue_id, "D-001")
        self.assertEqual(issues[1].issue_id, "D-002")

    def test_proposal_profile_gets_p_prefix(self) -> None:
        from secure_review.reviewer import _assign_issue_ids
        from secure_review.models import ReviewIssue
        issues = [
            ReviewIssue(severity="medium", title="t", details="d",
                        recommendation="r", source_document="x.pdf"),
        ]
        _assign_issue_ids(issues, "proposal")
        self.assertEqual(issues[0].issue_id, "P-001")

    def test_existing_id_preserved(self) -> None:
        """If LLM supplied an issue_id, ``_assign_issue_ids`` must not
        overwrite it."""
        from secure_review.reviewer import _assign_issue_ids
        from secure_review.models import ReviewIssue
        issues = [
            ReviewIssue(severity="high", title="t", details="d",
                        recommendation="r", source_document="x.pdf",
                        issue_id="LLM-CUSTOM-42"),
        ]
        _assign_issue_ids(issues, "design")
        self.assertEqual(issues[0].issue_id, "LLM-CUSTOM-42")


class BuildPromptOrderingMetadataTests(unittest.TestCase):
    """R-Q-1b (2026-05-06): build_prompt が複数文書に「文書 K/N」形式の
    順序メタを付与することの確認。

    Streamlit ``st.file_uploader`` の格納順は並列アップロード完了順
    に依存し、番号付き設計書 (1, 2, ..., 12) を投入しても順序が乱れる。
    streamlit_app.py 側で ``_natural_sort_key`` でソートするのに加え、
    プロンプト側でも「全 N 文書中 K 番目」を明示することで、LLM が
    「ファイルが欠落している」「順序がおかしい」と誤指摘するリスクを
    減らす。
    """

    def test_single_document_keeps_legacy_format(self) -> None:
        """単一文書のときは「文書: <name>」のまま (旧形式維持、回帰防止)。"""
        from secure_review.reviewer import build_prompt
        prompt = build_prompt([_doc(name="only.pdf", text="content")])
        self.assertIn("--- 文書: only.pdf ---", prompt)
        # 「文書 1/1」形式は出ないこと
        self.assertNotIn("文書 1/1", prompt)
        # 合計提示行も出ないこと
        self.assertNotIn("合計", prompt)

    def test_multiple_documents_get_position_metadata(self) -> None:
        """複数文書のときは「文書 K/N: <name>」形式と、合計件数の前置き。"""
        from secure_review.reviewer import build_prompt
        docs = [
            _doc(name="a.pdf", text="aaa"),
            _doc(name="b.pdf", text="bbb"),
            _doc(name="c.pdf", text="ccc"),
        ]
        prompt = build_prompt(docs)
        # 合計件数の前置き
        self.assertIn("合計 3 文書", prompt)
        # 各文書に K/N
        self.assertIn("--- 文書 1/3: a.pdf ---", prompt)
        self.assertIn("--- 文書 2/3: b.pdf ---", prompt)
        self.assertIn("--- 文書 3/3: c.pdf ---", prompt)

    def test_document_order_in_prompt_matches_input_order(self) -> None:
        """入力リストの順序がプロンプト内の出現順と一致する (LLM が順序を
        誤解しないために重要)。"""
        from secure_review.reviewer import build_prompt
        docs = [
            _doc(name="基本設計書 1.pdf", text="一"),
            _doc(name="基本設計書 2.pdf", text="二"),
            _doc(name="基本設計書 12.pdf", text="十二"),
        ]
        prompt = build_prompt(docs)
        # 1.pdf の位置 < 2.pdf の位置 < 12.pdf の位置
        pos_1 = prompt.index("基本設計書 1.pdf")
        pos_2 = prompt.index("基本設計書 2.pdf")
        pos_12 = prompt.index("基本設計書 12.pdf")
        self.assertLess(pos_1, pos_2)
        self.assertLess(pos_2, pos_12)

    def test_document_body_text_preserved_after_metadata(self) -> None:
        """順序メタ追加後も outbound_text 本体は失われない (回帰防止)。"""
        from secure_review.reviewer import build_prompt
        docs = [
            _doc(name="a.pdf", text="ALPHA_BODY"),
            _doc(name="b.pdf", text="BETA_BODY"),
        ]
        prompt = build_prompt(docs)
        self.assertIn("ALPHA_BODY", prompt)
        self.assertIn("BETA_BODY", prompt)

    def test_chapter_deep_dive_prompt_requires_section_and_new_findings(self) -> None:
        from secure_review.reviewer import build_prompt
        from secure_review.rubric import ChapterSection

        chapter = ChapterSection(
            chapter_id="ch1",
            chapter_label="第 1 章 はじめに",
            detected_chapter_num=1,
            text_start=0,
            text_end=20,
            extracted_text="第 1 章 はじめに\n目的\n範囲",
        )
        prompt = build_prompt(
            [_doc(name="design.docx", text="第 1 章 はじめに\n目的\n範囲")],
            deep_dive_target="design.docx",
            existing_issues=[],
            chapter=chapter,
        )
        self.assertIn("既存指摘と同じ内容は再掲せず", prompt)
        self.assertIn("issues の section には対象章名を必ず入れてください", prompt)
        self.assertIn("概要レビューと異なる結論になる場合", prompt)

    def test_chapter_overview_prompt_defines_suitable_criteria(self) -> None:
        from secure_review.reviewer import build_prompt

        prompt = build_prompt([
            _doc(
                name="design.docx",
                text=(
                    "第 1 章 はじめに\n目的と範囲\n"
                    "第 2 章 システム要件\n機能要件\n"
                    "第 3 章 システム構成\n構成概要"
                ),
            )
        ])
        self.assertIn("review で「適切」と書けるのは", prompt)
        self.assertIn("needs_deep_dive=true", prompt)

    def test_prompt_includes_structure_check_consistency_guidance(self) -> None:
        from secure_review.reviewer import build_prompt

        prompt = build_prompt([
            _doc(
                name="design.docx",
                text=(
                    "第 1 章 はじめに\n本書の目的と対象範囲を示す。\n"
                    "第 2 章 システム要件\n概要のみ。\n"
                    "第 3 章 システム構成\n構成概要"
                ),
            )
        ])
        self.assertIn("文書構成チェックとの整合指示", prompt)
        self.assertIn("chapter_overviews と issues は、この内容と矛盾しない", prompt)
        self.assertIn("必須要素不足", prompt)

    def test_prompt_includes_source_format_review_guidance(self) -> None:
        from secure_review.reviewer import build_prompt

        prompt = build_prompt([_doc(name="slides.pptx", text="提案資料")])
        self.assertIn("# 入力形式別の読み方", prompt)
        self.assertIn("PDF: 抽出テキストはページ順", prompt)
        self.assertIn("Word (.docx): 本文中心の技術文書", prompt)
        self.assertIn("Excel (.xlsx): シート/行/列の表", prompt)
        self.assertIn("Excelブック診断", prompt)
        self.assertIn("PowerPoint (.pptx): スライド単位の説明資料", prompt)

    def test_source_code_prompt_uses_code_analysis_mode(self) -> None:
        from secure_review.reviewer import build_prompt
        from secure_review.rubric import choose_rubric

        document = _doc(
            name="kobekan_sendmail.sh.txt",
            text="#!/bin/bash\nmailx -S ssl-verify=ignore user@example.com",
        )
        prompt = build_prompt(
            [document],
            rubric=choose_rubric([document], "source_code"),
        )
        self.assertIn("レビュー運用モード", prompt)
        self.assertIn("コード解析モード", prompt)
        self.assertIn("コード/スクリプト解析の注意", prompt)
        self.assertIn("設計書の章立て不足ではなく", prompt)

    def test_runbook_prompt_separates_light_and_formal_depth(self) -> None:
        from secure_review.reviewer import build_prompt
        from secure_review.rubric import choose_rubric

        document = _doc(
            name="滞留障害イベント解消 手順書.txt",
            text="１．事前確認\n２．systemctl restart zabbix-server\n３．mysql -N -e 'select 1'",
        )
        prompt = build_prompt(
            [document],
            rubric=choose_rubric([document], "operations_runbook"),
        )
        self.assertIn("手順書レビューの粒度", prompt)
        self.assertIn("簡易手順書", prompt)
        self.assertIn("正式手順書", prompt)

    def test_prompt_requires_structured_summary_and_purpose_alignment(self) -> None:
        from secure_review.reviewer import build_prompt
        prompt = build_prompt([_doc(name="design.md", text="第 1 章 はじめに\n本文")])
        self.assertIn("summary は文字列ではなく", prompt)
        self.assertIn("purpose_section_in_document", prompt)
        self.assertIn("purpose_divergence", prompt)
        self.assertIn("目的記載がない", prompt)

    def test_local_summary_is_added_when_provider_summary_is_legacy(self) -> None:
        from secure_review.reviewer import _build_review_result
        from secure_review.rubric import choose_rubric

        document = _doc(
            name="design.md",
            text="第 1 章 はじめに\n目的: 認証基盤を更新する。\n第 2 章 システム要件\n本文",
        )
        result = _build_review_result(
            summary="legacy summary",
            issues=[],
            provider="mock",
            documents=[document],
            rubric=choose_rubric([document], "design"),
            classification_confidence="forced",
            classification_reason="test",
        )
        self.assertFalse(result.summary_structured.is_empty())
        self.assertIn("認証基盤", result.summary_structured.purpose)
        self.assertIn("目的", result.summary_structured.purpose_section_in_document)

    def test_review_result_reconciles_chapter_overviews_with_structure_check(self) -> None:
        from secure_review.reviewer import _build_review_result
        from secure_review.rubric import choose_rubric

        document = _doc(
            name="design.docx",
            text=(
                "第 1 章 はじめに\n本書の目的と対象範囲を示す。\n"
                "第 2 章 システム要件\n概要のみ。\n"
                "第 3 章 システム構成\n構成概要"
            ),
        )
        overview = ChapterOverview(
            source_document="design.docx",
            chapter_id="ch2",
            chapter_label="第 2 章 システム要件",
            summary="要件の概要。",
            review="適切",
            needs_deep_dive=False,
        )
        result = _build_review_result(
            summary="summary",
            issues=[],
            provider="test",
            documents=[document],
            rubric=choose_rubric([document], "design"),
            classification_confidence="forced",
            classification_reason="test",
            chapter_overviews=(overview,),
        )
        reconciled = result.chapter_overviews[0]
        self.assertTrue(reconciled.needs_deep_dive)
        self.assertIn("文書構成チェック", reconciled.review)
        self.assertIn("必須要素不足", reconciled.review)
        self.assertIn(
            "文書構成チェック",
            result.to_dict()["chapter_overviews"][0]["review"],
        )

    def test_chapter_deep_dive_prompt_filters_unrelated_existing_issues(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import build_prompt
        from secure_review.rubric import ChapterSection

        chapter = ChapterSection(
            chapter_id="ch2",
            chapter_label="第 2 章 システム要件",
            detected_chapter_num=2,
            text_start=0,
            text_end=20,
            extracted_text="第 2 章 システム要件\n機能要件\n非機能要件",
        )
        issues = [
            ReviewIssue(
                severity="high",
                title="FIRST_ONLY_ISSUE",
                details="first details",
                recommendation="first recommendation",
                source_document="design.docx",
                section="第 1 章 はじめに",
            ),
            ReviewIssue(
                severity="medium",
                title="SECOND_ONLY_ISSUE",
                details="second details",
                recommendation="second recommendation",
                source_document="design.docx",
                section="第 2 章 システム要件",
            ),
        ]
        prompt = build_prompt(
            [_doc(name="design.docx", text="第 2 章 システム要件\n機能要件")],
            deep_dive_target="design.docx",
            existing_issues=issues,
            chapter=chapter,
        )
        self.assertIn("SECOND_ONLY_ISSUE", prompt)
        self.assertNotIn("FIRST_ONLY_ISSUE", prompt)


class SourceCodeHeuristicTests(unittest.TestCase):
    def test_python_exec_call_is_flagged(self) -> None:
        from secure_review.reviewer import _has_unprotected_command_execution
        self.assertTrue(_has_unprotected_command_execution("exec(user_input)"))

    def test_sql_exec_statement_is_not_flagged_as_python_exec(self) -> None:
        from secure_review.reviewer import _has_unprotected_command_execution
        sql = "CREATE PROCEDURE dbo.RunJob AS BEGIN EXEC(@sql); SELECT 1; END"
        self.assertFalse(_has_unprotected_command_execution(sql))

    def test_mock_source_code_flags_tls_verification_disabled(self) -> None:
        result = MockReviewProvider().review(
            [
                _doc(
                    name="kobekan_sendmail.sh.txt",
                    text="#!/bin/bash\nmailx -S ssl-verify=ignore -S smtp-auth-password=SECRET",
                )
            ],
            document_profile_override="source_code",
        )
        self.assertTrue(any("TLS" in issue.title for issue in result.issues))

    def test_mock_source_code_flags_network_without_timeout(self) -> None:
        result = MockReviewProvider().review(
            [
                _doc(
                    name="get_mails.py",
                    text="import urllib.request\nresponse = urllib.request.urlopen(req)\n",
                )
            ],
            document_profile_override="source_code",
        )
        self.assertTrue(any("タイムアウト" in issue.title for issue in result.issues))


class SourceCodeStaticFallbackTests(unittest.TestCase):
    def test_static_fact_filter_removes_false_syntax_error(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _filter_source_code_issues_by_static_facts

        issue = ReviewIssue(
            severity="high",
            title="構文エラー（Syntax Error）の存在",
            details="このコードは構文エラーにより実行できません。",
            recommendation="構文を修正してください。",
            source_document="lambda_function.py",
        )
        filtered = _filter_source_code_issues_by_static_facts(
            [issue],
            [_doc(name="lambda_function.py", text="def lambda_handler(event, context):\n    return 1\n")],
            "source_code",
        )

        self.assertEqual(filtered, [])

    def test_static_fact_filter_removes_llm_syntax_claim_even_when_python_is_broken(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _filter_source_code_issues_by_static_facts

        issue = ReviewIssue(
            severity="high",
            title="構文エラー（Syntax Error）の存在",
            details="このコードは構文エラーにより実行できません。",
            recommendation="構文を修正してください。",
            source_document="lambda_function.py",
        )
        filtered = _filter_source_code_issues_by_static_facts(
            [issue],
            [_doc(name="lambda_function.py", text="def lambda_handler(event, context):\n    return (\n")],
            "source_code",
        )

        self.assertEqual(filtered, [])

    def test_static_fact_filter_removes_false_missing_function_claim(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _filter_source_code_issues_by_static_facts

        issue = ReviewIssue(
            severity="high",
            title="主要関数の定義欠落による実行不能",
            details="lambda_handler内でgenerate_presigned_urlを呼び出すが、その定義が本文中に存在しない。",
            recommendation="欠落している関数定義を実装してください。",
            source_document="lambda_function.py",
        )
        filtered = _filter_source_code_issues_by_static_facts(
            [issue],
            [
                _doc(
                    name="lambda_function.py",
                    text=(
                        "def lambda_handler(event, context):\n"
                        "    return generate_presigned_url('key')\n\n"
                        "def generate_presigned_url(key):\n"
                        "    return key\n"
                    ),
                )
            ],
            "source_code",
        )

        self.assertEqual(filtered, [])

    def test_static_fact_filter_removes_source_missing_claims(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _filter_source_code_issues_by_static_facts

        issue = ReviewIssue(
            severity="high",
            title="ソースコードの欠落（実装不備）",
            details="提供されたソースコードが途中で切れており、主要関数の定義が一切存在しない。",
            recommendation="欠落している全関数を実装してください。",
            source_document="lambda_function.py",
        )
        filtered = _filter_source_code_issues_by_static_facts(
            [issue],
            [_doc(name="lambda_function.py", text="def lambda_handler(event, context):\n    return 1\n")],
            "source_code",
        )

        self.assertEqual(filtered, [])

    def test_static_fact_filter_removes_mask_placeholder_artifact_claims(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _filter_source_code_issues_by_static_facts

        issue = ReviewIssue(
            severity="medium",
            title="匿名化プレースホルダによるロジック破綻",
            details="匿名化プレースホルダにより処理が成立しない。",
            recommendation="プレースホルダを修正してください。",
            source_document="lambda_function.py",
        )
        filtered = _filter_source_code_issues_by_static_facts(
            [issue],
            [_doc(name="lambda_function.py", text="def lambda_handler(event, context):\n    return 1\n")],
            "source_code",
        )

        self.assertEqual(filtered, [])

    def test_static_fact_filter_keeps_non_verifiable_operational_risk(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _filter_source_code_issues_by_static_facts

        issue = ReviewIssue(
            severity="medium",
            title="大量データ処理時のメモリ不足リスク",
            details="S3イベントを全件リストに保持するため、件数増加時にメモリを圧迫する可能性がある。",
            recommendation="ストリーミング処理または分割処理を検討してください。",
            source_document="lambda_function.py",
        )
        filtered = _filter_source_code_issues_by_static_facts(
            [issue],
            [_doc(name="lambda_function.py", text="def lambda_handler(event, context):\n    return []\n")],
            "source_code",
        )

        self.assertEqual(filtered, [issue])

    def test_source_code_empty_llm_result_gets_static_fallback(self) -> None:
        from secure_review.reviewer import _source_code_static_fallback_if_empty

        issues = _source_code_static_fallback_if_empty(
            [],
            [
                _doc(
                    name="lambda_function.py",
                    text=(
                        "import json\n"
                        "import logging\n"
                        "logger = logging.getLogger()\n"
                        "def lambda_handler(event, context):\n"
                        "    logger.info(json.dumps(event))\n"
                        "    try:\n"
                        "        return {'statusCode': 200}\n"
                        "    except Exception as exc:\n"
                        "        logger.error(str(exc))\n"
                        "        return {'statusCode': 500}\n"
                    ),
                )
            ],
            "source_code",
        )

        titles = {issue.title for issue in issues}
        self.assertIn("入力イベントを丸ごとログ出力している", titles)
        self.assertIn("例外処理が広すぎる可能性", titles)

    def test_source_code_static_fallback_reports_real_python_syntax_error(self) -> None:
        from secure_review.reviewer import _source_code_static_fallback_if_empty

        issues = _source_code_static_fallback_if_empty(
            [],
            [_doc(name="lambda_function.py", text="def lambda_handler(event, context):\n    return (\n")],
            "source_code",
        )

        self.assertEqual(issues[0].title, "Python構文エラーを静的検出")
        self.assertIn("2行目付近", issues[0].current_state)
        self.assertIn("Lambda", issues[0].impact)

    def test_source_code_static_fallback_attaches_evidence_and_origin(self) -> None:
        from secure_review.reviewer import _source_code_static_fallback_if_empty

        issues = _source_code_static_fallback_if_empty(
            [],
            [
                _doc(
                    name="lambda_function.py",
                    text=(
                        "import json\n"
                        "import logging\n"
                        "logger = logging.getLogger()\n"
                        "def lambda_handler(event, context):\n"
                        "    logger.info(json.dumps(event))\n"
                        "    try:\n"
                        "        return {'statusCode': 200}\n"
                        "    except Exception as exc:\n"
                        "        logger.error(str(exc))\n"
                    ),
                )
            ],
            "source_code",
        )

        by_title = {issue.title: issue for issue in issues}
        logging_issue = by_title["入力イベントを丸ごとログ出力している"]
        broad_except_issue = by_title["例外処理が広すぎる可能性"]

        self.assertEqual(logging_issue.origin, "static_code_analysis")
        self.assertIn("lambda_handler 内", logging_issue.current_state)
        self.assertIn("logger.info", logging_issue.current_state)
        self.assertIn("lambda_handler 内", logging_issue.section)
        self.assertIn("CloudWatch Logs", logging_issue.impact)
        self.assertIn("except Exception", broad_except_issue.current_state)

    def test_source_code_summary_fallback_is_actionable_when_summary_is_empty(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _review_summary_or_fallback

        summary = _review_summary_or_fallback(
            "",
            [
                ReviewIssue(
                    severity="medium",
                    title="入力イベントを丸ごとログ出力している",
                    details="details",
                    recommendation="recommendation",
                    source_document="lambda_function.py",
                )
            ],
            "source_code",
        )

        self.assertIn("コード解析で", summary)
        self.assertIn("確認候補", summary)
        self.assertNotIn("LLM がレビューサマリを返しませんでした", summary)

    def test_source_code_summary_replaces_untrusted_incomplete_source_summary(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _review_summary_or_fallback

        summary = _review_summary_or_fallback(
            "提供されたソースコードが途中で切れており、このままでは動作しません。",
            [
                ReviewIssue(
                    severity="medium",
                    title="入力イベントを丸ごとログ出力している",
                    details="details",
                    recommendation="recommendation",
                    source_document="lambda_function.py",
                )
            ],
            "source_code",
        )

        self.assertIn("コード解析で", summary)
        self.assertNotIn("途中で切れて", summary)

    def test_source_code_static_fallback_does_not_override_model_issues(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _source_code_static_fallback_if_empty

        model_issue = ReviewIssue(
            severity="low",
            title="モデル由来の指摘",
            details="details",
            recommendation="recommendation",
            source_document="lambda_function.py",
        )
        issues = _source_code_static_fallback_if_empty(
            [model_issue],
            [_doc(name="lambda_function.py", text="logger.info(json.dumps(event))")],
            "source_code",
        )

        self.assertEqual(issues, [model_issue])

    def test_source_code_parser_notice_still_gets_static_fallback(self) -> None:
        from secure_review.models import ReviewIssue
        from secure_review.reviewer import _source_code_static_fallback_if_empty

        parse_notice = ReviewIssue(
            severity="info",
            title="LLM応答形式を解析できませんでした",
            details="raw response",
            recommendation="生レスポンスを確認してください。",
            source_document="lambda_function.py",
            issue_id="PARSE-001",
        )
        issues = _source_code_static_fallback_if_empty(
            [parse_notice],
            [
                _doc(
                    name="lambda_function.py",
                    text=(
                        "import json\n"
                        "import logging\n"
                        "logger = logging.getLogger()\n"
                        "def lambda_handler(event, context):\n"
                        "    logger.info(json.dumps(event))\n"
                        "    try:\n"
                        "        return {'statusCode': 200}\n"
                        "    except Exception as exc:\n"
                        "        logger.error(str(exc))\n"
                    ),
                )
            ],
            "source_code",
        )

        titles = {issue.title for issue in issues}
        self.assertNotIn("LLM応答形式を解析できませんでした", titles)
        self.assertIn("入力イベントを丸ごとログ出力している", titles)
        self.assertIn("例外処理が広すぎる可能性", titles)

    def test_static_fallback_is_source_code_only(self) -> None:
        from secure_review.reviewer import _source_code_static_fallback_if_empty

        issues = _source_code_static_fallback_if_empty(
            [],
            [_doc(name="runbook.md", text="logger.info(json.dumps(event))")],
            "design",
        )

        self.assertEqual(issues, [])


class NetworkConfigReviewTests(unittest.TestCase):
    def test_network_config_prompt_contains_machine_analysis(self) -> None:
        from secure_review.reviewer import build_prompt
        from secure_review.rubric import choose_rubric

        document = _doc(
            name="fortigate_config.conf",
            text=(
                "config system interface\n"
                " edit \"port1\"\n"
                "  set allowaccess ping http ssh\n"
                " next\n"
                "end\n"
                "config firewall policy\n"
                " edit 1\n"
                "  set srcintf \"port1\"\n"
                "  set dstintf \"port2\"\n"
                "  set srcaddr \"all\"\n"
                "  set dstaddr \"all\"\n"
                "  set service \"ALL\"\n"
                "  set action accept\n"
                " next\n"
                "end\n"
            ),
        )
        prompt = build_prompt(
            [document],
            rubric=choose_rubric([document], "network_config"),
        )
        self.assertIn("ネットワーク機器Configの機械解析", prompt)
        self.assertIn("正式なConfig監査ではなく", prompt)
        self.assertIn("広すぎるFirewall Policy", prompt)

    def test_mock_network_config_gets_nc_prefix(self) -> None:
        from secure_review.reviewer import MockReviewProvider

        document = _doc(
            name="router_config.txt",
            text=(
                "interface GigabitEthernet0/1\n"
                " ip address 10.0.0.1 255.255.255.0\n"
                "line vty 0 4\n"
                " transport input telnet ssh\n"
                "snmp-server community public RO\n"
            ),
        )
        result = MockReviewProvider().review(
            [document],
            document_profile_override="network_config",
        )
        self.assertEqual(result.document_profile, "network_config")
        self.assertTrue(result.issues)
        self.assertTrue(result.issues[0].issue_id.startswith("NC-"))
        self.assertTrue(any("Telnet" in issue.title for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
