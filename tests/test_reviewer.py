import os
import unittest
from unittest.mock import patch

from secure_review.models import SanitizedDocument
from secure_review.network_guard import UpstreamHttpError
from secure_review.reviewer import (
    GeminiApiReviewProvider,
    GeminiFreeTierProvider,
    MockReviewProvider,
    _extract_gemini_text,
    _extract_openai_like_text,
    _looks_like_quota,
    choose_provider,
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


if __name__ == "__main__":
    unittest.main()
