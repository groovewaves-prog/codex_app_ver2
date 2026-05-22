from __future__ import annotations

import unittest

from secure_review.future_review import build_future_review_report
from secure_review.models import ReviewIssue, ReviewResult, SanitizedDocument


class FutureReviewTests(unittest.TestCase):
    def test_ambiguous_expression_is_reported_when_evidence_is_missing(self) -> None:
        doc = SanitizedDocument(
            name="design.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text=(
                "第1章 運用方針\n"
                "障害時は必要に応じて切り戻す。\n"
                "第2章 監視\n"
                "監視アラートを確認する。"
            ),
        )

        report = build_future_review_report([doc])

        self.assertGreaterEqual(report.ambiguous_count, 1)
        first = report.ambiguous_findings[0]
        self.assertEqual(first.expression, "必要に応じて")
        self.assertIn("判断条件", first.missing_elements)

    def test_reader_risk_map_contains_expected_personas(self) -> None:
        doc = SanitizedDocument(
            name="design.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text=(
                "SAML OIDC MFA VPN RTO RPO SLA DNS AD FW API DB LB WAF IAM KMS\n"
                "監視と障害対応について記載する。"
            ),
        )

        report = build_future_review_report([doc])

        personas = {item.persona for item in report.reader_risks}
        self.assertEqual(personas, {"初任SE", "二次運用者", "監査人", "上長・承認者"})
        novice = next(item for item in report.reader_risks if item.persona == "初任SE")
        self.assertEqual(novice.risk_level, "high")

    def test_premortem_uses_review_issues_as_signals(self) -> None:
        doc = SanitizedDocument(
            name="design.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第1章 概要\n認証基盤の設計。バックアップを取得する。",
        )
        review = ReviewResult(
            summary="",
            provider="mock",
            prompt_preview="",
            issues=[
                ReviewIssue(
                    severity="high",
                    title="DR方針が不足",
                    details="RTO/RPO が未定義です。",
                    recommendation="RTO/RPOと切替手順を定義してください。",
                    source_document="design.txt",
                    section="第1章 概要",
                )
            ],
        )

        report = build_future_review_report([doc], review)

        titles = [item.title for item in report.premortem_scenarios]
        self.assertTrue(any("DR切替" in title for title in titles))

    def test_premortem_missing_elements_are_based_on_document_only(self) -> None:
        doc = SanitizedDocument(
            name="design.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第1章 概要\nバックアップを取得する。",
        )
        review = ReviewResult(
            summary="",
            provider="mock",
            prompt_preview="",
            issues=[
                ReviewIssue(
                    severity="high",
                    title="DR方針が不足",
                    details="RTO/RPO と切替手順が未定義です。",
                    recommendation="RTO/RPOと切替手順を定義してください。",
                    source_document="design.txt",
                    section="第1章 概要",
                )
            ],
        )

        report = build_future_review_report([doc], review)
        scenario = next(
            item for item in report.premortem_scenarios
            if item.scenario_id == "PM-001"
        )

        self.assertEqual(scenario.trigger_source, "both")
        self.assertIn("RTO/RPO", scenario.missing_elements)
        self.assertIn("切替手順", scenario.missing_elements)
        self.assertIn("DR方針が不足", scenario.review_hint)
        self.assertNotIn("RTO/RPO", scenario.confirmed_elements)

    def test_premortem_tracks_confirmed_document_elements(self) -> None:
        doc = SanitizedDocument(
            name="availability.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text=(
                "第8章 可用性\n"
                "DR対応では RTO 4時間、RPO 24時間を目標とする。"
                "バックアップからの切替手順を整備する。"
            ),
        )

        report = build_future_review_report([doc])
        scenario = next(
            item for item in report.premortem_scenarios
            if item.scenario_id == "PM-001"
        )

        self.assertEqual(scenario.trigger_source, "document")
        self.assertIn("RTO/RPO", scenario.confirmed_elements)
        self.assertIn("切替手順", scenario.confirmed_elements)
        self.assertIn("訓練", scenario.missing_elements)

    def test_premortem_source_prefers_matching_document(self) -> None:
        docs = [
            SanitizedDocument(
                name="01_overview.txt",
                original_excerpt="",
                sanitized_excerpt="",
                outbound_text="第1章 概要\n本システムの目的を記載する。",
            ),
            SanitizedDocument(
                name="08_availability.txt",
                original_excerpt="",
                sanitized_excerpt="",
                outbound_text="第8章 可用性\nバックアップを取得する。",
            ),
        ]
        review = ReviewResult(
            summary="",
            provider="mock",
            prompt_preview="",
            issues=[
                ReviewIssue(
                    severity="high",
                    title="全体方針不足",
                    details="目的が不明です。",
                    recommendation="目的を記載してください。",
                    source_document="01_overview.txt",
                    section="第1章 概要",
                )
            ],
        )

        report = build_future_review_report(docs, review)
        scenario = next(
            item for item in report.premortem_scenarios
            if item.scenario_id == "PM-001"
        )

        self.assertEqual(scenario.source_document, "08_availability.txt")

    def test_short_english_keywords_do_not_match_inside_words(self) -> None:
        doc = SanitizedDocument(
            name="memo.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第1章 概要\nadmin guide の説明のみ。",
        )

        report = build_future_review_report([doc])

        self.assertFalse(
            any(item.scenario_id == "PM-003" for item in report.premortem_scenarios)
        )

    def test_short_english_keywords_match_when_mixed_with_japanese(self) -> None:
        doc = SanitizedDocument(
            name="auth.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第1章 認証\nAD連携を行う。監視方式は未定。",
        )

        report = build_future_review_report([doc])

        scenario = next(
            item for item in report.premortem_scenarios
            if item.scenario_id == "PM-003"
        )
        self.assertEqual(scenario.trigger_source, "document")
        self.assertIn("代替経路", scenario.missing_elements)

    def test_premortem_can_be_triggered_by_review_issue_only(self) -> None:
        doc = SanitizedDocument(
            name="overview.txt",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第1章 概要\n本システムの目的を記載する。",
        )
        review = ReviewResult(
            summary="",
            provider="mock",
            prompt_preview="",
            issues=[
                ReviewIssue(
                    severity="medium",
                    title="運用監視方針の不足",
                    details="アラート発報後の判断基準が不足しています。",
                    recommendation="一次対応者とエスカレーション条件を定義してください。",
                    source_document="overview.txt",
                    section="第1章 概要",
                )
            ],
        )

        report = build_future_review_report([doc], review)

        scenario = next(
            item for item in report.premortem_scenarios
            if item.scenario_id == "PM-002"
        )
        self.assertEqual(scenario.trigger_source, "issue")
        self.assertIn("一次対応", scenario.missing_elements)
        self.assertIn("運用監視方針の不足", scenario.review_hint)


if __name__ == "__main__":
    unittest.main()
