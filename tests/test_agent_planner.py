from __future__ import annotations

import unittest

from secure_review.agent_planner import (
    build_operation_guide,
    build_review_display_policy,
)


class AgentPlannerTests(unittest.TestCase):
    def test_operation_guide_points_to_upload_first(self) -> None:
        guide = build_operation_guide(
            upload_count=0,
            has_preview_docs=False,
            blocked_count=0,
            confirmation_count=0,
            send_approved=False,
        )
        self.assertEqual(guide.step_label, "ステップ 1 / 文書アップロード")
        self.assertIn("ファイルを選択", guide.primary_action)

    def test_operation_guide_blocks_when_send_is_unsafe(self) -> None:
        guide = build_operation_guide(
            upload_count=1,
            has_preview_docs=True,
            blocked_count=1,
            confirmation_count=0,
            send_approved=False,
        )
        self.assertEqual(guide.tone, "block")
        self.assertIn("送信禁止", guide.done_when)

    def test_operation_guide_requires_final_approval_before_send(self) -> None:
        guide = build_operation_guide(
            upload_count=1,
            has_preview_docs=True,
            blocked_count=0,
            confirmation_count=0,
            send_approved=False,
            token_status="safe",
        )
        self.assertEqual(guide.step_label, "ステップ 3 / 最終承認")
        self.assertIn("最終承認", guide.primary_action)

    def test_operation_guide_review_done_focuses_on_remediation_plan(self) -> None:
        guide = build_operation_guide(
            upload_count=1,
            has_preview_docs=True,
            blocked_count=0,
            confirmation_count=0,
            send_approved=True,
            review_done=True,
        )

        self.assertEqual(guide.step_label, "ステップ 4 / レビュー結果確認")
        self.assertIn("修正計画カード", guide.primary_action)
        self.assertIn("監査・追加確認", guide.primary_action)
        self.assertNotIn("必要なときだけ", guide.primary_action)

    def test_display_policy_prioritizes_high_remediation_items(self) -> None:
        policy = build_review_display_policy(
            remediation_count=3,
            high_count=2,
            medium_count=1,
            structure_finding_count=1,
            future_hint_count=4,
            deep_candidate_count=2,
        )

        self.assertEqual(policy.tone, "block")
        self.assertEqual(policy.headline, "まず赤い修正計画カードを確認してください")
        self.assertNotIn("AI判断:", policy.headline)
        self.assertIn("修正計画カード", policy.show_now)
        self.assertIn("障害シナリオと予防策", policy.keep_collapsed)
        self.assertIn("元のレビュー指摘", policy.keep_collapsed)
        self.assertNotIn("証跡エクスポート", policy.keep_collapsed)
        self.assertFalse(policy.expand_quality_hints)

    def test_display_policy_medium_only_uses_yellow_card_headline(self) -> None:
        policy = build_review_display_policy(
            remediation_count=2,
            high_count=0,
            medium_count=2,
            structure_finding_count=0,
            future_hint_count=0,
            deep_candidate_count=0,
        )

        self.assertEqual(policy.tone, "warn")
        self.assertEqual(policy.headline, "黄色の修正計画カードから確認してください")
        self.assertNotIn("AI判断:", policy.headline)

    def test_display_policy_low_only_uses_sequential_card_headline(self) -> None:
        policy = build_review_display_policy(
            remediation_count=1,
            high_count=0,
            medium_count=0,
            structure_finding_count=0,
            future_hint_count=0,
            deep_candidate_count=0,
        )

        self.assertEqual(policy.tone, "success")
        self.assertEqual(policy.headline, "修正計画カードを順に確認してください")
        self.assertNotIn("AI判断:", policy.headline)

    def test_display_policy_no_cards_points_to_structure_check(self) -> None:
        policy = build_review_display_policy(
            remediation_count=0,
            high_count=0,
            medium_count=0,
            structure_finding_count=2,
            future_hint_count=0,
            deep_candidate_count=0,
        )

        self.assertEqual(policy.headline, "文書構成チェックの結果を確認してください")
        self.assertNotIn("AI判断:", policy.headline)

    def test_display_policy_audit_export_is_developer_only(self) -> None:
        normal = build_review_display_policy(
            remediation_count=1,
            high_count=1,
            medium_count=0,
            structure_finding_count=0,
            future_hint_count=0,
            deep_candidate_count=0,
            developer_mode=False,
        )
        developer = build_review_display_policy(
            remediation_count=1,
            high_count=1,
            medium_count=0,
            structure_finding_count=0,
            future_hint_count=0,
            deep_candidate_count=0,
            developer_mode=True,
        )

        self.assertNotIn("証跡エクスポート", normal.keep_collapsed)
        self.assertNotIn("証跡エクスポート", normal.developer_only)
        self.assertIn("証跡エクスポート", developer.developer_only)

    def test_display_policy_expands_quality_hints_when_no_remediation(self) -> None:
        policy = build_review_display_policy(
            remediation_count=0,
            high_count=0,
            medium_count=0,
            structure_finding_count=0,
            future_hint_count=2,
            deep_candidate_count=0,
        )

        self.assertEqual(policy.tone, "info")
        self.assertTrue(policy.expand_quality_hints)
        self.assertNotIn("障害シナリオと予防策", policy.keep_collapsed)


if __name__ == "__main__":
    unittest.main()
