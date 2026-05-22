from __future__ import annotations

import unittest

from secure_review.agent_planner import (
    build_operation_guide,
    build_review_agent_brief,
    build_review_display_policy,
)
from secure_review.models import SanitizedDocument


def _doc(
    name: str = "design.xlsx",
    *,
    decision: str = "safe",
    risk: str = "low",
    text: str = "本文",
) -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt=text,
        sanitized_excerpt=text,
        outbound_text=text,
        local_sensitivity_decision=decision,
        outbound_risk=risk,
    )


class AgentPlannerTests(unittest.TestCase):
    def test_empty_state_waits_for_upload(self) -> None:
        brief = build_review_agent_brief([], blocked_count=0, confirmation_count=0, send_approved=False)
        self.assertEqual(brief.mode, "待機")
        self.assertIn("アップロード", brief.next_action)

    def test_blocked_documents_stop_external_send(self) -> None:
        brief = build_review_agent_brief(
            [_doc(decision="block", risk="high")],
            blocked_count=1,
            confirmation_count=0,
            send_approved=False,
        )
        self.assertEqual(brief.mode, "停止判断")
        self.assertIn("外部送信", brief.mission)
        self.assertEqual(brief.stages[2].tone, "block")

    def test_excel_diagnostics_are_monitored(self) -> None:
        brief = build_review_agent_brief(
            [_doc(text="# Excelブック診断\n- シート数: 1\n# Sheet: A\nvalue")],
            blocked_count=0,
            confirmation_count=0,
            send_approved=True,
            token_status="safe",
        )
        self.assertEqual(brief.mode, "実行準備")
        self.assertIn("Excel診断: 1 件", brief.monitors)

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
        self.assertIn("必要なときだけ", guide.primary_action)

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
        self.assertIn("先に対応", policy.headline)
        self.assertIn("修正計画カード", policy.show_now)
        self.assertIn("品質改善ヒント", policy.keep_collapsed)
        self.assertFalse(policy.expand_quality_hints)

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
        self.assertNotIn("品質改善ヒント", policy.keep_collapsed)


if __name__ == "__main__":
    unittest.main()
