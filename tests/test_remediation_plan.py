from __future__ import annotations

import unittest

from secure_review.models import ReviewIssue, ReviewResult
from secure_review.remediation_plan import build_remediation_plan
from secure_review.structure_check import StructureCheckResult, StructureFinding


class RemediationPlanTests(unittest.TestCase):
    def test_builds_plan_from_high_review_issue(self) -> None:
        review = ReviewResult(
            summary="summary",
            issues=[
                ReviewIssue(
                    severity="high",
                    title="DR設計の未定義",
                    details="RPO/RTOがない",
                    recommendation="RPO/RTOと切替手順を追記する。",
                    source_document="design.pdf",
                    issue_id="D-001",
                    section="第8章 可用性",
                    current_state="バックアップの記載のみ。",
                    issue="復旧目標が未定義。",
                    impact="災害時の判断が遅れる。",
                    re_review_required=True,
                )
            ],
            provider="mock",
            prompt_preview="",
        )

        plan = build_remediation_plan(review)

        self.assertEqual(plan.high_count, 1)
        self.assertEqual(plan.items[0].item_id, "D-001")
        self.assertIn("RPO/RTO", plan.items[0].fix_policy)
        self.assertIn("第8章 可用性", plan.items[0].template)
        self.assertEqual(plan.re_review_steps[0].label, "必須再レビュー")

    def test_structure_findings_become_templates(self) -> None:
        review = ReviewResult(
            summary="summary",
            issues=[],
            provider="mock",
            prompt_preview="",
        )
        structure = StructureCheckResult(
            document_profile="design",
            document_count=1,
            detected_chapter_count=2,
            findings=(
                StructureFinding(
                    kind="missing_chapter",
                    severity="high",
                    message="運用設計が見当たりません。",
                    chapter_id="ch11",
                    chapter_name="運用設計",
                    expected_content="監視・アラート・バックアップ",
                ),
            ),
        )

        plan = build_remediation_plan(review, structure)

        self.assertEqual(plan.high_count, 1)
        self.assertEqual(plan.items[0].source_type, "structure_check")
        self.assertIn("運用設計", plan.items[0].title)
        self.assertIn("## 運用設計", plan.items[0].template)

    def test_empty_plan_still_has_completion_step(self) -> None:
        review = ReviewResult(summary="ok", issues=[], provider="mock", prompt_preview="")

        plan = build_remediation_plan(review)

        self.assertFalse(plan.items)
        self.assertEqual(plan.headline, "大きな修正アクションはありません")
        self.assertEqual(plan.re_review_steps[0].label, "軽微確認")


if __name__ == "__main__":
    unittest.main()
