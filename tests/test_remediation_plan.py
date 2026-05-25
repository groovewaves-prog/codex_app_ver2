from __future__ import annotations

import unittest

from secure_review.models import ReviewIssue, ReviewResult, SanitizedDocument
from secure_review.remediation_plan import (
    RemediationItem,
    build_remediation_plan,
    compare_remediation_plan_to_documents,
    remediation_plan_from_dict,
)
from secure_review.structure_check import StructureCheckResult, StructureFinding


class RemediationPlanTests(unittest.TestCase):
    def _sample_item(self, **overrides) -> RemediationItem:
        values = {
            "item_id": "D-001",
            "source_type": "review_issue",
            "severity": "high",
            "title": "DR設計の未定義",
            "target_document": "design.pdf",
            "target_section": "第8章 可用性",
            "problem": "RPO/RTOがない",
            "fix_policy": "RPO/RTOと切替手順を追記する。",
            "template": "RPO RTO 切替手順 バックアップ リージョン",
            "re_review_scope": "design.pdf / 第8章 可用性",
            "re_review_condition": "高重要度指摘が解消したか確認してください。",
            "effort": "大",
        }
        values.update(overrides)
        return RemediationItem(**values)

    def test_remediation_item_origin_defaults_to_initial(self) -> None:
        item = self._sample_item()

        self.assertEqual(item.origin, "initial")

    def test_remediation_item_origin_can_be_set_explicitly(self) -> None:
        item = self._sample_item(origin="document_deep_dive")

        self.assertEqual(item.origin, "document_deep_dive")

    def test_remediation_item_origin_round_trips_through_saved_plan(self) -> None:
        item = self._sample_item(origin="document_deep_dive")
        payload = {
            "headline": "前回の修正計画",
            "summary": "summary",
            "items": [item.to_dict()],
        }

        plan = remediation_plan_from_dict(payload)

        self.assertEqual(plan.items[0].origin, "document_deep_dive")

    def test_saved_plan_without_origin_loads_as_initial(self) -> None:
        payload = {
            "headline": "前回の修正計画",
            "summary": "summary",
            "items": [
                {
                    "item_id": "D-001",
                    "source_type": "review_issue",
                    "severity": "high",
                    "title": "DR設計の未定義",
                    "target_document": "design.pdf",
                    "target_section": "第8章 可用性",
                    "problem": "RPO/RTOがない",
                    "fix_policy": "RPO/RTOと切替手順を追記する。",
                    "template": "RPO RTO 切替手順 バックアップ リージョン",
                    "re_review_scope": "design.pdf / 第8章 可用性",
                    "re_review_condition": "高重要度指摘が解消したか確認してください。",
                    "effort": "大",
                }
            ],
        }

        plan = remediation_plan_from_dict(payload)

        self.assertEqual(plan.items[0].origin, "initial")

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
        self.assertIn("DR設計の未定義", plan.items[0].re_review_condition)
        self.assertIn("第8章 可用性", plan.items[0].re_review_condition)
        self.assertEqual(plan.re_review_steps[0].label, "必須再レビュー")

    def test_review_issue_origin_propagates_to_remediation_item(self) -> None:
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
                    origin="document_deep_dive",
                )
            ],
            provider="mock",
            prompt_preview="",
        )

        plan = build_remediation_plan(review)

        self.assertEqual(plan.items[0].origin, "document_deep_dive")

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
        self.assertIn("不足観点", plan.items[0].re_review_condition)

    def test_empty_plan_still_has_completion_step(self) -> None:
        review = ReviewResult(summary="ok", issues=[], provider="mock", prompt_preview="")

        plan = build_remediation_plan(review)

        self.assertFalse(plan.items)
        self.assertEqual(plan.headline, "大きな修正アクションはありません")
        self.assertEqual(plan.re_review_steps[0].label, "軽微確認")

    def test_saved_plan_can_be_loaded_and_compared_to_revised_document(self) -> None:
        payload = {
            "headline": "前回の修正計画",
            "summary": "summary",
            "items": [
                {
                    "item_id": "D-001",
                    "source_type": "review_issue",
                    "severity": "high",
                    "title": "DR設計の未定義",
                    "target_document": "design.pdf",
                    "target_section": "第8章 可用性",
                    "problem": "RPO/RTOがない",
                    "fix_policy": "RPO/RTOと切替手順を追記する。",
                    "template": "RPO RTO 切替手順 バックアップ リージョン",
                    "re_review_scope": "design.pdf / 第8章 可用性",
                    "re_review_condition": "高重要度指摘が解消したか確認してください。",
                    "effort": "大",
                }
            ],
        }
        plan = remediation_plan_from_dict(payload)
        revised = SanitizedDocument(
            name="design.pdf",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第8章 可用性\nRPO/RTO、切替手順、バックアップ、リージョン冗長化を追記した。",
        )

        report = compare_remediation_plan_to_documents(plan, [revised])

        self.assertEqual(report.total_count, 1)
        self.assertEqual(report.items[0].status, "improved")
        self.assertIn("RPO", report.items[0].evidence)


if __name__ == "__main__":
    unittest.main()
