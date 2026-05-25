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

    def _issue(self, **overrides) -> ReviewIssue:
        values = {
            "severity": "high",
            "title": "DR設計の未定義",
            "details": "RPO/RTOがない",
            "recommendation": "RPO/RTOと切替手順を追記する。",
            "source_document": "design.pdf",
            "issue_id": "D-001",
            "section": "第8章 可用性",
        }
        values.update(overrides)
        return ReviewIssue(**values)

    def _review_with_issues(self, *issues: ReviewIssue) -> ReviewResult:
        return ReviewResult(
            summary="summary",
            issues=list(issues),
            provider="mock",
            prompt_preview="",
        )

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
        review = self._review_with_issues(
            self._issue(origin="document_deep_dive")
        )

        plan = build_remediation_plan(review)

        self.assertEqual(plan.items[0].origin, "document_deep_dive")

    def test_initial_review_issues_build_initial_origin_items(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001"),
            self._issue(
                issue_id="D-002",
                severity="medium",
                title="運用体制の未整理",
                section="第10章 運用",
            ),
        )

        plan = build_remediation_plan(review)

        self.assertTrue(plan.items)
        self.assertTrue(all(item.origin == "initial" for item in plan.items))

    def test_document_deep_dive_origin_is_preserved_in_mixed_plan(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", title="初回指摘"),
            self._issue(
                issue_id="DD-001",
                title="文書深堀指摘",
                origin="document_deep_dive",
            ),
        )

        plan = build_remediation_plan(review)

        origins_by_title = {item.title: item.origin for item in plan.items}
        self.assertEqual(origins_by_title["初回指摘"], "initial")
        self.assertEqual(origins_by_title["文書深堀指摘"], "document_deep_dive")

    def test_chapter_deep_dive_origin_is_preserved_in_mixed_plan(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", title="初回指摘"),
            self._issue(
                issue_id="CD-001",
                title="章深堀指摘",
                origin="chapter_deep_dive",
            ),
        )

        plan = build_remediation_plan(review)

        origins_by_title = {item.title: item.origin for item in plan.items}
        self.assertEqual(origins_by_title["初回指摘"], "initial")
        self.assertEqual(origins_by_title["章深堀指摘"], "chapter_deep_dive")

    def test_dedup_does_not_include_origin_in_key(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", origin="initial"),
            self._issue(issue_id="DD-001", origin="document_deep_dive"),
        )

        plan = build_remediation_plan(review)

        self.assertEqual(len(plan.items), 1)
        self.assertEqual(plan.items[0].origin, "initial")

    def test_build_remediation_plan_is_idempotent_for_same_review_result(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", title="初回指摘"),
            self._issue(
                issue_id="CD-001",
                title="章深堀指摘",
                origin="chapter_deep_dive",
            ),
        )

        first = build_remediation_plan(review)
        second = build_remediation_plan(review)

        self.assertEqual(first.to_dict(), second.to_dict())

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
