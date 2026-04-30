"""Tests for the R-L (B0) data-model additions.

Covers:
- ReviewSummary class (new in B0): default empty, populated, is_empty(), to_dict()
- ReviewIssue extension (new optional fields): defaults, has_structured_fields()
- ReviewResult.summary_structured: default, populated, to_dict()

These tests guard the backward-compatibility contract: existing callers
that use only the legacy ``summary: str`` and minimal ReviewIssue fields
must continue to work.
"""
from __future__ import annotations

import unittest

from secure_review.models import ReviewIssue, ReviewResult, ReviewSummary


class ReviewSummaryTests(unittest.TestCase):
    def test_default_summary_is_empty(self) -> None:
        s = ReviewSummary()
        self.assertEqual(s.purpose, "")
        self.assertEqual(s.verdict, "")
        self.assertTrue(s.is_empty())

    def test_populated_summary_is_not_empty(self) -> None:
        s = ReviewSummary(verdict="C")
        self.assertFalse(s.is_empty())

    def test_summary_to_dict_contains_all_fields(self) -> None:
        s = ReviewSummary(purpose="目的", verdict="A")
        d = s.to_dict()
        self.assertIn("purpose", d)
        self.assertIn("verdict", d)
        self.assertIn("purpose_section_in_document", d)
        self.assertIn("purpose_divergence", d)
        self.assertIn("content_outline", d)
        self.assertIn("overall_evaluation", d)
        self.assertEqual(d["verdict"], "A")


class ReviewIssueExtensionTests(unittest.TestCase):
    def test_legacy_issue_has_no_structured_fields(self) -> None:
        """An issue built with only the original 5 fields must report
        has_structured_fields()=False, so UI fallback paths kick in."""
        i = ReviewIssue(
            severity="high",
            title="t",
            details="d",
            recommendation="r",
            source_document="x.pdf",
        )
        self.assertFalse(i.has_structured_fields())
        self.assertEqual(i.issue_id, "")
        self.assertFalse(i.re_review_required)

    def test_extended_issue_has_structured_fields(self) -> None:
        i = ReviewIssue(
            severity="medium",
            title="t",
            details="d",
            recommendation="r",
            source_document="x.pdf",
            issue_id="D-001",
            current_state="...",
            re_review_required=True,
        )
        self.assertTrue(i.has_structured_fields())


class ReviewResultBackwardCompatTests(unittest.TestCase):
    def test_default_summary_structured_is_empty(self) -> None:
        """Existing callers that don't set summary_structured must get
        an empty ReviewSummary by default (not None)."""
        r = ReviewResult(
            summary="legacy", issues=[], provider="x", prompt_preview=""
        )
        self.assertIsInstance(r.summary_structured, ReviewSummary)
        self.assertTrue(r.summary_structured.is_empty())

    def test_to_dict_includes_summary_structured(self) -> None:
        r = ReviewResult(
            summary="legacy",
            issues=[],
            provider="x",
            prompt_preview="",
            summary_structured=ReviewSummary(verdict="B"),
        )
        d = r.to_dict()
        self.assertIn("summary_structured", d)
        self.assertEqual(d["summary_structured"]["verdict"], "B")
        # legacy ``summary`` field is preserved
        self.assertEqual(d["summary"], "legacy")


if __name__ == "__main__":
    unittest.main()
