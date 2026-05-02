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

from secure_review.models import (
    LookupResult,
    MaskingPipelineState,
    NerCandidate,
    ReviewIssue,
    ReviewResult,
    ReviewSummary,
    SanitizedDocument,
)


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


class NerCandidateTests(unittest.TestCase):
    """R-M Phase 1: NerCandidate dataclass の基本契約。"""

    def test_seed_dict_candidate_is_confirmed(self) -> None:
        c = NerCandidate(
            text="KDDI",
            label="COMPANY",
            spacy_label="ORG",
            start=0,
            end=4,
            source="seed_dict",
            confirmed=True,
        )
        self.assertTrue(c.confirmed)
        self.assertEqual(c.source, "seed_dict")

    def test_to_dict_contains_all_fields(self) -> None:
        c = NerCandidate(
            text="アイレット",
            label="COMPANY",
            spacy_label="ORG",
            start=10,
            end=15,
            source="spacy_ner",
            confirmed=False,
        )
        d = c.to_dict()
        for key in ("text", "label", "spacy_label", "start", "end", "source", "confirmed"):
            self.assertIn(key, d)
        self.assertEqual(d["confirmed"], False)
        self.assertEqual(d["spacy_label"], "ORG")


class LookupResultTests(unittest.TestCase):
    """R-M Phase 2: gBizINFO 検索結果の基本契約。"""

    def test_default_fields(self) -> None:
        r = LookupResult(candidate_text="アイレット", hits=0)
        self.assertEqual(r.top_names, [])
        self.assertEqual(r.error, "")
        self.assertFalse(r.cached)

    def test_error_result_has_message(self) -> None:
        r = LookupResult(
            candidate_text="X", hits=0, error="timeout"
        )
        self.assertEqual(r.error, "timeout")
        self.assertEqual(r.hits, 0)

    def test_to_dict_contains_all_fields(self) -> None:
        r = LookupResult(
            candidate_text="アイレット",
            hits=16,
            top_names=["株式会社アイレット", "KDDIアイレット株式会社"],
            cached=True,
        )
        d = r.to_dict()
        self.assertEqual(d["candidate_text"], "アイレット")
        self.assertEqual(d["hits"], 16)
        self.assertEqual(len(d["top_names"]), 2)
        self.assertTrue(d["cached"])


class MaskingPipelineStateTests(unittest.TestCase):
    """R-M: パイプライン中間状態の基本契約。

    apply_user_decisions() の入力としての形を保証する。
    """

    def _make_sanitized(self) -> SanitizedDocument:
        return SanitizedDocument(
            name="x.txt",
            original_excerpt="orig",
            sanitized_excerpt="sani",
            outbound_text="sani",
        )

    def test_minimal_state_has_no_uncertain(self) -> None:
        """シード辞書のみで全マスクが確定したケース。
        確認 UI を出してはならないので has_uncertain は False。
        """
        s = MaskingPipelineState(
            name="x.txt",
            sanitized=self._make_sanitized(),
        )
        self.assertFalse(s.has_uncertain)
        self.assertEqual(s.confirmed_findings, [])
        self.assertEqual(s.uncertain_candidates, [])
        self.assertEqual(s.lookups, {})

    def test_has_uncertain_is_true_when_candidates_exist(self) -> None:
        candidate = NerCandidate(
            text="サンプル",
            label="COMPANY",
            spacy_label="ORG",
            start=0,
            end=4,
            source="spacy_ner",
            confirmed=False,
        )
        s = MaskingPipelineState(
            name="x.txt",
            sanitized=self._make_sanitized(),
            uncertain_candidates=[candidate],
        )
        self.assertTrue(s.has_uncertain)

    def test_to_dict_normalizes_tuples_and_nested_types(self) -> None:
        candidate = NerCandidate(
            text="アイレット",
            label="COMPANY",
            spacy_label="ORG",
            start=0,
            end=5,
            source="spacy_ner",
            confirmed=False,
        )
        lookup = LookupResult(candidate_text="アイレット", hits=16)
        s = MaskingPipelineState(
            name="x.txt",
            sanitized=self._make_sanitized(),
            confirmed_findings=[("KDDI", "COMPANY")],
            uncertain_candidates=[candidate],
            lookups={"アイレット": lookup},
        )
        d = s.to_dict()
        # confirmed_findings の tuple は list に正規化される
        self.assertEqual(d["confirmed_findings"], [["KDDI", "COMPANY"]])
        # nested 型も dict 化される
        self.assertIsInstance(d["uncertain_candidates"][0], dict)
        self.assertIsInstance(d["lookups"]["アイレット"], dict)
        self.assertIsInstance(d["sanitized"], dict)


if __name__ == "__main__":
    unittest.main()
