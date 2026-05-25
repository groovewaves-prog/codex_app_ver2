from __future__ import annotations

import unittest

from secure_review.models import SanitizationRecord, SanitizedDocument
from secure_review.ui_viewmodel import (
    document_attention_reasons,
    remediation_origin_badge,
    sort_documents_by_attention,
    structure_fix_guidance,
)


def _doc(
    name: str,
    *,
    decision: str = "safe",
    risk: str = "low",
    replacements: int = 0,
    tokens: int = 100,
) -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt="text",
        sanitized_excerpt="text",
        outbound_text="text",
        replacements=[
            SanitizationRecord(
                placeholder=f"[SITE_{index:03d}]",
                original=f"site-{index}",
                category="site",
            )
            for index in range(1, replacements + 1)
        ],
        estimated_input_tokens=tokens,
        outbound_risk=risk,
        local_sensitivity_decision=decision,
    )


class UiViewmodelTests(unittest.TestCase):
    def test_documents_with_attention_sort_before_safe_documents(self) -> None:
        docs = [
            _doc("safe.pdf"),
            _doc("masked.pdf", replacements=2),
            _doc("unknown.pdf", decision="unknown"),
            _doc("blocked.pdf", decision="block"),
        ]

        sorted_docs = sort_documents_by_attention(docs)

        self.assertEqual(
            [doc.name for doc in sorted_docs],
            ["blocked.pdf", "unknown.pdf", "masked.pdf", "safe.pdf"],
        )

    def test_attention_reasons_include_uncertain_candidates(self) -> None:
        doc = _doc("a.pdf", replacements=1)

        reasons = document_attention_reasons(doc, has_uncertain_candidates=True)

        self.assertIn("未確定マスク候補あり", reasons)
        self.assertIn("置換 1 件", reasons)

    def test_structure_fix_guidance_is_author_facing(self) -> None:
        guidance = structure_fix_guidance(
            "required_item_gap",
            item_name="本書の目的",
            chapter_name="はじめに",
        )

        self.assertIn("本書の目的", guidance)
        self.assertIn("追記", guidance)

    def test_remediation_origin_badge_for_document_deep_dive(self) -> None:
        badge = remediation_origin_badge("document_deep_dive")

        self.assertIsNotNone(badge)
        self.assertIn("文書深堀で追加", badge[0])
        self.assertEqual(badge[1], "origin-badge-document-deep-dive")

    def test_remediation_origin_badge_for_chapter_deep_dive(self) -> None:
        badge = remediation_origin_badge("chapter_deep_dive")

        self.assertIsNotNone(badge)
        self.assertIn("章深堀で追加", badge[0])
        self.assertEqual(badge[1], "origin-badge-chapter-deep-dive")

    def test_remediation_origin_badge_is_hidden_for_initial(self) -> None:
        self.assertIsNone(remediation_origin_badge("initial"))


if __name__ == "__main__":
    unittest.main()
