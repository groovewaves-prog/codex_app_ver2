from __future__ import annotations

import unittest
from unittest.mock import patch

from secure_review.models import SanitizedDocument
from secure_review.token_budget import estimate_review_token_budget


def _doc(name: str, text: str) -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt=text[:100],
        sanitized_excerpt=text[:100],
        outbound_text=text,
        estimated_input_tokens=max(1, len(text) // 4),
        local_sensitivity_decision="safe",
    )


class TokenBudgetTests(unittest.TestCase):
    def test_mock_provider_reports_no_external_consumption(self) -> None:
        with patch.dict("os.environ", {"REVIEW_PROVIDER": "mock"}, clear=True):
            estimate = estimate_review_token_budget([_doc("a.txt", "目的\n本文")])

        self.assertEqual(estimate.status, "mock")
        self.assertEqual(estimate.call_count, 1)
        self.assertIn("外部LLMトークンは消費しません", estimate.reasons[0])

    def test_gemma_multiple_documents_uses_chunked_estimate(self) -> None:
        docs = [
            _doc("a.docx", "第 1 章 はじめに\n目的\n" * 100),
            _doc("b.docx", "第 2 章 手順\n作業\n" * 100),
        ]
        with patch.dict(
            "os.environ",
            {
                "REVIEW_PROVIDER": "gemma",
                "GEMINI_CHUNKING": "true",
                "GEMINI_MAX_OUTPUT_TOKENS": "4096",
            },
            clear=True,
        ):
            estimate = estimate_review_token_budget(docs)

        self.assertEqual(estimate.review_mode, "chunked")
        self.assertEqual(estimate.call_count, 2)
        self.assertEqual(estimate.max_output_tokens_per_call, 4096)
        self.assertGreater(estimate.total_input_tokens, estimate.body_tokens)


if __name__ == "__main__":
    unittest.main()
