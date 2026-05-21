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
        self.assertEqual(estimate.minimum_wait_seconds, 0)
        self.assertEqual([item.name for item in estimate.document_estimates], ["a.docx", "b.docx"])
        self.assertGreater(estimate.total_input_tokens, estimate.body_tokens)

    def test_chunking_interval_surfaces_minimum_wait_time(self) -> None:
        docs = [
            _doc("01.pdf", "本文\n" * 100),
            _doc("02.pdf", "本文\n" * 100),
            _doc("03.pdf", "本文\n" * 100),
        ]
        with patch.dict(
            "os.environ",
            {
                "REVIEW_PROVIDER": "gemma",
                "GEMINI_CHUNKING": "true",
                "GEMINI_CHUNKING_INTERVAL": "6",
            },
            clear=True,
        ):
            estimate = estimate_review_token_budget(docs)

        self.assertEqual(estimate.call_count, 3)
        self.assertEqual(estimate.throttle_interval_seconds, 6)
        self.assertEqual(estimate.minimum_wait_seconds, 12)

    def test_large_multi_file_review_suggests_batches(self) -> None:
        docs = [
            _doc(f"{idx:02d}.pdf", "本文\n" * 800)
            for idx in range(1, 10)
        ]
        with patch.dict(
            "os.environ",
            {
                "REVIEW_PROVIDER": "gemma",
                "GEMINI_CHUNKING": "true",
            },
            clear=True,
        ):
            estimate = estimate_review_token_budget(docs)

        self.assertGreaterEqual(len(estimate.suggested_batches), 2)
        suggested_names = [
            name
            for batch in estimate.suggested_batches
            for name in batch.document_names
        ]
        self.assertEqual(suggested_names, [doc.name for doc in docs])


if __name__ == "__main__":
    unittest.main()
