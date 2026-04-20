import os
import unittest
from unittest.mock import patch

from secure_review.models import SanitizedDocument
from secure_review.reviewer import GeminiFreeTierProvider, MockReviewProvider, choose_provider


class ReviewerTests(unittest.TestCase):
    def test_mock_reviewer_detects_basic_risks(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [
                SanitizedDocument(
                    name="sw1.cfg",
                    original_excerpt="",
                    sanitized_excerpt="line vty 0 4\n transport input telnet\nsnmp-server community [SECRET_001] RO",
                    replacements=[],
                    findings=[],
                )
            ]
        )

        titles = {issue.title for issue in result.issues}
        self.assertIn("Telnet usage detected", titles)
        self.assertIn("SNMP community string usage", titles)

    @patch.dict(os.environ, {"REVIEW_PROVIDER": "gemini-free"}, clear=False)
    def test_choose_provider_returns_gemini_provider(self) -> None:
        provider = choose_provider()
        self.assertIsInstance(provider, GeminiFreeTierProvider)

    @patch.dict(os.environ, {}, clear=True)
    def test_gemini_provider_requires_api_key(self) -> None:
        provider = GeminiFreeTierProvider()
        with self.assertRaises(ValueError):
            provider.review([])


if __name__ == "__main__":
    unittest.main()
