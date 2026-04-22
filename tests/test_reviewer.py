import os
import unittest
from unittest.mock import patch

from secure_review.models import SanitizedDocument
from secure_review.reviewer import (
    GeminiFreeTierProvider,
    GeminiHostedGemmaProvider,
    MockReviewProvider,
    build_prompt,
    choose_provider,
)
from secure_review.rubric import choose_rubric, classify_documents


class ReviewerTests(unittest.TestCase):
    def test_mock_reviewer_detects_basic_risks(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [
                SanitizedDocument(
                    name="sw1.cfg",
                    original_excerpt="",
                    sanitized_excerpt="line vty 0 4\n transport input telnet\nsnmp-server community [SECRET_001] RO",
                    outbound_text="line vty 0 4\n transport input telnet\nsnmp-server community [SECRET_001] RO",
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=32,
                    outbound_risk="low",
                )
            ]
        )

        titles = {issue.title for issue in result.issues}
        self.assertIn("Telnet usage detected", titles)
        self.assertIn("SNMP community string usage", titles)

    def test_mock_reviewer_checks_purpose_configuration_and_timechart(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [
                SanitizedDocument(
                    name="change_runbook.md",
                    original_excerpt="",
                    sanitized_excerpt="change runbook",
                    outbound_text="change procedure\n1. start work\n2. health check",
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=16,
                    outbound_risk="low",
                )
            ]
        )

        titles = {issue.title for issue in result.issues}
        self.assertIn("冒頭の目的記載が不明確", titles)
        self.assertIn("構成情報の存在が確認できない", titles)
        self.assertIn("タイムチャートの記載または別紙参照が不足", titles)
        self.assertEqual(result.document_profile, "change_runbook")

    def test_mock_reviewer_detects_source_code_risks(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [
                SanitizedDocument(
                    name="job.py",
                    original_excerpt="",
                    sanitized_excerpt="import os",
                    outbound_text=(
                        "import os\n"
                        "password = 'secret123'\n"
                        "os.system(user_input)\n"
                        "try:\n"
                        "    run_job()\n"
                        "except:\n"
                        "    pass\n"
                    ),
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=40,
                    outbound_risk="low",
                )
            ]
        )

        titles = {issue.title for issue in result.issues}
        self.assertIn("ハードコードされた認証情報の疑い", titles)
        self.assertIn("危険なコマンド実行の可能性", titles)
        self.assertIn("例外処理が広すぎる可能性", titles)
        self.assertEqual(result.document_profile, "source_code")

    @patch.dict(os.environ, {"REVIEW_PROVIDER": "gemini-free"}, clear=False)
    def test_choose_provider_returns_gemini_provider(self) -> None:
        provider = choose_provider()
        self.assertIsInstance(provider, GeminiFreeTierProvider)

    @patch.dict(os.environ, {"REVIEW_PROVIDER": "gemma4"}, clear=False)
    def test_choose_provider_returns_gemma_provider(self) -> None:
        provider = choose_provider()
        self.assertIsInstance(provider, GeminiHostedGemmaProvider)

    @patch.dict(os.environ, {}, clear=True)
    def test_gemini_provider_requires_api_key(self) -> None:
        provider = GeminiHostedGemmaProvider()
        with self.assertRaises(ValueError):
            provider.review([])

    @patch.dict(os.environ, {"GEMINI_API_KEY": "dummy"}, clear=True)
    def test_gemma_provider_defaults_to_gemma_4_model(self) -> None:
        provider = GeminiHostedGemmaProvider()
        self.assertEqual(provider.model, "gemma-4-31b-it")

    def test_choose_rubric_detects_design_profile(self) -> None:
        rubric = choose_rubric(
            [
                SanitizedDocument(
                    name="basic_design.docx",
                    original_excerpt="",
                    sanitized_excerpt="purpose\nnetwork diagram",
                    outbound_text="purpose\nnetwork diagram\ntest items",
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=20,
                    outbound_risk="low",
                )
            ]
        )
        self.assertEqual(rubric.document_profile, "design")

    def test_choose_rubric_detects_source_code_profile(self) -> None:
        rubric = choose_rubric(
            [
                SanitizedDocument(
                    name="cleanup.ps1",
                    original_excerpt="",
                    sanitized_excerpt="function Invoke-Cleanup {}",
                    outbound_text="function Invoke-Cleanup { param($Target) Remove-Item $Target -Recurse }",
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=20,
                    outbound_risk="low",
                )
            ]
        )
        self.assertEqual(rubric.document_profile, "source_code")

    def test_unknown_extension_can_be_classified_as_source_code(self) -> None:
        classification = classify_documents(
            [
                SanitizedDocument(
                    name="deploy.custom",
                    original_excerpt="",
                    sanitized_excerpt="function Deploy-App {}",
                    outbound_text=(
                        "function Deploy-App {\n"
                        "  param($Target)\n"
                        "  Write-Host $Target\n"
                        "}\n"
                    ),
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=18,
                    outbound_risk="low",
                )
            ]
        )
        self.assertEqual(classification.document_profile, "source_code")
        self.assertIn(classification.confidence, {"medium", "high"})

    def test_provider_can_use_document_profile_override(self) -> None:
        provider = MockReviewProvider()
        result = provider.review(
            [
                SanitizedDocument(
                    name="notes.txt",
                    original_excerpt="",
                    sanitized_excerpt="generic text",
                    outbound_text="generic text without strong markers",
                    replacements=[],
                    findings=[],
                    estimated_input_tokens=8,
                    outbound_risk="low",
                )
            ],
            document_profile_override="source_code",
        )
        self.assertEqual(result.document_profile, "source_code")
        self.assertEqual(result.classification_confidence, "forced")

    def test_build_prompt_includes_rubric_requirements(self) -> None:
        document = SanitizedDocument(
            name="operations.md",
            original_excerpt="",
            sanitized_excerpt="operations runbook",
            outbound_text="operations runbook\nmonitoring items\nescalation",
            replacements=[],
            findings=[],
            estimated_input_tokens=12,
            outbound_risk="low",
        )
        prompt = build_prompt([document])
        self.assertIn("Mandatory checks:", prompt)
        self.assertIn("Evaluation axes:", prompt)
        self.assertIn("Document Profile:", prompt)


if __name__ == "__main__":
    unittest.main()
