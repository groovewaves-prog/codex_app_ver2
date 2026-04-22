import json
import os
import unittest
from unittest.mock import patch

from secure_review.models import SanitizedDocument
from secure_review.sensitivity import (
    HeuristicSensitivityClassifier,
    choose_sensitivity_classifier,
    _parse_sensitivity_assessment,
)


class SensitivityTests(unittest.TestCase):
    def test_heuristic_classifier_blocks_explicit_confidentiality(self) -> None:
        classifier = HeuristicSensitivityClassifier()
        assessment = classifier.assess(
            "change.md",
            "社外秘\n顧客名: 株式会社サンプル",
            SanitizedDocument(
                name="change.md",
                original_excerpt="",
                sanitized_excerpt="[COMPANY_001]",
                outbound_text="[COMPANY_001]",
                outbound_risk="medium",
            ),
        )

        self.assertEqual(assessment.decision, "block")
        self.assertTrue(any("confidentiality" in reason.lower() for reason in assessment.reasons))

    def test_heuristic_classifier_requests_more_masking(self) -> None:
        classifier = HeuristicSensitivityClassifier()
        assessment = classifier.assess(
            "design.md",
            "顧客名: Sample Corp\n案件名: migration",
            SanitizedDocument(
                name="design.md",
                original_excerpt="",
                sanitized_excerpt="[COMPANY_001]\n[PROJECT_001]",
                outbound_text="[COMPANY_001]\n[PROJECT_001]",
                outbound_risk="medium",
            ),
        )

        self.assertEqual(assessment.decision, "mask_and_continue")
        self.assertGreaterEqual(len(assessment.recommended_actions), 1)

    def test_parse_invalid_json_falls_back_to_mask_and_continue(self) -> None:
        assessment = _parse_sensitivity_assessment("not-json", "local-http")
        self.assertEqual(assessment.decision, "mask_and_continue")

    @patch.dict(os.environ, {"LOCAL_SENSITIVITY_PROVIDER": "heuristic"}, clear=False)
    def test_choose_sensitivity_classifier_defaults_to_heuristic(self) -> None:
        classifier = choose_sensitivity_classifier()
        self.assertEqual(classifier.name, "heuristic")

    def test_parse_valid_json_response(self) -> None:
        content = json.dumps(
            {
                "decision": "safe",
                "reasons": ["sanitized enough"],
                "recommended_actions": ["proceed"],
            }
        )
        assessment = _parse_sensitivity_assessment(content, "local-http")
        self.assertEqual(assessment.decision, "safe")
        self.assertEqual(assessment.provider, "local-http")


if __name__ == "__main__":
    unittest.main()
