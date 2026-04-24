import json
import os
import unittest
from unittest.mock import patch

from secure_review.models import SanitizedDocument
from secure_review.network_guard import LocalUrlError, UpstreamHttpError
from secure_review.sensitivity import (
    HeuristicSensitivityClassifier,
    choose_sensitivity_classifier,
)


def _document(name: str = "doc.md", text: str = "some content", risk: str = "low") -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt=text[:200],
        sanitized_excerpt=text[:200],
        outbound_text=text,
        outbound_risk=risk,
    )


class HeuristicSensitivityTests(unittest.TestCase):
    def test_explicit_markers_block(self) -> None:
        classifier = HeuristicSensitivityClassifier()
        assessment = classifier.assess(
            "doc.md",
            "社外秘\n顧客との打合せ議事録",
            _document(),
        )
        self.assertEqual(assessment.decision, "block")

    def test_safe_for_generic_content(self) -> None:
        classifier = HeuristicSensitivityClassifier()
        assessment = classifier.assess(
            "doc.md",
            "Routing protocols: BGP, OSPF, IS-IS.",
            _document(),
        )
        self.assertEqual(assessment.decision, "safe")

    def test_mask_and_continue_for_partial_hits(self) -> None:
        classifier = HeuristicSensitivityClassifier()
        assessment = classifier.assess(
            "doc.md",
            "担当者: Someone\nプロジェクト名: X",
            _document(),
        )
        self.assertEqual(assessment.decision, "mask_and_continue")


class SensitivityClassifierChoiceTests(unittest.TestCase):
    def test_default_is_heuristic(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            classifier = choose_sensitivity_classifier()
        self.assertIsInstance(classifier, HeuristicSensitivityClassifier)

    def test_local_http_rejects_non_loopback_url(self) -> None:
        """R1 on sensitivity side too."""
        with patch.dict(
            os.environ,
            {
                "LOCAL_SENSITIVITY_PROVIDER": "http",
                "LOCAL_SENSITIVITY_API_URL": "http://evil.example.com/v1",
                "LOCAL_SENSITIVITY_MODEL": "gemma3:12b",
            },
            clear=True,
        ):
            with self.assertRaises(LocalUrlError):
                choose_sensitivity_classifier()

    def test_local_http_accepts_loopback_url(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LOCAL_SENSITIVITY_PROVIDER": "http",
                "LOCAL_SENSITIVITY_API_URL": "http://127.0.0.1:11434/v1/responses",
                "LOCAL_SENSITIVITY_MODEL": "gemma3:12b",
            },
            clear=True,
        ):
            classifier = choose_sensitivity_classifier()
        self.assertEqual(classifier.name, "local-http")

    def test_local_http_fails_safe_to_mask_and_continue(self) -> None:
        """R3/R4: unreachable gate must escalate to human review, not allow."""
        with patch.dict(
            os.environ,
            {
                "LOCAL_SENSITIVITY_PROVIDER": "http",
                "LOCAL_SENSITIVITY_API_URL": "http://127.0.0.1:9999/v1/responses",
                "LOCAL_SENSITIVITY_MODEL": "gemma3:12b",
            },
            clear=True,
        ):
            classifier = choose_sensitivity_classifier()

        with patch(
            "secure_review.sensitivity.post_json_safely",
            side_effect=UpstreamHttpError("local sensitivity gate could not be reached."),
        ):
            assessment = classifier.assess("doc.md", "some text", _document())

        self.assertEqual(assessment.decision, "mask_and_continue")
        self.assertTrue(any("unavailable" in r.lower() for r in assessment.reasons))

    def test_local_http_truncation_downgrades_safe_to_mask(self) -> None:
        """M4: if only head was evaluated, 'safe' is not good enough."""
        with patch.dict(
            os.environ,
            {
                "LOCAL_SENSITIVITY_PROVIDER": "http",
                "LOCAL_SENSITIVITY_API_URL": "http://127.0.0.1:9999/v1/responses",
                "LOCAL_SENSITIVITY_MODEL": "gemma3:12b",
                "LOCAL_SENSITIVITY_INPUT_CHARS": "100",
            },
            clear=True,
        ):
            classifier = choose_sensitivity_classifier()

        payload = {
            "output_text": json.dumps(
                {
                    "decision": "safe",
                    "reasons": ["Looks fine"],
                    "recommended_actions": [],
                }
            )
        }
        long_text = "x" * 500
        with patch("secure_review.sensitivity.post_json_safely", return_value=payload):
            assessment = classifier.assess("doc.md", long_text, _document(text=long_text))

        self.assertEqual(assessment.decision, "mask_and_continue")
        self.assertTrue(any("budget" in r.lower() for r in assessment.reasons))


if __name__ == "__main__":
    unittest.main()
