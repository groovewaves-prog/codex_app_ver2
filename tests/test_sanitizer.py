import json
import os
import unittest
from unittest.mock import patch

from secure_review.sanitizer import (
    LocalSanitizationEnhancer,
    SensitiveDataSanitizer,
    _parse_local_sanitization_response,
    choose_local_sanitization_enhancer,
)


class SanitizerTests(unittest.TestCase):
    def test_masks_common_sensitive_values(self) -> None:
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize(
            "router.cfg",
            "hostname tokyo-rtr-01\npassword superSecret!\nip address 10.10.10.1 255.255.255.0\nsnmp-server community public RO",
        )

        self.assertIn("[HOSTNAME_001]", document.sanitized_excerpt)
        self.assertIn("[SECRET_001]", document.sanitized_excerpt)
        self.assertIn("[IPV4_001]", document.sanitized_excerpt)
        self.assertGreaterEqual(len(document.replacements), 3)
        self.assertGreater(document.estimated_input_tokens, 0)

    def test_detects_confidentiality_markers_and_masks_business_labels(self) -> None:
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize(
            "change.md",
            "社外秘\n顧客名: 株式会社サンプル\n案件名: 次期NW更改\n担当者: 山田太郎",
        )

        self.assertEqual(document.outbound_risk, "high")
        self.assertIn("[COMPANY_001]", document.sanitized_excerpt)
        self.assertIn("[PROJECT_001]", document.sanitized_excerpt)
        self.assertIn("[PERSON_001]", document.sanitized_excerpt)
        self.assertTrue(
            any("confidentiality markers" in finding.lower() for finding in document.findings)
        )

    def test_choose_local_sanitizer_defaults_to_none(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            enhancer = choose_local_sanitization_enhancer()
        self.assertIsInstance(enhancer, LocalSanitizationEnhancer)
        self.assertEqual(enhancer.name, "none")

    def test_local_http_sanitizer_can_apply_additional_masking(self) -> None:
        sanitizer = SensitiveDataSanitizer()
        initial = sanitizer.sanitize(
            "design.md",
            "customer-name Acme Corp\nsite-name Tokyo-DC-01\npurpose network migration",
        )

        payload = {
            "output_text": json.dumps(
                {
                    "sanitized_text": (
                        "[COMPANY_001]\n[SITE_001]\npurpose network migration"
                    ),
                    "findings": ["Masked remaining site identifier locally."],
                    "risk": "low",
                }
            )
        }

        with patch.dict(
            os.environ,
            {
                "LOCAL_SANITIZER_PROVIDER": "http",
                "LOCAL_SANITIZER_API_URL": "http://127.0.0.1:9999/v1/responses",
                "LOCAL_SANITIZER_MODEL": "gemma3:12b",
            },
            clear=True,
        ):
            enhancer = choose_local_sanitization_enhancer()

        with patch("secure_review.sanitizer._post_json", return_value=payload):
            enhanced = enhancer.enhance(
                "design.md",
                "customer-name Acme Corp\nsite-name Tokyo-DC-01\npurpose network migration",
                initial,
                sanitizer,
            )

        self.assertEqual(enhanced.local_sanitizer_provider, "local-http")
        self.assertIn("[SITE_001]", enhanced.outbound_text)
        self.assertTrue(
            any("additional masking" in finding.lower() for finding in enhanced.findings)
        )
        self.assertEqual(enhanced.outbound_risk, "medium")

    def test_parse_local_sanitizer_response_accepts_code_fences(self) -> None:
        response = _parse_local_sanitization_response(
            """```json
            {"sanitized_text":"[COMPANY_1]\\n[SITE_12]","findings":["ok"],"risk":"low"}
            ```""",
            "fallback",
        )

        self.assertEqual(response.sanitized_text, "[COMPANY_001]\n[SITE_012]")
        self.assertEqual(response.outbound_risk, "low")


if __name__ == "__main__":
    unittest.main()
