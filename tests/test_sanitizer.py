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
from secure_review.network_guard import LocalUrlError


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

    def test_ipv6_compressed_forms_are_masked(self) -> None:
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize(
            "router.cfg",
            "ipv6 address fe80::1/64\nipv6 neighbor 2001:db8::1\nloopback ::1",
        )
        self.assertIn("[IPV6_001]", document.sanitized_excerpt)

    def test_choose_local_sanitizer_defaults_to_none(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            enhancer = choose_local_sanitization_enhancer()
        self.assertIsInstance(enhancer, LocalSanitizationEnhancer)
        self.assertEqual(enhancer.name, "none")

    def test_local_http_sanitizer_rejects_non_loopback_url(self) -> None:
        """R1: non-loopback URLs must be rejected at construction."""
        with patch.dict(
            os.environ,
            {
                "LOCAL_SANITIZER_PROVIDER": "http",
                "LOCAL_SANITIZER_API_URL": "http://example.com/v1/responses",
                "LOCAL_SANITIZER_MODEL": "gemma3:12b",
            },
            clear=True,
        ):
            with self.assertRaises(LocalUrlError):
                choose_local_sanitization_enhancer()

    def test_local_http_sanitizer_accepts_loopback_url(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LOCAL_SANITIZER_PROVIDER": "http",
                "LOCAL_SANITIZER_API_URL": "http://127.0.0.1:11434/v1/responses",
                "LOCAL_SANITIZER_MODEL": "gemma3:12b",
            },
            clear=True,
        ):
            enhancer = choose_local_sanitization_enhancer()
        self.assertEqual(enhancer.name, "local-http")

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

        with patch("secure_review.sanitizer.post_json_safely", return_value=payload):
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

    def test_local_http_sanitizer_fails_safe_when_llm_unreachable(self) -> None:
        """R3/R4: if the local LLM is down, we keep regex-only sanitization."""
        from secure_review.network_guard import UpstreamHttpError

        sanitizer = SensitiveDataSanitizer()
        initial = sanitizer.sanitize("design.md", "password secret123\ncompany-name Example Co.")

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

        with patch(
            "secure_review.sanitizer.post_json_safely",
            side_effect=UpstreamHttpError("local sanitizer could not be reached."),
        ):
            enhanced = enhancer.enhance(
                "design.md",
                "password secret123\ncompany-name Example Co.",
                initial,
                sanitizer,
            )

        # Regex-masked text should still be there.
        self.assertIn("[SECRET_001]", enhanced.outbound_text)
        # And a finding should record the fallback.
        self.assertTrue(any("unavailable" in f.lower() for f in enhanced.findings))

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
