import unittest

from secure_review.sanitizer import SensitiveDataSanitizer


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


if __name__ == "__main__":
    unittest.main()
