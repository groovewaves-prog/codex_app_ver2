import json
import os
import unittest
from unittest.mock import patch

from secure_review.models import SanitizationRecord
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

    # ------------------------------------------------------------------
    # R-H / M1: bare hostname detection via internal naming convention.
    # ------------------------------------------------------------------

    def test_internal_hostname_pattern_detects_naming_convention_variants(self) -> None:
        """Positive cases: regex must catch site-internal device identifiers
        without a ``hostname:`` label, across the documented variants
        (separator, casing, segment count, digit width)."""
        sanitizer = SensitiveDataSanitizer()
        positives = [
            "tokyo-rtr-01",       # basic 3-segment, hyphen
            "osaka-fw-001",       # 3-digit number
            "lb-001",             # 2-segment form (no location prefix)
            "Prd-DB-001",         # mixed case
            "prd_app_01",         # underscore separator
            "srv.web.001",        # dot separator
            "host-12345",         # 5-digit number
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                document = sanitizer.sanitize("doc.md", f"connect to {sample} for verification")
                self.assertIn(
                    "[HOSTNAME_",
                    document.sanitized_excerpt,
                    f"expected {sample} to be masked but excerpt was {document.sanitized_excerpt!r}",
                )
                self.assertNotIn(sample, document.sanitized_excerpt)

    def test_internal_hostname_pattern_does_not_overmatch_common_strings(self) -> None:
        """Negative cases: regex must not flag common non-secret strings such
        as version numbers, dates, encoding labels, internal review ids,
        documentation strings, and tokens that *contain* a device keyword
        as a substring of a longer word (``localhost``, ``combat``)."""
        sanitizer = SensitiveDataSanitizer()
        negatives = [
            "python-3.11",            # version: middle is a digit, not a keyword
            "utf-8",                  # encoding label: middle is a digit
            "windows-server-2019",    # 'server' is not in vocabulary (only 'srv')
            "gemma-4-31b",            # documentation string, middle is a digit
            "2026-04-27",             # date: middle '04' is not a keyword
            "r1-r4",                  # 'r4' is not a keyword and second token has no digits
            "localhost-01",           # 'host' is inside 'localhost', not a separate token
            "combat-01",              # 'bat' is inside 'combat', not a separate token
        ]
        for sample in negatives:
            with self.subTest(sample=sample):
                document = sanitizer.sanitize("doc.md", f"reference {sample} in passing")
                self.assertNotIn(
                    "[HOSTNAME_",
                    document.sanitized_excerpt,
                    f"{sample} was masked but should not have been; excerpt={document.sanitized_excerpt!r}",
                )
                self.assertIn(sample, document.sanitized_excerpt)

    def test_internal_hostname_pattern_consistent_placeholder_for_same_value(self) -> None:
        """The same bare hostname appearing multiple times must collapse to a
        single placeholder (``[HOSTNAME_001]``), not get a fresh number on
        each occurrence."""
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize(
            "ops.md",
            "rebooted tokyo-rtr-01 at 10:00. tokyo-rtr-01 came back online at 10:05.",
        )
        self.assertIn("[HOSTNAME_001]", document.sanitized_excerpt)
        self.assertNotIn("[HOSTNAME_002]", document.sanitized_excerpt)
        self.assertNotIn("tokyo-rtr-01", document.sanitized_excerpt)
        # Both occurrences should now read [HOSTNAME_001].
        self.assertEqual(document.sanitized_excerpt.count("[HOSTNAME_001]"), 2)

    def test_internal_hostname_pattern_unifies_with_labelled_hostname_detection(self) -> None:
        """A document mixing the labelled form (``hostname tokyo-rtr-01``)
        and the bare form must end up with one consistent placeholder for
        the same underlying value."""
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize(
            "router.cfg",
            "hostname tokyo-rtr-01\n! later in the doc, bare reference: tokyo-rtr-01 is the active node.",
        )
        self.assertIn("[HOSTNAME_001]", document.sanitized_excerpt)
        self.assertNotIn("[HOSTNAME_002]", document.sanitized_excerpt)
        self.assertNotIn("tokyo-rtr-01", document.sanitized_excerpt)

    # ------------------------------------------------------------------
    # R-J: pattern priority — label-based patterns must not re-mask values
    # that an earlier, more-specific pattern already placeholder-ised.
    # ------------------------------------------------------------------

    def test_label_pattern_does_not_remask_email_placeholder(self) -> None:
        """``連絡先: yamada@example.com`` must end up as
        ``連絡先: [EMAIL_001]``, not ``連絡先: [PERSON_001]``. The email
        pattern runs first and produces ``[EMAIL_001]``; the ``person``
        label pattern must recognise that value as already-masked and skip
        re-masking it under a less-specific category."""
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize("contact.md", "連絡先: yamada@example.com")
        self.assertIn("[EMAIL_001]", document.sanitized_excerpt)
        self.assertNotIn("[PERSON_001]", document.sanitized_excerpt)
        # The original email must not survive in the sanitized output.
        self.assertNotIn("yamada@example.com", document.sanitized_excerpt)
        # Replacement records must record the email category, not person.
        categories = {rec.category for rec in document.replacements}
        self.assertIn("email", categories)
        self.assertNotIn("person", categories)

    def test_label_pattern_still_masks_natural_language_values(self) -> None:
        """The label-based ``person`` pattern must still mask plain-text
        values that are not already placeholders. Regression guard for the
        R-J fix above — we want the early-exit only when the captured value
        IS a placeholder, not in general."""
        sanitizer = SensitiveDataSanitizer()
        document = sanitizer.sanitize("contact.md", "担当者: 山田太郎")
        self.assertIn("[PERSON_001]", document.sanitized_excerpt)
        self.assertNotIn("山田太郎", document.sanitized_excerpt)

    def test_label_pattern_skips_remask_for_each_category(self) -> None:
        """The R-J fix must apply uniformly across all label-based patterns
        (company / project / ticket / person) — none of them should re-mask
        an existing placeholder. We verify this with a value that gets
        placeholder-ised by the labelled hostname pattern first."""
        sanitizer = SensitiveDataSanitizer()
        # ``hostname tokyo-rtr-01`` → ``[HOSTNAME_001]``. Then ``担当者: ...``
        # references the same identifier; we want the second occurrence to
        # stay ``[HOSTNAME_001]``, not become ``[PERSON_001]``.
        document = sanitizer.sanitize(
            "ops.md",
            "hostname tokyo-rtr-01\n担当者: tokyo-rtr-01",
        )
        # The hostname placeholder must survive in both spots.
        self.assertEqual(document.sanitized_excerpt.count("[HOSTNAME_001]"), 2)
        self.assertNotIn("[PERSON_001]", document.sanitized_excerpt)


class RegisterNerFindingTests(unittest.TestCase):
    """R-M PR-A: register_ner_finding() の基本契約。

    NER 経由の発見をプレイスホルダに採番する経路。テキスト置換と台帳
    組み込みは呼び出し側 (run_masking_pipeline) の責務で、本メソッドは
    採番のみを担う責務分離。
    """

    def test_returns_placeholder_and_record(self) -> None:
        s = SensitiveDataSanitizer()
        placeholder, record = s.register_ner_finding("KDDI", "company")

        self.assertTrue(placeholder.startswith("[COMPANY_"))
        self.assertTrue(placeholder.endswith("]"))
        self.assertIsInstance(record, SanitizationRecord)
        self.assertEqual(record.placeholder, placeholder)
        self.assertEqual(record.original, "KDDI")
        self.assertEqual(record.category, "company")

    def test_idempotent_for_same_category_value_pair(self) -> None:
        """同一 (category, value) で複数回呼んでも同じプレイスホルダ。
        ner_masker が同じ候補を二度発見しても番号が膨らまない保証。
        """
        s = SensitiveDataSanitizer()
        p1, _ = s.register_ner_finding("KDDI", "company")
        p2, _ = s.register_ner_finding("KDDI", "company")
        self.assertEqual(p1, p2)

    def test_different_values_get_distinct_placeholders(self) -> None:
        s = SensitiveDataSanitizer()
        p1, _ = s.register_ner_finding("KDDI", "company")
        p2, _ = s.register_ner_finding("NTT", "company")
        self.assertNotEqual(p1, p2)
        # 連番がインクリメントされている
        self.assertEqual(p1, "[COMPANY_001]")
        self.assertEqual(p2, "[COMPANY_002]")

    def test_categories_have_independent_counters(self) -> None:
        """カテゴリ別カウンタが独立。COMPANY と SITE が混ざらない。"""
        s = SensitiveDataSanitizer()
        c1, _ = s.register_ner_finding("KDDI", "company")
        site1, _ = s.register_ner_finding("府中DC", "site")
        c2, _ = s.register_ner_finding("NTT", "company")

        self.assertEqual(c1, "[COMPANY_001]")
        self.assertEqual(site1, "[SITE_001]")
        self.assertEqual(c2, "[COMPANY_002]")

    def test_shares_numbering_with_regex_pipeline(self) -> None:
        """R-M の核心: regex 経路と NER 経路で番号を共有する。

        同一 SensitiveDataSanitizer インスタンスで sanitize_text() を
        実行した後に register_ner_finding を呼ぶと、同じカテゴリの
        既存採番を継続する形で次の番号が振られる。
        """
        s = SensitiveDataSanitizer()
        # regex 経路で 1 件 person カテゴリを発生させる
        result = s.sanitize_text("担当者: 山田太郎")
        regex_persons = [r for r in result.records if r.category == "person"]
        self.assertEqual(len(regex_persons), 1)
        self.assertEqual(regex_persons[0].placeholder, "[PERSON_001]")

        # NER 経路で続けて person を登録すると、PERSON_002 になるはず
        placeholder, _ = s.register_ner_finding("佐藤花子", "person")
        self.assertEqual(placeholder, "[PERSON_002]")

    def test_no_side_effect_on_sanitize_text_records(self) -> None:
        """register_ner_finding は sanitize_text のローカル records には
        影響しない (台帳組み込みは呼び出し側の責務)。
        """
        s = SensitiveDataSanitizer()
        s.register_ner_finding("KDDI", "company")

        # 直後の sanitize_text の records には KDDI は含まれない
        # (テキスト中に "KDDI" が現れていないため、当然ながら)
        result = s.sanitize_text("Hello world")
        self.assertEqual(
            [r for r in result.records if r.original == "KDDI"], []
        )


if __name__ == "__main__":
    unittest.main()
