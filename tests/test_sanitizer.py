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

    # ------------------------------------------------------------------
    # R-N: label-pattern hardening for Japanese AWS design docs.
    #
    # Three structural defects were previously producing nonsense category
    # assignments on real-world docs:
    #   A. ``[:=: ]+`` allowed a bare space as a label separator, so any
    #      keyword followed by a single space matched.
    #   B. English keywords like ``manager`` / ``vendor`` matched as the
    #      second word of a phrase (``Systems Manager``, ``Software
    #      vendor``).
    #   C. Even with A and B fixed, ``LABEL: PUBLIC_SERVICE_NAME`` was
    #      still being masked, destroying the technical meaning
    #      (``Amazon SES`` becoming ``[COMPANY_001]``).
    #
    # The R-N fixes are: separator no longer accepts bare space (Fix A);
    # English keywords must appear at line start with optional indent
    # (Fix B); a public-term allowlist post-filters company / project /
    # ticket / person matches (Fix C).
    # ------------------------------------------------------------------

    def _label_records(self, sanitizer, name: str, text: str):
        """Helper: return only label-based records (company/project/ticket/person)."""
        document = sanitizer.sanitize(name, text)
        return [
            r
            for r in document.replacements
            if r.category in ("company", "project", "ticket", "person")
        ]

    def test_rn_fix_a_bare_space_separator_no_longer_matches(self) -> None:
        """Fix A: a single space between keyword and value must NOT be
        treated as a label separator. ``vendor SMTP AUTH`` is not
        ``vendor: SMTP AUTH``."""
        sanitizer = SensitiveDataSanitizer()
        # Each of these used to produce a bogus mask under the old
        # ``[:=: ]+`` separator class.
        for sample in [
            "vendor SMTP AUTH",
            "client AWS Direct Connect",
            "ベンダ Amazon SES",
            "プロジェクト名 府中 DC",
            "担当者 デフォルト",
            "案件名 フェーズ 1",
            "顧客名 パブリッククラウドサービス",
        ]:
            with self.subTest(sample=sample):
                self.assertEqual(
                    self._label_records(sanitizer, "doc.md", sample),
                    [],
                    f"{sample!r} produced a label-based mask but should not "
                    f"under the no-bare-space separator rule",
                )

    def test_rn_fix_a_colon_separator_still_matches(self) -> None:
        """Fix A regression guard: legitimate colon / equals / full-width-
        colon separators must still trigger masking on real label values."""
        sanitizer = SensitiveDataSanitizer()
        cases = [
            ("顧客名: 株式会社サンプル", "company"),
            ("顧客名:株式会社サンプル", "company"),       # no space
            ("顧客名: 株式会社サンプル", "company"),     # full-width space
            ("顧客名:株式会社サンプル", "company"),    # full-width colon
            ("案件名 = 次期NW更改", "project"),           # equals with spaces
            ("担当者: 山田太郎", "person"),
            ("変更番号: CR-2026-0042", "ticket"),
        ]
        for text, expected_category in cases:
            with self.subTest(text=text):
                records = self._label_records(sanitizer, "doc.md", text)
                self.assertEqual(
                    len(records),
                    1,
                    f"expected 1 mask for {text!r}, got {records}",
                )
                self.assertEqual(records[0].category, expected_category)

    def test_rn_fix_b_english_keyword_must_be_at_line_start(self) -> None:
        """Fix B: English label keywords (manager / vendor / customer / ...)
        must be anchored at line start (with optional indent). This kills
        the ``Systems Manager: SES`` / ``Account Manager: 山田`` /
        ``Software vendor: Acme`` false-positive pattern where the
        keyword is actually the second word of a longer phrase."""
        sanitizer = SensitiveDataSanitizer()
        # All of these must produce zero label-based records: the English
        # keyword is mid-phrase, not at line start.
        for sample in [
            "AWS Systems Manager: SES",
            "Account Manager: 山田太郎",
            "Software vendor: ACME",
            "Service customer: BigCo",
        ]:
            with self.subTest(sample=sample):
                self.assertEqual(
                    self._label_records(sanitizer, "doc.md", sample),
                    [],
                    f"{sample!r} matched as a label even though the keyword "
                    f"is mid-phrase",
                )

    def test_rn_fix_b_line_start_english_label_still_matches(self) -> None:
        """Fix B regression guard: a clean line-start English label must
        still be detected, even with leading indentation."""
        sanitizer = SensitiveDataSanitizer()
        cases = [
            "vendor: ACME Corporation",
            "    customer: BigCo",       # indented (table-like layout)
            "\tmanager: 田中一郎",         # tab-indented
            "owner: john.doe",
        ]
        for sample in cases:
            with self.subTest(sample=sample):
                records = self._label_records(sanitizer, "doc.md", sample)
                self.assertEqual(
                    len(records),
                    1,
                    f"expected 1 mask for line-start label {sample!r}, "
                    f"got {records}",
                )

    def test_rn_fix_b_japanese_keywords_keep_relaxed_boundary(self) -> None:
        """Fix B regression guard: Japanese keywords retain the relaxed
        ``(?:^|\\b)`` prefix because CJK word-boundary semantics work
        correctly for them. Inline Japanese labels (after punctuation,
        full-width space, etc.) must still match."""
        sanitizer = SensitiveDataSanitizer()
        cases = [
            "なお、担当者: 山田太郎までご連絡ください",
            "（連絡先: 03-1234-5678）",
            "顧客名: 株式会社サンプル",
        ]
        for sample in cases:
            with self.subTest(sample=sample):
                records = self._label_records(sanitizer, "doc.md", sample)
                self.assertGreaterEqual(
                    len(records),
                    1,
                    f"expected at least 1 mask for inline JP label {sample!r}",
                )

    def test_rn_fix_c_public_aws_service_names_are_not_masked(self) -> None:
        """Fix C: when the captured value is a widely-public AWS service
        name or standard protocol, the substitution must be skipped.
        ``連絡先: SMTP AUTH`` must remain ``連絡先: SMTP AUTH``, not
        become ``連絡先: [PERSON_001]``."""
        sanitizer = SensitiveDataSanitizer()
        for sample in [
            "vendor: AWS",
            "vendor: Amazon",
            "manager: Amazon SES",
            "連絡先: SMTP AUTH",
            "案件名: VPC",
            "システム名: Amazon Data Firehose",
            "サービス名: CloudWatch",
            "システム名: Direct Connect Gateway",
            "プロジェクト名: Private VIF",
            "案件名: MX レコード",
            "顧客名: パブリッククラウドサービス",
        ]:
            with self.subTest(sample=sample):
                records = self._label_records(sanitizer, "doc.md", sample)
                self.assertEqual(
                    records,
                    [],
                    f"public-term value in {sample!r} was masked but the "
                    f"allowlist should have skipped it",
                )

    def test_rn_fix_c_dmarc_policy_values_are_not_masked(self) -> None:
        """Fix C: DMARC / SPF policy values like ``p=none`` /
        ``p=quarantine`` must not be misclassified as identifiers.
        These appear in mail-design docs alongside DKIM / DMARC
        explanations and have no PII content."""
        sanitizer = SensitiveDataSanitizer()
        for sample in [
            "案件名: p=none",
            "案件名: p=quarantine",
            "案件名: p=reject",
        ]:
            with self.subTest(sample=sample):
                self.assertEqual(
                    self._label_records(sanitizer, "doc.md", sample),
                    [],
                )

    def test_rn_fix_c_real_customer_names_still_masked(self) -> None:
        """Fix C regression guard: the allowlist must NOT exempt real
        customer / project / person names. Anything that is not in the
        public-term list must still be masked under its label."""
        sanitizer = SensitiveDataSanitizer()
        cases = [
            ("顧客名: 株式会社サンプル", "株式会社サンプル", "company"),
            ("案件名: 次期NW更改", "次期NW更改", "project"),
            ("担当者: 山田太郎", "山田太郎", "person"),
            ("変更番号: CR-2026-0042", "CR-2026-0042", "ticket"),
            ("vendor: ACME Corporation", "ACME Corporation", "company"),
        ]
        for text, expected_value, expected_category in cases:
            with self.subTest(text=text):
                records = self._label_records(sanitizer, "doc.md", text)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].original, expected_value)
                self.assertEqual(records[0].category, expected_category)

    def test_rn_value_capture_stops_at_japanese_punctuation(self) -> None:
        """Fix D (bonus): the value capture must stop on Japanese
        punctuation (``、``, ``；``, ``。``) just as it does on ASCII
        comma / semicolon. Otherwise a single match greedily eats
        across clause boundaries."""
        sanitizer = SensitiveDataSanitizer()
        records = self._label_records(
            sanitizer,
            "doc.md",
            "顧客名: 株式会社サンプル、担当者: 山田太郎",
        )
        # Two distinct masks: company and person, NOT one giant
        # ``株式会社サンプル、担当者: 山田太郎`` mega-match.
        self.assertEqual(len(records), 2)
        originals = {r.original for r in records}
        self.assertIn("株式会社サンプル", originals)
        self.assertIn("山田太郎", originals)


if __name__ == "__main__":
    unittest.main()
