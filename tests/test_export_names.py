from __future__ import annotations

import unittest
from datetime import datetime

from secure_review.export_names import (
    audit_json_filename,
    audit_log_zip_filename,
    export_timestamp,
    remediation_plan_json_filename,
)


class ExportNamesTests(unittest.TestCase):
    def test_export_timestamp_uses_minute_precision(self) -> None:
        now = datetime(2026, 5, 26, 9, 5, 42)

        self.assertEqual(export_timestamp(now), "20260526_0905")

    def test_remediation_plan_filename_is_for_re_review_ledger(self) -> None:
        now = datetime(2026, 5, 26, 9, 5)

        self.assertEqual(
            remediation_plan_json_filename(now),
            "remediation_plan_20260526_0905.json",
        )

    def test_audit_filename_uses_audit_prefix_and_kind(self) -> None:
        now = datetime(2026, 5, 26, 9, 5)

        self.assertEqual(
            audit_json_filename("review_result", now),
            "audit_review_result_20260526_0905.json",
        )

    def test_audit_filename_sanitizes_kind(self) -> None:
        now = datetime(2026, 5, 26, 9, 5)

        self.assertEqual(
            audit_json_filename("send-log", now),
            "audit_send_log_20260526_0905.json",
        )

    def test_audit_zip_filename_uses_audit_log_prefix(self) -> None:
        now = datetime(2026, 5, 26, 9, 5)

        self.assertEqual(
            audit_log_zip_filename(now),
            "audit_log_20260526_0905.zip",
        )


if __name__ == "__main__":
    unittest.main()
