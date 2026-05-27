from __future__ import annotations

import json
import unittest
import zipfile
from datetime import datetime
from io import BytesIO

from streamlit_audit_ui import build_audit_export_zip


class AuditExportZipTests(unittest.TestCase):
    def test_build_audit_export_zip_contains_four_json_files(self) -> None:
        exported_at = datetime(2026, 5, 26, 9, 5)
        payloads = (
            ("sanitized_text", {"export_type": "audit_sanitized_text"}),
            ("mask_candidates", {"export_type": "audit_mask_candidates"}),
            ("send_log", {"export_type": "audit_send_log"}),
            ("review_result", {"export_type": "audit_review_result"}),
        )

        zip_bytes = build_audit_export_zip(payloads, exported_at)

        with zipfile.ZipFile(BytesIO(zip_bytes)) as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                [
                    "audit_mask_candidates_20260526_0905.json",
                    "audit_review_result_20260526_0905.json",
                    "audit_sanitized_text_20260526_0905.json",
                    "audit_send_log_20260526_0905.json",
                ],
            )
            review_payload = json.loads(
                archive.read("audit_review_result_20260526_0905.json").decode("utf-8")
            )
            self.assertEqual(review_payload["export_type"], "audit_review_result")


if __name__ == "__main__":
    unittest.main()
