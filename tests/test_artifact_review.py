from __future__ import annotations

import unittest

from secure_review.artifact_review import (
    detect_artifact_review_mode,
    render_artifact_review_mode_for_prompt,
)
from secure_review.models import SanitizedDocument


def _doc(name: str, text: str) -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt=text[:200],
        sanitized_excerpt=text[:200],
        outbound_text=text,
    )


class ArtifactReviewModeTests(unittest.TestCase):
    def test_shell_text_file_uses_code_analysis_mode(self) -> None:
        mode = detect_artifact_review_mode(
            [
                _doc(
                    "kobekan_sendmail.sh.txt",
                    "#!/bin/bash\nmailx -S ssl-verify=ignore -s test user@example.com",
                )
            ],
            "source_code",
        )
        self.assertEqual(mode.mode_id, "code_analysis")
        self.assertIn("コード解析モード", mode.mode_name)
        self.assertIn("Shell", mode.detected_languages)
        self.assertIn("実行せず", render_artifact_review_mode_for_prompt(mode))

    def test_powershell_script_language_is_detected(self) -> None:
        mode = detect_artifact_review_mode(
            [
                _doc(
                    "Close-StaleProblems.ps1",
                    "param([switch]$DryRun)\nInvoke-RestMethod -Uri $url\nWrite-Output 'ok'",
                )
            ],
            "source_code",
        )
        self.assertEqual(mode.mode_id, "code_analysis")
        self.assertIn("PowerShell", mode.detected_languages)

    def test_light_runbook_keeps_two_depth_options(self) -> None:
        mode = detect_artifact_review_mode(
            [
                _doc(
                    "滞留障害イベント解消 手順書.txt",
                    "１．事前確認\n①GUIを確認\n２．トリガーを編集\n３．systemctl restart zabbix-server",
                )
            ],
            "operations_runbook",
        )
        self.assertEqual(mode.mode_id, "runbook_depth")
        self.assertEqual(mode.runbook_depth, "light_high_risk")
        self.assertIn("簡易", mode.mode_name)
        self.assertIn("正式手順書", mode.primary_output)

    def test_design_document_uses_plain_document_review(self) -> None:
        mode = detect_artifact_review_mode(
            [_doc("基本設計書.pdf", "第1章 はじめに\n目的")],
            "design",
        )
        self.assertEqual(mode.mode_id, "document_review")
        self.assertIn("文書レビュー", mode.mode_name)


if __name__ == "__main__":
    unittest.main()
