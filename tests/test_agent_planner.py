from __future__ import annotations

import unittest

from secure_review.agent_planner import build_review_agent_brief
from secure_review.models import SanitizedDocument


def _doc(
    name: str = "design.xlsx",
    *,
    decision: str = "safe",
    risk: str = "low",
    text: str = "本文",
) -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt=text,
        sanitized_excerpt=text,
        outbound_text=text,
        local_sensitivity_decision=decision,
        outbound_risk=risk,
    )


class AgentPlannerTests(unittest.TestCase):
    def test_empty_state_waits_for_upload(self) -> None:
        brief = build_review_agent_brief([], blocked_count=0, confirmation_count=0, send_approved=False)
        self.assertEqual(brief.mode, "待機")
        self.assertIn("アップロード", brief.next_action)

    def test_blocked_documents_stop_external_send(self) -> None:
        brief = build_review_agent_brief(
            [_doc(decision="block", risk="high")],
            blocked_count=1,
            confirmation_count=0,
            send_approved=False,
        )
        self.assertEqual(brief.mode, "停止判断")
        self.assertIn("外部送信", brief.mission)
        self.assertEqual(brief.stages[2].tone, "block")

    def test_excel_diagnostics_are_monitored(self) -> None:
        brief = build_review_agent_brief(
            [_doc(text="# Excelブック診断\n- シート数: 1\n# Sheet: A\nvalue")],
            blocked_count=0,
            confirmation_count=0,
            send_approved=True,
            token_status="safe",
        )
        self.assertEqual(brief.mode, "実行準備")
        self.assertIn("Excel診断: 1 件", brief.monitors)


if __name__ == "__main__":
    unittest.main()
