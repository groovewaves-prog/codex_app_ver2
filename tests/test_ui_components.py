from __future__ import annotations

import unittest

from secure_review.ui_components import (
    big_number_summary,
    collapsed_list_row,
    effort_badge,
    issue_card_header,
    metric_pair,
    severity_chip,
    status_bar,
)


class UiComponentsTests(unittest.TestCase):
    def test_all_builders_return_strings(self) -> None:
        samples = [
            severity_chip("high", 2),
            effort_badge("large"),
            status_bar("送信準備完了", "Step 3", "✅"),
            big_number_summary(4, "件", "Issues"),
            issue_card_header("high", "large", "D-001", "第 1 章", "タイトル"),
            collapsed_list_row("📄", "詳細", "補足"),
            metric_pair("予定 call", "3"),
        ]

        for sample in samples:
            self.assertIsInstance(sample, str)
            self.assertTrue(sample.startswith("<"))

    def test_severity_chip_high_with_count(self) -> None:
        html = severity_chip("high", 2)

        self.assertIn("高", html)
        self.assertIn("2", html)
        self.assertIn("sr-severity-high", html)

    def test_html_escape_for_user_supplied_values(self) -> None:
        html = issue_card_header(
            "high",
            "large",
            "<script>alert(1)</script>",
            "第 <b>1</b> 章",
            "危険 <img src=x onerror=alert(1)>",
        )

        self.assertNotIn("<script>", html)
        self.assertNotIn("<b>1</b>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("第 &lt;b&gt;1&lt;/b&gt; 章", html)

    def test_invalid_levels_fallback_safely(self) -> None:
        severity = severity_chip("<script>", 1)
        effort = effort_badge("<script>")

        self.assertIn("sr-severity-neutral", severity)
        self.assertIn("情報", severity)
        self.assertNotIn("<script>", severity)
        self.assertIn("sr-effort-medium", effort)
        self.assertIn("工数 中", effort)
        self.assertNotIn("<script>", effort)


if __name__ == "__main__":
    unittest.main()
