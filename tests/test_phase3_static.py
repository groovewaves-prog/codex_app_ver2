from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Phase3StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")

    def test_copilot_keeps_details_collapsed(self) -> None:
        self.assertIn("AI Operation Co-Pilot", self.app_source)
        self.assertIn("assist-step", self.app_source)
        self.assertIn("assist-title", self.app_source)
        self.assertIn("次にすること:", self.app_source)
        self.assertIn("🔍 操作の詳細 — 理由・完了の目安・注意点", self.app_source)
        self.assertNotIn("<div class=\"assist-note\"><b>なぜ必要か:", self.app_source)
        self.assertNotIn("<div class=\"assist-note\"><b>完了の目安:", self.app_source)
        self.assertNotIn("<div class=\"assist-note\"><b>注意:", self.app_source)
        self.assertNotIn("この画面で見るポイント", self.app_source)

    def test_document_profile_selector_is_inside_details_expander(self) -> None:
        details_index = self.app_source.index("⚙️ 詳細設定 — 辞書・R-M・開発者表示を切り替えるときに開く")
        profile_label_index = self.app_source.index('<div class="sidebar-section-label">文書種別</div>')
        profile_select_index = self.app_source.index('profile_label = st.selectbox(')
        customer_selector_index = self.app_source.index("render_customer_selector(sidebar=False)")

        self.assertEqual(self.app_source.count('<div class="sidebar-section-label">文書種別</div>'), 1)
        self.assertLess(details_index, profile_label_index)
        self.assertLess(profile_label_index, profile_select_index)
        self.assertLess(profile_select_index, customer_selector_index)

    def test_sidebar_details_separator_is_not_duplicated(self) -> None:
        self.assertNotIn('st.markdown("---")\n\n    st.markdown("---")', self.app_source)


if __name__ == "__main__":
    unittest.main()
