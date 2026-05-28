from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Step4UxStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")
        cls.audit_source = (ROOT / "streamlit_audit_ui.py").read_text(encoding="utf-8")

    def test_step4_v2_uses_design_foundation_components(self) -> None:
        self.assertIn("def _render_step4_v2", self.app_source)
        self.assertIn("sr_ui.status_bar", self.app_source)
        self.assertIn("sr_ui.big_number_summary", self.app_source)
        self.assertIn("sr_ui.severity_chip", self.app_source)
        self.assertIn("sr_ui.issue_card_header", self.app_source)
        self.assertIn("sr_ui.collapsed_list_row", self.app_source)
        self.assertIn("不足章", self.app_source)
        self.assertIn("将来リスク", self.app_source)

    def test_step4_v2_has_core_sections(self) -> None:
        self.assertIn("対応すべき指摘", self.app_source)
        self.assertIn("補助で見るもの", self.app_source)
        self.assertIn("文書構成チェック", self.app_source)
        self.assertIn("章単位の追加レビュー", self.app_source)
        self.assertIn("将来の障害リスク", self.app_source)
        self.assertIn("修正計画の使い方", self.app_source)
        self.assertIn("対応が必要な指摘はありませんでした", self.app_source)

    def test_step4_v2_integrates_chapter_reanalysis(self) -> None:
        self.assertIn("章を再分析", self.app_source)
        self.assertIn("_find_chapter_for_remediation_item", self.app_source)
        self.assertIn("ch_deepdive_entry_btn_", self.app_source)
        self.assertIn("step4_issue_deepdive_", self.app_source)

    def test_step4_no_longer_imports_display_policy(self) -> None:
        self.assertNotIn("DisplayPolicy,", self.app_source)
        self.assertNotIn("build_review_display_policy,", self.app_source)
        self.assertNotIn("def _render_display_policy_assist", self.app_source)

    def test_audit_export_is_zip_and_developer_only(self) -> None:
        self.assertIn('st.session_state.get("developer_mode", False)', self.app_source)
        self.assertIn("証跡をまとめてダウンロード (ZIP)", self.audit_source)
        self.assertIn("audit_log_zip_filename", self.audit_source)
        self.assertNotIn("監査用 — 匿名化テキストJSONを保存", self.audit_source)
        self.assertNotIn("audit_export_sanitized_text_button", self.audit_source)


if __name__ == "__main__":
    unittest.main()
