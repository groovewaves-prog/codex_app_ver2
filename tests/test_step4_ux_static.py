from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Step4UxStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")
        cls.audit_source = (ROOT / "streamlit_audit_ui.py").read_text(encoding="utf-8")

    def _function_body(self, name: str) -> str:
        start = self.app_source.index(f"def {name}")
        next_def = self.app_source.find("\ndef ", start + 1)
        if next_def == -1:
            return self.app_source[start:]
        return self.app_source[start:next_def]

    def test_step4_v2_uses_design_foundation_components(self) -> None:
        self.assertIn("def _render_step4_v2", self.app_source)
        self.assertIn("sr_ui.status_bar", self.app_source)
        self.assertIn("sr_ui.big_number_summary", self.app_source)
        self.assertIn("sr_ui.severity_chip", self.app_source)
        self.assertIn("sr_ui.issue_card_header", self.app_source)

    def test_step4_v2_has_core_sections(self) -> None:
        self.assertIn("対応すべき指摘", self.app_source)
        self.assertIn("対応が必要な指摘はありませんでした", self.app_source)
        self.assertIn("_render_step4_item_context", self.app_source)
        self.assertIn("対象文書", self.app_source)
        self.assertIn("対象箇所", self.app_source)
        self.assertIn("出どころ", self.app_source)

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

    def test_g2_old_planner_and_director_copy_is_not_rendered(self) -> None:
        self.assertNotIn("REMEDIATION PLANNER", self.app_source)
        self.assertNotIn("このパネルの目的", self.app_source)
        self.assertNotIn("まず赤い", self.app_source)
        self.assertNotIn("AI DISPLAY DIRECTOR", self.app_source)

    def test_g2_big_number_summary_renders_total_issue_count(self) -> None:
        self.assertIn("issue_count = len(remediation_plan.items)", self.app_source)
        self.assertIn('sr_ui.big_number_summary(issue_count, "件の指摘", lead)', self.app_source)
        self.assertIn("この文書には対応が必要な指摘があります", self.app_source)

    def test_g2_issue_card_header_contains_required_metadata(self) -> None:
        self.assertIn("sr_ui.issue_card_header(", self.app_source)
        self.assertIn("item.severity", self.app_source)
        self.assertIn("item.effort", self.app_source)
        self.assertIn("item.item_id", self.app_source)
        self.assertIn("item.target_section", self.app_source)
        self.assertIn("item.title", self.app_source)
        self.assertIn("item.target_document", self.app_source)
        self.assertIn("_step4_item_source_label", self.app_source)

    def test_step4_issue_list_uses_consistent_labels_and_document_filter(self) -> None:
        self.assertIn("_STEP4_ISSUE_DEFAULT_LIMIT = 12", self.app_source)
        self.assertIn("def _step4_issue_list_label", self.app_source)
        self.assertIn('f"指摘 {index:02d}"', self.app_source)
        self.assertIn("対象文書で絞り込み", self.app_source)
        self.assertIn("すべての文書", self.app_source)
        self.assertIn("すべて表示（残り", self.app_source)
        self.assertNotIn('label = f"{item.item_id or index} · {item.title}"', self.app_source)

    def test_step4_copy_action_uses_document_draft_wording(self) -> None:
        self.assertIn("文書追記案をコピー", self.app_source)
        self.assertIn("文書へ転記する本文案", self.app_source)
        self.assertNotIn("追記の雛形をコピー", self.app_source)

    def test_step4_hides_document_draft_for_code_analysis_mode(self) -> None:
        self.assertIn("def _is_code_analysis_review", self.app_source)
        self.assertIn('mode.mode_id == "code_analysis"', self.app_source)
        self.assertIn("show_document_draft = not _is_code_analysis_review", self.app_source)
        issue_card_body = self._function_body("_render_step4_issue_card")
        self.assertIn("show_document_draft: bool = True", issue_card_body)
        self.assertIn("if show_document_draft:", issue_card_body)

    def test_g2_issue_cards_have_chapter_reanalysis_entry(self) -> None:
        self.assertIn("matched_chapter = _find_chapter_for_remediation_item", self.app_source)
        self.assertIn("if matched_chapter is not None:", self.app_source)
        self.assertIn("step4_issue_deepdive_", self.app_source)
        self.assertIn('st.button("🔬 章を再分析"', self.app_source)

    def test_step4_auxiliary_section_is_not_rendered(self) -> None:
        body = self._function_body("_render_step4_v2")
        self.assertNotIn("_render_step4_auxiliary_sections", body)
        self.assertNotIn("補助で見るもの", body)
        self.assertNotIn("不足章", body)
        self.assertNotIn("将来リスク", body)

    def test_g2_document_detail_toggle_is_removed_from_step4(self) -> None:
        self.assertNotIn("文書別の詳細表示", self.app_source)
        self.assertNotIn("文書別の詳細確認", self.app_source)
        self.assertNotIn("show_document_detail_sections", self.app_source)

    def test_g2_per_document_legacy_grouping_is_removed(self) -> None:
        self.assertNotIn("_render_review_result_dashboard", self.app_source)
        self.assertNotIn("_render_remediation_plan", self.app_source)
        self.assertNotIn("_render_chapter_deep_dive_entry_section", self.app_source)
        self.assertNotIn("文書別の元指摘", self.app_source)

    def test_g2_zero_issue_message_is_preserved(self) -> None:
        self.assertIn("対応が必要な指摘はありませんでした", self.app_source)
        self.assertIn("対応が必要な修正計画カードはありません", self.app_source)


if __name__ == "__main__":
    unittest.main()
