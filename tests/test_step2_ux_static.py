from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Step2UxStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")

    def _function_body(self, name: str) -> str:
        marker = f"def {name}"
        start = self.app_source.index(marker)
        next_def = self.app_source.find("\ndef ", start + len(marker))
        if next_def == -1:
            return self.app_source[start:]
        return self.app_source[start:next_def]

    def test_step2_v2_uses_status_bar_without_copilot(self) -> None:
        body = self._function_body("_render_step2_v2")
        self.assertIn("def _render_step2_v2", self.app_source)
        self.assertIn("sr_ui.status_bar", self.app_source)
        self.assertNotIn("_render_operation_assist", body)
        self.assertNotIn("_render_workflow_top_panel", body)
        self.assertNotIn("build_operation_guide", body)

    def test_mask_candidates_are_promoted_before_document_details(self) -> None:
        body = self._function_body("_render_step2_v2")
        mask_index = body.index("_render_step2_mask_decision_section")
        action_index = body.index("_render_step2_next_action")
        detail_index = body.index("_render_step2_document_details")
        self.assertLess(mask_index, detail_index)
        self.assertLess(action_index, detail_index)
        self.assertIn("マスクするか判断が必要な語が", self.app_source)
        self.assertIn("固有名詞っぽい語が検出されました", self.app_source)

    def test_no_candidate_state_is_compact(self) -> None:
        self.assertIn("✓ 要確認の語はありませんでした", self.app_source)
        self.assertIn("外部送信前に追加判断が必要な固有名詞候補は検出されていません", self.app_source)

    def test_summary_chips_show_anonymization_overview(self) -> None:
        self.assertIn('_step2_chip("安全"', self.app_source)
        self.assertIn('_step2_chip("要確認"', self.app_source)
        self.assertIn('_step2_chip("候補"', self.app_source)
        self.assertIn('_step2_chip("本文tokens"', self.app_source)
        self.assertIn("ファイルを匿名化しました", self.app_source)

    def test_document_details_are_collapsed_list_rows(self) -> None:
        body = self._function_body("_render_step2_document_details")
        self.assertIn("sr_ui.collapsed_list_row", body)
        self.assertIn("with st.expander", body)
        self.assertIn("LLM送信対象テキスト", body)
        self.assertIn("匿名化後の抜粋", body)
        self.assertIn("置換一覧", body)

    def test_send_ready_is_gated_by_remaining_candidates(self) -> None:
        body = self._function_body("_render_step2_next_action")
        self.assertIn("candidate_total, decided_count = _mask_decision_progress", body)
        self.assertIn("disabled = bool(blocked_docs) or candidate_total > 0", body)
        self.assertIn("マスク判断候補が", body)
        self.assertIn("判断を反映するため", body)
        self.assertIn("送信準備を完了する", body)
        self.assertIn("匿名化結果を再生成", body)

    def test_mask_decision_persistence_connection_is_reused(self) -> None:
        self.assertIn("def _decision_key", self.app_source)
        self.assertIn('st.session_state.setdefault("user_decisions", {})', self.app_source)
        self.assertIn("apply_user_decisions(", self.app_source)
        self.assertIn("step2_mask_decision_", self.app_source)
        self.assertIn("st.session_state.masking_states", self.app_source)
        self.assertIn("uncertain_candidates=[]", self.app_source)

    def test_old_step2_duplicate_widgets_are_removed(self) -> None:
        self.assertNotIn("_render_review_bundle_overview(", self.app_source)
        self.assertNotIn("_render_anonymization_summary(", self.app_source)
        self.assertNotIn("_render_uncertain_candidates_card(", self.app_source)
        self.assertNotIn("_render_anonymization_detail_panel(", self.app_source)
        self.assertNotIn("doc_check_button", self.app_source)
        self.assertNotIn("匿名化結果の内訳", self.app_source)


if __name__ == "__main__":
    unittest.main()
