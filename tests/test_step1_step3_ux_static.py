from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Step1Step3UxStaticTests(unittest.TestCase):
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

    def _sidebar_block(self) -> str:
        start = self.app_source.index("with st.sidebar:")
        end = self.app_source.index("# --------------------------------------------------------------------- main")
        return self.app_source[start:end]

    def test_main_area_restores_concise_app_title(self) -> None:
        main_start = self.app_source.index("# --------------------------------------------------------------------- main")
        main_block = self.app_source[main_start:]
        self.assertIn("sr-app-title-row", self.app_source)
        self.assertIn("sr-app-title-icon", self.app_source)
        self.assertIn("sr-app-title-text", self.app_source)
        self.assertIn("font-size: clamp(30px, 3.1vw, 38px)", self.app_source)
        self.assertIn("border-bottom: 1px solid rgba(8,119,96,0.24)", self.app_source)
        self.assertIn("SR", main_block)
        self.assertIn("技術文書レビュー支援ツール", main_block)
        self.assertNotIn("ローカルで匿名化", main_block[: main_block.index("# -- Step 1")])
        self.assertNotIn("Document Review Command Center", self.app_source)

    def test_step1_v2_has_upload_first_layout(self) -> None:
        body = self._function_body("_render_step1_v2")
        self.assertIn("def _render_step1_v2", self.app_source)
        self.assertIn("準備中 · ステップ 1 / 3", body)
        self.assertIn("文書アップロード", body)
        self.assertIn("レビューする設計書を選択してください", body)
        self.assertIn("前回のレビュー結果と比較する", body)
        self.assertIn("レビュー対象ファイル", body)
        self.assertIn("_render_selected_uploads", body)
        self.assertIn("匿名化してプレビュー", body)

    def test_step1_v2_keeps_duplicate_warning_in_file_list(self) -> None:
        step_body = self._function_body("_render_step1_v2")
        list_body = self._function_body("_render_selected_uploads")
        self.assertIn("_detect_duplicate_uploads", step_body)
        self.assertIn("重複ファイル", list_body)
        self.assertIn("削除してから匿名化プレビューを実行", list_body)
        self.assertIn("upload-file-row warn", list_body)

    def test_sidebar_does_not_duplicate_app_name(self) -> None:
        sidebar = self._sidebar_block()
        self.assertNotIn("sidebar-brand", self.app_source)
        self.assertNotIn("sidebar-title", self.app_source)
        self.assertNotIn("Review Cockpit", sidebar)
        self.assertNotIn("技術文書レビュー支援ツール", sidebar)

    def test_new_review_button_is_primary_with_explanation(self) -> None:
        sidebar = self._sidebar_block()
        self.assertIn("↻ 新しいレビューを始める", sidebar)
        self.assertIn('type="primary"', sidebar)
        self.assertIn("アップロード済みの文書、マスク判断、レビュー結果をクリア", sidebar)
        self.assertIn("最初からやり直します", sidebar)
        self.assertIn('[data-testid="stSidebar"] div.stButton > button[kind="primary"]', self.app_source)
        self.assertIn("background: linear-gradient(135deg, #0f2119 0%, #17372b 100%) !important", self.app_source)
        self.assertIn("color: #fffdf8 !important", self.app_source)
        self.assertIn("-webkit-text-fill-color: #fffdf8 !important", self.app_source)

    def test_hero_and_copilot_are_not_rendered(self) -> None:
        self.assertNotIn("app-hero", self.app_source)
        self.assertNotIn("hero-subtitle", self.app_source)
        self.assertNotIn("AI Operation Co-Pilot", self.app_source)
        self.assertNotIn("_render_workflow_top_panel", self.app_source)
        self.assertNotIn("_render_operation_assist", self.app_source)

    def test_step3_v2_has_send_boundary_contrast(self) -> None:
        body = self._function_body("_render_step3_v2")
        self.assertIn("def _render_step3_v2", self.app_source)
        self.assertIn("送信", body)
        self.assertIn("外部 LLM サービスに匿名化済みテキストを送ります", body)
        self.assertIn("send-boundary-grid", body)
        self.assertIn("送信されるもの", body)
        self.assertIn("送信されないもの", body)
        self.assertIn("匿名化済みテキスト", body)
        self.assertIn("アップロードした原文ファイル", body)
        self.assertIn("マスク候補の元の語", body)

    def test_step3_v2_approval_gate_reuses_existing_state(self) -> None:
        body = self._function_body("_render_step3_v2")
        self.assertIn("st.checkbox", body)
        self.assertIn("上記の内容で送信することを承認します", body)
        self.assertIn("can_send = bool(preview_docs) and not blocked_docs and send_approved", body)
        self.assertIn("レビューを実行", body)
        self.assertIn("disabled=not can_send", body)
        self.assertIn("ステップ 2 に戻る", body)
        self.assertIn("on_click=_reset_step3_send_state_for_step2", body)
        self.assertNotIn("st.session_state.send_approval = False", body)
        self.assertNotIn("st.rerun()", body)

    def test_review_runtime_status_preserves_progress_and_error_states(self) -> None:
        self.assertIn("def _render_review_runtime_status", self.app_source)
        self.assertIn("レビュー実行中 · 外部 LLM へ送信中", self.app_source)
        self.assertIn("レビュー完了 · 結果を表示します", self.app_source)
        self.assertIn("レビュー停止 · ローカル設定エラー", self.app_source)
        self.assertIn("レビュー停止 · 送信前チェックエラー", self.app_source)
        self.assertIn("レビュー停止 · LLM 応答エラー", self.app_source)
        self.assertIn("レビュー停止 · 予期しないエラー", self.app_source)

    def test_status_bar_does_not_join_step_number_to_state(self) -> None:
        self.assertIn("準備中 · ステップ 1 / 3", self.app_source)
        self.assertIn("準備中 · ステップ 2 / 3", self.app_source)
        self.assertIn("送信準備完了 · ステップ 3 / 3", self.app_source)
        self.assertNotIn('"準備中 · ステップ 1 / 3", "レビュー前", "1"', self.app_source)
        self.assertNotIn('1準備中', self.app_source)
        self.assertNotIn('2準備中', self.app_source)
        self.assertNotIn('3送信準備完了', self.app_source)

    def test_backend_send_and_outbound_guard_paths_remain(self) -> None:
        self.assertIn("_enforce_outbound_guard(", self.app_source)
        self.assertIn("provider_impl.review(", self.app_source)
        self.assertIn("review_progress.progress", self.app_source)
        self.assertIn("st.session_state.review_in_progress", self.app_source)


if __name__ == "__main__":
    unittest.main()
