from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Step4UxStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")
        cls.audit_source = (ROOT / "streamlit_audit_ui.py").read_text(encoding="utf-8")

    def test_display_director_uses_action_first_copy(self) -> None:
        self.assertIn("📊 AI 判断の詳細を見る", self.app_source)
        self.assertNotIn("AI判断:", self.app_source)
        self.assertNotIn("表示量を自動調整中", self.app_source)

    def test_remediation_and_deep_dive_labels_are_distinct(self) -> None:
        self.assertIn("📝 この指摘の対応案 — 文書に追記する内容のたたき台", self.app_source)
        self.assertIn("🔬 この章をAIで再分析 — より具体的な指摘を引き出す", self.app_source)
        self.assertIn("現在の指摘では不十分なときに使います。", self.app_source)
        self.assertNotIn("🛠 担当者が追記する文章案を開く", self.app_source)
        self.assertNotIn("🔬 この章を深堀", self.app_source)

    def test_future_failure_cards_keep_only_unique_forward_looking_fields(self) -> None:
        self.assertIn("🔮 障害シナリオと予防策 — 主要な指摘の先にある将来リスク", self.app_source)
        self.assertIn("故障への道筋:", self.app_source)
        self.assertIn("次の一手:", self.app_source)
        self.assertNotIn("発火理由:", self.app_source)
        self.assertNotIn("本文で確認済み:", self.app_source)
        self.assertNotIn("本文で不足:", self.app_source)
        self.assertNotIn("レビュー指摘ヒント:", self.app_source)

    def test_audit_export_is_zip_and_developer_only(self) -> None:
        self.assertIn('st.session_state.get("developer_mode", False)', self.app_source)
        self.assertIn("📥 証跡をまとめてダウンロード (ZIP)", self.audit_source)
        self.assertIn("audit_log_zip_filename", self.audit_source)
        self.assertNotIn("📦 監査用 — 匿名化テキストJSONを保存", self.audit_source)
        self.assertNotIn("audit_export_sanitized_text_button", self.audit_source)


if __name__ == "__main__":
    unittest.main()
