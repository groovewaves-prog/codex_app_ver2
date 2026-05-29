from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class G5CleanupStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")
        audit_path = ROOT / "streamlit_audit_ui.py"
        cls.audit_source = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""

    def test_design_foundation_preview_scaffold_is_removed(self) -> None:
        self.assertNotIn("_render_design_foundation_preview", self.app_source)
        self.assertNotIn("デザイン基盤プレビュー", self.app_source)
        self.assertNotIn("sr-design-preview", self.app_source)

    def test_agent_planner_module_is_removed_from_runtime(self) -> None:
        self.assertFalse((ROOT / "secure_review" / "agent_planner.py").exists())
        self.assertNotIn("secure_review.agent_planner", self.app_source)
        self.assertFalse((ROOT / "tests" / "test_agent_planner.py").exists())

    def test_old_guidance_ui_terms_are_not_rendered(self) -> None:
        combined = self.app_source + "\n" + self.audit_source
        for old_term in (
            "DISPLAY DIRECTOR",
            "REMEDIATION PLANNER",
            "章別深堀候補",
            "文書別の詳細表示",
            "Review Cockpit",
            "このパネルの目的",
            "Document Review Command",
        ):
            self.assertNotIn(old_term, combined)

    def test_chapter_matching_does_not_require_removed_chapter_name_attr(self) -> None:
        self.assertIn("_find_chapter_for_remediation_item", self.app_source)
        self.assertNotIn("chapter.chapter_name", self.app_source)
        self.assertIn("chapter.chapter_label", self.app_source)


if __name__ == "__main__":
    unittest.main()
