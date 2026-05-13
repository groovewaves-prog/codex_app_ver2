import unittest

from secure_review.models import SanitizedDocument
from secure_review.structure_check import build_structure_check_result


def _doc(name: str, text: str) -> SanitizedDocument:
    return SanitizedDocument(
        name=name,
        original_excerpt=text[:200],
        sanitized_excerpt=text[:200],
        outbound_text=text,
    )


class StructureCheckTests(unittest.TestCase):
    def test_design_missing_chapter_is_evaluated_across_review_set(self) -> None:
        docs = [
            _doc(
                "overview.docx",
                "第 1 章 はじめに\n本書の目的と対象範囲を示す。\n"
                "第 2 章 システム要件\n機能要件と非機能要件を定義する。\n"
                "第 3 章 システム全体構成\n全体構成図と構成要素を示す。",
            ),
            _doc(
                "network.docx",
                "第 4 章 ネットワーク設計\nネットワーク構成と経路設計を示す。\n"
                "第 5 章 アカウント・認可設計\n認証方式と権限分離を示す。\n"
                "第 8 章 可用性設計\nSLO と DR 方針を示す。",
            ),
        ]
        result = build_structure_check_result(docs, "design")
        missing_ids = {
            finding.chapter_id
            for finding in result.findings
            if finding.kind == "missing_chapter"
        }
        self.assertNotIn("ch1", missing_ids)
        self.assertNotIn("ch2", missing_ids)
        self.assertNotIn("ch3", missing_ids)
        self.assertNotIn("ch4", missing_ids)
        self.assertIn("ch10", missing_ids)

    def test_design_purpose_gap_is_reported_as_required_item_gap(self) -> None:
        docs = [
            _doc(
                "design.docx",
                "第 1 章 はじめに\n概要のみ。\n"
                "第 2 章 システム要件\n機能要件と非機能要件を定義する。\n"
                "第 3 章 システム全体構成\n全体構成図と構成要素を示す。",
            )
        ]
        result = build_structure_check_result(docs, "design")
        item_ids = {
            finding.item_id
            for finding in result.findings
            if finding.kind == "required_item_gap"
        }
        self.assertIn("1.1", item_ids)

    def test_generic_profile_checks_purpose_at_beginning(self) -> None:
        result = build_structure_check_result(
            [_doc("runbook.md", "手順\n1. 作業を開始する。")],
            "operations_runbook",
        )
        self.assertTrue(result.findings)
        self.assertEqual(result.findings[0].kind, "required_item_gap")


if __name__ == "__main__":
    unittest.main()
