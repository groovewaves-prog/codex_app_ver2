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
        messages = "\n".join(finding.message for finding in result.findings)
        self.assertIn("不足観点", messages)
        self.assertNotIn("第10章", messages)

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
        messages = "\n".join(finding.message for finding in result.findings)
        self.assertIn("確認範囲「はじめに」", messages)

    def test_document_wide_items_are_not_forced_into_intro(self) -> None:
        result = build_structure_check_result(
            [
                _doc(
                    "design.docx",
                    "第 1 章 はじめに\n本書の目的と対象範囲を示す。\n"
                    "第 2 章 システム要件\n機能要件と非機能要件を定義する。\n"
                    "第 3 章 システム全体構成\n全体構成図と構成要素を示す。\n"
                    "第 7 章 運用体制\n関係者、責任範囲、エスカレーションパスを示す。\n"
                    "付録 改訂履歴\n版番号、改訂日、改訂内容、承認者を示す。",
                )
            ],
            "design",
        )
        item_ids = {
            finding.item_id
            for finding in result.findings
            if finding.kind == "required_item_gap"
        }
        self.assertNotIn("1.3", item_ids)
        self.assertNotIn("1.6", item_ids)

    def test_document_wide_items_are_reported_as_document_scope(self) -> None:
        result = build_structure_check_result(
            [
                _doc(
                    "design.docx",
                    "第 1 章 はじめに\n本書の目的と対象範囲を示す。\n"
                    "第 2 章 システム要件\n機能要件と非機能要件を定義する。\n"
                    "第 3 章 システム全体構成\n全体構成図と構成要素を示す。",
                )
            ],
            "design",
        )
        document_wide_gaps = [
            finding
            for finding in result.findings
            if finding.kind == "required_item_gap"
            and finding.item_id in {"1.3", "1.6"}
        ]
        self.assertTrue(document_wide_gaps)
        self.assertTrue(all(finding.chapter_name == "文書全体" for finding in document_wide_gaps))
        messages = "\n".join(finding.message for finding in document_wide_gaps)
        self.assertIn("文書全体", messages)
        self.assertNotIn("不足観点「はじめに」", messages)

    def test_design_plain_text_gets_template_suggestion(self) -> None:
        result = build_structure_check_result(
            [
                _doc(
                    "flat_design.txt",
                    "HikariAuth の認証方式をSAMLにする。MFAを使う。AWSで動かす。",
                )
            ],
            "design",
        )
        kinds = {finding.kind for finding in result.findings}
        self.assertIn("chapter_structure_missing", kinds)
        self.assertIn("structure_template_suggestion", kinds)
        template = next(
            finding.suggested_content
            for finding in result.findings
            if finding.kind == "structure_template_suggestion"
        )
        self.assertIn("目的", template)
        self.assertIn("非機能要件", template)
        messages = "\n".join(finding.message for finding in result.findings)
        self.assertNotIn("第1章", messages)

    def test_design_embedded_viewpoint_is_structure_suggestion(self) -> None:
        result = build_structure_check_result(
            [
                _doc(
                    "mixed_design.docx",
                    "第 1 章 はじめに\n本書の目的と対象範囲を示す。\n"
                    "第 2 章 システム要件\n機能要件と非機能要件を定義する。\n"
                    "セキュリティは脅威モデル、暗号化、監査ログを検討する。\n"
                    "運用は監視、アラート、バックアップを検討する。\n"
                    "第 3 章 システム全体構成\n全体構成図と構成要素を示す。",
                )
            ],
            "design",
        )
        organization_ids = {
            finding.chapter_id
            for finding in result.findings
            if finding.kind == "structure_organization_suggestion"
        }
        missing_ids = {
            finding.chapter_id
            for finding in result.findings
            if finding.kind == "missing_chapter"
        }
        self.assertIn("ch10", organization_ids)
        self.assertIn("ch11", organization_ids)
        self.assertNotIn("ch10", missing_ids)
        self.assertNotIn("ch11", missing_ids)

    def test_generic_profile_checks_purpose_at_beginning(self) -> None:
        result = build_structure_check_result(
            [_doc("runbook.md", "手順\n1. 作業を開始する。")],
            "operations_runbook",
        )
        self.assertTrue(result.findings)
        self.assertEqual(result.findings[0].kind, "required_item_gap")


if __name__ == "__main__":
    unittest.main()
