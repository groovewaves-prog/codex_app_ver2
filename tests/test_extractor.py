import base64
import io
import unittest
import zipfile
from unittest.mock import patch

from secure_review.extractor import extract_text
from secure_review.rubric import extract_chapters_from_text


class ExtractorTests(unittest.TestCase):
    def test_extracts_docx_text_from_binary_payload(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "word/document.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                    "<w:body><w:p><w:r><w:t>目的</w:t></w:r></w:p>"
                    "<w:p><w:r><w:t>ネットワーク更改</w:t></w:r></w:p></w:body></w:document>"
                ),
            )

        text, warnings = extract_text(
            "design.docx",
            base64.b64encode(buffer.getvalue()).decode("ascii"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "base64",
        )

        self.assertIn("形式: Word (.docx)", text)
        self.assertIn("抽出上の注意", text)
        self.assertIn("目的", text)
        self.assertIn("ネットワーク更改", text)
        self.assertEqual(warnings, [])

    def test_extraction_metadata_does_not_become_review_chapter(self) -> None:
        text = (
            "# 抽出メタ情報\n"
            "- 形式: Word (.docx)\n\n"
            "# 抽出本文\n"
            "第 1 章 はじめに\n目的と範囲\n"
            "第 2 章 システム要件\n機能要件と非機能要件\n"
            "第 3 章 システム全体構成\n構成概要\n"
        )

        chapters = extract_chapters_from_text(text)

        self.assertEqual(["ch1", "ch2", "ch3"], [chapter.chapter_id for chapter in chapters])
        self.assertEqual("第 1 章 はじめに", chapters[0].chapter_label)

    def test_extracts_xlsx_sheet_rows(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "xl/workbook.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                    '<sheets><sheet name="確認項目" sheetId="1" r:id="rId1"/></sheets></workbook>'
                ),
            )
            archive.writestr(
                "xl/sharedStrings.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    "<si><t>項目</t></si><si><t>結果</t></si></sst>"
                ),
            )
            archive.writestr(
                "xl/worksheets/sheet1.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    "<sheetData>"
                    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
                    '<row r="2"><c r="A2" t="inlineStr"><is><t>Ping</t></is></c><c r="B2" t="inlineStr"><is><t>OK</t></is></c></row>'
                    "</sheetData></worksheet>"
                ),
            )

        text, warnings = extract_text(
            "checklist.xlsx",
            base64.b64encode(buffer.getvalue()).decode("ascii"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "base64",
        )

        self.assertIn("形式: Excel (.xlsx)", text)
        self.assertIn("シートごとに行テキスト", text)
        self.assertIn("# Excelブック診断", text)
        self.assertIn("- シート数: 1", text)
        self.assertIn("- 数式セル数: 0", text)
        self.assertIn("# Sheet: 確認項目", text)
        self.assertIn("項目 | 結果", text)
        self.assertIn("Ping | OK", text)
        self.assertEqual(warnings, [])

    def test_xlsx_workbook_diagnostics_include_hidden_formula_and_links(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "xl/workbook.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                    '<sheets>'
                    '<sheet name="Visible" sheetId="1" r:id="rId1"/>'
                    '<sheet name="HiddenConfig" sheetId="2" state="hidden" r:id="rId2"/>'
                    '</sheets></workbook>'
                ),
            )
            archive.writestr(
                "xl/_rels/workbook.xml.rels",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>'
                    '</Relationships>'
                ),
            )
            archive.writestr(
                "xl/worksheets/sheet1.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                    '<dimension ref="A1:C2"/>'
                    '<sheetData>'
                    '<row r="1"><c r="A1" t="inlineStr"><is><t>Item</t></is></c>'
                    '<c r="B1"><f>SUM(C1:C2)</f><v>10</v></c></row>'
                    '</sheetData>'
                    '<mergeCells count="1"><mergeCell ref="A1:B1"/></mergeCells>'
                    '<hyperlinks><hyperlink ref="A1" r:id="rId1"/></hyperlinks>'
                    '</worksheet>'
                ),
            )
            archive.writestr(
                "xl/worksheets/sheet2.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Hidden note</t></is></c></row></sheetData>'
                    '</worksheet>'
                ),
            )
            archive.writestr(
                "xl/comments1.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    '<commentList><comment ref="A1"><text><r><t>Review comment</t></r></text></comment></commentList>'
                    '</comments>'
                ),
            )

        text, warnings = extract_text(
            "workbook.xlsx",
            base64.b64encode(buffer.getvalue()).decode("ascii"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "base64",
        )

        self.assertIn("# Excelブック診断", text)
        self.assertIn("- シート数: 2", text)
        self.assertIn("- 非表示シート数: 1 (HiddenConfig)", text)
        self.assertIn("- 数式セル数: 1", text)
        self.assertIn("- ハイパーリンク数: 1", text)
        self.assertIn("- 結合セル範囲数: 1", text)
        self.assertIn("- コメント文字列数: 1", text)
        self.assertIn("[formula: SUM(C1:C2)]", text)
        self.assertIn("# Excelコメント: comments1.xml", text)
        self.assertIn("Review comment", text)
        self.assertIn("# Sheet: HiddenConfig", text)
        self.assertEqual(warnings, [])

    def test_extracts_pptx_slide_text(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "ppt/slides/slide1.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                    "<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>切替手順</a:t></a:r></a:p>"
                    "<a:p><a:r><a:t>22:00 開始</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
                ),
            )
            archive.writestr(
                "ppt/notesSlides/notesSlide1.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                    "<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>切戻し条件は別紙</a:t></a:r></a:p>"
                    "</p:txBody></p:sp></p:spTree></p:cSld></p:notes>"
                ),
            )

        text, warnings = extract_text(
            "change.pptx",
            base64.b64encode(buffer.getvalue()).decode("ascii"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "base64",
        )

        self.assertIn("形式: PowerPoint (.pptx)", text)
        self.assertIn("スライド本文とノート", text)
        self.assertIn("# Slide 1", text)
        self.assertIn("切替手順", text)
        self.assertIn("Notes:", text)
        self.assertIn("切戻し条件は別紙", text)
        self.assertEqual(warnings, [])

    def test_image_without_local_ocr_returns_presence_notice(self) -> None:
        text, warnings = extract_text(
            "diagram.png",
            base64.b64encode(b"fake-image").decode("ascii"),
            "image/png",
            "base64",
        )

        self.assertIn("Image detected", text)
        self.assertTrue(any("OCR" in warning for warning in warnings))

    def test_image_ocr_adds_local_diagram_summary(self) -> None:
        ocr_text = "Internet\nFortiGate-01\nFortiGate-02\nHA\nDMZ\nVLAN 100\n10.0.0.0/24"
        with patch("secure_review.extractor._run_local_ocr", return_value=ocr_text):
            text, warnings = extract_text(
                "diagram.png",
                base64.b64encode(b"fake-image").decode("ascii"),
                "image/png",
                "base64",
            )

        self.assertEqual(warnings, [])
        self.assertIn("構成図OCRサマリ", text)
        self.assertIn("画像そのものは外部LLMへ送信せず", text)
        self.assertIn("接続線・矢印・配置関係は確定解析していない", text)
        self.assertIn("## OCR text", text)
        self.assertIn("FortiGate-01", text)


if __name__ == "__main__":
    unittest.main()
