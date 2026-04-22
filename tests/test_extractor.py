import base64
import io
import unittest
import zipfile

from secure_review.extractor import extract_text


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

        self.assertIn("目的", text)
        self.assertIn("ネットワーク更改", text)
        self.assertEqual(warnings, [])

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

        self.assertIn("# Sheet: 確認項目", text)
        self.assertIn("項目 | 結果", text)
        self.assertIn("Ping | OK", text)
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


if __name__ == "__main__":
    unittest.main()
