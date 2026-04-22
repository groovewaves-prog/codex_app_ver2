from __future__ import annotations

import base64
import csv
import html
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".txt",
    ".md",
    ".py",
    ".ps1",
    ".psm1",
    ".psd1",
    ".sh",
    ".bash",
    ".bsh",
    ".ksh",
    ".zsh",
    ".vbs",
    ".vba",
    ".bas",
    ".cls",
    ".frm",
    ".psql",
    ".sql",
    ".cfg",
    ".conf",
    ".log",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".html",
    ".htm",
    ".xml",
    ".docx",
    ".xlsx",
    ".pptx",
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".tif",
    ".tiff",
    ".webp",
}

IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".tif",
    ".tiff",
    ".webp",
}

DRAWINGML_NAMESPACES = {
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
}

SPREADSHEET_NAMESPACES = {
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "rel": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}

PRESENTATION_NAMESPACES = {
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "rel": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}


def extract_text(
    name: str,
    raw_content: str,
    content_type: str = "text/plain",
    transfer_encoding: str = "text",
) -> tuple[str, list[str]]:
    extension = Path(name).suffix.lower()
    warnings: list[str] = []

    if transfer_encoding == "base64":
        try:
            binary = base64.b64decode(raw_content)
        except ValueError:
            warnings.append(f"{name}: Binary payload could not be decoded, using the raw text instead.")
            binary = raw_content.encode("utf-8", errors="ignore")
    else:
        binary = raw_content.encode("latin1", errors="ignore")

    if extension not in SUPPORTED_EXTENSIONS:
        warnings.append(f"{name}: The current extractor does not officially support {extension or 'this file type'} yet.")
        return _decode_text(binary), warnings

    if extension == ".json":
        return _format_json(_decode_text(binary), name, warnings), warnings
    if extension in {".html", ".htm", ".xml"}:
        return _strip_markup(_decode_text(binary)), warnings
    if extension == ".csv":
        return _format_csv(_decode_text(binary), name, warnings), warnings
    if extension == ".docx":
        return _extract_docx(binary, name, warnings), warnings
    if extension == ".xlsx":
        return _extract_xlsx(binary, name, warnings), warnings
    if extension == ".pptx":
        return _extract_pptx(binary, name, warnings), warnings
    if extension in IMAGE_EXTENSIONS or content_type.startswith("image/"):
        return _extract_image(binary, name, warnings), warnings

    return _decode_text(binary), warnings


def _decode_text(binary: bytes) -> str:
    for encoding in ("utf-8", "cp932", "utf-16", "latin1"):
        try:
            return binary.decode(encoding)
        except UnicodeDecodeError:
            continue
    return binary.decode("utf-8", errors="ignore")


def _format_json(raw_text: str, name: str, warnings: list[str]) -> str:
    try:
        parsed = json.loads(raw_text)
        return json.dumps(parsed, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        warnings.append(f"{name}: JSON parsing failed, so the raw content was used.")
        return raw_text


def _format_csv(raw_text: str, name: str, warnings: list[str]) -> str:
    try:
        reader = csv.reader(io.StringIO(raw_text))
        lines = [" | ".join(row) for row in reader]
        return "\n".join(lines)
    except csv.Error:
        warnings.append(f"{name}: CSV parsing failed, so the raw content was used.")
        return raw_text


def _strip_markup(raw_text: str) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", raw_text, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_docx(binary: bytes, name: str, warnings: list[str]) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(binary)) as archive:
            xml_paths = [
                path
                for path in archive.namelist()
                if path.startswith("word/") and path.endswith(".xml") and not path.startswith("word/_rels/")
            ]
            xml_paths.sort()
            sections = []
            for path in xml_paths:
                text = _collect_xml_text(archive.read(path))
                if text:
                    sections.append(f"[{Path(path).name}]\n{text}")

            image_text = _extract_embedded_images(archive, "word/media/", warnings, name)
            if image_text:
                sections.append(image_text)

            return "\n\n".join(section for section in sections if section).strip() or _decode_text(binary)
    except Exception:
        warnings.append(f"{name}: DOCX extraction failed, so the raw content was used.")
        return _decode_text(binary)


def _extract_xlsx(binary: bytes, name: str, warnings: list[str]) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(binary)) as archive:
            shared_strings = _read_shared_strings(archive)
            sheet_names = _read_workbook_sheet_names(archive)
            sections: list[str] = []

            worksheet_paths = [
                path
                for path in archive.namelist()
                if path.startswith("xl/worksheets/") and path.endswith(".xml")
            ]
            worksheet_paths.sort()

            for index, path in enumerate(worksheet_paths, start=1):
                sheet_name = sheet_names.get(f"rId{index}", Path(path).stem)
                sheet_text = _read_worksheet(archive.read(path), shared_strings)
                sections.append(f"# Sheet: {sheet_name}\n{sheet_text}".strip())

            image_text = _extract_embedded_images(archive, "xl/media/", warnings, name)
            if image_text:
                sections.append(image_text)

            return "\n\n".join(section for section in sections if section).strip() or _decode_text(binary)
    except Exception:
        warnings.append(f"{name}: XLSX extraction failed, so the raw content was used.")
        return _decode_text(binary)


def _extract_pptx(binary: bytes, name: str, warnings: list[str]) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(binary)) as archive:
            slides = [
                path
                for path in archive.namelist()
                if re.fullmatch(r"ppt/slides/slide\d+\.xml", path)
            ]
            slides.sort(key=_numeric_suffix)

            notes = {
                _numeric_suffix(path): _collect_xml_text(archive.read(path))
                for path in archive.namelist()
                if re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", path)
            }

            sections: list[str] = []
            for path in slides:
                slide_number = _numeric_suffix(path)
                text = _collect_xml_text(archive.read(path))
                notes_text = notes.get(slide_number, "")
                block = [f"# Slide {slide_number}"]
                if text:
                    block.append(text)
                if notes_text:
                    block.append(f"Notes:\n{notes_text}")
                sections.append("\n".join(block).strip())

            image_text = _extract_embedded_images(archive, "ppt/media/", warnings, name)
            if image_text:
                sections.append(image_text)

            return "\n\n".join(section for section in sections if section).strip() or _decode_text(binary)
    except Exception:
        warnings.append(f"{name}: PPTX extraction failed, so the raw content was used.")
        return _decode_text(binary)


def _extract_image(binary: bytes, name: str, warnings: list[str]) -> str:
    ocr_text = _run_local_ocr(binary, name, warnings)
    if ocr_text:
        return f"# Image: {name}\nOCR text:\n{ocr_text}"

    warnings.append(
        f"{name}: Local OCR is unavailable, so only the file presence was recorded. Install Tesseract for image text extraction."
    )
    return f"# Image: {name}\nImage detected. OCR text was not available in the current environment."


def _collect_xml_text(binary: bytes) -> str:
    try:
        root = ET.fromstring(binary)
    except ET.ParseError:
        return ""

    texts = []
    for text_node in root.findall(".//a:t", DRAWINGML_NAMESPACES):
        if text_node.text and text_node.text.strip():
            texts.append(text_node.text.strip())

    if not texts:
        for node in root.iter():
            if node.text and node.text.strip():
                texts.append(node.text.strip())

    return "\n".join(texts)


def _read_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []

    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    values = []
    for string_item in root.findall(".//main:si", SPREADSHEET_NAMESPACES):
        parts = [
            node.text.strip()
            for node in string_item.findall(".//main:t", SPREADSHEET_NAMESPACES)
            if node.text and node.text.strip()
        ]
        values.append("".join(parts))
    return values


def _read_workbook_sheet_names(archive: zipfile.ZipFile) -> dict[str, str]:
    names: dict[str, str] = {}
    if "xl/workbook.xml" not in archive.namelist():
        return names

    root = ET.fromstring(archive.read("xl/workbook.xml"))
    for sheet in root.findall(".//main:sheets/main:sheet", SPREADSHEET_NAMESPACES):
        rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id", "")
        name = sheet.attrib.get("name", rel_id or "Sheet")
        if rel_id:
            names[rel_id] = name
    return names


def _read_worksheet(binary: bytes, shared_strings: list[str]) -> str:
    root = ET.fromstring(binary)
    lines = []
    for row in root.findall(".//main:sheetData/main:row", SPREADSHEET_NAMESPACES):
        values = []
        for cell in row.findall("main:c", SPREADSHEET_NAMESPACES):
            cell_type = cell.attrib.get("t", "")
            value_node = cell.find("main:v", SPREADSHEET_NAMESPACES)
            inline_node = cell.find("main:is", SPREADSHEET_NAMESPACES)

            value = ""
            if inline_node is not None:
                fragments = [
                    node.text.strip()
                    for node in inline_node.findall(".//main:t", SPREADSHEET_NAMESPACES)
                    if node.text and node.text.strip()
                ]
                value = "".join(fragments)
            elif value_node is not None and value_node.text:
                raw_value = value_node.text.strip()
                if cell_type == "s" and raw_value.isdigit():
                    index = int(raw_value)
                    if 0 <= index < len(shared_strings):
                        value = shared_strings[index]
                    else:
                        value = raw_value
                else:
                    value = raw_value

            values.append(value)

        if any(values):
            lines.append(" | ".join(values).rstrip())

    return "\n".join(lines).strip() or "(No cell text found)"


def _extract_embedded_images(
    archive: zipfile.ZipFile,
    prefix: str,
    warnings: list[str],
    name: str,
) -> str:
    image_sections: list[str] = []
    media_paths = [path for path in archive.namelist() if path.startswith(prefix)]
    media_paths.sort()

    for media_path in media_paths:
        image_binary = archive.read(media_path)
        ocr_text = _run_local_ocr(image_binary, f"{name}:{Path(media_path).name}", warnings)
        if ocr_text:
            image_sections.append(f"Image OCR [{Path(media_path).name}]\n{ocr_text}")
        else:
            image_sections.append(
                f"Image OCR [{Path(media_path).name}]\nOCR text was not available in the current environment."
            )

    if not image_sections:
        return ""

    return "Embedded images:\n" + "\n\n".join(image_sections)


def _run_local_ocr(binary: bytes, name: str, warnings: list[str]) -> str:
    tesseract = shutil.which("tesseract")
    if not tesseract:
        return ""

    suffix = Path(name).suffix or ".png"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as input_file:
        input_file.write(binary)
        input_path = input_file.name

    try:
        result = subprocess.run(
            [tesseract, input_path, "stdout", "-l", "jpn+eng"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        output = (result.stdout or "").strip()
        if result.returncode == 0 and output:
            return output

        fallback = subprocess.run(
            [tesseract, input_path, "stdout"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        output = (fallback.stdout or "").strip()
        if fallback.returncode == 0 and output:
            warnings.append(f"{name}: OCR succeeded with the default Tesseract language profile.")
            return output

        stderr = (result.stderr or fallback.stderr or "").strip()
        if stderr:
            warnings.append(f"{name}: OCR failed locally: {stderr[:200]}")
        return ""
    except subprocess.TimeoutExpired:
        warnings.append(f"{name}: OCR timed out locally.")
        return ""
    finally:
        try:
            os.remove(input_path)
        except OSError:
            pass


def _numeric_suffix(path: str) -> int:
    match = re.search(r"(\d+)(?=\.xml$)", path)
    return int(match.group(1)) if match else 0
