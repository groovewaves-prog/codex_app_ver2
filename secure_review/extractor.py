from __future__ import annotations

import base64
import csv
import html
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from secure_review.network_diagram import render_diagram_ocr_summary


LOGGER = logging.getLogger("secure_review.extractor")


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
    ".pdf",
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


# Defense against zip bombs: no single Office file we care about should
# expand past this uncompressed size.
MAX_UNCOMPRESSED_ARCHIVE_BYTES = int(os.getenv("MAX_UNCOMPRESSED_ARCHIVE_BYTES", str(200 * 1024 * 1024)))
# Upper bound on PDF pages we extract to avoid pathological inputs.
MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "300"))


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
    if extension == ".pdf":
        return _extract_pdf(binary, name, warnings), warnings
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


def _open_archive_safely(binary: bytes, name: str) -> zipfile.ZipFile | None:
    """Open a zip archive but refuse ones that look like zip bombs."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(binary))
    except zipfile.BadZipFile:
        return None

    total_uncompressed = sum(info.file_size for info in archive.infolist())
    if total_uncompressed > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
        LOGGER.warning(
            "Refused to extract %s: uncompressed size %s exceeds cap %s",
            name,
            total_uncompressed,
            MAX_UNCOMPRESSED_ARCHIVE_BYTES,
        )
        archive.close()
        raise ValueError(
            f"{name}: archive uncompressed size exceeds the safety limit "
            f"({MAX_UNCOMPRESSED_ARCHIVE_BYTES // (1024 * 1024)} MiB)."
        )
    return archive


def _extract_docx(binary: bytes, name: str, warnings: list[str]) -> str:
    try:
        archive = _open_archive_safely(binary, name)
    except ValueError as exc:
        warnings.append(str(exc))
        return ""
    if archive is None:
        warnings.append(f"{name}: DOCX archive is not a valid zip file.")
        return _decode_text(binary)

    try:
        with archive:
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
        archive = _open_archive_safely(binary, name)
    except ValueError as exc:
        warnings.append(str(exc))
        return ""
    if archive is None:
        warnings.append(f"{name}: XLSX archive is not a valid zip file.")
        return _decode_text(binary)

    try:
        with archive:
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
        archive = _open_archive_safely(binary, name)
    except ValueError as exc:
        warnings.append(str(exc))
        return ""
    if archive is None:
        warnings.append(f"{name}: PPTX archive is not a valid zip file.")
        return _decode_text(binary)

    try:
        with archive:
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


def _extract_pdf(binary: bytes, name: str, warnings: list[str]) -> str:
    """Extract text from a PDF.

    Prefers ``pypdf`` (pure Python, pip-installable). If ``pypdf`` is not
    installed and ``pdftotext`` is available on PATH, falls back to it.
    Otherwise, records a clear warning and returns a placeholder so the
    downstream sanitizer still produces a document record.
    """
    try:
        import pypdf  # type: ignore
    except ImportError:
        return _extract_pdf_via_binary(binary, name, warnings)

    try:
        reader = pypdf.PdfReader(io.BytesIO(binary))
    except Exception as exc:
        warnings.append(f"{name}: PDF could not be opened ({exc}). The raw bytes were skipped.")
        return f"# PDF: {name}\nPDF could not be parsed."

    if getattr(reader, "is_encrypted", False):
        try:
            # pypdf attempts an empty-password decrypt on some files.
            reader.decrypt("")
        except Exception:
            warnings.append(f"{name}: PDF is encrypted and cannot be read without a password.")
            return f"# PDF: {name}\nPDF is encrypted and cannot be read."

    sections: list[str] = []
    pages = reader.pages
    page_count = len(pages)
    limit = min(page_count, MAX_PDF_PAGES)

    for index in range(limit):
        try:
            text = pages[index].extract_text() or ""
        except Exception as exc:
            warnings.append(f"{name}: page {index + 1} text extraction failed ({exc}).")
            continue
        text = text.strip()
        if text:
            sections.append(f"# Page {index + 1}\n{text}")

    if page_count > MAX_PDF_PAGES:
        warnings.append(
            f"{name}: PDF has {page_count} pages; only the first {MAX_PDF_PAGES} were extracted. "
            "Split the file if the tail contains content that needs review."
        )

    if not sections:
        warnings.append(
            f"{name}: No text extracted from PDF. It may be a scanned image; consider OCR before review."
        )
        return f"# PDF: {name}\nNo text content extracted. The file may be a scanned image."

    return "\n\n".join(sections)


def _extract_pdf_via_binary(binary: bytes, name: str, warnings: list[str]) -> str:
    """Fall back to the ``pdftotext`` CLI if pypdf is unavailable."""
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        warnings.append(
            f"{name}: PDF extraction is unavailable (install `pypdf` with `pip install pypdf`). "
            "The file was recorded but not read."
        )
        return f"# PDF: {name}\nPDF detected. Install pypdf to enable text extraction."

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as input_file:
        input_file.write(binary)
        input_path = input_file.name

    try:
        result = subprocess.run(
            [pdftotext, "-layout", "-enc", "UTF-8", input_path, "-"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        output = (result.stdout or "").strip()
        if result.returncode != 0 or not output:
            stderr = (result.stderr or "").strip()
            warnings.append(f"{name}: pdftotext failed: {stderr[:200]}")
            return f"# PDF: {name}\nPDF could not be parsed by pdftotext."
        return f"# PDF: {name}\n{output}"
    except subprocess.TimeoutExpired:
        warnings.append(f"{name}: pdftotext timed out.")
        return f"# PDF: {name}\nPDF extraction timed out."
    finally:
        try:
            os.remove(input_path)
        except OSError:
            pass


def _extract_image(binary: bytes, name: str, warnings: list[str]) -> str:
    ocr_text = _run_local_ocr(binary, name, warnings)
    if ocr_text:
        return _format_image_ocr_text(name, ocr_text)

    warnings.append(
        f"{name}: Local OCR is unavailable, so only the file presence was recorded. Install Tesseract for image text extraction."
    )
    return f"# Image: {name}\nImage detected. OCR text was not available in the current environment."


def _format_image_ocr_text(name: str, ocr_text: str) -> str:
    diagram_summary = render_diagram_ocr_summary(ocr_text)
    return (
        f"# Image: {name}\n"
        f"{diagram_summary}\n\n"
        "## OCR text\n"
        f"{ocr_text}"
    )


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
            image_sections.append(
                f"Image OCR [{Path(media_path).name}]\n"
                f"{render_diagram_ocr_summary(ocr_text)}\n\n"
                "OCR text:\n"
                f"{ocr_text}"
            )
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
    # Guard against odd extensions leaking into subprocess metadata.
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix):
        suffix = ".png"

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
