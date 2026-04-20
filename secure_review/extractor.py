from __future__ import annotations

import csv
import html
import io
import json
import re
import zipfile
from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".txt",
    ".md",
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
}


def extract_text(name: str, raw_text: str) -> tuple[str, list[str]]:
    extension = Path(name).suffix.lower()
    warnings: list[str] = []

    if extension not in SUPPORTED_EXTENSIONS:
        warnings.append(
            f"{name}: このMVPでは {extension or '拡張子なし'} は未対応です。"
        )
        return raw_text, warnings

    if extension == ".json":
        return _format_json(raw_text, name, warnings), warnings
    if extension in {".html", ".htm", ".xml"}:
        return _strip_markup(raw_text), warnings
    if extension == ".csv":
        return _format_csv(raw_text, name, warnings), warnings
    if extension == ".docx":
        return _extract_docx(raw_text, name, warnings), warnings

    return raw_text, warnings


def _format_json(raw_text: str, name: str, warnings: list[str]) -> str:
    try:
        parsed = json.loads(raw_text)
        return json.dumps(parsed, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        warnings.append(f"{name}: JSONとして解釈できなかったため、そのまま扱います。")
        return raw_text


def _format_csv(raw_text: str, name: str, warnings: list[str]) -> str:
    try:
        reader = csv.reader(io.StringIO(raw_text))
        lines = [" | ".join(row) for row in reader]
        return "\n".join(lines)
    except csv.Error:
        warnings.append(f"{name}: CSVとして解釈できなかったため、そのまま扱います。")
        return raw_text


def _strip_markup(raw_text: str) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", raw_text, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_docx(raw_text: str, name: str, warnings: list[str]) -> str:
    try:
        docx_bytes = raw_text.encode("latin1")
        with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8", errors="ignore")
        text = re.sub(r"<[^>]+>", " ", document_xml)
        text = html.unescape(text)
        return re.sub(r"\s+", " ", text).strip()
    except Exception:
        warnings.append(f"{name}: DOCX解析に失敗したため、そのまま扱います。")
        return raw_text
