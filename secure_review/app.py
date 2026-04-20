from __future__ import annotations

import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from secure_review.extractor import extract_text
from secure_review.models import UploadedDocument
from secure_review.reviewer import choose_provider
from secure_review.sanitizer import SensitiveDataSanitizer


ROOT_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT_DIR / "static"
STATIC_ROOT = STATIC_DIR.resolve()


class ReviewRequestHandler(BaseHTTPRequestHandler):
    server_version = "SecureReview/0.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return

        if self.path.startswith("/static/"):
            relative_path = self.path.removeprefix("/static/")
            file_path = (STATIC_DIR / relative_path).resolve()
            if file_path.is_file() and STATIC_ROOT in file_path.parents:
                content_type, _ = mimetypes.guess_type(str(file_path))
                self._serve_file(file_path, content_type or "application/octet-stream")
                return

        self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/review":
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_length).decode("utf-8")
            request_json = json.loads(payload)
            documents = request_json.get("documents", [])
            uploaded = [
                UploadedDocument(
                    name=item.get("name", "untitled.txt"),
                    content=item.get("content", ""),
                    content_type=item.get("contentType", "text/plain"),
                )
                for item in documents
            ]
            if not uploaded:
                self._send_json(
                    {"error": "At least one file is required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            sanitizer = SensitiveDataSanitizer()
            sanitized_documents = []
            extraction_warnings: list[str] = []

            for document in uploaded:
                extracted_text, warnings = extract_text(document.name, document.content)
                extraction_warnings.extend(warnings)
                sanitized_documents.append(sanitizer.sanitize(document.name, extracted_text))

            review = choose_provider().review(sanitized_documents)

            response = {
                "documents": [item.to_dict() for item in sanitized_documents],
                "review": review.to_dict(),
                "warnings": extraction_warnings,
                "security": {
                    "message": (
                        "Only sanitized text is sent to the LLM layer. "
                        "Raw text and replacement maps stay in server memory only."
                    ),
                    "replacements": sum(len(doc.replacements) for doc in sanitized_documents),
                },
            }
            self._send_json(response)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # noqa: BLE001
            self._send_json(
                {"error": f"Review processing failed: {exc}"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _serve_file(self, file_path: Path, content_type: str) -> None:
        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), ReviewRequestHandler)
    print(f"Secure review app listening on http://{host}:{port}")
    server.serve_forever()
