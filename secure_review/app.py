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
from secure_review.sensitivity import choose_sensitivity_classifier


ROOT_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT_DIR / "static"
STATIC_ROOT = STATIC_DIR.resolve()
SAFE_TOTAL_INPUT_TOKENS = 8_000
SAFE_DOCUMENT_INPUT_TOKENS = 3_000


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
            document_profile_override = request_json.get("documentProfile")
            uploaded = [
                UploadedDocument(
                    name=item.get("name", "untitled.txt"),
                    content=item.get("content", ""),
                    content_type=item.get("contentType", "text/plain"),
                    transfer_encoding=item.get("transferEncoding", "text"),
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
            sensitivity_classifier = choose_sensitivity_classifier()
            sanitized_documents = []
            extraction_warnings: list[str] = []

            for document in uploaded:
                extracted_text, warnings = extract_text(
                    document.name,
                    document.content,
                    document.content_type,
                    document.transfer_encoding,
                )
                extraction_warnings.extend(warnings)
                sanitized = sanitizer.sanitize(document.name, extracted_text)
                assessment = sensitivity_classifier.assess(document.name, extracted_text, sanitized)
                sanitized.local_sensitivity_decision = assessment.decision
                sanitized.local_sensitivity_reasons = assessment.reasons
                sanitized.local_sensitivity_provider = assessment.provider
                sanitized.findings.extend(
                    [f"Local sensitivity gate: {assessment.decision}. {reason}" for reason in assessment.reasons]
                )
                extraction_warnings.extend(
                    [
                        f"{document.name}: local sensitivity gate recommends more masking. {action}"
                        for action in assessment.recommended_actions
                    ]
                    if assessment.decision == "mask_and_continue"
                    else []
                )
                sanitized_documents.append(sanitized)

            provider = choose_provider()
            self._enforce_outbound_guard(provider.name, sanitized_documents)
            extraction_warnings.extend(self._build_volume_warnings(sanitized_documents))
            review = provider.review(sanitized_documents, document_profile_override)
            if review.classification_confidence == "low":
                extraction_warnings.append(
                    "Document classification confidence is low. Consider specifying documentProfile explicitly if the review focus should be source_code, design, change_runbook, or operations_runbook."
                )

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
                    "max_outbound_risk": self._max_outbound_risk(sanitized_documents),
                    "estimated_input_tokens": sum(
                        doc.estimated_input_tokens for doc in sanitized_documents
                    ),
                    "local_sensitivity_provider": sensitivity_classifier.name,
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

    @staticmethod
    def _build_volume_warnings(sanitized_documents: list) -> list[str]:
        warnings: list[str] = []
        total_tokens = sum(doc.estimated_input_tokens for doc in sanitized_documents)

        if total_tokens > SAFE_TOTAL_INPUT_TOKENS:
            warnings.append(
                "Estimated outbound input exceeds the conservative 8,000-token review budget. "
                "Split the review by chapter or create a review_handoff.md before continuing."
            )

        for document in sanitized_documents:
            if document.estimated_input_tokens > SAFE_DOCUMENT_INPUT_TOKENS:
                warnings.append(
                    f"{document.name}: Estimated outbound input exceeds the conservative 3,000-token-per-document budget. "
                    "Consider reviewing this file in smaller sections."
                )

        return warnings

    @staticmethod
    def _enforce_outbound_guard(provider_name: str, sanitized_documents: list) -> None:
        if provider_name == "mock":
            return

        risky_documents = [
            document.name
            for document in sanitized_documents
            if document.outbound_risk == "high" or document.local_sensitivity_decision == "block"
        ]
        if risky_documents:
            joined = ", ".join(risky_documents)
            raise ValueError(
                "Outbound review was blocked because explicit confidentiality markers were detected "
                f"in the following file(s): {joined}. Please prepare a more strongly sanitized copy first."
            )

    @staticmethod
    def _max_outbound_risk(sanitized_documents: list) -> str:
        order = {"low": 0, "medium": 1, "high": 2}
        highest = "low"
        for document in sanitized_documents:
            if order.get(document.outbound_risk, 0) > order[highest]:
                highest = document.outbound_risk
        return highest


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), ReviewRequestHandler)
    print(f"Secure review app listening on http://{host}:{port}")
    server.serve_forever()
