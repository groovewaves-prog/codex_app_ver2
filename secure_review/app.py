from __future__ import annotations

import json
import logging
import mimetypes
import os
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from secure_review.extractor import extract_text
from secure_review.models import SanitizedDocument, UploadedDocument
from secure_review.network_guard import LocalUrlError
from secure_review.reviewer import choose_provider
from secure_review.sanitizer import SensitiveDataSanitizer, choose_local_sanitization_enhancer
from secure_review.sensitivity import choose_sensitivity_classifier


LOGGER = logging.getLogger("secure_review.app")


ROOT_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT_DIR / "static"
STATIC_ROOT = STATIC_DIR.resolve()
SAFE_TOTAL_INPUT_TOKENS = 8_000
SAFE_DOCUMENT_INPUT_TOKENS = 3_000
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", str(64 * 1024 * 1024)))
REQUIRE_MASK_AND_CONTINUE_CONFIRM = os.getenv("MASK_AND_CONTINUE_REQUIRE_CONFIRM", "true").lower() != "false"
_SENSITIVITY_DECISION_LABELS = {
    "safe": "安全",
    "mask_and_continue": "要確認",
    "block": "送信禁止",
    "unknown": "未判定",
}


class ReviewRequestHandler(BaseHTTPRequestHandler):
    server_version = "SecureReview/0.2"

    # ------------------------------------------------------------------ GET

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

    # ----------------------------------------------------------------- POST

    def do_POST(self) -> None:  # noqa: N802
        request_id = uuid.uuid4().hex[:8]
        try:
            if self.path == "/api/preview":
                self._handle_preview(request_id)
                return
            if self.path == "/api/review":
                self._handle_review(request_id)
                return
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            # ValueError carries a user-safe message (validation).
            self._send_json({"error": str(exc), "request_id": request_id}, status=HTTPStatus.BAD_REQUEST)
        except LocalUrlError as exc:
            LOGGER.error("[%s] Local URL rejected: %s", request_id, exc)
            self._send_json(
                {
                    "error": (
                        "A local-only endpoint was configured with a non-loopback URL. "
                        "Check LOCAL_SANITIZER_API_URL and LOCAL_SENSITIVITY_API_URL."
                    ),
                    "request_id": request_id,
                },
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        except Exception as exc:  # noqa: BLE001
            # Never expose exception text to the client.
            LOGGER.exception("[%s] Request failed", request_id)
            self._send_json(
                {
                    "error": "Review processing failed. See server logs for details.",
                    "request_id": request_id,
                    # A short category helps the UI without revealing specifics.
                    "error_type": type(exc).__name__,
                },
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    # ------------------------------------------------------------ handlers

    def _handle_preview(self, request_id: str) -> None:
        request_json = self._read_json_body()
        documents = self._parse_uploaded_documents(request_json)
        document_profile_override = request_json.get("documentProfile")

        sanitized_documents, extraction_warnings = _run_sanitization_pipeline(documents)

        response = {
            "request_id": request_id,
            "status": _status_for(sanitized_documents),
            "documents": [item.to_dict() for item in sanitized_documents],
            "warnings": extraction_warnings,
            "security": _security_summary(sanitized_documents),
            "document_profile_hint": document_profile_override or "",
        }
        LOGGER.info(
            "[%s] preview complete: status=%s docs=%s",
            request_id,
            response["status"],
            len(sanitized_documents),
        )
        self._send_json(response)

    def _handle_review(self, request_id: str) -> None:
        request_json = self._read_json_body()
        documents = self._parse_uploaded_documents(request_json)
        document_profile_override = request_json.get("documentProfile")
        confirm_flag = bool(request_json.get("confirmMaskAndContinue", False))
        # Per-document confirmations: {doc_name: true}
        doc_confirmations = request_json.get("documentConfirmations") or {}
        if not isinstance(doc_confirmations, dict):
            doc_confirmations = {}

        sanitized_documents, extraction_warnings = _run_sanitization_pipeline(documents)

        # Always refuse block.
        self._enforce_block_gate(sanitized_documents)

        # Anything other than an explicit safe/block decision requires confirmation.
        if REQUIRE_MASK_AND_CONTINUE_CONFIRM:
            needs_confirm = [
                document.name
                for document in sanitized_documents
                if _requires_confirmation(document)
                and not (confirm_flag or bool(doc_confirmations.get(document.name)))
            ]
            if needs_confirm:
                response = {
                    "request_id": request_id,
                    "status": "confirmation_required",
                    "documents_requiring_confirmation": needs_confirm,
                    "documents": [item.to_dict() for item in sanitized_documents],
                    "warnings": extraction_warnings,
                    "security": _security_summary(sanitized_documents),
                }
                LOGGER.info(
                    "[%s] review blocked pending confirmation: %s",
                    request_id,
                    needs_confirm,
                )
                self._send_json(response, status=HTTPStatus.CONFLICT)
                return

        provider = choose_provider()
        _enforce_outbound_guard(provider.name, sanitized_documents)
        extraction_warnings.extend(_build_volume_warnings(sanitized_documents))
        review = provider.review(sanitized_documents, document_profile_override)
        if review.classification_confidence == "low":
            extraction_warnings.append(
                "Document classification confidence is low. Consider specifying documentProfile explicitly if the review focus should be source_code, network_config, design, proposal, change_runbook, or operations_runbook."
            )

        response = {
            "request_id": request_id,
            "status": "ok",
            "documents": [item.to_dict() for item in sanitized_documents],
            "review": review.to_dict(),
            "warnings": extraction_warnings,
            "security": _security_summary(sanitized_documents),
        }
        LOGGER.info(
            "[%s] review complete: provider=%s issues=%s",
            request_id,
            review.provider,
            len(review.issues),
        )
        self._send_json(response)

    # ---------------------------------------------------------------- utils

    def _read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > MAX_REQUEST_BYTES:
            raise ValueError(
                f"Request body is too large ({content_length} bytes). "
                f"Limit is {MAX_REQUEST_BYTES} bytes."
            )
        raw = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("Request body is not valid JSON.") from None

    def _parse_uploaded_documents(self, request_json: dict[str, Any]) -> list[UploadedDocument]:
        documents = request_json.get("documents", [])
        if not isinstance(documents, list) or not documents:
            raise ValueError("At least one file is required.")

        uploaded = [
            UploadedDocument(
                name=str(item.get("name", "untitled.txt")),
                content=item.get("content", "") or "",
                content_type=str(item.get("contentType", "text/plain")),
                transfer_encoding=str(item.get("transferEncoding", "text")),
            )
            for item in documents
            if isinstance(item, dict)
        ]
        if not uploaded:
            raise ValueError("At least one file is required.")
        return uploaded

    @staticmethod
    def _enforce_block_gate(sanitized_documents: list[SanitizedDocument]) -> None:
        blocked = [
            document.name
            for document in sanitized_documents
            if document.local_sensitivity_decision == "block" or document.outbound_risk == "high"
        ]
        if blocked:
            raise ValueError(
                "Outbound review was blocked because the local gate flagged the following file(s): "
                + ", ".join(blocked)
                + ". Prepare a more strongly sanitized copy first."
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
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


# -------------------------------------------------------- pipeline helpers

def _run_sanitization_pipeline(
    uploaded: list[UploadedDocument],
) -> tuple[list[SanitizedDocument], list[str]]:
    sanitizer = SensitiveDataSanitizer()
    local_sanitizer = choose_local_sanitization_enhancer()
    sensitivity_classifier = choose_sensitivity_classifier()

    sanitized_documents: list[SanitizedDocument] = []
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
        sanitized = local_sanitizer.enhance(
            document.name,
            extracted_text,
            sanitized,
            sanitizer,
        )
        assessment = sensitivity_classifier.assess(document.name, extracted_text, sanitized)
        sanitized.local_sensitivity_decision = assessment.decision
        sanitized.local_sensitivity_reasons = assessment.reasons
        sanitized.local_sensitivity_provider = assessment.provider
        _append_unique_findings(
            sanitized,
            [
                _format_local_sensitivity_finding(assessment.decision, reason)
                for reason in assessment.reasons
            ],
        )
        if assessment.decision == "mask_and_continue":
            extraction_warnings.extend(
                f"{document.name}: local sensitivity gate recommends more masking. {action}"
                for action in assessment.recommended_actions
            )
        sanitized_documents.append(sanitized)

    return sanitized_documents, extraction_warnings


def _format_local_sensitivity_finding(decision: str, reason: str) -> str:
    label = _SENSITIVITY_DECISION_LABELS.get(decision, decision or "未判定")
    return f"ローカル機密度ゲート: {label}. {reason}"


def _append_unique_findings(
    sanitized: SanitizedDocument,
    findings: list[str],
) -> None:
    """Append findings without repeating identical UI messages."""
    seen = {str(item).strip() for item in sanitized.findings if str(item).strip()}
    for finding in findings:
        text = str(finding).strip()
        if text and text not in seen:
            sanitized.findings.append(text)
            seen.add(text)


def _status_for(sanitized_documents: list[SanitizedDocument]) -> str:
    decisions = {doc.local_sensitivity_decision for doc in sanitized_documents}
    if "block" in decisions or any(doc.outbound_risk == "high" for doc in sanitized_documents):
        return "blocked"
    if any(_requires_confirmation(doc) for doc in sanitized_documents):
        return "confirmation_required"
    return "safe"


def _requires_confirmation(document: SanitizedDocument) -> bool:
    decision = document.local_sensitivity_decision or "unknown"
    return decision != "safe" and decision != "block"


def _security_summary(sanitized_documents: list[SanitizedDocument]) -> dict[str, Any]:
    return {
        "message": (
            "Only sanitized text is sent to the LLM layer. "
            "Raw text and replacement maps stay in server memory only."
        ),
        "replacements": sum(len(doc.replacements) for doc in sanitized_documents),
        "max_outbound_risk": _max_outbound_risk(sanitized_documents),
        "estimated_input_tokens": sum(doc.estimated_input_tokens for doc in sanitized_documents),
        "local_sanitizer_provider": (
            next(
                (doc.local_sanitizer_provider for doc in sanitized_documents if doc.local_sanitizer_provider),
                "",
            )
        ),
        "local_sensitivity_provider": (
            next(
                (doc.local_sensitivity_provider for doc in sanitized_documents if doc.local_sensitivity_provider),
                "",
            )
        ),
    }


def _build_volume_warnings(sanitized_documents: list[SanitizedDocument]) -> list[str]:
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


def _enforce_outbound_guard(provider_name: str, sanitized_documents: list[SanitizedDocument]) -> None:
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


def _max_outbound_risk(sanitized_documents: list[SanitizedDocument]) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    highest = "low"
    for document in sanitized_documents:
        if order.get(document.outbound_risk, 0) > order[highest]:
            highest = document.outbound_risk
    return highest


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    server = ThreadingHTTPServer((host, port), ReviewRequestHandler)
    print(f"Secure review app listening on http://{host}:{port}")
    server.serve_forever()
