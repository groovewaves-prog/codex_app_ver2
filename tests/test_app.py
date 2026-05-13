import base64
import json
import os
import unittest
from http import HTTPStatus
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import threading

from http.server import ThreadingHTTPServer

from secure_review.app import ReviewRequestHandler
from secure_review.models import SanitizedDocument


def _start_test_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReviewRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, f"http://{host}:{port}"


def _post(url, payload):
    req = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _doc(name, text):
    return {
        "name": name,
        "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
        "contentType": "text/plain",
        "transferEncoding": "base64",
    }


class AppIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server, self.thread, self.base = _start_test_server()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_preview_returns_sanitization_without_calling_provider(self) -> None:
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True):
            code, body = _post(
                self.base + "/api/preview",
                {"documents": [_doc("router.cfg", "interface Gi0/1\nip address 10.0.0.1 255.0.0.0")]},
            )
        self.assertEqual(code, HTTPStatus.OK)
        self.assertEqual(body["status"], "safe")
        self.assertIn("documents", body)
        self.assertEqual(len(body["documents"]), 1)
        self.assertNotIn("review", body)

    def test_review_safe_document_succeeds(self) -> None:
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True):
            code, body = _post(
                self.base + "/api/review",
                {"documents": [_doc("router.cfg", "interface Gi0/1\nip address 10.0.0.1 255.0.0.0")]},
            )
        self.assertEqual(code, HTTPStatus.OK)
        self.assertEqual(body["status"], "ok")
        self.assertIn("review", body)

    def test_review_blocks_on_explicit_confidentiality_marker(self) -> None:
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True):
            code, body = _post(
                self.base + "/api/review",
                {
                    "documents": [
                        _doc(
                            "change.md",
                            "社外秘\n顧客名: 株式会社サンプル\n案件名: 次期NW更改",
                        )
                    ]
                },
            )
        # 社外秘 triggers heuristic=block which raises ValueError -> 400.
        self.assertEqual(code, HTTPStatus.BAD_REQUEST)
        self.assertIn("blocked", body["error"].lower())

    def test_review_requires_confirmation_for_mask_and_continue(self) -> None:
        """R2: mask_and_continue must not silently pass through."""
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True):
            # Text that triggers mask_and_continue via heuristic.
            code, body = _post(
                self.base + "/api/review",
                {
                    "documents": [
                        _doc(
                            "runbook.md",
                            "担当者: Alice\nプロジェクト名: MigrationX",
                        )
                    ]
                },
            )
        self.assertEqual(code, HTTPStatus.CONFLICT)
        self.assertEqual(body["status"], "confirmation_required")
        self.assertIn("runbook.md", body["documents_requiring_confirmation"])

    def test_review_requires_confirmation_for_unknown_sensitivity(self) -> None:
        """Unknown sensitivity must not be treated as safe."""
        sanitized = SanitizedDocument(
            name="unknown.md",
            original_excerpt="content",
            sanitized_excerpt="content",
            outbound_text="content",
            local_sensitivity_decision="unknown",
        )
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True), \
             patch("secure_review.app._run_sanitization_pipeline", return_value=([sanitized], [])):
            code, body = _post(
                self.base + "/api/review",
                {"documents": [_doc("unknown.md", "content")]},
            )
        self.assertEqual(code, HTTPStatus.CONFLICT)
        self.assertEqual(body["status"], "confirmation_required")
        self.assertIn("unknown.md", body["documents_requiring_confirmation"])

    def test_review_proceeds_after_confirmation(self) -> None:
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True):
            code, body = _post(
                self.base + "/api/review",
                {
                    "documents": [
                        _doc(
                            "runbook.md",
                            "担当者: Alice\nプロジェクト名: MigrationX",
                        )
                    ],
                    "confirmMaskAndContinue": True,
                },
            )
        self.assertEqual(code, HTTPStatus.OK)
        self.assertEqual(body["status"], "ok")

    def test_per_document_confirmations_gate_partial(self) -> None:
        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True):
            code, body = _post(
                self.base + "/api/review",
                {
                    "documents": [
                        _doc("a.md", "担当者: Alice\nプロジェクト名: X"),
                        _doc("b.md", "generic content only"),
                    ],
                    "documentConfirmations": {"a.md": True},
                },
            )
        # a.md is confirmed, b.md is heuristic=safe, so review should proceed.
        self.assertEqual(code, HTTPStatus.OK)

    def test_error_response_does_not_leak_exception_details(self) -> None:
        """R3: internal exceptions must produce generic messages."""

        def boom(*args, **kwargs):
            raise RuntimeError("internal detail with sensitive prompt echo")

        with patch.dict(os.environ, {"REVIEW_PROVIDER": "mock"}, clear=True), \
             patch("secure_review.app._run_sanitization_pipeline", side_effect=boom):
            code, body = _post(
                self.base + "/api/review",
                {"documents": [_doc("x.md", "abc")]},
            )
        self.assertEqual(code, HTTPStatus.INTERNAL_SERVER_ERROR)
        self.assertNotIn("sensitive prompt echo", body.get("error", ""))
        self.assertIn("request_id", body)


if __name__ == "__main__":
    unittest.main()
