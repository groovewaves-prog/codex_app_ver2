import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from secure_review.network_guard import (
    LocalUrlError,
    UpstreamHttpError,
    post_json_safely,
    validate_local_url,
)


class ValidateLocalUrlTests(unittest.TestCase):
    def test_accepts_ipv4_loopback(self) -> None:
        self.assertEqual(
            validate_local_url("http://127.0.0.1:11434/v1/responses"),
            "http://127.0.0.1:11434/v1/responses",
        )

    def test_accepts_ipv6_loopback(self) -> None:
        self.assertEqual(
            validate_local_url("http://[::1]:8080/api"),
            "http://[::1]:8080/api",
        )

    def test_accepts_localhost_hostname(self) -> None:
        self.assertEqual(
            validate_local_url("http://localhost:11434/v1"),
            "http://localhost:11434/v1",
        )

    def test_rejects_public_hostname(self) -> None:
        with self.assertRaises(LocalUrlError):
            validate_local_url("http://example.com/v1", label="test")

    def test_rejects_rfc1918_private_ip(self) -> None:
        # Private but non-loopback IPs must still be refused.
        with self.assertRaises(LocalUrlError):
            validate_local_url("http://192.168.1.1/v1")
        with self.assertRaises(LocalUrlError):
            validate_local_url("http://10.0.0.1/v1")

    def test_rejects_non_http_schemes(self) -> None:
        with self.assertRaises(LocalUrlError):
            validate_local_url("file:///etc/passwd")
        with self.assertRaises(LocalUrlError):
            validate_local_url("ftp://127.0.0.1/")

    def test_rejects_empty_url(self) -> None:
        with self.assertRaises(LocalUrlError):
            validate_local_url("")

    def test_rejects_hostname_that_is_not_loopback_literal(self) -> None:
        # Even if an attacker's DNS record points to 127.0.0.1, we still
        # refuse because we do not resolve at all — configure a literal.
        with self.assertRaises(LocalUrlError):
            validate_local_url("http://evil.internal/v1")


class PostJsonSafelyTests(unittest.TestCase):
    def test_http_error_does_not_leak_body(self) -> None:
        """R3: upstream body must not surface in the raised exception."""
        error = urllib.error.HTTPError(
            "http://127.0.0.1:11434/v1/responses",
            500,
            "Internal Server Error",
            {},
            io.BytesIO(b"sensitive prompt echo: 'customer Acme Corp password123'"),
        )

        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(UpstreamHttpError) as ctx:
                post_json_safely(
                    "http://127.0.0.1:11434/v1/responses",
                    {"model": "x"},
                    {"Content-Type": "application/json"},
                    context_label="test",
                )

        message = str(ctx.exception)
        self.assertNotIn("Acme", message)
        self.assertNotIn("password123", message)
        self.assertNotIn("prompt echo", message)
        self.assertIn("HTTP 500", message)

    def test_timeout_raises_generic_error(self) -> None:
        with patch("urllib.request.urlopen", side_effect=TimeoutError("conn timed out")):
            with self.assertRaises(UpstreamHttpError) as ctx:
                post_json_safely(
                    "http://127.0.0.1:11434/v1/responses",
                    {},
                    {},
                    context_label="test",
                )
        self.assertIn("could not be reached", str(ctx.exception))

    def test_invalid_json_response_is_generic(self) -> None:
        class FakeResponse:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *args):
                return False

            def read(self_inner):
                return b"not json at all"

        with patch("urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(UpstreamHttpError) as ctx:
                post_json_safely(
                    "http://127.0.0.1:11434/v1/responses",
                    {},
                    {},
                    context_label="test",
                )
        self.assertIn("invalid JSON", str(ctx.exception))

    def test_successful_response_returns_parsed_json(self) -> None:
        class FakeResponse:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *args):
                return False

            def read(self_inner):
                return json.dumps({"output_text": "hello"}).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=FakeResponse()):
            result = post_json_safely(
                "http://127.0.0.1:11434/v1/responses",
                {"model": "x"},
                {},
                context_label="test",
            )
        self.assertEqual(result, {"output_text": "hello"})


if __name__ == "__main__":
    unittest.main()
