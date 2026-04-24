"""Network boundary helpers.

This module centralizes two security-critical responsibilities:

1. Loopback-only URL validation for anything that is supposed to stay on the
   local machine (local sanitizer, local sensitivity gate). This addresses the
   review finding that the previous code accepted any URL from the environment
   and would happily send original text to a misconfigured remote host.

2. A safe HTTP client that never leaks request or response bodies into the
   exception chain. Previously, upstream error bodies were embedded verbatim
   into ``RuntimeError`` messages and propagated to the UI, which could
   surface prompt fragments or provider diagnostic text. Here, we scrub the
   exception so only a generic message reaches the caller, while optionally
   writing a truncated, redacted log entry for operators.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


LOGGER = logging.getLogger("secure_review.network")


_LOOPBACK_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback"}


class LocalUrlError(ValueError):
    """Raised when a URL that is required to be local is not."""


class UpstreamHttpError(RuntimeError):
    """Raised when an upstream HTTP call fails.

    The message is intentionally generic. Rich detail is logged separately.
    """


def validate_local_url(url: str, *, label: str = "endpoint") -> str:
    """Return the URL if it points to a loopback address, else raise.

    Accepts:
    - ``http://127.0.0.1[:port]/...``
    - ``http://[::1][:port]/...``
    - ``http://localhost[:port]/...``

    Rejects anything else, including:
    - Public IPs, private non-loopback IPs (10/8, 192.168/16, ...)
    - Arbitrary hostnames that resolve to loopback (DNS rebinding safety)
    - ``file://``, ``gopher://``, and other non-http(s) schemes
    """

    if not url or not isinstance(url, str):
        raise LocalUrlError(f"{label} URL is empty.")

    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise LocalUrlError(f"{label} URL must use http or https: {url!r}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise LocalUrlError(f"{label} URL has no host: {url!r}")

    if host in _LOOPBACK_HOSTNAMES:
        return url

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP. We refuse to resolve via DNS because a DNS record
        # could be changed to point a name like "local.example.com" at a public
        # IP. A loopback tool must be configured with a loopback literal.
        raise LocalUrlError(
            f"{label} URL host {host!r} is not a loopback literal. "
            f"Use 127.0.0.1, ::1, or localhost."
        )

    if not address.is_loopback:
        raise LocalUrlError(
            f"{label} URL host {host!r} is not a loopback address."
        )

    return url


def post_json_safely(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    *,
    timeout: int = 60,
    context_label: str = "upstream",
) -> dict[str, Any]:
    """POST JSON to ``url`` and return the parsed JSON response.

    On any failure, raises :class:`UpstreamHttpError` with a generic message.
    Detailed diagnostic information is written to the module logger with the
    request body redacted.
    """

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = _redact(exc.read().decode("utf-8", errors="replace"))
        LOGGER.warning(
            "%s HTTP %s from %s: %s",
            context_label,
            exc.code,
            _redact_url(url),
            detail[:500],
        )
        raise UpstreamHttpError(
            f"{context_label} returned HTTP {exc.code}. See server logs for details."
        ) from None
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        LOGGER.warning("%s transport error to %s: %s", context_label, _redact_url(url), exc)
        raise UpstreamHttpError(
            f"{context_label} could not be reached. See server logs for details."
        ) from None

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        LOGGER.warning(
            "%s returned invalid JSON from %s (first 200 chars): %r",
            context_label,
            _redact_url(url),
            raw[:200],
        )
        raise UpstreamHttpError(
            f"{context_label} returned invalid JSON. See server logs for details."
        ) from None


def _redact_url(url: str) -> str:
    """Strip query and fragment from a URL before logging."""
    try:
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
    except Exception:
        return "<url>"


def _redact(text: str) -> str:
    """Best-effort redaction of upstream bodies for logging.

    We never log the full body, and we drop anything that looks like a long
    quoted string (typically a prompt or document chunk).
    """

    if not text:
        return ""

    # Drop anything that looks like a long quoted literal; upstream errors
    # sometimes echo the request body here.
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if len(stripped) > 240:
            lines.append(stripped[:120] + " ...[truncated]")
        else:
            lines.append(stripped)
    joined = " | ".join(lines)
    return joined[:800]
