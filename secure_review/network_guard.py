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
import os
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

    課題 2 改修 (2026-05-08):
        retryable と status_code 属性を追加し、上位の呼び出し側 (例: GeminiApiReviewProvider)
        がリトライ判定に使えるようにする。
        - status_code: HTTP ステータスコード (transport error の場合は None)
        - retryable: リトライすれば成功する可能性があるか
            * HTTP 503/504/429 → True (一時的な問題)
            * HTTP 500/502 → True (サーバ側エラー、たまに復旧する)
            * HTTP 4xx (上記以外) → False (恒久的な問題、リクエスト側が悪い)
            * transport error (timeout, connection refused, ...) → True
            * JSON parse error → False (サーバ応答の構造問題、リトライしても同じ)
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = True,
    ) -> None:
        # レビュー後修正 (2026-05-08): デフォルト retryable=True に変更。
        # 理由: 旧スタイル UpstreamHttpError("msg") (status_code/retryable なしで raise)
        #       との後方互換性。旧コードは「失敗したらとりあえずリトライ」前提だった。
        #       既存テスト test_retry_once_then_raise_on_transport_error 互換性のため、
        #       明示的に retryable=False と指定しない限りリトライ対象とする。
        # 新規 raise 箇所 (post_json_safely 内) は明示的に True/False をセットしているので
        # デフォルト変更の影響は受けない。
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


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


# 課題 2 改修 (2026-05-08): リトライ可能な HTTP ステータスコード集合
# - 429 Too Many Requests: レート制限、待てば解消
# - 500 Internal Server Error: サーバ側の一時的問題
# - 502 Bad Gateway: 上流ゲートウェイ問題
# - 503 Service Unavailable: 高負荷など、Gemini ログでも観測
# - 504 Gateway Timeout: 上流タイムアウト
_RETRYABLE_HTTP_STATUS = {429, 500, 502, 503, 504}


def _resolve_default_timeout() -> int:
    """環境変数 LLM_HTTP_TIMEOUT があれば優先、なければデフォルト 60 秒。

    課題 2 改修 (2026-05-08): chunking 後の単一 call の応答時間に余裕を持たせる
    + 環境ごとに調整可能 (Streamlit Cloud は遅いことがある)。
    """
    raw = os.getenv("LLM_HTTP_TIMEOUT", "").strip()
    if not raw:
        return 60
    try:
        value = int(raw)
        if value < 5 or value > 600:
            LOGGER.warning(
                "LLM_HTTP_TIMEOUT=%s is out of range [5, 600], using default 60",
                raw,
            )
            return 60
        return value
    except ValueError:
        LOGGER.warning("LLM_HTTP_TIMEOUT=%r is not an integer, using default 60", raw)
        return 60


def post_json_safely(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    *,
    timeout: int | None = None,
    context_label: str = "upstream",
) -> dict[str, Any]:
    """POST JSON to ``url`` and return the parsed JSON response.

    On any failure, raises :class:`UpstreamHttpError` with a generic message.
    Detailed diagnostic information is written to the module logger with the
    request body redacted.

    課題 2 改修 (2026-05-08):
        - timeout=None の場合、環境変数 LLM_HTTP_TIMEOUT で制御可能に。
        - UpstreamHttpError に status_code と retryable を設定し、上位がリトライ判定で使える。
    """

    if timeout is None:
        timeout = _resolve_default_timeout()

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
        # 課題 2 改修: HTTP ステータスに基づく retryable 判定
        retryable = exc.code in _RETRYABLE_HTTP_STATUS
        raise UpstreamHttpError(
            f"{context_label} returned HTTP {exc.code}. See server logs for details.",
            status_code=exc.code,
            retryable=retryable,
        ) from None
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        LOGGER.warning("%s transport error to %s: %s", context_label, _redact_url(url), exc)
        # 課題 2 改修: transport error はリトライ可能 (一時的なネットワーク問題)
        raise UpstreamHttpError(
            f"{context_label} could not be reached. See server logs for details.",
            status_code=None,
            retryable=True,
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
        # 課題 2 改修: JSON パース失敗はリトライしても同じ結果になる可能性が高い
        raise UpstreamHttpError(
            f"{context_label} returned invalid JSON. See server logs for details.",
            status_code=None,
            retryable=False,
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
