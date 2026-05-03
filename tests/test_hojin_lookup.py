"""R-M PR-C: HojinLookup のテスト。

ネットワーク I/O は urllib.request.urlopen をモックする。
実 API は呼ばない (handoff: API 検証は本日のセッション初期に PR #22 で
別途確認済み)。
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch
from urllib import error as urllib_error

from secure_review.hojin_lookup import HojinLookup


def _mock_response(payload: dict, status: int = 200) -> MagicMock:
    """urlopen のコンテキストマネージャ戻り値をモックする。"""
    body = json.dumps(payload).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = body
    resp.status = status
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class HojinLookupSearchTests(unittest.TestCase):
    """正常系: API 応答のパース。"""

    def test_successful_search_extracts_hits_and_top_names(self) -> None:
        payload = {
            "hojin-infos": [
                {"name": "株式会社アイレット"},
                {"name": "KDDIアイレット株式会社"},
                {"name": "アイレット工業株式会社"},
            ]
        }
        client = HojinLookup(api_token="dummy")
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            return_value=_mock_response(payload),
        ):
            result = client.search("アイレット")

        self.assertEqual(result.hits, 3)
        self.assertEqual(len(result.top_names), 3)
        self.assertIn("株式会社アイレット", result.top_names)
        self.assertEqual(result.error, "")
        self.assertFalse(result.cached)

    def test_zero_hits_returns_empty_top_names(self) -> None:
        client = HojinLookup(api_token="dummy")
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            return_value=_mock_response({"hojin-infos": []}),
        ):
            result = client.search("ZZZNONEXISTENT")
        self.assertEqual(result.hits, 0)
        self.assertEqual(result.top_names, [])
        self.assertEqual(result.error, "")

    def test_top_names_capped_by_max_top_names(self) -> None:
        payload = {"hojin-infos": [{"name": f"company_{i}"} for i in range(20)]}
        client = HojinLookup(api_token="dummy", max_top_names=5)
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            return_value=_mock_response(payload),
        ):
            result = client.search("X")
        self.assertEqual(result.hits, 20)  # ヒット件数は全件
        self.assertEqual(len(result.top_names), 5)  # top_names のみ制限


class HojinLookupCacheTests(unittest.TestCase):
    """in-memory キャッシュ。"""

    def test_second_call_with_same_name_is_cached(self) -> None:
        client = HojinLookup(api_token="dummy")
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            return_value=_mock_response({"hojin-infos": [{"name": "X"}]}),
        ) as mock_open:
            r1 = client.search("KDDI")
            r2 = client.search("KDDI")

        self.assertEqual(mock_open.call_count, 1)  # 2 回目は API 呼ばない
        self.assertFalse(r1.cached)
        self.assertTrue(r2.cached)
        self.assertEqual(r1.hits, r2.hits)

    def test_different_names_are_not_confused(self) -> None:
        client = HojinLookup(api_token="dummy")
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            return_value=_mock_response({"hojin-infos": [{"name": "X"}]}),
        ) as mock_open:
            client.search("KDDI")
            client.search("NTT")
        self.assertEqual(mock_open.call_count, 2)


class HojinLookupErrorHandlingTests(unittest.TestCase):
    """異常系: 例外を呼び出し側に投げず LookupResult.error に格納する。"""

    def test_missing_api_token_returns_error_result(self) -> None:
        client = HojinLookup(api_token="")
        result = client.search("KDDI")
        self.assertEqual(result.hits, 0)
        self.assertIn("token", result.error.lower())

    def test_empty_query_returns_error_result(self) -> None:
        client = HojinLookup(api_token="dummy")
        result = client.search("")
        self.assertEqual(result.hits, 0)
        self.assertIn("empty", result.error.lower())

    def test_http_error_returns_error_result_without_fallback(self) -> None:
        """4xx / 5xx は v1 にフォールバックしない (到達できているため)。"""
        client = HojinLookup(api_token="dummy")
        http_err = urllib_error.HTTPError(
            url="x", code=403, msg="Forbidden", hdrs=None, fp=None  # type: ignore[arg-type]
        )
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            side_effect=http_err,
        ) as mock_open:
            result = client.search("KDDI")
        self.assertEqual(mock_open.call_count, 1)  # v2 のみ、v1 呼ばない
        self.assertIn("HTTP 403", result.error)
        self.assertEqual(result.hits, 0)

    def test_network_error_falls_back_to_v1(self) -> None:
        """URLError 時は v1 にフォールバック。"""
        client = HojinLookup(api_token="dummy")
        net_err = urllib_error.URLError("network unreachable")

        # v2 で失敗、v1 で成功
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            side_effect=[
                net_err,
                _mock_response({"hojin-infos": [{"name": "X"}]}),
            ],
        ) as mock_open:
            result = client.search("KDDI")

        self.assertEqual(mock_open.call_count, 2)  # v2 + v1
        self.assertEqual(result.hits, 1)
        self.assertEqual(result.error, "")

    def test_both_endpoints_failing_returns_error(self) -> None:
        client = HojinLookup(api_token="dummy")
        net_err = urllib_error.URLError("unreachable")
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            side_effect=[net_err, net_err],
        ):
            result = client.search("KDDI")
        self.assertIn("network error", result.error)
        self.assertEqual(result.hits, 0)

    def test_invalid_json_returns_error(self) -> None:
        client = HojinLookup(api_token="dummy")
        bad_resp = MagicMock()
        bad_resp.read.return_value = b"not json"
        bad_resp.__enter__ = MagicMock(return_value=bad_resp)
        bad_resp.__exit__ = MagicMock(return_value=False)
        with patch(
            "secure_review.hojin_lookup.urllib_request.urlopen",
            return_value=bad_resp,
        ):
            result = client.search("KDDI")
        self.assertIn("invalid response", result.error)


if __name__ == "__main__":
    unittest.main()
