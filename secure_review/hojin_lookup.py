"""R-M Phase 2: gBizINFO 法人名検索クライアント。

責務:
- gBizINFO API への問い合わせ (v2 → v1 フォールバック)
- in-memory キャッシュ (セッション寿命、SQLite 永続化なし)
- LookupResult への正規化

責務外:
- ユーザ判断 UI (streamlit_app.py) → PR-D
- マスク適用 (run_masking_pipeline) → PR-D

API 仕様 (handoff および本日のセッション初期に検証済み):
- 認証: ``X-hojinInfo-api-token`` ヘッダー
- v2 エンドポイント: https://api.info.gbiz.go.jp/hojin/v2/hojin?name={name}
- v1 フォールバック: https://info.gbiz.go.jp/hojin/v1/hojin?name={name}
- レスポンス: JSON、``hojin-infos`` フィールドに法人配列

実機検証結果 (handoff より):
- アイレット (カタカナ): 16 件、540 ms 程度。精度高
- iret (英字略称): 21 件、636 ms 程度。誤マッチ多い
"""
from __future__ import annotations

import json
import logging
from typing import Any
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from secure_review.models import LookupResult

logger = logging.getLogger(__name__)

GBIZINFO_V2_BASE = "https://api.info.gbiz.go.jp/hojin/v2"
GBIZINFO_V1_BASE = "https://info.gbiz.go.jp/hojin/v1"
DEFAULT_TIMEOUT = 5.0
DEFAULT_TOP_NAMES = 5


class HojinLookup:
    """gBizINFO 法人名検索の薄いラッパ。

    プロセス内シングルトンとして使うことを想定 (Streamlit 側で
    @st.cache_resource を付けてキャッシュ)。in-memory キャッシュにより
    同一名の重複問い合わせを抑える。
    """

    def __init__(
        self,
        api_token: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_top_names: int = DEFAULT_TOP_NAMES,
    ) -> None:
        self._api_token = api_token
        self._timeout = timeout
        self._max_top_names = max_top_names
        self._cache: dict[str, LookupResult] = {}

    def search(self, name: str) -> LookupResult:
        """法人名を検索し LookupResult を返す。

        - キャッシュヒット: cached=True で即座に返す
        - API トークン未設定: error メッセージを設定して返す (例外は出さない)
        - HTTP エラー: error メッセージを設定して返す (例外は出さない)
        - v2 でネットワークエラー時: v1 にフォールバック

        本メソッドは例外を呼び出し側に投げない。失敗は LookupResult.error
        に格納されるので、呼び出し側はそれを見て安全側 (= マスクする) に
        判断できる。
        """
        if not name or not name.strip():
            return LookupResult(candidate_text=name, hits=0, error="empty query")

        if name in self._cache:
            cached = self._cache[name]
            # cached フラグを True に変えた複製を返す (元のキャッシュは不変)
            return LookupResult(
                candidate_text=cached.candidate_text,
                hits=cached.hits,
                top_names=list(cached.top_names),
                error=cached.error,
                cached=True,
            )

        if not self._api_token:
            # トークン未設定はキャッシュしない
            # (起動後に設定された場合に再試行可能にするため)
            return LookupResult(
                candidate_text=name,
                hits=0,
                error="API token not configured",
            )

        result = self._search_with_fallback(name)
        # エラーでもキャッシュ (同一セッション内で連続失敗を抑制)
        self._cache[name] = result
        return result

    def _search_with_fallback(self, name: str) -> LookupResult:
        """v2 で試し、ネットワークエラー時のみ v1 にフォールバック。

        4xx/5xx は到達できているのでフォールバックしない (v1 でも結果は同じ)。
        """
        try:
            return self._search_one(name, base=GBIZINFO_V2_BASE)
        except urllib_error.URLError as exc:
            logger.warning("gBizINFO v2 failed (%s), falling back to v1", exc)
            try:
                return self._search_one(name, base=GBIZINFO_V1_BASE)
            except urllib_error.URLError as exc2:
                return LookupResult(
                    candidate_text=name, hits=0, error=f"network error: {exc2}"
                )

    def _search_one(self, name: str, base: str) -> LookupResult:
        """1 エンドポイントへの単一問い合わせ。

        Raises:
            urllib_error.URLError: ネットワーク到達不能。フォールバック対象。
        """
        query = urllib_parse.urlencode({"name": name})
        url = f"{base}/hojin?{query}"
        req = urllib_request.Request(
            url,
            headers={
                "X-hojinInfo-api-token": self._api_token,
                "Accept": "application/json",
            },
        )

        try:
            with urllib_request.urlopen(req, timeout=self._timeout) as resp:
                payload_bytes = resp.read()
        except urllib_error.HTTPError as exc:
            # 4xx/5xx はネットワーク失敗ではないのでフォールバックしない
            return LookupResult(
                candidate_text=name,
                hits=0,
                error=f"HTTP {exc.code}",
            )

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return LookupResult(
                candidate_text=name,
                hits=0,
                error=f"invalid response: {exc}",
            )

        return self._parse_payload(name, payload)

    def _parse_payload(self, name: str, payload: dict[str, Any]) -> LookupResult:
        """gBizINFO レスポンスから hits と上位法人名を抽出する。

        レスポンス構造の差異 (v1 / v2、検索結果なし) に頑健にする。
        """
        infos = payload.get("hojin-infos") or payload.get("hojinInfos") or []
        if not isinstance(infos, list):
            infos = []

        top_names: list[str] = []
        for info in infos[: self._max_top_names]:
            if not isinstance(info, dict):
                continue
            n = info.get("name") or info.get("hojin_name") or ""
            if n:
                top_names.append(str(n))

        return LookupResult(
            candidate_text=name,
            hits=len(infos),
            top_names=top_names,
        )
