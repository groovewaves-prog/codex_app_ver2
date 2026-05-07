"""R-W: マスク判断履歴の記録・集計・推奨。

責務:
- ユーザのマスク/素通し判断を JSONL 形式で永続化 (R-W-1)
- 過去の全判断を集計し、推奨エンジンで「seed dict / allowlist 昇格候補」を抽出 (R-W-4)
- ユーザ判断に基づき ``ner_seeds_user.yaml`` / ``tech_allowlist_user.yaml`` を更新 (R-W-3 サポート)

スキーマ設計 (R-V multi-customer 対応含む):
    {
      "schema_version": "1",
      "ts": "2026-05-08T14:32:11",
      "user_id": "default",        # 将来 multi-user 化に備え
      "customer_id": "kddi_mail_relay",  # 将来 multi-tenant 化に備え (R-V)
      "session_id": "20260508-143200-abc",
      "doc": "基本設計書 2.pdf",
      "term": "東京",
      "label": "GPE",
      "source": "watchlist",       # seed_dict / spacy_ner / watchlist
      "decision": "mask",          # mask / skip
      "context": "...20文字..."     # 文脈 (最大 120 文字)
    }

ストレージ:
    data/audit/<customer_id>/<YYYY-MM-DD>.jsonl

冪等性:
- 同一エントリの重複記録は許容 (seek 不要、append のみ)
- 集計時は重複しても件数として正しくカウントされる

責務外:
- UI 描画 (streamlit_app.py)
- seed dict ロード (ner_masker.py)
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

# 推奨エンジンの閾値 (Q2: 標準)
RECOMMEND_THRESHOLD_RATIO = 0.90       # 90% 以上一貫
RECOMMEND_THRESHOLD_OCCURRENCES = 5    # 5 回以上出現

SCHEMA_VERSION = "1"
DEFAULT_USER_ID = "default"
DEFAULT_CUSTOMER_ID = "kddi_mail_relay"
DEFAULT_AUDIT_ROOT = Path("data/audit")

# R-W security (2026-05-08): customer_id にパス区切りや特殊文字を許さない。
# 許可: 英数字、アンダースコア、ハイフン (例: "kddi_mail_relay", "acme-corp")
# 拒否: "../", "/", "\", スペース、その他の特殊文字
_CUSTOMER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")


def _validate_customer_id(customer_id: str) -> str:
    """customer_id がパス安全か検証。不正なら ValueError。

    本格利用化に向けた path traversal 対策 (B2)。multi-tenant 拡張時に
    悪意のある入力でファイルシステム外へ書き込まれることを防ぐ。
    """
    if not isinstance(customer_id, str) or not _CUSTOMER_ID_PATTERN.match(customer_id):
        raise ValueError(
            f"Invalid customer_id: {customer_id!r}. "
            "Allowed: alphanumeric, underscore, hyphen only."
        )
    return customer_id


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def generate_session_id() -> str:
    """セッション識別子を生成。Streamlit セッション開始時に 1 回呼ぶ想定。"""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    rand = uuid.uuid4().hex[:6]
    return f"{ts}-{rand}"


def _audit_dir_for(customer_id: str, root: Path | None = None) -> Path:
    """customer_id に対応する audit ディレクトリを返す (R-V 対応)。"""
    _validate_customer_id(customer_id)
    root = root or DEFAULT_AUDIT_ROOT
    return root / customer_id


def log_decisions(
    *,
    document_name: str,
    decisions: Mapping[str, bool],
    candidate_metadata: Mapping[str, Mapping[str, Any]],
    customer_id: str = DEFAULT_CUSTOMER_ID,
    user_id: str = DEFAULT_USER_ID,
    session_id: str | None = None,
    audit_root: Path | None = None,
) -> Path:
    """ユーザの判断結果を JSONL に追記する。

    Args:
        document_name: 文書名 (例: "基本設計書 2.pdf")
        decisions: {candidate_text: bool}  True = mask, False = skip
        candidate_metadata: {candidate_text: {label, source, context}}
            label: spaCy ラベル相当 ("ORG"/"GPE" 等)
            source: "seed_dict" / "spacy_ner" / "watchlist"
            context: 周辺テキスト (最大 120 文字程度)
        customer_id: 顧客識別子 (R-V)。デフォルトは "kddi_mail_relay"
        user_id: ユーザ識別子 (将来用)。デフォルトは "default"
        session_id: セッション識別子。省略時は呼び出しごとに新規生成
            (推奨は streamlit_app の session_state で 1 セッション 1 ID)
        audit_root: ログ出力の root ディレクトリ。省略時は data/audit

    Returns:
        書き込んだ JSONL ファイルのパス
    """
    audit_dir = _audit_dir_for(customer_id, audit_root)
    audit_dir.mkdir(parents=True, exist_ok=True)
    out_path = audit_dir / f"{_today_str()}.jsonl"

    if session_id is None:
        session_id = generate_session_id()

    written_count = 0
    with out_path.open("a", encoding="utf-8") as f:
        for term, decision in decisions.items():
            meta = candidate_metadata.get(term) or {}
            entry = {
                "schema_version": SCHEMA_VERSION,
                "ts": _now_iso(),
                "user_id": user_id,
                "customer_id": customer_id,
                "session_id": session_id,
                "doc": document_name,
                "term": term,
                "label": meta.get("label", "UNKNOWN"),
                "source": meta.get("source", ""),
                "decision": "mask" if decision else "skip",
                "context": (meta.get("context", "") or "")[:120],
            }
            f.write(json.dumps(entry, ensure_ascii=False))
            f.write("\n")
            written_count += 1

    if written_count > 0:
        logger.info(
            "audit_log: %d decision(s) written to %s (session=%s, doc=%s)",
            written_count, out_path, session_id, document_name,
        )
    return out_path


def _read_jsonl_safely(path: Path) -> Iterable[dict[str, Any]]:
    """JSONL を 1 行ずつ読み、壊れた行はスキップ (将来のスキーマ進化に対応)。"""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("audit_log: broken JSONL line %s:%d: %s", path, line_num, exc)
                continue


def aggregate_decisions(
    *,
    customer_id: str | None = DEFAULT_CUSTOMER_ID,
    session_id: str | None = None,
    audit_root: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """過去の audit log を集計する。

    Args:
        customer_id: 集計対象顧客。None なら全顧客横断 (R-V 対応)。
        session_id: 特定セッションのみ集計したい時に指定 (R-W-2 用)。
        audit_root: ルート。省略時は data/audit

    Returns:
        {term: {
            "label": "GPE",
            "mask_count": N,
            "skip_count": M,
            "total": K,
            "mask_ratio": 0.0..1.0,
            "examples": [{"doc": ..., "context": ...}, ...],  最大 3 件
            "first_seen": ISO ts,
            "last_seen": ISO ts,
            "customer_ids": ["kddi_mail_relay", ...],  # 横断時に複数
        }}
    """
    root = audit_root or DEFAULT_AUDIT_ROOT
    if not root.exists():
        return {}

    # 対象 JSONL ファイル収集
    if customer_id is None:
        # 全顧客横断
        jsonl_paths: list[Path] = []
        for customer_dir in sorted(root.iterdir()):
            if not customer_dir.is_dir():
                continue
            jsonl_paths.extend(sorted(customer_dir.glob("*.jsonl")))
    else:
        cust_dir = _audit_dir_for(customer_id, root)
        jsonl_paths = sorted(cust_dir.glob("*.jsonl")) if cust_dir.exists() else []

    aggregated: dict[str, dict[str, Any]] = {}

    for path in jsonl_paths:
        for entry in _read_jsonl_safely(path):
            # session フィルタ
            if session_id is not None and entry.get("session_id") != session_id:
                continue

            term = entry.get("term") or ""
            if not term:
                continue

            agg = aggregated.setdefault(term, {
                "label": entry.get("label", ""),
                "mask_count": 0,
                "skip_count": 0,
                "examples": [],
                "first_seen": entry.get("ts", ""),
                "last_seen": entry.get("ts", ""),
                "customer_ids": set(),
            })

            decision = entry.get("decision", "skip")
            if decision == "mask":
                agg["mask_count"] += 1
            else:
                agg["skip_count"] += 1

            ts = entry.get("ts", "")
            if ts and ts < agg["first_seen"]:
                agg["first_seen"] = ts
            if ts and ts > agg["last_seen"]:
                agg["last_seen"] = ts

            cust = entry.get("customer_id", DEFAULT_CUSTOMER_ID)
            agg["customer_ids"].add(cust)

            # 文脈例は最大 3 件 (代表例として)
            if len(agg["examples"]) < 3:
                ex = {
                    "doc": entry.get("doc", ""),
                    "context": entry.get("context", ""),
                    "decision": decision,
                }
                # 重複除外
                if ex not in agg["examples"]:
                    agg["examples"].append(ex)

    # 集計後処理: ratio 計算、set → list 変換
    for term, agg in aggregated.items():
        agg["total"] = agg["mask_count"] + agg["skip_count"]
        agg["mask_ratio"] = agg["mask_count"] / agg["total"] if agg["total"] > 0 else 0.0
        agg["customer_ids"] = sorted(agg["customer_ids"])

    return aggregated


def recommend_action(agg_entry: Mapping[str, Any]) -> str:
    """集計エントリから推奨アクションを判定する (R-W-4 推奨エンジン)。

    Returns:
        推奨カテゴリ:
        - "promote_seed_mask"      : ⚡ seed dict に confirm:true で追加 (auto-mask)
        - "promote_seed_skip"      : ⚡ tech_allowlist に追加 (常に素通し)
        - "context_dependent"      : 🤔 文脈依存 (現状の uncertain candidate のまま)
        - "insufficient_data"      : データ不足 (出現回数 < 閾値)

    判定ロジック (Q2 標準閾値):
        - 出現回数 < 5: "insufficient_data"
        - mask_ratio >= 90%: "promote_seed_mask"
        - mask_ratio <= 10%: "promote_seed_skip"
        - その他 (10-90%): "context_dependent"
    """
    total = agg_entry.get("total", 0)
    if total < RECOMMEND_THRESHOLD_OCCURRENCES:
        return "insufficient_data"

    ratio = agg_entry.get("mask_ratio", 0.0)
    if ratio >= RECOMMEND_THRESHOLD_RATIO:
        return "promote_seed_mask"
    if ratio <= (1.0 - RECOMMEND_THRESHOLD_RATIO):
        return "promote_seed_skip"
    return "context_dependent"


def append_to_user_seeds(
    *,
    text: str,
    label: str,
    canonical: str | None = None,
    confirm: bool = True,
    customer_id: str = DEFAULT_CUSTOMER_ID,
    seeds_root: Path | None = None,
) -> tuple[Path, bool]:
    """ユーザ判断結果を ``ner_seeds_user.yaml`` に追記する (R-W-3)。

    R-V (multi-customer) 対応:
        ファイル位置は ``data/customers/<customer_id>/ner_seeds_user.yaml``。
        ディレクトリが無ければ作成する。

    重複チェック:
        既に同じ ``text`` のエントリがあれば追記せず、(path, False) を返す。

    Args:
        text: マッチ対象文字列
        label: spaCy ラベル ("ORG"/"GPE"/"FAC"/"PERSON")
        canonical: 別名統合用 (省略時は text と同一)
        confirm: True なら auto-mask、False なら uncertain candidate にまわす
        customer_id: 顧客識別子 (R-V)
        seeds_root: data ディレクトリのルート (テスト用)

    Returns:
        (書き込んだファイルパス, 新規追加されたか) のタプル
    """
    _validate_customer_id(customer_id)
    root = seeds_root or Path("data")
    user_seeds_path = root / "customers" / customer_id / "ner_seeds_user.yaml"

    # 初回はヘッダ付きで初期化
    if not user_seeds_path.exists():
        user_seeds_path.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "# ====================================================================\n"
            "# 自動生成: R-W-3 でユーザが「永続化」ボタンを押した結果が記録されます。\n"
            f"# 顧客 ID: {customer_id}\n"
            "# 手動編集も可能。同じ text のエントリ重複は安全 (後勝ち or 無視)。\n"
            "# 削除は機械的判断由来の追加を取り消したい時に有効。\n"
            "# ====================================================================\n"
            "phrases:\n"
        )
        user_seeds_path.write_text(header, encoding="utf-8")

    # 既存内容を読み、重複チェック
    import yaml  # 遅延 import (audit_log 単独テストでは不要)
    with user_seeds_path.open("r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f) or {}
        except yaml.YAMLError as exc:
            logger.warning("user_seeds parse failed (treating as empty): %s", exc)
            data = {}

    existing_phrases = data.get("phrases") or []
    for entry in existing_phrases:
        if isinstance(entry, dict) and entry.get("text") == text:
            logger.info("append_to_user_seeds: %r already in %s, skipping", text, user_seeds_path)
            return (user_seeds_path, False)

    # 新エントリ追記 (raw text で。yaml.dump はコメントを破壊するため避ける)
    canonical_actual = canonical or text
    new_block = (
        f"  - text: {json.dumps(text, ensure_ascii=False)}\n"
        f"    label: {label}\n"
        f"    canonical: {json.dumps(canonical_actual, ensure_ascii=False)}\n"
        f"    confirm: {str(confirm).lower()}\n"
    )

    with user_seeds_path.open("a", encoding="utf-8") as f:
        f.write(new_block)

    logger.info(
        "append_to_user_seeds: added %r (label=%s, confirm=%s) to %s",
        text, label, confirm, user_seeds_path,
    )
    return (user_seeds_path, True)


def append_to_user_allowlist(
    *,
    text: str,
    customer_id: str = DEFAULT_CUSTOMER_ID,
    seeds_root: Path | None = None,
) -> tuple[Path, bool]:
    """ユーザ判断「素通し確定」を ``tech_allowlist_user.yaml`` に追記する (R-W-3)。

    Returns:
        (書き込んだファイルパス, 新規追加されたか)
    """
    _validate_customer_id(customer_id)
    root = seeds_root or Path("data")
    user_allowlist_path = root / "customers" / customer_id / "tech_allowlist_user.yaml"

    if not user_allowlist_path.exists():
        user_allowlist_path.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "# ====================================================================\n"
            "# 自動生成: R-W-3 でユーザが「素通し確定」ボタンを押した結果が記録されます。\n"
            f"# 顧客 ID: {customer_id}\n"
            "# ====================================================================\n"
            "user_allowlist:\n"
        )
        user_allowlist_path.write_text(header, encoding="utf-8")

    import yaml
    with user_allowlist_path.open("r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f) or {}
        except yaml.YAMLError:
            data = {}

    existing = data.get("user_allowlist") or []
    if text in existing:
        return (user_allowlist_path, False)

    with user_allowlist_path.open("a", encoding="utf-8") as f:
        f.write(f"  - {json.dumps(text, ensure_ascii=False)}\n")

    return (user_allowlist_path, True)


# CLI ヘルパ: python -m secure_review.audit_log で集計サマリ表示
def _cli_summary(customer_id: str | None = None) -> None:
    """簡易 CLI サマリ (R-W-4 のテキスト版)。"""
    agg = aggregate_decisions(customer_id=customer_id)
    if not agg:
        print(f"No audit data for customer={customer_id or '(all)'}")
        return

    print(f"=== Audit summary (customer={customer_id or '(all)'}) ===")
    print(f"{'term':<20} {'label':<8} {'mask':>5} {'skip':>5} {'ratio':>6} recommendation")
    print("-" * 80)
    for term in sorted(agg.keys(), key=lambda t: -agg[t]["total"]):
        e = agg[term]
        rec = recommend_action(e)
        rec_short = {
            "promote_seed_mask": "→ seed dict (mask)",
            "promote_seed_skip": "→ allowlist (skip)",
            "context_dependent": "🤔 context-dep",
            "insufficient_data": "(insufficient)",
        }[rec]
        print(
            f"{term[:20]:<20} {e['label'][:8]:<8} {e['mask_count']:>5} "
            f"{e['skip_count']:>5} {e['mask_ratio']*100:>5.1f}% {rec_short}"
        )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="audit log summary")
    parser.add_argument("--customer", default=None, help="customer_id filter")
    args = parser.parse_args()
    _cli_summary(customer_id=args.customer)
