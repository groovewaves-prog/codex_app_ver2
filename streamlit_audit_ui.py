"""R-W-2 / R-W-3 / R-W-4 の Streamlit UI 実装。

責務:
- セッション内のマスク判断サマリ表示 (R-W-2)
- 「永続化する」ボタン → user_seeds.yaml / user_allowlist.yaml 追記 (R-W-3)
- 全期間の判断履歴と推奨エンジン表示 (R-W-4)
- マスク辞書プロファイル セレクタ (R-V)

streamlit_app.py からの呼び出しは:
    from streamlit_audit_ui import (
        ensure_session_state, render_customer_selector,
        render_session_summary, render_history_panel,
    )
    ensure_session_state()
    render_customer_selector()
    # ... 既存パイプライン後 ...
    render_session_summary()
    # ... ページ最下部 ...
    render_history_panel()

設計原則:
- Streamlit の rerun サイクルに対応して、各 render_* は idempotent
- ボタン操作は即座に効果を反映 (ファイル書き込みを完了 → メッセージ表示)
- 失敗時は例外を握りつぶさず st.error で表示 (silent failure を避ける)
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import streamlit as st

from secure_review.audit_log import (
    DEFAULT_CUSTOMER_ID,
    aggregate_decisions,
    append_to_user_allowlist,
    append_to_user_seeds,
    generate_session_id,
    recommend_action,
)
from secure_review.export_names import audit_json_filename, audit_log_zip_filename

CUSTOMERS_DIR = Path("data/customers")
HISTORY_DEFAULT_LIMIT = 10
HISTORY_EXPANDED_STATE_KEY = "history_expanded"


def _sort_history_terms(
    agg: Mapping[str, Mapping[str, Any]],
) -> list[tuple[str, Mapping[str, Any]]]:
    """Sort mask-decision history terms by decision count descending."""
    return sorted(
        agg.items(),
        key=lambda kv: (
            -int(kv[1].get("total", 0) or 0),
            str(kv[0]),
        ),
    )


def _select_history_terms_for_display(
    sorted_terms: list[tuple[str, Mapping[str, Any]]],
    *,
    expanded: bool,
    limit: int = HISTORY_DEFAULT_LIMIT,
) -> tuple[list[tuple[str, Mapping[str, Any]]], int, bool]:
    """Return visible terms, remaining count, and whether display is limited."""
    total_terms = len(sorted_terms)
    if total_terms > limit and not expanded:
        return sorted_terms[:limit], total_terms - limit, True
    return sorted_terms, 0, False


def _split_history_terms_by_recommendation(
    terms: list[tuple[str, Mapping[str, Any]]],
) -> tuple[
    list[tuple[str, Mapping[str, Any]]],
    list[tuple[str, Mapping[str, Any]]],
    list[tuple[str, Mapping[str, Any]]],
    list[tuple[str, Mapping[str, Any]]],
]:
    promote_mask = []
    promote_skip = []
    context_dep = []
    insufficient = []
    for term, entry in terms:
        rec = recommend_action(entry)
        if rec == "promote_seed_mask":
            promote_mask.append((term, entry))
        elif rec == "promote_seed_skip":
            promote_skip.append((term, entry))
        elif rec == "context_dependent":
            context_dep.append((term, entry))
        else:
            insufficient.append((term, entry))
    return promote_mask, promote_skip, context_dep, insufficient


# ============================================================
# セッション状態管理
# ============================================================

def ensure_session_state() -> None:
    """st.session_state に R-W 関連のキーを初期化する。

    streamlit_app.py の最上位で 1 度呼ぶ。冪等。
    """
    if "audit_session_id" not in st.session_state:
        st.session_state.audit_session_id = generate_session_id()
    if "customer_id" not in st.session_state:
        st.session_state.customer_id = DEFAULT_CUSTOMER_ID


def get_session_id() -> str:
    ensure_session_state()
    return st.session_state.audit_session_id


def get_customer_id() -> str:
    ensure_session_state()
    return st.session_state.customer_id


# ============================================================
# マスク辞書プロファイル セレクタ (R-V)
# ============================================================

def _list_customers() -> list[str]:
    """data/customers/ 配下のディレクトリを列挙して候補リストを返す。"""
    if not CUSTOMERS_DIR.exists():
        return [DEFAULT_CUSTOMER_ID]
    candidates = sorted(
        p.name for p in CUSTOMERS_DIR.iterdir() if p.is_dir()
    )
    if DEFAULT_CUSTOMER_ID not in candidates:
        candidates.insert(0, DEFAULT_CUSTOMER_ID)
    return candidates


def render_customer_selector(*, sidebar: bool = True) -> str:
    """マスク辞書プロファイル selector を描画する (サイドバー or 本文)。

    Returns:
        選択された customer_id (st.session_state.customer_id にも反映)。
    """
    ensure_session_state()
    container = st.sidebar if sidebar else st
    candidates = _list_customers()
    current = st.session_state.customer_id
    try:
        default_idx = candidates.index(current)
    except ValueError:
        default_idx = 0

    selected = container.selectbox(
        "🧩 マスク辞書プロファイル",
        options=candidates,
        index=default_idx,
        key="customer_id_selector",
        help=(
            "NER の seed dict / allowlist / マスク判断履歴を分離する単位です。"
            "通常は既定値のままで問題ありません。"
            " 新規プロファイルは data/customers/<id>/ ディレクトリを作成すれば追加されます。"
        ),
    )
    container.caption(
        "通常は変更不要です。プロジェクト固有のマスク辞書や判断履歴を分けたい場合だけ切り替えます。"
    )
    if selected != st.session_state.customer_id:
        # R-W-ε (2026-05-08): 切り替え警告。マスク判断中だった場合は確認を求める。
        # ファイル添付があり、かつ confirmation 対象になった (preview_docs に
        # uncertain_candidates がある) 場合に警告を表示。
        has_pending = bool(st.session_state.get("preview_docs"))
        if has_pending:
            container.warning(
                f"⚠️ マスク辞書プロファイルを **{st.session_state.customer_id}** から "
                f"**{selected}** に切り替えると、"
                "現在のセッションの判断履歴が新セッションに分離されます。"
                " 進行中の判断は失われませんが、サマリ画面で別セッションとして集計されます。"
            )
            if not container.button(
                f"🔄 {selected} に切り替える", key="confirm_customer_switch",
            ):
                # 確認ボタンが押されるまで切り替えない
                return st.session_state.customer_id

        st.session_state.customer_id = selected
        # customer_id 切り替え時はセッション ID も新規発行 (混合を避ける)
        st.session_state.audit_session_id = generate_session_id()
        st.rerun()
    return selected


# ============================================================
# R-W-2: セッション内サマリ
# ============================================================

def _format_examples(examples: list[Mapping[str, Any]]) -> str:
    """文脈例を 1 行ずつフォーマット。"""
    lines = []
    for ex in examples[:3]:
        doc = ex.get("doc", "")
        ctx = (ex.get("context", "") or "").strip().replace("\n", " ")[:80]
        decision = ex.get("decision", "")
        marker = "🛡️" if decision == "mask" else "🟢"
        lines.append(f"  {marker} `{doc}`: ...{ctx}...")
    return "\n".join(lines)


def render_session_summary() -> None:
    """R-W-2: 本セッションのマスク判断サマリ expander を描画。

    apply_user_decisions が customer_id/session_id 付きで呼ばれた直後に
    audit log に追記された内容を集計表示。
    各エントリに R-W-3 の永続化ボタンを表示。

    課題 1 修正 (2026-05-08):
        永続化ボタン押下時の rerun で expander が勝手に折りたたまれる問題への対処。
        session_state.session_summary_expanded で展開状態を保持し、永続化ボタン押下後も
        ユーザの操作意図 (= 連続で複数語を判断する) を維持する。
        デフォルトは True (展開) - 永続化ボタンが画面に現れている = ユーザがそれを使う
        意図がある状況なので、展開がデフォルトの方が UX として自然。
    """
    ensure_session_state()
    customer_id = get_customer_id()
    session_id = get_session_id()

    agg = aggregate_decisions(
        customer_id=customer_id,
        session_id=session_id,
    )
    if not agg:
        return  # まだ判断なし → expander 非表示

    total_decisions = sum(e["total"] for e in agg.values())
    mask_count = sum(e["mask_count"] for e in agg.values())
    skip_count = sum(e["skip_count"] for e in agg.values())

    # 課題 1 修正: 展開状態を session_state で保持
    # デフォルト True (展開) — サマリは永続化操作の起点なので、最初から見えている方が良い
    if "session_summary_expanded" not in st.session_state:
        st.session_state.session_summary_expanded = True

    with st.expander(
        f"📊 本セッションのマスク判断サマリ "
        f"(語 {len(agg)} 種類、判断 {total_decisions} 件: マスク {mask_count} / 素通し {skip_count})",
        expanded=st.session_state.session_summary_expanded,
    ):
        st.caption(
            "このセッションで `uncertain candidates` UI で判断された結果です。"
            " 同じ語を将来も同じ判断にしたい場合は永続化ボタンで反映できます (次回セッションから有効)。"
        )
        # 判断回数の多い順にソート
        sorted_terms = sorted(agg.items(), key=lambda kv: -kv[1]["total"])
        for term, e in sorted_terms:
            _render_term_card(term, e, customer_id, key_prefix="session")


def _render_term_card(
    term: str,
    agg_entry: Mapping[str, Any],
    customer_id: str,
    *,
    key_prefix: str,
) -> None:
    """1 つの語に対するサマリカードと永続化ボタンを描画。

    R-W-3 のボタンロジックは _persist_term() に委譲。
    """
    label = agg_entry.get("label", "")
    mask_count = agg_entry.get("mask_count", 0)
    skip_count = agg_entry.get("skip_count", 0)
    ratio_pct = agg_entry.get("mask_ratio", 0.0) * 100
    rec = recommend_action(agg_entry)

    rec_badge = {
        "promote_seed_mask": "⚡ **マスク確定推奨** (90%+ 一貫)",
        "promote_seed_skip": "⚡ **素通し確定推奨** (90%+ 一貫)",
        "context_dependent": "🤔 文脈依存 (現状維持推奨)",
        "insufficient_data": "📉 データ不足 (5 件未満)",
    }.get(rec, "")

    cols = st.columns([2.5, 1, 1, 1, 3])
    cols[0].markdown(f"**`{term}`** ({label})")
    cols[1].metric("マスク", mask_count)
    cols[2].metric("素通し", skip_count)
    cols[3].metric("一貫性", f"{ratio_pct:.0f}%")
    cols[4].markdown(rec_badge)

    # 文脈例 (折りたたみ)
    examples = agg_entry.get("examples", [])
    if examples:
        with st.expander(f"文脈例 ({len(examples)} 件)", expanded=False):
            st.markdown(_format_examples(examples))

    # R-W-3: 永続化ボタン (3 種類)
    btn_cols = st.columns([1, 1, 1, 2])
    base_key = f"{key_prefix}_{term}"

    # Q2 修正 (2026-05-08): ボタン名を機能差分が明確になるよう変更。
    # 「watchlist (人間判断)」→「都度判断 (毎回確認)」: 毎回 UI で確認したい語
    # 「素通し確定」: もう確認不要、候補にも出さない語 (異なる目的)
    if btn_cols[0].button(
        "📥 マスク確定 (自動伏字)", key=f"{base_key}_mask",
        help=(
            "次回セッションから【自動的にマスク】されます (uncertain UI に出ません)。"
            "確実に機密と分かっている語に使います。例: KDDI、府中、KDDIアイレット。"
            " 反映先: ner_seeds_user.yaml (confirm:true)。"
            " ⚠️ 永続化は次回セッション以降に有効。今のセッションには影響しません。"
        ),
    ):
        _persist_term(term, label, customer_id, action="seed_mask")

    if btn_cols[1].button(
        "👁️ 都度判断 (毎回確認)", key=f"{base_key}_watch",
        help=(
            "次回セッションでも【uncertain UI に表示】され、毎回ユーザが判断します。"
            "文脈次第でマスク要否が変わる語に使います (例: 用途により判断が分かれる地名)。"
            " 反映先: ner_seeds_user.yaml (confirm:false)。"
            " ⚠️ 永続化は次回セッション以降に有効。今のセッションには影響しません。"
        ),
    ):
        _persist_term(term, label, customer_id, action="seed_watch")

    if btn_cols[2].button(
        "🟢 素通し確定 (候補から除外)", key=f"{base_key}_allow",
        help=(
            "次回セッションから【候補にも出ません】(完全スキップ)。もう判断不要な"
            "公知用語に使います。例: 東京リージョン、Amazon SES、AWS、Linux。"
            " 反映先: tech_allowlist_user.yaml。"
            " ⚠️ 永続化は次回セッション以降に有効。今のセッションには影響しません。"
        ),
    ):
        _persist_term(term, label, customer_id, action="allowlist")

    btn_cols[3].markdown(" ")  # spacer
    st.divider()


def _persist_term(
    term: str,
    label: str,
    customer_id: str,
    *,
    action: str,
) -> None:
    """R-W-3: 永続化ボタンの実処理。

    action:
      - "seed_mask"  : ner_seeds_user.yaml に confirm:true で追記
      - "seed_watch" : ner_seeds_user.yaml に confirm:false で追記
      - "allowlist"  : tech_allowlist_user.yaml に追記
    """
    try:
        if action in ("seed_mask", "seed_watch"):
            confirm = (action == "seed_mask")
            # canonical はとりあえず term と同じ。複雑な統合は手動編集で。
            path, added = append_to_user_seeds(
                text=term,
                label=label or "ORG",
                canonical=term,
                confirm=confirm,
                customer_id=customer_id,
            )
            if added:
                _kind = "自動伏字" if confirm else "都度判断"
                st.success(
                    f"✅ `{term}` を `{path}` に追加しました ({_kind})。"
                    " 次回セッションから反映されます。今のセッションでは効果がありません。"
                )
            else:
                st.info(f"ℹ️ `{term}` は既に `{path}` に登録済みです。")
        elif action == "allowlist":
            path, added = append_to_user_allowlist(
                text=term,
                customer_id=customer_id,
            )
            if added:
                st.success(
                    f"✅ `{term}` を `{path}` に追加しました (素通し確定)。"
                    " 次回セッションから候補にも出なくなります。今のセッションでは効果がありません。"
                )
            else:
                st.info(f"ℹ️ `{term}` は既に `{path}` に登録済みです。")
        else:
            st.error(f"未知の action: {action}")
    except Exception as exc:  # noqa: BLE001
        st.error(f"⚠️ 永続化に失敗しました: {exc}")


# ============================================================
# R-W-export: レビュー証跡の保存 (チャットでの貼り付け負担軽減)
# ============================================================

def build_audit_export_zip(
    export_specs: tuple[tuple[str, Mapping[str, Any]], ...],
    exported_at: datetime,
) -> bytes:
    """Bundle audit JSON payloads into one in-memory ZIP archive."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for kind, payload in export_specs:
            archive.writestr(
                audit_json_filename(kind, exported_at),
                json.dumps(payload, ensure_ascii=False, indent=2, default=str),
            )
    return buffer.getvalue()


def render_log_export_button() -> None:
    """Render one bundled audit ZIP export button for review evidence.

    現在の preview_docs (匿名化済み文書) と review_result (LLM レビュー結果)
    を用途別の監査 JSON にシリアライズし、1つの ZIP download_button で配布。

    Streamlit Cloud で動作する想定。ユーザはダウンロードした audit_*.json を
    監査・共有用の証跡として扱う。再レビュー比較用の修正計画JSONとは分ける。

    出力 JSON 構造 (代表的な内容):
        {
          "schema_version": "1",
          "exported_at": "2026-05-08T12:34:56",
          "session_id": "...",
          "customer_id": "kddi_mail_relay",
          "documents": [
            {
              "name": "基本設計書 4.pdf",
              "sanitized_excerpt": "...",
              "outbound_text": "...",
              "findings": [...],
              "confirmed_findings": [{"text": "...", "label": "..."}, ...],
              "uncertain_candidates": [{"text": "...", "label": "...", "spacy_label": "...", "source": "..."}, ...],
              "outbound_risk": "low",
              "local_sensitivity_decision": "...",
              ...
            }
          ],
          "deep_dive_results": {            # R-Y (B4 で追加)
            "<doc_name>": [
              {"summary": "...", "issues": [...], "provider": "...", "model": "..."}
            ]
          },
          "review_result": {...} (LLM レビュー結果、ある場合)
        }
    """
    preview_docs = st.session_state.get("preview_docs")
    if not preview_docs:
        return

    customer_id = get_customer_id()
    session_id = get_session_id()
    masking_states = st.session_state.get("masking_states") or {}

    docs_data = []
    for doc in preview_docs:
        doc_data = {
            "name": getattr(doc, "name", ""),
            "sanitized_excerpt": getattr(doc, "sanitized_excerpt", ""),
            "outbound_text": getattr(doc, "outbound_text", ""),
            "findings": list(getattr(doc, "findings", [])),
            "replacements_count": len(getattr(doc, "replacements", [])),
            "outbound_risk": getattr(doc, "outbound_risk", ""),
            "local_sensitivity_decision": getattr(doc, "local_sensitivity_decision", ""),
            "local_sensitivity_reasons": list(getattr(doc, "local_sensitivity_reasons", [])),
            "estimated_input_tokens": getattr(doc, "estimated_input_tokens", 0),
        }

        # masking_states があれば、確定/未確定候補も含める
        state = masking_states.get(getattr(doc, "name", ""))
        if state is not None:
            confirmed = []
            for item in getattr(state, "confirmed_findings", []) or []:
                # tuple (text, label) または NerCandidate
                if isinstance(item, tuple) and len(item) == 2:
                    confirmed.append({"text": item[0], "label": item[1]})
                else:
                    confirmed.append({
                        "text": getattr(item, "text", str(item)),
                        "label": getattr(item, "label", ""),
                    })
            doc_data["confirmed_findings"] = confirmed

            uncertain = []
            for cand in getattr(state, "uncertain_candidates", []) or []:
                uncertain.append({
                    "text": getattr(cand, "text", ""),
                    "label": getattr(cand, "label", ""),
                    "spacy_label": getattr(cand, "spacy_label", ""),
                    "source": getattr(cand, "source", ""),
                    "confirmed": getattr(cand, "confirmed", False),
                })
            doc_data["uncertain_candidates"] = uncertain

        docs_data.append(doc_data)

    exported_at = datetime.now()
    base_meta = {
        "schema_version": "1",  # R-W-export schema (B2 修正で追加)
        "exported_at": exported_at.isoformat(timespec="seconds"),
        "session_id": session_id,
        "customer_id": customer_id,
    }

    sanitized_text_data = {
        **base_meta,
        "export_type": "audit_sanitized_text",
        "documents": [
            {
                "name": doc.get("name", ""),
                "sanitized_excerpt": doc.get("sanitized_excerpt", ""),
                "outbound_text": doc.get("outbound_text", ""),
                "replacements_count": doc.get("replacements_count", 0),
                "outbound_risk": doc.get("outbound_risk", ""),
                "estimated_input_tokens": doc.get("estimated_input_tokens", 0),
            }
            for doc in docs_data
        ],
    }

    mask_candidates_data = {
        **base_meta,
        "export_type": "audit_mask_candidates",
        "documents": [
            {
                "name": doc.get("name", ""),
                "findings": doc.get("findings", []),
                "confirmed_findings": doc.get("confirmed_findings", []),
                "uncertain_candidates": doc.get("uncertain_candidates", []),
                "local_sensitivity_decision": doc.get("local_sensitivity_decision", ""),
                "local_sensitivity_reasons": doc.get("local_sensitivity_reasons", []),
            }
            for doc in docs_data
        ],
    }

    send_log_data = {
        **base_meta,
        "export_type": "audit_send_log",
        "documents": docs_data,
    }

    # B4 (2026-05-08): 深堀レビュー結果 (R-Y) も log に含める
    # session_state.deep_dive_results は {doc_name: [ReviewResult, ...]} の dict
    deep_dive_results = st.session_state.get("deep_dive_results") or {}
    if deep_dive_results:
        serialized_dd: dict = {}
        for dd_doc_name, dd_review_list in deep_dive_results.items():
            entries: list = []
            for dd_review in dd_review_list:
                dd_issues_data: list = []
                for dd_i in (getattr(dd_review, "issues", []) or []):
                    dd_issues_data.append({
                        "issue_id": getattr(dd_i, "issue_id", "") or "",
                        "severity": getattr(dd_i, "severity", "") or "",
                        "title": getattr(dd_i, "title", "") or "",
                        "current_state": getattr(dd_i, "current_state", "") or "",
                        "issue": getattr(dd_i, "issue", "") or "",
                        "impact": getattr(dd_i, "impact", "") or "",
                        "recommendation": getattr(dd_i, "recommendation", "") or "",
                        "details": getattr(dd_i, "details", "") or "",
                        "section": getattr(dd_i, "section", "") or "",
                        "source_document": getattr(dd_i, "source_document", "") or "",
                    })
                entries.append({
                    "summary": getattr(dd_review, "summary", "") or "",
                    "provider": getattr(dd_review, "provider", "") or "",
                    "model": getattr(dd_review, "model", "") or "",
                    "issues": dd_issues_data,
                })
            serialized_dd[dd_doc_name] = entries
        send_log_data["deep_dive_results"] = serialized_dd

    # LLM レビュー結果が available なら含める
    review_result_data = {
        **base_meta,
        "export_type": "audit_review_result",
        "documents": [{"name": doc.get("name", "")} for doc in docs_data],
    }
    review = st.session_state.get("review_result")
    if review is not None:
        if hasattr(review, "to_dict"):
            try:
                review_result_data["review_result"] = review.to_dict()
            except Exception:
                review_result_data["review_result"] = repr(review)
        else:
            review_result_data["review_result"] = repr(review)
    if "deep_dive_results" in send_log_data:
        review_result_data["deep_dive_results"] = send_log_data["deep_dive_results"]

    export_specs: tuple[tuple[str, Mapping[str, Any]], ...] = (
        ("sanitized_text", sanitized_text_data),
        ("mask_candidates", mask_candidates_data),
        ("send_log", send_log_data),
        ("review_result", review_result_data),
    )

    st.download_button(
        label="📥 証跡をまとめてダウンロード (ZIP)",
        data=build_audit_export_zip(export_specs, exported_at),
        file_name=audit_log_zip_filename(exported_at),
        mime="application/zip",
        help=(
            "匿名化テキスト、マスク候補、送信ログ、レビュー結果の4つの監査用JSONを"
            "1つのZIPにまとめて保存します。再レビュー比較用の修正計画JSONではありません。"
        ),
        key="audit_export_zip_button",
        type="secondary",
        width="stretch",
    )


# ============================================================
# R-W-4: 全期間履歴と推奨
# ============================================================

def render_history_panel() -> None:
    """R-W-4: 全期間のマスク判断履歴と推奨エンジン出力。

    現在の customer_id 配下の全 audit log を集計して表示。
    sidebar に「過去 7 日 / 30 日 / 全期間」フィルタを置くことも可能だが、
    MVP では全期間集計 (12 PDFs × N セッション程度ならパフォーマンス上問題なし)。
    """
    ensure_session_state()
    customer_id = get_customer_id()

    agg = aggregate_decisions(customer_id=customer_id)

    total_terms = len(agg)
    with st.expander(
        f"📈 全期間のマスク判断履歴と推奨 ({total_terms} 件 / 辞書プロファイル: {customer_id})",
        expanded=False,
    ):
        if not agg:
            st.info(
                "まだ判断履歴がありません。"
                " 未確定マスク候補をユーザが判断し、匿名化結果を再生成した場合のみ、"
                "ここに過去の判断パターンと seed dict / allowlist 昇格推奨が蓄積されます。"
                "安全判定で候補がない文書では履歴は増えません。"
            )
            return

        sorted_terms = _sort_history_terms(agg)
        history_expanded = bool(st.session_state.get(HISTORY_EXPANDED_STATE_KEY, False))
        display_terms, remaining_terms, is_limited = _select_history_terms_for_display(
            sorted_terms,
            expanded=history_expanded,
            limit=HISTORY_DEFAULT_LIMIT,
        )
        if is_limited:
            st.caption(f"全 {total_terms} 件中、上位 {HISTORY_DEFAULT_LIMIT} 件を表示")
        elif total_terms > HISTORY_DEFAULT_LIMIT:
            st.caption(f"全 {total_terms} 件を表示中")

        # 推奨カテゴリ別サマリ
        all_promote_mask, all_promote_skip, all_context_dep, all_insufficient = (
            _split_history_terms_by_recommendation(sorted_terms)
        )
        promote_mask, promote_skip, context_dep, insufficient = (
            _split_history_terms_by_recommendation(display_terms)
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("⚡ マスク確定推奨", len(all_promote_mask))
        c2.metric("⚡ 素通し確定推奨", len(all_promote_skip))
        c3.metric("🤔 文脈依存", len(all_context_dep))
        c4.metric("📉 データ不足", len(all_insufficient))

        st.divider()

        # 強い推奨 (⚡) を優先表示
        if promote_mask:
            st.markdown("### ⚡ マスク確定推奨 (90%+ がマスク判断)")
            for term, e in promote_mask:
                _render_term_card(term, e, customer_id, key_prefix="hist_pm")

        if promote_skip:
            st.markdown("### ⚡ 素通し確定推奨 (90%+ が素通し判断)")
            for term, e in promote_skip:
                _render_term_card(term, e, customer_id, key_prefix="hist_ps")

        if context_dep:
            with st.expander(
                f"🤔 文脈依存 ({len(context_dep)} 種類) - 表示するには展開",
                expanded=False,
            ):
                for term, e in context_dep:
                    _render_term_card(term, e, customer_id, key_prefix="hist_cd")

        if insufficient:
            with st.expander(
                f"📉 データ不足 ({len(insufficient)} 種類、5 件未満) - 表示するには展開",
                expanded=False,
            ):
                for term, e in insufficient:
                    _render_term_card(term, e, customer_id, key_prefix="hist_id")

        if is_limited:
            if st.button(
                f"📂 もっと見る (残り {remaining_terms} 件)",
                key="history_expand_btn",
            ):
                st.session_state[HISTORY_EXPANDED_STATE_KEY] = True
                st.rerun()
        elif total_terms > HISTORY_DEFAULT_LIMIT:
            if st.button(
                f"📁 上位 {HISTORY_DEFAULT_LIMIT} 件のみ表示に戻す",
                key="history_collapse_btn",
            ):
                st.session_state[HISTORY_EXPANDED_STATE_KEY] = False
                st.rerun()
