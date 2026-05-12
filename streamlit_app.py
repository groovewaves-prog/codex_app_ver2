"""Streamlit UI for secure_review (Japanese localization).

Design intent:
- This is a forensic tool. Clarity of decision state beats decoration.
- Three decisions are visually distinct at a glance: safe (green), needs
  confirm (amber), blocked (red).
- The four-step flow enforces R2: no external call happens before the user
  has seen the sanitized preview and explicitly confirmed each
  mask_and_continue document.

Run with:
    streamlit run streamlit_app.py
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import traceback
import uuid
from pathlib import Path

import streamlit as st

from secure_review.app import _run_sanitization_pipeline, _enforce_outbound_guard
from secure_review.env_loader import load_dotenv
from secure_review.models import (
    MaskingPipelineState,
    NerCandidate,
    SanitizedDocument,
    UploadedDocument,
)
from secure_review.network_guard import LocalUrlError
from secure_review.reviewer import choose_provider
# Phase 7 段階 2-C (2026-05-08): 章単位深堀り
from secure_review.rubric import ChapterSection, extract_chapters_from_text
from secure_review.run_masking_pipeline import (
    apply_user_decisions,
    run_masking_pipeline,
)

# R-W-2/3/4 (2026-05-08): マスク判断履歴 UI モジュール
from streamlit_audit_ui import (
    ensure_session_state,
    render_customer_selector,
    render_session_summary,
    render_log_export_button,
    render_history_panel,
)

# R-W (2026-05-08): セッション状態 (customer_id, audit_session_id) を初期化
ensure_session_state()

# R-X-1 (2026-05-08): file_uploader の動的 key を初期化。
# セッションリセット時にこの key を新規発行することで、widget 自身を
# 新規描画させ、視覚的にもファイル一覧をクリアする。
if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = f"uploads_{uuid.uuid4().hex[:8]}"


# Load .env once per session so settings survive reruns.
# On Streamlit Community Cloud, values live in st.secrets instead of a .env
# file; we bridge them to os.environ so that the rest of the codebase
# (which reads via os.getenv) works unchanged in both environments.
if "env_loaded" not in st.session_state:
    load_dotenv()
    try:
        for key, value in st.secrets.items():
            if isinstance(value, (str, int, float, bool)) and key not in os.environ:
                os.environ[key] = str(value)
    except (FileNotFoundError, st.errors.StreamlitSecretNotFoundError):
        # No secrets.toml present (typical for local dev). Not an error.
        pass
    except Exception:
        # Any other access issue should not block local use.
        pass
    st.session_state.env_loaded = True


st.set_page_config(
    page_title="セキュアレビュー",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------------------------- style

STYLE = """
<style>
:root {
    --bg-base: #f4efe6;
    --bg-card: #ffffff;
    --ink: #1f2a1d;
    --ink-soft: #4a5549;
    --accent: #2f6d3a;
    --accent-soft: #e6efe2;
    --warn: #a16b1a;
    --warn-soft: #f6ead1;
    --danger: #9a2a2a;
    --danger-soft: #f4dcdc;
    --rule: #d9d1c0;
}

.stApp {
    background: var(--bg-base);
    color: var(--ink);
}

.block-container { padding-top: 2rem; max-width: 1200px; }

h1, h2, h3 { font-family: 'Georgia', 'Hiragino Mincho ProN', 'Yu Mincho', 'Times New Roman', serif; color: var(--ink); letter-spacing: -0.01em; }

.decision-badge {
    display: inline-block;
    padding: 0.18rem 0.7rem;
    border-radius: 2px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', sans-serif;
}
.decision-safe   { background: var(--accent-soft); color: var(--accent); border-left: 3px solid var(--accent); }
.decision-mask   { background: var(--warn-soft);   color: var(--warn);   border-left: 3px solid var(--warn); }
.decision-block  { background: var(--danger-soft); color: var(--danger); border-left: 3px solid var(--danger); }

.doc-card {
    background: var(--bg-card);
    border: 1px solid var(--rule);
    border-left: 4px solid var(--accent);
    padding: 1rem 1.2rem;
    margin-bottom: 0.8rem;
}
.doc-card.mask  { border-left-color: var(--warn); }
.doc-card.block { border-left-color: var(--danger); }

.doc-meta {
    color: var(--ink-soft);
    font-size: 0.82rem;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
}

.step-header {
    font-family: 'Georgia', 'Hiragino Mincho ProN', 'Yu Mincho', serif;
    color: var(--ink-soft);
    font-size: 0.82rem;
    letter-spacing: 0.12em;
    margin-top: 1.5rem;
    margin-bottom: 0.3rem;
}

pre.sanitized {
    background: #fafaf6;
    border: 1px solid var(--rule);
    padding: 0.8rem;
    font-size: 0.78rem;
    max-height: 280px;
    min-height: 60px;
    overflow-y: auto;
    resize: vertical;
    white-space: pre-wrap;
}

.muted { color: var(--ink-soft); font-size: 0.88rem; }
hr { border: none; border-top: 1px solid var(--rule); margin: 1.2rem 0; }

.issue-row {
    border-left: 3px solid var(--rule);
    padding: 0.4rem 0.9rem;
    margin-bottom: 0.5rem;
    background: var(--bg-card);
}
.issue-row.high   { border-left-color: var(--danger); }
.issue-row.medium { border-left-color: var(--warn); }
.issue-row.low    { border-left-color: var(--accent); }
.issue-row.info   { border-left-color: var(--ink-soft); }

.provider-line {
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.78rem;
    color: var(--ink-soft);
}
</style>
"""
st.markdown(STYLE, unsafe_allow_html=True)


# ------------------------------------------------------------------- helpers

DECISION_CLASSES = {
    "safe": "decision-safe",
    "mask_and_continue": "decision-mask",
    "block": "decision-block",
    "unknown": "decision-mask",
}

DECISION_LABELS = {
    "safe": "安全",
    "mask_and_continue": "要確認",
    "block": "送信禁止",
    "unknown": "不明",
}

SEVERITY_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "情報",
}

PROFILE_LABELS = {
    "design": "設計書",
    "proposal": "企画書",
    "change_runbook": "変更・切替手順書",
    "operations_runbook": "保守・運用手順書",
    "source_code": "ソースコード",
}

# B3: total verdict labels (A / B / C / D from the structured summary).
VERDICT_LABELS = {
    "A": "A: 問題なし",
    "B": "B: 軽微な指摘",
    "C": "C: 重要指摘あり",
    "D": "D: リリース不可",
}

# B3: total verdict to existing decision-* CSS class for color reuse.
# A reuses decision-safe (green), B uses decision-safe-light (light green),
# C reuses decision-mask (orange/amber), D reuses decision-block (red).
VERDICT_CSS_CLASS = {
    "A": "decision-safe",
    "B": "decision-safe",
    "C": "decision-mask",
    "D": "decision-block",
}

# B3: required_timing badge to color hint. Mapped to existing decision-*
# classes for visual consistency.
REQUIRED_TIMING_CSS_CLASS = {
    "リリース前必須": "decision-block",      # red
    "詳細設計開始前": "decision-mask",        # orange
    "運用開始前": "decision-mask",            # orange
    "次フェーズで可": "decision-safe",        # green
}


def _decision_badge(decision: str) -> str:
    css = DECISION_CLASSES.get(decision, "decision-mask")
    label = DECISION_LABELS.get(decision, decision)
    return f'<span class="decision-badge {css}">{label}</span>'


def _doc_card_class(decision: str) -> str:
    if decision == "block":
        return "doc-card block"
    if decision == "mask_and_continue":
        return "doc-card mask"
    return "doc-card"


def _profile_label(value: str | None) -> str:
    if value is None:
        return "-"
    return PROFILE_LABELS.get(value, value)


def _verdict_badge(verdict: str) -> str:
    """B3: render an A/B/C/D verdict badge using existing decision-* classes."""
    if not verdict:
        return ""
    label = VERDICT_LABELS.get(verdict, f"判定: {verdict}")
    css = VERDICT_CSS_CLASS.get(verdict, "decision-mask")
    return f'<span class="decision-badge {css}">{label}</span>'


def _required_timing_badge(timing: str) -> str:
    """B3: render a required-timing badge with color based on urgency."""
    if not timing:
        return ""
    css = REQUIRED_TIMING_CSS_CLASS.get(timing, "decision-mask")
    return f'<span class="decision-badge {css}">{timing}</span>'


def _re_review_badge(re_review_required: bool) -> str:
    """B3: render a re-review-required badge."""
    if re_review_required:
        return '<span class="decision-badge decision-mask">再レビュー要</span>'
    return ""


def _reset_state() -> None:
    for key in (
        "preview_docs",
        "preview_warnings",
        "preview_security",
        "preview_error",
        "preview_trace",
        "preview_attempted",
        "send_approval",
        "anonymization_details_visible",
        "review_result",
        # R-M (PR-D2)
        "masking_states",
        "user_decisions",
        "last_uploaded_filenames",
        # R-Y (2026-05-08): 深堀結果。リセット時にクリアしないと、
        # 次のレビュー実行時に同名文書の旧深堀結果が表示されてしまう。
        "deep_dive_results",
        # Phase 7 段階 2-C (2026-05-08): 章境界キャッシュ。文書が変われば再計算。
        "chapter_sections_cache",
    ):
        st.session_state.pop(key, None)


def _natural_sort_key(name: str) -> tuple:
    """R-Q-1b (2026-05-06): 自然順ソート用キー。

    Streamlit の ``st.file_uploader`` は複数ファイルを並列アップロード
    するため、``st.session_state.uploads`` の格納順は完了順 (≒ファイル
    サイズ・ネット速度依存) になる。``基本設計書 1, 2, ..., 12`` のような
    番号付き設計書を投入したとき、12 → 5 → 2 のような無秩序な順番で
    LLM に渡してしまうと、レビューが「セクション順序が不明」「文書 N が
    欠落」のような誤指摘を出すことがあった。

    本関数はファイル名を「数字塊」と「非数字塊」に分け、数字塊は
    int に変換することで、辞書順 (``1`` < ``10`` < ``2``) ではなく
    数値順 (``1`` < ``2`` < ``10``) でソートできるようにする。

    例:
        "基本設計書 1.pdf"  -> ("基本設計書 ", 1, ".pdf")
        "基本設計書 2.pdf"  -> ("基本設計書 ", 2, ".pdf")
        "基本設計書 10.pdf" -> ("基本設計書 ", 10, ".pdf")

    非数字部分は lowercase 化して大文字小文字差を吸収する。
    """
    parts = re.split(r"(\d+)", name)
    return tuple(int(p) if p.isdigit() else p.lower() for p in parts)


def _get_uploads() -> list:
    """R-X-1 (2026-05-08): 動的 uploader_key からファイル一覧を取得。

    file_uploader の key を ``st.session_state.uploader_key`` から取得することで、
    リセット時の key 再発行による widget 再描画に対応する。
    """
    key = st.session_state.get("uploader_key", "uploads")
    return st.session_state.get(key, []) or []


def _detect_duplicate_uploads() -> list[tuple[str, str]]:
    """R-X-2 (2026-05-08): SHA256 ハッシュでアップロードの重複を検出する。

    Returns:
        ``[(重複ファイル名, 先に検出された同一内容ファイル名), ...]`` のリスト。
        空 list なら重複なし。判定はファイル名ではなくバイト内容で行うため、
        同名でも内容が違えば重複扱いしない (逆も同様)。
    """
    seen: dict[str, str] = {}  # hash -> 最初に登録された filename
    duplicates: list[tuple[str, str]] = []
    for upload in _get_uploads():
        try:
            content = upload.getvalue()
        except Exception:  # noqa: BLE001
            continue
        h = hashlib.sha256(content).hexdigest()
        if h in seen:
            duplicates.append((upload.name, seen[h]))
        else:
            seen[h] = upload.name
    return duplicates


def _uploaded_to_documents() -> list[UploadedDocument]:
    """アップロードファイルを UploadedDocument のリストに変換する。

    R-Q-1b: 戻り値は ``_natural_sort_key`` で安定化された順序になる。
    Streamlit の並列アップロード完了順に依存しないので、LLM プロンプト
    も「番号付きファイル名 → 番号順」で組み立てられる。
    """
    items: list[UploadedDocument] = []
    uploads = _get_uploads()  # R-X-1: 動的 uploader_key 経由
    # R-Q-1b: stabilise ordering by natural-sort filename
    uploads_sorted = sorted(uploads, key=lambda u: _natural_sort_key(u.name))
    for upload in uploads_sorted:
        content = upload.getvalue()
        items.append(
            UploadedDocument(
                name=upload.name,
                content=base64.b64encode(content).decode("ascii"),
                content_type=upload.type or "application/octet-stream",
                transfer_encoding="base64",
            )
        )
    return items


def _render_anonymization_summary(preview_docs: list[SanitizedDocument]) -> None:
    counts = {"safe": 0, "mask_and_continue": 0, "block": 0, "unknown": 0}
    replacement_count = 0
    estimated_tokens = 0
    uncertain_count = 0
    masking_states = st.session_state.get("masking_states", {}) or {}
    for doc in preview_docs:
        counts[doc.local_sensitivity_decision] = counts.get(doc.local_sensitivity_decision, 0) + 1
        replacement_count += len(getattr(doc, "replacements", []) or [])
        estimated_tokens += int(getattr(doc, "estimated_input_tokens", 0) or 0)
        state = masking_states.get(doc.name)
        if state is not None:
            uncertain_count += len(getattr(state, "uncertain_candidates", []) or [])

    st.markdown("#### 匿名化結果サマリ")
    cols = st.columns(6)
    cols[0].metric("文書数", len(preview_docs))
    cols[1].metric("安全", counts.get("safe", 0))
    cols[2].metric("要確認", counts.get("mask_and_continue", 0))
    cols[3].metric("送信禁止", counts.get("block", 0))
    cols[4].metric("置換数", replacement_count)
    cols[5].metric("未確定候補", uncertain_count)
    st.caption(
        f"LLM 送信対象の推定トークン数: {estimated_tokens:,}。"
        "送信されるのは匿名化済みテキストのみです。"
    )


def _render_anonymization_detail_panel(preview_docs: list[SanitizedDocument]) -> None:
    st.markdown("#### 匿名化後テキスト確認")
    st.caption(
        "下記が外部 LLM に送信される匿名化済みテキストです。"
        "必要に応じて置換一覧も確認してください。"
    )
    for doc in preview_docs:
        digest = hashlib.sha256(
            f"{doc.name}|{doc.outbound_text}|{doc.sanitized_excerpt}".encode("utf-8")
        ).hexdigest()[:12]
        with st.expander(f"📄 {doc.name} の匿名化結果", expanded=True):
            meta_cols = st.columns(4)
            meta_cols[0].metric("推定トークン", doc.estimated_input_tokens)
            meta_cols[1].metric("置換数", len(doc.replacements))
            meta_cols[2].metric("外部送信リスク", doc.outbound_risk)
            meta_cols[3].metric(
                "判定",
                {
                    "safe": "安全",
                    "mask_and_continue": "要確認",
                    "block": "送信禁止",
                }.get(doc.local_sensitivity_decision, doc.local_sensitivity_decision),
            )
            tabs = st.tabs(["LLM送信対象テキスト", "匿名化後の抜粋", "置換一覧"])
            with tabs[0]:
                st.text_area(
                    "LLM送信対象テキスト",
                    value=doc.outbound_text or "(空)",
                    height=260,
                    disabled=True,
                    key=f"outbound_text_confirm_{digest}",
                    label_visibility="collapsed",
                )
            with tabs[1]:
                st.text_area(
                    "匿名化後の抜粋",
                    value=doc.sanitized_excerpt or "(空)",
                    height=220,
                    disabled=True,
                    key=f"sanitized_excerpt_confirm_{digest}",
                    label_visibility="collapsed",
                )
            with tabs[2]:
                if doc.replacements:
                    rows = [
                        {"プレースホルダ": r.placeholder, "カテゴリ": r.category, "原文": r.original}
                        for r in doc.replacements
                    ]
                    st.dataframe(rows, width='stretch', hide_index=True)
                else:
                    st.caption("置換は記録されませんでした。")


def _find_chapter_overview(review, doc_name: str, chapter: ChapterSection):
    for overview in getattr(review, "chapter_overviews", ()) or ():
        source = getattr(overview, "source_document", "")
        chapter_id = getattr(overview, "chapter_id", "")
        chapter_label = getattr(overview, "chapter_label", "")
        if source == doc_name and chapter_id and chapter_id == chapter.chapter_id:
            return overview
        if source == doc_name and chapter_label == chapter.chapter_label:
            return overview
    return None


def _chapter_excerpt(text: str, limit: int = 220) -> str:
    cleaned = re.sub(r"\s+", " ", text or "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + "..."


def _run_chapter_deep_dive(
    doc_name: str,
    chapter: ChapterSection,
    review,
    document_profile_override: str | None,
) -> None:
    preview_docs = st.session_state.get("preview_docs") or []
    if not preview_docs:
        st.error("preview_docs が見つかりません。ステップ 1〜3 を再実行してください。")
        return
    try:
        provider_impl = choose_provider()
        if provider_impl.name == "mock":
            st.warning(
                "⚠️ mock プロバイダでは章単位深堀りも実質通常レビューと同じです。"
            )
        _enforce_outbound_guard(provider_impl.name, preview_docs)
        with st.spinner(
            f"{provider_impl.name} で「{chapter.chapter_label}」を深堀レビュー中..."
        ):
            deep_review = provider_impl.review(
                preview_docs,
                document_profile_override,
                deep_dive_target=doc_name,
                existing_issues=review.issues,
                chapter=chapter,
            )
        if "deep_dive_results" not in st.session_state:
            st.session_state.deep_dive_results = {}
        st.session_state.deep_dive_results.setdefault(doc_name, []).append(deep_review)
        st.rerun()
    except LocalUrlError as exc:
        st.error(f"ローカルエンドポイントの設定に問題があります: {exc}")
    except ValueError as exc:
        st.error(str(exc))
    except RuntimeError as exc:
        st.error(str(exc))
    except Exception as exc:  # noqa: BLE001
        request_id = uuid.uuid4().hex[:8]
        st.error(f"章単位深堀りに失敗しました ({request_id})。")
        with st.expander("詳細トレース"):
            st.code(traceback.format_exc())

# ----------------------------------------------------------------------
# R-M (PR-D2) helpers: NER + 法人名検索によるカスタムマスク辞書統合。
#
# 設計判断 (handoff_R-M_2026-05-03.md D5/D6/D8):
# - _is_rm_enabled: Streamlit Secrets の R_M_DISABLED が "true" でない限り
#   R-M 機能は有効 (デフォルト ON、緊急時は Secrets で OFF にできる)
# - _get_ner_masker / _get_hojin_lookup: @st.cache_resource でプロセス内
#   に 1 回だけロード。失敗時は None を返してパイプラインを既存挙動に
#   フォールバック
# - _build_sanitizer: あえてキャッシュしない。SensitiveDataSanitizer は
#   内部に counter を持つので、毎回新規にして文書ごとに [COMPANY_001]
#   から始まるように保つ
# ----------------------------------------------------------------------


def _is_rm_enabled() -> bool:
    """R-M (Phase 1+2) を有効にするか判定する。

    Streamlit Secrets に ``R_M_DISABLED = "true"`` が設定されていれば
    機能を完全に無効化 (UI も非表示)。デフォルトは ON。緊急時に
    コード変更なしで Secrets だけで OFF にできるキルスイッチ。
    """
    try:
        flag = st.secrets.get("R_M_DISABLED", "false")
        return str(flag).lower() != "true"
    except Exception:
        return True


@st.cache_resource(show_spinner="日本語 NER モデル (ja_core_news_md) をロード中...")
def _get_ner_masker():
    """NerMasker をロードして返す。失敗時は None。

    R-M Phase 1: spaCy + EntityRuler + シード辞書 (data/ner_seeds.yaml)。
    """
    if not _is_rm_enabled():
        return None
    try:
        from secure_review.ner_masker import NerMasker

        # R-V (2026-05-08): customer_id を渡して顧客 PJ 固有 seed dict もロード
        return NerMasker(
            seed_yaml_path="data/ner_seeds.yaml",
            customer_id=st.session_state.get("customer_id", "kddi_mail_relay"),
        )
    except Exception as exc:  # noqa: BLE001
        st.warning(
            f"NER モデルの初期化に失敗しました。R-M 機能はオフで動作します。"
            f"詳細: {type(exc).__name__}: {exc}"
        )
        return None


@st.cache_resource
def _get_hojin_lookup():
    """HojinLookup をロードして返す。トークン未設定時は None。

    R-M Phase 2: gBizINFO API クライアント。
    GBIZINFO_API_TOKEN が Streamlit Secrets に未設定の環境では None を
    返し、未確定候補に対する gBizINFO 検索は行われない (NER だけは動く)。
    """
    if not _is_rm_enabled():
        return None
    try:
        token = st.secrets.get("GBIZINFO_API_TOKEN", "")
    except Exception:
        token = ""
    if not token:
        return None
    try:
        from secure_review.hojin_lookup import HojinLookup

        return HojinLookup(api_token=token)
    except Exception as exc:  # noqa: BLE001
        st.warning(
            f"HojinLookup の初期化に失敗しました。gBizINFO 検索は無効化されます。"
            f"詳細: {type(exc).__name__}: {exc}"
        )
        return None


def _build_sanitizer():
    """SensitiveDataSanitizer を新規生成する (キャッシュしない)。

    Sanitizer は内部に placeholder counter / _seen を持つので、
    キャッシュすると複数文書で counter が連続してしまう。文書ごとに
    [COMPANY_001] から始まるように、呼び出し毎に新規インスタンス。
    """
    from secure_review.sanitizer import SensitiveDataSanitizer

    return SensitiveDataSanitizer()


def _decision_key(doc_name: str, candidate_text: str) -> str:
    """user_decisions の session_state キーを構築する。

    同名候補が異なる文書に現れた場合に判断を独立させるため doc 名を含める。
    """
    return f"{doc_name}::{candidate_text}"


def _render_uncertain_candidates_card(
    state: MaskingPipelineState,
    full_text: str = "",
) -> None:
    """1 つの文書の未確定候補リストを UI に描画する。

    各候補について gBizINFO 検索結果と「マスクする / しない」ラジオを
    表示し、ユーザの選択を ``st.session_state.user_decisions`` に格納する。
    デフォルトは「マスクする」(D4 安全側)。

    PR-F: 候補テキストの周辺コンテキスト (前後 30 文字) を表示する。
    「東京」のような単語が「東京リージョン」「東京都」「東京駅」のいずれを
    指すかをユーザが判断できるようにするため。``full_text`` が空文字の
    場合 (古い呼び出しや抽出失敗) は文脈表示をスキップする。

    Args:
        state: その文書の MaskingPipelineState。
        full_text: 元のテキスト全体 (extractor 抽出済み)。文脈抜粋に使う。
    """
    user_decisions = st.session_state.setdefault("user_decisions", {})

    # 確定済み候補 (シード辞書ヒット + PR-F で gBizINFO 失敗から昇格したもの)
    if state.confirmed_findings:
        with st.expander(
            f"自動マスク済み ({len(state.confirmed_findings)} 件)",
            expanded=False,
        ):
            st.caption(
                "シード辞書ヒット、または gBizINFO 検索が失敗 (404 / ネット"
                "ワークエラー等) した候補です。後者は判断材料がないため安全側"
                "でマスクしています。マスクを外したい場合は手動で対応して"
                "ください。"
            )
            for value, label in state.confirmed_findings:
                st.markdown(f"- `{value}` → カテゴリ: **{label}**")

    if not state.uncertain_candidates:
        return

    with st.expander(
        f"⚠️ マスク候補 ({len(state.uncertain_candidates)} 件、ご確認ください)",
        expanded=True,  # 注意喚起のため初期は開いておく
    ):
        st.caption(
            "以下の固有名詞が未確定候補として検出されました。"
            "それぞれについて、外部 LLM に送信する前にマスクするかをお選びください。"
            "迷う場合は **マスクする** を推奨 (機密漏洩防止優先)。"
        )

        # PR-F: 候補数が多い場合は固定高さのスクロールコンテナに入れる。
        # 5 件以下: 余白が出ないようコンテナなし。
        # 6 件以上: height=600 px のスクロールコンテナで縦伸びを防ぐ。
        _num_candidates = len(state.uncertain_candidates)
        if _num_candidates > 5:
            _scroll_container = st.container(height=600, border=False)
        else:
            _scroll_container = st.container(border=False)

        with _scroll_container:
            for cand in state.uncertain_candidates:
                with st.container(border=True):
                    # 候補テキスト + ラベル
                    st.markdown(
                        f"**「{cand.text}」** "
                        f"<span class='muted'>(カテゴリ: {cand.label} / "
                        f"spaCy: {cand.spacy_label})</span>",
                        unsafe_allow_html=True,
                    )

                    # コンテキスト抜粋 (PR-F)
                    if full_text and cand.start >= 0 and cand.end > cand.start:
                        ctx_start = max(0, cand.start - 30)
                        ctx_end = min(len(full_text), cand.end + 30)
                        before = full_text[ctx_start:cand.start]
                        after = full_text[cand.end:ctx_end]
                        # 改行は半角スペースに置換して 1 行に
                        before_clean = before.replace("\n", " ").replace("\r", " ")
                        after_clean = after.replace("\n", " ").replace("\r", " ")
                        prefix = "..." if ctx_start > 0 else ""
                        suffix = "..." if ctx_end < len(full_text) else ""
                        st.markdown(
                            f"📝 文脈: {prefix}{before_clean}**{cand.text}**{after_clean}{suffix}"
                        )

                    # gBizINFO 検索結果
                    lookup = state.lookups.get(cand.text)
                    if lookup is None:
                        st.caption("gBizINFO 検索: 未実行 (トークン未設定または機能無効)")
                    elif lookup.error:
                        # PR-F: error あり候補は run_masking_pipeline の昇格処理で
                        # confirmed に移されるため、本来 uncertain には現れないはず。
                        # 念のため警告として表示。
                        st.warning(
                            f"🏢 gBizINFO 検索失敗: {lookup.error}。"
                            "判断は人間にお任せします。"
                        )
                    else:
                        if lookup.hits == 0:
                            st.caption(
                                "🏢 gBizINFO 検索: ヒット 0 件 "
                                "(法人名としては未登録)"
                            )
                        else:
                            top_str = "、".join(lookup.top_names[:5])
                            st.markdown(
                                f"🏢 gBizINFO 検索: **{lookup.hits} 件**ヒット"
                                + (f" — {top_str}" if top_str else "")
                            )

                    # ラジオボタン (デフォルト: マスクする)
                    key = _decision_key(state.name, cand.text)
                    # 初期値: 既存の判断があれば維持、なければ True (マスク)
                    current = user_decisions.get(key, True)
                    choice = st.radio(
                        "判断",
                        options=["マスクする (推奨)", "マスクしない"],
                        index=0 if current else 1,
                        key=f"radio_{key}",
                        horizontal=True,
                        label_visibility="collapsed",
                    )
                    user_decisions[key] = choice == "マスクする (推奨)"


# ------------------------------------------------------------------- sidebar

with st.sidebar:
    st.markdown("### 🛡 セキュアレビュー")
    st.caption("外部 LLM へ送信する前に、ローカル環境で匿名化を実施します。")
    st.markdown("---")

    provider = os.getenv("REVIEW_PROVIDER", "mock")
    local_san = os.getenv("LOCAL_SANITIZER_PROVIDER", "none")
    local_sens = os.getenv("LOCAL_SENSITIVITY_PROVIDER", "heuristic")

    st.markdown("##### 動作環境")
    st.markdown(
        f'<div class="provider-line">レビュー LLM   → <b>{provider}</b><br/>'
        f"匿名化         → <b>{local_san}</b><br/>"
        f'機密度判定     → <b>{local_sens}</b></div>',
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("##### レビュー対象プロファイル")
    profile_options = [
        ("(自動判定)", None),
        ("設計書", "design"),
        ("変更・切替手順書", "change_runbook"),
        ("保守・運用手順書", "operations_runbook"),
        ("ソースコード", "source_code"),
    ]
    profile_label = st.selectbox(
        "プロファイル指定",
        [label for label, _ in profile_options],
        index=0,
        label_visibility="collapsed",
    )
    document_profile_override = dict(profile_options)[profile_label]

    st.markdown("---")

    # R-V (2026-05-08): 顧客 PJ セレクタ
    render_customer_selector(sidebar=False)

    st.markdown("---")
    if st.button("セッションをリセット", width='stretch'):
        _reset_state()
        # R-X-1 (2026-05-08): 旧 uploader_key の widget 状態を pop し、
        # 新しい key を発行することで、file_uploader を視覚的にも空にする。
        old_key = st.session_state.get("uploader_key")
        if old_key:
            st.session_state.pop(old_key, None)
        st.session_state.uploader_key = f"uploads_{uuid.uuid4().hex[:8]}"
        st.rerun()

    st.caption(
        "アップロードされた文書はサーバ上に保存されません。"
        "本セッション中のメモリ上のみで処理されます。"
    )

    # ----------------------------------------------------------------
    # 開発者モード (2026-05-08 追加)
    # 実務ユーザの画面をすっきり保つため、デバッグ・実験 UI を分離する。
    # OFF (デフォルト): 実務機能のみ表示
    # ON: プロンプトプレビュー / LLM 生レスポンス / NER Diagnostics /
    #     gBizINFO Diagnostics などの実験・診断 UI が追加表示される
    # 環境変数 DEVELOPER_MODE_DEFAULT=true で初期値を ON にできる。
    # ----------------------------------------------------------------
    st.markdown("---")
    _developer_mode_default = (
        os.getenv("DEVELOPER_MODE_DEFAULT", "false").strip().lower() == "true"
    )
    if "developer_mode" not in st.session_state:
        st.session_state.developer_mode = _developer_mode_default

    st.session_state.developer_mode = st.toggle(
        "⚙️ 開発者モード",
        value=st.session_state.developer_mode,
        help=(
            "OFF (デフォルト): 実務機能のみ表示。"
            "ON: プロンプトプレビュー、LLM 生レスポンス、NER Diagnostics、"
            "gBizINFO Diagnostics などの実装検証用 UI が追加表示されます。"
            " 環境変数 DEVELOPER_MODE_DEFAULT=true で初期値を ON にできます。"
        ),
    )

    # ----------------------------------------------------------------
    # 採用規格セクション (2026-05-08 追加)
    # 本ツールのレビュー基準が依拠する業界標準を明示する。
    # ユーザの「文書構造については、参照した業界標準についてツールのどこ
    # かに記載してもらえますか?」というご要望への対応。
    # 詳細は文書「設計書 構造定義書 v0.2」を参照。
    # ----------------------------------------------------------------
    st.markdown("---")
    with st.expander("📚 採用規格 (レビュー基準の根拠)", expanded=False):
        st.markdown(
            "本ツールのレビュー基準は、以下の業界標準・公的ガイドラインに"
            "基づいて構築されています。"
        )
        st.markdown(
            "**🇯🇵 IPA「機能要件の合意形成ガイド」**  \n"
            "(独) 情報処理推進機構が公開する設計実務向けガイド。"
            "日本の SI 業界で広く参照される。  \n"
            "→ 本ツールでは **章立てのベース構造** に採用。"
        )
        st.markdown(
            "**☁️ AWS Well-Architected Framework**  \n"
            "AWS が公開するクラウドベストプラクティス集。"
            "クラウド設計の事実上の業界標準。  \n"
            "5 つの柱: 運用 (OE) / セキュリティ (SEC) / 信頼性 (REL) "
            "/ パフォーマンス (PERF) / コスト (COST)  \n"
            "→ 本ツールでは **非機能要件と各章のチェック項目** に採用。"
        )
        st.markdown(
            "**🌐 ISO/IEC 25010 (旧 JIS X 0129)**  \n"
            "ソフトウェア・システム品質モデルの国際標準。"
            "8 つの品質特性を定義。  \n"
            "機能適合性 / 性能効率性 / 互換性 / 使用性 / 信頼性 / "
            "セキュリティ / 保守性 / 移植性  \n"
            "→ 本ツールでは **品質特性のチェック観点** に採用。"
        )
        st.caption(
            "詳細は社内ドキュメント「設計書 構造定義書」を参照してください。"
        )


# --------------------------------------------------------------------- main

st.markdown("## セキュアレビュー")
st.markdown(
    '<p class="muted">外部に文書が送信される前に、ローカル匿名化と機密度判定で'
    'レビュー対象を確認します。</p>',
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------
# R-M (PR-D2) 設定セクション
# ----------------------------------------------------------------------

if _is_rm_enabled():
    with st.expander(
        "🔧 R-M (カスタム辞書 + 法人名検索) 設定",
        expanded=False,
    ):
        st.caption(
            "R-M Phase 1+2: 既存の正規表現マスキングに加え、spaCy NER と "
            "EntityRuler によるシード辞書、gBizINFO による法人名検索を統合し、"
            "未確定の固有名詞についてユーザに判断を委ねる機能。"
        )

        # 機能 ON/OFF (デフォルト ON)
        rm_enabled_user = st.checkbox(
            "この機能を使う (推奨: ON)",
            value=True,
            key="rm_enabled_user",
            help=(
                "OFF にすると、既存の正規表現マスキングのみで処理します。"
                "シード辞書ヒットや gBizINFO 検索は行いません。"
            ),
        )

        # gBizINFO トークン状態の透明性表示
        try:
            _rm_token = st.secrets.get("GBIZINFO_API_TOKEN", "")
        except Exception:
            _rm_token = ""
        if _rm_token:
            st.caption("✅ GBIZINFO_API_TOKEN は設定済みです (gBizINFO 検索が有効)")
        else:
            st.caption(
                "⚠️ GBIZINFO_API_TOKEN は未設定です。"
                "シード辞書 + spaCy NER のみで動作し、未確定候補に対する"
                "gBizINFO 検索結果は表示されません。"
            )
else:
    rm_enabled_user = False


# -- Step 1: Upload --------------------------------------------------------

st.markdown('<div class="step-header">ステップ 1 — 文書アップロード</div>', unsafe_allow_html=True)

st.file_uploader(
    "ファイルを選択",
    accept_multiple_files=True,
    key=st.session_state.uploader_key,  # R-X-1: 動的 key (リセット時に再発行)
    label_visibility="collapsed",
    help=(
        "対応形式: txt, md, docx, xlsx, pptx, pdf, csv, json, yaml/yml, xml, "
        "html, スクリプト (py, ps1, sh, vbs, sql など), 画像。"
        " 同一内容のファイルは重複検出されアップロードできません。"
    ),
)

col1, col2 = st.columns([1, 5])
with col1:
    preview_clicked = st.button(
        "匿名化結果を確認",
        type="primary",
        disabled=not _get_uploads(),  # R-X-1: 動的 uploader_key 経由
        width='stretch',
    )
with col2:
    _uploads_now = _get_uploads()
    if _uploads_now:
        names = ", ".join(u.name for u in _uploads_now)
        st.markdown(f'<div class="muted">処理待ち: {names}</div>', unsafe_allow_html=True)


if preview_clicked:
    st.session_state.preview_attempted = True
    for key in (
        "preview_docs",
        "preview_warnings",
        "preview_error",
        "preview_trace",
        "send_approval",
        "anonymization_details_visible",
        "review_result",
    ):
        st.session_state.pop(key, None)

    # Phase 7 段階 1.5 (2026-05-08): docs_checked フラグ廃止に伴い、リセット不要に
    # 古い deep_dive_results も新 preview には不適合なのでクリア
    st.session_state.pop("deep_dive_results", None)
    # Phase 7 段階 2-C (2026-05-08): 章キャッシュも古い文書のものなのでクリア
    st.session_state.pop("chapter_sections_cache", None)

    # R-X-2 (2026-05-08): SHA256 で重複アップロードを検出し、あれば中断
    duplicates = _detect_duplicate_uploads()
    if duplicates:
        dup_lines = "\n".join(
            f"- **{name}** は **{seen}** と内容が同一です"
            for name, seen in duplicates
        )
        st.error(
            f"⚠️ **重複アップロード検出 ({len(duplicates)} 件)**\n\n"
            f"{dup_lines}\n\n"
            "重複ファイルを × で削除してから再度「匿名化してプレビュー」を押してください。"
            " (「セッションをリセット」で全ファイル一括クリアも可能)"
        )
        st.stop()  # 以降の preview 処理を中断

    documents = _uploaded_to_documents()
    progress = st.progress(0, text="文書を読み込んでいます...")
    try:
        progress.progress(20, text="ローカル匿名化パイプラインを開始しています...")
        with st.spinner("ローカルで匿名化中..."):
            progress.progress(45, text="抽出・匿名化・機密度判定を実行しています...")
            sanitized, warnings = _run_sanitization_pipeline(documents)
        progress.progress(85, text="匿名化結果プレビューを準備しています...")
        st.session_state.preview_docs = sanitized
        st.session_state.preview_warnings = warnings
        st.session_state.anonymization_details_visible = True
        st.session_state.pop("review_result", None)

        # ----- R-M (PR-D2): 未確定候補抽出と gBizINFO 検索 -----
        # rm_enabled_user は Step 0 のチェックボックスで設定。
        # 既存の sanitize は preview_docs に既に格納済み。R-M はそれを
        # 上書きせず、masking_states として並行に管理する。送信時 (Step
        # 3) に apply_user_decisions で preview_docs を再生成する。
        if rm_enabled_user:
            ner_masker = _get_ner_masker()
            hojin_lookup = _get_hojin_lookup()
            masking_states: dict[str, MaskingPipelineState] = {}
            try:
                with st.spinner("R-M (NER + 法人名検索) を実行中..."):
                    for sdoc in sanitized:
                        # _run_sanitization_pipeline は extractor で PDF /
                        # DOCX / XLSX 等からテキスト抽出を済ませてから
                        # regex マスキングを行う。NER の入力には
                        # **抽出済みのテキスト** を使う必要があるため、
                        # base64 で生バイナリを decode するのではなく、
                        # SanitizedDocument.original_excerpt を渡す。
                        # original_excerpt は extractor の出力、すなわち
                        # 「人間が読めるテキスト形式」になっている。
                        text_for_ner = sdoc.original_excerpt or ""
                        if not text_for_ner.strip():
                            # 抽出に失敗したファイル (画像等) はスキップ
                            continue
                        sanitizer = _build_sanitizer()
                        try:
                            state = run_masking_pipeline(
                                name=sdoc.name,
                                text=text_for_ner,
                                sanitizer=sanitizer,
                                ner_masker=ner_masker,
                                hojin_lookup=hojin_lookup,
                            )
                            masking_states[sdoc.name] = state
                            # R-W-export (2026-05-08): ログダウンロード用に session_state に保存
                            st.session_state.masking_states = dict(masking_states)
                        except Exception as exc:  # noqa: BLE001
                            # 1 文書の R-M 失敗が他文書を巻き込まないよう個別に防御
                            st.warning(
                                f"R-M パイプライン (文書 {sdoc.name}) で警告: "
                                f"{type(exc).__name__}: {exc}"
                            )
                st.session_state.masking_states = masking_states
                # 新しいプレビューでは過去のユーザ判断はリセット
                st.session_state.user_decisions = {}
            except Exception as exc:  # noqa: BLE001
                st.warning(
                    f"R-M 全体処理で警告: {type(exc).__name__}: {exc}。"
                    "既存の正規表現マスキング結果のみで続行します。"
                )
                st.session_state.masking_states = {}
                st.session_state.user_decisions = {}
        else:
            # R-M OFF の場合は既存 masking_states をクリア
            st.session_state.masking_states = {}
            st.session_state.user_decisions = {}
        progress.progress(100, text="匿名化結果プレビューの準備が完了しました。")
    except LocalUrlError as exc:
        progress.progress(100, text="匿名化処理で停止しました。")
        st.session_state.preview_error = (
            "ローカル限定エンドポイントの設定に問題があります: "
            f"{exc}。LOCAL_SANITIZER_API_URL と LOCAL_SENSITIVITY_API_URL を確認してください。"
        )
    except Exception as exc:  # noqa: BLE001
        progress.progress(100, text="匿名化処理で停止しました。")
        st.session_state.preview_error = f"匿名化処理に失敗しました: {exc}"
        st.session_state.preview_trace = traceback.format_exc()


# -- Step 2: Preview -------------------------------------------------------

preview_error = st.session_state.get("preview_error")
if preview_error:
    st.markdown('<div class="step-header">ステップ 2 — 匿名化結果プレビュー</div>', unsafe_allow_html=True)
    st.error(preview_error)
    st.info(
        "匿名化結果が作成されなかったため、ステップ 3 には進めません。"
        "設定やローカル Ollama の起動状態を確認してから、もう一度「匿名化結果を確認」を押してください。"
    )
    if st.session_state.get("preview_trace"):
        with st.expander("詳細トレース"):
            st.code(st.session_state.preview_trace)

preview_docs = st.session_state.get("preview_docs")
if st.session_state.get("preview_attempted") and not preview_error and not preview_docs:
    st.markdown('<div class="step-header">ステップ 2 — 匿名化結果プレビュー</div>', unsafe_allow_html=True)
    st.info("匿名化結果はまだ作成されていません。ファイルを確認して、もう一度実行してください。")

if preview_docs:
    st.markdown('<div class="step-header">ステップ 2 — 匿名化結果プレビュー</div>', unsafe_allow_html=True)

    counts = {"safe": 0, "mask_and_continue": 0, "block": 0, "unknown": 0}
    for doc in preview_docs:
        counts[doc.local_sensitivity_decision] = counts.get(doc.local_sensitivity_decision, 0) + 1

    summary_cols = st.columns(4)
    summary_cols[0].metric("文書数", len(preview_docs))
    summary_cols[1].metric("安全", counts.get("safe", 0))
    summary_cols[2].metric("要確認", counts.get("mask_and_continue", 0))
    summary_cols[3].metric("送信禁止", counts.get("block", 0))

    warnings = st.session_state.get("preview_warnings", [])
    if warnings:
        with st.expander(f"抽出・パイプライン警告 ({len(warnings)} 件)"):
            for warning in warnings:
                st.markdown(f"- {warning}")

    # PR-J: 文書数が 4 件以上の場合、ステップ 2 の各文書カードを
    # 高さ 600px のスクロール可能コンテナで包む。本文+別紙の構成で
    # 11 ファイル前後を読み込んだ際に画面が縦に長く伸びすぎる問題への対処。
    # 3 件以下の場合は従来通りスクロールなし (画面圧迫の心配がないため)。
    _step2_use_scroll = len(preview_docs) >= 4
    _step2_container = (
        st.container(height=600) if _step2_use_scroll else st.container()
    )
    with _step2_container:
        for doc in preview_docs:
            card_class = _doc_card_class(doc.local_sensitivity_decision)
            st.markdown(f'<div class="{card_class}">', unsafe_allow_html=True)

            header_left = (
                f"<b>{doc.name}</b> "
                f'<span class="doc-meta"> · {doc.estimated_input_tokens} トークン '
                f"· 外部送信リスク: {doc.outbound_risk}</span>"
            )
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                f'<div>{header_left}</div>'
                f"<div>{_decision_badge(doc.local_sensitivity_decision)}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

            if doc.local_sensitivity_reasons:
                st.markdown("**判定理由**")
                for reason in doc.local_sensitivity_reasons:
                    st.markdown(f"- {reason}")

            if doc.findings:
                with st.expander(f"匿名化検知内容 ({len(doc.findings)} 件)"):
                    for finding in doc.findings:
                        st.markdown(f"- {finding}")

            # ----- R-M (PR-D2 + PR-F): 未確定候補カード (α 案: 各文書のカード内) -----
            # PR-F: SanitizedDocument.original_excerpt を full_text として渡し、
            # _render_uncertain_candidates_card がコンテキスト抜粋を表示できるように。
            _masking_state = st.session_state.get("masking_states", {}).get(doc.name)
            if _masking_state is not None:
                _render_uncertain_candidates_card(
                    _masking_state,
                    full_text=doc.original_excerpt or "",
                )

            # PR-F: 「匿名化後の抜粋」「置換一覧」は長文化しがちなため
            # エクスパンダーで折りたたむ。デフォルトは閉じておき、ユーザは
            # マスク候補の検討に集中できる。
            with st.expander("📄 匿名化後の抜粋・置換一覧", expanded=False):
                tabs = st.tabs(["匿名化後の抜粋", "置換一覧"])
                with tabs[0]:
                    st.markdown(
                        f"<pre class='sanitized'>{doc.sanitized_excerpt or '(空)'}</pre>",
                        unsafe_allow_html=True,
                    )
                with tabs[1]:
                    if doc.replacements:
                        rows = [
                            {"プレースホルダ": r.placeholder, "カテゴリ": r.category, "原文": r.original}
                            for r in doc.replacements[:50]
                        ]
                        st.dataframe(rows, width='stretch', hide_index=True)
                        if len(doc.replacements) > 50:
                            st.caption(f"全 {len(doc.replacements)} 件中 50 件を表示しています。")
                    else:
                        st.caption("置換は記録されませんでした。")

            st.markdown("</div>", unsafe_allow_html=True)

    # -- Step 3: Confirmation gate ----------------------------------------

    # PR-I-FIX: 承認を要求する文書の判定基準を 2 系統に拡張する。
    # (a) ローカル機密度判定が mask_and_continue (既存): 機密ブロッカー検出
    # (b) R-M で uncertain 候補が残っている (新規): spaCy NER で検出された
    #     企業名・人名等のうち、ユーザがまだ意思決定していない候補がある
    # どちらか一方でもあれば、外部送信前にユーザの明示的な承認を必須にする。
    # 元実装は (a) のみだったため、機密ゲートが safe を返した文書については
    # R-M uncertain があっても承認なしで送信できてしまっていた。
    _masking_states_for_gate = st.session_state.get("masking_states", {}) or {}

    def _has_uncertain_candidates(name: str) -> bool:
        state = _masking_states_for_gate.get(name)
        if state is None:
            return False
        return bool(getattr(state, "uncertain_candidates", None))

    mask_docs = [
        doc
        for doc in preview_docs
        if doc.local_sensitivity_decision == "mask_and_continue"
        or _has_uncertain_candidates(doc.name)
    ]
    blocked_docs = [
        doc
        for doc in preview_docs
        if doc.local_sensitivity_decision == "block" or doc.outbound_risk == "high"
    ]

    st.markdown('<div class="step-header">ステップ 3 — 確認 & 送信</div>', unsafe_allow_html=True)

    if blocked_docs:
        st.error(
            "次のファイルは外部レビューへの送信が禁止されています: "
            + ", ".join(doc.name for doc in blocked_docs)
            + "。より厳密に匿名化したコピーを準備してから再試行してください。"
        )

    confirmations: dict[str, bool] = {}
    if mask_docs and not blocked_docs:
        st.warning(
            f"{len(mask_docs)} 件の文書は外部送信前に明示的な確認が必要です。"
            "上記の匿名化後の抜粋を確認し、各文書について承認してください。"
        )
        # PR-J: 4 件以上の場合、承認チェックボックス群を高さ 400px の
        # スクロール可能コンテナで包む。11 ファイル前後を承認する際に
        # 画面が縦に長く伸びすぎる問題への対処。
        _step3_use_scroll = len(mask_docs) >= 4
        _step3_container = (
            st.container(height=400) if _step3_use_scroll else st.container()
        )
        with _step3_container:
            for doc in mask_docs:
                # PR-I-FIX: R-M uncertain がある場合は、文言で何を確認すべきかを補足
                _is_rm_only = (
                    doc.local_sensitivity_decision != "mask_and_continue"
                    and _has_uncertain_candidates(doc.name)
                )
                _label_suffix = (
                    "(マスク候補の確認 + 匿名化結果の確認)"
                    if _is_rm_only
                    else "(匿名化後の抜粋の確認)"
                )
                confirmations[doc.name] = st.checkbox(
                    f"**{doc.name}** の匿名化後の抜粋を確認し、外部レビューに送信して安全であることを承認します。 {_label_suffix}",
                    key=f"confirm_{doc.name}",
                )
    elif not blocked_docs:
        st.success(
            "追加承認が必要な文書はありません。"
            "匿名化結果を確認したうえで、このまま外部レビューへ送信できます。"
        )

    send_approved = False
    if not blocked_docs:
        st.markdown("**LLM 送信前の最終承認**")
        send_approved = st.checkbox(
            "ステップ 2 の匿名化結果、マスク候補、送信対象ログを確認し、"
            "匿名化済みテキストを外部 LLM レビューに送信することを承認します。",
            key="send_approval",
        )

    all_confirmed = (not mask_docs) or all(confirmations.get(doc.name) for doc in mask_docs)
    can_send = bool(preview_docs) and not blocked_docs and all_confirmed and send_approved

    # Phase 7 段階 1.5 (2026-05-08): docs_checked ガード廃止 + ボタン改名
    # ユーザフィードバック: 「匿名化してプレビュー」直後にサマリは既に見えているため、
    # 「文書チェック」ボタンを押す手順は冗長だった。
    #
    # 1. 「📋 匿名化結果を確認」(secondary, 旧「文書チェック」) — オプション操作
    #    ユーザ判断 (uncertain candidate) を反映して preview_docs を再生成。
    #    押さなくても先に進める (ガードではなくオプション)。
    # 2. 「レビューに送信」(primary) — preview_docs があれば常時有効
    #    各文書の承認 (all_confirmed) と送信禁止 (blocked_docs) のチェックは継続。
    can_check = bool(preview_docs) and not blocked_docs and all_confirmed
    can_send = bool(preview_docs) and not blocked_docs and all_confirmed and send_approved

    check_col, send_col, status_col = st.columns([1.5, 1.5, 4])
    with check_col:
        check_clicked = st.button(
            "📋 匿名化結果を確認",
            type="secondary",
            disabled=not can_check,
            width='stretch',
            help=(
                "マスク判断を反映し、preview_docs を再生成します (オプション操作)。"
                " このステップでは LLM には何も送信されません。"
                " 押さなくても「レビューに送信」で先に進めますが、uncertain candidate を"
                " 修正した場合や、最新の匿名化結果を確認したい場合に使用します。"
            ),
            key="doc_check_button",
        )
    with send_col:
        send_clicked = st.button(
            "レビューに送信",
            type="primary",
            disabled=not can_send,
            width='stretch',
            help=(
                "LLM プロバイダに匿名化済みテキストを送信し、レビュー結果を取得します。"
            ),
            key="send_review_button",
        )
    with status_col:
        if blocked_docs:
            st.markdown(
                '<div class="muted">送信禁止の文書があるため、送信できません。</div>',
                unsafe_allow_html=True,
            )
        elif mask_docs and not all_confirmed:
            st.markdown(
                '<div class="muted">送信ボタンを有効にするには、上記の各文書を確認・承認してください。</div>',
                unsafe_allow_html=True,
            )
        elif not send_approved:
            st.markdown(
                '<div class="muted">送信ボタンを有効にするには、LLM 送信前の最終承認をチェックしてください。</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="muted">✅ 送信準備完了。設定された LLM プロバイダには'
                '匿名化済みのテキストのみが送信されます。</div>',
                unsafe_allow_html=True,
            )

    # Phase 7 段階 1.5 (2026-05-08): 「📋 匿名化結果を確認」押下時の処理
    # 旧「文書チェック」のロジックを温存しつつ、docs_checked ガードを撤廃。
    # ローカル処理のみ (LLM 送信なし):
    #   - ユーザ判断を反映して preview_docs を再生成
    #   - session_state.preview_docs を更新
    # 押さなくても先に進める (オプション操作)。
    if check_clicked:
        try:
            _states = st.session_state.get("masking_states", {})
            _decisions_all = st.session_state.get("user_decisions", {})
            if _states:
                rebuilt: list = []
                for doc in preview_docs:
                    state = _states.get(doc.name)
                    if state is None:
                        rebuilt.append(doc)
                        continue
                    doc_decisions: dict[str, bool] = {}
                    for cand in state.uncertain_candidates:
                        key = _decision_key(doc.name, cand.text)
                        doc_decisions[cand.text] = _decisions_all.get(key, True)
                    sanitizer = _build_sanitizer()
                    try:
                        new_doc = apply_user_decisions(
                            state=state,
                            user_decisions=doc_decisions,
                            sanitizer=sanitizer,
                            customer_id=st.session_state.get("customer_id"),
                            session_id=st.session_state.get("audit_session_id"),
                        )
                        rebuilt.append(new_doc)
                    except Exception as exc:  # noqa: BLE001
                        st.warning(
                            f"R-M apply_user_decisions (文書 {doc.name}) で警告: "
                            f"{type(exc).__name__}: {exc}。元の sanitize 結果を使います。"
                        )
                        rebuilt.append(doc)
                preview_docs = rebuilt
                st.session_state.preview_docs = preview_docs

            # Phase 7 段階 1.5: docs_checked フラグ廃止 (オプション操作のためガード不要)
            # 古いレビュー結果が残っていればクリア (新しい判断には合わないため)
            st.session_state.pop("review_result", None)
            st.session_state.pop("deep_dive_results", None)
            st.session_state.pop("send_approval", None)
            st.session_state.anonymization_details_visible = True
            # Phase 7 段階 2-C: outbound_text が変わると章境界が変わる可能性
            st.session_state.pop("chapter_sections_cache", None)
            st.success(
                "✅ 匿名化結果を再生成しました。下記サマリで確認できます。"
                " 「レビューに送信」で LLM レビューを実行できます。"
            )
        except Exception as exc:  # noqa: BLE001
            _request_id = uuid.uuid4().hex[:8]
            st.error(f"匿名化結果の再生成に失敗しました ({_request_id})。")
            with st.expander("詳細トレース"):
                st.code(traceback.format_exc())

    # Phase 7 段階 1.5 (2026-05-08): preview_docs があれば常時表示
    # docs_checked ガードを廃止し、プレビュー直後からサマリと DL ボタンが見えるように。
    # ユーザフィードバック: 「匿名化してプレビュー」直後にサマリは既に見えていたほうが
    # 自然な UX (「文書チェック」を押すまで見えない、は不自然だった)。
    if preview_docs:
        _render_anonymization_summary(preview_docs)
        if st.session_state.get("anonymization_details_visible", False):
            _render_anonymization_detail_panel(preview_docs)
        # R-W-2 (2026-05-08): 本セッションのマスク判断サマリ
        render_session_summary()
        # R-W-export (2026-05-08): 結果ログのダウンロードボタン
        render_log_export_button()

    # Q12 (2026-05-08): 「レビューに送信」押下時の処理
    # LLM 送信のみ (文書チェック後の preview_docs を使用)。
    #
    # 課題 2 改修 (2026-05-08): chunking 進捗表示
    # GeminiApiReviewProvider が文書ごとに API call する際、
    # st.progress と st.status で進捗を可視化する。
    # これにより 60〜120 秒の処理中もユーザがフリーズと誤認しない。
    if send_clicked:
        review_progress = st.progress(0.0, text="送信前チェックを開始しています...")
        # 課題 1 拡張 (2026-05-08): ボタン押下時に「本セッションのマスク判断サマリ」を
        # 折りたたむ。Streamlit の st.expander は開閉状態を session_state に自動
        # バインドしないため、True のままだと rerun 後に勝手に再展開してしまう。
        # ボタン押下時に明示的に False に設定することで、レビュー結果が下に表示される
        # 際にサマリが邪魔にならない UX を実現する。
        st.session_state.session_summary_expanded = False
        try:
            preview_docs = st.session_state.get("preview_docs") or preview_docs
            review_progress.progress(20, text="レビュー LLM の設定を確認しています...")
            provider_impl = choose_provider()
            review_progress.progress(40, text="外部送信ガードを確認しています...")
            _enforce_outbound_guard(provider_impl.name, preview_docs)

            # 進捗表示用 progress bar (chunking で文書ごとに更新)
            _progress_bar = st.progress(0.0, text="")

            def _update_progress(idx: int, total: int, doc_name: str) -> None:
                """課題 2 改修: chunking 進捗 callback。
                Gemini プロバイダから文書処理ごとに呼び出される。
                """
                try:
                    fraction = min(1.0, idx / max(1, total))
                    if doc_name == "完了":
                        _progress_bar.progress(1.0, text=f"✅ 全 {total} 文書のレビュー完了")
                    else:
                        # 文書名が長すぎると progress bar の text が見づらくなるので適度に切る
                        display_name = doc_name if len(doc_name) <= 50 else doc_name[:47] + "..."
                        _progress_bar.progress(
                            fraction,
                            text=f"📄 {idx}/{total} 処理中: {display_name}",
                        )
                except Exception:  # noqa: BLE001
                    # progress bar の更新失敗は致命的ではない (ログのみ)
                    pass

            with st.spinner(f"{provider_impl.name} でレビュー実行中..."):
                review_progress.progress(
                    65,
                    text=f"{provider_impl.name} に匿名化済みテキストを送信し、レビューを実行しています...",
                )
                review = provider_impl.review(
                    preview_docs,
                    document_profile_override,
                    progress_callback=_update_progress,
                )
            review_progress.progress(100, text="レビューが完了しました。")

            # progress bar をクリア (結果表示の邪魔にならないように)
            _progress_bar.empty()

            st.session_state.review_result = review
        except LocalUrlError as exc:
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.error(f"ローカルエンドポイントの設定に問題があります: {exc}")
        except ValueError as exc:
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.error(str(exc))
        except RuntimeError as exc:
            # Gemini quota and similar user-actionable errors come through here.
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.error(str(exc))
        except Exception as exc:  # noqa: BLE001
            review_progress.progress(100, text="レビュー処理で停止しました。")
            request_id = uuid.uuid4().hex[:8]
            st.error(f"レビューに失敗しました ({request_id})。詳細はサーバログを確認してください。")
            with st.expander("詳細トレース"):
                st.code(traceback.format_exc())


# -- Step 4: Review result -------------------------------------------------

review = st.session_state.get("review_result")
if review is not None:
    st.markdown('<div class="step-header">ステップ 4 — レビュー結果</div>', unsafe_allow_html=True)

    left, right = st.columns([4, 2])
    with left:
        # B3: render structured summary (4 sections + verdict) when present;
        # fall back to legacy single-line summary when summary_structured is empty.
        ss = review.summary_structured
        if not ss.is_empty():
            # New structured summary - render 4 sections with verdict badge.
            if ss.purpose:
                st.markdown(f"**目的** — {ss.purpose}")

            # PR-I: classify the four cases of purpose_section_in_document
            # and purpose_divergence to give the user the right kind of
            # feedback:
            # - section present + no divergence: just show the section ref
            # - section present + divergence: show both as warning
            # - section missing + AI-derived purpose available: prompt the
            #   author to add a purpose section, with the AI's purpose as
            #   a starter draft
            # - both empty: nothing to show
            _has_section = bool(ss.purpose_section_in_document)
            _has_divergence = bool(ss.purpose_divergence)
            _has_purpose = bool(ss.purpose)

            if _has_section:
                # Document has a "目的" section — show its location and any
                # divergence the LLM detected.
                divergence_parts = [
                    f"_文書記載箇所_: {ss.purpose_section_in_document}"
                ]
                if _has_divergence:
                    divergence_parts.append(f"_乖離_: {ss.purpose_divergence}")
                color = "#a04a00" if _has_divergence else "#5a5040"
                st.markdown(
                    f"<div style='margin-top:0.3rem;color:{color};font-size:0.9rem;'>"
                    + " · ".join(divergence_parts)
                    + "</div>",
                    unsafe_allow_html=True,
                )
            elif _has_purpose:
                # PR-I: no "目的" section in the document but the LLM did
                # derive a purpose from the content. Recommend the author
                # add one and offer the LLM's purpose as a starter draft.
                with st.container(border=True):
                    st.markdown(
                        "⚠️ **ドキュメントに「目的」項目が見当たりません。**"
                        "冒頭(第1章または「はじめに」直後)に目的セクションを追記する"
                        "ことを推奨します。以下は本ドキュメントの内容から推定した目的の"
                        "草案です。必要に応じて加筆・修正のうえ反映してください。"
                    )
                    st.code(ss.purpose, language=None)

            if ss.content_outline:
                st.markdown(f"**内容要約** — {ss.content_outline}")
            if ss.overall_evaluation:
                # Render overall evaluation alongside the verdict badge.
                badge = _verdict_badge(ss.verdict)
                st.markdown(
                    f"**全体評価** — {ss.overall_evaluation} {badge}",
                    unsafe_allow_html=True,
                )
            elif ss.verdict:
                # Edge case: verdict supplied but no overall_evaluation.
                badge = _verdict_badge(ss.verdict)
                st.markdown(f"**総合判定**: {badge}", unsafe_allow_html=True)
        else:
            # Legacy: plain-text summary in a single line.
            st.markdown(f"**サマリ** — {review.summary}")
        # R-B + R-C (ε): show the concrete model identifier alongside the
        # internal provider slug so operators can see at a glance which
        # model produced this review.
        meta_parts = [f"プロバイダ: {review.provider}"]
        if review.model:
            meta_parts.append(f"モデル: {review.model}")
        meta_parts.append(f"ルーブリック: {review.rubric_name or review.rubric_id or '-'}")
        meta_parts.append(
            f"プロファイル: {_profile_label(review.document_profile)} "
            f"({review.classification_confidence or '-'})"
        )
        st.markdown(
            f'<div class="provider-line">{" · ".join(meta_parts)}</div>',
            unsafe_allow_html=True,
        )
        # R-K: surface profile-detection conflicts so operators can decide
        # whether to override via the sidebar selector.
        if review.classification_confidence == "conflict":
            st.warning(
                f"⚠️ プロファイル自動判定で **競合** が検出されました。"
                f"暫定的に「{_profile_label(review.document_profile)}」を選択していますが、"
                f"サイドバーから手動で別のプロファイルを選ぶこともできます。\n\n"
                f"**判定根拠**: {review.classification_reason}"
            )
    with right:
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in review.issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        st.markdown(
            f"<div style='text-align:right;'>"
            f"<span class='decision-badge decision-block'>高 {severity_counts.get('high', 0)}</span> "
            f"<span class='decision-badge decision-mask'>中 {severity_counts.get('medium', 0)}</span> "
            f"<span class='decision-badge decision-safe'>低 {severity_counts.get('low', 0)}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("### 文書全体の概要")
    _summary_struct = review.summary_structured
    with st.container(border=True):
        if not _summary_struct.is_empty():
            if _summary_struct.purpose:
                st.markdown(f"**目的**: {_summary_struct.purpose}")
            if _summary_struct.content_outline:
                st.markdown(f"**内容要約**: {_summary_struct.content_outline}")
            if _summary_struct.overall_evaluation:
                st.markdown(f"**全体評価**: {_summary_struct.overall_evaluation}")
            if _summary_struct.verdict:
                st.markdown(f"**総合判定**: {_verdict_badge(_summary_struct.verdict)}", unsafe_allow_html=True)
        elif review.summary:
            st.markdown(review.summary)
        else:
            st.info("LLM から文書全体の概要は返りませんでした。結果ログの生レスポンスを確認してください。")

    st.markdown("---")

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}

    # R-Y (2026-05-08): 文書ごとにグループ化して表示する。
    # 章別概要レビューを全章表示し、深堀り結果は同じ文書グループ内に
    # 追加表示する (蓄積式)。
    issues_by_doc: dict[str, list] = {}
    for _issue in review.issues:
        _key = getattr(_issue, "source_document", "") or "(出典不明)"
        issues_by_doc.setdefault(_key, []).append(_issue)

    # Q4 修正 (2026-05-08): preview_docs にある全文書を表示する。
    # LLM が指摘を出さなかった文書は issues_by_doc に入らないため、
    # 旧実装ではその文書のヘッダも深堀ボタンも表示されなかった。
    # 全文書のレビュー状況を一覧する + 指摘なしの文書も深堀対象にできるよう、
    # preview_docs ベースで順序リストを構築する。
    _preview_docs_for_order = st.session_state.get("preview_docs") or []
    _ordered_doc_names = [d.name for d in _preview_docs_for_order]
    # preview_docs にない出典 (例: "(出典不明)") は最後に追加
    for _n in issues_by_doc:
        if _n not in _ordered_doc_names:
            _ordered_doc_names.append(_n)

    # PR-J: 4 件以上の指摘がある場合、ステップ 4 の指摘リストを高さ 800px の
    # スクロール可能コンテナで包む。複数文書の総合レビューで指摘が 8-15 件
    # 出る際に、画面が縦に長く伸びすぎる問題への対処。プロンプトプレビュー
    # と生レスポンスはコンテナの外に置き、デバッグ時は通常通り展開できる。
    _step4_use_scroll = len(review.issues) >= 4
    _step4_container = (
        st.container(height=800) if _step4_use_scroll else st.container()
    )

    # 深堀結果 (文書名 -> [ReviewResult, ...]) を session_state から取得
    _deep_results_all = st.session_state.get("deep_dive_results") or {}

    with _step4_container:
        for _doc_name in _ordered_doc_names:
            # Q4 修正: issues_by_doc に存在しない文書 (= LLM 指摘なし) は空リスト
            _doc_issues = sorted(
                issues_by_doc.get(_doc_name, []),
                key=lambda i: severity_order.get(i.severity, 4),
            )

            st.markdown(f"### 📄 {_doc_name}")

            # Phase 7 段階 2-C (2026-05-08): 章境界検出 + 章単位深堀り UI
            # Q35=A: 3 章以上検出時のみ「複数章ファイル」と判定して章サブグループ表示。
            # 検出は preview_docs から (LLM 結果ではなく入力テキストベース)。
            # キャッシュ: session_state.chapter_sections_cache に文書名→ChapterSection
            # の dict を保持。preview リセット時にクリアされる。
            _preview_docs_for_chapter = st.session_state.get("preview_docs") or []
            _doc_for_chapter = next(
                (d for d in _preview_docs_for_chapter if d.name == _doc_name), None
            )
            _chapters: tuple = ()
            if _doc_for_chapter is not None:
                # キャッシュチェック (rerun ごとの再計算回避)
                if "chapter_sections_cache" not in st.session_state:
                    st.session_state.chapter_sections_cache = {}
                _cache = st.session_state.chapter_sections_cache
                if _doc_name not in _cache:
                    _cache[_doc_name] = extract_chapters_from_text(
                        _doc_for_chapter.outbound_text
                    )
                _chapters = _cache[_doc_name]

            if len(_chapters) >= 3:
                st.markdown(
                    f"<div style='margin-top:0.6rem;padding:0.5rem 0.8rem;"
                    f"background:#f5f5f0;border-left:3px solid #888;'>"
                    f"📖 <b>このファイルから {len(_chapters)} 章を検出しました。</b> "
                    f"章ごとに深堀りできます。</div>",
                    unsafe_allow_html=True,
                )

                with st.expander(f"🧭 章別概要レビュー ({len(_chapters)} 章)", expanded=True):
                    st.caption(
                        "概要レビューは全章を表示します。トークン消費を抑えるため、"
                        "深堀り実行は開発者モードでも最初の章のみ有効です。"
                    )
                    _chapter_container = (
                        st.container(height=640) if len(_chapters) >= 4 else st.container()
                    )
                    with _chapter_container:
                        for _ch_idx, _ch in enumerate(_chapters):
                            _overview = _find_chapter_overview(review, _doc_name, _ch)
                            _summary = (
                                getattr(_overview, "summary", "") if _overview is not None else ""
                            ) or _chapter_excerpt(_ch.extracted_text)
                            _overview_review = (
                                getattr(_overview, "review", "") if _overview is not None else ""
                            ) or "LLM から章別概要が返らなかったため、章本文の抜粋を表示しています。"
                            _needs_deep = bool(
                                getattr(_overview, "needs_deep_dive", False)
                                if _overview is not None else False
                            )
                            _deep_badge = (
                                "<span class='decision-badge decision-mask'>深堀候補</span>"
                                if _needs_deep else ""
                            )

                            with st.container(border=True):
                                _ch_col1, _ch_col2 = st.columns([5, 2])
                                with _ch_col1:
                                    st.markdown(
                                        f"**{_ch.chapter_label}** "
                                        f"<span class='doc-meta'>({_ch.chapter_id}, "
                                        f"{len(_ch.extracted_text)} chars)</span> "
                                        f"{_deep_badge}",
                                        unsafe_allow_html=True,
                                    )
                                    st.markdown(f"**章の概要**: {_summary}")
                                    st.markdown(f"**概要レビュー**: {_overview_review}")
                                with _ch_col2:
                                    _can_run_chapter = _ch_idx == 0
                                    _ch_btn_key = (
                                        "ch_deepdive_btn_"
                                        + hashlib.sha256(
                                            f"{_doc_name}|{_ch.chapter_id}|{_ch_idx}".encode("utf-8")
                                        ).hexdigest()[:12]
                                    )
                                    _ch_clicked = st.button(
                                        "🔬 この章を深堀",
                                        key=_ch_btn_key,
                                        disabled=not _can_run_chapter,
                                        help=(
                                            f"{_ch.chapter_label} のみを対象に深堀りします。"
                                            if _can_run_chapter
                                            else "トークン制限対策として、現在は最初の章のみ深堀りできます。"
                                        ),
                                        width='stretch',
                                    )
                                if _ch_clicked:
                                    _run_chapter_deep_dive(
                                        _doc_name,
                                        _ch,
                                        review,
                                        document_profile_override,
                                    )

            # Q4 修正 (2026-05-08): 指摘なしの場合の表示
            if not _doc_issues:
                st.markdown(
                    "<div class='issue-row info' style='color:#4a5549;font-size:0.92rem;'>"
                    "✅ <b>この文書に対する LLM 指摘はありません。</b> "
                    "より詳細な分析が必要なら章別概要レビュー内の「🔬 この章を深堀」をご利用ください。"
                    "</div>",
                    unsafe_allow_html=True,
                )

            # 既存指摘の表示 (severity 順)
            for issue in _doc_issues:
                severity_jp = SEVERITY_LABELS.get(issue.severity, issue.severity)
                # B3: prefer structured display when issue has new fields (current_state,
                # issue, impact, etc.); fall back to legacy details/recommendation only.
                if issue.has_structured_fields():
                    # New structured display.
                    id_prefix = f"<b>{issue.issue_id}</b> · " if issue.issue_id else ""
                    section_suffix = (
                        f' · 章: {issue.section}' if issue.section else ''
                    )
                    timing_badge = _required_timing_badge(issue.required_timing)
                    re_review_badge = _re_review_badge(issue.re_review_required)
                    badges = " ".join(b for b in (timing_badge, re_review_badge) if b)
                    badges_html = f"<div style='margin-top:0.4rem;'>{badges}</div>" if badges else ""

                    body_parts = []
                    if issue.current_state:
                        body_parts.append(
                            f"<div style='margin-top:0.3rem;'>"
                            f"<b>現状:</b> {issue.current_state}</div>"
                        )
                    if issue.issue:
                        body_parts.append(
                            f"<div style='margin-top:0.2rem;'>"
                            f"<b>問題点:</b> {issue.issue}</div>"
                        )
                    if issue.impact:
                        body_parts.append(
                            f"<div style='margin-top:0.2rem;'>"
                            f"<b>影響:</b> {issue.impact}</div>"
                        )
                    if issue.recommendation:
                        body_parts.append(
                            f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.92rem;'>"
                            f"<b>推奨対応:</b> {issue.recommendation}</div>"
                        )

                    st.markdown(
                        f"<div class='issue-row {issue.severity}'>"
                        f"{id_prefix}<b>[{severity_jp}]</b> {issue.title} "
                        f'<span class="doc-meta">{section_suffix}</span>'
                        + "".join(body_parts)
                        + badges_html
                        + "</div>",
                        unsafe_allow_html=True,
                    )
                else:
                    # Legacy display.
                    st.markdown(
                        f"<div class='issue-row {issue.severity}'>"
                        f"<b>[{severity_jp}]</b> {issue.title}<br/>"
                        f"<div style='margin-top:0.3rem;'>{issue.details}</div>"
                        f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.88rem;'>"
                        f"<b>推奨対応:</b> {issue.recommendation}</div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

            # R-Y: 深堀結果の表示 (この文書のもの、蓄積式)
            _deep_for_this = _deep_results_all.get(_doc_name, [])
            for _idx, _deep_review in enumerate(_deep_for_this, 1):
                _label = (
                    f"📌 深堀結果 (#{_idx})" if len(_deep_for_this) > 1
                    else "📌 深堀結果"
                )
                with st.expander(_label, expanded=True):
                    if _deep_review.summary:
                        st.markdown(f"**深堀サマリ** — {_deep_review.summary}")
                    _sorted_dd = sorted(
                        _deep_review.issues,
                        key=lambda i: severity_order.get(i.severity, 4),
                    )
                    if not _sorted_dd:
                        st.info(
                            "(深堀指摘なし。LLM が新規指摘を生成しませんでした。)"
                        )
                    for _ddissue in _sorted_dd:
                        _sev_jp = SEVERITY_LABELS.get(
                            _ddissue.severity, _ddissue.severity
                        )
                        if _ddissue.has_structured_fields():
                            _idp = (
                                f"<b>{_ddissue.issue_id}</b> · "
                                if _ddissue.issue_id else ""
                            )
                            _ssfx = (
                                f' · 章: {_ddissue.section}'
                                if _ddissue.section else ''
                            )
                            _bp = []
                            if _ddissue.current_state:
                                _bp.append(
                                    f"<div style='margin-top:0.3rem;'>"
                                    f"<b>現状:</b> {_ddissue.current_state}</div>"
                                )
                            if _ddissue.issue:
                                _bp.append(
                                    f"<div style='margin-top:0.2rem;'>"
                                    f"<b>問題点:</b> {_ddissue.issue}</div>"
                                )
                            if _ddissue.impact:
                                _bp.append(
                                    f"<div style='margin-top:0.2rem;'>"
                                    f"<b>影響:</b> {_ddissue.impact}</div>"
                                )
                            if _ddissue.recommendation:
                                _bp.append(
                                    f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.92rem;'>"
                                    f"<b>推奨対応:</b> {_ddissue.recommendation}</div>"
                                )
                            st.markdown(
                                f"<div class='issue-row {_ddissue.severity}'>"
                                f"{_idp}<b>[{_sev_jp}]</b> {_ddissue.title}"
                                f'<span class="doc-meta">{_ssfx}</span>'
                                + "".join(_bp)
                                + "</div>",
                                unsafe_allow_html=True,
                            )
                        else:
                            st.markdown(
                                f"<div class='issue-row {_ddissue.severity}'>"
                                f"<b>[{_sev_jp}]</b> {_ddissue.title}<br/>"
                                f"<div style='margin-top:0.3rem;'>{_ddissue.details}</div>"
                                f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.88rem;'>"
                                f"<b>推奨対応:</b> {_ddissue.recommendation}</div>"
                                f"</div>",
                                unsafe_allow_html=True,
                            )

            # Phase 7 (2026-05-08): この文書のチェック項目評価表示。
            # 一段目では空 tuple なので非表示、深堀り後 (Phase 7-B) に表示される。
            # Phase 6 で構築したロジックを温存し、深堀り側で活用する設計。
            _doc_checklists = [
                cr for cr in (review.checklist_results or ())
                if cr.source_document == _doc_name
            ]
            if _doc_checklists:
                # 集計: status 別カウント
                _status_counts = {
                    "excellent": 0, "good": 0, "acceptable": 0,
                    "needs_improvement": 0, "unacceptable": 0, "not_applicable": 0,
                }
                for _cr in _doc_checklists:
                    _status_counts[_cr.status] = _status_counts.get(_cr.status, 0) + 1
                # 「X 充足 / Y 注意 / Z 不充足」の表示用集計
                _ok_count = _status_counts["excellent"] + _status_counts["good"] + _status_counts["acceptable"]
                _warn_count = _status_counts["needs_improvement"]
                _bad_count = _status_counts["unacceptable"]
                _na_count = _status_counts["not_applicable"]

                _summary_label = (
                    f"✅ チェック項目評価 "
                    f"({_ok_count} 充足 / {_warn_count} 注意 / {_bad_count} 不充足"
                    + (f" / {_na_count} 該当なし" if _na_count else "")
                    + ")"
                )
                with st.expander(_summary_label, expanded=False):
                    st.caption(
                        "構造定義書 v0.2 の 15 章 78 項目から、この文書に該当する項目を "
                        "LLM が 5 段階で評価した結果です。問題のある項目が上に表示されます。"
                    )
                    # Q19=A: status 重要度順 (問題駆動型 UI)
                    _status_order = {
                        "unacceptable": 0,
                        "needs_improvement": 1,
                        "acceptable": 2,
                        "good": 3,
                        "excellent": 4,
                        "not_applicable": 5,
                    }
                    _status_emoji = {
                        "excellent": "🌟",
                        "good": "✅",
                        "acceptable": "🟡",
                        "needs_improvement": "⚠️",
                        "unacceptable": "❌",
                        "not_applicable": "➖",
                    }
                    _status_label_jp = {
                        "excellent": "模範",
                        "good": "充足",
                        "acceptable": "可",
                        "needs_improvement": "要改善",
                        "unacceptable": "不充足",
                        "not_applicable": "該当なし",
                    }
                    # 重要度順にソート、同 status 内では item_id で安定化
                    _sorted_crs = sorted(
                        _doc_checklists,
                        key=lambda c: (
                            _status_order.get(c.status, 99),
                            tuple(int(p) for p in c.item_id.split(".") if p.isdigit())
                            if c.item_id else (99,),
                        ),
                    )
                    for _cr in _sorted_crs:
                        _emoji = _status_emoji.get(_cr.status, "❓")
                        _slabel = _status_label_jp.get(_cr.status, _cr.status)
                        _evidence_html = (
                            f' <span style="color:#888;font-size:0.85rem;">'
                            f'(根拠: {_cr.evidence})</span>'
                            if _cr.evidence else ""
                        )
                        st.markdown(
                            f"<div style='padding:0.4rem 0.6rem;margin:0.3rem 0;"
                            f"border-left:3px solid #ccc;background:#fafaf7;'>"
                            f"<b>{_emoji} {_cr.item_id} {_cr.item_name}</b> "
                            f"<span style='color:#666;font-size:0.85rem;'>[{_slabel}]</span>"
                            f"{_evidence_html}<br/>"
                            f"<span style='color:#444;font-size:0.92rem;'>{_cr.reason}</span>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

            st.markdown("")  # 文書間の余白

    # Phase 7 (2026-05-08): 欠落章サジェスチョン表示
    # 一段目では空 tuple なので非表示、深堀り後 (Phase 7-B) に表示される。
    # Phase 6 で構築したロジックを温存し、深堀り側で活用する設計。
    _missing_chapters = review.missing_chapters or ()
    # out_of_scope は表示しない (UI からは見せない、LLM の判断は記録に残す)
    _displayable_mc = [
        mc for mc in _missing_chapters
        if mc.verdict in ("should_have", "recommended")
    ]
    if _displayable_mc:
        st.markdown("---")
        st.markdown("### 📋 欠落章へのサジェスチョン")
        st.caption(
            "構造定義書 v0.2 の 15 章のうち、この文書群が **明らかにカバーしていない章** を "
            "LLM が判定した結果です。設計書として完成度を上げるための参考としてご活用ください。"
        )

        # verdict 別にグループ化 (should_have を上に、recommended を下に)
        _should_have = [mc for mc in _displayable_mc if mc.verdict == "should_have"]
        _recommended = [mc for mc in _displayable_mc if mc.verdict == "recommended"]

        if _should_have:
            st.markdown(
                f"<div style='margin-top:0.6rem;font-weight:bold;color:#a02020;'>"
                f"🔴 重要欠落 ({len(_should_have)} 件) — 設計書として本来必要"
                f"</div>",
                unsafe_allow_html=True,
            )
            for _mc in _should_have:
                _suggested_html = (
                    f"<div style='margin-top:0.4rem;color:#4a5549;font-size:0.92rem;'>"
                    f"<b>本来書かれるべき内容:</b><br/>"
                    f"{_mc.suggested_content}</div>"
                    if _mc.suggested_content else ""
                )
                st.markdown(
                    f"<div style='padding:0.6rem 0.8rem;margin:0.4rem 0;"
                    f"border-left:4px solid #c04040;background:#fff5f5;'>"
                    f"<b>📕 {_mc.chapter_id} {_mc.chapter_name}</b><br/>"
                    f"<span style='color:#444;font-size:0.92rem;'>"
                    f"<b>判定理由:</b> {_mc.justification}</span>"
                    f"{_suggested_html}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

        if _recommended:
            st.markdown(
                f"<div style='margin-top:0.8rem;font-weight:bold;color:#a07020;'>"
                f"🟡 推奨欠落 ({len(_recommended)} 件) — あればよい (Optional)"
                f"</div>",
                unsafe_allow_html=True,
            )
            for _mc in _recommended:
                _suggested_html = (
                    f"<div style='margin-top:0.4rem;color:#4a5549;font-size:0.92rem;'>"
                    f"<b>本来書かれるべき内容:</b><br/>"
                    f"{_mc.suggested_content}</div>"
                    if _mc.suggested_content else ""
                )
                st.markdown(
                    f"<div style='padding:0.6rem 0.8rem;margin:0.4rem 0;"
                    f"border-left:4px solid #c0a040;background:#fffaf0;'>"
                    f"<b>📒 {_mc.chapter_id} {_mc.chapter_name}</b><br/>"
                    f"<span style='color:#444;font-size:0.92rem;'>"
                    f"<b>判定理由:</b> {_mc.justification}</span>"
                    f"{_suggested_html}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

    # 開発者モード ON 時のみ表示 (2026-05-08): プロンプト・LLM 生レスポンスの確認用
    if st.session_state.get("developer_mode", False):
        st.markdown("---")
        st.markdown(
            "<div style='color:#888;font-size:0.85rem;'>"
            "⚙️ 以下は <b>開発者モード ON 時のみ表示</b>される実装検証用 UI です。"
            "</div>",
            unsafe_allow_html=True,
        )
        with st.expander("プロンプトプレビュー (先頭 2000 文字)"):
            st.code(review.prompt_preview or "(空)", language="text")

        with st.expander("LLM の生レスポンス (デバッグ用)"):
            raw = getattr(review, "raw_response", "") or ""
            if raw.strip():
                st.caption(
                    "LLM プロバイダから返ってきた未加工のレスポンスです。"
                    "指摘表示が空の場合や形式が崩れている場合の原因調査に使用します。"
                )
                st.code(raw[:8000], language="json")
                if len(raw) > 8000:
                    st.caption(f"全 {len(raw)} 文字中、先頭 8000 文字のみ表示しています。")
            else:
                st.caption(
                    "生レスポンスは記録されていません (mock プロバイダ使用時、または "
                    "プロバイダ実装が raw_response を保持していない場合)。"
                )

    # R-Y (2026-05-08): 深堀レビューは Step 4 の文書ごとグループ表示に統合済み。
    # 各章カードの「🔬 この章を深堀」ボタンから実行する。


# ----------------------------------------------------------------------
# R-M experiment: Japanese NER Diagnostics expander.
#
# Step 2 of the R-M (custom mask dictionary) feasibility check.
# Goal: confirm that a Japanese NER pipeline can be loaded and used on
# real Japanese text within the Streamlit Cloud Free Tier (1GB RAM)
# constraint.
#
# The model used is spacy-official ``ja_core_news_md`` rather than GiNZA.
# GiNZA was tried first (2026-05-01) but ginza 5.2.0 requires spacy 3.7.x,
# which has no cp314 wheels - the resulting source build hung Streamlit
# Cloud in a boot loop. The spacy-official Japanese pipeline tracks
# current spacy releases and runs cleanly on Python 3.14.
#
# A later attempt to upgrade to ja_core_news_trf for better minor-company
# detection (e.g. "iret") also failed: spacy[transformers] pulls in
# spacy-alignments which depends on blis 0.7.11, and blis has no cp314
# wheels and its source build fails. Reverted to ja_core_news_md.
#
# As a follow-up optimisation we now load ja_core_news_md with the
# non-NER pipeline components disabled (parser, senter, attribute_ruler).
# This reduces RAM and parse latency without affecting NER accuracy
# - tok2vec (which the NER head depends on) and ner itself stay enabled.
#
# This block is intentionally isolated:
# - Located outside any review_result conditional, so it's always visible.
# - Lazy-loads the model only when the user clicks the analyse button.
# - Cached via @st.cache_resource so the model is loaded at most once
#   per session; subsequent calls reuse the in-memory instance.
# - Failure paths (import error, model load error) display st.error
#   without affecting any of the existing R-K / R-L review functionality.
# ----------------------------------------------------------------------


@st.cache_resource(show_spinner="日本語 NER モデル (spaCy ja_core_news_md) をロード中...")
def _load_spacy_ja_model():
    """Lazy-load the spacy-official ja_core_news_md pipeline. Cached so
    subsequent calls reuse it.

    Returns the loaded spacy.Language pipeline, or raises an exception that
    the caller should surface via st.error.
    """
    import spacy
    # Disable pipeline components we don't need for NER, to reduce RAM
    # and inference latency. ja_core_news_md's full pipeline is:
    # tok2vec, parser, senter, ner, attribute_ruler.
    # We need tok2vec (NER depends on it) and ner. The rest can go.
    return spacy.load(
        "ja_core_news_md",
        disable=["parser", "senter", "attribute_ruler"],
    )


def _format_memory_usage() -> str:
    """Return a human-readable RSS memory string for the current process.

    Returns ``"(取得不可)"`` if psutil is unavailable - we don't add psutil
    as a hard dependency just for diagnostics.
    """
    try:
        import os
        import resource
        # On Linux, ru_maxrss is in kilobytes.
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_mb = rss_kb / 1024
        return f"{rss_mb:.1f} MB (peak RSS)"
    except Exception:
        return "(取得不可)"


_SPACY_JA_DIAG_DEFAULT_TEXT = (
    "KDDI様の府中DCから送信されるメールを Amazon SES で SMTP リレーするシステムを設計する。"
    "担当: iret 開発チーム。検証環境は東京リージョンに構築し、"
    "本番環境は大阪リージョンも併用する。"
)


# 開発者モード ON 時のみ表示 (2026-05-08): NER 検出と gBizINFO 検索の実装検証用
if st.session_state.get("developer_mode", False):
    st.markdown("---")
    st.markdown(
        "<div style='color:#888;font-size:0.85rem;'>"
        "🧪 以下は開発者モード時のみ表示される実装検証・実験用 UI です。"
        "</div>",
        unsafe_allow_html=True,
    )

    with st.expander("🔍 日本語 NER Diagnostics (R-M 実験)", expanded=False):
        st.caption(
            "R-M (カスタムマスク辞書) 実装に向けた予備調査。spaCy 公式の日本語パイプライン "
            "(ja_core_news_md) で固有表現抽出 (NER) を試し、Streamlit Cloud Free Tier 上で"
            "動くかを確認します。既存のレビュー機能には影響しません。"
        )
        diag_text = st.text_area(
            "解析対象テキスト",
            value=_SPACY_JA_DIAG_DEFAULT_TEXT,
            height=120,
            key="spacy_ja_diag_text",
            help="ここに入れたテキストに対して、spaCy で日本語固有表現抽出を行います。",
        )
        if st.button("解析実行", key="spacy_ja_diag_run"):
            import time
            try:
                mem_before = _format_memory_usage()
                t_load_start = time.perf_counter()
                nlp = _load_spacy_ja_model()
                t_load_end = time.perf_counter()

                t_parse_start = time.perf_counter()
                doc = nlp(diag_text)
                t_parse_end = time.perf_counter()

                mem_after = _format_memory_usage()

                st.success("解析完了")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("モデルロード時間", f"{t_load_end - t_load_start:.2f} s")
                with col2:
                    st.metric("解析時間", f"{(t_parse_end - t_parse_start) * 1000:.0f} ms")
                with col3:
                    st.metric("メモリ (RSS)", mem_after)

                if doc.ents:
                    st.markdown("**検出されたエンティティ**")
                    ent_rows = [
                        {
                            "テキスト": ent.text,
                            "ラベル": ent.label_,
                            "開始位置": ent.start_char,
                            "終了位置": ent.end_char,
                        }
                        for ent in doc.ents
                    ]
                    st.dataframe(ent_rows, width="stretch")
                else:
                    st.info("エンティティは検出されませんでした。")

                with st.expander("形態素解析の詳細 (debug)", expanded=False):
                    token_rows = [
                        {
                            "表層形": tok.text,
                            "品詞": tok.pos_,
                            "詳細品詞": tok.tag_,
                            "原形": tok.lemma_,
                        }
                        for tok in doc
                    ][:50]  # cap at first 50 tokens to keep UI light
                    st.dataframe(token_rows, width="stretch")
                    if len(doc) > 50:
                        st.caption(f"先頭 50 トークンのみ表示 (全 {len(doc)} トークン中)")

            except ImportError as e:
                st.error(
                    "spaCy または ja_core_news_md モデルが import できません。"
                    f"requirements.txt の設定を確認してください。詳細: {e}"
                )
            except Exception as e:
                st.error(
                    "日本語 NER の実行中にエラーが発生しました。"
                    f"Streamlit Cloud のログも確認してください。詳細: {type(e).__name__}: {e}"
                )


    # ----------------------------------------------------------------------
    # R-M experiment: gBizINFO API Diagnostics expander.
    #
    # Step 5 of the R-M (custom mask dictionary) feasibility check.
    # Goal: confirm that the spacy NER + EntityRuler combo can be augmented
    # with a dynamic lookup against gBizINFO's REST API to detect company
    # names that are not in the seed dictionary (e.g. "iret").
    #
    # Strategy: when the user types a candidate string, hit gBizINFO's
    # /hojin endpoint with name= as the query. If any results come back,
    # the candidate is highly likely a real company name. The free-tier API
    # requires a token (GBIZINFO_API_TOKEN in Streamlit Secrets) that is
    # obtained by submitting an application at
    # https://info.gbiz.go.jp/hojin/various_registration/form
    #
    # This block is intentionally isolated:
    # - Located outside any review_result conditional.
    # - All HTTP I/O wrapped in try/except so a network outage or invalid
    #   token surfaces a clear st.error inside the expander only - the rest
    #   of the UI keeps working as long as Gemini reviews are still possible.
    # - When GBIZINFO_API_TOKEN is missing, the expander shows a friendly
    #   notice rather than crashing.
    # ----------------------------------------------------------------------


    _GBIZINFO_API_BASE_V2 = "https://api.info.gbiz.go.jp/hojin/v2"
    _GBIZINFO_API_BASE_V1 = "https://info.gbiz.go.jp/hojin/v1"
    _GBIZINFO_DIAG_DEFAULT_NAME = "iret"


    def _get_gbizinfo_token() -> str | None:
        """Fetch GBIZINFO_API_TOKEN from Streamlit Secrets, or None if absent."""
        try:
            return st.secrets.get("GBIZINFO_API_TOKEN")
        except Exception:
            return None


    def _gbizinfo_search_by_name(
        name: str,
        token: str,
        api_base: str = _GBIZINFO_API_BASE_V2,
        timeout: float = 10.0,
    ) -> tuple[int, dict | None, str | None]:
        """Call gBizINFO /hojin?name={name} and return (status_code, json_or_none,
        error_message_or_none).

        Errors are returned as a string in the third tuple element rather than
        raised, so the caller can show them inline without aborting the page.
        """
        import urllib.parse
        import urllib.request
        import json as _json

        encoded_name = urllib.parse.quote(name)
        url = f"{api_base}/hojin?name={encoded_name}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "X-hojinInfo-api-token": token,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                try:
                    payload = _json.loads(body)
                except _json.JSONDecodeError as e:
                    return resp.status, None, f"JSON 解析エラー: {e}"
                return resp.status, payload, None
        except urllib.error.HTTPError as e:
            return e.code, None, f"HTTP エラー {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            return 0, None, f"通信エラー: {e.reason}"
        except Exception as e:  # noqa: BLE001
            return 0, None, f"想定外のエラー: {type(e).__name__}: {e}"


    with st.expander("🏢 gBizINFO 検索 Diagnostics (R-M Phase 2 実験)", expanded=False):
        st.caption(
            "R-M Phase 2 の予備調査。gBizINFO REST API に法人名を問い合わせ、"
            "未知の固有名詞が「企業名らしさ」を持つかを動的に判定できるかを確認します。"
            "出典: 経済産業省 gBizINFO。"
        )

        _gbizinfo_token = _get_gbizinfo_token()
        if not _gbizinfo_token:
            st.warning(
                "GBIZINFO_API_TOKEN が Streamlit Secrets に設定されていません。"
                "https://info.gbiz.go.jp/hojin/various_registration/form で利用申請を行い、"
                "メールで届いた API トークンを Streamlit Secrets に "
                "`GBIZINFO_API_TOKEN = \"...\"` の形式で追加してください。"
            )
        else:
            st.caption("✅ GBIZINFO_API_TOKEN は設定済みです。")

        gbiz_query = st.text_input(
            "検索する法人名",
            value=_GBIZINFO_DIAG_DEFAULT_NAME,
            key="gbizinfo_diag_query",
            help="部分一致検索。例: 'iret' → 'アイレット株式会社' がヒットするかを確認",
        )

        gbiz_api_version = st.radio(
            "API バージョン",
            options=["v2", "v1"],
            index=0,
            horizontal=True,
            key="gbizinfo_diag_version",
            help="v2 が推奨。v1 はフォールバック確認用",
        )

        if st.button(
            "gBizINFO 検索実行",
            key="gbizinfo_diag_run",
            disabled=not _gbizinfo_token,
        ):
            import time

            api_base = (
                _GBIZINFO_API_BASE_V2 if gbiz_api_version == "v2" else _GBIZINFO_API_BASE_V1
            )
            with st.spinner(f"gBizINFO ({gbiz_api_version}) を検索中..."):
                t0 = time.perf_counter()
                status, payload, err = _gbizinfo_search_by_name(
                    gbiz_query, _gbizinfo_token, api_base=api_base
                )
                elapsed = time.perf_counter() - t0

            col1, col2 = st.columns(2)
            with col1:
                st.metric("レスポンスコード", str(status))
            with col2:
                st.metric("検索時間", f"{elapsed * 1000:.0f} ms")

            if err:
                st.error(f"検索失敗: {err}")
                st.caption(
                    "考えられる原因: トークンが無効 / API バージョン不一致 / "
                    "ネットワーク制限 / レート制限超過 / API ダウン"
                )
            elif payload is None:
                st.warning(
                    "レスポンスは正常 (HTTP "
                    f"{status}) ですが、内容が空です。レート制限や検索結果ゼロの"
                    "可能性があります。"
                )
            else:
                # Try common keys: "hojin-infos" (v1) and similar in v2.
                hojin_list = (
                    payload.get("hojin-infos")
                    or payload.get("hojinInfos")
                    or payload.get("hojinInfo")
                    or []
                )
                if not isinstance(hojin_list, list):
                    hojin_list = [hojin_list] if hojin_list else []

                st.success(f"ヒット件数: {len(hojin_list)} 件")

                if hojin_list:
                    # Show up to 10 rows for inspection.
                    rows = []
                    for h in hojin_list[:10]:
                        if not isinstance(h, dict):
                            continue
                        rows.append(
                            {
                                "法人名": h.get("name") or h.get("hojin_name") or "",
                                "法人番号": h.get("corporate_number")
                                or h.get("corporateNumber")
                                or "",
                                "所在地": h.get("location")
                                or h.get("address")
                                or "",
                                "法人種別": h.get("kind") or "",
                            }
                        )
                    if rows:
                        st.dataframe(rows, width="stretch")
                    if len(hojin_list) > 10:
                        st.caption(
                            f"先頭 10 件のみ表示 (全 {len(hojin_list)} 件)"
                        )

                with st.expander("生のレスポンス JSON (debug)", expanded=False):
                    import json as _json

                    st.code(
                        _json.dumps(payload, ensure_ascii=False, indent=2)[:5000],
                        language="json",
                    )
                    if len(_json.dumps(payload, ensure_ascii=False)) > 5000:
                        st.caption("先頭 5000 文字のみ表示")


# R-W-4 (2026-05-08): 全期間のマスク判断履歴と推奨エンジン (ページ最下部)
render_history_panel()
