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
import io
import os
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
from secure_review.run_masking_pipeline import (
    apply_user_decisions,
    run_masking_pipeline,
)


# Load .env once per session so settings survive reruns.
# On Streamlit Community Cloud, values live in st.secrets instead of a .env
# file; we bridge them to os.environ so that the rest of the codebase
# (which reads via os.getenv) works unchanged in both environments.
if "env_loaded" not in st.session_state:
    load_dotenv()
    try:
        for key, value in st.secrets.items():
            if isinstance(value, str) and key not in os.environ:
                os.environ[key] = value
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
    overflow-y: auto;
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
        "review_result",
        # R-M (PR-D2)
        "masking_states",
        "user_decisions",
        "last_uploaded_filenames",
    ):
        st.session_state.pop(key, None)


def _uploaded_to_documents() -> list[UploadedDocument]:
    items: list[UploadedDocument] = []
    for upload in st.session_state.get("uploads", []) or []:
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

        return NerMasker(seed_yaml_path="data/ner_seeds.yaml")
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
    if st.button("セッションをリセット", use_container_width=True):
        _reset_state()
        st.session_state.pop("uploads", None)
        st.rerun()

    st.caption(
        "アップロードされた文書はサーバ上に保存されません。"
        "本セッション中のメモリ上のみで処理されます。"
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
    key="uploads",
    label_visibility="collapsed",
    help=(
        "対応形式: txt, md, docx, xlsx, pptx, pdf, csv, json, yaml/yml, xml, "
        "html, スクリプト (py, ps1, sh, vbs, sql など), 画像。"
    ),
)

col1, col2 = st.columns([1, 5])
with col1:
    preview_clicked = st.button(
        "匿名化してプレビュー",
        type="primary",
        disabled=not st.session_state.get("uploads"),
        use_container_width=True,
    )
with col2:
    if st.session_state.get("uploads"):
        names = ", ".join(u.name for u in st.session_state.uploads)
        st.markdown(f'<div class="muted">処理待ち: {names}</div>', unsafe_allow_html=True)


if preview_clicked:
    documents = _uploaded_to_documents()
    try:
        with st.spinner("ローカルで匿名化中..."):
            sanitized, warnings = _run_sanitization_pipeline(documents)
        st.session_state.preview_docs = sanitized
        st.session_state.preview_warnings = warnings
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
    except LocalUrlError as exc:
        st.error(
            "ローカル限定エンドポイントの設定に問題があります: "
            f"{exc}。LOCAL_SANITIZER_API_URL と LOCAL_SENSITIVITY_API_URL を確認してください。"
        )
    except Exception as exc:  # noqa: BLE001
        st.error(f"匿名化処理に失敗しました: {exc}")
        with st.expander("詳細トレース"):
            st.code(traceback.format_exc())


# -- Step 2: Preview -------------------------------------------------------

preview_docs = st.session_state.get("preview_docs")
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
                    st.dataframe(rows, use_container_width=True, hide_index=True)
                    if len(doc.replacements) > 50:
                        st.caption(f"全 {len(doc.replacements)} 件中 50 件を表示しています。")
                else:
                    st.caption("置換は記録されませんでした。")

        st.markdown("</div>", unsafe_allow_html=True)

    # -- Step 3: Confirmation gate ----------------------------------------

    mask_docs = [doc for doc in preview_docs if doc.local_sensitivity_decision == "mask_and_continue"]
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
        for doc in mask_docs:
            confirmations[doc.name] = st.checkbox(
                f"**{doc.name}** の匿名化後の抜粋を確認し、外部レビューに送信して安全であることを承認します。",
                key=f"confirm_{doc.name}",
            )

    all_confirmed = (not mask_docs) or all(confirmations.get(doc.name) for doc in mask_docs)
    can_send = bool(preview_docs) and not blocked_docs and all_confirmed

    send_col, status_col = st.columns([1, 5])
    with send_col:
        send_clicked = st.button(
            "レビューに送信",
            type="primary",
            disabled=not can_send,
            use_container_width=True,
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
        else:
            st.markdown(
                '<div class="muted">送信準備完了。設定された LLM プロバイダには'
                '匿名化済みのテキストのみが送信されます。</div>',
                unsafe_allow_html=True,
            )

    if send_clicked:
        try:
            # ----- R-M (PR-D2): ユーザ判断を反映して outbound テキストを再生成 -----
            # masking_states があれば、各文書について
            # apply_user_decisions を呼んで preview_docs を上書き。
            # その後 _enforce_outbound_guard と provider.review に渡す。
            _states = st.session_state.get("masking_states", {})
            _decisions_all = st.session_state.get("user_decisions", {})
            if _states:
                rebuilt: list = []
                for doc in preview_docs:
                    state = _states.get(doc.name)
                    if state is None:
                        rebuilt.append(doc)
                        continue
                    # この文書に紐づくユーザ判断だけを抽出
                    doc_decisions: dict[str, bool] = {}
                    for cand in state.uncertain_candidates:
                        key = _decision_key(doc.name, cand.text)
                        # 未選択の場合はデフォルト True (マスク、安全側)
                        doc_decisions[cand.text] = _decisions_all.get(key, True)
                    sanitizer = _build_sanitizer()
                    try:
                        new_doc = apply_user_decisions(
                            state=state,
                            user_decisions=doc_decisions,
                            sanitizer=sanitizer,
                        )
                        # 既存 doc の sensitivity 判定情報を保持
                        # (apply_user_decisions は state.sanitized から構築するので、
                        #  ローカル機密度判定は state 側にすでに反映済み)
                        rebuilt.append(new_doc)
                    except Exception as exc:  # noqa: BLE001
                        st.warning(
                            f"R-M apply_user_decisions (文書 {doc.name}) で警告: "
                            f"{type(exc).__name__}: {exc}。元の sanitize 結果を使います。"
                        )
                        rebuilt.append(doc)
                preview_docs = rebuilt
                # session_state も新しい preview_docs に更新しておく
                st.session_state.preview_docs = preview_docs

            provider_impl = choose_provider()
            _enforce_outbound_guard(provider_impl.name, preview_docs)
            with st.spinner(f"{provider_impl.name} でレビュー実行中..."):
                review = provider_impl.review(preview_docs, document_profile_override)
            st.session_state.review_result = review
        except LocalUrlError as exc:
            st.error(f"ローカルエンドポイントの設定に問題があります: {exc}")
        except ValueError as exc:
            st.error(str(exc))
        except RuntimeError as exc:
            # Gemini quota and similar user-actionable errors come through here.
            st.error(str(exc))
        except Exception as exc:  # noqa: BLE001
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
            if ss.purpose_section_in_document or ss.purpose_divergence:
                # Show divergence between AI-inferred purpose and the document's
                # stated purpose, when available.
                divergence_parts = []
                if ss.purpose_section_in_document:
                    divergence_parts.append(
                        f"_文書記載箇所_: {ss.purpose_section_in_document}"
                    )
                if ss.purpose_divergence:
                    divergence_parts.append(f"_乖離_: {ss.purpose_divergence}")
                if divergence_parts:
                    st.markdown(
                        "<div style='margin-top:0.3rem;color:#5a5040;font-size:0.9rem;'>"
                        + " · ".join(divergence_parts)
                        + "</div>",
                        unsafe_allow_html=True,
                    )
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

    st.markdown("---")

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_issues = sorted(review.issues, key=lambda i: severity_order.get(i.severity, 4))

    for issue in sorted_issues:
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
                f'<span class="doc-meta"> · 出典: {issue.source_document}{section_suffix}</span>'
                + "".join(body_parts)
                + badges_html
                + "</div>",
                unsafe_allow_html=True,
            )
        else:
            # Legacy display (pre-B2 LLM responses or providers that don't yet
            # produce the new schema).
            st.markdown(
                f"<div class='issue-row {issue.severity}'>"
                f"<b>[{severity_jp}]</b> {issue.title} "
                f'<span class="doc-meta"> · 出典: {issue.source_document}</span><br/>'
                f"<div style='margin-top:0.3rem;'>{issue.details}</div>"
                f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.88rem;'>"
                f"<b>推奨対応:</b> {issue.recommendation}</div>"
                f"</div>",
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
