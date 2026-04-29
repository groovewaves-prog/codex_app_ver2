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
from secure_review.models import UploadedDocument
from secure_review.network_guard import LocalUrlError
from secure_review.reviewer import choose_provider


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
    "change_runbook": "変更・切替手順書",
    "operations_runbook": "保守・運用手順書",
    "source_code": "ソースコード",
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


def _reset_state() -> None:
    for key in ("preview_docs", "preview_warnings", "preview_security", "review_result"):
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
