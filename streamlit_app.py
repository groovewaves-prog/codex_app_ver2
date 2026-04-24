"""Streamlit UI for secure_review.

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
if "env_loaded" not in st.session_state:
    load_dotenv()
    st.session_state.env_loaded = True


st.set_page_config(
    page_title="Secure Review",
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

h1, h2, h3 { font-family: 'Georgia', 'Times New Roman', serif; color: var(--ink); letter-spacing: -0.01em; }

.decision-badge {
    display: inline-block;
    padding: 0.18rem 0.7rem;
    border-radius: 2px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-family: 'SF Mono', 'Consolas', monospace;
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
    font-family: 'SF Mono', 'Consolas', monospace;
}

.step-header {
    font-family: 'Georgia', serif;
    color: var(--ink-soft);
    font-size: 0.8rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
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
    font-family: 'SF Mono', 'Consolas', monospace;
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
    "safe": "SAFE",
    "mask_and_continue": "NEEDS CONFIRM",
    "block": "BLOCKED",
    "unknown": "UNKNOWN",
}


def _decision_badge(decision: str) -> str:
    css = DECISION_CLASSES.get(decision, "decision-mask")
    label = DECISION_LABELS.get(decision, decision.upper())
    return f'<span class="decision-badge {css}">{label}</span>'


def _doc_card_class(decision: str) -> str:
    if decision == "block":
        return "doc-card block"
    if decision == "mask_and_continue":
        return "doc-card mask"
    return "doc-card"


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
    st.markdown("### 🛡 Secure Review")
    st.caption("Local-first sanitization before any external LLM transfer.")
    st.markdown("---")

    provider = os.getenv("REVIEW_PROVIDER", "mock")
    local_san = os.getenv("LOCAL_SANITIZER_PROVIDER", "none")
    local_sens = os.getenv("LOCAL_SENSITIVITY_PROVIDER", "heuristic")

    st.markdown("##### Environment")
    st.markdown(
        f'<div class="provider-line">review  → <b>{provider}</b><br/>'
        f"sanitizer → <b>{local_san}</b><br/>"
        f'sensitivity → <b>{local_sens}</b></div>',
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("##### Review profile")
    profile_options = [
        ("(auto-detect)", None),
        ("design", "design"),
        ("change_runbook", "change_runbook"),
        ("operations_runbook", "operations_runbook"),
        ("source_code", "source_code"),
    ]
    profile_label = st.selectbox(
        "Force profile",
        [label for label, _ in profile_options],
        index=0,
        label_visibility="collapsed",
    )
    document_profile_override = dict(profile_options)[profile_label]

    st.markdown("---")
    if st.button("Reset session", use_container_width=True):
        _reset_state()
        st.session_state.pop("uploads", None)
        st.rerun()

    st.caption(
        "No document content is persisted. All state lives in server memory "
        "for this session only."
    )


# --------------------------------------------------------------------- main

st.markdown("## Secure Review")
st.markdown(
    '<p class="muted">Review artifacts through a local sanitizer and sensitivity gate '
    "before any content leaves the machine.</p>",
    unsafe_allow_html=True,
)


# -- Step 1: Upload --------------------------------------------------------

st.markdown('<div class="step-header">Step 1 — Upload</div>', unsafe_allow_html=True)

st.file_uploader(
    "Select files",
    accept_multiple_files=True,
    key="uploads",
    label_visibility="collapsed",
    help=(
        "Supported: txt, md, docx, xlsx, pptx, pdf, csv, json, yaml/yml, xml, "
        "html, scripts (py, ps1, sh, vbs, sql...), images."
    ),
)

col1, col2 = st.columns([1, 5])
with col1:
    preview_clicked = st.button(
        "Sanitize & preview",
        type="primary",
        disabled=not st.session_state.get("uploads"),
        use_container_width=True,
    )
with col2:
    if st.session_state.get("uploads"):
        names = ", ".join(u.name for u in st.session_state.uploads)
        st.markdown(f'<div class="muted">Queued: {names}</div>', unsafe_allow_html=True)


if preview_clicked:
    documents = _uploaded_to_documents()
    try:
        with st.spinner("Sanitizing locally..."):
            sanitized, warnings = _run_sanitization_pipeline(documents)
        st.session_state.preview_docs = sanitized
        st.session_state.preview_warnings = warnings
        st.session_state.pop("review_result", None)
    except LocalUrlError as exc:
        st.error(
            "A local-only endpoint is misconfigured: "
            f"{exc}. Check LOCAL_SANITIZER_API_URL and LOCAL_SENSITIVITY_API_URL."
        )
    except Exception as exc:  # noqa: BLE001
        st.error(f"Sanitization failed: {exc}")
        with st.expander("Trace"):
            st.code(traceback.format_exc())


# -- Step 2: Preview -------------------------------------------------------

preview_docs = st.session_state.get("preview_docs")
if preview_docs:
    st.markdown('<div class="step-header">Step 2 — Sanitization preview</div>', unsafe_allow_html=True)

    counts = {"safe": 0, "mask_and_continue": 0, "block": 0, "unknown": 0}
    for doc in preview_docs:
        counts[doc.local_sensitivity_decision] = counts.get(doc.local_sensitivity_decision, 0) + 1

    summary_cols = st.columns(4)
    summary_cols[0].metric("Documents", len(preview_docs))
    summary_cols[1].metric("Safe", counts.get("safe", 0))
    summary_cols[2].metric("Needs confirm", counts.get("mask_and_continue", 0))
    summary_cols[3].metric("Blocked", counts.get("block", 0))

    warnings = st.session_state.get("preview_warnings", [])
    if warnings:
        with st.expander(f"Extraction & pipeline warnings ({len(warnings)})"):
            for warning in warnings:
                st.markdown(f"- {warning}")

    for doc in preview_docs:
        card_class = _doc_card_class(doc.local_sensitivity_decision)
        st.markdown(f'<div class="{card_class}">', unsafe_allow_html=True)

        header_left = (
            f"<b>{doc.name}</b> "
            f'<span class="doc-meta"> · {doc.estimated_input_tokens} tokens '
            f"· outbound risk: {doc.outbound_risk}</span>"
        )
        st.markdown(
            f'<div style="display:flex;justify-content:space-between;align-items:center;">'
            f'<div>{header_left}</div>'
            f"<div>{_decision_badge(doc.local_sensitivity_decision)}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

        if doc.local_sensitivity_reasons:
            st.markdown("**Gate reasoning**")
            for reason in doc.local_sensitivity_reasons:
                st.markdown(f"- {reason}")

        if doc.findings:
            with st.expander(f"Sanitizer findings ({len(doc.findings)})"):
                for finding in doc.findings:
                    st.markdown(f"- {finding}")

        tabs = st.tabs(["Sanitized excerpt", "Replacements"])
        with tabs[0]:
            st.markdown(
                f"<pre class='sanitized'>{doc.sanitized_excerpt or '(empty)'}</pre>",
                unsafe_allow_html=True,
            )
        with tabs[1]:
            if doc.replacements:
                rows = [
                    {"placeholder": r.placeholder, "category": r.category, "original": r.original}
                    for r in doc.replacements[:50]
                ]
                st.dataframe(rows, use_container_width=True, hide_index=True)
                if len(doc.replacements) > 50:
                    st.caption(f"Showing 50 of {len(doc.replacements)} replacements.")
            else:
                st.caption("No replacements recorded.")

        st.markdown("</div>", unsafe_allow_html=True)

    # -- Step 3: Confirmation gate ----------------------------------------

    mask_docs = [doc for doc in preview_docs if doc.local_sensitivity_decision == "mask_and_continue"]
    blocked_docs = [
        doc
        for doc in preview_docs
        if doc.local_sensitivity_decision == "block" or doc.outbound_risk == "high"
    ]

    st.markdown('<div class="step-header">Step 3 — Confirm & send</div>', unsafe_allow_html=True)

    if blocked_docs:
        st.error(
            "The following file(s) are blocked from external review: "
            + ", ".join(doc.name for doc in blocked_docs)
            + ". Prepare a more strongly sanitized copy before retrying."
        )

    confirmations: dict[str, bool] = {}
    if mask_docs and not blocked_docs:
        st.warning(
            f"{len(mask_docs)} document(s) need explicit confirmation before "
            "external transfer. Review the sanitized excerpt above and confirm each one."
        )
        for doc in mask_docs:
            confirmations[doc.name] = st.checkbox(
                f"I have reviewed the sanitized excerpt of **{doc.name}** and "
                "accept that it is safe to send for external review.",
                key=f"confirm_{doc.name}",
            )

    all_confirmed = (not mask_docs) or all(confirmations.get(doc.name) for doc in mask_docs)
    can_send = bool(preview_docs) and not blocked_docs and all_confirmed

    send_col, status_col = st.columns([1, 5])
    with send_col:
        send_clicked = st.button(
            "Send for review",
            type="primary",
            disabled=not can_send,
            use_container_width=True,
        )
    with status_col:
        if blocked_docs:
            st.markdown(
                '<div class="muted">Cannot send while documents are blocked.</div>',
                unsafe_allow_html=True,
            )
        elif mask_docs and not all_confirmed:
            st.markdown(
                '<div class="muted">Confirm each document above to enable the send button.</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="muted">Ready. The configured LLM provider will receive '
                "only the sanitized text.</div>",
                unsafe_allow_html=True,
            )

    if send_clicked:
        try:
            provider_impl = choose_provider()
            _enforce_outbound_guard(provider_impl.name, preview_docs)
            with st.spinner(f"Running review with {provider_impl.name}..."):
                review = provider_impl.review(preview_docs, document_profile_override)
            st.session_state.review_result = review
        except LocalUrlError as exc:
            st.error(f"Local endpoint misconfigured: {exc}")
        except ValueError as exc:
            st.error(str(exc))
        except RuntimeError as exc:
            # Gemini quota and similar user-actionable errors come through here.
            st.error(str(exc))
        except Exception as exc:  # noqa: BLE001
            request_id = uuid.uuid4().hex[:8]
            st.error(f"Review failed ({request_id}). See server logs for details.")
            with st.expander("Trace"):
                st.code(traceback.format_exc())


# -- Step 4: Review result -------------------------------------------------

review = st.session_state.get("review_result")
if review is not None:
    st.markdown('<div class="step-header">Step 4 — Review result</div>', unsafe_allow_html=True)

    left, right = st.columns([4, 2])
    with left:
        st.markdown(f"**Summary** — {review.summary}")
        st.markdown(
            f'<div class="provider-line">provider: {review.provider} · '
            f"rubric: {review.rubric_name or review.rubric_id or '-'} · "
            f'profile: {review.document_profile or "-"} '
            f"({review.classification_confidence or '-'})</div>",
            unsafe_allow_html=True,
        )
    with right:
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in review.issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        st.markdown(
            f"<div style='text-align:right;'>"
            f"<span class='decision-badge decision-block'>HIGH {severity_counts.get('high', 0)}</span> "
            f"<span class='decision-badge decision-mask'>MED {severity_counts.get('medium', 0)}</span> "
            f"<span class='decision-badge decision-safe'>LOW {severity_counts.get('low', 0)}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("---")

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorted_issues = sorted(review.issues, key=lambda i: severity_order.get(i.severity, 4))

    for issue in sorted_issues:
        st.markdown(
            f"<div class='issue-row {issue.severity}'>"
            f"<b>[{issue.severity.upper()}]</b> {issue.title} "
            f'<span class="doc-meta"> · source: {issue.source_document}</span><br/>'
            f"<div style='margin-top:0.3rem;'>{issue.details}</div>"
            f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.88rem;'>"
            f"<b>Recommendation:</b> {issue.recommendation}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    with st.expander("Prompt preview (first 2000 chars)"):
        st.code(review.prompt_preview or "(empty)", language="text")
