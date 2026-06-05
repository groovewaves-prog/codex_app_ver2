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
from collections import Counter
import hashlib
import html
import io
import json
import os
import re
import traceback
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import streamlit as st

from secure_review.app import _run_sanitization_pipeline, _enforce_outbound_guard
from secure_review.env_loader import load_dotenv
from secure_review.export_names import remediation_plan_json_filename
from secure_review.models import (
    MaskingPipelineState,
    NerCandidate,
    ReviewResult,
    SanitizedDocument,
    UploadedDocument,
)
from secure_review.artifact_review import detect_artifact_review_mode
from secure_review.future_review import FutureReviewReport, build_future_review_report
from secure_review.network_guard import LocalUrlError
from secure_review.reviewer import choose_provider, provider_display_name
from secure_review.remediation_plan import (
    RemediationComparisonReport,
    RemediationPlan,
    build_remediation_plan,
    compare_remediation_plan_to_documents,
    remediation_plan_from_dict,
)
# Phase 7 段階 2-C (2026-05-08): 章単位深堀り
from secure_review.rubric import ChapterSection, classify_documents, extract_chapters_from_text
from secure_review.run_masking_pipeline import (
    apply_user_decisions,
    run_masking_pipeline,
)
from secure_review.structure_check import (
    StructureCheckResult,
    build_structure_check_result,
)
from secure_review.token_budget import estimate_review_token_budget
from secure_review import ui_components as sr_ui
from secure_review.ui_viewmodel import (
    remediation_origin_badge,
    structure_fix_guidance,
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
    page_title="技術文書レビュー支援ツール",
    page_icon="📄",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------------------------- style

STYLE = """
<style>
:root {
    --bg-base: #f3efe4;
    --bg-card: #fffdf8;
    --ink: #17251f;
    --ink-soft: #53645e;
    --accent: #087760;
    --accent-strong: #034c42;
    --accent-soft: #dff0ea;
    --cyan: #38a8b8;
    --warn: #a76700;
    --warn-soft: #fff0c9;
    --danger: #9d2f2f;
    --danger-soft: #f8ded8;
    --rule: #d7cbb8;
    --shadow: 0 18px 45px rgba(24, 35, 30, 0.10);

    /* G-1 design foundation tokens. Keep these as aliases so future theme
       adjustments flow through the existing visual system. */
    --sr-danger-bg: var(--danger-soft);
    --sr-danger-fg: var(--danger);
    --sr-warning-bg: var(--warn-soft);
    --sr-warning-fg: var(--warn);
    --sr-success-bg: var(--accent-soft);
    --sr-success-fg: var(--accent);
    --sr-text-primary: var(--ink);
    --sr-text-secondary: var(--ink-soft);
    --sr-text-tertiary: var(--ink-soft);
    --sr-bg-primary: var(--bg-card);
    --sr-bg-secondary: var(--bg-base);
    --sr-border: var(--rule);
    --sr-space-section: 3rem;
    --sr-space-card: 1.5rem;
    --sr-radius-sm: 6px;
    --sr-radius-md: 10px;
    --sr-radius-lg: 14px;
}

.stApp {
    background:
        radial-gradient(circle at top left, rgba(8,119,96,0.13), transparent 32rem),
        radial-gradient(circle at top right, rgba(56,168,184,0.10), transparent 28rem),
        linear-gradient(180deg, #f8f5ed 0%, var(--bg-base) 52%, #eee8da 100%);
    color: var(--ink);
}

.block-container { padding-top: 3.65rem; max-width: 1240px; }

h1, h2, h3 {
    font-family: 'BIZ UDPGothic', 'Yu Gothic', 'Hiragino Kaku Gothic ProN', 'Meiryo', sans-serif;
    color: var(--ink);
    letter-spacing: -0.02em;
}
.sr-app-title-row {
    display: flex;
    align-items: center;
    gap: 0.85rem;
    color: var(--ink);
    border: 1px solid rgba(8,119,96,0.16);
    border-bottom: 1px solid rgba(8,119,96,0.24);
    border-radius: 24px;
    background:
        linear-gradient(135deg, rgba(255,253,248,0.96) 0%, rgba(238,248,243,0.88) 100%);
    box-shadow: 0 18px 44px rgba(24,35,30,0.10);
    padding: 1.05rem 1.2rem;
    margin: 0.35rem 0 1.55rem;
}
.sr-app-title-icon {
    flex: 0 0 auto;
    display: inline-grid;
    place-items: center;
    width: 44px;
    height: 44px;
    border-radius: 15px 15px 20px 20px;
    background: linear-gradient(135deg, var(--ink) 0%, #244237 100%);
    color: var(--bg-card);
    border: 1px solid rgba(255,253,248,0.28);
    box-shadow: 0 12px 26px rgba(23,37,31,0.22);
    font-family: 'SF Mono', 'Consolas', 'Yu Gothic', sans-serif;
    font-size: 0.82rem;
    font-weight: 900;
    letter-spacing: 0.08em;
    line-height: 1;
}
.sr-app-title-text {
    color: var(--ink);
    font-family: 'BIZ UDPGothic', 'Yu Gothic', 'Hiragino Kaku Gothic ProN', 'Meiryo', sans-serif;
    font-size: clamp(30px, 3.1vw, 38px);
    font-weight: 850;
    letter-spacing: -0.035em;
    line-height: 1.12;
    text-shadow: 0 1px 0 rgba(255,253,248,0.72);
}
@media (max-width: 720px) {
    .block-container { padding-top: 2.8rem; }
    .sr-app-title-row {
        align-items: flex-start;
        padding: 0.95rem 1rem;
        border-radius: 20px;
    }
    .sr-app-title-icon {
        width: 38px;
        height: 38px;
        border-radius: 13px 13px 17px 17px;
        font-size: 0.74rem;
    }
    .sr-app-title-text {
        font-size: clamp(25px, 7vw, 31px);
        line-height: 1.16;
    }
}

[data-testid="stSidebar"] {
    background:
        radial-gradient(circle at top left, rgba(56,168,184,0.18), transparent 16rem),
        linear-gradient(180deg, #edf4f1 0%, #e8eee9 48%, #dde8e4 100%);
}
[data-testid="stSidebarContent"] {
    padding: 1.45rem 1rem 1.6rem;
}
[data-testid="stSidebar"] hr {
    border: none;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(8,119,96,0.22), transparent);
    margin: 1.35rem 0;
}
[data-testid="stSidebar"] .stCaption,
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label {
    color: #52635d;
}
[data-testid="stSidebar"] [data-baseweb="select"] > div {
    border-radius: 18px;
    border: 1px solid rgba(8,119,96,0.18);
    background: rgba(255,253,248,0.88);
    min-height: 3rem;
    box-shadow: 0 10px 22px rgba(24,35,30,0.06);
}
[data-testid="stSidebar"] div.stButton > button {
    min-height: 3.1rem;
    border-radius: 20px !important;
    border: 1px solid rgba(8,119,96,0.20) !important;
    background: rgba(255,253,248,0.88) !important;
    color: var(--ink) !important;
    font-weight: 800;
    box-shadow: 0 14px 28px rgba(24,35,30,0.08);
}
[data-testid="stSidebar"] div.stButton > button:hover {
    background: rgba(228,244,236,0.96) !important;
    color: var(--accent-strong) !important;
    transform: translateY(-1px);
}
[data-testid="stSidebar"] div[data-testid="stExpander"] details {
    border-radius: 20px !important;
    border: 1px solid rgba(8,119,96,0.18) !important;
    background: rgba(255,253,248,0.74) !important;
    box-shadow: 0 14px 30px rgba(24,35,30,0.075);
}
[data-testid="stSidebar"] div[data-testid="stExpander"] summary {
    min-height: 3.25rem;
    padding-left: 0.35rem;
}
.sidebar-section-label {
    color: var(--ink);
    font-size: 0.78rem;
    font-weight: 900;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin: 0.2rem 0 0.55rem;
}
.sidebar-help {
    color: var(--ink-soft);
    font-size: 0.78rem;
    line-height: 1.55;
    margin-top: 0.55rem;
}
.env-panel {
    border: 1px solid rgba(8,119,96,0.16);
    border-radius: 22px;
    background: rgba(255,253,248,0.70);
    padding: 0.85rem 0.85rem 0.7rem;
    box-shadow: 0 12px 26px rgba(24,35,30,0.06);
}
.env-row {
    display: grid;
    grid-template-columns: 4.7rem minmax(0, 1fr);
    gap: 0.55rem;
    align-items: baseline;
    padding: 0.34rem 0;
    border-bottom: 1px solid rgba(8,119,96,0.09);
}
.env-row:last-child {
    border-bottom: none;
}
.env-label {
    color: var(--ink-soft);
    font-size: 0.72rem;
    letter-spacing: 0.06em;
}
.env-value {
    color: var(--accent-strong);
    font-size: 0.8rem;
    font-weight: 900;
    overflow-wrap: anywhere;
}
.sidebar-memory-card {
    border: 1px solid rgba(8,119,96,0.13);
    border-left: 4px solid var(--cyan);
    border-radius: 18px;
    background: rgba(247,252,250,0.72);
    padding: 0.75rem 0.8rem;
    color: var(--ink-soft);
    font-size: 0.78rem;
    line-height: 1.6;
}

div.stButton > button[kind="primary"],
button[data-testid="stBaseButton-primary"] {
    background: #2f6d3a !important;
    border: 1px solid #265b32 !important;
    color: #ffffff !important;
    box-shadow: 0 2px 0 rgba(31, 42, 29, 0.14);
}
div.stButton > button[kind="primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: #265b32 !important;
    border-color: #1f4f2a !important;
    color: #ffffff !important;
}
div.stButton > button[kind="primary"]:disabled,
button[data-testid="stBaseButton-primary"]:disabled {
    background: #e7e1d6 !important;
    border-color: var(--rule) !important;
    color: #8a8377 !important;
    box-shadow: none;
}
div.stButton > button,
button[data-testid="stBaseButton-secondary"],
div[data-testid="stDownloadButton"] button {
    border-radius: 14px !important;
    border: 1px solid rgba(8,119,96,0.18) !important;
    background: rgba(255,253,248,0.86) !important;
    color: var(--ink) !important;
    box-shadow: 0 8px 18px rgba(24,35,30,0.06);
    min-height: 2.65rem;
}
div.stButton > button:hover,
button[data-testid="stBaseButton-secondary"]:hover,
div[data-testid="stDownloadButton"] button:hover {
    border-color: rgba(8,119,96,0.36) !important;
    background: rgba(237,246,232,0.94) !important;
    color: var(--accent-strong) !important;
}
div.stButton > button:disabled,
button[data-testid="stBaseButton-secondary"]:disabled,
div[data-testid="stDownloadButton"] button:disabled {
    background: rgba(231,225,214,0.74) !important;
    color: #9b9386 !important;
    box-shadow: none;
}
[data-testid="stSidebar"] div.stButton > button[kind="primary"],
[data-testid="stSidebar"] button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, #0f2119 0%, #17372b 100%) !important;
    border: 1px solid rgba(255,253,248,0.18) !important;
    color: #fffdf8 !important;
    padding: 11px 16px !important;
    box-shadow: 0 16px 30px rgba(24,35,30,0.18) !important;
    letter-spacing: 0.02em !important;
}
[data-testid="stSidebar"] div.stButton > button[kind="primary"] *,
[data-testid="stSidebar"] button[data-testid="stBaseButton-primary"] * {
    color: #fffdf8 !important;
    -webkit-text-fill-color: #fffdf8 !important;
}
[data-testid="stSidebar"] div.stButton > button[kind="primary"]:hover,
[data-testid="stSidebar"] button[data-testid="stBaseButton-primary"]:hover {
    background: linear-gradient(135deg, #091610 0%, #10281f 100%) !important;
    color: #fffdf8 !important;
    border-color: rgba(255,253,248,0.28) !important;
}
[data-testid="stSidebar"] div.stButton > button[kind="primary"]:disabled,
[data-testid="stSidebar"] button[data-testid="stBaseButton-primary"]:disabled {
    background: rgba(231,225,214,0.74) !important;
    color: #8a8377 !important;
    box-shadow: none !important;
}
[data-testid="stSidebar"] div.stButton > button[kind="primary"]:disabled *,
[data-testid="stSidebar"] button[data-testid="stBaseButton-primary"]:disabled * {
    color: #8a8377 !important;
    -webkit-text-fill-color: #8a8377 !important;
}

.decision-badge {
    display: inline-block;
    padding: 0.22rem 0.66rem;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', sans-serif;
}
.decision-safe   { background: var(--accent-soft); color: var(--accent); border: 1px solid rgba(8,119,96,0.22); }
.decision-mask   { background: var(--warn-soft);   color: var(--warn);   border: 1px solid rgba(167,103,0,0.22); }
.decision-block  { background: var(--danger-soft); color: var(--danger); border: 1px solid rgba(157,47,47,0.22); }

.doc-card {
    position: relative;
    overflow: hidden;
    background:
        linear-gradient(135deg, rgba(255,253,248,0.96) 0%, rgba(249,244,234,0.94) 100%);
    border: 1px solid rgba(215,203,184,0.82);
    border-left: 6px solid var(--accent);
    border-radius: 20px;
    padding: 0.95rem 1.05rem;
    margin-bottom: 0.85rem;
    box-shadow: 0 12px 28px rgba(24,35,30,0.07);
}
.doc-card.mask  { border-left-color: var(--warn); }
.doc-card.block { border-left-color: var(--danger); }
.doc-card::after {
    content: "";
    position: absolute;
    right: -4rem;
    top: -4rem;
    width: 10rem;
    height: 10rem;
    background: radial-gradient(circle, rgba(8,119,96,0.08), transparent 68%);
    pointer-events: none;
}
.doc-card-header {
    position: relative;
    z-index: 1;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
}
.doc-title {
    font-size: 1.05rem;
    font-weight: 900;
    color: var(--ink);
    line-height: 1.35;
}
.doc-submeta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    margin-top: 0.34rem;
}
.doc-meta-pill {
    border: 1px solid rgba(83,100,94,0.16);
    background: rgba(255,255,255,0.58);
    border-radius: 999px;
    padding: 0.16rem 0.48rem;
    color: var(--ink-soft);
    font-size: 0.74rem;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
}
.doc-attention-row {
    position: relative;
    z-index: 1;
    display: flex;
    gap: 0.35rem;
    flex-wrap: wrap;
    margin-top: 0.55rem;
}
.doc-reason-block {
    position: relative;
    z-index: 1;
    border: 1px solid rgba(215,203,184,0.62);
    background: rgba(255,255,255,0.58);
    border-radius: 16px;
    padding: 0.7rem 0.85rem;
    margin-top: 0.75rem;
}
.doc-reason-title {
    color: var(--ink);
    font-weight: 900;
    font-size: 0.88rem;
    margin-bottom: 0.4rem;
}
.doc-reason-list {
    margin: 0;
    padding-left: 1.1rem;
    color: var(--ink);
    line-height: 1.65;
    font-size: 0.9rem;
}

.doc-meta {
    color: var(--ink-soft);
    font-size: 0.82rem;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
}

.step-header {
    margin: 1.35rem 0 0.75rem;
}
.step-banner {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 0.8rem;
    align-items: center;
    border: 1px solid rgba(8,119,96,0.18);
    border-radius: 22px;
    background:
        linear-gradient(135deg, rgba(255,253,248,0.95) 0%, rgba(233,245,239,0.88) 100%);
    padding: 0.72rem 0.9rem;
    box-shadow: 0 14px 32px rgba(24,35,30,0.075);
}
.step-index {
    display: grid;
    place-items: center;
    width: 3.05rem;
    height: 3.05rem;
    border-radius: 18px;
    background:
        linear-gradient(135deg, var(--accent-strong) 0%, var(--accent) 100%);
    color: #f7fff9;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 1.15rem;
    font-weight: 900;
    box-shadow: 0 10px 22px rgba(8,119,96,0.22);
}
.step-copy {
    min-width: 0;
}
.step-kicker {
    color: var(--accent-strong);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.68rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    font-weight: 900;
}
.step-title {
    color: var(--ink);
    font-size: 1.18rem;
    line-height: 1.3;
    font-weight: 900;
    margin-top: 0.12rem;
}
.step-desc {
    color: var(--ink-soft);
    font-size: 0.82rem;
    line-height: 1.5;
    margin-top: 0.22rem;
}
@media (max-width: 760px) {
    .step-banner {
        grid-template-columns: 1fr;
    }
    .step-index {
        width: 2.55rem;
        height: 2.55rem;
        border-radius: 14px;
        font-size: 1rem;
    }
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
    font-size: 0.92rem;
    line-height: 1.5;
}
.issue-row.high   { border-left-color: var(--danger); }
.issue-row.medium { border-left-color: var(--warn); }
.issue-row.low    { border-left-color: var(--accent); }
.issue-row.info   { border-left-color: var(--ink-soft); }

.future-lens {
    margin: 1.05rem 0;
    border: 1px solid rgba(8,119,96,0.18);
    border-radius: 22px;
    background:
        radial-gradient(circle at top right, rgba(85,200,178,0.15), transparent 28%),
        linear-gradient(135deg, rgba(255,253,248,0.98), rgba(238,247,242,0.92));
    padding: 1rem;
    box-shadow: 0 18px 38px rgba(24,35,30,0.08);
}
.future-lens-head {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
}
.future-lens-kicker {
    color: var(--accent-strong);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.68rem;
    font-weight: 900;
    letter-spacing: 0.18em;
    text-transform: uppercase;
}
.future-lens-title {
    color: var(--ink);
    font-size: 1.24rem;
    font-weight: 900;
    line-height: 1.35;
}
.future-lens-copy {
    color: var(--ink-soft);
    font-size: 0.86rem;
    line-height: 1.6;
    margin-top: 0.25rem;
}
.future-lens-metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    justify-content: flex-end;
}
.future-pill {
    border: 1px solid rgba(8,119,96,0.16);
    border-radius: 999px;
    background: rgba(255,255,255,0.78);
    color: var(--ink);
    font-size: 0.78rem;
    font-weight: 800;
    padding: 0.34rem 0.62rem;
}
.future-card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 0.65rem;
    margin-top: 0.75rem;
}
.future-card {
    border: 1px solid var(--rule);
    border-left: 4px solid var(--accent);
    border-radius: 16px;
    background: rgba(255,255,255,0.82);
    padding: 0.78rem;
    font-size: 0.86rem;
    line-height: 1.55;
}
.future-card.high { border-left-color: var(--danger); background: rgba(255,245,242,0.92); }
.future-card.medium { border-left-color: var(--warn); background: rgba(255,249,234,0.92); }
.future-card.low { border-left-color: var(--accent); }
.future-card-title {
    font-weight: 900;
    color: var(--ink);
    line-height: 1.35;
}
.future-card-meta {
    color: var(--ink-soft);
    font-size: 0.75rem;
    margin: 0.25rem 0 0.35rem;
}
.future-card-text {
    color: var(--ink);
    font-size: 0.84rem;
    margin-top: 0.26rem;
}
.feedback-panel {
    border: 1px solid rgba(8,119,96,0.14);
    border-radius: 16px;
    background: rgba(247,252,248,0.84);
    padding: 0.7rem 0.85rem;
    margin: 0.45rem 0 0.8rem;
}
@media (max-width: 760px) {
    .future-lens-head { display: block; }
    .future-lens-metrics { justify-content: flex-start; margin-top: 0.6rem; }
}

.review-compact {
    font-size: 0.92rem;
    line-height: 1.55;
}

.structure-check-card {
    border-left: 3px solid var(--rule);
    background: var(--bg-card);
    padding: 0.45rem 0.75rem;
    margin: 0.35rem 0;
    font-size: 0.9rem;
    line-height: 1.5;
}
.structure-check-card.high { border-left-color: var(--danger); background: #fff7f6; }
.structure-check-card.medium { border-left-color: var(--warn); background: #fffaf0; }
.structure-check-card.info { border-left-color: var(--ink-soft); background: #fafaf6; }

.status-flow {
    display: flex;
    gap: 0.18rem;
    margin: 0.35rem 0 0.65rem;
    font-size: 0.72rem;
    font-weight: 600;
}
.status-step {
    flex: 1;
    text-align: center;
    padding: 0.32rem 0.3rem;
    background: #e8e5dc;
    color: #6f746c;
    border-radius: 2px;
}
.status-step.done {
    background: #dfeada;
    color: var(--accent);
}
.status-step.active {
    background: #edf3e8;
    color: var(--accent);
    box-shadow: inset 0 -2px 0 var(--accent);
}
.status-step.blocked {
    background: var(--danger-soft);
    color: var(--danger);
}

.height-control {
    color: var(--ink-soft);
    font-size: 0.82rem;
    margin-top: 0.25rem;
}

.bundle-card {
    border: 1px solid var(--rule);
    background: #fffdf7;
    padding: 0.75rem 0.9rem;
    margin: 0.6rem 0;
}
.bundle-kicker {
    color: var(--ink-soft);
    font-size: 0.78rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.insight-panel {
    border: 1px solid #d6c9b5;
    border-left: 5px solid var(--accent);
    border-radius: 22px;
    background:
        linear-gradient(135deg, rgba(255,255,255,0.92) 0%, rgba(250,246,236,0.96) 100%);
    padding: 0.95rem 1rem;
    margin: 0.8rem 0 1rem;
    box-shadow: var(--shadow);
}
.insight-panel.warn { border-left-color: var(--warn); background: linear-gradient(135deg, #fffdf7 0%, #fbf1dc 100%); }
.insight-panel.block { border-left-color: var(--danger); background: linear-gradient(135deg, #fffdf7 0%, #f8e7e2 100%); }
.insight-panel.safe { border-left-color: var(--accent); background: linear-gradient(135deg, #fffdf7 0%, #eaf2e5 100%); }
.insight-header {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
}
.insight-kicker {
    color: var(--ink-soft);
    font-size: 0.72rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
}
.insight-title {
    font-family: 'BIZ UDPGothic', 'Yu Gothic', 'Hiragino Kaku Gothic ProN', 'Meiryo', sans-serif;
    color: var(--ink);
    font-size: 1.25rem;
    font-weight: 700;
    margin-top: 0.15rem;
}
.insight-detail {
    color: var(--ink-soft);
    font-size: 0.86rem;
    line-height: 1.55;
    max-width: 720px;
}
.insight-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(128px, 1fr));
    gap: 0.55rem;
    margin-top: 0.85rem;
}
.insight-metric {
    background: rgba(255,255,255,0.78);
    border: 1px solid rgba(217, 209, 192, 0.82);
    border-top: 3px solid var(--rule);
    border-radius: 16px;
    padding: 0.58rem 0.65rem 0.65rem;
    min-height: 86px;
}
.insight-metric.safe { border-top-color: var(--accent); background: rgba(237,246,232,0.72); }
.insight-metric.warn { border-top-color: var(--warn); background: rgba(255,249,234,0.86); }
.insight-metric.block { border-top-color: var(--danger); background: rgba(255,245,242,0.92); }
.insight-metric.info { border-top-color: #7c8878; }
.insight-label {
    color: var(--ink-soft);
    font-size: 0.75rem;
    letter-spacing: 0.04em;
}
.insight-value {
    color: var(--ink);
    font-size: 1.55rem;
    line-height: 1.1;
    margin-top: 0.3rem;
    font-family: 'BIZ UDPGothic', 'Yu Gothic', 'Hiragino Kaku Gothic ProN', 'Meiryo', sans-serif;
    font-weight: 900;
}
.insight-note {
    color: var(--ink-soft);
    font-size: 0.72rem;
    line-height: 1.4;
    margin-top: 0.32rem;
}
@media (max-width: 760px) {
    .insight-header { display: block; }
    .insight-detail { margin-top: 0.45rem; }
}
.readiness-panel {
    display: grid;
    grid-template-columns: minmax(260px, 1.1fr) minmax(360px, 1.7fr);
    gap: 0.85rem;
    border: 1px solid #d6c9b5;
    border-radius: 24px;
    background: linear-gradient(135deg, #fffdf7 0%, #f2ebdd 100%);
    padding: 1rem;
    margin: 0.7rem 0 0.9rem;
    box-shadow: var(--shadow);
}
.readiness-main {
    border-left: 5px solid var(--accent);
    background: rgba(255,255,255,0.62);
    border-radius: 18px;
    padding: 0.85rem 1rem;
}
.readiness-main.warn { border-left-color: var(--warn); }
.readiness-main.block { border-left-color: var(--danger); }
.readiness-main.split { border-left-color: var(--warn); background: #fff9ea; }
.readiness-eyebrow {
    color: var(--ink-soft);
    font-size: 0.72rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
}
.readiness-title {
    font-family: 'BIZ UDPGothic', 'Yu Gothic', 'Hiragino Kaku Gothic ProN', 'Meiryo', sans-serif;
    font-size: 1.55rem;
    font-weight: 700;
    margin-top: 0.2rem;
}
.readiness-detail {
    color: var(--ink-soft);
    font-size: 0.9rem;
    line-height: 1.55;
    margin-top: 0.35rem;
}
.readiness-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.65rem;
}
.readiness-card {
    background: rgba(255,255,255,0.78);
    border: 1px solid rgba(217, 209, 192, 0.72);
    border-radius: 16px;
    padding: 0.65rem 0.75rem;
    min-height: 92px;
}
.readiness-card-title {
    color: var(--ink-soft);
    font-size: 0.74rem;
    letter-spacing: 0.08em;
}
.readiness-card-value {
    font-size: 1rem;
    font-weight: 700;
    margin-top: 0.25rem;
}
.readiness-card-note {
    color: var(--ink-soft);
    font-size: 0.78rem;
    line-height: 1.45;
    margin-top: 0.25rem;
}
.summary-chip-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
    gap: 0.62rem;
    margin: 0.75rem 0 0.7rem;
}
.summary-chip {
    border: 1px solid rgba(217, 209, 192, 0.72);
    background:
        linear-gradient(135deg, rgba(255,255,255,0.86) 0%, rgba(250,246,236,0.94) 100%);
    border-radius: 18px;
    padding: 0.62rem 0.72rem;
    min-height: 82px;
    box-shadow: 0 8px 20px rgba(24,35,30,0.05);
}
.summary-chip.safe { border-top: 3px solid var(--accent); background: rgba(237,246,232,0.74); }
.summary-chip.warn { border-top: 3px solid var(--warn); background: rgba(255,249,234,0.86); }
.summary-chip.block { border-top: 3px solid var(--danger); background: rgba(255,245,242,0.92); }
.summary-chip.info { border-top: 3px solid #7c8878; }
.summary-chip-label {
    color: var(--ink-soft);
    font-size: 0.74rem;
    letter-spacing: 0.06em;
}
.summary-chip-value {
    color: var(--ink);
    font-family: 'BIZ UDPGothic', 'Yu Gothic', 'Hiragino Kaku Gothic ProN', 'Meiryo', sans-serif;
    font-size: 1.45rem;
    line-height: 1.05;
    font-weight: 900;
    margin-top: 0.32rem;
}
.summary-panel {
    border: 1px solid rgba(8,119,96,0.16);
    border-radius: 24px;
    background:
        linear-gradient(135deg, rgba(255,253,248,0.94) 0%, rgba(239,247,241,0.86) 100%);
    padding: 1rem;
    margin: 1rem 0 0.9rem;
    box-shadow: var(--shadow);
}
.summary-panel-head {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
}
.summary-panel-title {
    font-size: 1.45rem;
    font-weight: 900;
    color: var(--ink);
}
.summary-panel-note {
    color: var(--ink-soft);
    font-size: 0.86rem;
    line-height: 1.55;
    max-width: 560px;
}

.send-gate-panel {
    border: 1px solid rgba(8,119,96,0.18);
    border-left: 6px solid var(--accent);
    border-radius: 22px;
    background:
        linear-gradient(135deg, rgba(255,253,248,0.95) 0%, rgba(234,245,231,0.92) 100%);
    padding: 0.9rem 1rem;
    margin: 0.65rem 0 0.85rem;
    box-shadow: 0 12px 28px rgba(24,35,30,0.07);
}
.send-gate-panel.warn { border-left-color: var(--warn); background: linear-gradient(135deg, #fffdf8 0%, #fff3d3 100%); }
.send-gate-panel.block { border-left-color: var(--danger); background: linear-gradient(135deg, #fffdf8 0%, #f9e3dd 100%); }
.send-gate-kicker {
    color: var(--ink-soft);
    font-size: 0.72rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
}
.send-gate-title {
    color: var(--ink);
    font-size: 1.2rem;
    font-weight: 900;
    margin-top: 0.22rem;
}
.send-gate-detail {
    color: var(--ink-soft);
    line-height: 1.6;
    margin-top: 0.35rem;
    font-size: 0.92rem;
}
.approval-box {
    border: 1px solid rgba(8,119,96,0.18);
    border-radius: 20px;
    background: rgba(255,253,248,0.78);
    padding: 0.85rem 1rem 0.7rem;
    margin: 0.8rem 0 0.9rem;
    box-shadow: 0 10px 24px rgba(24,35,30,0.05);
}
.approval-title {
    color: var(--ink);
    font-size: 1.04rem;
    font-weight: 900;
}
.approval-note {
    color: var(--ink-soft);
    font-size: 0.86rem;
    line-height: 1.5;
    margin-top: 0.25rem;
}

div[data-testid="stExpander"] details {
    border: 1px solid rgba(8,119,96,0.16) !important;
    border-radius: 16px !important;
    background: rgba(255,253,248,0.70) !important;
    box-shadow: 0 8px 18px rgba(24,35,30,0.045);
}
div[data-testid="stExpander"] summary {
    min-height: 3rem;
    font-weight: 800 !important;
    color: var(--ink) !important;
}

@media (max-width: 900px) {
    .readiness-panel { grid-template-columns: 1fr; }
    .readiness-grid { grid-template-columns: 1fr; }
}
.fix-guide {
    margin-top: 0.35rem;
    padding: 0.35rem 0.55rem;
    background: #fbfaf4;
    border-left: 3px solid var(--accent);
    color: var(--ink-soft);
    font-size: 0.86rem;
}
.remediation-panel {
    border: 1px solid rgba(8,119,96,0.18);
    border-radius: 24px;
    background:
        radial-gradient(circle at top right, rgba(56,168,184,0.12), transparent 18rem),
        linear-gradient(135deg, rgba(255,253,248,0.96) 0%, rgba(235,246,239,0.90) 100%);
    padding: 1rem;
    margin: 0.95rem 0 1rem;
    box-shadow: var(--shadow);
}
.remediation-head {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
}
.remediation-kicker {
    color: var(--accent-strong);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    font-weight: 900;
}
.remediation-title {
    color: var(--ink);
    font-size: 1.34rem;
    line-height: 1.3;
    font-weight: 900;
    margin-top: 0.22rem;
}
.remediation-summary {
    color: var(--ink-soft);
    font-size: 0.88rem;
    line-height: 1.55;
    max-width: 520px;
}
.remediation-purpose {
    border: 1px solid rgba(8,119,96,0.13);
    border-radius: 16px;
    background: rgba(247,252,250,0.78);
    color: var(--ink-soft);
    font-size: 0.86rem;
    line-height: 1.55;
    padding: 0.68rem 0.78rem;
    margin-top: 0.82rem;
}
.remediation-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 0.72rem;
    margin-top: 0.9rem;
}
.remediation-card {
    border: 1px solid rgba(217, 209, 192, 0.76);
    border-left: 5px solid var(--rule);
    border-radius: 18px;
    background: rgba(255,255,255,0.72);
    padding: 0.78rem 0.82rem;
}
.remediation-card.high { border-left-color: var(--danger); background: rgba(255,245,242,0.92); }
.remediation-card.medium { border-left-color: var(--warn); background: rgba(255,249,234,0.88); }
.remediation-card.low { border-left-color: var(--accent); }
.remediation-card-title {
    color: var(--ink);
    font-size: 0.96rem;
    line-height: 1.4;
    font-weight: 900;
}
.origin-badge-row {
    margin-top: 0.46rem;
}
.origin-badge {
    display: inline-flex;
    align-items: center;
    width: fit-content;
    border-radius: 999px;
    padding: 0.2rem 0.55rem;
    font-size: 0.72rem;
    font-weight: 850;
    letter-spacing: 0.02em;
    border: 1px solid transparent;
}
.origin-badge-document-deep-dive {
    color: #145a7a;
    background: linear-gradient(135deg, #e8f4fb 0%, #dff1f7 100%);
    border-color: #afd8e8;
}
.origin-badge-chapter-deep-dive {
    color: #27614c;
    background: linear-gradient(135deg, #edf8ed 0%, #e0f2df 100%);
    border-color: #b8d9b2;
}
.deep-dive-merged-note {
    border: 1px solid rgba(8,119,96,0.16);
    border-left: 4px solid var(--accent);
    border-radius: 15px;
    background:
        linear-gradient(135deg, rgba(247,252,248,0.94) 0%, rgba(238,247,232,0.92) 100%);
    color: var(--ink);
    padding: 0.58rem 0.72rem;
    margin: 0.55rem 0 0.42rem;
    font-size: 0.88rem;
    line-height: 1.5;
    box-shadow: 0 6px 16px rgba(24, 35, 30, 0.04);
}
.deep-dive-merged-note b {
    color: var(--accent-strong);
}
.remediation-meta {
    color: var(--ink-soft);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.72rem;
    line-height: 1.45;
    margin-top: 0.35rem;
}
.remediation-text {
    color: var(--ink-soft);
    font-size: 0.84rem;
    line-height: 1.55;
    margin-top: 0.45rem;
}
.re-review-lane {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.6rem;
    margin-top: 0.85rem;
}
.re-review-step {
    border: 1px solid rgba(8,119,96,0.14);
    border-radius: 16px;
    background: rgba(247,252,250,0.78);
    padding: 0.68rem 0.75rem;
}
.re-review-label {
    color: var(--accent-strong);
    font-weight: 900;
    font-size: 0.88rem;
}
.re-review-detail {
    color: var(--ink-soft);
    font-size: 0.8rem;
    line-height: 1.5;
    margin-top: 0.28rem;
}
.next-work-lane {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.58rem;
    margin-top: 0.78rem;
}
.next-work-step {
    border: 1px solid rgba(217,209,192,0.70);
    border-radius: 16px;
    background: rgba(255,255,255,0.66);
    padding: 0.64rem 0.72rem;
}
.next-work-label {
    color: var(--ink);
    font-weight: 900;
    font-size: 0.86rem;
}
.next-work-detail {
    color: var(--ink-soft);
    font-size: 0.78rem;
    line-height: 1.45;
    margin-top: 0.25rem;
}
.comparison-panel {
    border: 1px solid rgba(8,119,96,0.18);
    border-radius: 22px;
    background:
        radial-gradient(circle at top left, rgba(255,191,71,0.11), transparent 17rem),
        linear-gradient(135deg, rgba(255,253,248,0.96) 0%, rgba(239,248,245,0.92) 100%);
    padding: 0.92rem 1rem;
    margin: 0.9rem 0 1rem;
    box-shadow: 0 12px 28px rgba(24,35,30,0.055);
}
.comparison-head {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
}
.comparison-title {
    color: var(--ink);
    font-weight: 900;
    font-size: 1.08rem;
}
.comparison-detail {
    color: var(--ink-soft);
    font-size: 0.84rem;
    line-height: 1.55;
    margin-top: 0.28rem;
}
.comparison-metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 0.42rem;
    margin-top: 0.72rem;
}
.comparison-pill {
    border: 1px solid rgba(217,209,192,0.72);
    border-radius: 999px;
    background: rgba(255,255,255,0.72);
    padding: 0.28rem 0.55rem;
    color: var(--ink);
    font-weight: 800;
    font-size: 0.78rem;
}
.comparison-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 0.62rem;
    margin-top: 0.78rem;
}
.comparison-card {
    border: 1px solid rgba(217,209,192,0.76);
    border-left: 5px solid var(--rule);
    border-radius: 17px;
    background: rgba(255,255,255,0.72);
    padding: 0.72rem 0.78rem;
}
.comparison-card.improved { border-left-color: var(--accent); background: rgba(244,252,247,0.90); }
.comparison-card.partial { border-left-color: var(--warn); background: rgba(255,249,234,0.90); }
.comparison-card.not_confirmed { border-left-color: var(--danger); background: rgba(255,245,242,0.90); }
.comparison-card.needs_review { border-left-color: var(--cyan); }
.comparison-card-title {
    color: var(--ink);
    font-weight: 900;
    font-size: 0.9rem;
    line-height: 1.4;
}
.comparison-card-meta {
    color: var(--ink-soft);
    font-size: 0.73rem;
    line-height: 1.45;
    margin-top: 0.28rem;
}
.comparison-card-text {
    color: var(--ink-soft);
    font-size: 0.8rem;
    line-height: 1.5;
    margin-top: 0.38rem;
}
.export-panel {
    border: 1px solid rgba(8,119,96,0.16);
    border-left: 5px solid var(--cyan);
    border-radius: 20px;
    background:
        linear-gradient(135deg, rgba(255,253,248,0.88) 0%, rgba(236,247,245,0.86) 100%);
    padding: 0.85rem 0.95rem;
    margin: 0.75rem 0 0.9rem;
    box-shadow: 0 10px 24px rgba(24,35,30,0.055);
}
.export-title {
    color: var(--ink);
    font-weight: 900;
    font-size: 1rem;
}
.export-detail {
    color: var(--ink-soft);
    font-size: 0.84rem;
    line-height: 1.55;
    margin-top: 0.35rem;
}
.sr-chip,
.sr-effort-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    width: fit-content;
    border-radius: 999px;
    border: 1px solid transparent;
    padding: 0.22rem 0.62rem;
    font-size: 0.76rem;
    font-weight: 900;
    line-height: 1.2;
}
.sr-severity-high {
    background: var(--sr-danger-bg);
    color: var(--sr-danger-fg);
    border-color: rgba(157,47,47,0.18);
}
.sr-severity-medium {
    background: var(--sr-warning-bg);
    color: var(--sr-warning-fg);
    border-color: rgba(167,103,0,0.18);
}
.sr-severity-low {
    background: var(--sr-success-bg);
    color: var(--sr-success-fg);
    border-color: rgba(8,119,96,0.18);
}
.sr-severity-neutral {
    background: var(--sr-bg-secondary);
    color: var(--sr-text-secondary);
    border-color: var(--sr-border);
}
.sr-effort-large {
    background: var(--sr-danger-bg);
    color: var(--sr-danger-fg);
    border-color: rgba(157,47,47,0.18);
}
.sr-effort-medium {
    background: var(--sr-warning-bg);
    color: var(--sr-warning-fg);
    border-color: rgba(167,103,0,0.18);
}
.sr-effort-small {
    background: var(--sr-success-bg);
    color: var(--sr-success-fg);
    border-color: rgba(8,119,96,0.18);
}
.sr-status-bar {
    display: flex;
    justify-content: space-between;
    gap: 0.8rem;
    align-items: center;
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-lg);
    background: var(--sr-bg-primary);
    color: var(--sr-text-primary);
    padding: 0.72rem 0.85rem;
    box-shadow: 0 10px 24px rgba(24,35,30,0.055);
}
.sr-status-main {
    display: inline-flex;
    align-items: center;
    gap: 0.42rem;
    font-weight: 900;
}
.sr-status-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 1.15rem;
    color: var(--sr-text-secondary);
}
.sr-status-meta {
    color: var(--sr-text-secondary);
    font-size: 0.78rem;
}
.workflow-v2 {
    margin: 0.7rem 0 1.15rem;
}
.step-v2-heading {
    margin: 0.9rem 0 0.85rem;
}
.step-v2-kicker {
    color: var(--sr-text-tertiary);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.76rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
}
.step-v2-title {
    color: var(--sr-text-primary);
    font-size: 1.65rem;
    font-weight: 900;
    line-height: 1.25;
    margin-top: 0.12rem;
}
.step-v2-subtitle {
    color: var(--sr-text-secondary);
    font-size: 0.92rem;
    line-height: 1.55;
    margin-top: 0.25rem;
}
.upload-zone-v2,
.compare-card-v2,
.send-destination-card,
.approval-card-v2 {
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-lg);
    background: rgba(255,253,248,0.82);
    box-shadow: 0 12px 28px rgba(24,35,30,0.055);
    padding: 0.9rem 1rem;
    margin: 0.85rem 0;
}
.upload-file-row {
    display: flex;
    justify-content: space-between;
    gap: 0.8rem;
    align-items: center;
    border: 1px solid rgba(217,209,192,0.72);
    border-radius: var(--sr-radius-md);
    background: rgba(255,255,255,0.72);
    padding: 0.62rem 0.72rem;
    margin: 0.42rem 0;
}
.upload-file-row.warn {
    border-left: 5px solid var(--warn);
    background: #fff7e4;
}
.upload-file-name {
    color: var(--sr-text-primary);
    font-weight: 900;
    overflow-wrap: anywhere;
}
.upload-file-meta {
    color: var(--sr-text-secondary);
    font-size: 0.82rem;
    white-space: nowrap;
}
.send-boundary-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.85rem;
    margin: 0.9rem 0;
}
.send-boundary-card {
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-lg);
    background: var(--sr-bg-primary);
    padding: 0.95rem 1rem;
    min-height: 10rem;
}
.send-boundary-card.send {
    border-left: 6px solid var(--accent);
}
.send-boundary-card.keep {
    border-left: 6px solid var(--cyan);
}
.send-boundary-title {
    color: var(--sr-text-primary);
    font-weight: 900;
    font-size: 1.06rem;
}
.send-boundary-list {
    margin: 0.55rem 0 0;
    padding-left: 1.1rem;
    color: var(--sr-text-secondary);
    line-height: 1.65;
    font-size: 0.9rem;
}
.send-destination-title {
    color: var(--sr-text-primary);
    font-size: 1.2rem;
    font-weight: 900;
}
.send-destination-meta {
    color: var(--sr-text-secondary);
    font-size: 0.9rem;
    line-height: 1.6;
    margin-top: 0.25rem;
}
.approval-card-v2 {
    background: linear-gradient(135deg, rgba(255,253,248,0.95) 0%, rgba(239,246,242,0.9) 100%);
}
.approval-card-v2.warn {
    border-left: 6px solid var(--warn);
}
.approval-card-v2.block {
    border-left: 6px solid var(--danger);
    background: #fff0ec;
}
@media (max-width: 760px) {
    .send-boundary-grid { grid-template-columns: 1fr; }
    .upload-file-row { display: block; }
    .upload-file-meta { margin-top: 0.2rem; }
}
.step2-v2 {
    margin: 0.7rem 0 1.2rem;
}
.step2-heading {
    margin: 0.9rem 0 0.85rem;
}
.step2-kicker {
    color: var(--sr-text-tertiary);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.76rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
}
.step2-title {
    color: var(--sr-text-primary);
    font-size: 1.65rem;
    font-weight: 900;
    line-height: 1.25;
    margin-top: 0.12rem;
}
.step2-subtitle {
    color: var(--sr-text-secondary);
    font-size: 0.92rem;
    line-height: 1.55;
    margin-top: 0.25rem;
}
.step2-summary-lead {
    color: var(--sr-text-primary);
    font-size: 1.08rem;
    font-weight: 900;
    margin-top: 0.35rem;
}
.artifact-mode-card {
    border: 1px solid rgba(8,119,96,0.18);
    border-left: 6px solid var(--accent);
    border-radius: var(--sr-radius-lg);
    background: linear-gradient(135deg, rgba(255,253,248,0.92) 0%, rgba(223,240,234,0.56) 100%);
    box-shadow: 0 12px 28px rgba(24,35,30,0.055);
    padding: 0.9rem 1rem;
    margin: 0.8rem 0 0.95rem;
}
.artifact-mode-kicker {
    color: var(--sr-text-tertiary);
    font-family: 'SF Mono', 'Consolas', 'Hiragino Sans', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.13em;
    text-transform: uppercase;
}
.artifact-mode-title {
    color: var(--sr-text-primary);
    font-size: 1.08rem;
    font-weight: 900;
    margin-top: 0.15rem;
}
.artifact-mode-summary {
    color: var(--sr-text-secondary);
    font-size: 0.9rem;
    line-height: 1.62;
    margin-top: 0.36rem;
}
.artifact-mode-note {
    color: var(--sr-text-secondary);
    font-size: 0.82rem;
    line-height: 1.55;
    margin: 0.42rem 0 0;
    padding-left: 1.1rem;
}
.step2-mask-band {
    border: 1px solid rgba(167,103,0,0.22);
    border-left: 6px solid var(--warn);
    border-radius: var(--sr-radius-lg);
    background: linear-gradient(135deg, #fffdf8 0%, #fff4d8 100%);
    padding: 0.95rem 1rem;
    margin: 1rem 0 0.85rem;
    box-shadow: 0 12px 28px rgba(24,35,30,0.06);
}
.step2-mask-band.safe {
    border-left-color: var(--accent);
    border-color: rgba(8,119,96,0.16);
    background: linear-gradient(135deg, rgba(255,253,248,0.95) 0%, rgba(234,245,231,0.92) 100%);
}
.step2-mask-title {
    color: var(--sr-text-primary);
    font-size: 1.18rem;
    font-weight: 900;
}
.step2-mask-detail {
    color: var(--sr-text-secondary);
    font-size: 0.9rem;
    line-height: 1.55;
    margin-top: 0.28rem;
}
.step2-candidate-card {
    border: 1px solid rgba(217, 209, 192, 0.85);
    border-radius: var(--sr-radius-md);
    background: rgba(255,255,255,0.72);
    padding: 0.75rem 0.85rem;
    margin-top: 0.65rem;
}
.step2-candidate-word {
    color: var(--sr-text-primary);
    font-size: 1rem;
    font-weight: 900;
}
.step2-candidate-meta {
    color: var(--sr-text-secondary);
    font-size: 0.8rem;
    margin-top: 0.18rem;
}
.step2-candidate-context {
    color: var(--sr-text-secondary);
    background: rgba(247,247,245,0.72);
    border-radius: var(--sr-radius-sm);
    font-size: 0.84rem;
    line-height: 1.55;
    margin-top: 0.45rem;
    padding: 0.45rem 0.55rem;
}
.step2-doc-detail-head {
    color: var(--sr-text-secondary);
    font-size: 0.86rem;
    line-height: 1.55;
    margin-bottom: 0.55rem;
}
.step2-next-action {
    border: 1px solid rgba(8,119,96,0.18);
    border-radius: var(--sr-radius-lg);
    background: rgba(255,253,248,0.76);
    padding: 0.85rem 1rem;
    margin: 0.9rem 0 0.8rem;
}
.step2-next-title {
    color: var(--sr-text-primary);
    font-weight: 900;
}
.step2-next-detail {
    color: var(--sr-text-secondary);
    font-size: 0.88rem;
    line-height: 1.55;
    margin-top: 0.2rem;
}
.sr-big-number {
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-lg);
    background: var(--sr-bg-primary);
    padding: 0.75rem 0.85rem;
}
.sr-big-number-lead {
    color: var(--sr-text-tertiary);
    font-size: 0.72rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 800;
}
.sr-big-number-value {
    color: var(--sr-text-primary);
    font-size: 1.75rem;
    font-weight: 900;
    line-height: 1.1;
}
.sr-issue-card-header {
    border: 1px solid var(--sr-border);
    border-left: 5px solid var(--sr-warning-fg);
    border-radius: var(--sr-radius-lg);
    background: var(--sr-bg-primary);
    padding: 0.85rem 0.95rem;
}
.sr-issue-card-header.high { border-left-color: var(--sr-danger-fg); }
.sr-issue-card-header.medium { border-left-color: var(--sr-warning-fg); }
.sr-issue-card-header.low { border-left-color: var(--sr-success-fg); }
.sr-issue-card-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    align-items: center;
    margin-bottom: 0.5rem;
}
.sr-issue-card-submeta {
    color: var(--sr-text-tertiary);
    font-size: 0.75rem;
    font-weight: 800;
}
.sr-issue-card-title {
    color: var(--sr-text-primary);
    font-size: 0.98rem;
    font-weight: 900;
    line-height: 1.45;
}
.sr-collapsed-row {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 0.65rem;
    align-items: start;
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-md);
    background: var(--sr-bg-primary);
    padding: 0.65rem 0.72rem;
}
.sr-collapsed-row-title {
    color: var(--sr-text-primary);
    font-weight: 900;
    line-height: 1.35;
}
.sr-collapsed-row-subtitle {
    color: var(--sr-text-secondary);
    font-size: 0.78rem;
    line-height: 1.45;
    margin-top: 0.14rem;
}
.sr-metric-pair {
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-md);
    background: var(--sr-bg-primary);
    padding: 0.62rem 0.7rem;
}
.sr-metric-label {
    color: var(--sr-text-tertiary);
    font-size: 0.7rem;
    font-weight: 800;
    letter-spacing: 0.06em;
}
.sr-metric-value {
    color: var(--sr-text-primary);
    font-size: 1.05rem;
    font-weight: 900;
    margin-top: 0.1rem;
}
.step4-v2 {
    display: flex;
    flex-direction: column;
    gap: 1.05rem;
}
.step4-summary-note {
    border: 1px solid rgba(8,119,96,0.14);
    border-radius: var(--sr-radius-md);
    background: rgba(255,253,248,0.72);
    color: var(--sr-text-secondary);
    padding: 0.8rem 0.9rem;
    line-height: 1.7;
}
.step4-chip-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.55rem;
    align-items: center;
}
.step4-section-head {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: center;
    margin-top: 0.7rem;
}
.step4-section-title {
    color: var(--sr-text-primary);
    font-size: 1.35rem;
    font-weight: 900;
    letter-spacing: -0.02em;
}
.step4-section-caption {
    color: var(--sr-text-secondary);
    font-size: 0.86rem;
    line-height: 1.6;
    margin-top: 0.2rem;
}
.step4-card-body {
    border: 1px solid var(--sr-border);
    border-radius: var(--sr-radius-lg);
    background: rgba(255,253,248,0.70);
    padding: 0.85rem;
    margin-top: 0.55rem;
}
.step4-item-context {
    display: flex;
    flex-wrap: wrap;
    gap: 0.42rem;
    margin-top: 0.58rem;
}
.step4-context-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.28rem;
    border: 1px solid rgba(8,119,96,0.14);
    border-radius: 999px;
    background: rgba(255,255,255,0.68);
    color: var(--sr-text-secondary);
    font-size: 0.78rem;
    line-height: 1.35;
    padding: 0.28rem 0.58rem;
}
.step4-context-pill b {
    color: var(--sr-text-primary);
    font-weight: 850;
}
.step4-field-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.75rem;
}
.step4-field {
    border: 1px solid rgba(8,119,96,0.11);
    border-radius: var(--sr-radius-md);
    background: rgba(247,247,245,0.78);
    padding: 0.72rem 0.78rem;
}
.step4-field-label {
    color: var(--sr-text-tertiary);
    font-size: 0.74rem;
    font-weight: 900;
    letter-spacing: 0.08em;
    margin-bottom: 0.35rem;
}
.step4-field-value {
    color: var(--sr-text-primary);
    font-size: 0.9rem;
    line-height: 1.65;
    white-space: pre-wrap;
}
.step4-copy-note {
    color: var(--sr-text-secondary);
    font-size: 0.82rem;
    line-height: 1.55;
}
.step4-aux-list {
    display: grid;
    gap: 0.7rem;
}
.step4-guide-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.75rem;
}
.step4-guide-card {
    border: 1px solid rgba(8,119,96,0.12);
    border-radius: var(--sr-radius-md);
    background: rgba(255,253,248,0.72);
    padding: 0.75rem 0.8rem;
}
.step4-guide-title {
    color: var(--sr-text-primary);
    font-weight: 900;
}
.step4-guide-body {
    color: var(--sr-text-secondary);
    font-size: 0.84rem;
    line-height: 1.6;
    margin-top: 0.35rem;
}
@media (max-width: 760px) {
    .step4-section-head { display: block; }
    .step4-field-grid { grid-template-columns: 1fr; }
    .step4-guide-grid { grid-template-columns: 1fr; }
}
@media (max-width: 760px) {
    .remediation-head { display: block; }
    .remediation-summary { margin-top: 0.45rem; }
}

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
    "unknown": "未判定",
}

TOKEN_BUDGET_STATUS_LABELS = {
    "mock": "外部消費なし",
    "safe": "通常範囲",
    "caution": "注意",
    "split_recommended": "分割推奨",
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
    "network_config": "ネットワーク機器Config",
    "source_code": "ソースコード",
}

ISSUE_ID_PREFIX_HELP = {
    "design": "D = Design（設計書）",
    "proposal": "P = Proposal（企画書）",
    "change_runbook": "CR = Change Runbook（変更・切替手順書）",
    "operations_runbook": "OR = Operations Runbook（保守・運用手順書）",
    "network_config": "NC = Network Config（ネットワーク機器Config）",
    "source_code": "SC = Source Code（ソースコード）",
}

MAX_CHAPTER_DEEP_DIVE_PASSES = 2

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


def _profile_label(value: str | None) -> str:
    if value is None:
        return "-"
    return PROFILE_LABELS.get(value, value)


def _issue_id_prefix_help(value: str | None) -> str:
    if value is None:
        return "I = Issue（レビュー指摘）"
    return ISSUE_ID_PREFIX_HELP.get(value, "I = Issue（レビュー指摘）")


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
        "anonymization_details_expand_once",
        "review_result",
        "structure_result",
        "remediation_plan",
        "review_issue_feedback",
        "review_issue_feedback_notes",
        # R-M (PR-D2)
        "masking_states",
        "user_decisions",
        "last_uploaded_filenames",
        # R-Y (2026-05-08): 深堀結果。リセット時にクリアしないと、
        # 次のレビュー実行時に同名文書の旧深堀結果が表示されてしまう。
        "deep_dive_results",
        "chapter_deep_dive_results",
        "deep_dive_notice",
        # Phase 7 段階 2-C (2026-05-08): 章境界キャッシュ。文書が変われば再計算。
        "chapter_sections_cache",
        # 再レビュー用の前回修正計画JSON
        "enable_previous_remediation_review",
        "previous_remediation_plan",
        "previous_remediation_plan_upload",
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


def _format_file_size(num_bytes: int | None) -> str:
    size = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _upload_size(upload) -> int:
    try:
        return int(getattr(upload, "size", 0) or len(upload.getvalue()))
    except Exception:  # noqa: BLE001
        return 0


def _render_direct_status_bar(state_label: str, meta_right: str = "", icon: str = "") -> None:
    st.markdown(
        sr_ui.status_bar(state_label, meta_right, icon),
        unsafe_allow_html=True,
    )


def _render_step_v2_heading(step_label: str, title: str, subtitle: str) -> None:
    st.markdown(
        f"""
<section class="step-v2-heading">
  <div class="step-v2-kicker">{html.escape(step_label)}</div>
  <div class="step-v2-title">{html.escape(title)}</div>
  <div class="step-v2-subtitle">{html.escape(subtitle)}</div>
</section>
        """,
        unsafe_allow_html=True,
    )


def _render_selected_uploads(uploads: list, duplicates: list[tuple[str, str]]) -> None:
    if not uploads:
        st.caption("まだファイルは選択されていません。")
        return

    duplicate_map = {name: seen for name, seen in duplicates}
    st.markdown("#### 選択中ファイル")
    for upload in sorted(uploads, key=lambda u: _natural_sort_key(u.name)):
        seen = duplicate_map.get(upload.name)
        row_class = "upload-file-row warn" if seen else "upload-file-row"
        warning = f" / {html.escape(seen)} と同一内容" if seen else ""
        st.markdown(
            f"""
<div class="{row_class}">
  <div class="upload-file-name">{html.escape(upload.name)}</div>
  <div class="upload-file-meta">{html.escape(_format_file_size(_upload_size(upload)))}{warning}</div>
</div>
            """,
            unsafe_allow_html=True,
        )
    if duplicates:
        st.warning(
            f"重複ファイルが {len(duplicates)} 件あります。該当ファイルを削除してから匿名化プレビューを実行してください。"
        )


def _render_step1_v2() -> bool:
    uploads = _get_uploads()
    duplicates = _detect_duplicate_uploads() if uploads else []

    st.markdown("<div class='workflow-v2 step1-v2'>", unsafe_allow_html=True)
    _render_direct_status_bar("準備中 · ステップ 1 / 3", "レビュー前")
    _render_step_v2_heading(
        "ステップ 1",
        "文書アップロード",
        "レビューする設計書を選択してください。",
    )

    with st.expander("前回のレビュー結果と比較する", expanded=False):
        st.caption("修正後文書の再レビュー時だけ使います。通常レビューでは閉じたままで問題ありません。")
        _render_previous_remediation_plan_loader()

    st.markdown("<section class='upload-zone-v2'>", unsafe_allow_html=True)
    st.file_uploader(
        "レビュー対象ファイル",
        accept_multiple_files=True,
        key=st.session_state.uploader_key,
        help=(
            "対応形式: txt, md, docx, xlsx, pptx, pdf, csv, json, yaml/yml, xml, "
            "html, スクリプト (py, ps1, sh, vbs, sql など), 画像。"
            " 同一内容のファイルは重複検出されアップロードできません。"
        ),
    )
    _render_selected_uploads(uploads, duplicates)
    st.markdown("</section>", unsafe_allow_html=True)

    preview_clicked = st.button(
        "匿名化してプレビュー",
        type="primary",
        disabled=not uploads,
        width="stretch",
        key="step1_preview_button_v2",
        help="選択した文書をローカルで抽出・匿名化し、Step 2 の確認画面へ進みます。",
    )
    st.markdown("</div>", unsafe_allow_html=True)
    return preview_clicked


def _estimate_for_step3(
    preview_docs: list[SanitizedDocument],
    document_profile_override: str | None,
):
    try:
        return estimate_review_token_budget(preview_docs, document_profile_override)
    except Exception:  # noqa: BLE001
        return None


def _review_meta(preview_docs: list[SanitizedDocument], estimate=None) -> str:
    if estimate is not None:
        return f"{len(preview_docs)} ファイル · {estimate.body_tokens:,} tokens"
    tokens = sum(int(getattr(doc, "estimated_input_tokens", 0) or 0) for doc in preview_docs)
    return f"{len(preview_docs)} ファイル · {tokens:,} tokens"


def _format_chunking_interval_note(estimate) -> str:
    if estimate is None:
        return ""
    interval = float(getattr(estimate, "throttle_interval_seconds", 0.0) or 0.0)
    wait_total = int(getattr(estimate, "minimum_wait_seconds", 0) or 0)
    if interval <= 0 or wait_total <= 0:
        return ""
    interval_label = f"{interval:g}"
    return (
        f" / API呼び出し間隔: {interval_label}秒/回"
        f"（待機合計: {wait_total}秒、LLM応答時間は別）"
    )


def _format_review_runtime_error(exc: RuntimeError) -> str:
    message = str(exc)
    if "HTTP 503" in message or "Service Unavailable" in message:
        return (
            "Gemini/Gemma API が一時的に応答できませんでした (HTTP 503)。"
            "これはローカルLLMの応答時間ではなく、外部API側の混雑・一時停止・モデル提供側の不安定さで発生します。\n\n"
            "数分置いてから再実行してください。連続して発生する場合は、ファイル数を減らして分割レビューするか、"
            "Streamlit Secrets の `GEMINI_MAX_RETRIES` / `GEMINI_CHUNKING_INTERVAL` / `GEMINI_TIMEOUT_SECONDS` を見直してください。"
        )
    return message


def _render_review_runtime_status(
    state_label: str,
    preview_docs: list[SanitizedDocument],
    *,
    icon: str = "↗",
    estimate=None,
) -> None:
    _render_direct_status_bar(state_label, _review_meta(preview_docs, estimate), icon)


def _reset_step3_send_state_for_step2() -> None:
    """Reset Step 3 approval before rerendering Step 2."""
    st.session_state.send_approval = False
    st.session_state.step2_ready_acknowledged = False


def _render_step3_v2(
    preview_docs: list[SanitizedDocument],
    *,
    blocked_docs: list[SanitizedDocument],
    mask_docs: list[SanitizedDocument],
    provider_label: str,
    estimate,
) -> tuple[bool, bool]:
    status_label = "送信不可 · ステップ 3 / 3" if blocked_docs else "送信準備完了 · ステップ 3 / 3"
    st.markdown("<div class='workflow-v2 step3-v2'>", unsafe_allow_html=True)
    _render_direct_status_bar(status_label, _review_meta(preview_docs, estimate))
    _render_step_v2_heading(
        "ステップ 3",
        "送信",
        "外部 LLM サービスに匿名化済みテキストを送ります。原文はここから先には出ません。",
    )

    wait_note = ""
    if estimate is not None:
        wait_note = _format_chunking_interval_note(estimate)
        call_note = f"予定 call: {estimate.call_count} / 入力概算: {estimate.total_input_tokens:,} tokens"
    else:
        call_note = "予定 call: 未計算 / 入力概算: 未計算"
    st.markdown(
        f"""
<section class="send-destination-card">
  <div class="send-destination-title">送信先: {html.escape(provider_label)}</div>
  <div class="send-destination-meta">{html.escape(call_note + wait_note)}</div>
</section>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="send-boundary-grid">
  <section class="send-boundary-card send">
    <div class="send-boundary-title">送信されるもの</div>
    <ul class="send-boundary-list">
      <li>匿名化済みテキスト</li>
      <li>レビュー基準プロンプト</li>
      <li>{html.escape(_review_meta(preview_docs, estimate))}</li>
    </ul>
  </section>
  <section class="send-boundary-card keep">
    <div class="send-boundary-title">送信されないもの</div>
    <ul class="send-boundary-list">
      <li>アップロードした原文ファイル</li>
      <li>ファイル binary そのもの</li>
      <li>マスク候補の元の語とローカル判断履歴</li>
    </ul>
  </section>
</div>
        """,
        unsafe_allow_html=True,
    )

    if blocked_docs:
        st.markdown(
            f"""
<section class="approval-card-v2 block">
  <div class="send-destination-title">送信できません</div>
  <div class="send-destination-meta">
    送信禁止の文書があります: {html.escape(", ".join(doc.name for doc in blocked_docs))}。
    対象文書を修正するか、再プレビューしてください。
  </div>
</section>
            """,
            unsafe_allow_html=True,
        )
        send_approved = False
    else:
        if mask_docs:
            st.markdown(
                f"""
<section class="approval-card-v2 warn">
  <div class="send-destination-title">追加確認を含む送信です</div>
  <div class="send-destination-meta">
    {len(mask_docs)} 件の文書に要確認または未判定項目があります。
    Step 2 の匿名化結果を確認したうえで承認してください。
  </div>
</section>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
<section class="approval-card-v2">
  <div class="send-destination-title">ローカル境界を越える直前の確認です</div>
  <div class="send-destination-meta">
    チェックするとレビュー実行ボタンが有効になります。外部へ送る対象は匿名化済みテキストのみです。
  </div>
</section>
                """,
                unsafe_allow_html=True,
            )
        send_approved = st.checkbox(
            "上記の内容で送信することを承認します。",
            key="send_approval",
            help="匿名化済みテキストを外部 LLM レビューへ送信する最終承認です。",
        )

    can_send = bool(preview_docs) and not blocked_docs and send_approved
    col_send, col_back = st.columns([1.35, 1.0])
    with col_send:
        send_clicked = st.button(
            "レビューを実行",
            type="primary",
            disabled=not can_send,
            width="stretch",
            help="LLM プロバイダに匿名化済みテキストを送信し、レビュー結果を取得します。",
            key="send_review_button",
        )
    with col_back:
        st.button(
            "ステップ 2 に戻る",
            type="secondary",
            width="stretch",
            key="back_to_step2_button",
            on_click=_reset_step3_send_state_for_step2,
        )

    if blocked_docs:
        st.caption("送信禁止の文書があるため、レビューは実行できません。")
    elif not send_approved:
        st.caption("レビューを実行するには、承認チェックを入れてください。")
    else:
        st.caption("送信準備完了。設定された LLM プロバイダには匿名化済みテキストのみが送信されます。")

    st.markdown("</div>", unsafe_allow_html=True)
    return send_clicked, send_approved


def _build_anonymization_summary(preview_docs: list[SanitizedDocument]) -> dict[str, int]:
    counts = {"safe": 0, "mask_and_continue": 0, "block": 0, "unknown": 0}
    replacement_count = 0
    estimated_tokens = 0
    uncertain_count = 0
    masking_states = st.session_state.get("masking_states", {}) or {}
    for doc in preview_docs:
        decision = doc.local_sensitivity_decision or "unknown"
        counts[decision] = counts.get(decision, 0) + 1
        replacement_count += len(getattr(doc, "replacements", []) or [])
        estimated_tokens += int(getattr(doc, "estimated_input_tokens", 0) or 0)
        state = masking_states.get(doc.name)
        if state is not None:
            uncertain_count += len(getattr(state, "uncertain_candidates", []) or [])
    return {
        "safe": counts.get("safe", 0),
        "mask_and_continue": counts.get("mask_and_continue", 0),
        "block": counts.get("block", 0),
        "unknown": counts.get("unknown", 0),
        "replacement_count": replacement_count,
        "estimated_tokens": estimated_tokens,
        "uncertain_count": uncertain_count,
    }


def _iter_uncertain_mask_candidates(
    masking_states: dict,
) -> list[tuple[MaskingPipelineState, NerCandidate]]:
    candidates: list[tuple[MaskingPipelineState, NerCandidate]] = []
    for state in (masking_states or {}).values():
        for candidate in getattr(state, "uncertain_candidates", ()) or ():
            candidates.append((state, candidate))
    return candidates


def _mask_decision_progress(masking_states: dict) -> tuple[int, int]:
    candidates = _iter_uncertain_mask_candidates(masking_states)
    decisions = st.session_state.get("user_decisions", {}) or {}
    decided = sum(
        1
        for state, candidate in candidates
        if _decision_key(state.name, candidate.text) in decisions
    )
    return len(candidates), decided


def _step2_chip(label: str, value: object, level: str) -> str:
    level_key = {
        "success": "low",
        "warning": "medium",
        "neutral": "neutral",
        "danger": "high",
    }.get(level, "neutral")
    return (
        f"<span class='sr-chip sr-severity-{level_key}'>"
        f"{html.escape(label)}<span>{html.escape(str(value))}</span></span>"
    )


def _render_step2_header_and_summary(
    preview_docs: list[SanitizedDocument],
    masking_states: dict,
) -> None:
    summary = _build_anonymization_summary(preview_docs)
    total_tokens = summary["estimated_tokens"]
    st.markdown(
        sr_ui.status_bar(
            "準備中 · ステップ 2 / 3",
            f"{len(preview_docs)} ファイル / {total_tokens:,} tokens",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        """
<section class="step2-heading">
  <div class="step2-kicker">Step 2</div>
  <div class="step2-title">匿名化結果の確認</div>
  <div class="step2-subtitle">外部 LLM に送信する前に、内容と安全性を確認します。</div>
</section>
        """,
        unsafe_allow_html=True,
    )
    chip_html = "".join(
        [
            _step2_chip("安全", summary["safe"], "success"),
            _step2_chip("要確認", summary["mask_and_continue"] + summary["unknown"], "warning"),
            _step2_chip("候補", summary["uncertain_count"], "warning" if summary["uncertain_count"] else "neutral"),
            _step2_chip("本文tokens", f"{total_tokens:,}", "neutral"),
        ]
    )
    st.markdown(
        f"""
<div class="step2-summary-lead">{len(preview_docs)} ファイルを匿名化しました</div>
<div class="step4-chip-row">{chip_html}</div>
        """,
        unsafe_allow_html=True,
    )


def _render_artifact_review_mode_notice(
    preview_docs: list[SanitizedDocument],
    document_profile_override: str | None,
) -> None:
    if not preview_docs:
        return
    classification = classify_documents(preview_docs, document_profile_override)
    mode = detect_artifact_review_mode(preview_docs, classification.document_profile)
    notes_html = "".join(f"<li>{html.escape(note)}</li>" for note in mode.ui_notes[:3])
    meta_parts = [
        f"判定: {_profile_label(classification.document_profile)}",
        f"信頼度: {classification.confidence}",
    ]
    if mode.detected_languages:
        meta_parts.append(f"形式: {', '.join(mode.detected_languages)}")
    if mode.runbook_depth:
        meta_parts.append(f"粒度: {mode.runbook_depth}")
    st.markdown(
        f"""
<section class="artifact-mode-card">
  <div class="artifact-mode-kicker">Review Mode</div>
  <div class="artifact-mode-title">{html.escape(mode.mode_name)}</div>
  <div class="artifact-mode-summary">{html.escape(mode.summary)}</div>
  <div class="artifact-mode-summary"><strong>出力方針:</strong> {html.escape(mode.primary_output)}</div>
  <ul class="artifact-mode-note">{notes_html}</ul>
  <div class="artifact-mode-summary">{html.escape(' / '.join(meta_parts))}</div>
</section>
        """,
        unsafe_allow_html=True,
    )


def _is_code_analysis_review(
    preview_docs: list[SanitizedDocument],
    document_profile_override: str | None,
) -> bool:
    if not preview_docs:
        return False
    classification = classify_documents(preview_docs, document_profile_override)
    mode = detect_artifact_review_mode(preview_docs, classification.document_profile)
    return mode.mode_id == "code_analysis"


def _candidate_context_excerpt(candidate: NerCandidate, full_text: str) -> str:
    if not full_text or candidate.start < 0 or candidate.end <= candidate.start:
        return ""
    ctx_start = max(0, candidate.start - 30)
    ctx_end = min(len(full_text), candidate.end + 30)
    before = full_text[ctx_start:candidate.start].replace("\n", " ").replace("\r", " ")
    after = full_text[candidate.end:ctx_end].replace("\n", " ").replace("\r", " ")
    prefix = "..." if ctx_start > 0 else ""
    suffix = "..." if ctx_end < len(full_text) else ""
    return f"{prefix}{before}{candidate.text}{after}{suffix}"


def _render_mask_candidate_decision(
    state: MaskingPipelineState,
    candidate: NerCandidate,
    full_text: str,
) -> None:
    key = _decision_key(state.name, candidate.text)
    user_decisions = st.session_state.setdefault("user_decisions", {})
    current = bool(user_decisions.get(key, True))
    context = _candidate_context_excerpt(candidate, full_text)
    with st.container(border=True):
        st.markdown(
            f"""
<div class="step2-candidate-card">
  <div class="step2-candidate-word">「{html.escape(candidate.text)}」</div>
  <div class="step2-candidate-meta">
    文書: {html.escape(state.name)} / カテゴリ: {html.escape(candidate.label)} / spaCy: {html.escape(candidate.spacy_label)}
  </div>
  {f'<div class="step2-candidate-context">文脈: {html.escape(context)}</div>' if context else ''}
</div>
            """,
            unsafe_allow_html=True,
        )
        lookup = state.lookups.get(candidate.text)
        if lookup is None:
            st.caption("gBizINFO 検索: 未実行 (トークン未設定または機能無効)")
        elif lookup.error:
            st.warning(f"🏢 gBizINFO 検索失敗: {lookup.error}。判断は人間にお任せします。")
        elif lookup.hits == 0:
            st.caption("🏢 gBizINFO 検索: ヒット 0 件 (法人名としては未登録)")
        else:
            top_str = "、".join(lookup.top_names[:5])
            st.markdown(
                f"🏢 gBizINFO 検索: **{lookup.hits} 件**ヒット"
                + (f" — {top_str}" if top_str else "")
            )
        choice = st.radio(
            "判断",
            options=["マスクする (推奨)", "マスクしない"],
            index=0 if current else 1,
            key=f"step2_mask_decision_{key}",
            horizontal=True,
            label_visibility="collapsed",
        )
        user_decisions[key] = choice == "マスクする (推奨)"


def _render_step2_mask_decision_section(
    preview_docs: list[SanitizedDocument],
    masking_states: dict,
) -> None:
    candidates = _iter_uncertain_mask_candidates(masking_states)
    if not candidates:
        st.markdown(
            """
<section class="step2-mask-band safe">
  <div class="step2-mask-title">✓ 要確認の語はありませんでした</div>
  <div class="step2-mask-detail">外部送信前に追加判断が必要な固有名詞候補は検出されていません。</div>
</section>
            """,
            unsafe_allow_html=True,
        )
        return

    doc_text = {doc.name: doc.original_excerpt or "" for doc in preview_docs}
    st.markdown(
        f"""
<section class="step2-mask-band">
  <div class="step2-mask-title">マスクするか判断が必要な語が {len(candidates)} 件あります</div>
  <div class="step2-mask-detail">
    固有名詞っぽい語が検出されました。外部 LLM に送る前に、マスクするか判断してください。
    判断後は「匿名化結果を再生成」で反映します。
  </div>
</section>
        """,
        unsafe_allow_html=True,
    )
    for state, candidate in candidates:
        _render_mask_candidate_decision(state, candidate, doc_text.get(state.name, ""))


def _render_step2_document_details(
    preview_docs: list[SanitizedDocument],
    masking_states: dict,
) -> None:
    st.markdown("#### 文書ごとの詳細")
    st.caption("必要な文書だけ開いて、匿名化後テキスト、置換一覧、検知理由を確認できます。")
    for doc in preview_docs:
        state = (masking_states or {}).get(doc.name)
        candidate_count = len(getattr(state, "uncertain_candidates", ()) or ()) if state else 0
        decision_label = DECISION_LABELS.get(
            doc.local_sensitivity_decision or "unknown",
            doc.local_sensitivity_decision or "unknown",
        )
        subtitle = (
            f"{decision_label} / 置換 {len(doc.replacements)} 件 / "
            f"{doc.estimated_input_tokens} tokens / 候補 {candidate_count} 件"
        )
        with st.expander(f"📄 {doc.name} — {subtitle}", expanded=False):
            st.markdown(
                sr_ui.collapsed_list_row(
                    "📄",
                    doc.name,
                    f"外部送信リスク: {doc.outbound_risk} / {subtitle}",
                ),
                unsafe_allow_html=True,
            )
            if doc.local_sensitivity_reasons:
                st.markdown("**判定理由**")
                for reason in doc.local_sensitivity_reasons:
                    st.markdown(f"- {reason}")
            if doc.findings:
                with st.expander(f"匿名化検知内容 ({len(doc.findings)} 件)", expanded=False):
                    for finding in doc.findings:
                        st.markdown(f"- {finding}")
            if state and getattr(state, "confirmed_findings", None):
                with st.expander(f"自動マスク済み ({len(state.confirmed_findings)} 件)", expanded=False):
                    for value, label in state.confirmed_findings:
                        st.markdown(f"- `{value}` → カテゴリ: **{label}**")
            _render_source_format_diagnostics(doc)
            tabs = st.tabs(["LLM送信対象テキスト", "匿名化後の抜粋", "置換一覧"])
            digest = hashlib.sha256(
                f"{doc.name}|{doc.outbound_text}|{doc.sanitized_excerpt}".encode("utf-8")
            ).hexdigest()[:12]
            with tabs[0]:
                st.text_area(
                    "LLM送信対象テキスト",
                    value=doc.outbound_text or "(空)",
                    height=220,
                    disabled=True,
                    key=f"step2_v2_outbound_text_{digest}",
                    label_visibility="collapsed",
                )
            with tabs[1]:
                st.text_area(
                    "匿名化後の抜粋",
                    value=doc.sanitized_excerpt or "(空)",
                    height=180,
                    disabled=True,
                    key=f"step2_v2_sanitized_excerpt_{digest}",
                    label_visibility="collapsed",
                )
            with tabs[2]:
                if doc.replacements:
                    rows = [
                        {"プレースホルダ": r.placeholder, "カテゴリ": r.category, "原文": r.original}
                        for r in doc.replacements
                    ]
                    st.dataframe(rows, width="stretch", hide_index=True)
                else:
                    st.caption("置換は記録されませんでした。")


def _regenerate_anonymization_from_mask_decisions(
    preview_docs: list[SanitizedDocument],
    masking_states: dict,
) -> None:
    decisions_all = st.session_state.get("user_decisions", {})
    rebuilt: list[SanitizedDocument] = []
    resolved_states: dict[str, MaskingPipelineState] = {}
    for doc in preview_docs:
        state = (masking_states or {}).get(doc.name)
        if state is None:
            rebuilt.append(doc)
            continue
        doc_decisions: dict[str, bool] = {}
        for candidate in state.uncertain_candidates:
            key = _decision_key(doc.name, candidate.text)
            doc_decisions[candidate.text] = decisions_all.get(key, True)
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
            resolved_states[doc.name] = MaskingPipelineState(
                name=state.name,
                sanitized=new_doc,
                confirmed_findings=list(state.confirmed_findings)
                + [
                    (candidate.text, candidate.label)
                    for candidate in state.uncertain_candidates
                    if doc_decisions.get(candidate.text, True)
                ],
                uncertain_candidates=[],
                lookups=dict(state.lookups),
            )
        except Exception as exc:  # noqa: BLE001
            st.warning(
                f"R-M apply_user_decisions (文書 {doc.name}) で警告: "
                f"{type(exc).__name__}: {exc}。元の sanitize 結果を使います。"
            )
            rebuilt.append(doc)
            resolved_states[doc.name] = state

    st.session_state.preview_docs = rebuilt
    if resolved_states:
        st.session_state.masking_states = {
            **(st.session_state.get("masking_states", {}) or {}),
            **resolved_states,
        }
    for key in (
        "review_result",
        "structure_result",
        "remediation_plan",
        "deep_dive_results",
        "chapter_deep_dive_results",
        "deep_dive_notice",
        "send_approval",
        "chapter_sections_cache",
    ):
        st.session_state.pop(key, None)
    st.session_state.anonymization_details_visible = False
    st.session_state.anonymization_details_expand_once = False
    st.session_state.anonymization_regenerated_message = True


def _render_step2_next_action(
    *,
    masking_states: dict,
    blocked_docs: list[SanitizedDocument],
    can_regenerate_anonymization: bool,
) -> bool:
    candidate_total, decided_count = _mask_decision_progress(masking_states)
    disabled = bool(blocked_docs) or candidate_total > 0
    if blocked_docs:
        detail = "送信禁止の文書があります。対象文書を修正するか、再プレビューしてください。"
    elif candidate_total and decided_count < candidate_total:
        detail = (
            f"マスク判断候補が {candidate_total - decided_count} 件あります。"
            "判断後、「匿名化結果を再生成」を押してください。"
        )
    elif candidate_total:
        detail = "判断を反映するため「匿名化結果を再生成」を押してください。"
    else:
        detail = "確認できました。次の Step 3 で最終承認するとレビュー送信できます。"

    st.markdown(
        f"""
<section class="step2-next-action">
  <div class="step2-next-title">次アクション</div>
  <div class="step2-next-detail">{html.escape(detail)}</div>
</section>
        """,
        unsafe_allow_html=True,
    )
    col_ready, col_regen = st.columns([1.35, 1.2])
    with col_ready:
        ready_clicked = st.button(
            "送信準備を完了する",
            type="primary",
            disabled=disabled,
            width="stretch",
            key="step2_ready_button",
            help="Step 2 の確認を終え、Step 3 の最終承認へ進みます。",
        )
        if ready_clicked:
            st.session_state.step2_ready_acknowledged = True
            st.success("Step 2 の確認を記録しました。Step 3 で最終承認してください。")
    with col_regen:
        regen_help = (
            "マスク候補の判断を反映し、匿名化済みテキストを再生成します。"
            if can_regenerate_anonymization
            else "再生成が必要なマスク候補はありません。"
        )
        return st.button(
            "匿名化結果を再生成",
            type="secondary",
            disabled=not can_regenerate_anonymization,
            width="stretch",
            key="step2_regenerate_button",
            help=regen_help,
        )


def _render_step2_v2(
    preview_docs: list[SanitizedDocument],
    *,
    preview_warnings: list[str],
    document_profile_override: str | None,
    masking_states: dict,
    blocked_docs: list[SanitizedDocument],
    can_regenerate_anonymization: bool,
) -> None:
    st.markdown("<div class='step2-v2'>", unsafe_allow_html=True)
    _render_step2_header_and_summary(preview_docs, masking_states)
    _render_artifact_review_mode_notice(preview_docs, document_profile_override)
    if preview_warnings:
        with st.expander(f"抽出・パイプライン警告 ({len(preview_warnings)} 件)", expanded=False):
            for warning in preview_warnings:
                st.markdown(f"- {warning}")

    _render_step2_mask_decision_section(preview_docs, masking_states)
    regenerate_clicked = _render_step2_next_action(
        masking_states=masking_states,
        blocked_docs=blocked_docs,
        can_regenerate_anonymization=can_regenerate_anonymization,
    )
    if regenerate_clicked:
        try:
            _regenerate_anonymization_from_mask_decisions(preview_docs, masking_states)
            st.rerun()
        except Exception:  # noqa: BLE001
            request_id = uuid.uuid4().hex[:8]
            st.error(f"匿名化結果の再生成に失敗しました ({request_id})。")
            with st.expander("詳細トレース"):
                st.code(traceback.format_exc())

    if st.session_state.pop("anonymization_regenerated_message", False):
        st.success("✅ 匿名化結果を再生成しました。下記サマリで確認できます。")

    _render_step2_document_details(preview_docs, masking_states)
    _render_token_budget_panel(preview_docs, document_profile_override)
    previous_plan = st.session_state.get("previous_remediation_plan")
    if st.session_state.get("enable_previous_remediation_review") and previous_plan is not None:
        comparison_report = compare_remediation_plan_to_documents(previous_plan, preview_docs)
        _render_remediation_comparison_report(comparison_report)
    render_session_summary()
    st.markdown("</div>", unsafe_allow_html=True)


def _render_token_budget_panel(
    preview_docs: list[SanitizedDocument],
    document_profile_override: str | None,
) -> None:
    """Render a pre-send estimate of Gemma/Gemini token impact."""
    if not preview_docs:
        return

    try:
        estimate = estimate_review_token_budget(
            preview_docs,
            document_profile_override,
        )
    except Exception as exc:  # noqa: BLE001
        st.warning(f"トークン予算の概算に失敗しました: {exc}")
        return

    status_label = TOKEN_BUDGET_STATUS_LABELS.get(estimate.status, estimate.status)

    with st.expander("🧮 Gemma4送信前トークン予算（概算）", expanded=estimate.status != "safe"):
        metric_cols = st.columns(5)
        metric_cols[0].metric("予定call数", estimate.call_count)
        metric_cols[1].metric("本文推定", f"{estimate.body_tokens:,}")
        metric_cols[2].metric("最大/1call", f"{estimate.max_call_input_tokens:,}")
        metric_cols[3].metric("入力合計", f"{estimate.total_input_tokens:,}")
        metric_cols[4].metric("判定", status_label)

        st.caption(
            "本文推定に加え、システムプロンプト、レビュー指示、Config/OCRサマリ等を含めた概算です。"
            "実際の課金・消費トークンとは完全一致しません。"
        )
        st.caption(
            f"出力上限の設定: {estimate.max_output_tokens_per_call:,} tokens/call "
            f"(最大予約枠の概算: {estimate.estimated_output_token_cap:,})。"
            "深堀ボタンを押すと追加callが発生します。"
        )
        if estimate.minimum_wait_seconds > 0:
            st.caption(
                "Free tier のレート制限対策として、API呼び出し間隔を "
                f"{estimate.throttle_interval_seconds:g}秒/回にしています。"
                f"待機合計は {_format_duration(estimate.minimum_wait_seconds)} ですが、"
                "これは応答時間ではありません。実際には各callのLLM処理時間がさらに加わります。"
            )

        for reason in estimate.reasons:
            if estimate.status == "split_recommended":
                st.warning(reason)
            elif estimate.status == "caution":
                st.info(reason)
            else:
                st.success(reason)

        if estimate.status in {"caution", "split_recommended"}:
            st.markdown(
                "- 普段使いの長い手順書では、章単位に分ける、別紙ログを外す、"
                "画像OCR結果を確認して不要行を削る、といった運用を推奨します。"
            )
        _render_token_budget_details(estimate)


def _format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} 秒"
    minutes, rest = divmod(seconds, 60)
    if rest == 0:
        return f"{minutes} 分"
    return f"{minutes} 分 {rest} 秒"


def _md_cell(value: object) -> str:
    return str(value).replace("|", "｜").replace("\n", " ")


def _render_token_budget_details(estimate) -> None:
    if not getattr(estimate, "document_estimates", ()):
        return

    document_estimates = sorted(
        estimate.document_estimates,
        key=lambda item: item.call_input_tokens,
        reverse=True,
    )
    rows = [
        "| 文書 | 本文tokens | 1call入力概算 |",
        "|---|---:|---:|",
    ]
    for item in document_estimates[:8]:
        rows.append(
            f"| {_md_cell(item.name)} | {item.body_tokens:,} | {item.call_input_tokens:,} |"
        )
    st.markdown("**文書別の送信規模（大きい順）**")
    st.markdown("\n".join(rows))

    if len(document_estimates) > 8:
        st.caption(f"残り {len(document_estimates) - 8} 件は省略しています。")

    suggested_batches = getattr(estimate, "suggested_batches", ()) or ()
    if suggested_batches:
        st.markdown("**推奨レビュー分割案**")
        for batch in suggested_batches:
            names = "、".join(batch.document_names)
            st.markdown(
                f"- {batch.label}: {batch.call_count} call / "
                f"{batch.total_input_tokens:,} tokens / {names}"
            )
        st.caption(
            "分割案は、1回の評価で扱うファイル数と入力規模を抑えるための目安です。"
            "文書の意味上のまとまりがある場合は、そちらを優先してください。"
        )


def _has_uncertain_candidates_for_doc(masking_states: dict, name: str) -> bool:
    state = (masking_states or {}).get(name)
    if state is None:
        return False
    return bool(getattr(state, "uncertain_candidates", None))


def _requires_manual_confirmation_for_doc(
    doc: SanitizedDocument,
    masking_states: dict,
) -> bool:
    decision = doc.local_sensitivity_decision or "unknown"
    if decision == "block":
        return False
    return (
        decision in {"mask_and_continue", "unknown"}
        or decision not in {"safe", "mask_and_continue", "block", "unknown"}
        or _has_uncertain_candidates_for_doc(masking_states, doc.name)
    )


def _render_insight_panel(
    *,
    kicker: str,
    title: str,
    detail: str,
    metrics: list[dict[str, object]],
    tone: str = "info",
) -> None:
    """Render a compact dashboard card without relying on Streamlit metric chrome."""
    metric_html = []
    for metric in metrics:
        metric_tone = str(metric.get("tone") or "info")
        note = str(metric.get("note") or "")
        note_html = f"<div class='insight-note'>{html.escape(note)}</div>" if note else ""
        metric_html.append(
            "<div class='insight-metric {tone}'>"
            "<div class='insight-label'>{label}</div>"
            "<div class='insight-value'>{value}</div>"
            "{note}"
            "</div>".format(
                tone=html.escape(metric_tone),
                label=html.escape(str(metric.get("label") or "")),
                value=html.escape(str(metric.get("value") or "")),
                note=note_html,
            )
        )
    st.markdown(
        f"""
<section class="insight-panel {html.escape(tone)}">
  <div class="insight-header">
    <div>
      <div class="insight-kicker">{html.escape(kicker)}</div>
      <div class="insight-title">{html.escape(title)}</div>
    </div>
    <div class="insight-detail">{html.escape(detail)}</div>
  </div>
  <div class="insight-grid">{''.join(metric_html)}</div>
</section>
""",
        unsafe_allow_html=True,
    )


def _render_step_header(step: int, title: str, description: str) -> None:
    st.markdown(
        f"""
<div class="step-header">
  <section class="step-banner">
    <div class="step-index">{step}</div>
    <div class="step-copy">
      <div class="step-kicker">Step {step}</div>
      <div class="step-title">{html.escape(title)}</div>
      <div class="step-desc">{html.escape(description)}</div>
    </div>
  </section>
</div>
        """,
        unsafe_allow_html=True,
    )


def _scroll_height_control(
    label: str,
    *,
    key: str,
    default: int,
    min_value: int = 320,
    max_value: int = 1000,
) -> int:
    st.markdown(
        f"<div class='height-control'>{html.escape(label)}を調整できます。</div>",
        unsafe_allow_html=True,
    )
    return st.slider(
        label,
        min_value=min_value,
        max_value=max_value,
        value=int(st.session_state.get(key, default)),
        step=40,
        key=key,
        label_visibility="collapsed",
    )


def _has_regeneratable_mask_candidates(masking_states: dict) -> bool:
    """Return True when the regenerate button can actually change output."""
    for state in (masking_states or {}).values():
        confirmed = getattr(state, "confirmed_findings", None) or []
        uncertain = getattr(state, "uncertain_candidates", None) or []
        if confirmed or uncertain:
            return True
    return False


def _extract_excel_workbook_diagnostics(text: str) -> str:
    marker = "# Excelブック診断"
    start = (text or "").find(marker)
    if start < 0:
        return ""
    rest = text[start:]
    next_sheet = rest.find("\n# Sheet:")
    if next_sheet >= 0:
        rest = rest[:next_sheet]
    return rest.strip()


def _render_source_format_diagnostics(doc: SanitizedDocument) -> None:
    excel_diagnostics = _extract_excel_workbook_diagnostics(doc.outbound_text or "")
    if not excel_diagnostics:
        return

    with st.expander("📊 Excelブック診断（ローカル抽出）", expanded=False):
        st.caption(
            "シート構成、非表示シート、数式、リンク、結合セルなどをローカルで抽出した補助情報です。"
            "この内容も匿名化・機密度判定の対象になります。"
        )
        st.markdown(excel_diagnostics)


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


def _chapter_cache_key(doc_name: str, chapter: ChapterSection) -> str:
    digest = hashlib.sha256(f"{doc_name}|{chapter.chapter_id}".encode("utf-8")).hexdigest()
    return digest[:16]


def _issue_text(issue) -> str:
    fields = (
        "section",
        "title",
        "current_state",
        "issue",
        "impact",
        "details",
        "recommendation",
    )
    return " ".join(str(getattr(issue, field, "") or "") for field in fields)


def _infer_issue_chapter(issue, chapters: tuple) -> str:
    if not chapters:
        return str(getattr(issue, "section", "") or "").strip()

    explicit = str(getattr(issue, "section", "") or "").strip()
    if explicit:
        return explicit

    text = _issue_text(issue)
    match = re.search(r"第\s*([0-9０-９]+)\s*章", text)
    if match:
        number = match.group(1).translate(str.maketrans("０１２３４５６７８９", "0123456789"))
        for chapter in chapters:
            if re.search(rf"第\s*{re.escape(number)}\s*章", chapter.chapter_label):
                return chapter.chapter_label
        return f"第 {number} 章"

    tokens = set(
        token
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9:/._+-]{1,}|[一-龥ァ-ンー]{3,}", text)
        if len(token) >= 3
    )
    best_label = ""
    best_score = 0
    for chapter in chapters:
        haystack = f"{chapter.chapter_label}\n{chapter.extracted_text}"
        score = sum(1 for token in tokens if token in haystack)
        if score > best_score:
            best_score = score
            best_label = chapter.chapter_label
    return best_label if best_score >= 2 else ""


def _render_document_structure_check(result: StructureCheckResult) -> None:
    st.markdown("### 文書構成チェック")
    st.caption(
        "設計書に通常必要とされる観点が、今回アップロードされた文書群に含まれているかを確認します。"
        "不足している観点は、レビュー結果の前提として先に確認してください。"
    )

    findings = list(result.findings or ())
    high_findings = [f for f in findings if f.severity == "high"]
    medium_findings = [f for f in findings if f.severity == "medium"]
    missing_chapters = [f for f in findings if f.kind == "missing_chapter"]
    item_gaps = [f for f in findings if f.kind == "required_item_gap"]
    organization_suggestions = [
        f
        for f in findings
        if f.kind in {"chapter_structure_missing", "structure_template_suggestion", "structure_organization_suggestion"}
    ]

    if high_findings:
        structure_tone = "block"
        structure_title = "重要な構成不足があります"
        structure_detail = "レビュー本文に入る前に、欠けている観点や必須要素を確認してください。"
    elif medium_findings or organization_suggestions:
        structure_tone = "warn"
        structure_title = "構成上の確認点があります"
        structure_detail = "記述はあるものの、見出し・章・粒度を整理するとレビューしやすくなります。"
    else:
        structure_tone = "safe"
        structure_title = "構成観点は概ね整っています"
        structure_detail = "今回の構成チェックでは、標準観点に対する明確な不足は検出されていません。"

    _render_insight_panel(
        kicker="Structure Check",
        title=structure_title,
        detail=structure_detail,
        tone=structure_tone,
        metrics=[
            {"label": "対象文書", "value": result.document_count, "tone": "info", "note": "一括レビュー対象"},
            {"label": "検出章", "value": result.detected_chapter_count, "tone": "info", "note": "章・見出しの抽出数"},
            {"label": "重要不足", "value": len(high_findings), "tone": "block" if high_findings else "safe", "note": "先に確認する不足"},
            {"label": "要確認", "value": len(medium_findings), "tone": "warn" if medium_findings else "safe", "note": "補足確認が必要"},
            {"label": "不足観点", "value": len(missing_chapters), "tone": "block" if missing_chapters else "safe", "note": "記述が見当たらない"},
            {"label": "必須要素不足", "value": len(item_gaps), "tone": "block" if item_gaps else "safe", "note": "中身が足りない"},
            {"label": "整理提案", "value": len(organization_suggestions), "tone": "warn" if organization_suggestions else "safe", "note": "章立て・粒度の改善"},
        ],
    )

    if not findings:
        st.success("標準構成上の明確な不足観点・必須要素不足・構成整理提案は検出されませんでした。")
        return

    st.warning(
        "文書の構成で確認したい点があります。"
        "「不足観点」は該当する記述が見当たらないもの、"
        "「必須要素不足」は記述はあるものの中身が足りないもの、"
        "「構成整理の提案」は記述はあるものの見出し・章・粒度を整理した方がよいものです。"
        "章概要レビューは各章本文の概要評価であり、ここでは文書全体の管理項目も含めて確認します。"
    )

    severity_order = {"high": 0, "medium": 1, "info": 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            severity_order.get(f.severity, 9),
            _chapter_sort_value(f.chapter_id),
            f.kind,
            _item_sort_value(f.item_id),
        ),
    )
    _structure_height = (
        _scroll_height_control(
            "文書構成チェックの表示高さ",
            key="structure_check_scroll_height",
            default=360,
            min_value=280,
            max_value=760,
        )
        if len(sorted_findings) >= 6 else None
    )
    container = (
        st.container(height=_structure_height)
        if _structure_height is not None else st.container()
    )
    with container:
        for finding in sorted_findings:
            severity_label = {
                "high": "重要不足",
                "medium": "要確認",
                "info": "情報",
            }.get(finding.severity, finding.severity)
            source = (
                f"<div class='doc-meta'>対象: {html.escape(finding.source_document)}</div>"
                if finding.source_document else ""
            )
            expected = (
                f"<div style='margin-top:0.25rem;color:#4a5549;'>"
                f"<b>本来必要な内容:</b> {html.escape(finding.expected_content)}</div>"
                if finding.expected_content else ""
            )
            fix_guide = structure_fix_guidance(
                finding.kind,
                item_name=finding.item_name,
                chapter_name=finding.chapter_name,
            )
            fix_guide_html = (
                f"<div class='fix-guide'><b>直し方:</b> "
                f"{html.escape(fix_guide)}</div>"
            )
            title_parts = [severity_label]
            if finding.kind == "structure_template_suggestion":
                title_parts.append("章立てテンプレート案")
            elif finding.kind in {"chapter_structure_missing", "structure_organization_suggestion"}:
                title_parts.append("構成整理の提案")
                if finding.chapter_name:
                    title_parts.append(f"対象観点: {finding.chapter_name}")
            elif finding.kind == "required_item_gap":
                title_parts.append(f"必須要素不足: {finding.item_name or '未指定'}")
                if finding.chapter_name:
                    title_parts.append(f"確認範囲: {finding.chapter_name}")
            elif finding.chapter_name:
                title_parts.append(f"不足観点: {finding.chapter_name}")
            if finding.item_name and finding.kind != "required_item_gap":
                title_parts.append(f"必須要素: {finding.item_name}")
            title = " · ".join(title_parts)
            suggested = ""
            if finding.suggested_content:
                suggested = (
                    "<div style='margin-top:0.35rem;color:#4a5549;'>"
                    "<b>見出し例:</b></div>"
                    "<pre class='sanitized' style='max-height:260px;'>"
                    f"{html.escape(finding.suggested_content)}"
                    "</pre>"
                )
            st.markdown(
                f"<div class='structure-check-card {finding.severity}'>"
                f"<b>{html.escape(title)}</b><br/>"
                f"{html.escape(finding.message)}"
                f"{source}"
                f"{expected}"
                f"{fix_guide_html}"
                f"{suggested}"
                f"</div>",
                unsafe_allow_html=True,
            )

    if item_gaps:
        st.caption(
            "章内必須要素不足はキーワード検出による一次判定です。"
            "表現ゆれで検出できない場合があるため、最終判断では本文も確認してください。"
        )


def _structure_findings_for_chapter(
    result: StructureCheckResult | None,
    doc_name: str,
    chapter: ChapterSection,
) -> list:
    if result is None:
        return []
    findings = []
    for finding in result.findings or ():
        if finding.severity not in {"high", "medium"}:
            continue
        if finding.source_document and finding.source_document != doc_name:
            continue
        if finding.chapter_id != chapter.chapter_id:
            continue
        findings.append(finding)
    return findings


def _chapter_sort_value(chapter_id: str) -> int:
    match = re.search(r"\d+", chapter_id or "")
    return int(match.group(0)) if match else 999


def _item_sort_value(item_id: str) -> tuple[int, int]:
    match = re.match(r"(\d+)(?:\.(\d+))?", item_id or "")
    if not match:
        return (999, 999)
    return (int(match.group(1)), int(match.group(2) or 0))


def _render_compact_field(label: str, value: str) -> None:
    if not value:
        return
    st.markdown(
        f"<div class='review-compact'><b>{html.escape(label)}</b>: "
        f"{html.escape(str(value))}</div>",
        unsafe_allow_html=True,
    )


def _render_review_issue(issue, severity_order: dict[str, int]) -> None:
    severity_jp = SEVERITY_LABELS.get(issue.severity, issue.severity)
    if issue.has_structured_fields():
        id_prefix = f"<b>{issue.issue_id}</b> · " if issue.issue_id else ""
        section_suffix = f' · 章: {issue.section}' if issue.section else ''
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
        if not (issue.current_state or issue.issue or issue.impact) and issue.details:
            body_parts.append(
                f"<div style='margin-top:0.3rem;'>{issue.details}</div>"
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
        st.markdown(
            f"<div class='issue-row {issue.severity}'>"
            f"<b>[{severity_jp}]</b> {issue.title}<br/>"
            f"<div style='margin-top:0.3rem;'>{issue.details}</div>"
            f"<div style='margin-top:0.3rem;color:#4a5549;font-size:0.88rem;'>"
            f"<b>推奨対応:</b> {issue.recommendation}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )


def _tag_review_issues(review: ReviewResult, origin: str) -> ReviewResult:
    for issue in getattr(review, "issues", []) or []:
        issue.origin = origin
    return review


def _iter_review_results(value):
    if not value:
        return
    if isinstance(value, dict):
        iterable = value.values()
    elif isinstance(value, (list, tuple)):
        iterable = value
    else:
        iterable = (value,)
    for entry in iterable:
        if isinstance(entry, (list, tuple)):
            for nested in _iter_review_results(entry):
                yield nested
        elif isinstance(entry, ReviewResult):
            yield entry


def _iter_session_deep_dive_reviews():
    for deep_review in _iter_review_results(st.session_state.get("deep_dive_results")):
        yield "document_deep_dive", deep_review
    for deep_review in _iter_review_results(st.session_state.get("chapter_deep_dive_results")):
        yield "chapter_deep_dive", deep_review


def _review_with_deep_dive_issues(review: ReviewResult) -> ReviewResult:
    combined_issues = list(getattr(review, "issues", []) or [])
    for origin, deep_review in _iter_session_deep_dive_reviews():
        _tag_review_issues(deep_review, origin)
        combined_issues.extend(getattr(deep_review, "issues", []) or [])
    return replace(review, issues=combined_issues)


def _rebuild_remediation_plan_for_session(
    review: ReviewResult,
    structure_result: StructureCheckResult | None = None,
) -> RemediationPlan:
    plan = build_remediation_plan(
        _review_with_deep_dive_issues(review),
        structure_result,
    )
    st.session_state["remediation_plan"] = plan
    return plan


def _count_review_issues(review_results: list[ReviewResult]) -> int:
    return sum(len(getattr(result, "issues", []) or []) for result in review_results)


def _run_chapter_deep_dive(
    doc_name: str,
    chapter: ChapterSection,
    review,
    document_profile_override: str | None,
) -> None:
    cache_key = _chapter_cache_key(doc_name, chapter)
    chapter_cache = st.session_state.setdefault("chapter_deep_dive_results", {})
    previous_results = chapter_cache.get(cache_key, [])
    if len(previous_results) >= MAX_CHAPTER_DEEP_DIVE_PASSES:
        st.session_state.deep_dive_notice = (
            f"{chapter.chapter_label} は既に {MAX_CHAPTER_DEEP_DIVE_PASSES} 回の深堀りを完了しています。"
            "これ以上は新規観点が重複しやすいため、既存結果の確認を優先してください。"
        )
        st.rerun()
        return

    preview_docs = st.session_state.get("preview_docs") or []
    if not preview_docs:
        st.error("preview_docs が見つかりません。ステップ 1〜3 を再実行してください。")
        return
    try:
        provider_impl = choose_provider()
        provider_label = provider_display_name(
            provider_impl.name,
            getattr(provider_impl, "model", ""),
        )
        if provider_impl.name == "mock":
            st.warning(
                "⚠️ mock プロバイダでは章単位深堀りも実質通常レビューと同じです。"
            )
        _enforce_outbound_guard(provider_impl.name, preview_docs)
        with st.spinner(
            f"{provider_label} で「{chapter.chapter_label}」を深堀レビュー中..."
        ):
            previous_issues = [
                issue
                for result in previous_results
                for issue in getattr(result, "issues", []) or []
            ]
            deep_review = provider_impl.review(
                preview_docs,
                document_profile_override,
                deep_dive_target=doc_name,
                existing_issues=[*review.issues, *previous_issues],
                chapter=chapter,
            )
            _tag_review_issues(deep_review, "chapter_deep_dive")
        chapter_cache.setdefault(cache_key, []).append(deep_review)
        st.session_state.chapter_deep_dive_results = chapter_cache
        _rebuild_remediation_plan_for_session(
            review,
            st.session_state.get("structure_result"),
        )
        st.session_state.deep_dive_notice = (
            f"{chapter.chapter_label} の深堀りレビューを記録しました。"
        )
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


def _collect_deep_dive_candidates(
    review,
    preview_docs: list[SanitizedDocument],
    structure_result: StructureCheckResult | None,
) -> list[tuple[str, ChapterSection, str]]:
    """Collect chapter candidates that deserve attention before users scroll."""
    candidates: list[tuple[str, ChapterSection, str]] = []
    if "chapter_sections_cache" not in st.session_state:
        st.session_state.chapter_sections_cache = {}
    cache = st.session_state.chapter_sections_cache
    for doc in preview_docs:
        if doc.name not in cache:
            cache[doc.name] = extract_chapters_from_text(doc.outbound_text)
        chapters = cache.get(doc.name) or ()
        for chapter in chapters:
            overview = _find_chapter_overview(review, doc.name, chapter)
            structure_findings = _structure_findings_for_chapter(
                structure_result,
                doc.name,
                chapter,
            )
            if bool(getattr(overview, "needs_deep_dive", False)):
                reason = getattr(overview, "review", "") or "概要レビューで深堀候補と判定されました。"
                candidates.append((doc.name, chapter, reason))
            elif structure_findings:
                candidates.append(
                    (
                        doc.name,
                        chapter,
                        f"文書構成チェックで {len(structure_findings)} 件の追加確認点があります。",
                    )
                )
    return candidates


def _chapters_for_document(doc: SanitizedDocument) -> tuple[ChapterSection, ...]:
    """Return cached chapter sections for a sanitized document."""
    if "chapter_sections_cache" not in st.session_state:
        st.session_state.chapter_sections_cache = {}
    cache = st.session_state.chapter_sections_cache
    if doc.name not in cache:
        cache[doc.name] = extract_chapters_from_text(doc.outbound_text)
    return tuple(cache.get(doc.name) or ())


def _chapter_needs_deep_dive(
    review,
    doc_name: str,
    chapter: ChapterSection,
    structure_result: StructureCheckResult | None,
) -> tuple[bool, str]:
    overview = _find_chapter_overview(review, doc_name, chapter)
    if bool(getattr(overview, "needs_deep_dive", False)):
        reason = getattr(overview, "review", "") or "概要レビューで深堀候補と判定されました。"
        return True, reason
    structure_findings = _structure_findings_for_chapter(
        structure_result,
        doc_name,
        chapter,
    )
    if structure_findings:
        return (
            True,
            f"文書構成チェックで {len(structure_findings)} 件の追加確認点があります。",
        )
    return False, "概要レビューでは深堀候補としては扱っていません。"


def _remediation_origin_badge_html(origin: str) -> str:
    badge = remediation_origin_badge(origin)
    if badge is None:
        return ""
    label, css_class = badge
    return (
        "<div class='origin-badge-row'>"
        f"<span class='origin-badge {html.escape(css_class)}'>"
        f"{html.escape(label)}</span>"
        "</div>"
    )


def _step4_document_label(preview_docs: list[SanitizedDocument]) -> str:
    if not preview_docs:
        return "対象文書なし"
    if len(preview_docs) == 1:
        return preview_docs[0].name
    return f"{len(preview_docs)} 文書"


def _step4_review_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _step4_future_hint_count(report: FutureReviewReport | None) -> int:
    if report is None:
        return 0
    return (
        getattr(report, "ambiguous_count", 0)
        + len(getattr(report, "reader_risks", ()) or ())
        + len(getattr(report, "premortem_scenarios", ()) or ())
    )


def _step4_structure_finding_count(result: StructureCheckResult | None) -> int:
    if result is None:
        return 0
    return len(getattr(result, "findings", ()) or ())


def _step4_severity_counts(plan: RemediationPlan) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "neutral": 0}
    for item in plan.items:
        key = item.severity if item.severity in counts else "neutral"
        counts[key] += 1
    return counts


def _step4_overall_comment(review: ReviewResult) -> str:
    summary_structured = getattr(review, "summary_structured", None)
    if summary_structured and not summary_structured.is_empty():
        for value in (
            getattr(summary_structured, "overall_evaluation", ""),
            getattr(summary_structured, "content_outline", ""),
            getattr(summary_structured, "purpose", ""),
        ):
            value = (value or "").strip()
            if value:
                return value[:260] + ("..." if len(value) > 260 else "")
    summary = (getattr(review, "summary", "") or "").strip()
    return summary[:260] + ("..." if len(summary) > 260 else "")


def _step4_effort_rank(effort: str) -> int:
    return {"large": 0, "medium": 1, "small": 2}.get((effort or "").lower(), 3)


_STEP4_ISSUE_DEFAULT_LIMIT = 12


def _sorted_step4_items(plan: RemediationPlan) -> list:
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(
        plan.items,
        key=lambda item: (
            severity_rank.get(item.severity, 4),
            _step4_effort_rank(item.effort),
            item.item_id,
        ),
    )


def _shorten_step4_label(value: str, limit: int = 34) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)] + "…"


def _step4_severity_label(severity: str) -> str:
    return {
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "参考",
    }.get((severity or "").lower(), "確認")


def _step4_issue_list_label(item, index: int, *, show_document: bool) -> str:
    parts = [
        f"指摘 {index:02d}",
        _step4_severity_label(item.severity),
    ]
    if show_document:
        parts.append(_shorten_step4_label(item.target_document or "対象文書", 28))
    parts.extend(
        [
            _shorten_step4_label(item.target_section or "該当箇所", 24),
            _shorten_step4_label(item.title or "レビュー指摘", 46),
        ]
    )
    return " · ".join(part for part in parts if part)


def _filter_step4_items_by_document(items: list) -> tuple[list, bool]:
    document_counts = Counter((item.target_document or "対象文書") for item in items)
    if len(document_counts) <= 1:
        return items, False
    options = ["__all__"] + sorted(document_counts)

    def _format_option(value: str) -> str:
        if value == "__all__":
            return f"すべての文書（{len(items)} 件）"
        return f"{_shorten_step4_label(value, 42)}（{document_counts[value]} 件）"

    selected = st.selectbox(
        "対象文書で絞り込み",
        options=options,
        format_func=_format_option,
        key="step4_issue_document_filter",
        help="複数ファイルを一括レビューした場合は、文書ごとに指摘を絞り込めます。",
    )
    if selected == "__all__":
        return items, True
    return [item for item in items if (item.target_document or "対象文書") == selected], False


def _extract_template_section(template: str, label: str) -> str:
    if not template:
        return ""
    pattern = re.compile(
        rf"-\s*{re.escape(label)}[:：]\s*(.*?)(?=\n-\s*[^:\n]+[:：]|\Z)",
        re.DOTALL,
    )
    match = pattern.search(template)
    if not match:
        return ""
    value = match.group(1).strip()
    value = re.sub(r"^\s*-\s*", "", value, flags=re.MULTILINE).strip()
    return value


def _step4_item_fields(item) -> dict[str, str]:
    return {
        "現状": getattr(item, "current_state", "") or _extract_template_section(item.template, "現状"),
        "問題点": item.problem,
        "修正方針": item.fix_policy,
        "影響と判断基準": getattr(item, "impact", "") or _extract_template_section(item.template, "影響と判断基準"),
        "完了条件": getattr(item, "completion_condition", "") or _extract_template_section(item.template, "完了条件"),
        "再レビュー条件": item.re_review_condition,
    }


def _normalize_chapter_match_text(value: str) -> str:
    return re.sub(r"[\s　_\-・:：/／()（）\[\]【】]+", "", (value or "").lower())


def _find_chapter_for_remediation_item(
    item,
    preview_docs: list[SanitizedDocument],
) -> tuple[str, ChapterSection] | None:
    joined_for_match = " ".join(
        str(part or "")
        for part in (
            item.target_section,
            item.title,
            item.problem,
            item.fix_policy,
            item.re_review_scope,
        )
    )
    candidate_text = _normalize_chapter_match_text(joined_for_match)
    chapter_number_match = re.search(r"第\s*(\d+)\s*章", joined_for_match)
    document_candidates = [
        doc
        for doc in preview_docs
        if item.target_document and item.target_document in doc.name
    ] or list(preview_docs)
    for doc in document_candidates:
        for chapter in _chapters_for_document(doc):
            chapter_text = _normalize_chapter_match_text(
                f"{chapter.chapter_id} {chapter.chapter_label}"
            )
            if chapter_text and chapter_text in candidate_text:
                return doc.name, chapter
            if chapter_number_match and chapter_number_match.group(1) in chapter.chapter_label:
                return doc.name, chapter
            if chapter.chapter_id and _normalize_chapter_match_text(chapter.chapter_id) in candidate_text:
                return doc.name, chapter
    return None


def _render_step4_status_and_summary(
    review: ReviewResult,
    preview_docs: list[SanitizedDocument],
    remediation_plan: RemediationPlan,
    structure_result: StructureCheckResult | None,
    future_report: FutureReviewReport | None,
) -> None:
    issue_count = len(remediation_plan.items)
    lead = (
        "この文書には対応が必要な指摘があります"
        if issue_count
        else "対応が必要な指摘はありませんでした"
    )
    st.markdown(
        sr_ui.status_bar(
            f"レビュー完了 · {_step4_review_timestamp()}",
            _step4_document_label(preview_docs),
            "✓",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        sr_ui.big_number_summary(issue_count, "件の指摘", lead),
        unsafe_allow_html=True,
    )
    overall_comment = _step4_overall_comment(review)
    if overall_comment:
        st.markdown(
            f"<div class='step4-summary-note'>{html.escape(overall_comment)}</div>",
            unsafe_allow_html=True,
        )
    counts = _step4_severity_counts(remediation_plan)
    chips = []
    if counts.get("high"):
        chips.append(sr_ui.severity_chip("high", counts["high"]))
    if counts.get("medium"):
        chips.append(sr_ui.severity_chip("medium", counts["medium"]))
    if chips:
        st.markdown(
            "<div class='step4-chip-row'>" + "".join(chips) + "</div>",
            unsafe_allow_html=True,
        )


def _render_step4_field_grid(fields: dict[str, str]) -> None:
    html_fields = []
    for label, value in fields.items():
        if not value:
            value = "該当情報はまだ明確ではありません。修正文書で補足してください。"
        html_fields.append(
            "<div class='step4-field'>"
            f"<div class='step4-field-label'>{html.escape(label)}</div>"
            f"<div class='step4-field-value'>{html.escape(str(value))}</div>"
            "</div>"
        )
    st.markdown(
        "<div class='step4-field-grid'>" + "".join(html_fields) + "</div>",
        unsafe_allow_html=True,
    )


def _step4_item_source_label(item) -> str:
    if item.source_type == "structure_check":
        return "文書構成チェック由来"
    if item.origin == "document_deep_dive":
        return "文書深堀で追加"
    if item.origin == "chapter_deep_dive":
        return "章深堀で追加"
    return "初回レビュー由来"


def _render_step4_item_context(item) -> None:
    target_document = item.target_document or "対象文書"
    target_section = item.target_section or "該当箇所"
    source_label = _step4_item_source_label(item)
    st.markdown(
        "<div class='step4-item-context'>"
        f"<span class='step4-context-pill'>📄 <b>対象文書</b>{html.escape(target_document)}</span>"
        f"<span class='step4-context-pill'>§ <b>対象箇所</b>{html.escape(target_section)}</span>"
        f"<span class='step4-context-pill'>↳ <b>出どころ</b>{html.escape(source_label)}</span>"
        "</div>",
        unsafe_allow_html=True,
    )


def _render_step4_issue_card(
    item,
    *,
    index: int,
    expanded: bool,
    review: ReviewResult,
    preview_docs: list[SanitizedDocument],
    document_profile_override: str | None,
    show_document_in_label: bool = False,
    show_document_draft: bool = True,
) -> None:
    label = _step4_issue_list_label(item, index, show_document=show_document_in_label)
    with st.expander(label, expanded=expanded):
        matched_chapter = _find_chapter_for_remediation_item(item, preview_docs)
        header_col, action_col = st.columns([5, 1.35])
        with header_col:
            st.markdown(
                sr_ui.issue_card_header(
                    item.severity,
                    item.effort,
                    item.item_id,
                    item.target_section,
                    item.title,
                ),
                unsafe_allow_html=True,
            )
            origin_badge = _remediation_origin_badge_html(item.origin)
            if origin_badge:
                st.markdown(origin_badge, unsafe_allow_html=True)
            _render_step4_item_context(item)
        with action_col:
            if matched_chapter is not None:
                doc_name, chapter = matched_chapter
                button_key = (
                    "step4_issue_deepdive_"
                    + hashlib.sha256(
                        f"{item.item_id}|{doc_name}|{chapter.chapter_id}".encode("utf-8")
                    ).hexdigest()[:12]
                )
                if st.button("🔬 章を再分析", key=button_key, width="stretch"):
                    _run_chapter_deep_dive(
                        doc_name,
                        chapter,
                        review,
                        document_profile_override,
                    )
        st.markdown("<div class='step4-card-body'>", unsafe_allow_html=True)
        _render_step4_field_grid(_step4_item_fields(item))
        st.markdown("</div>", unsafe_allow_html=True)
        if show_document_draft:
            copy_key = f"step4_template_copy_{index}_{item.item_id}"
            if st.button("文書追記案をコピー", key=copy_key):
                st.info("下のコードブロック右上のコピー操作で、文書へ転記する本文案をコピーできます。")
            st.code(item.template, language="markdown")


def _render_step4_issue_cards(
    plan: RemediationPlan,
    review: ReviewResult,
    preview_docs: list[SanitizedDocument],
    document_profile_override: str | None,
) -> None:
    left, right = st.columns([4, 1.55])
    with left:
        st.markdown(
            "<div class='step4-section-title'>対応すべき指摘</div>"
            "<div class='step4-section-caption'>重要度の高いものから、担当者・追記内容・再レビュー条件を確認します。</div>",
            unsafe_allow_html=True,
        )
    with right:
        st.download_button(
            "📒 修正計画 JSON",
            data=json.dumps(plan.to_dict(), ensure_ascii=False, indent=2),
            file_name=remediation_plan_json_filename(),
            mime="application/json",
            type="primary",
            width="stretch",
            help="次回、修正後の文書と一緒に読み込ませると、前回指摘の解消状況を照合できます。",
        )
    items = _sorted_step4_items(plan)
    if not items:
        st.success("対応が必要な修正計画カードはありません。")
        return
    show_document_draft = not _is_code_analysis_review(preview_docs, document_profile_override)
    items, showing_all_documents = _filter_step4_items_by_document(items)
    if not items:
        st.info("選択した文書に対応すべき指摘はありません。")
        return
    show_all_key = "step4_show_all_issue_cards"
    show_all = bool(st.session_state.get(show_all_key, False))
    if len(items) > _STEP4_ISSUE_DEFAULT_LIMIT and not show_all:
        display_items = items[:_STEP4_ISSUE_DEFAULT_LIMIT]
        remaining = len(items) - _STEP4_ISSUE_DEFAULT_LIMIT
        st.caption(
            f"全 {len(items)} 件中、重要度順に上位 {_STEP4_ISSUE_DEFAULT_LIMIT} 件を表示しています。"
            "必要に応じて対象文書で絞り込むか、すべて表示してください。"
        )
    else:
        display_items = items
        remaining = 0
        if len(items) > _STEP4_ISSUE_DEFAULT_LIMIT:
            st.caption(f"全 {len(items)} 件を表示中です。")
    first_high_opened = False
    for index, item in enumerate(display_items, 1):
        expanded = False
        if item.severity == "high" and not first_high_opened:
            expanded = True
            first_high_opened = True
        _render_step4_issue_card(
            item,
            index=index,
            expanded=expanded,
            review=review,
            preview_docs=preview_docs,
            document_profile_override=document_profile_override,
            show_document_in_label=showing_all_documents,
            show_document_draft=show_document_draft,
        )
    if len(items) > _STEP4_ISSUE_DEFAULT_LIMIT:
        if show_all:
            if st.button("上位 12 件の表示に戻す", key="step4_issue_show_less"):
                st.session_state[show_all_key] = False
                st.rerun()
        elif st.button(f"すべて表示（残り {remaining} 件）", key="step4_issue_show_all"):
            st.session_state[show_all_key] = True
            st.rerun()


def _render_step4_chapter_auxiliary(
    review: ReviewResult,
    preview_docs: list[SanitizedDocument],
    structure_result: StructureCheckResult | None,
    document_profile_override: str | None,
) -> None:
    docs_with_chapters = [
        (doc, _chapters_for_document(doc))
        for doc in preview_docs
    ]
    docs_with_chapters = [
        (doc, chapters)
        for doc, chapters in docs_with_chapters
        if len(chapters) >= 3
    ]
    if not docs_with_chapters:
        st.caption("3章以上を検出した文書がないため、章単位の追加レビューは表示していません。")
        return
    developer_all = bool(st.session_state.get("developer_mode", False))
    for doc, chapters in docs_with_chapters:
        st.markdown(
            sr_ui.collapsed_list_row(
                "📄",
                f"{doc.name} · {len(chapters)}章",
                "章の概要を確認し、必要な章だけAIで再分析できます。",
            ),
            unsafe_allow_html=True,
        )
        candidate_indices = [
            idx for idx, candidate in enumerate(chapters)
            if _chapter_needs_deep_dive(review, doc.name, candidate, structure_result)[0]
        ]
        enabled_idx = None if developer_all else (candidate_indices[0] if candidate_indices else None)
        for chapter_idx, chapter in enumerate(chapters):
            overview = _find_chapter_overview(review, doc.name, chapter)
            summary = (
                getattr(overview, "summary", "") if overview is not None else ""
            ) or _chapter_excerpt(chapter.extracted_text)
            needs_deep, reason = _chapter_needs_deep_dive(
                review,
                doc.name,
                chapter,
                structure_result,
            )
            chapter_key = _chapter_cache_key(doc.name, chapter)
            pass_count = len((st.session_state.get("chapter_deep_dive_results") or {}).get(chapter_key, []))
            can_run = developer_all or chapter_idx == enabled_idx
            can_run = can_run and pass_count < MAX_CHAPTER_DEEP_DIVE_PASSES
            row_col, button_col = st.columns([5, 1.4])
            with row_col:
                st.markdown(f"**{chapter.chapter_label}**")
                st.caption(f"{summary[:180]} / {reason[:160]}")
            with button_col:
                button_key = (
                    "ch_deepdive_entry_btn_"
                    + hashlib.sha256(
                        f"{doc.name}|{chapter.chapter_id}|{chapter_idx}".encode("utf-8")
                    ).hexdigest()[:12]
                )
                if st.button(
                    "🔬 この章を再分析",
                    key=button_key,
                    disabled=not can_run,
                    width="stretch",
                    help="この章をAIで再レビューし、追加指摘を修正計画に合流します。",
                ):
                    _run_chapter_deep_dive(
                        doc.name,
                        chapter,
                        review,
                        document_profile_override,
                    )


def _render_step4_future_auxiliary(report: FutureReviewReport | None) -> None:
    if report is None:
        st.caption("将来リスクの解析結果はありません。")
        return
    if not _step4_future_hint_count(report):
        st.success("将来リスク・読み手リスク・曖昧表現の大きな補助指摘はありません。")
        return
    for item in (getattr(report, "premortem_scenarios", ()) or ())[:4]:
        st.markdown(
            sr_ui.collapsed_list_row(
                "🔮",
                item.title,
                f"{item.failure_path} / 次の一手: {item.prevention}",
            ),
            unsafe_allow_html=True,
        )
    for item in (getattr(report, "reader_risks", ()) or ())[:3]:
        st.markdown(
            sr_ui.collapsed_list_row(
                "👥",
                f"{item.persona} の誤読リスク",
                f"{item.reason} / {item.recommendation}",
            ),
            unsafe_allow_html=True,
        )
    for item in (getattr(report, "ambiguous_findings", ()) or ())[:3]:
        st.markdown(
            sr_ui.collapsed_list_row(
                "？",
                f"曖昧表現: {item.expression}",
                item.recommendation,
            ),
            unsafe_allow_html=True,
        )


def _render_step4_usage_guide(plan: RemediationPlan) -> None:
    guide_cards = [
        ("1. 担当割当", "赤いカードから担当者を決め、対象章と修正方針を共有します。"),
        ("2. 追記案の反映", "文書追記案を文書本体に転記し、実案件の数値・担当・期限に合わせて具体化します。"),
        ("3. 再確認", "再レビュー条件に書かれた章・観点だけを確認します。"),
        ("必須再レビュー", "高重要度の修正後は、該当章だけを再アップロードして確認します。"),
        ("差分レビュー", "中重要度は、追記箇所と関連箇所を中心に確認します。"),
        ("完了確認", "修正後の文書で構成チェック、概要レビュー、深堀候補が矛盾しないか確認します。"),
    ]
    html_cards = []
    for title, body in guide_cards:
        html_cards.append(
            "<div class='step4-guide-card'>"
            f"<div class='step4-guide-title'>{html.escape(title)}</div>"
            f"<div class='step4-guide-body'>{html.escape(body)}</div>"
            "</div>"
        )
    st.markdown(
        "<div class='step4-guide-grid'>" + "".join(html_cards) + "</div>",
        unsafe_allow_html=True,
    )
    if plan.re_review_steps:
        st.caption("再レビュー種別")
        for step in plan.re_review_steps:
            st.markdown(
                sr_ui.collapsed_list_row("↻", step.label, f"{step.detail} / 契機: {step.trigger}"),
                unsafe_allow_html=True,
            )


def _render_step4_auxiliary_sections(
    review: ReviewResult,
    preview_docs: list[SanitizedDocument],
    structure_result: StructureCheckResult | None,
    remediation_plan: RemediationPlan,
    future_report: FutureReviewReport | None,
    document_profile_override: str | None,
) -> None:
    st.markdown(
        "<div class='step4-section-title'>補助で見るもの</div>"
        "<div class='step4-section-caption'>必要な根拠や追加確認だけを、機能別に開いて確認します。</div>",
        unsafe_allow_html=True,
    )
    with st.expander("文書構成チェック — 章立て不足の根拠を確認", expanded=False):
        count = _step4_structure_finding_count(structure_result)
        st.markdown(
            sr_ui.collapsed_list_row("📐", "文書構成チェック", f"{count}件の確認点"),
            unsafe_allow_html=True,
        )
        if structure_result is not None:
            _render_document_structure_check(structure_result)
        checklist_results = getattr(review, "checklist_results", ()) or ()
        if checklist_results:
            st.caption("チェック項目評価")
            for result in checklist_results[:12]:
                st.markdown(
                    sr_ui.collapsed_list_row(
                        "✓",
                        f"{getattr(result, 'item_name', '')} · {getattr(result, 'status', '')}",
                        f"{getattr(result, 'source_document', '')} / {getattr(result, 'reason', '')}",
                    ),
                    unsafe_allow_html=True,
                )
    with st.expander("章単位の追加レビュー — 指摘カード以外の章を直接選ぶ", expanded=False):
        _render_step4_chapter_auxiliary(
            review,
            preview_docs,
            structure_result,
            document_profile_override,
        )
    with st.expander("将来の障害リスク — 主要指摘の先にある予防策を確認", expanded=False):
        _render_step4_future_auxiliary(future_report)
    with st.expander("修正計画の使い方 — 担当割当から再レビューまで", expanded=False):
        _render_step4_usage_guide(remediation_plan)


def _render_step4_dev_footer(review: ReviewResult) -> None:
    _render_review_log_export_panel()
    if not st.session_state.get("developer_mode", False):
        return
    with st.expander("🧪 LLM メタ情報・プロンプト（開発者向け）", expanded=False):
        st.markdown(
            sr_ui.metric_pair("LLM", provider_display_name(review.provider, review.model)),
            unsafe_allow_html=True,
        )
        st.markdown(
            sr_ui.metric_pair("Rubric", review.rubric_name or review.rubric_id or "-"),
            unsafe_allow_html=True,
        )
        st.code(review.prompt_preview or "(prompt preview なし)", language="markdown")
        if review.raw_response:
            st.code(review.raw_response, language="json")


def _render_step4_v2(
    *,
    review: ReviewResult,
    preview_docs: list[SanitizedDocument],
    structure_result: StructureCheckResult | None,
    remediation_plan: RemediationPlan,
    future_report: FutureReviewReport | None,
    document_profile_override: str | None,
) -> None:
    st.markdown("<div class='step4-v2'>", unsafe_allow_html=True)
    _render_step4_status_and_summary(
        review,
        preview_docs,
        remediation_plan,
        structure_result,
        future_report,
    )
    _render_step4_issue_cards(
        remediation_plan,
        review,
        preview_docs,
        document_profile_override,
    )
    _render_step4_dev_footer(review)
    st.markdown("</div>", unsafe_allow_html=True)


def _render_review_log_export_panel() -> None:
    if not st.session_state.get("developer_mode", False):
        return
    with st.expander("📦 証跡エクスポート — 監査ログを共有・保存するときに開く", expanded=False):
        st.markdown(
            """
<div class="export-panel">
  <div class="export-title">監査ログをまとめて保存</div>
  <div class="export-detail">
    匿名化済みテキスト、マスク候補、送信対象ログ、レビュー結果を 1 つの ZIP にまとめて保存します。
    再レビュー用の修正計画JSONとは用途が異なります。開発者・監査担当者が検証ログを共有したい場合だけ利用してください。
  </div>
</div>
            """,
            unsafe_allow_html=True,
        )
        render_log_export_button()


def _load_remediation_plan_json(uploaded_file) -> RemediationPlan:
    try:
        payload = json.loads(uploaded_file.getvalue().decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ValueError("修正計画JSONを UTF-8 として読み込めませんでした。") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON形式を解析できませんでした: {exc}") from exc
    return remediation_plan_from_dict(payload)


def _render_previous_remediation_plan_loader() -> None:
    st.session_state.setdefault("enable_previous_remediation_review", False)
    with st.container(border=True):
        enabled = st.toggle(
            "前回文書の再レビューを使う",
            key="enable_previous_remediation_review",
            help=(
                "前回保存した修正計画JSONと今回の修正文書を照合したい場合だけオンにします。"
                "通常レビューではオフのままで問題ありません。"
            ),
        )
        st.caption(
            "オンにした場合だけ、前回JSONの読み込み、前回計画との照合、今回JSONの保存を表示します。"
            "通常の文書レビューはJSONなしで実行できます。"
        )

    if not enabled:
        st.session_state.pop("previous_remediation_plan", None)
        st.session_state.pop("previous_remediation_plan_upload", None)
        return

    with st.expander("🔁 前回の修正計画JSONを読み込む（任意・再レビュー時のみ）", expanded=True):
        st.caption(
            "初回レビューでは不要です。担当者が文書を修正した後、前回保存した修正計画JSONをここで読み込むと、"
            "今回アップロードした修正文書に改善要素が反映されているかをローカルで照合できます。"
        )
        uploaded_plan = st.file_uploader(
            "前回保存した修正計画JSON（旧 remediation_plan.json も可）",
            type=["json"],
            accept_multiple_files=False,
            key="previous_remediation_plan_upload",
            label_visibility="collapsed",
            help=(
                "ファイル名には依存しません。旧 remediation_plan.json も、"
                "新しい remediation_plan_YYYYMMDD_HHMM.json も読み込めます。"
            ),
        )
        if uploaded_plan is not None:
            try:
                plan = _load_remediation_plan_json(uploaded_plan)
                st.session_state.previous_remediation_plan = plan
                st.success(
                    f"前回の修正計画JSONを読み込みました: {len(plan.items)} 件。"
                    "匿名化プレビュー後に改善状況を照合します。"
                )
            except ValueError as exc:
                st.session_state.pop("previous_remediation_plan", None)
                st.error(str(exc))
        elif st.session_state.get("previous_remediation_plan"):
            plan = st.session_state.previous_remediation_plan
            st.info(f"前回の修正計画JSONを保持中です: {len(plan.items)} 件。")


def _comparison_status_label(status: str) -> str:
    return {
        "improved": "改善あり",
        "partial": "一部改善",
        "not_confirmed": "未確認",
        "needs_review": "要確認",
    }.get(status, "要確認")


def _render_remediation_comparison_report(report: RemediationComparisonReport) -> None:
    item_cards = []
    for item in report.items[:8]:
        item_cards.append(
            """
<div class="comparison-card {status}">
  <div class="comparison-card-title">{title}</div>
  <div class="comparison-card-meta">{label} / {severity} / {target}</div>
  <div class="comparison-card-text"><b>確認結果:</b> {evidence}</div>
  <div class="comparison-card-text"><b>次の確認:</b> {next_action}</div>
</div>
            """.format(
                status=html.escape(item.status),
                title=html.escape(item.title),
                label=html.escape(_comparison_status_label(item.status)),
                severity=html.escape(item.severity),
                target=html.escape(f"{item.target_document} / {item.target_section}"),
                evidence=html.escape(item.evidence),
                next_action=html.escape(item.next_action),
            )
        )
    st.markdown(
        f"""
<section class="comparison-panel">
  <div class="comparison-head">
    <div>
      <div class="remediation-kicker">Re-review Memory</div>
      <div class="comparison-title">前回の修正計画JSONと今回文書を照合しました</div>
      <div class="comparison-detail">
        前回計画「{html.escape(report.source_headline)}」の指摘項目が、今回の匿名化後テキストに反映されているかを
        ローカルで簡易照合しています。これは送信前の目視補助であり、最終判断は今回のLLMレビュー結果と合わせて確認してください。
      </div>
    </div>
  </div>
  <div class="comparison-metrics">
    <span class="comparison-pill">対象 {report.total_count}</span>
    <span class="comparison-pill">改善あり {report.improved_count}</span>
    <span class="comparison-pill">一部改善 {report.partial_count}</span>
    <span class="comparison-pill">未確認 {report.not_confirmed_count}</span>
    <span class="comparison-pill">要確認 {report.needs_review_count}</span>
  </div>
  <div class="comparison-grid">{''.join(item_cards)}</div>
</section>
        """,
        unsafe_allow_html=True,
    )


FEEDBACK_OPTIONS = ("未評価", "有効", "言い過ぎ", "不要", "見落としあり")


def _future_tone_label(level: str) -> str:
    return {
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "情報",
    }.get(level, level or "-")


def _future_card(title: str, meta: str, body: str, action: str, tone: str = "low") -> str:
    return f"""
<div class="future-card {html.escape(tone)}">
  <div class="future-card-title">{html.escape(title)}</div>
  <div class="future-card-meta">{html.escape(meta)}</div>
  <div class="future-card-text">{html.escape(body)}</div>
  <div class="future-card-text"><b>次の一手:</b> {html.escape(action)}</div>
</div>
    """


def _premortem_card(item) -> str:
    return f"""
<div class="future-card {html.escape(item.risk_level)}">
  <div class="future-card-title">{html.escape(item.title)}</div>
  <div class="future-card-meta">
    {html.escape(item.scenario_id)} / {html.escape(item.source_document)} / {html.escape(item.section)} /
    {html.escape(_future_tone_label(item.risk_level))}
  </div>
  <div class="future-card-text"><b>故障への道筋:</b> {html.escape(item.failure_path)}</div>
  <div class="future-card-text"><b>次の一手:</b> {html.escape(item.prevention)}</div>
</div>
    """


def _issue_feedback_key(issue) -> str:
    # section は後段の章推定で補完されることがあるため、キーには含めない。
    # ここに含めると初回表示と再描画後でフィードバックが別扱いになる。
    raw = "|".join(
        str(part or "")
        for part in (
            getattr(issue, "issue_id", ""),
            getattr(issue, "source_document", ""),
            getattr(issue, "title", ""),
            getattr(issue, "issue", ""),
            getattr(issue, "recommendation", ""),
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _feedback_counts(review) -> dict[str, int]:
    feedback = st.session_state.get("review_issue_feedback") or {}
    keys = {_issue_feedback_key(issue) for issue in getattr(review, "issues", []) or []}
    counts = {option: 0 for option in FEEDBACK_OPTIONS}
    for key in keys:
        value = feedback.get(key, "未評価")
        counts[value if value in counts else "未評価"] += 1
    counts["合計"] = len(keys)
    counts["評価済み"] = counts["合計"] - counts["未評価"]
    return counts


def _render_issue_feedback_control(issue, scope: str = "main") -> None:
    key = _issue_feedback_key(issue)
    feedback = st.session_state.setdefault("review_issue_feedback", {})
    notes = st.session_state.setdefault("review_issue_feedback_notes", {})
    current = feedback.get(key, "未評価")
    if current not in FEEDBACK_OPTIONS:
        current = "未評価"
    with st.expander("🧭 この指摘の精度を評価（メタレビュー用）", expanded=False):
        choice = st.radio(
            "この指摘は実務上どうでしたか？",
            FEEDBACK_OPTIONS,
            index=FEEDBACK_OPTIONS.index(current),
            horizontal=True,
            key=f"issue_feedback_{scope}_{key}",
            help="この評価は外部送信されません。レビュー基準の調整候補を把握するためのセッション内メモです。",
        )
        feedback[key] = choice
        if choice in {"言い過ぎ", "不要", "見落としあり"}:
            notes[key] = st.text_area(
                "補足メモ",
                value=notes.get(key, ""),
                key=f"issue_feedback_note_{scope}_{key}",
                height=82,
                placeholder="例: この観点は本資料のスコープ外 / 実際には別紙に記載あり / 逆に○○観点が不足",
            )
        st.session_state.review_issue_feedback = feedback
        st.session_state.review_issue_feedback_notes = notes


def _render_feedback_summary(review) -> None:
    counts = _feedback_counts(review)
    total = counts.get("合計", 0)
    if total == 0:
        st.info("まだ評価対象のレビュー指摘がありません。")
        return
    st.markdown(
        f"""
<div class="feedback-panel">
  <b>レビュー品質フィードバック</b><br/>
  評価済み {counts.get('評価済み', 0)} / {total} 件。
  有効 {counts.get('有効', 0)} 件、言い過ぎ {counts.get('言い過ぎ', 0)} 件、
  不要 {counts.get('不要', 0)} 件、見落としあり {counts.get('見落としあり', 0)} 件。
</div>
        """,
        unsafe_allow_html=True,
    )
    if counts.get("言い過ぎ", 0) or counts.get("不要", 0):
        st.caption("言い過ぎ・不要が増える観点は、次回のレビュー基準調整候補として扱います。")
    if counts.get("見落としあり", 0):
        st.caption("見落としありのメモは、ルーブリック追加候補として確認してください。")


def _render_future_review_lens(
    report: FutureReviewReport,
    review,
    *,
    expanded: bool = False,
) -> None:
    show_meta_review = bool(st.session_state.get("developer_mode", False))
    feedback_counts = _feedback_counts(review) if show_meta_review else {}
    high_or_medium_reader = sum(
        1 for item in report.reader_risks if item.risk_level in {"high", "medium"}
    )
    metric_html = "".join(
        (
            f'<span class="future-pill">未確定表現 {report.ambiguous_count}</span>',
            f'<span class="future-pill">読み手リスク {high_or_medium_reader}</span>',
            f'<span class="future-pill">未来障害候補 {len(report.premortem_scenarios)}</span>',
            (
                f'<span class="future-pill">指摘評価 '
                f"{feedback_counts.get('評価済み', 0)}/{feedback_counts.get('合計', 0)}</span>"
                if show_meta_review else ""
            ),
        )
    )

    with st.expander("🔮 障害シナリオと予防策 — 主要な指摘の先にある将来リスク", expanded=expanded):
        st.markdown(
            f"""
<section class="future-lens">
  <div class="future-lens-head">
    <div>
      <div class="future-lens-kicker">Future Review Lens</div>
      <div class="future-lens-title">先読みレビュー</div>
      <div class="future-lens-copy">
        これは修正計画とは別角度で、将来の障害シナリオと予防策を提示します。
        指摘対応後も残りそうな運用・復旧・読み手リスクを確認したい場面で開いてください。
      </div>
    </div>
    <div class="future-lens-metrics">
      {metric_html}
    </div>
  </div>
</section>
            """,
            unsafe_allow_html=True,
        )
        tab_labels = ["曖昧表現", "読み手リスク", "未来障害"]
        if show_meta_review:
            tab_labels.append("メタレビュー")
        tabs = st.tabs(tab_labels)

        with tabs[0]:
            if not report.ambiguous_findings:
                st.success("未確定のまま残っている典型的な曖昧表現は検出されませんでした。")
            else:
                cards = [
                    _future_card(
                        title=f"{item.expression} · 不足: {', '.join(item.missing_elements)}",
                        meta=f"{item.source_document} / {item.section} / {_future_tone_label(item.severity)}",
                        body=item.context or "該当表現の周辺文脈を抽出できませんでした。",
                        action=item.recommendation,
                        tone=item.severity,
                    )
                    for item in report.ambiguous_findings
                ]
                st.markdown(
                    f"<div class='future-card-grid'>{''.join(cards)}</div>",
                    unsafe_allow_html=True,
                )

        with tabs[1]:
            cards = [
                _future_card(
                    title=f"{item.persona}: {_future_tone_label(item.risk_level)}",
                    meta=f"{item.source_document} / {item.section}",
                    body=item.reason + (f" シグナル: {', '.join(item.signals)}" if item.signals else ""),
                    action=item.recommendation,
                    tone=item.risk_level,
                )
                for item in report.reader_risks
            ]
            st.markdown(
                f"<div class='future-card-grid'>{''.join(cards)}</div>",
                unsafe_allow_html=True,
            )

        with tabs[2]:
            st.caption(
                "ここでは追加の外部LLM呼び出しは行いません。修正計画と重なる根拠欄は省き、将来障害への道筋と予防策だけを表示します。"
            )
            if not report.premortem_scenarios:
                st.success("代表的な未来障害シナリオに直結する予兆は強く検出されませんでした。")
            else:
                cards = [_premortem_card(item) for item in report.premortem_scenarios]
                st.markdown(
                    f"<div class='future-card-grid'>{''.join(cards)}</div>",
                    unsafe_allow_html=True,
                )

        if show_meta_review:
            with tabs[3]:
                _render_feedback_summary(review)
                st.caption(
                    "開発者モードでのみ表示されます。指摘の有効性を記録し、レビュー基準の調整材料にします。"
                )

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

        # R-V (2026-05-08): customer_id を渡してプロファイル固有 seed dict もロード
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


# ------------------------------------------------------------------- sidebar

with st.sidebar:
    st.markdown('<div class="sidebar-section-label">レビュー操作</div>', unsafe_allow_html=True)
    if st.button("↻ 新しいレビューを始める", width='stretch', type="primary"):
        _reset_state()
        # R-X-1 (2026-05-08): 旧 uploader_key の widget 状態を pop し、視覚的にも空にする。
        old_key = st.session_state.get("uploader_key")
        if old_key:
            st.session_state.pop(old_key, None)
        st.session_state.uploader_key = f"uploads_{uuid.uuid4().hex[:8]}"
        st.rerun()

    st.markdown(
        """
<div class="sidebar-memory-card">
  アップロード済みの文書、マスク判断、レビュー結果をクリアして、最初からやり直します。
  アップロード文書はサーバ上に保存されず、本セッション中のメモリ上のみで処理されます。
</div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("---")

    provider = os.getenv("REVIEW_PROVIDER", "mock")
    provider_model = (
        os.getenv("GEMMA_MODEL", "").strip()
        or os.getenv("GEMINI_MODEL", "").strip()
        or os.getenv("LLM_MODEL", "").strip()
    )
    provider_label = provider_display_name(provider, provider_model)
    local_san = os.getenv("LOCAL_SANITIZER_PROVIDER", "none")
    local_sens = os.getenv("LOCAL_SENSITIVITY_PROVIDER", "heuristic")

    st.markdown(
        f"""
<div class="sidebar-section-label">動作環境</div>
<div class="env-panel">
  <div class="env-row"><span class="env-label">LLM</span><span class="env-value">{html.escape(provider_label)}</span></div>
  <div class="env-row"><span class="env-label">匿名化</span><span class="env-value">{html.escape(local_san)}</span></div>
  <div class="env-row"><span class="env-label">機密判定</span><span class="env-value">{html.escape(local_sens)}</span></div>
</div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    with st.expander("⚙️ 詳細設定 — 辞書・R-M・開発者表示を切り替えるときに開く", expanded=False):
        st.caption(
            "通常操作では変更不要です。プロジェクト固有のマスク辞書、R-M、"
            "開発者向け表示を切り替える場合だけ使います。"
        )
        st.markdown('<div class="sidebar-section-label">文書種別</div>', unsafe_allow_html=True)
        profile_options = [
            ("(自動判定)", None),
            ("設計書", "design"),
            ("変更・切替手順書", "change_runbook"),
            ("保守・運用手順書", "operations_runbook"),
            ("ネットワーク機器Config", "network_config"),
            ("ソースコード", "source_code"),
        ]
        profile_label = st.selectbox(
            "文書種別",
            [label for label, _ in profile_options],
            index=0,
            label_visibility="collapsed",
            help=(
                "通常は自動判定のままで利用します。"
                "自動判定が実際の文書種別と異なる場合だけ、手動で上書きしてください。"
            ),
        )
        document_profile_override = dict(profile_options)[profile_label]
        st.markdown(
            '<div class="sidebar-help">通常は自動判定で問題ありません。誤判定時のみ手動で変更します。</div>',
            unsafe_allow_html=True,
        )

        # R-V (2026-05-08): マスク辞書プロファイル selector
        st.markdown("---")
        render_customer_selector(sidebar=False)

        st.markdown("---")
        if _is_rm_enabled():
            st.markdown("##### R-M（固有名詞候補の追加検知）")
            rm_enabled_user = st.checkbox(
                "R-M を使う（推奨: ON）",
                value=True,
                key="rm_enabled_user",
                help=(
                    "OFF にすると、既存の正規表現マスキングのみで処理します。"
                    "シード辞書ヒットや gBizINFO 検索は行いません。"
                ),
            )
            try:
                _rm_token = st.secrets.get("GBIZINFO_API_TOKEN", "")
            except Exception:
                _rm_token = ""
            if _rm_token:
                st.caption("✅ GBIZINFO_API_TOKEN は設定済みです。")
            else:
                st.caption(
                    "⚠️ GBIZINFO_API_TOKEN は未設定です。"
                    "シード辞書 + spaCy NER のみで動作します。"
                )
        else:
            rm_enabled_user = False

        st.markdown("---")
        _developer_mode_default = (
            os.getenv("DEVELOPER_MODE_DEFAULT", "false").strip().lower() == "true"
        )
        if "developer_mode" not in st.session_state:
            st.session_state.developer_mode = _developer_mode_default

        st.session_state.developer_mode = st.toggle(
            "開発者モード",
            value=st.session_state.developer_mode,
            help=(
                "OFF: 実務機能のみ表示。ON: プロンプトプレビュー、LLM 生レスポンス、"
                "NER Diagnostics、gBizINFO Diagnostics などの実装検証用 UI を表示します。"
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

st.markdown(
    """
<div class="sr-app-title-row">
  <span class="sr-app-title-icon" aria-hidden="true">SR</span>
  <span class="sr-app-title-text">技術文書レビュー支援ツール</span>
</div>
    """,
    unsafe_allow_html=True,
)

# -- Step 1: Upload --------------------------------------------------------

preview_clicked = _render_step1_v2()

if preview_clicked:
    st.session_state.preview_attempted = True
    for key in (
        "preview_docs",
        "preview_warnings",
        "preview_error",
        "preview_trace",
        "send_approval",
        "anonymization_details_visible",
        "anonymization_details_expand_once",
        "review_result",
        "structure_result",
        "remediation_plan",
        "review_issue_feedback",
        "review_issue_feedback_notes",
    ):
        st.session_state.pop(key, None)

    # Phase 7 段階 1.5 (2026-05-08): docs_checked フラグ廃止に伴い、リセット不要に
    # 古い deep_dive_results も新 preview には不適合なのでクリア
    st.session_state.pop("deep_dive_results", None)
    st.session_state.pop("chapter_deep_dive_results", None)
    st.session_state.pop("deep_dive_notice", None)
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
            " (「新しいレビューを始める」で全ファイル一括クリアも可能)"
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
        st.session_state.anonymization_details_expand_once = False
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
                                base_sanitized=sdoc,
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

preview_docs = st.session_state.get("preview_docs") or []
_operation_estimate = None
if preview_docs:
    try:
        _operation_estimate = estimate_review_token_budget(
            preview_docs,
            document_profile_override,
        )
    except Exception:
        _operation_estimate = None

preview_error = st.session_state.get("preview_error")
if preview_error:
    _render_step_header(
        2,
        "匿名化結果プレビュー",
        "ローカル匿名化と機密度判定の結果を確認します。",
    )
    st.error(preview_error)
    st.info(
        "匿名化結果が作成されなかったため、ステップ 3 には進めません。"
        "設定やローカル Ollama の起動状態を確認してから、もう一度「匿名化してプレビュー」を押してください。"
    )
    if st.session_state.get("preview_trace"):
        with st.expander("詳細トレース"):
            st.code(st.session_state.preview_trace)

if st.session_state.get("preview_attempted") and not preview_error and not preview_docs:
    _render_step_header(
        2,
        "匿名化結果プレビュー",
        "ローカル匿名化と機密度判定の結果を確認します。",
    )
    st.info("匿名化結果はまだ作成されていません。ファイルを確認して、もう一度実行してください。")

if preview_docs:
    _masking_states_for_gate = st.session_state.get("masking_states", {}) or {}
    mask_docs = [
        doc
        for doc in preview_docs
        if _requires_manual_confirmation_for_doc(doc, _masking_states_for_gate)
    ]
    blocked_docs = [
        doc
        for doc in preview_docs
        if doc.local_sensitivity_decision == "block" or doc.outbound_risk == "high"
    ]
    can_regenerate_anonymization = _has_regeneratable_mask_candidates(
        _masking_states_for_gate
    )

    _render_step2_v2(
        preview_docs,
        preview_warnings=st.session_state.get("preview_warnings", []) or [],
        document_profile_override=document_profile_override,
        masking_states=_masking_states_for_gate,
        blocked_docs=blocked_docs,
        can_regenerate_anonymization=can_regenerate_anonymization,
    )

    # -- Step 3: Confirmation gate ----------------------------------------

    send_clicked, send_approved = _render_step3_v2(
        preview_docs,
        blocked_docs=blocked_docs,
        mask_docs=mask_docs,
        provider_label=provider_label,
        estimate=_operation_estimate,
    )

    # Q12 (2026-05-08): 「レビューに送信」押下時の処理
    # LLM 送信のみ (文書チェック後の preview_docs を使用)。
    #
    # 課題 2 改修 (2026-05-08): chunking 進捗表示
    # GeminiApiReviewProvider が文書ごとに API call する際、
    # st.progress と st.status で進捗を可視化する。
    # これにより 60〜120 秒の処理中もユーザがフリーズと誤認しない。
    if send_clicked:
        st.session_state.review_in_progress = True
        st.session_state.pop("structure_result", None)
        st.session_state.pop("remediation_plan", None)
        st.session_state.pop("deep_dive_results", None)
        st.session_state.pop("chapter_deep_dive_results", None)
        st.session_state.pop("deep_dive_notice", None)
        _render_review_runtime_status(
            "レビュー実行中 · 外部 LLM へ送信中",
            preview_docs,
            icon="↗",
            estimate=_operation_estimate,
        )
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
            provider_label = provider_display_name(
                provider_impl.name,
                getattr(provider_impl, "model", ""),
            )
            review_progress.progress(40, text="外部送信ガードを確認しています...")
            _enforce_outbound_guard(provider_impl.name, preview_docs)

            def _update_progress(idx: int, total: int, doc_name: str) -> None:
                """課題 2 改修: chunking 進捗 callback。
                Gemini プロバイダから文書処理ごとに呼び出される。
                """
                try:
                    fraction = min(1.0, idx / max(1, total))
                    if doc_name == "完了":
                        review_progress.progress(100, text=f"✅ 全 {total} 文書のレビュー完了")
                    else:
                        # 文書名が長すぎると progress bar の text が見づらくなるので適度に切る
                        display_name = doc_name if len(doc_name) <= 50 else doc_name[:47] + "..."
                        review_progress.progress(
                            int(45 + fraction * 45),
                            text=f"📄 {idx}/{total} 処理中: {display_name}",
                        )
                except Exception:  # noqa: BLE001
                    # progress bar の更新失敗は致命的ではない (ログのみ)
                    pass

            with st.spinner(f"{provider_label} でレビュー実行中..."):
                review_progress.progress(
                    65,
                    text=f"{provider_label} に匿名化済みテキストを送信し、レビューを実行しています...",
                )
                review = provider_impl.review(
                    preview_docs,
                    document_profile_override,
                    progress_callback=_update_progress,
                )
            review_progress.progress(100, text="レビューが完了しました。")

            st.session_state.review_result = review
            st.session_state.pop("review_issue_feedback", None)
            st.session_state.pop("review_issue_feedback_notes", None)
            st.session_state.review_in_progress = False
            _render_review_runtime_status(
                "レビュー完了 · 結果を表示します",
                preview_docs,
                icon="✓",
                estimate=_operation_estimate,
            )
        except LocalUrlError as exc:
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.session_state.review_in_progress = False
            _render_review_runtime_status(
                "レビュー停止 · ローカル設定エラー",
                preview_docs,
                icon="!",
                estimate=_operation_estimate,
            )
            st.error(f"ローカルエンドポイントの設定に問題があります: {exc}")
        except ValueError as exc:
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.session_state.review_in_progress = False
            _render_review_runtime_status(
                "レビュー停止 · 送信前チェックエラー",
                preview_docs,
                icon="!",
                estimate=_operation_estimate,
            )
            st.error(str(exc))
        except RuntimeError as exc:
            # Gemini quota and similar user-actionable errors come through here.
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.session_state.review_in_progress = False
            _render_review_runtime_status(
                "レビュー停止 · LLM 応答エラー",
                preview_docs,
                icon="!",
                estimate=_operation_estimate,
            )
            st.error(_format_review_runtime_error(exc))
        except Exception as exc:  # noqa: BLE001
            review_progress.progress(100, text="レビュー処理で停止しました。")
            st.session_state.review_in_progress = False
            _render_review_runtime_status(
                "レビュー停止 · 予期しないエラー",
                preview_docs,
                icon="!",
                estimate=_operation_estimate,
            )
            request_id = uuid.uuid4().hex[:8]
            st.error(f"レビューに失敗しました ({request_id})。詳細はサーバログを確認してください。")
            with st.expander("詳細トレース"):
                st.code(traceback.format_exc())


# -- Step 4: Review result -------------------------------------------------

review = st.session_state.get("review_result")
if review is not None:
    _preview_docs_for_structure = st.session_state.get("preview_docs") or []
    _structure_result_for_review = None
    if _preview_docs_for_structure:
        _structure_result_for_review = build_structure_check_result(
            _preview_docs_for_structure,
            review.document_profile or "",
        )
        st.session_state["structure_result"] = _structure_result_for_review
    _remediation_plan = _rebuild_remediation_plan_for_session(
        review,
        _structure_result_for_review,
    )
    _future_report = build_future_review_report(
        _preview_docs_for_structure,
        review,
    )
    _deep_dive_notice = st.session_state.pop("deep_dive_notice", "")
    if _deep_dive_notice:
        st.info(_deep_dive_notice)
    _render_step4_v2(
        review=review,
        preview_docs=_preview_docs_for_structure,
        structure_result=_structure_result_for_review,
        remediation_plan=_remediation_plan,
        future_report=_future_report,
        document_profile_override=document_profile_override,
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
