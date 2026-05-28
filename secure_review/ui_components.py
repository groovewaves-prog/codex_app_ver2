"""Reusable HTML UI components for the Streamlit review interface.

G-1 adds these pure builders as a design foundation. Existing screens keep
their current rendering until later phases opt in to these components.
"""
from __future__ import annotations

import html


_SEVERITY_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "neutral": "情報",
}

_EFFORT_LABELS = {
    "large": "工数 大",
    "medium": "工数 中",
    "small": "工数 小",
}


def _escape(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _severity_key(level: str) -> str:
    normalized = (level or "").strip().lower()
    return normalized if normalized in _SEVERITY_LABELS else "neutral"


def _effort_key(level: str) -> str:
    normalized = (level or "").strip().lower()
    return normalized if normalized in _EFFORT_LABELS else "medium"


def severity_chip(level: str, count: int | None = None) -> str:
    """Return a severity chip.

    level: "high" | "medium" | "low" | "neutral". Unknown values fall back to
    neutral without exposing the raw input.
    """
    key = _severity_key(level)
    label = _SEVERITY_LABELS[key]
    suffix = "" if count is None else f"<span>{_escape(count)}</span>"
    return f'<span class="sr-chip sr-severity-{key}">{_escape(label)}{suffix}</span>'


def effort_badge(level: str) -> str:
    """Return an effort badge for "large" | "medium" | "small"."""
    key = _effort_key(level)
    return f'<span class="sr-effort-badge sr-effort-{key}">{_escape(_EFFORT_LABELS[key])}</span>'


def status_bar(state_label: str, meta_right: str = "", icon: str = "") -> str:
    """Return a top-of-page status bar."""
    icon_part = f'<span class="sr-status-icon">{_escape(icon)}</span>' if icon else ""
    meta_part = f'<span class="sr-status-meta">{_escape(meta_right)}</span>' if meta_right else ""
    return (
        '<div class="sr-status-bar">'
        f'<div class="sr-status-main">{icon_part}<span>{_escape(state_label)}</span></div>'
        f"{meta_part}"
        "</div>"
    )


def big_number_summary(number: int, unit: str, lead: str = "") -> str:
    """Return a large-number summary block."""
    lead_part = f'<div class="sr-big-number-lead">{_escape(lead)}</div>' if lead else ""
    return (
        '<div class="sr-big-number">'
        f"{lead_part}"
        f'<div class="sr-big-number-value">{_escape(number)} <span>{_escape(unit)}</span></div>'
        "</div>"
    )


def issue_card_header(severity: str, effort: str, issue_id: str, chapter: str, title: str) -> str:
    """Return the header area for an issue card."""
    severity_key = _severity_key(severity)
    return (
        f'<div class="sr-issue-card-header {severity_key}">'
        '<div class="sr-issue-card-meta">'
        f"{severity_chip(severity)}"
        f"{effort_badge(effort)}"
        f'<span class="sr-issue-card-submeta">{_escape(issue_id)}</span>'
        f'<span class="sr-issue-card-submeta">{_escape(chapter)}</span>'
        "</div>"
        f'<div class="sr-issue-card-title">{_escape(title)}</div>'
        "</div>"
    )


def collapsed_list_row(icon: str, title: str, subtitle: str) -> str:
    """Return a compact row for collapsed helper sections."""
    return (
        '<div class="sr-collapsed-row">'
        f'<div class="sr-collapsed-row-icon">{_escape(icon)}</div>'
        "<div>"
        f'<div class="sr-collapsed-row-title">{_escape(title)}</div>'
        f'<div class="sr-collapsed-row-subtitle">{_escape(subtitle)}</div>'
        "</div>"
        "</div>"
    )


def metric_pair(label: str, value: str) -> str:
    """Return a label/value metric pair."""
    return (
        '<div class="sr-metric-pair">'
        f'<div class="sr-metric-label">{_escape(label)}</div>'
        f'<div class="sr-metric-value">{_escape(value)}</div>'
        "</div>"
    )
