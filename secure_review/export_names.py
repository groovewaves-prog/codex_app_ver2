from __future__ import annotations

from datetime import datetime


def export_timestamp(now: datetime | None = None) -> str:
    """Return a compact timestamp for user-downloaded JSON files."""
    return (now or datetime.now()).strftime("%Y%m%d_%H%M")


def remediation_plan_json_filename(now: datetime | None = None) -> str:
    """Filename for the re-review remediation-plan ledger."""
    return f"remediation_plan_{export_timestamp(now)}.json"


def audit_json_filename(kind: str, now: datetime | None = None) -> str:
    """Filename for audit exports, using a consistent audit_ prefix."""
    safe_kind = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in kind).strip("_")
    return f"audit_{safe_kind or 'log'}_{export_timestamp(now)}.json"
