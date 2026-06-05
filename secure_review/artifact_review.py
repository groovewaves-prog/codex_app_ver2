from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath
import re

from secure_review.models import SanitizedDocument


@dataclass(frozen=True)
class ArtifactReviewMode:
    """How the uploaded artifact should be reviewed.

    The document profile decides the broad rubric. This mode describes the
    practical handling: code/config analysis, lightweight runbook review, or
    ordinary document review. It is intentionally pure so it can be reused by
    the prompt builder and the Streamlit UI.
    """

    mode_id: str
    mode_name: str
    summary: str
    primary_output: str
    prompt_guidance: tuple[str, ...]
    ui_notes: tuple[str, ...]
    detected_languages: tuple[str, ...] = ()
    runbook_depth: str = ""


_LANGUAGE_PATTERNS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "Python",
        (".py",),
        ("def ", "import ", "from ", "if __name__ == ", "urllib.request", "requests."),
    ),
    (
        "PowerShell",
        (".ps1", ".psm1", ".psd1"),
        ("param(", "write-host", "invoke-", "get-", "set-", "$erroractionpreference"),
    ),
    (
        "Shell",
        (".sh", ".bash", ".bsh", ".ksh", ".zsh"),
        ("#!/bin/", "set -e", "mailx", "systemctl", "grep ", "awk ", "sed "),
    ),
    (
        "SQL",
        (".sql", ".psql"),
        ("select ", "insert ", "update ", "delete from", "create table", "alter table"),
    ),
    (
        "VBA/VBScript",
        (".vbs", ".vba", ".bas", ".cls", ".frm"),
        ("sub ", "end sub", "function ", "createobject(", "select case"),
    ),
)


_HIGH_RISK_RUNBOOK_TERMS = (
    "systemctl restart",
    "reboot",
    "shutdown",
    "delete",
    "drop ",
    "truncate ",
    "rm -rf",
    "event.acknowledge",
    "housekeeper_execute",
    "mysql ",
    "update ",
    "障害イベント",
    "切り替え",
    "切替",
    "再起動",
    "削除",
)


def detect_artifact_review_mode(
    documents: list[SanitizedDocument],
    document_profile: str,
) -> ArtifactReviewMode:
    """Return the practical review mode for the uploaded artifacts."""

    if document_profile == "source_code":
        languages = _detect_code_languages(documents)
        language_text = " / ".join(languages) if languages else "コード/スクリプト"
        return ArtifactReviewMode(
            mode_id="code_analysis",
            mode_name="コード解析モード",
            summary=(
                f"{language_text} として扱い、設計書の章立てではなく、"
                "目的・入力/出力・秘密情報・外部通信・破壊的処理・ログ・例外処理を確認します。"
            ),
            primary_output="実行せずに、コードの安全性・運用リスク・改善候補を要約します。",
            prompt_guidance=(
                "これは設計書レビューではなくコード/スクリプト解析です。章立て不足を主指摘にしないでください。",
                "コードは実行せず、静的に読める範囲で目的、入力、出力、外部依存、秘密情報、ログ、例外処理、再実行性を確認してください。",
                "ハードコードされた認証情報、TLS検証無効化、タイムアウト不足、危険なコマンド、破壊的操作、広すぎる例外処理を優先して指摘してください。",
                "断定できない外部仕様や環境依存は、確認事項として分離してください。",
            ),
            ui_notes=(
                "設計書の体裁ではなく、コード/スクリプトの読み取り結果を出します。",
                "正式な静的解析ツールではなく、レビュー補助の概要解析です。",
            ),
            detected_languages=languages,
        )

    if document_profile == "network_config":
        return ArtifactReviewMode(
            mode_id="config_analysis",
            mode_name="Config概要解析モード",
            summary=(
                "Cisco / Fortinet などの機器Configとして扱い、設計書の章立てではなく、"
                "通信許可、管理アクセス、冗長性、危険設定の候補を確認します。"
            ),
            primary_output="正式なConfig監査ではなく、注意候補と設計書との突き合わせ観点を出します。",
            prompt_guidance=(
                "これはネットワーク機器Configの概要解析です。章立て不足を主指摘にしないでください。",
                "ACL、Firewall Policy、NAT、管理アクセス、VPN、ルーティング、冗長性の注意候補を確認してください。",
                "文脈依存が強い設定は断定せず、確認観点として整理してください。",
            ),
            ui_notes=(
                "Config本文から読み取れる範囲で危険候補を示します。",
                "構成図や設計書が別にある場合は、突き合わせレビューが有効です。",
            ),
        )

    if document_profile in {"operations_runbook", "change_runbook"}:
        depth = _infer_runbook_depth(documents)
        if depth == "light_high_risk":
            mode_name = "簡易手順書レビュー（高リスク操作あり）"
            summary = (
                "簡易な手順書として扱います。ただし再起動・DB操作・削除などの高リスク操作が含まれるため、"
                "最低限の安全条件と確認ポイントを優先します。"
            )
        elif depth == "light":
            mode_name = "簡易手順書レビュー"
            summary = (
                "簡易な手順書として使う前提で、過剰に正式文書化せず、"
                "実行に必要な最低限の前提・確認・戻し方を確認します。"
            )
        else:
            mode_name = "正式手順書レビュー"
            summary = (
                "正式な手順書として扱い、目的、前提、影響、実施条件、確認、切戻し、責任分担を確認します。"
            )
        return ArtifactReviewMode(
            mode_id="runbook_depth",
            mode_name=mode_name,
            summary=summary,
            primary_output=(
                "簡易版として使う場合の最低限の補強と、正式手順書へ拡張する場合の追加項目を分けて提示します。"
            ),
            prompt_guidance=(
                "手順書レビューでは、ユーザが簡易版のまま使いたい可能性と、正式手順書へ拡張したい可能性を分けて扱ってください。",
                "簡易版として成立させるための最低限の修正と、正式化する場合の追加章・追加確認を混同しないでください。",
                "作業影響、前提条件、バックアウト/切戻し、成功判定、失敗時の連絡、実行権限、ログ確認を優先してください。",
                "簡易文書に対して、業界標準の全章立て不足を大量に指摘しすぎないでください。必要な粒度を説明してください。",
            ),
            ui_notes=(
                "簡易のまま使う場合と、正式手順書へ育てる場合を分けてレビューします。",
                "危険操作がある場合は、軽量レビューでも安全確認を強めます。",
            ),
            runbook_depth=depth,
        )

    return ArtifactReviewMode(
        mode_id="document_review",
        mode_name="文書レビュー",
        summary="設計書・説明資料として扱い、構成、品質、リスク、抜け漏れを確認します。",
        primary_output="対応すべき指摘と、必要に応じた改善案を提示します。",
        prompt_guidance=(
            "通常の技術文書レビューとして、目的、範囲、構成、品質、リスクを確認してください。",
        ),
        ui_notes=("文書としての構成・品質・リスクを中心に確認します。",),
    )


def render_artifact_review_mode_for_prompt(mode: ArtifactReviewMode) -> str:
    """Render mode guidance for LLM prompts."""

    lines = [
        f"レビュー運用モード: {mode.mode_name}",
        f"概要: {mode.summary}",
        f"期待する出力: {mode.primary_output}",
    ]
    if mode.detected_languages:
        lines.append(f"検出言語/形式: {', '.join(mode.detected_languages)}")
    if mode.runbook_depth:
        lines.append(f"手順書の粒度: {mode.runbook_depth}")
    lines.append("モード別の注意:")
    lines.extend(f"- {item}" for item in mode.prompt_guidance)
    return "\n".join(lines)


def _detect_code_languages(documents: list[SanitizedDocument]) -> tuple[str, ...]:
    found: list[str] = []
    for document in documents:
        name = (document.name or "").lower()
        suffixes = tuple(s.lower() for s in PurePath(name).suffixes)
        text = (document.outbound_text or "").lower()
        for language, extensions, signals in _LANGUAGE_PATTERNS:
            if language in found:
                continue
            if any(ext in suffixes for ext in extensions) or any(signal in text for signal in signals):
                found.append(language)
    return tuple(found)


def _infer_runbook_depth(documents: list[SanitizedDocument]) -> str:
    text = "\n".join(document.outbound_text or "" for document in documents)
    lowered = text.lower()
    has_high_risk = any(term in lowered or term in text for term in _HIGH_RISK_RUNBOOK_TERMS)
    step_count = len(re.findall(r"(?m)^\s*(?:\d+[\.．、]|[①②③④⑤⑥⑦⑧⑨⑩]|・)\s*", text))
    char_count = len(text)

    if char_count <= 9000 and step_count >= 2:
        return "light_high_risk" if has_high_risk else "light"
    if has_high_risk and char_count <= 14000:
        return "light_high_risk"
    return "formal"
