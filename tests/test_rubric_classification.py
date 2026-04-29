"""Tests for the R-K filename-first profile classification logic.

These tests cover the rewritten ``detect_document_profile`` and
``classify_documents`` functions in ``secure_review.rubric``. They focus on:

- Filename signals (design / change_runbook / operations_runbook).
- Body strong signals (when filename gives no hint).
- Conflict detection (filename vs body, multiple filename profiles).
- Backward-compatible behaviour for source code, forced overrides, and
  the default design fallback.
"""
from __future__ import annotations

import unittest

from secure_review.models import SanitizedDocument
from secure_review.rubric import (
    classify_documents,
    detect_document_profile,
)


def _doc(name: str, body: str = "") -> SanitizedDocument:
    """Helper: build a minimal SanitizedDocument for classification tests."""
    return SanitizedDocument(
        name=name,
        original_excerpt=body,
        sanitized_excerpt=body,
        outbound_text=body,
    )


class FilenameSignalTests(unittest.TestCase):
    """Filename keywords drive classification when the body is neutral."""

    def test_filename_design_simple(self) -> None:
        """A single 設計書 file → design / high."""
        result = detect_document_profile([_doc("基本設計書 1. はじめに.pdf", "本書の位置付け")])
        self.assertEqual(result.document_profile, "design")
        self.assertEqual(result.confidence, "high")

    def test_filename_design_multiple_files(self) -> None:
        """12 design files (today's real upload) → design / high."""
        docs = [
            _doc(f"基本設計書_{i}__テスト設計.pdf", "設計内容のダミー") for i in range(1, 13)
        ]
        result = detect_document_profile(docs)
        self.assertEqual(result.document_profile, "design")
        self.assertEqual(result.confidence, "high")

    def test_filename_change_runbook(self) -> None:
        """A 作業計画書 file → change_runbook / high."""
        result = detect_document_profile(
            [_doc("2026-05-15_FW更新_作業計画書.pdf", "作業内容のダミー")]
        )
        self.assertEqual(result.document_profile, "change_runbook")
        self.assertEqual(result.confidence, "high")

    def test_filename_operations_runbook(self) -> None:
        """A 日次運用 file → operations_runbook / high."""
        result = detect_document_profile([_doc("日次運用手順.pdf", "毎日の運用作業")])
        self.assertEqual(result.document_profile, "operations_runbook")
        self.assertEqual(result.confidence, "high")


class BodyStrongSignalTests(unittest.TestCase):
    """Body keywords drive classification when filename gives no hint."""

    def test_body_strong_signal_change_runbook_only(self) -> None:
        """Neutral filename + 'タイムチャート' / '切戻し' in body → change_runbook / medium."""
        result = detect_document_profile(
            [_doc("memo.pdf", "タイムチャートと切戻し手順を以下に示す")]
        )
        self.assertEqual(result.document_profile, "change_runbook")
        self.assertEqual(result.confidence, "medium")

    def test_body_strong_signal_operations_only(self) -> None:
        """Neutral filename + 'エスカレーション' in body → operations_runbook / medium."""
        result = detect_document_profile(
            [_doc("memo.pdf", "障害発生時のエスカレーションフローについて")]
        )
        self.assertEqual(result.document_profile, "operations_runbook")
        self.assertEqual(result.confidence, "medium")


class ConflictDetectionTests(unittest.TestCase):
    """Two kinds of conflict: filename vs body, and multiple filename profiles."""

    def test_conflict_filename_vs_body(self) -> None:
        """Filename 設計書 + body 切戻し手順 → design (provisional) / conflict."""
        result = detect_document_profile(
            [_doc("可用性設計書.pdf", "障害時の切戻し手順を以下に定義する。")]
        )
        self.assertEqual(result.document_profile, "design")
        self.assertEqual(result.confidence, "conflict")
        # The reason should mention the body signal so users understand why.
        self.assertIn("change_runbook", result.reason)
        self.assertIn("design", result.reason)

    def test_conflict_multiple_filenames(self) -> None:
        """One 設計書.pdf + one 作業計画書.pdf in same upload → conflict."""
        result = detect_document_profile(
            [
                _doc("システム設計書.pdf", "設計内容"),
                _doc("移行作業計画書.pdf", "作業内容"),
            ]
        )
        self.assertEqual(result.confidence, "conflict")
        # design has 1 hit, change_runbook has 1 hit → tie → priority order
        # picks design first.
        self.assertEqual(result.document_profile, "design")

    def test_conflict_multi_filenames_majority(self) -> None:
        """5 設計書 + 1 作業計画書 → design wins by majority, still conflict."""
        docs = [_doc(f"基本設計書_{i}.pdf", "") for i in range(1, 6)]
        docs.append(_doc("移行作業計画書.pdf", ""))
        result = detect_document_profile(docs)
        self.assertEqual(result.document_profile, "design")
        self.assertEqual(result.confidence, "conflict")


class BackwardCompatibilityTests(unittest.TestCase):
    """Legacy behaviour for source code, forced overrides, and default fallback."""

    def test_source_code_extension_unchanged(self) -> None:
        """All-.py upload → source_code / high (unchanged from old logic)."""
        docs = [
            _doc("script.py", "def foo(): pass"),
            _doc("util.py", "import os"),
        ]
        result = detect_document_profile(docs)
        self.assertEqual(result.document_profile, "source_code")
        self.assertEqual(result.confidence, "high")

    def test_source_code_syntax_unchanged(self) -> None:
        """A .txt file containing 'def x(): pass' → source_code (syntax-based)."""
        result = detect_document_profile([_doc("snippet.txt", "def hello():\n    return 1")])
        self.assertEqual(result.document_profile, "source_code")
        # syntax-based detection picks high or medium depending on _looks_like_source_code.
        self.assertIn(result.confidence, ("high", "medium"))

    def test_forced_profile_overrides_all(self) -> None:
        """forced_profile bypasses content-based detection entirely."""
        # Filename strongly suggests design, but caller forces operations_runbook.
        result = classify_documents(
            [_doc("基本設計書.pdf", "通常の設計内容")],
            forced_profile="operations_runbook",
        )
        self.assertEqual(result.document_profile, "operations_runbook")
        self.assertEqual(result.confidence, "forced")

    def test_default_design_when_no_signals(self) -> None:
        """No filename hint, no body signal, unrecognised extension → design / low.

        Note: a ``.pdf``/``.md``/etc. file would match DESIGN_EXTENSIONS and
        return ``medium``. To reach the bare ``low`` fallback we need an
        extension outside both DESIGN_EXTENSIONS and SOURCE_CODE_EXTENSIONS.
        """
        result = detect_document_profile(
            [_doc("memo.unknownext", "ただのメモ。特に signal は無い。")]
        )
        self.assertEqual(result.document_profile, "design")
        self.assertEqual(result.confidence, "low")

    def test_default_design_pdf_without_signals(self) -> None:
        """A .pdf with no signals → design / medium (extension-based fallback).

        Documents the second-tier fallback so future contributors don't
        accidentally regress this behaviour.
        """
        result = detect_document_profile(
            [_doc("memo.pdf", "ただのメモ。特に signal は無い。")]
        )
        self.assertEqual(result.document_profile, "design")
        self.assertEqual(result.confidence, "medium")


if __name__ == "__main__":
    unittest.main()
