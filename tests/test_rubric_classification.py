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

    def test_cisco_ios_config_body_detected(self) -> None:
        """Cisco IOS style config body → network_config / medium."""
        result = detect_document_profile(
            [
                _doc(
                    "router.txt",
                    "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n"
                    "line vty 0 4\n transport input ssh\nrouter ospf 1",
                )
            ]
        )
        self.assertEqual(result.document_profile, "network_config")
        self.assertEqual(result.confidence, "medium")

    def test_fortios_config_filename_and_body_detected(self) -> None:
        """FortiGate config file → network_config / high."""
        result = detect_document_profile(
            [
                _doc(
                    "fortigate_config.conf",
                    "config system interface\n edit \"port1\"\n set allowaccess ping ssh\n next\nend\n"
                    "config firewall policy\n edit 1\n set srcintf \"port1\"\n set dstintf \"port2\"\n next\nend",
                )
            ]
        )
        self.assertEqual(result.document_profile, "network_config")
        self.assertEqual(result.confidence, "high")

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


# ----------------------------------------------------------------------
# B1 (R-L) tests: rubric deepening, proposal profile, filename signal extension
# ----------------------------------------------------------------------


class DesignRubricDeepeningTests(unittest.TestCase):
    """B1: design rubric was deepened from 2 MCs to 5 MCs and from 3-checkpoint
    EAs to 5-7-checkpoint EAs."""

    def test_design_has_five_mandatory_checks(self) -> None:
        from secure_review.rubric import RUBRICS
        design = RUBRICS["design"]
        self.assertEqual(len(design.mandatory_checks), 5)
        ids = [mc.id for mc in design.mandatory_checks]
        self.assertIn("requirement_traceability", ids)
        self.assertIn("non_functional_coverage", ids)
        self.assertIn("risk_and_open_issues", ids)

    def test_design_evaluation_axes_weight_sum_is_100(self) -> None:
        from secure_review.rubric import RUBRICS
        design = RUBRICS["design"]
        total = sum(ax.weight for ax in design.evaluation_axes)
        self.assertEqual(total, 100)

    def test_design_security_axis_has_more_than_three_checkpoints(self) -> None:
        """B1 enriched the security axis from 3 to 7 checkpoints."""
        from secure_review.rubric import RUBRICS
        design = RUBRICS["design"]
        sec_axis = next(ax for ax in design.evaluation_axes if ax.id == "security")
        self.assertGreater(len(sec_axis.checkpoints), 3)


class ProposalProfileTests(unittest.TestCase):
    """B1: new ``proposal`` profile for 企画書 / 提案書."""

    def test_proposal_rubric_exists(self) -> None:
        from secure_review.rubric import RUBRICS
        self.assertIn("proposal", RUBRICS)

    def test_proposal_rubric_has_four_mandatory_checks(self) -> None:
        """proposal applies purpose / configuration / traceability / risks
        but not non_functional_coverage (which is design-only)."""
        from secure_review.rubric import RUBRICS
        proposal = RUBRICS["proposal"]
        self.assertEqual(len(proposal.mandatory_checks), 4)
        ids = [mc.id for mc in proposal.mandatory_checks]
        self.assertNotIn("non_functional_coverage", ids)

    def test_proposal_evaluation_axes_weight_sum_is_100(self) -> None:
        from secure_review.rubric import RUBRICS
        proposal = RUBRICS["proposal"]
        total = sum(ax.weight for ax in proposal.evaluation_axes)
        self.assertEqual(total, 100)


class NetworkConfigProfileTests(unittest.TestCase):
    """Cisco/Fortinet Config profile is available as a bounded overview mode."""

    def test_network_config_rubric_exists(self) -> None:
        from secure_review.rubric import RUBRICS
        self.assertIn("network_config", RUBRICS)

    def test_network_config_evaluation_axes_weight_sum_is_100(self) -> None:
        from secure_review.rubric import RUBRICS
        rubric = RUBRICS["network_config"]
        total = sum(axis.weight for axis in rubric.evaluation_axes)
        self.assertEqual(total, 100)

    def test_design_rubric_contains_detailed_design_viewpoints(self) -> None:
        from secure_review.rubric import RUBRICS
        design = RUBRICS["design"]
        all_checkpoints = "\n".join(
            checkpoint
            for axis in design.evaluation_axes
            for checkpoint in axis.checkpoints
        )
        self.assertIn("インターフェース仕様", all_checkpoints)
        self.assertIn("状態遷移", all_checkpoints)
        self.assertIn("コード・SQL・機器Config", all_checkpoints)


class ProposalFilenameSignalTests(unittest.TestCase):
    """B1: filename signal extended with FILENAME_PROPOSAL_KEYWORDS."""

    def test_filename_proposal_simple(self) -> None:
        result = detect_document_profile(
            [_doc("新メールリレーシステム企画書.pdf", "ビジネス目的の概要")]
        )
        self.assertEqual(result.document_profile, "proposal")
        self.assertEqual(result.confidence, "high")

    def test_design_takes_priority_over_proposal(self) -> None:
        """When both design and proposal keywords appear, design wins."""
        result = detect_document_profile(
            [_doc("運用設計書(企画段階).pdf", "")]
        )
        self.assertEqual(result.document_profile, "design")

    def test_proposal_takes_priority_over_change_runbook(self) -> None:
        """When both proposal and change_runbook signals are present
        (no design), proposal wins by priority order."""
        result = detect_document_profile(
            [
                _doc("企画書 v1.pdf", ""),
                _doc("移行作業計画書.pdf", ""),
            ]
        )
        # Both filenames hit, so confidence=conflict and the priority
        # tuple breaks the tie in favour of proposal.
        self.assertEqual(result.document_profile, "proposal")
        self.assertEqual(result.confidence, "conflict")


class MandatoryCheckSelectionTests(unittest.TestCase):
    """B1: ``_select_mandatory_checks`` filters by applies_to."""

    def test_design_picks_traceability_and_non_functional_and_risks(self) -> None:
        from secure_review.rubric import _select_mandatory_checks
        ids = [mc.id for mc in _select_mandatory_checks("design")]
        self.assertIn("requirement_traceability", ids)
        self.assertIn("non_functional_coverage", ids)
        self.assertIn("risk_and_open_issues", ids)
        # timechart is runbook-only, must NOT be included for design
        self.assertNotIn("timechart_information", ids)

    def test_change_runbook_picks_timechart_but_not_traceability(self) -> None:
        from secure_review.rubric import _select_mandatory_checks
        ids = [mc.id for mc in _select_mandatory_checks("change_runbook")]
        self.assertIn("timechart_information", ids)
        self.assertNotIn("requirement_traceability", ids)
        self.assertNotIn("non_functional_coverage", ids)


if __name__ == "__main__":
    unittest.main()
