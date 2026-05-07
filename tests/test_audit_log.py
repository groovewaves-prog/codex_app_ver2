"""R-W-1 + R-W-3 + R-W-4: audit_log モジュールのテスト。

実 spaCy 不要 (audit_log 自体は spaCy 非依存)。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secure_review.audit_log import (
    DEFAULT_CUSTOMER_ID,
    aggregate_decisions,
    append_to_user_allowlist,
    append_to_user_seeds,
    generate_session_id,
    log_decisions,
    recommend_action,
)


class LogDecisionsTests(unittest.TestCase):
    """log_decisions の動作検証。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_writes_jsonl_entries(self):
        """各判断が JSONL の 1 行として書き出される。"""
        path = log_decisions(
            document_name="test.pdf",
            decisions={"東京": True, "Amazon": False},
            candidate_metadata={
                "東京": {"label": "GPE", "source": "watchlist", "context": "東京リージョン"},
                "Amazon": {"label": "ORG", "source": "spacy_ner", "context": "Amazon SES"},
            },
            customer_id="test_customer",
            session_id="sess-001",
            audit_root=self.tmpdir,
        )
        self.assertTrue(path.exists())
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 2)
        terms = {ln["term"] for ln in lines}
        self.assertEqual(terms, {"東京", "Amazon"})
        # 必須フィールド
        for ln in lines:
            self.assertEqual(ln["schema_version"], "1")
            self.assertEqual(ln["customer_id"], "test_customer")
            self.assertEqual(ln["session_id"], "sess-001")
            self.assertIn(ln["decision"], ("mask", "skip"))

    def test_directory_created_per_customer(self):
        """customer_id ごとに別ディレクトリに記録される (R-V)。"""
        log_decisions(
            document_name="d1.pdf",
            decisions={"A": True},
            candidate_metadata={"A": {"label": "ORG"}},
            customer_id="cust_a",
            session_id="s1",
            audit_root=self.tmpdir,
        )
        log_decisions(
            document_name="d2.pdf",
            decisions={"B": False},
            candidate_metadata={"B": {"label": "GPE"}},
            customer_id="cust_b",
            session_id="s2",
            audit_root=self.tmpdir,
        )
        self.assertTrue((self.tmpdir / "cust_a").is_dir())
        self.assertTrue((self.tmpdir / "cust_b").is_dir())
        self.assertEqual(len(list((self.tmpdir / "cust_a").glob("*.jsonl"))), 1)
        self.assertEqual(len(list((self.tmpdir / "cust_b").glob("*.jsonl"))), 1)

    def test_append_does_not_overwrite(self):
        """同じファイルに連続 log_decisions 呼ぶと追記される。"""
        log_decisions(
            document_name="d1.pdf",
            decisions={"A": True},
            candidate_metadata={"A": {"label": "ORG"}},
            customer_id="x",
            session_id="s1",
            audit_root=self.tmpdir,
        )
        log_decisions(
            document_name="d1.pdf",
            decisions={"B": False},
            candidate_metadata={"B": {"label": "GPE"}},
            customer_id="x",
            session_id="s1",
            audit_root=self.tmpdir,
        )
        path = self.tmpdir / "x" / next((self.tmpdir / "x").glob("*.jsonl")).name
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)

    def test_context_truncated_at_120_chars(self):
        """文脈フィールドは最大 120 文字に切り詰める。"""
        long_ctx = "あ" * 200
        log_decisions(
            document_name="d.pdf",
            decisions={"X": True},
            candidate_metadata={"X": {"label": "ORG", "context": long_ctx}},
            customer_id="c",
            session_id="s",
            audit_root=self.tmpdir,
        )
        path = next((self.tmpdir / "c").glob("*.jsonl"))
        entry = json.loads(path.read_text(encoding="utf-8").strip())
        self.assertLessEqual(len(entry["context"]), 120)


class AggregateDecisionsTests(unittest.TestCase):
    """aggregate_decisions の集計ロジック検証。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def _seed(self, customer_id, decisions_with_meta, session_id="s1"):
        """テスト用にデータを書き込むヘルパ。"""
        decisions = {term: dec for term, (dec, _) in decisions_with_meta.items()}
        meta = {term: m for term, (_, m) in decisions_with_meta.items()}
        log_decisions(
            document_name="t.pdf",
            decisions=decisions,
            candidate_metadata=meta,
            customer_id=customer_id,
            session_id=session_id,
            audit_root=self.tmpdir,
        )

    def test_aggregates_by_term(self):
        """同じ term の複数判断を集計する。"""
        self._seed("c1", {"東京": (True, {"label": "GPE"})}, session_id="s1")
        self._seed("c1", {"東京": (True, {"label": "GPE"})}, session_id="s2")
        self._seed("c1", {"東京": (False, {"label": "GPE"})}, session_id="s3")
        agg = aggregate_decisions(customer_id="c1", audit_root=self.tmpdir)
        self.assertEqual(agg["東京"]["mask_count"], 2)
        self.assertEqual(agg["東京"]["skip_count"], 1)
        self.assertEqual(agg["東京"]["total"], 3)
        self.assertAlmostEqual(agg["東京"]["mask_ratio"], 2 / 3, places=2)

    def test_session_filter(self):
        """session_id 指定時はそのセッションのみ集計 (R-W-2 用)。"""
        self._seed("c1", {"X": (True, {"label": "ORG"})}, session_id="this")
        self._seed("c1", {"X": (False, {"label": "ORG"})}, session_id="other")
        agg = aggregate_decisions(customer_id="c1", session_id="this", audit_root=self.tmpdir)
        self.assertEqual(agg["X"]["mask_count"], 1)
        self.assertEqual(agg["X"]["skip_count"], 0)

    def test_cross_customer_aggregation(self):
        """customer_id=None 指定時は全顧客横断 (R-V)。"""
        self._seed("c1", {"X": (True, {"label": "ORG"})})
        self._seed("c2", {"X": (False, {"label": "ORG"})})
        agg = aggregate_decisions(customer_id=None, audit_root=self.tmpdir)
        self.assertEqual(agg["X"]["mask_count"], 1)
        self.assertEqual(agg["X"]["skip_count"], 1)
        self.assertEqual(set(agg["X"]["customer_ids"]), {"c1", "c2"})

    def test_missing_directory_returns_empty(self):
        """audit log が無い時は空 dict を返す (エラーにしない)。"""
        agg = aggregate_decisions(customer_id="never", audit_root=self.tmpdir)
        self.assertEqual(agg, {})


class RecommendActionTests(unittest.TestCase):
    """推奨エンジン (R-W-4) の判定ロジック検証。

    閾値 (Q2 標準): 90% 以上一貫 + 5 回以上で推奨。
    """

    def test_promote_seed_mask_for_consistent_mask(self):
        """100% mask × 5 回 → seed dict 推奨。"""
        agg = {"mask_count": 5, "skip_count": 0, "total": 5, "mask_ratio": 1.0}
        self.assertEqual(recommend_action(agg), "promote_seed_mask")

    def test_promote_seed_skip_for_consistent_skip(self):
        """0% mask × 10 回 → tech_allowlist 推奨。"""
        agg = {"mask_count": 0, "skip_count": 10, "total": 10, "mask_ratio": 0.0}
        self.assertEqual(recommend_action(agg), "promote_seed_skip")

    def test_context_dependent_for_mixed(self):
        """50% mask × 10 回 → 文脈依存。"""
        agg = {"mask_count": 5, "skip_count": 5, "total": 10, "mask_ratio": 0.5}
        self.assertEqual(recommend_action(agg), "context_dependent")

    def test_insufficient_for_few_occurrences(self):
        """2 回しか出現しない → データ不足。"""
        agg = {"mask_count": 2, "skip_count": 0, "total": 2, "mask_ratio": 1.0}
        self.assertEqual(recommend_action(agg), "insufficient_data")

    def test_threshold_boundary_90_percent(self):
        """ちょうど 90% mask × 10 回 → seed dict 昇格。"""
        agg = {"mask_count": 9, "skip_count": 1, "total": 10, "mask_ratio": 0.9}
        self.assertEqual(recommend_action(agg), "promote_seed_mask")

    def test_threshold_boundary_89_percent(self):
        """89% mask は文脈依存扱い (90% 未満)。"""
        agg = {"mask_count": 89, "skip_count": 11, "total": 100, "mask_ratio": 0.89}
        self.assertEqual(recommend_action(agg), "context_dependent")


class AppendToUserSeedsTests(unittest.TestCase):
    """append_to_user_seeds の YAML 追記動作検証 (R-W-3)。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_creates_file_with_header(self):
        """初回呼び出しで新規ファイル + ヘッダ作成。"""
        path, added = append_to_user_seeds(
            text="iret", label="ORG", canonical="KDDIアイレット",
            confirm=False, customer_id="kddi_mail_relay",
            seeds_root=self.tmpdir,
        )
        self.assertTrue(added)
        self.assertTrue(path.exists())
        content = path.read_text(encoding="utf-8")
        self.assertIn("phrases:", content)
        self.assertIn("iret", content)
        self.assertIn("KDDIアイレット", content)
        self.assertIn("confirm: false", content)

    def test_appends_to_existing_file(self):
        """既存ファイルに追記。"""
        append_to_user_seeds(
            text="A", label="ORG", customer_id="c", seeds_root=self.tmpdir,
        )
        path, added = append_to_user_seeds(
            text="B", label="GPE", customer_id="c", seeds_root=self.tmpdir,
        )
        self.assertTrue(added)
        content = path.read_text(encoding="utf-8")
        self.assertIn("text: \"A\"", content)
        self.assertIn("text: \"B\"", content)

    def test_skips_duplicate(self):
        """同じ text で 2 回呼んだ時、2 回目は追記しない。"""
        append_to_user_seeds(
            text="X", label="ORG", customer_id="c", seeds_root=self.tmpdir,
        )
        path, added = append_to_user_seeds(
            text="X", label="ORG", customer_id="c", seeds_root=self.tmpdir,
        )
        self.assertFalse(added)
        # 1 エントリのみ存在
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["phrases"]), 1)

    def test_yaml_is_parseable(self):
        """生成された YAML が PyYAML で正しくパース可能。"""
        path, _ = append_to_user_seeds(
            text="府中", label="GPE", canonical="府中",
            confirm=False, customer_id="c", seeds_root=self.tmpdir,
        )
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["phrases"]), 1)
        entry = data["phrases"][0]
        self.assertEqual(entry["text"], "府中")
        self.assertEqual(entry["label"], "GPE")
        self.assertEqual(entry["confirm"], False)


class AppendToUserAllowlistTests(unittest.TestCase):
    """append_to_user_allowlist の動作検証。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_creates_and_appends(self):
        path, added = append_to_user_allowlist(
            text="OurInternalTool", customer_id="c", seeds_root=self.tmpdir,
        )
        self.assertTrue(added)
        content = path.read_text(encoding="utf-8")
        self.assertIn("user_allowlist:", content)
        self.assertIn("OurInternalTool", content)

    def test_skips_duplicate(self):
        append_to_user_allowlist(text="X", customer_id="c", seeds_root=self.tmpdir)
        _, added = append_to_user_allowlist(text="X", customer_id="c", seeds_root=self.tmpdir)
        self.assertFalse(added)


class GenerateSessionIdTests(unittest.TestCase):
    def test_unique_per_call(self):
        sid1 = generate_session_id()
        sid2 = generate_session_id()
        self.assertNotEqual(sid1, sid2)

    def test_format_starts_with_date(self):
        sid = generate_session_id()
        # YYYYMMDD-HHMMSS-<6chars>
        parts = sid.split("-")
        self.assertEqual(len(parts), 3)
        self.assertEqual(len(parts[0]), 8)  # YYYYMMDD



class CustomerIdValidationTests(unittest.TestCase):
    """R-W-security (2026-05-08): path traversal 対策の検証 (B2)。"""

    def test_rejects_path_traversal_in_log(self):
        """customer_id="../../../etc/passwd" は ValueError。"""
        from secure_review.audit_log import log_decisions
        with self.assertRaises(ValueError):
            log_decisions(
                document_name="x.pdf",
                decisions={"a": True},
                candidate_metadata={"a": {"label": "ORG"}},
                customer_id="../../../etc/passwd",
            )

    def test_rejects_slash_in_log(self):
        from secure_review.audit_log import log_decisions
        with self.assertRaises(ValueError):
            log_decisions(
                document_name="x.pdf",
                decisions={},
                candidate_metadata={},
                customer_id="cust/sub",
            )

    def test_rejects_backslash_in_log(self):
        from secure_review.audit_log import log_decisions
        with self.assertRaises(ValueError):
            log_decisions(
                document_name="x.pdf",
                decisions={},
                candidate_metadata={},
                customer_id="cust\\sub",
            )

    def test_accepts_valid_customer_id(self):
        """英数字 + _ + - は OK。"""
        from secure_review.audit_log import log_decisions
        import tempfile
        from pathlib import Path
        tmp = Path(tempfile.mkdtemp())
        # 例外が出ないこと
        log_decisions(
            document_name="x.pdf",
            decisions={},
            candidate_metadata={},
            customer_id="kddi_mail-relay_v2",
            audit_root=tmp,
        )

    def test_rejects_in_append_to_user_seeds(self):
        from secure_review.audit_log import append_to_user_seeds
        with self.assertRaises(ValueError):
            append_to_user_seeds(
                text="x", label="ORG",
                customer_id="../bad",
            )


if __name__ == "__main__":
    unittest.main()
