"""R-V (2026-05-08): NerMasker の顧客 PJ 固有 seed dict ロード機能のテスト。

実 spaCy 必須 (EntityRuler.patterns 検査のため)。
mock 環境では setUpClass で skip。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock


def _install_spacy_mock():
    if "spacy" in sys.modules:
        return
    spacy_mock = MagicMock()
    spacy_mock.load = MagicMock()
    sys.modules["spacy"] = spacy_mock


def _install_models_mock():
    if "secure_review" not in sys.modules:
        models_mock = MagicMock()
        models_mock.NerCandidate = MagicMock
        try:
            import secure_review  # noqa: F401
            sys.modules["secure_review.models"] = models_mock
        except ImportError:
            secure_review_mock = MagicMock()
            secure_review_mock.models = models_mock
            sys.modules["secure_review"] = secure_review_mock
            sys.modules["secure_review.models"] = models_mock


_install_spacy_mock()
_install_models_mock()


class CustomerSeedLoadingTests(unittest.TestCase):
    """customer_id 指定時に customers/<id>/ner_seeds.yaml が読まれること。"""

    @classmethod
    def setUpClass(cls):
        spacy_mod = sys.modules.get("spacy")
        if spacy_mod is None or isinstance(spacy_mod, MagicMock):
            raise unittest.SkipTest("Requires real spaCy installation")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # 共通 seeds
        (self.tmp / "ner_seeds.yaml").write_text(
            'phrases:\n  - text: "Common"\n    label: ORG\n',
            encoding="utf-8",
        )
        # customer 固有 seeds
        cust_dir = self.tmp / "customers" / "test_pj"
        cust_dir.mkdir(parents=True)
        (cust_dir / "ner_seeds.yaml").write_text(
            'phrases:\n  - text: "CustomerA"\n    label: ORG\n',
            encoding="utf-8",
        )
        # customer user_seeds (R-W-3 自動生成想定)
        (cust_dir / "ner_seeds_user.yaml").write_text(
            'phrases:\n  - text: "AutoAdded"\n    label: GPE\n    confirm: false\n',
            encoding="utf-8",
        )

    def test_loads_common_and_customer(self):
        """共通 + 顧客固有の両方が EntityRuler に登録される。"""
        from secure_review.ner_masker import NerMasker
        masker = NerMasker(
            seed_yaml_path=str(self.tmp / "ner_seeds.yaml"),
            allowlist_yaml_path="/nonexistent/allowlist.yaml",
            customer_id="test_pj",
            data_root=str(self.tmp),
        )
        ids = [p.get("id", "") for p in masker._ruler.patterns]
        self.assertIn("seed:phrase:Common", ids)
        self.assertIn("seed:phrase:CustomerA", ids)
        self.assertIn("watch:phrase:AutoAdded", ids)

    def test_customer_id_none_skips_customer_seeds(self):
        """customer_id=None なら共通 seed dict のみロード (R-V 以前互換)。"""
        from secure_review.ner_masker import NerMasker
        masker = NerMasker(
            seed_yaml_path=str(self.tmp / "ner_seeds.yaml"),
            allowlist_yaml_path="/nonexistent/allowlist.yaml",
            customer_id=None,
            data_root=str(self.tmp),
        )
        ids = [p.get("id", "") for p in masker._ruler.patterns]
        self.assertIn("seed:phrase:Common", ids)
        self.assertNotIn("seed:phrase:CustomerA", ids)
        self.assertNotIn("watch:phrase:AutoAdded", ids)

    def test_missing_customer_directory_silent(self):
        """存在しない customer_id でもエラーにならず、共通のみロード。"""
        from secure_review.ner_masker import NerMasker
        masker = NerMasker(
            seed_yaml_path=str(self.tmp / "ner_seeds.yaml"),
            allowlist_yaml_path="/nonexistent/allowlist.yaml",
            customer_id="nonexistent_customer",
            data_root=str(self.tmp),
        )
        ids = [p.get("id", "") for p in masker._ruler.patterns]
        self.assertIn("seed:phrase:Common", ids)


class CustomerAllowlistLoadingTests(unittest.TestCase):
    """customer_id 指定時に customers/<id>/tech_allowlist*.yaml が読まれること。"""

    @classmethod
    def setUpClass(cls):
        spacy_mod = sys.modules.get("spacy")
        if spacy_mod is None or isinstance(spacy_mod, MagicMock):
            raise unittest.SkipTest("Requires real spaCy installation")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # 共通 allowlist
        (self.tmp / "tech_allowlist.yaml").write_text(
            'tech:\n  - "AWS"\n  - "VPC"\n',
            encoding="utf-8",
        )
        # customer 固有 allowlist (手動)
        cust_dir = self.tmp / "customers" / "test_pj"
        cust_dir.mkdir(parents=True)
        (cust_dir / "tech_allowlist.yaml").write_text(
            'project:\n  - "MyTool"\n',
            encoding="utf-8",
        )
        # customer user allowlist (R-W-3 自動)
        (cust_dir / "tech_allowlist_user.yaml").write_text(
            'user_allowlist:\n  - "OurInternalAPI"\n',
            encoding="utf-8",
        )
        # 共通 seeds (空でも何でも良い、masker 起動のため)
        (self.tmp / "ner_seeds.yaml").write_text("phrases: []\n", encoding="utf-8")

    def test_loads_all_three_allowlists(self):
        """共通 + 顧客手動 + 顧客自動 が全部 _tech_allowlist にマージされる。"""
        from secure_review.ner_masker import NerMasker
        masker = NerMasker(
            seed_yaml_path=str(self.tmp / "ner_seeds.yaml"),
            allowlist_yaml_path=str(self.tmp / "tech_allowlist.yaml"),
            customer_id="test_pj",
            data_root=str(self.tmp),
        )
        # 大文字小文字無視で _tech_allowlist には小文字で格納
        self.assertIn("aws", masker._tech_allowlist)
        self.assertIn("vpc", masker._tech_allowlist)
        self.assertIn("mytool", masker._tech_allowlist)
        self.assertIn("ourinternalapi", masker._tech_allowlist)


if __name__ == "__main__":
    unittest.main()
