"""R-M PR-B: NerMasker のテスト。

handoff 判断 5 のテスト方針に従う:
- 単体ロジック: spacy.blank("ja") + EntityRuler のみで検証
- 実モデル (ja_core_news_md) はテストで使わない
- 統計 NER の挙動は対象外 (実機 Diagnostics で確認)

設計判断 (PR-B 実装時):
- SudachiPy のトークナイズ挙動と suffixes/honorifics 設計が不適合だった
  ため、Phase 1 では phrases のみを採用。本テストも phrases 関連のみを
  カバーする。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import spacy

from secure_review import ner_masker as nm_module


def _make_blank_ner_masker(yaml_content: str) -> "nm_module.NerMasker":
    """spacy.load を spacy.blank('ja') に差し替えた NerMasker を作る。

    blank モデルには ner / tok2vec / doc_cleaner などはないので、
    EntityRuler のみで動作する純粋なシード辞書マッチャーになる。
    """
    blank = spacy.blank("ja")

    with tempfile.TemporaryDirectory() as tmpdir:
        yaml_path = Path(tmpdir) / "ner_seeds.yaml"
        yaml_path.write_text(yaml_content, encoding="utf-8")

        with patch.object(nm_module.spacy, "load", return_value=blank):
            return nm_module.NerMasker(seed_yaml_path=yaml_path)


class NerMaskerSeedDictTests(unittest.TestCase):
    """シード辞書 (phrases) ヒットの基本契約。"""

    def test_phrase_hit_is_confirmed(self) -> None:
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "KDDI"\n    label: ORG\n'
        )
        candidates = masker.extract_candidates("KDDI 様の府中DCで作業します")
        kddi = [c for c in candidates if c.text == "KDDI"]
        self.assertEqual(len(kddi), 1)
        self.assertTrue(kddi[0].confirmed)
        self.assertEqual(kddi[0].source, "seed_dict")
        self.assertEqual(kddi[0].label, "COMPANY")
        self.assertEqual(kddi[0].spacy_label, "ORG")

    def test_canonical_normalizes_alias(self) -> None:
        """別名は canonical に正規化される。"""
        masker = _make_blank_ner_masker(
            'version: 1\n'
            'phrases:\n'
            '  - text: "KDDIアイレット"\n    label: ORG\n'
            '  - text: "アイレット"\n    label: ORG\n    canonical: "KDDIアイレット"\n'
        )
        candidates = masker.extract_candidates("アイレットの開発チーム")
        names = {c.text for c in candidates}
        self.assertIn("KDDIアイレット", names)
        self.assertNotIn("アイレット", names)

    def test_duplicate_occurrences_collapse_to_one_candidate(self) -> None:
        """同じ候補が複数箇所に出現しても 1 つだけ返る (項目 e 不変条件)。"""
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "KDDI"\n    label: ORG\n'
        )
        candidates = masker.extract_candidates("KDDI と KDDI と KDDI")
        kddi = [c for c in candidates if c.text == "KDDI"]
        self.assertEqual(len(kddi), 1)


class NerMaskerLabelMappingTests(unittest.TestCase):
    """spaCy ラベル → 既存マスクカテゴリのマッピング (handoff 判断 3)。"""

    def test_org_maps_to_company(self) -> None:
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "TestOrg"\n    label: ORG\n'
        )
        candidates = masker.extract_candidates("TestOrg について")
        self.assertEqual(candidates[0].label, "COMPANY")

    def test_gpe_maps_to_site(self) -> None:
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "東京"\n    label: GPE\n'
        )
        candidates = masker.extract_candidates("東京で会議")
        self.assertEqual(candidates[0].label, "SITE")

    def test_fac_maps_to_site(self) -> None:
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "府中DC"\n    label: FAC\n'
        )
        candidates = masker.extract_candidates("府中DC 訪問")
        self.assertEqual(candidates[0].label, "SITE")

    def test_person_maps_to_person(self) -> None:
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "山田太郎"\n    label: PERSON\n'
        )
        candidates = masker.extract_candidates("山田太郎 担当")
        self.assertEqual(candidates[0].label, "PERSON")

    def test_product_label_is_skipped(self) -> None:
        """PRODUCT は素通し (handoff 判断 3): 候補に含まれない。"""
        masker = _make_blank_ner_masker(
            'version: 1\nphrases:\n  - text: "Linux"\n    label: PRODUCT\n'
        )
        candidates = masker.extract_candidates("Linux で動作")
        self.assertEqual(candidates, [])


class NerMaskerEdgeCaseTests(unittest.TestCase):
    """境界条件。"""

    def test_empty_yaml_is_safe(self) -> None:
        """空のシード YAML でも例外を出さず空候補リストを返す。"""
        masker = _make_blank_ner_masker(
            'version: 1\nphrases: []\ntoken_patterns: []\n'
        )
        self.assertEqual(masker.extract_candidates("何もヒットしないテキスト"), [])

    def test_missing_yaml_file_does_not_crash(self) -> None:
        """シード YAML が存在しない場合も初期化は成功する。"""
        blank = spacy.blank("ja")
        with patch.object(nm_module.spacy, "load", return_value=blank):
            masker = nm_module.NerMasker(seed_yaml_path="/nonexistent/path.yaml")
        # シード辞書ゼロでも extract_candidates は動く
        self.assertEqual(masker.extract_candidates("text"), [])

    def test_add_phrase_runtime_addition(self) -> None:
        """セッション内ユーザ追加が即座に反映される。"""
        masker = _make_blank_ner_masker(
            'version: 1\nphrases: []\n'
        )
        before = masker.extract_candidates("MyCompany について")
        masker.add_phrase("MyCompany", label="ORG")
        after = masker.extract_candidates("MyCompany について")

        self.assertEqual(before, [])
        self.assertEqual(len(after), 1)
        self.assertTrue(after[0].confirmed)


if __name__ == "__main__":
    unittest.main()
