"""PR-G: NerMasker の技術用語 allowlist 機能のテスト。

spaCy / ja_core_news_md はテスト環境で利用できない場合があるため、
``sys.modules['spacy']`` レベルで spaCy をモックしてから ner_masker を
import する。これで _is_tech_term と _load_tech_allowlist の
ロジックを spaCy なしで検証できる。
extract_candidates の統合動作 (allowlist + EntityRuler) は spaCy が
利用可能な環境 (Streamlit Cloud) でのみ実機検証する。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock


# ner_masker.py を import する前に spaCy をモックしておく。
# これがないと "import spacy" の時点で ModuleNotFoundError になる。
def _install_spacy_mock() -> None:
    if "spacy" in sys.modules:
        return
    spacy_mock = MagicMock()
    spacy_mock.load = MagicMock()
    sys.modules["spacy"] = spacy_mock


def _install_models_mock() -> None:
    """secure_review.models をモック (NerCandidate を含む)。

    テスト環境にこのリポジトリの models.py の最新版がない場合への対応。
    NerCandidate は _is_tech_term / _load_tech_allowlist のテストでは
    使われないので、空の MagicMock で十分。
    """
    if "secure_review" not in sys.modules:
        # まだロードされていなければスタブを作る
        models_mock = MagicMock()
        models_mock.NerCandidate = MagicMock
        # secure_review パッケージ自体は実体の方を使うので、
        # secure_review.models だけをモックする
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


def _make_masker(allowlist_terms: list[str] | None = None):
    """テスト用 NerMasker を返す。

    spacy.load が MagicMock を返すよう mock 済み。allowlist YAML を
    一時ファイルに書き出してロードさせる。allowlist_terms=None なら
    allowlist は空 (path 不在シナリオのテスト用)。
    """
    from secure_review.ner_masker import NerMasker  # spacy mock 後に import

    # spacy.load の戻り値を構築 (pipe_names と add_pipe を持つ)
    mock_nlp = MagicMock()
    mock_nlp.pipe_names = []
    mock_nlp.add_pipe = MagicMock(return_value=MagicMock())
    sys.modules["spacy"].load.return_value = mock_nlp

    if allowlist_terms is None:
        # 存在しないパスを指定して allowlist を空のままに
        return NerMasker(
            seed_yaml_path="/nonexistent/seeds.yaml",
            allowlist_yaml_path="/nonexistent/allowlist.yaml",
        )

    tmpdir = tempfile.mkdtemp()
    yaml_path = Path(tmpdir) / "allowlist.yaml"
    yaml_text = "test_category:\n"
    for t in allowlist_terms:
        yaml_text += f'  - "{t}"\n'
    yaml_path.write_text(yaml_text, encoding="utf-8")

    return NerMasker(
        seed_yaml_path="/nonexistent/seeds.yaml",
        allowlist_yaml_path=str(yaml_path),
    )


class IsTechTermTests(unittest.TestCase):
    """_is_tech_term のテスト (PR-G)。"""

    def test_exact_match_returns_true(self) -> None:
        """完全一致なら True。"""
        m = _make_masker(["VPC", "DirectConnectGateway"])
        self.assertTrue(m._is_tech_term("VPC"))
        self.assertTrue(m._is_tech_term("DirectConnectGateway"))

    def test_case_insensitive_match(self) -> None:
        """大文字小文字を区別しない。"""
        m = _make_masker(["VPC", "DirectConnect"])
        self.assertTrue(m._is_tech_term("vpc"))
        self.assertTrue(m._is_tech_term("Vpc"))
        self.assertTrue(m._is_tech_term("DIRECTCONNECT"))
        self.assertTrue(m._is_tech_term("directconnect"))

    def test_non_match_returns_false(self) -> None:
        """allowlist にない用語は False。"""
        m = _make_masker(["VPC"])
        self.assertFalse(m._is_tech_term("KDDI"))
        self.assertFalse(m._is_tech_term("経済産業省"))
        self.assertFalse(m._is_tech_term("府中DC"))

    def test_partial_match_returns_false(self) -> None:
        """部分一致はしない (完全一致のみ)。"""
        m = _make_masker(["VPC"])
        self.assertFalse(m._is_tech_term("VPC設定"))
        self.assertFalse(m._is_tech_term("MyVPC"))
        self.assertFalse(m._is_tech_term("VPCs"))

    def test_whitespace_trimmed_in_input(self) -> None:
        """前後空白は無視されて比較される。"""
        m = _make_masker(["S3"])
        self.assertTrue(m._is_tech_term("  S3  "))
        self.assertTrue(m._is_tech_term("\tS3\n"))

    def test_empty_input_returns_false(self) -> None:
        """空文字や空白のみは False。"""
        m = _make_masker(["VPC"])
        self.assertFalse(m._is_tech_term(""))
        self.assertFalse(m._is_tech_term("   "))


class LoadTechAllowlistTests(unittest.TestCase):
    """_load_tech_allowlist のテスト (PR-G)。"""

    def _make_masker_with_yaml(self, yaml_content: str):
        from secure_review.ner_masker import NerMasker

        mock_nlp = MagicMock()
        mock_nlp.pipe_names = []
        mock_nlp.add_pipe = MagicMock(return_value=MagicMock())
        sys.modules["spacy"].load.return_value = mock_nlp

        tmpdir = tempfile.mkdtemp()
        yaml_path = Path(tmpdir) / "allowlist.yaml"
        yaml_path.write_text(yaml_content, encoding="utf-8")

        return NerMasker(
            seed_yaml_path="/nonexistent/seeds.yaml",
            allowlist_yaml_path=str(yaml_path),
        )

    def test_multiple_categories_flattened(self) -> None:
        """複数カテゴリがあっても 1 つの set にフラット化される。"""
        m = self._make_masker_with_yaml(
            'aws:\n  - "VPC"\n  - "S3"\nazure:\n  - "Azure"\n'
        )
        self.assertIn("vpc", m._tech_allowlist)
        self.assertIn("s3", m._tech_allowlist)
        self.assertIn("azure", m._tech_allowlist)
        self.assertEqual(len(m._tech_allowlist), 3)

    def test_empty_yaml_yields_empty_allowlist(self) -> None:
        """空の YAML でも例外なく空 set を返す。"""
        m = self._make_masker_with_yaml("")
        self.assertEqual(m._tech_allowlist, set())

    def test_non_list_categories_ignored(self) -> None:
        """list でないエントリは無視される (堅牢性)。"""
        m = self._make_masker_with_yaml(
            'aws:\n  - "VPC"\nbroken: "not a list"\n'
        )
        self.assertIn("vpc", m._tech_allowlist)
        self.assertEqual(len(m._tech_allowlist), 1)

    def test_nonexistent_path_silently_skipped(self) -> None:
        """allowlist YAML が存在しない場合、allowlist は空のまま。"""
        m = _make_masker(allowlist_terms=None)
        self.assertEqual(m._tech_allowlist, set())


if __name__ == "__main__":
    unittest.main()
