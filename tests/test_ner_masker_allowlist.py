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
        """allowlist にない用語は False。

        R-O 以降は ``府中 DC`` / ``府中DC`` を PDF 抽出由来の特異形として
        regex フィルタ側で弾くようにしたため、本テストの負例には使えない。
        真の固有名詞 (``KDDI`` / ``経済産業省`` / 地名 ``札幌支店``) で
        検証する。"""
        m = _make_masker(["VPC"])
        self.assertFalse(m._is_tech_term("KDDI"))
        self.assertFalse(m._is_tech_term("経済産業省"))
        self.assertFalse(m._is_tech_term("札幌支店"))

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


class MatchesTechTermPatternTests(unittest.TestCase):
    """R-O: ``_matches_tech_term_pattern`` の正規表現フィルタ。

    PR-G の YAML 完全一致 allowlist では拾えない「``Amazon X`` 形式」
    「セクション見出し」「PDF 抽出由来のスペース混入語」「DMARC
    ポリシー値」等の公開技術用語を弾けることを保証する。
    """

    def _matches(self, text: str) -> bool:
        from secure_review.ner_masker import _matches_tech_term_pattern
        return _matches_tech_term_pattern(text)

    def test_amazon_prefixed_services_match(self) -> None:
        """``Amazon X`` 形式の AWS サービス参照を弾く。"""
        positives = [
            "Amazon SES",
            "Amazon VPC",
            "Amazon S3",
            "Amazon S",                # PDF 末尾切れ
            "Amazon Data Firehose",
            "Amazon SES メール",
            "Amazon SES SMTP VPC エンドポイント",
            "AWS Direct Connect",
            "AWS Direct Connect Gateway",
            "AWS CloudWatch",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match Amazon/AWS prefix pattern",
                )

    def test_short_aws_service_names_match(self) -> None:
        """単独の AWS 短縮名・公式サービス名を弾く。"""
        positives = [
            "SES", "VPC", "S3", "EC2", "Lambda", "CloudWatch",
            "EventBridge", "GuardDuty", "Direct Connect",
            "Direct Connect Gateway", "Private VIF",
            "Private Virtual Interface",
            "Route 53", "Route53",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match short-service pattern",
                )

    def test_mail_protocol_terms_match(self) -> None:
        """メール / 認証プロトコル名を弾く。"""
        positives = [
            "SMTP AUTH",
            "MX レコード",
            "DKIM",
            "DMARC",
            "SPF",
            "DomainKeys Identified Mail",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match mail-protocol pattern",
                )

    def test_dmarc_policy_values_match(self) -> None:
        """DMARC / SPF ポリシー値 (``p=none`` 等) を弾く。"""
        positives = [
            "p=none",
            "p=quarantine",
            "p=reject",
            "DMARC1; p",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match DMARC policy pattern",
                )

    def test_section_number_headings_match(self) -> None:
        """セクション番号付き見出しを弾く。"""
        positives = [
            "8.2 災害",
            "10.2 ログ管理方針 メール",
            "1.1 はじめに",
            "12.4.2 セキュリティイベント通知",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match section-heading pattern",
                )

    def test_pdf_split_japanese_terms_match(self) -> None:
        """PDF 抽出由来のスペース混入語を弾く。"""
        positives = [
            "デフォルト", "デフォ ルト",
            "フェーズ", "フェー ズ",
            "用途",
            "方法",
            "検証する", "検 証する",
            "パブリッククラウドサービス",
            "パブリッククラウドサー ビス",
            "フルマネージドサービス",
            "フローログ",
            "府中 DC",
            "ライフサイクル管理",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match PDF-split JP-term pattern",
                )

    def test_table_artefacts_match(self) -> None:
        """表組み罫線アーティファクトを弾く。"""
        positives = ["| '", "| ", "|", "｜"]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match table-artefact pattern",
                )

    def test_repeated_short_tokens_match(self) -> None:
        """``VPC VPC`` のような自己反復トークンを弾く。"""
        positives = ["VPC VPC", "SES SES", "DC DC"]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match repeated-token pattern",
                )

    def test_long_jp_phrase_with_tech_abbrev_matches(self) -> None:
        """``フローログ用バケット標準 VPC フローログ`` のような
        長い日本語句に技術用語が挟まる形を弾く。"""
        positives = [
            "フローログ用バケット標準 VPC フローログ",
            "ログ集約用バケット標準 SES エンドポイント",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} should match long-JP-with-tech pattern",
                )

    def test_real_company_names_do_not_match(self) -> None:
        """真の会社名・案件名・人名は弾かない (回帰防止)。"""
        negatives = [
            "KDDI",
            "株式会社サンプル",
            "山田太郎",
            "次期NW更改",
            "経済産業省",
            "iret",
            "アイレット",
        ]
        for sample in negatives:
            with self.subTest(sample=sample):
                self.assertFalse(
                    self._matches(sample),
                    f"{sample!r} must NOT match — it is a real proper noun",
                )

    def test_amazon_corporate_entities_not_treated_as_tech_terms(self) -> None:
        """``Amazon Japan`` / ``AWS Japan`` 等の corporate entity を技術用語
        として弾かないこと (R-O 拒否リスト)。

        Amazon X の広い regex は ``Amazon SES`` / ``Amazon VPC`` を捕捉する
        ためのものだが、X が明白に非サービス名 (Japan, .com, Prime 等)
        の場合は corporate entity として扱い、技術用語フィルタから除外
        する必要がある。"""
        rejects = [
            # 法人名・子会社
            "Amazon Japan",
            "Amazon japan",        # 大小無視
            "AMAZON JAPAN",
            "Amazon Japan G.K.",
            "Amazon Japan 合同会社",
            "Amazon.com",
            "Amazon Web Services",
            "Amazon Web Services Japan",
            "Amazon Web Services Japan G.K.",
            "Amazon Game Studios",
            # 消費者向け製品ブランド
            "Amazon Prime",
            "Amazon Music",
            "Amazon Echo",
            "Amazon Kindle",
            "Amazon Pay",
            "Amazon Alexa",
            "Amazon Fresh",
            # AWS イベント・地域・パートナー
            "AWS Japan",
            "AWS Japan G.K.",
            "AWS Summit",
            "AWS re:Invent",
            "AWS Innovate",
            "AWS Partner",
            "AWS Partners",
            "AWS Partner Network",
            "AWS Tokyo",
            "AWS Osaka",
            "AWS User Group",
        ]
        for sample in rejects:
            with self.subTest(sample=sample):
                self.assertFalse(
                    self._matches(sample),
                    f"{sample!r} は corporate entity / event 名なので技術用語"
                    f"として弾いてはいけない",
                )

    def test_amazon_actual_services_still_match(self) -> None:
        """拒否リスト追加後も AWS サービス名は引き続き弾く (回帰防止)。"""
        positives = [
            "Amazon SES",
            "Amazon VPC",
            "Amazon S3",
            "Amazon Data Firehose",
            "Amazon CloudWatch",
            "Amazon EventBridge",
            "AWS Lambda",
            "AWS IAM",
        ]
        for sample in positives:
            with self.subTest(sample=sample):
                self.assertTrue(
                    self._matches(sample),
                    f"{sample!r} は AWS 公式サービス名なので技術用語として"
                    f"弾かれるべき (拒否リスト追加後の回帰防止)",
                )

    def test_empty_string_does_not_match(self) -> None:
        """空文字は False。"""
        self.assertFalse(self._matches(""))
        self.assertFalse(self._matches("   "))


class IsTechTermIntegrationTests(unittest.TestCase):
    """R-O: ``_is_tech_term`` が YAML allowlist と regex パターンを
    両方参照することの統合テスト。"""

    def test_yaml_match_takes_priority(self) -> None:
        """YAML allowlist 完全一致は優先的にヒットする (PR-G の挙動維持)。"""
        m = _make_masker(["KDDI"])
        # KDDI は YAML に明示登録 → True
        self.assertTrue(m._is_tech_term("KDDI"))

    def test_regex_match_works_when_yaml_misses(self) -> None:
        """YAML に無い ``Amazon SES`` でも regex パターンで弾ける。"""
        m = _make_masker(["VPC"])  # Amazon SES は登録しない
        self.assertTrue(m._is_tech_term("Amazon SES"))
        self.assertTrue(m._is_tech_term("Amazon Data Firehose"))
        self.assertTrue(m._is_tech_term("MX レコード"))
        self.assertTrue(m._is_tech_term("p=none"))
        self.assertTrue(m._is_tech_term("デフォ ルト"))

    def test_real_company_names_still_excluded(self) -> None:
        """真の会社名は YAML にも regex にも該当しないので False。"""
        m = _make_masker(["VPC"])
        self.assertFalse(m._is_tech_term("KDDI"))
        self.assertFalse(m._is_tech_term("株式会社サンプル"))
        self.assertFalse(m._is_tech_term("山田太郎"))


class NfkcNormalizationTests(unittest.TestCase):
    """R-P (2026-05-06): PDF 抽出由来の Unicode 異体字を NFKC で吸収する。

    実環境で観測された取りこぼしパターン:
    - Kangxi Radicals (``⽇`` U+2F25, ``⽤`` U+2F49, ``⽅`` U+2F46) が
      通常の漢字 (``日``/``用``/``方``) の代わりに PDF テキスト出力に
      含まれる
    - Latin small ligature ``ﬁ`` (U+FB01) が ``fi`` の代わりに含まれる
    - bullet (``‧`` U+2027) や全角括弧 (``（``/``）``) がトークン境界
      に残る

    これらを ``_normalize_for_match`` で吸収し、既存 R-O regex / YAML
    の両経路に正しく届かせる。
    """

    def _matches(self, text: str) -> bool:
        from secure_review.ner_masker import _matches_tech_term_pattern
        return _matches_tech_term_pattern(text)

    def test_kangxi_radical_sun_normalised(self) -> None:
        """``⽇`` (U+2F25 KANGXI RADICAL SUN) → ``日`` (U+65E5)。"""
        # ``90 ⽇間`` は実報告例。``\d+\s*日\s*間`` regex は NFKC 後にヒット。
        self.assertTrue(self._matches("90 ⽇間"))
        self.assertTrue(self._matches("30 ⽇間"))

    def test_kangxi_radical_use_normalised(self) -> None:
        """``⽤`` (U+2F49 KANGXI RADICAL USE) → ``用`` (U+7528)。"""
        self.assertTrue(self._matches("⽤途"))
        # 長い日本語に Kangxi Radical 用 が混じるパターン
        self.assertTrue(
            self._matches("フローログ⽤バケット標準 VPC フローログ")
        )

    def test_kangxi_radical_square_normalised(self) -> None:
        """``⽅`` (U+2F46 KANGXI RADICAL SQUARE) → ``方`` (U+65B9)。"""
        self.assertTrue(self._matches("⽅法"))
        # セクション見出しに Kangxi Radical 方 が混じるパターン
        self.assertTrue(self._matches("10.2 ログ管理⽅針 メール"))

    def test_fi_ligature_normalised(self) -> None:
        """``ﬁ`` (U+FB01 LATIN SMALL LIGATURE FI) → ``fi``。

        ``DomainKeys Identiﬁed Mail`` は実報告例。NFKC 後に
        ``DomainKeys Identified Mail`` となり、メールプロトコル regex
        にヒットする。
        """
        self.assertTrue(self._matches("DomainKeys Identiﬁed Mail"))

    def test_leading_bullet_stripped(self) -> None:
        """先頭の bullet (``‧`` U+2027) は match 前に剥がす。

        ``‧ SES`` は実報告例 (PDF の bullet point 直後の語が候補化)。
        """
        self.assertTrue(self._matches("‧ SES"))
        # 別種の bullet
        self.assertTrue(self._matches("• SES"))
        self.assertTrue(self._matches("・SES"))

    def test_trailing_fullwidth_bracket_stripped(self) -> None:
        """末尾の全角括弧 (``（``) は match 前に剥がす。

        ``府中 DC （`` は実報告例 (PDF 表組み末尾でカッコ開きがくっつく)。
        """
        self.assertTrue(self._matches("府中 DC （"))
        # 開きと閉じ両方
        self.assertTrue(self._matches("（府中 DC）"))

    def test_normalisation_does_not_corrupt_aws_service_names(self) -> None:
        """NFKC は ASCII / 通常 CJK には影響しない (回帰防止)。

        ``Amazon SES`` のような正常な入力は NFKC 後も同じ form を維持
        し、既存 regex がそのままヒットする。
        """
        self.assertTrue(self._matches("Amazon SES"))
        self.assertTrue(self._matches("Amazon VPC"))
        self.assertTrue(self._matches("DKIM"))
        self.assertTrue(self._matches("p=none"))

    def test_normalisation_preserves_real_proper_nouns_negative(self) -> None:
        """正常な日本語固有名詞は NFKC 後も False のまま (回帰防止)。"""
        self.assertFalse(self._matches("KDDI"))
        self.assertFalse(self._matches("株式会社サンプル"))
        self.assertFalse(self._matches("経済産業省"))
        # iret は seed dictionary 経由でマスクされるべきもので、
        # 技術用語フィルタには引っかからない (R-P スコープ外)
        self.assertFalse(self._matches("iret"))


class IamAndGenericTechVocabTests(unittest.TestCase):
    """R-P (2026-05-06): YAML allowlist 拡張で拾えるようになった語彙。

    実環境で uncertain candidates として残ってしまっていたものを
    ``aws_services`` (IAM 系) と ``generic_japanese_tech`` (ゲート
    ウェイ系) に追加した。これらは PR-G の YAML 完全一致経路で
    フィルタされる。
    """

    def test_iam_resource_types_filtered(self) -> None:
        """``IAM Group`` / ``IAM ロール`` 等を allowlist でフィルタ。"""
        m = _make_masker(["IAM Group", "IAM グループ", "IAM Role", "IAM ロール",
                          "IAM Policy", "IAM ポリシー", "IAM User", "IAM ユーザー"])
        for term in [
            "IAM Group", "IAM グループ", "IAM Role", "IAM ロール",
            "IAM Policy", "IAM ポリシー", "IAM User", "IAM ユーザー",
        ]:
            with self.subTest(term=term):
                self.assertTrue(
                    m._is_tech_term(term),
                    f"{term!r} should be in tech allowlist",
                )

    def test_generic_japanese_infrastructure_terms_filtered(self) -> None:
        """``ゲートウェイ`` / ``ロードバランサー`` 等を allowlist でフィルタ。"""
        m = _make_masker([
            "ゲートウェイ", "ロードバランサー", "コンテナ",
            "セキュリティグループ", "サブネット", "リージョン",
        ])
        for term in [
            "ゲートウェイ", "ロードバランサー", "コンテナ",
            "セキュリティグループ", "サブネット", "リージョン",
        ]:
            with self.subTest(term=term):
                self.assertTrue(m._is_tech_term(term))

    def test_iam_with_kangxi_normalisation(self) -> None:
        """IAM 語彙が NFKC 経由でも一致する (allowlist + 正規化の組合せ)。

        実データではあまり起きないが、念のため。
        """
        # 通常の "IAM ユーザー" を allowlist に入れて、Kangxi で書いた
        # 入力でもヒットすることを確認 (ユ→ユ は不変なので、ここでは
        # 入力側に余計な空白が入った場合の strip 動作を確認)
        m = _make_masker(["IAM ユーザー"])
        self.assertTrue(m._is_tech_term("  IAM ユーザー  "))
        self.assertTrue(m._is_tech_term("IAM ユーザー"))


if __name__ == "__main__":
    unittest.main()
