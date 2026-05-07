"""R-M Phase 1: spaCy NER + EntityRuler + シード辞書による候補抽出。

責務:
- spaCy パイプラインの構築・保持 (Memory Zone + doc_cleaner)
- シード YAML のロードと EntityRuler パターン化
- テキストからのエンティティ候補抽出 (NerCandidate のリスト)

責務外 (呼び出し側で行う):
- gBizINFO 検索 (hojin_lookup.py) → PR-C
- マスク適用とテキスト書き換え (run_masking_pipeline) → PR-D
- 台帳組み込み (sanitizer.register_ner_finding 経由) → PR-A 完了済み

設計判断 (PR-B 実装時の発見):
- SudachiPy が日本語複合語を分割するため、「サフィックス + 1 トークン」
  のような token pattern では句読点・助詞を巻き込む誤検出が多発する。
- そのため Phase 1 では phrases のみとし、suffixes / honorifics は採用
  しない。未知の企業名は後段の統計 NER とユーザ確認 UI (PR-D) で拾う。
"""
from __future__ import annotations

import re
import unicodedata
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import spacy
import yaml

from secure_review.models import NerCandidate

# spaCy ラベル → 既存マスクカテゴリ (handoff 判断 3)
# PRODUCT は意図的に含めない (技術用語として LLM レビューに有用なので素通し)
SPACY_TO_MASK_CATEGORY: dict[str, str] = {
    "ORG": "company",
    "GPE": "site",
    "FAC": "site",
    "PERSON": "person",
}


# R-O (2026-05-05): pattern-based tech-term filter for spaCy mis-detections
# that the YAML allowlist cannot reach.
#
# Background. PR-G's `_is_tech_term` did exact-match-only on a YAML list.
# Real-world Japanese AWS design docs produced spaCy NER hits that the
# YAML cannot enumerate practically:
#
#   1. Compound public-service references (``Amazon SES``, ``Amazon VPC``,
#      ``Amazon Data Firehose``, ``Amazon SES SMTP VPC エンドポイント``) —
#      enumerating every (Amazon, AWS) × (service-name) × (suffix) is
#      hopeless and brittle.
#   2. PDF extraction inserts stray spaces inside Japanese words
#      (``デフォ ルト``, ``フェー ズ``, ``検 証する``, ``パブリック
#      クラウドサー ビス``, ``府中 DC``). These never hit an exact-match
#      list because the surface form is broken.
#   3. Section-number headings the NER picks up as ORG/PERSON/SITE
#      (``8.2 災害``, ``10.2 ログ管理方針 メール``, ``SLA 障害``).
#   4. Mail-protocol vocabulary (``MX レコード``, ``DKIM``, ``DomainKeys
#      Identified Mail``, ``DMARC``, ``SMTP AUTH``, ``p=none``,
#      ``p=quarantine``, ``DMARC1; p``).
#   5. PDF table-cell artefacts (``| '``, ``VPC VPC``, ``フローログ用
#      バケット標準 VPC フローログ``).
#
# This regex layer is consulted *in addition to* `_tech_allowlist`. A
# match here means the candidate is a public technical reference and
# should not be masked. Seed-dictionary hits (`confirmed=True`) bypass
# this filter because they were explicitly registered as something the
# operator wants masked.
# R-O: rejection list applied BEFORE the tech-term patterns. If a value
# matches one of these "Amazon X" / "AWS X" forms where X is clearly NOT
# an AWS service name (e.g. ``Amazon Japan`` is a real company, not a
# service), the value is treated as a regular candidate instead of a
# public technical term. This prevents the broad ``Amazon\s+\w+`` rule
# from accidentally exempting legitimate corporate names.
_TECH_TERM_REJECT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Amazon X where X is a known non-AWS-service noun (corporate
    # subsidiary, consumer product, region/locale name).
    re.compile(
        r"^\s*Amazon\s+"
        r"(?:Japan|Japan\s+G\.?K\.?|Japan\s+合同会社|"
        r"\.com|"
        r"Web\s+Services?(?:\s+Japan(?:\s+G\.?K\.?)?)?|"
        r"Prime|Music|Echo|Kindle|Alexa|Fresh|Pay|"
        r"Pharmacy|Robotics|Studios|Books|"
        r"Game\s+Studios|"
        r"Marketplace|Mechanical\s+Turk|"
        r"Logistics)\s*$",
        re.IGNORECASE,
    ),
    # AWS X where X is a non-service noun (re:Invent / Summit etc.,
    # plus partner / event / region naming forms).
    re.compile(
        r"^\s*AWS\s+(?:Japan|Japan\s+G\.?K\.?|"
        r"Summit|re:Invent|Reinvent|Loft|Innovate|"
        r"Partner(?:s|\s+Network)?|"
        r"Tokyo|Osaka|Singapore|Sydney|"
        r"User\s+Group|UG)\s*$",
        re.IGNORECASE,
    ),
)


_TECH_TERM_REGEX_PATTERNS: tuple[re.Pattern[str], ...] = (
    # AWS / Amazon prefixed service references with optional trailing
    # technical noun. Catches ``Amazon SES``, ``Amazon Data Firehose``,
    # ``Amazon S3``, ``AWS CloudWatch``, ``Amazon SES SMTP VPC エンドポイント``,
    # ``Amazon VPC``, ``Amazon S`` (PDF truncation), etc.
    re.compile(
        r"^\s*(?:Amazon|AWS)\s+"
        r"[A-Za-z0-9][A-Za-z0-9 ./\-]{0,60}"
        r"(?:\s+(?:メール|エンドポイント|レコード|サービス|"
        r"フロー(?:ログ)?|バケット|ゲートウェイ|プロトコル|"
        r"SMTP(?:\s+VPC\s+エンドポイント)?|VPC(?:\s+エンドポイント)?))?"
        r"\s*$",
        re.IGNORECASE,
    ),
    # AWS short service names + standard internet protocols + common
    # infrastructure abbreviations, alone or followed by a trailing
    # technical noun. Catches ``SES``, ``VPC``, ``Direct Connect Gateway``,
    # ``Private VIF``, ``MX レコード``, ``DKIM``, ``SMTP AUTH``, ``Route 53``,
    # ``NLB``, ``EventBridge``, ``GuardDuty``, ``CloudWatch``, etc.
    re.compile(
        r"^\s*"
        r"(?:SES|S3|EC2|VPC|VIF|VPN|SNS|SQS|IAM|RDS|EBS|ELB|ALB|NLB|"
        r"KMS|ACM|WAF|CloudWatch|CloudFront|CloudTrail|CloudShell|"
        r"Route\s*53|Lambda|EventBridge|GuardDuty|Config|Athena|"
        r"Firehose|Backlog|AMS|"
        r"Direct\s*Connect(?:\s+Gateway)?|"
        r"(?:Private|Public)\s+VIF|"
        r"(?:Private|Public)\s+Virtual\s+Interface|"
        r"SMTP(?:S)?|IMAP|POP3|HTTP|HTTPS|TLS|SSL|SSH|FTP|SFTP|"
        r"NTP|DNS|DKIM|DMARC|SPF|MX|AUTH|"
        r"DomainKeys\s+Identified\s+Mail|"
        r"BGP|OSPF|VRRP|HSRP|VLAN|NAT|ACL|CIDR)"
        r"(?:\s+(?:AUTH|レコード|エンドポイント|プロトコル|サービス|"
        r"VPC(?:\s+エンドポイント)?|SMTP(?:\s+VPC\s+エンドポイント)?))?"
        r"\s*$",
        re.IGNORECASE,
    ),
    # DMARC / SPF policy values. ``p=none``, ``p=quarantine``, ``p=reject``,
    # also the mangled ``DMARC1; p`` from PDF text extraction.
    re.compile(
        r"^\s*(?:DMARC\d*\s*[;:]?\s*)?[a-z]{1,3}=[A-Za-z][A-Za-z0-9_\-]*\s*$",
        re.IGNORECASE,
    ),
    re.compile(r"^\s*DMARC\d*\s*[;:]?\s*[a-z]\s*$", re.IGNORECASE),
    # Section-number headings: ``8.2 災害``, ``10.2 ログ管理方針 メール``.
    # Numeric prefix (``N`` or ``N.M`` or ``N.M.K``) followed by a short
    # Japanese phrase. Limit phrase to 30 chars to keep this conservative.
    re.compile(
        r"^\s*\d+(?:\.\d+){0,3}\s+"
        r"[\u3040-\u30FF\u4E00-\u9FFFA-Za-z][\u3040-\u30FF\u4E00-\u9FFFA-Za-z0-9 ]{0,30}"
        r"\s*$"
    ),
    # ``SLA 障害``, ``VPC VPC``, ``ライフサイクル管理`` and similar tech-noun
    # phrases that spaCy mis-tags. Pattern: a recognised tech abbreviation
    # or katakana noun followed by a short Japanese / English noun.
    re.compile(
        r"^\s*(?:SLA|SLO|SLI|SOC|RPO|RTO|MFA|VPC|DNS|DC|AZ|API|CLI|UI|UX|"
        r"VPN|NAT|ACL|MX|TLS|SSL|DKIM|DMARC|SPF|TCP|UDP|SES|S3)"
        r"\s+"
        r"[\u3040-\u30FF\u4E00-\u9FFFA-Za-z][\u3040-\u30FF\u4E00-\u9FFFA-Za-z0-9 ]{0,30}"
        r"\s*$",
        re.IGNORECASE,
    ),
    # Self-repeating short tokens (``VPC VPC``, ``SES SES``) — typical of
    # PDF column-header repetition. Two short identical alphanumeric tokens
    # separated by whitespace.
    re.compile(r"^\s*([A-Za-z][A-Za-z0-9]{1,5})\s+\1\s*$"),
    # ``フローログ用バケット標準 VPC フローログ`` shape: long Japanese
    # noun phrase containing a public technical abbreviation.
    re.compile(
        r"^\s*[\u3040-\u30FF\u4E00-\u9FFFA-Za-z][\u3040-\u30FF\u4E00-\u9FFFA-Za-z0-9 ]{2,80}"
        r"\s+(?:VPC|DNS|VPN|VIF|SES|S3|SMTP|DKIM|DMARC|SPF|MX|TLS|TCP|UDP)"
        r"\s+[\u3040-\u30FF\u4E00-\u9FFFA-Za-z][\u3040-\u30FF\u4E00-\u9FFFA-Za-z0-9 ]{0,40}\s*$",
        re.IGNORECASE,
    ),
    # Stray punctuation / table-cell artefacts: ``| '``, ``| ``, etc.
    # Requires at least one bar / quote character so pure whitespace
    # does not match.
    re.compile(r"^\s*[|｜][|｜\u3000\s'`\"]*[A-Za-z0-9 ]{0,4}\s*$"),
    # Generic infrastructure / cloud-provider single tokens (extends the
    # YAML list with case-insensitive coverage and a few common omissions).
    re.compile(
        r"^\s*(?:AWS|GCP|OCI|Azure|Amazon|Google|Microsoft|Oracle|"
        r"VPC|DC|AZ|MFA|RBAC|ABAC|SLA|SLO|SLI|SOC|RPO|RTO|"
        r"API|CLI|GUI|SDK|UI|UX|CSV|TSV|TIFF|JPEG|PNG|GIF|PDF|"
        r"DKIM|DMARC|SPF|MX|SMTP|IMAP|POP3|TLS|SSL|HTTPS?|"
        r"TCP|UDP|ICMP|IPSec|RADIUS|LDAP|JSON|XML|YAML|"
        r"JWT|OAuth2?|SAML|OIDC|JOSE|JWE|JWS|JWK|"
        r"Backlog|Slack|GitHub|GitLab|Jira|"
        r"PagerDuty|Datadog|Splunk|"
        r"Kubernetes|Docker|Terraform|Ansible|Chef|Puppet|"
        r"Linux|Windows|macOS|Ubuntu|CentOS|RHEL|Debian|"
        r"Python|Java|Ruby|Go|Rust|TypeScript|JavaScript|"
        r"React|Vue|Angular|Next\.?js|Nuxt|Svelte)\s*$",
        re.IGNORECASE,
    ),
    # Generic Japanese technical terms that look identifier-ish but are
    # not sensitive: ``デフォルト``, ``フェーズ``, ``用途``, ``方法``,
    # ``パブリッククラウドサービス``, ``フルマネージドサービス``,
    # ``オンプレミス``, ``オンプレミス環境`` etc.
    # Also tolerates the PDF-injected stray space (``デフォ ルト``,
    # ``フェー ズ``, ``検 証する``, ``パブリッククラウドサー ビス``,
    # ``府中 DC``) by allowing optional whitespace anywhere inside.
    re.compile(
        r"^\s*(?:"
        r"パ\s*ブ\s*リ\s*ッ\s*ク\s*ク\s*ラ\s*ウ\s*ド(?:\s*サ\s*ー?\s*ビ\s*ス)?|"
        r"フ\s*ル\s*マ\s*ネ\s*ー?\s*ジ\s*ド\s*サ\s*ー?\s*ビ\s*ス|"
        r"オ\s*ン\s*プ\s*レ\s*ミ\s*ス(?:\s*環\s*境)?|"
        r"プ\s*ラ\s*イ\s*ベ\s*ー?\s*ト\s*サ\s*ブ\s*ネ\s*ッ\s*ト|"
        r"パ\s*ブ\s*リ\s*ッ\s*ク\s*サ\s*ブ\s*ネ\s*ッ\s*ト|"
        r"デ\s*フ\s*ォ\s*ル\s*ト|"
        r"フ\s*ェ\s*ー?\s*ズ|"
        r"用\s*途|方\s*法|"
        r"検\s*証(?:\s*す\s*る)?|"
        r"ラ\s*イ\s*フ\s*サ\s*イ\s*ク\s*ル(?:\s*管\s*理)?|"
        r"フ\s*ロ\s*ー?\s*ロ\s*グ(?:\s*用\s*バ\s*ケ\s*ッ\s*ト)?|"
        r"\d+\s*日\s*間"
        r")\s*$"
    ),
)


# R-P (2026-05-06): characters stripped from token boundaries before
# tech-term matching. PDF table-cell extraction can leave bullets,
# brackets, and stray quotation marks attached to a token. The default
# ``str.strip()`` handles only whitespace, so we extend the set to
# cover the symbols seen on real design docs:
#   - ‧ (U+2027 HYPHENATION POINT) — leading bullet observed before "SES"
#   - ・ (U+30FB KATAKANA MIDDLE DOT) — Japanese bullet
#   - • (U+2022 BULLET) — generic bullet
#   - ｟ ｠ ﹝ ﹞ etc. via NFKC reduction (handled elsewhere)
#   - （ ） full-width brackets — observed trailing on "府中 DC （"
#   - 「 」『 』 Japanese quotation brackets
#   - 【 】 black lenticular brackets used for headings
#   - U+3000 IDEOGRAPHIC SPACE
_TRIM_CHARS = (
    " \t\n\r"
    "\u3000"          # IDEOGRAPHIC SPACE
    "\u2027"          # HYPHENATION POINT
    "\u00B7"          # MIDDLE DOT
    "\u2022"          # BULLET
    "\u30FB"          # KATAKANA MIDDLE DOT
    "\uFF65"          # HALFWIDTH KATAKANA MIDDLE DOT
    "()[]{}（）「」『』【】〈〉《》"
    "\"'`"
)


def _normalize_for_match(text: str) -> str:
    """Return ``text`` after NFKC + extended trim, for tech-term matching.

    Two transformations:

    1. NFKC normalisation. Collapses Kangxi Radicals (``⽇`` U+2F25,
       ``⽤`` U+2F49, ``⽅`` U+2F46) into their CJK Unified counterparts
       (``日`` U+65E5, ``用`` U+7528, ``方`` U+65B9), and reduces
       ligatures (``ﬁ`` U+FB01 → ``fi``). PDF extractors emit these
       compatibility code points whenever the embedded font's CMap
       maps glyphs to compatibility ranges instead of unified ones.
    2. Strip extended punctuation. Beyond whitespace, removes bullets
       and brackets sometimes left attached to tokens by table-cell
       extraction (``‧ SES``, ``府中 DC （``).

    The original text is intentionally preserved by callers — only
    the comparison key is normalised. This way, when a token IS to be
    masked, the un-normalised surface form remains the search key and
    the mask still lands on the actual character sequence in the
    source document.
    """
    if not text:
        return ""
    nfkc = unicodedata.normalize("NFKC", text)
    return nfkc.strip(_TRIM_CHARS)


def _matches_tech_term_pattern(text: str) -> bool:
    """Return True iff ``text`` matches any R-O regex pattern.

    Used in addition to the YAML-based exact-match allowlist. The
    intent is to catch families of public-technical-term shapes that
    cannot be enumerated literally (``Amazon X``, section headings,
    PDF-extraction artefacts, etc.). Seed-dictionary hits should
    bypass this — the caller is responsible for that gate.

    A small reject list (``_TECH_TERM_REJECT_PATTERNS``) is consulted
    *first* to handle ``Amazon X`` / ``AWS X`` forms where ``X`` is
    clearly NOT a service name (e.g. ``Amazon Japan`` is a real
    corporate entity, not a service). Reject-list hits return False
    immediately so the broader allow-pattern does not exempt them.

    R-P (2026-05-06): input is NFKC-normalised and trimmed of
    bullet/bracket symbols before matching. PDF extraction in the
    wild produces Kangxi Radicals (``⽇`` U+2F25 instead of ``日``,
    ``⽤``/``⽅`` similarly) and ligatures (``ﬁ`` instead of ``fi``)
    because the underlying font's CMap points at compatibility code
    points. NFKC collapses both. The trim list also drops bullet
    points (``‧`` U+2027, ``・`` U+30FB) and stray brackets that
    table-cell extraction can leave attached to a token.
    """
    if not text:
        return False
    stripped = _normalize_for_match(text)
    if not stripped:
        return False
    # Reject list: things that look like ``Amazon X`` but are corporate
    # entities, not AWS services. These must NOT be treated as public
    # technical terms.
    for pattern in _TECH_TERM_REJECT_PATTERNS:
        if pattern.fullmatch(stripped):
            return False
    for pattern in _TECH_TERM_REGEX_PATTERNS:
        if pattern.fullmatch(stripped):
            return True
    return False


class NerMasker:
    """spaCy NER + EntityRuler + シード辞書を統合したエンティティ抽出器。

    プロセス内シングルトンとして使うことを想定 (Streamlit 側で
    @st.cache_resource を付けてキャッシュ)。spaCy モデルロードが重い
    (RAM ~462 MB) ため再ロードは避ける。
    """

    def __init__(
        self,
        seed_yaml_path: str | Path = "data/ner_seeds.yaml",
        model_name: str = "ja_core_news_md",
        allowlist_yaml_path: str | Path = "data/tech_allowlist.yaml",
    ) -> None:
        self._nlp = spacy.load(model_name)
        # tok2vec の中間 tensor をクリアしてメモリ抑制 (handoff 判断 5)
        if "doc_cleaner" not in self._nlp.pipe_names:
            self._nlp.add_pipe("doc_cleaner", config={"attrs": {"tensor": None}})

        # EntityRuler を NER の前に挿入 (シード辞書ヒットを優先)
        # blank モデルでは ner pipe がないので before 指定が失敗する。
        # その場合は last (デフォルト) で追加する。
        if "ner" in self._nlp.pipe_names:
            self._ruler = self._nlp.add_pipe("entity_ruler", before="ner")
        else:
            self._ruler = self._nlp.add_pipe("entity_ruler")

        # シード YAML をロードして EntityRuler に投入
        self._canonical_map: dict[str, str] = {}  # text -> canonical name
        seed_path = Path(seed_yaml_path)
        if seed_path.exists():
            self._load_seeds(seed_path)

        # PR-G: 技術用語 allowlist (AWS / Azure / GCP のサービス名・概念用語)
        # を読み込む。ここに含まれる用語は spaCy が誤検知しても候補から除外する。
        self._tech_allowlist: set[str] = set()
        allowlist_path = Path(allowlist_yaml_path)
        if allowlist_path.exists():
            self._load_tech_allowlist(allowlist_path)

    def _load_seeds(self, path: Path) -> None:
        """シード YAML をロードし EntityRuler パターンに変換する。"""
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        patterns: list[dict[str, Any]] = []

        # phrases: 完全一致 string pattern (spaCy が内部でトークン化してマッチ)
        # R-S (2026-05-07): 各エントリに任意の ``confirm: false`` フラグを
        # 付けることで「強制検出するが auto-mask せず uncertain candidate に
        # まわす」watchlist 動作になる。確定機密 (顧客名など、ID 接頭辞
        # ``seed:``) と区別するため、watchlist エントリは ID 接頭辞 ``watch:``
        # を付ける。下流の ``extract_candidates`` で接頭辞を見て confirmed
        # フラグを切り替える。
        for entry in data.get("phrases", []) or []:
            text = entry["text"]
            label = entry["label"]
            canonical = entry.get("canonical") or text
            confirm_flag = entry.get("confirm", True)
            id_prefix = "seed" if confirm_flag else "watch"
            patterns.append(
                {
                    "label": label,
                    "pattern": text,
                    "id": f"{id_prefix}:phrase:{canonical}",
                }
            )
            if canonical != text:
                self._canonical_map[text] = canonical

        # token_patterns: 脱出ハッチ (そのまま投入)
        for entry in data.get("token_patterns", []) or []:
            patterns.append(entry)

        if patterns:
            self._ruler.add_patterns(patterns)

    def _load_tech_allowlist(self, path: Path) -> None:
        """技術用語 allowlist YAML をロードして set に保持する (PR-G)。

        YAML はカテゴリ別の dict になっているが、ここでは単純に
        全エントリを 1 つの set に flatten する (カテゴリは人間が
        メンテナンスしやすくするためだけのもの、コード側では区別不要)。

        比較は大文字小文字を区別しないので、ここで lowercase に正規化
        してから格納する。

        R-P (2026-05-06): エントリも NFKC + 拡張 strip を通してから
        格納する。YAML 編集者が誤って Kangxi Radical を貼り付けた
        ような場合でも、入力側の NFKC 正規化と form を揃えるため。
        """
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        for category_items in data.values():
            if not isinstance(category_items, list):
                continue
            for entry in category_items:
                if isinstance(entry, str) and entry.strip():
                    self._tech_allowlist.add(_normalize_for_match(entry).lower())

    def _is_tech_term(self, text: str) -> bool:
        """text が技術用語 allowlist に含まれていれば True (PR-G + R-O + R-P)。

        2 段構え:
          1. PR-G の YAML allowlist (大文字小文字無視・完全一致)
          2. R-O の regex パターン群 (``Amazon X`` / セクション見出し /
             PDF 抽出由来のスペース混入語 / DMARC ポリシー値 等を網羅)

        R-P (2026-05-06): 比較前に ``_normalize_for_match`` を通す。
        PDF 抽出由来の Kangxi Radical (``⽇`` ``⽤`` ``⽅``) や ligature
        (``ﬁ``) を NFKC で吸収し、bullet / 全角括弧などのトークン境界
        ゴミも除去してから allowlist と比較する。``_matches_tech_term_pattern``
        側でも同じ正規化が走るため二度手間に見えるが、YAML 一致の
        早期 return パスのために必要。

        いずれかにヒットすれば True。シード辞書ヒットは呼び出し側で
        除外されているので、本メソッドは confirmed=False の候補に
        対してのみ意味を持つ。
        """
        normalized = _normalize_for_match(text).lower()
        if normalized in self._tech_allowlist:
            return True
        # R-O + R-P: pattern-based filter, also normalises internally.
        return _matches_tech_term_pattern(text)

    def add_phrase(self, text: str, label: str = "ORG") -> None:
        """セッション内ユーザ追加用 (永続化なし)。

        UI から「次回もこの語をマスク」要望が来た時に呼ぶ想定。
        プロセス再起動でリセットされる (handoff 判断 1: SQLite 永続化なし)。
        """
        self._ruler.add_patterns(
            [{"label": label, "pattern": text, "id": f"user:{text}"}]
        )

    def extract_candidates(self, text: str) -> list[NerCandidate]:
        """テキストからエンティティ候補を抽出する。

        Memory Zone 内で spaCy パイプラインを実行し、抽出後すぐに
        NerCandidate に変換することで Doc オブジェクトを早期解放する。

        Returns:
            NerCandidate のリスト。confirmed=True はシード辞書ヒット
            (EntityRuler 由来)、confirmed=False は統計 NER のみのヒット。
            PRODUCT 等のマッピング外ラベルは除外される。
            重複 (同一 text + label) は最初の出現位置のみ残す。
        """
        candidates: list[NerCandidate] = []
        seen_keys: set[tuple[str, str]] = set()  # (text, label) で重複排除

        # spaCy 3.8+ では memory_zone() が利用可能
        # 3.7 系へのフォールバック
        zone = (
            self._nlp.memory_zone()
            if hasattr(self._nlp, "memory_zone")
            else nullcontext()
        )
        with zone:
            doc = self._nlp(text)
            for ent in doc.ents:
                spacy_label = ent.label_
                category = SPACY_TO_MASK_CATEGORY.get(spacy_label)
                if category is None:
                    continue  # PRODUCT 等は素通し

                # PR-G: 技術用語 allowlist チェック。シード辞書ヒット
                # (EntityRuler 経由) は通すが、spaCy 統計 NER の誤検知
                # (例: 「DirectConnectGateway」を PERSON と誤判定) を弾く。
                # シード辞書側で同じ用語を意図的に登録した場合は
                # confirmed=True として通したいので、ent_id_ で seed/user
                # 由来を確認してからフィルタする。
                # R-S (2026-05-07): watchlist (confirm: false) 由来も dict_match
                # として tech-term filter を素通りさせる。confirmed フラグだけが
                # 後段で異なる扱いになる。
                is_dict_match = bool(ent.ent_id_) and (
                    ent.ent_id_.startswith("seed:")
                    or ent.ent_id_.startswith("user:")
                    or ent.ent_id_.startswith("watch:")
                )
                if not is_dict_match and self._is_tech_term(ent.text):
                    continue  # 技術用語として誤検知された候補は除外

                # canonical 統合: シード辞書で別名→正規名に正規化
                surface = ent.text
                canonical = self._canonical_map.get(surface, surface)

                key = (canonical, category)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # confirmed 判定: ent_id の接頭辞で判別。
                # R-S (2026-05-07): "watch:" 接頭辞は強制検出専用 (auto-mask
                # しないが uncertain candidate として表示)。
                if ent.ent_id_ and (
                    ent.ent_id_.startswith("seed:")
                    or ent.ent_id_.startswith("user:")
                ):
                    source = "seed_dict"
                    confirmed = True
                elif ent.ent_id_ and ent.ent_id_.startswith("watch:"):
                    source = "watchlist"
                    confirmed = False
                else:
                    source = "spacy_ner"
                    confirmed = False

                candidates.append(
                    NerCandidate(
                        text=canonical,
                        label=category.upper(),  # "COMPANY" / "SITE" / "PERSON"
                        spacy_label=spacy_label,
                        start=ent.start_char,
                        end=ent.end_char,
                        source=source,
                        confirmed=confirmed,
                    )
                )

        return candidates
