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

    def _load_seeds(self, path: Path) -> None:
        """シード YAML をロードし EntityRuler パターンに変換する。"""
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        patterns: list[dict[str, Any]] = []

        # phrases: 完全一致 string pattern (spaCy が内部でトークン化してマッチ)
        for entry in data.get("phrases", []) or []:
            text = entry["text"]
            label = entry["label"]
            canonical = entry.get("canonical") or text
            patterns.append(
                {
                    "label": label,
                    "pattern": text,
                    "id": f"seed:phrase:{canonical}",
                }
            )
            if canonical != text:
                self._canonical_map[text] = canonical

        # token_patterns: 脱出ハッチ (そのまま投入)
        for entry in data.get("token_patterns", []) or []:
            patterns.append(entry)

        if patterns:
            self._ruler.add_patterns(patterns)

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

                # canonical 統合: シード辞書で別名→正規名に正規化
                surface = ent.text
                canonical = self._canonical_map.get(surface, surface)

                key = (canonical, category)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # confirmed 判定: ent_id が "seed:" or "user:" で始まれば辞書由来
                source = (
                    "seed_dict"
                    if ent.ent_id_ and (
                        ent.ent_id_.startswith("seed:")
                        or ent.ent_id_.startswith("user:")
                    )
                    else "spacy_ner"
                )
                confirmed = source == "seed_dict"

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
