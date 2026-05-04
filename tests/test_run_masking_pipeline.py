"""R-M PR-D1: run_masking_pipeline のテスト。

NerMasker / HojinLookup は Fake クラスで差し替え、spaCy / urllib を
一切呼ばない。ロジック (振り分け、フォールバック、テキスト置換) のみを
網羅する。

実モデル (ja_core_news_md) を使った検証は streamlit_app.py の Diagnostics
エクスパンダーで実機確認する役割分担 (handoff_R-M_2026-05-03.md D7 参照)。
"""
from __future__ import annotations

import unittest
from typing import Optional
from unittest.mock import MagicMock

from secure_review.models import (
    LookupResult,
    NerCandidate,
)
from secure_review.run_masking_pipeline import (
    apply_user_decisions,
    run_masking_pipeline,
)
from secure_review.sanitizer import SensitiveDataSanitizer


# -----------------------------------------------------------------------------
# Fake クラス群
# -----------------------------------------------------------------------------


class FakeNerMasker:
    """NerMasker の最小限のスタブ。

    実装は spaCy ロード等が重いので、テストでは extract_candidates の
    戻り値を事前指定したものを返す。
    """

    def __init__(self, candidates: Optional[list[NerCandidate]] = None) -> None:
        self._candidates = list(candidates) if candidates else []
        self.calls: list[str] = []  # 呼ばれた text を記録

    def extract_candidates(self, text: str) -> list[NerCandidate]:
        self.calls.append(text)
        return list(self._candidates)


class RaisingNerMasker:
    """例外を投げる NerMasker(フォールバック動作テスト用)。"""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def extract_candidates(self, text: str) -> list[NerCandidate]:
        raise self._exc


class FakeHojinLookup:
    """HojinLookup のスタブ。事前指定した dict を引いて返す。"""

    def __init__(self, results: Optional[dict[str, LookupResult]] = None) -> None:
        self._results = dict(results) if results else {}
        self.calls: list[str] = []

    def search(self, name: str) -> LookupResult:
        self.calls.append(name)
        if name in self._results:
            return self._results[name]
        # デフォルト: ヒット 0 件
        return LookupResult(candidate_text=name, hits=0)


class RaisingHojinLookup:
    """例外を投げる HojinLookup(LookupResult.error 経路ではなく
    ハード例外側のフォールバックテスト用)。"""

    def search(self, name: str) -> LookupResult:
        raise RuntimeError("boom")


# -----------------------------------------------------------------------------
# ヘルパ
# -----------------------------------------------------------------------------


def _candidate(
    text: str,
    *,
    label: str = "COMPANY",
    confirmed: bool = False,
    spacy_label: str = "ORG",
    start: int = 0,
    end: int = 0,
) -> NerCandidate:
    return NerCandidate(
        text=text,
        label=label,
        spacy_label=spacy_label,
        start=start,
        end=end,
        source="seed_dict" if confirmed else "spacy_ner",
        confirmed=confirmed,
    )


# -----------------------------------------------------------------------------
# run_masking_pipeline のテスト
# -----------------------------------------------------------------------------


class RunMaskingPipelineTests(unittest.TestCase):
    """run_masking_pipeline の振り分けロジック。"""

    def test_empty_pipeline_returns_only_sanitized(self) -> None:
        """ner_masker=None / hojin_lookup=None でも sanitize 結果は返る。"""
        sanitizer = SensitiveDataSanitizer()
        state = run_masking_pipeline(
            name="doc.txt",
            text="Just plain text without sensitive content.",
            sanitizer=sanitizer,
            ner_masker=None,
            hojin_lookup=None,
        )
        self.assertEqual(state.name, "doc.txt")
        self.assertEqual(state.confirmed_findings, [])
        self.assertEqual(state.uncertain_candidates, [])
        self.assertEqual(state.lookups, {})
        # sanitized 自体は生成されている
        self.assertIsNotNone(state.sanitized)

    def test_confirmed_candidates_go_to_confirmed_findings(self) -> None:
        """confirmed=True の候補は confirmed_findings に振り分けられる。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[
                _candidate("KDDI", confirmed=True),
                _candidate("NTT", confirmed=True),
            ]
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="KDDI と NTT のシステム連携。",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=None,
        )
        self.assertEqual(
            state.confirmed_findings,
            [("KDDI", "COMPANY"), ("NTT", "COMPANY")],
        )
        self.assertEqual(state.uncertain_candidates, [])

    def test_uncertain_candidates_go_to_uncertain_list(self) -> None:
        """confirmed=False の候補は uncertain_candidates に入る。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[
                _candidate("アイレット", confirmed=False),
                _candidate("ABC 商事", confirmed=False),
            ]
        )
        hojin = FakeHojinLookup(
            results={
                "アイレット": LookupResult(
                    candidate_text="アイレット",
                    hits=16,
                    top_names=["株式会社アイレット", "KDDI アイレット株式会社"],
                ),
                "ABC 商事": LookupResult(candidate_text="ABC 商事", hits=0),
            }
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="アイレットと ABC 商事との取引。",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=hojin,
        )
        self.assertEqual(state.confirmed_findings, [])
        self.assertEqual(len(state.uncertain_candidates), 2)
        self.assertEqual(state.uncertain_candidates[0].text, "アイレット")
        self.assertEqual(len(state.lookups), 2)
        self.assertEqual(state.lookups["アイレット"].hits, 16)
        self.assertEqual(state.lookups["ABC 商事"].hits, 0)

    def test_mixed_candidates_split_correctly(self) -> None:
        """confirmed と uncertain が混在しても正しく振り分けられる。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[
                _candidate("KDDI", confirmed=True),
                _candidate("アイレット", confirmed=False),
                _candidate("NTT", confirmed=True),
            ]
        )
        hojin = FakeHojinLookup(
            results={
                "アイレット": LookupResult(
                    candidate_text="アイレット", hits=16
                ),
            }
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=hojin,
        )
        self.assertEqual(len(state.confirmed_findings), 2)
        self.assertEqual(len(state.uncertain_candidates), 1)
        # gBizINFO は uncertain にだけ問い合わせ (confirmed には引かない)
        self.assertEqual(hojin.calls, ["アイレット"])

    def test_no_hojin_lookup_skips_lookups(self) -> None:
        """hojin_lookup=None で uncertain があっても lookups は空。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[_candidate("アイレット", confirmed=False)]
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=None,
        )
        self.assertEqual(len(state.uncertain_candidates), 1)
        self.assertEqual(state.lookups, {})

    def test_ner_masker_failure_falls_back_to_sanitize_only(self) -> None:
        """NerMasker が例外を投げても sanitize 結果は返る。"""
        sanitizer = SensitiveDataSanitizer()
        ner = RaisingNerMasker(RuntimeError("spaCy boom"))
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=None,
        )
        # 既存 sanitize は届く
        self.assertIsNotNone(state.sanitized)
        # NER 関連は空
        self.assertEqual(state.confirmed_findings, [])
        self.assertEqual(state.uncertain_candidates, [])

    def test_hojin_lookup_returns_error_result_promotes_to_confirmed(self) -> None:
        """HojinLookup が LookupResult.error を返した場合、候補は安全側として
        confirmed_findings に昇格し uncertain_candidates から外れる。

        これは PR-F (R-M Phase 2 改善) で追加された挙動: gBizINFO 検索失敗時は
        判断材料がないので、ユーザに尋ねず自動マスクに倒す (機密漏洩防止優先)。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[_candidate("XYZ", confirmed=False)]
        )
        hojin = FakeHojinLookup(
            results={
                "XYZ": LookupResult(
                    candidate_text="XYZ", hits=0, error="HTTP 503"
                ),
            }
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=hojin,
        )
        # uncertain からは外れて confirmed に昇格
        self.assertEqual(len(state.uncertain_candidates), 0)
        self.assertIn(("XYZ", "COMPANY"), state.confirmed_findings)
        # lookups には error 情報が引き続き格納されている (UI 表示用)
        self.assertEqual(state.lookups["XYZ"].error, "HTTP 503")

    def test_hojin_lookup_hard_exception_caught(self) -> None:
        """HojinLookup.search が例外を投げてもパイプラインは継続。

        ハード例外時も LookupResult.error が設定されるので、PR-F の昇格
        ロジックが適用される (uncertain から外れて confirmed に昇格)。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[_candidate("XYZ", confirmed=False)]
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=RaisingHojinLookup(),
        )
        # error 付き LookupResult が格納されている
        self.assertEqual(len(state.lookups), 1)
        self.assertIn("unexpected", state.lookups["XYZ"].error)
        # PR-F: ハード例外候補も confirmed に昇格
        self.assertEqual(len(state.uncertain_candidates), 0)
        self.assertIn(("XYZ", "COMPANY"), state.confirmed_findings)

    def test_zero_hits_without_error_stays_uncertain(self) -> None:
        """gBizINFO が 200 + 0 件 (実在しない法人) を返した候補は、
        引き続き uncertain (ユーザ判断) に留まる。

        PR-F の昇格対象は「LookupResult.error が空でない場合のみ」。
        200 + 0 件は検索が成功した結果としての 0 件なので、ユーザに
        判断材料 (=「gBizINFO に登録なし」という情報) として提示する。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[_candidate("ZZZ_NOTREAL", confirmed=False)]
        )
        hojin = FakeHojinLookup(
            results={
                "ZZZ_NOTREAL": LookupResult(
                    candidate_text="ZZZ_NOTREAL", hits=0
                ),  # error 空
            }
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=hojin,
        )
        # 200 + 0 件は uncertain に残る (昇格しない)
        self.assertEqual(len(state.uncertain_candidates), 1)
        self.assertEqual(state.uncertain_candidates[0].text, "ZZZ_NOTREAL")
        self.assertEqual(state.lookups["ZZZ_NOTREAL"].hits, 0)
        self.assertEqual(state.lookups["ZZZ_NOTREAL"].error, "")
        # confirmed には昇格しない
        self.assertNotIn(
            ("ZZZ_NOTREAL", "COMPANY"), state.confirmed_findings
        )

    def test_mixed_promotion_keeps_searchable_candidates_uncertain(self) -> None:
        """error あり/なしが混在する場合: error あり候補のみ昇格、
        error なし候補は uncertain に残る (PR-F)。"""
        sanitizer = SensitiveDataSanitizer()
        ner = FakeNerMasker(
            candidates=[
                _candidate("FAILED_LOOKUP", confirmed=False),
                _candidate("VALID_LOOKUP", confirmed=False),
            ]
        )
        hojin = FakeHojinLookup(
            results={
                "FAILED_LOOKUP": LookupResult(
                    candidate_text="FAILED_LOOKUP", hits=0, error="HTTP 404"
                ),
                "VALID_LOOKUP": LookupResult(
                    candidate_text="VALID_LOOKUP",
                    hits=5,
                    top_names=["株式会社 X", "Y 商事"],
                ),
            }
        )
        state = run_masking_pipeline(
            name="doc.txt",
            text="...",
            sanitizer=sanitizer,
            ner_masker=ner,
            hojin_lookup=hojin,
        )
        # FAILED は confirmed に昇格、VALID は uncertain に残る
        self.assertIn(("FAILED_LOOKUP", "COMPANY"), state.confirmed_findings)
        self.assertNotIn(("VALID_LOOKUP", "COMPANY"), state.confirmed_findings)
        uncertain_texts = [c.text for c in state.uncertain_candidates]
        self.assertIn("VALID_LOOKUP", uncertain_texts)
        self.assertNotIn("FAILED_LOOKUP", uncertain_texts)


# -----------------------------------------------------------------------------
# apply_user_decisions のテスト
# -----------------------------------------------------------------------------


class ApplyUserDecisionsTests(unittest.TestCase):
    """apply_user_decisions のマスク反映ロジック。"""

    def _build_state(
        self,
        text: str = "KDDI と アイレット のシステム。",
        confirmed: list[tuple[str, str]] | None = None,
        uncertain: list[NerCandidate] | None = None,
    ):
        """テスト用に state と sanitizer を組で用意するヘルパ。"""
        sanitizer = SensitiveDataSanitizer()
        state = run_masking_pipeline(
            name="doc.txt",
            text=text,
            sanitizer=sanitizer,
            ner_masker=FakeNerMasker(
                candidates=(
                    [
                        _candidate(t, label=l, confirmed=True)
                        for t, l in (confirmed or [])
                    ]
                    + list(uncertain or [])
                )
            ),
            hojin_lookup=None,
        )
        return state, sanitizer

    def test_confirmed_findings_always_masked(self) -> None:
        """confirmed_findings は user_decisions と無関係にマスクされる。"""
        state, sanitizer = self._build_state(
            text="KDDI と システム連携。",
            confirmed=[("KDDI", "COMPANY")],
        )
        result = apply_user_decisions(
            state=state, user_decisions={}, sanitizer=sanitizer
        )
        # KDDI が placeholder に置換されている
        self.assertNotIn("KDDI", result.outbound_text)
        # placeholder は [COMPANY_NNN] 形式 (sanitizer の既存規約)
        any_company = any(
            r.placeholder.startswith("[COMPANY_") and r.original == "KDDI"
            for r in result.replacements
        )
        self.assertTrue(any_company)

    def test_uncertain_with_decision_true_masked(self) -> None:
        """user_decisions[text]=True の uncertain はマスクされる。"""
        cand = _candidate("アイレット", label="COMPANY", confirmed=False)
        state, sanitizer = self._build_state(
            text="アイレット と取引。",
            uncertain=[cand],
        )
        result = apply_user_decisions(
            state=state,
            user_decisions={"アイレット": True},
            sanitizer=sanitizer,
        )
        self.assertNotIn("アイレット", result.outbound_text)

    def test_uncertain_with_decision_false_kept(self) -> None:
        """user_decisions[text]=False の uncertain はマスクされない。"""
        cand = _candidate("アイレット", label="COMPANY", confirmed=False)
        state, sanitizer = self._build_state(
            text="アイレット と取引。",
            uncertain=[cand],
        )
        result = apply_user_decisions(
            state=state,
            user_decisions={"アイレット": False},
            sanitizer=sanitizer,
        )
        # マスクされていないので原文がそのまま残る
        self.assertIn("アイレット", result.outbound_text)

    def test_missing_key_in_user_decisions_treated_as_false(self) -> None:
        """user_decisions にキーがない uncertain は False 扱い (マスクしない)。"""
        cand = _candidate("XYZ", label="COMPANY", confirmed=False)
        state, sanitizer = self._build_state(
            text="XYZ と取引。",
            uncertain=[cand],
        )
        result = apply_user_decisions(
            state=state,
            user_decisions={},  # キー欠落
            sanitizer=sanitizer,
        )
        self.assertIn("XYZ", result.outbound_text)

    def test_extra_keys_in_user_decisions_ignored(self) -> None:
        """user_decisions に対応する候補がない余分なキーは無視される。"""
        cand = _candidate("XYZ", label="COMPANY", confirmed=False)
        state, sanitizer = self._build_state(
            text="XYZ と取引。",
            uncertain=[cand],
        )
        # まったく関係ないキーを混ぜる
        result = apply_user_decisions(
            state=state,
            user_decisions={"XYZ": True, "ABCDEFG": True, "12345": False},
            sanitizer=sanitizer,
        )
        # XYZ だけマスク、他は無視
        self.assertNotIn("XYZ", result.outbound_text)
        # records には XYZ だけ追加
        added = [r for r in result.replacements if r.original == "XYZ"]
        self.assertEqual(len(added), 1)

    def test_state_is_not_mutated(self) -> None:
        """apply_user_decisions は state を変更しない (不変性)。"""
        cand = _candidate("XYZ", label="COMPANY", confirmed=False)
        state, sanitizer = self._build_state(
            text="XYZ と取引。",
            uncertain=[cand],
        )
        before_uncertain = list(state.uncertain_candidates)
        before_lookups = dict(state.lookups)
        apply_user_decisions(
            state=state,
            user_decisions={"XYZ": True},
            sanitizer=sanitizer,
        )
        # state は手付かず
        self.assertEqual(state.uncertain_candidates, before_uncertain)
        self.assertEqual(state.lookups, before_lookups)

    def test_mixed_decisions_apply_correctly(self) -> None:
        """複数 uncertain で True / False が混在しても正しく適用される。"""
        cands = [
            _candidate("AAA", label="COMPANY", confirmed=False),
            _candidate("BBB", label="COMPANY", confirmed=False),
            _candidate("CCC", label="COMPANY", confirmed=False),
        ]
        state, sanitizer = self._build_state(
            text="AAA と BBB と CCC の話。",
            uncertain=cands,
        )
        result = apply_user_decisions(
            state=state,
            user_decisions={"AAA": True, "BBB": False, "CCC": True},
            sanitizer=sanitizer,
        )
        self.assertNotIn("AAA", result.outbound_text)
        self.assertIn("BBB", result.outbound_text)  # マスクされず残る
        self.assertNotIn("CCC", result.outbound_text)


if __name__ == "__main__":
    unittest.main()
