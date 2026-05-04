"""R-M Phase 1+2: マスキングパイプライン本体。

R-K の regex マスキング (sanitizer.py)、R-M Phase 1 の NER 候補抽出
(ner_masker.py)、R-M Phase 2 の gBizINFO 検索 (hojin_lookup.py) を
糊付けし、ユーザ判断を待つ中間状態 (MaskingPipelineState) を構築する
``run_masking_pipeline``、およびユーザ判断後に最終的な匿名化済み文書を
生成する ``apply_user_decisions`` を提供する。

設計判断 (handoff_R-M_2026-05-03.md の D1-D2):
- ner_masker と hojin_lookup は Optional。None なら該当機能をスキップして
  既存 sanitize 結果のみで動作 (R-K/R-L へのリグレッション回避)。
- 例外時もパイプライン全体を止めない。NerMasker 例外時は既存 sanitize
  結果を返す。HojinLookup 例外は LookupResult.error に格納して継続。
- 状態は不変。run_masking_pipeline の戻り値を session_state に保持し、
  apply_user_decisions は state から新しい SanitizedDocument を生成する
  (state は変更しない)。

責務外:
- UI 描画 → streamlit_app.py (PR-D2)
- spaCy / urllib の直接呼び出し → ner_masker.py / hojin_lookup.py
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from secure_review.models import (
    LookupResult,
    MaskingPipelineState,
    NerCandidate,
    SanitizationRecord,
    SanitizedDocument,
)
from secure_review.sanitizer import SensitiveDataSanitizer

if TYPE_CHECKING:
    # NerMasker は spaCy をハードに import するため、runtime では遅延 import。
    # ner_masker パラメータは duck typing で扱う (extract_candidates() があれば OK)。
    from secure_review.ner_masker import NerMasker
    from secure_review.hojin_lookup import HojinLookup

logger = logging.getLogger(__name__)


def run_masking_pipeline(
    name: str,
    text: str,
    sanitizer: SensitiveDataSanitizer,
    ner_masker: "Optional[NerMasker]",
    hojin_lookup: "Optional[HojinLookup]",
) -> MaskingPipelineState:
    """Phase 1+2 パイプラインを実行し、ユーザ判断前の中間状態を返す。

    フロー:
      1. sanitizer.sanitize(name, text) で regex マスキング (R-K)
      2. ner_masker.extract_candidates(text) で NER 候補抽出 (R-M Phase 1)
         - confirmed=True (シード辞書ヒット) → confirmed_findings へ
         - confirmed=False (統計 NER のみ)  → uncertain_candidates へ
      3. uncertain_candidates 各 text について hojin_lookup.search(name)
         で gBizINFO 問い合わせ (R-M Phase 2)
      4. 結果を MaskingPipelineState にまとめて返す

    Args:
        name: ドキュメント名 (例: "report.pdf")。SanitizedDocument.name に
            埋め込まれる。
        text: マスク対象のテキスト全体。
        sanitizer: 既存の R-K regex マスキングを実行。state.sanitized の
            生成元として使われ、以降 apply_user_decisions に渡されたとき
            register_ner_finding() を介して NER 由来のマスクを追加する。
            **同じインスタンスを apply_user_decisions にも渡すこと**
            (counter / _seen 共有のため)。
        ner_masker: 候補抽出器。None なら NER スキップで sanitize 結果のみ。
        hojin_lookup: gBizINFO クライアント。None なら gBizINFO 検索スキップ。

    Returns:
        MaskingPipelineState: 不変な中間状態。``has_uncertain`` プロパティで
        ユーザ判断 UI を出すべきかが分かる。
    """
    # Step 1: 既存 regex マスキング
    sanitized = sanitizer.sanitize(name, text)

    state = MaskingPipelineState(name=name, sanitized=sanitized)

    # Step 2: NER 候補抽出
    if ner_masker is None:
        return state

    try:
        candidates: list[NerCandidate] = ner_masker.extract_candidates(text)
    except Exception as exc:  # noqa: BLE001
        # NerMasker が壊れていても既存 sanitize は届ける (R-K/R-L 維持)
        logger.warning("NerMasker.extract_candidates failed: %s", exc)
        return state

    # confirmed / uncertain への振り分け
    for cand in candidates:
        if cand.confirmed:
            # シード辞書ヒット: 後段で自動マスク
            state.confirmed_findings.append((cand.text, cand.label))
        else:
            state.uncertain_candidates.append(cand)

    # Step 3: gBizINFO 検索 (uncertain のみ)
    if hojin_lookup is None or not state.uncertain_candidates:
        return state

    for cand in state.uncertain_candidates:
        if cand.text in state.lookups:
            # 同一文書内に同じ text が複数現れた場合のスキップ
            continue
        try:
            result: LookupResult = hojin_lookup.search(cand.text)
        except Exception as exc:  # noqa: BLE001
            # HojinLookup の search はそもそも例外を投げない設計だが念のため
            logger.warning("HojinLookup.search('%s') raised: %s", cand.text, exc)
            result = LookupResult(
                candidate_text=cand.text,
                hits=0,
                error=f"unexpected: {type(exc).__name__}",
            )
        state.lookups[cand.text] = result

    # Step 4: gBizINFO 検索失敗 (error あり) の候補を confirmed_findings へ昇格。
    # 機密漏洩防止優先 (D4 安全側) の方針で、検索結果が判断材料として使えない
    # ものはユーザに尋ねず自動的にマスクする。住所のような spaCy が高信頼で
    # 検出した固有名詞を「人間に判断させる」のは UX として不自然なので、
    # gBizINFO 404 / ネットワークエラー時の候補は自動マスクへ。
    # 200 + 0 件 (実在しない法人) はユーザの目視判断材料として残す。
    promoted_texts: set[str] = set()
    for cand in list(state.uncertain_candidates):
        result = state.lookups.get(cand.text)
        if result is not None and result.error:
            # 検索失敗 → 自動マスクへ昇格
            state.confirmed_findings.append((cand.text, cand.label))
            promoted_texts.add(cand.text)
    if promoted_texts:
        state.uncertain_candidates = [
            c for c in state.uncertain_candidates if c.text not in promoted_texts
        ]

    return state


def apply_user_decisions(
    state: MaskingPipelineState,
    user_decisions: dict[str, bool],
    sanitizer: SensitiveDataSanitizer,
) -> SanitizedDocument:
    """ユーザ判断を反映し、最終的な匿名化済み文書を生成する。

    確定済み候補 (シード辞書ヒット) は user_decisions と無関係に常にマスク。
    未確定候補は ``user_decisions[candidate.text] is True`` のもののみマスク。

    Args:
        state: run_masking_pipeline の戻り値。本関数は ``state`` を変更しない。
        user_decisions: 候補テキスト → True (マスクする) / False (しない)。
            state.uncertain_candidates の各 text に対応。キー欠落は False 扱い。
        sanitizer: state.sanitized 生成時と **同一の** SensitiveDataSanitizer
            インスタンス。register_ner_finding() の counter / _seen 共有のため
            必須。違うインスタンスを渡すと番号が衝突する。

    Returns:
        SanitizedDocument: 最終的な outbound_text / sanitized_excerpt /
        replacements を含む。元の state.sanitized は変更されない (新しい
        SanitizedDocument が返る)。
    """
    # マスクすべき (text, label) ペアを集約
    # confirmed は常にマスク
    to_mask: list[tuple[str, str]] = list(state.confirmed_findings)

    # uncertain はユーザ判断に従う
    for cand in state.uncertain_candidates:
        if user_decisions.get(cand.text, False):
            to_mask.append((cand.text, cand.label))

    # 元のテキスト (sanitized_excerpt) と outbound_text に対し、
    # 各候補をプレースホルダで置換しつつ、replacements 台帳に追加
    sanitized_excerpt = state.sanitized.sanitized_excerpt
    outbound_text = state.sanitized.outbound_text
    replacements = list(state.sanitized.replacements)
    findings = list(state.sanitized.findings)

    # 同一 (text, label) は 1 度だけ処理 (NerCandidate 側で重複排除済みだが念のため)
    seen: set[tuple[str, str]] = set()
    for value, label in to_mask:
        key = (value, label)
        if key in seen:
            continue
        seen.add(key)

        # NerCandidate.label は "COMPANY"/"SITE"/"PERSON" (大文字)
        # register_ner_finding の category 引数は小文字を期待
        category = label.lower()

        try:
            placeholder, record = sanitizer.register_ner_finding(value, category)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "register_ner_finding failed for (%r, %r): %s", value, label, exc
            )
            continue

        # テキスト全体を置換 (regex マスキング後の状態に対して)
        sanitized_excerpt = sanitized_excerpt.replace(value, placeholder)
        outbound_text = outbound_text.replace(value, placeholder)

        # 同一 placeholder が既に records にある場合は追加しない (冪等)
        if not any(r.placeholder == placeholder for r in replacements):
            replacements.append(record)

        # findings の重複も避ける
        finding_summary = f"NER {category}: {value}"
        if finding_summary not in findings:
            findings.append(finding_summary)

    return SanitizedDocument(
        name=state.sanitized.name,
        original_excerpt=state.sanitized.original_excerpt,
        sanitized_excerpt=sanitized_excerpt,
        outbound_text=outbound_text,
        replacements=replacements,
        findings=findings,
        estimated_input_tokens=state.sanitized.estimated_input_tokens,
        outbound_risk=state.sanitized.outbound_risk,
        local_sanitizer_provider=state.sanitized.local_sanitizer_provider,
        local_sensitivity_decision=state.sanitized.local_sensitivity_decision,
        local_sensitivity_reasons=list(state.sanitized.local_sensitivity_reasons),
        local_sensitivity_provider=state.sanitized.local_sensitivity_provider,
    )
