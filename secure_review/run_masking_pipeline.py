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
    *,
    auto_mask_on_lookup_error: bool = False,
) -> MaskingPipelineState:
    """Phase 1+2 パイプラインを実行し、ユーザ判断前の中間状態を返す。

    フロー:
      1. sanitizer.sanitize(name, text) で regex マスキング (R-K)
      2. ner_masker.extract_candidates(text) で NER 候補抽出 (R-M Phase 1)
         - confirmed=True (シード辞書ヒット) → confirmed_findings へ
         - confirmed=False (統計 NER のみ)  → uncertain_candidates へ
      3. uncertain_candidates 各 text について hojin_lookup.search(name)
         で gBizINFO 問い合わせ (R-M Phase 2)
      4. (R-O 以降のデフォルト) gBizINFO 検索失敗候補も uncertain のまま
         残す。``auto_mask_on_lookup_error=True`` を明示的に渡すと、
         旧 PR-F の挙動 (検索失敗候補を confirmed_findings へ自動昇格)
         に切り替わる。

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
        auto_mask_on_lookup_error: gBizINFO 検索失敗時に候補を自動的に
            confirmed_findings へ昇格させるか。デフォルト False (R-O)。
            False のとき、検索失敗候補は uncertain_candidates のまま残り、
            ユーザの明示的な判断 (apply_user_decisions の user_decisions
            引数) を必須にする。これは「実データで spaCy 統計 NER が
            技術用語を多数誤検知した結果、検索失敗で全部自動マスクへ
            昇格してしまいレビューが壊れる」事象 (R-O) への対策。
            旧 PR-F 挙動を保ちたいテストや運用シナリオは明示的に
            True を渡す。

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

    # Step 4: gBizINFO 検索失敗 (error あり) の候補の扱い。
    #
    # R-O (2026-05-05): デフォルトでは昇格しない (uncertain のまま残す)。
    # 旧 PR-F は「検索失敗 = 判断材料なし → 機密漏洩防止優先で自動マスク」
    # という設計だったが、実データでは spaCy 統計 NER が AWS 公式
    # サービス名・標準プロトコル名・PDF 抽出由来のスペース混入語などを
    # 大量に誤検知し、`GBIZINFO_API_TOKEN` 未設定時は全件 error
    # 扱いとなって、レビュー出力が ``[COMPANY_001] のバウンス率`` のような
    # 無意味な表示で埋め尽くされた (R-O 報告)。
    #
    # 対策として _is_tech_term の R-O パターン強化と、本ステップの
    # デフォルト無効化を組み合わせる。この 2 つで Streamlit Cloud の
    # GBIZINFO_API_TOKEN 設定状況に左右されず、誤検知が減る方向にだけ
    # 動く (技術用語は弾かれ、それ以外は人間判断に回る)。
    #
    # ``auto_mask_on_lookup_error=True`` を明示的に渡せば旧挙動を維持
    # するので、既存テストや「機密漏洩を絶対避けたい運用」では引数指定で
    # 切り替え可能。
    if auto_mask_on_lookup_error:
        promoted_texts: set[str] = set()
        for cand in list(state.uncertain_candidates):
            result = state.lookups.get(cand.text)
            if result is not None and result.error:
                # 検索失敗 → 自動マスクへ昇格 (旧 PR-F 挙動)
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
    *,
    customer_id: str | None = None,
    session_id: str | None = None,
    audit_root: "Optional[object]" = None,  # Path | None, 文字列回避
) -> SanitizedDocument:
    """ユーザ判断を反映し、最終的な匿名化済み文書を生成する。

    確定済み候補 (シード辞書ヒット) は user_decisions と無関係に常にマスク。
    未確定候補は ``user_decisions[candidate.text] is True`` のもののみマスク。

    R-W-1 (2026-05-08): ユーザ判断結果を audit log に記録する。
    ``customer_id`` を指定すると、``data/audit/<customer_id>/<date>.jsonl``
    に追記される。``customer_id=None`` (default) なら audit log は記録しない
    (R-W 機能を使わない既存呼び出し元との後方互換性)。

    Args:
        state: run_masking_pipeline の戻り値。本関数は ``state`` を変更しない。
        user_decisions: 候補テキスト → True (マスクする) / False (しない)。
            state.uncertain_candidates の各 text に対応。キー欠落は False 扱い。
        sanitizer: state.sanitized 生成時と **同一の** SensitiveDataSanitizer
            インスタンス。register_ner_finding() の counter / _seen 共有のため
            必須。違うインスタンスを渡すと番号が衝突する。
        customer_id: R-W-1 audit log の顧客識別子。None なら audit 記録なし。
        session_id: R-W-1 audit log のセッション識別子。指定推奨 (Streamlit
            session_state 経由で 1 セッション 1 ID に束ねる)。
        audit_root: R-W-1 audit log の出力ルート (テスト用)。

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

    # R-W-1: audit log にユーザ判断結果を追記。customer_id 指定時のみ動作。
    # 失敗してもパイプライン全体は止めない (best-effort)。
    if customer_id is not None:
        try:
            from secure_review.audit_log import log_decisions

            # 候補メタデータ収集 (uncertain_candidates から)
            candidate_metadata: dict[str, dict[str, object]] = {}
            for cand in state.uncertain_candidates:
                # 文脈を周辺テキストから抽出 (60 字前後)
                ctx_start = max(0, cand.start - 30)
                ctx_end = min(len(state.sanitized.original_excerpt), cand.end + 30)
                ctx = state.sanitized.original_excerpt[ctx_start:ctx_end]
                candidate_metadata[cand.text] = {
                    "label": cand.label,
                    "source": cand.source,
                    "context": ctx,
                }

            # 全 uncertain candidate の判断を記録 (検出されたが decisions に
                # 入っていない = "skip" 判断とみなす)
            full_decisions: dict[str, bool] = {}
            for cand in state.uncertain_candidates:
                full_decisions[cand.text] = bool(user_decisions.get(cand.text, False))

            log_decisions(
                document_name=state.sanitized.name,
                decisions=full_decisions,
                candidate_metadata=candidate_metadata,
                customer_id=customer_id,
                session_id=session_id,
                audit_root=audit_root,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("audit_log write failed: %s", exc)

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
