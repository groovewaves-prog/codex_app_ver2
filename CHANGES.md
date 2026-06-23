# Changes — April 2026 hardening pass

Baseline commit: `eaf605a`.

### Code analysis mode — evidence-first review cards

- Changed Step 4 code-analysis cards from document-review labels (`現状` / `修正方針`) to code-review labels: `検出根拠`, `該当箇所`, `リスク`, `推奨確認`, `運用影響`, and `再解析条件`.
- Added deterministic evidence snippets for static code findings, including function name, approximate line number, and matched code pattern; secret-like assignments are redacted in evidence text.
- Marked static code findings as `静的検出由来` instead of presenting them as ordinary first-pass LLM findings.
- Replaced the empty-summary fallback for source-code reviews with an actionable code-analysis summary when findings exist.
- Hardened source-code review filtering so LLM-only claims about syntax errors, truncated/missing source, missing implementation, or anonymization placeholder breakage are suppressed unless represented by deterministic local static findings.
- Reworked source-code review anchoring so deterministic local findings are always merged into code-analysis results, syntax checks are skipped for anonymized placeholder-mutated code, and broad LLM claims about missing implementation / incomplete later phases are filtered out.

### Code analysis mode — hide document-draft templates

- Step 4 now hides the `文書追記案` copy block when the uploaded artifacts are detected as `コード解析モード`; code/script reviews focus on findings, risks, and code-level remediation instead of document insertion text.
- Kept the document-draft template visible for ordinary design documents and runbooks where the user is expected to update the source document.
- Excluded design-document structure-check findings from the Step 4 remediation plan in code analysis mode, preventing off-target `文書全体` / `冒頭の目的記載` items from appearing in code reviews.
- Code-analysis remediation JSON now uses code-oriented checklist text, `コード修正メモ`, `必須再解析`, and diff/retest conditions instead of document-draft templates and chapter-based review steps.

### Artifact review mode — code/config/script-aware review and runbook depth

- Added `secure_review.artifact_review` to separate broad document profile from practical review handling: code analysis, config overview, lightweight runbook review, or ordinary document review.
- Step 2 now shows a compact review-mode card before mask decisions so users can confirm whether the upload will be treated as a design document, code/script, config, or lightweight/formal runbook.
- Extended review prompts so source code/scripts focus on static code risks instead of document chapter structure, and runbooks separate "簡易版として使う最低限の補強" from "正式手順書へ拡張する追加項目".
- Strengthened source-code detection for `.sh.txt` style scripts and PowerShell-like text, and added mock heuristics for TLS verification disabled, missing network timeouts, and high-impact operations without safety guards.

### Step 4 focus pass — issue cards as the single review path

- Removed the Step 4 auxiliary-section render path so users focus on the actionable issue cards instead of a parallel "補助で見るもの" area.
- Added visible context chips to each issue card for target document, target section, and issue origin.
- Limited top summary chips to actionable severity counts, avoiding detached "不足章" / "将来リスク" counts without a clear destination.
- Changed the card copy block from a review-result recap into a document-draft style `文書追記案`, with explicit placeholders for values the author should fill in.
- Clarified Step 3's `6秒` display as an API-call interval for Free tier throttling, not LLM response time, and added a user-facing explanation for Gemini/Gemma HTTP 503 failures.
- Normalized Step 4 issue-list labels to `指摘 NN · 重要度 · 文書 · 対象箇所 · タイトル`, added document filtering for multi-file reviews, and limited the initial issue list to the top 12 items with a show-all control.
- Updated Step 4 static tests to guard against reintroducing the auxiliary section in `_render_step4_v2`.

### G-5 — cleanup, regression guard, and handoff refresh

- Removed the developer-only G-1 design foundation preview scaffold from the sidebar while keeping the production `secure_review.ui_components` helpers.
- Deleted the now-unused `secure_review.agent_planner` module and its dedicated tests after confirming Co-Pilot / DisplayPolicy references were gone from runtime code.
- Fixed the Step 4 chapter re-analysis matcher so it no longer expects a non-existent `ChapterSection.chapter_name` attribute.
- Added static regression coverage for removed old UI terms, removed preview scaffolding, removed planner module, and chapter matching safety.
- Refreshed handoff/manual/checklist notes for the current v2 UI and recorded remaining future-review internal terminology as a follow-up observation.

### G-4.5 follow-up — readable masthead and reset action

- Reworked the main app title into a high-contrast masthead card with an `SR` mark, larger responsive typography, and safe top spacing below the Streamlit toolbar.
- Strengthened the sidebar `↻ 新しいレビューを始める` button contrast by overriding both the button and its nested Streamlit text elements.
- Kept the app title purpose-focused with no method-specific subtitle.

### G-4.5 fix — title, reset button contrast, and status spacing

- Upgraded the main app title to a 28px shield-icon title row with a thin divider and no subtitle.
- Forced the sidebar `↻ 新しいレビューを始める` primary button to use a dark background and light text for reliable contrast.
- Removed numeric status-bar icons from Step 1/2/3 and added spacing for status icons so labels no longer appear as `1準備中`.

### G-4.5 — App title and sidebar reset guidance

- Restored a concise main-area app title (`技術文書レビュー支援ツール`) without bringing back the old hero banner or long subtitle.
- Removed the duplicate app-name brand card from the sidebar so the title appears only in the main area.
- Promoted `新しいレビューを始める` to a primary sidebar action and added a short explanation that it clears uploaded documents, mask decisions, and review results for a fresh start.

### G-4 — Step 1 upload and Step 3 send rebuild

- Rebuilt Step 1 around a compact upload-first layout with direct status bar, previous-review comparison expander, selected-file list, duplicate warnings, and `匿名化してプレビュー`.
- Rebuilt Step 3 around the external-send boundary: destination summary, `送信されるもの / 送信されないもの` contrast, final approval checkbox, `レビューを実行`, and `ステップ 2 に戻る`.
- Removed the Streamlit Co-Pilot rendering path from all active steps and review-running/error states. Runtime status now uses direct `sr_ui.status_bar` rendering while preserving review progress, completion, and error-state messages.
- Kept the send gate, outbound guard, provider call, token budget, uploader reset, and duplicate-detection backend paths unchanged. The obsolete `secure_review.agent_planner` module was removed in G-5.
- Verification: `python -m unittest discover tests` passes with the updated G-4 static regression tests.

### G-3 — Step 2 anonymization review rebuild

- Rebuilt Step 2 around a review-before-send layout: status bar, Step 2 heading, anonymization summary chips, top-priority mask decision section, compact per-document detail list, and next-action controls.
- Promoted uncertain mask candidates from per-document cards to the top of Step 2 so users decide mask/no-mask before external review. Existing R-W decision persistence (`_decision_key`, `user_decisions`, `apply_user_decisions`) is reused.
- Gated `送信準備を完了する` while uncertain candidates remain. After `匿名化結果を再生成`, resolved masking states clear `uncertain_candidates`, allowing Step 3 confirmation to proceed.
- Removed the active Step 2 path for duplicate bundle/check/card UI and Step 2 Co-Pilot.
- Verification: `python -m unittest discover tests` passes with 374 tests, including 8 new Step 2 static regression tests.

### G-2 — Step 4 review result rebuild

- Rebuilt Step 4 around a conclusion-first layout: status bar, big-number issue summary, severity chips, issue cards, and auxiliary sections.
- Removed the active Step 4 path for AI Display Director / Remediation Planner / per-document detail grouping. The main user path is now "対応すべき指摘"; supporting information is grouped under "補助で見るもの".
- Integrated chapter re-analysis into issue cards when the target chapter can be matched, while preserving direct chapter selection under the auxiliary "章単位の追加レビュー" section.
- Kept remediation-plan JSON as the primary review ledger download and kept audit ZIP behind developer mode.
- Verification: `python -m unittest discover tests` passes with 358 tests.

### D-1 step1 — Review Command Agent removed

- Step 2 に表示していた Review Command Agent / レビュー管制エージェントを削除し、レビュー前の次アクション案内を AI Operation Co-Pilot に一本化。
- `build_review_agent_brief`、`AgentBrief` / `AgentStage`、専用CSS、専用テスト3件を削除。
- レビュー後の表示調整は AI Display Director が担当する方針を維持。
- Verification: `python -m unittest discover tests` passes with 314 tests. Before this cleanup, 317 tests passed; the difference is the removed Review Command Agent-only tests.

### D-1 step2 — Sticky Task Panel and Task Panel for State removed

- Sticky Task Panel / Task Panel for State を削除し、次の一手の案内をレビュー前は AI Operation Co-Pilot、レビュー後は AI Display Director に集約。
- ステータスバーを Sticky Task Panel から切り離し、Co-Pilot 直下に1回だけ表示する構成へ変更。
- 未使用になった `next_action_for_preview` と専用テストを削除。
- Verification: `python -m unittest discover tests` passes with 313 tests. Before this cleanup, 314 tests passed; the difference is the removed task-panel-only viewmodel test.

### D-1 step3 — Next action card removed; D-1 complete

- Step 4 冒頭に残っていた `_render_next_action_card` と `NextAction` dataclass を削除し、レビュー後の次アクション案内を AI Display Director に一本化。
- 専用CSS `.next-action-card` を削除。
- D-1 計画（次の一手案内の整理）は本ステップで完了。

### D-2 step1 — add origin field to ReviewIssue and RemediationItem

- 深堀指摘を修正計画へ合流する前段として、`ReviewIssue` と `RemediationItem` に `origin` フィールドを追加。
- 既定値は `"initial"` とし、既存レビュー・旧形式の修正計画JSONは表示変更なしで読み込めるよう後方互換を維持。
- `ReviewIssue.origin` を修正計画カードへ伝搬し、構成チェック由来の修正計画は `"initial"` として扱う。

### D-2 step2 — tag deep-dive issues and rebuild remediation plan

- 章単位深堀で得た新規指摘に `origin="chapter_deep_dive"` を付与し、修正計画を再構築する流路を追加。
- 旧 `deep_dive_results` に文書深堀結果が存在する場合は `origin="document_deep_dive"` として修正計画に合流できるようにした。
- 修正計画JSONには、初回レビューと深堀由来の item が origin 別に保持される。

### D-2 step3 — Origin badges and deep-dive section collapse

- 修正計画カードに、深堀由来の item だけ `[🔬 文書深堀で追加]` / `[📌 章深堀で追加]` バッジを表示。
- 初回レビュー由来の item はバッジ非表示のままにし、通常カードの視覚ノイズを抑制。
- 章別詳細内の深堀結果は、合流済み件数のサマリ行 + デフォルト閉の詳細 expander に縮退。

### D-6 — replace generic expander labels with specific guidance

- レビュー結果ページの expander / toggle ラベルから「必要なときだけ」系の汎用句を削除。
- 「短い名前 — いつ・なぜ開くか」の形式に統一し、補助情報を開く判断理由をラベル上で明示。
- AI Display Director の `keep_collapsed` 表示名も新ラベルの短い名前と同期。

### D-5 — separate remediation plan JSON from audit log JSON naming

- 修正計画直下の保存ボタンを `📒 再レビュー用の修正計画JSONを保存` に改名し、ファイル名を `remediation_plan_YYYYMMDD_HHMM.json` に変更。
- 証跡エクスポート内の監査用JSONを `audit_` 接頭辞付きのファイル名へ統一。
- 旧 `remediation_plan.json` も前回修正計画JSONとして読み込める後方互換を維持。

### Fix — remediation current_state fallback

- 追記テンプレートの「現状」欄で、内部指示文がそのまま表示される問題を修正。
- `ReviewIssue.current_state` が空の場合は、`details` 内の `【現状】` / `現状:` / `現状の記載:` から補完し、抽出できない場合はユーザ向けの確認誘導文を表示。
- LLM プロンプト例と評価方針に `current_state` の出力指示を明示。

### Fix — Step 4 UX improvements

- AI Display Director をアクション起点の見出しに再設計し、詳細理由は `📊 AI 判断の詳細を見る` に退避。
- 追記案 expander と章別AI再分析ボタンのラベルを明確化し、文書追記と追加レビューの役割を分離。
- 先読みレビューを `障害シナリオと予防策` に改名し、未来障害カードは「故障への道筋」と「次の一手」に絞って表示。
- 証跡エクスポートは開発者モード配下へ移し、4つの監査JSONを `audit_log_YYYYMMDD_HHMM.zip` に統合。

### Fix — Phase 2 deep-dive entry

- Step 4 の章単位深堀ボタンを、文書別詳細表示トグル配下から修正計画直下の独立セクション `章別深堀` に移動。
- `文書別の詳細表示` トグルは、章別概要・元指摘・深堀結果詳細の表示だけを制御する責務へ縮小。
- 旧 `章別深堀候補` expander を廃止し、AI Display Director の補助表示からも同項目を削除。

### Fix — Phase 3 Co-Pilot compression and selector relocation

- AI Operation Co-Pilot の常時表示をステップ、見出し、次アクションに絞り、理由、完了目安、注意点、チェックリストは折りたたみ詳細へ移動。
- サイドバー上部の文書種別セレクタを詳細設定 expander 内の先頭へ移動し、通常利用時のサイドバーを簡素化。

### Fix — Phase 4 mask decision history pagination

- The all-period mask decision history keeps the existing aggregation logic, but now defaults to the top 10 terms by decision count.
- Histories with 11 or more terms show a "show more" control and can be collapsed back to the top 10 view.
- The history expander title and caption now expose the total term count, while category metrics continue to summarize all terms.

### G-1 — design foundation tokens and reusable UI components

- Added `--sr-*` design tokens as aliases to the existing Streamlit theme variables, preserving the current visual tone while preparing shared UI building blocks.
- Added `secure_review/ui_components.py` with pure HTML builders for severity chips, effort badges, status bars, summary numbers, issue headers, collapsed rows, and metric pairs.
- Added a developer-mode-only design foundation preview in the sidebar; existing production UI paths are not replaced in this phase.

## For the GitHub push chat

This document is designed to serve as the PR body for the upcoming GitHub
push. The summary below is the short description; the rest of the file
gives the detail for reviewers.

### PR summary (one-paragraph version)

R1–R4 security-boundary hardening for the secure_review review pipeline,
plus: Streamlit UI (now the primary UI), PDF extraction via pypdf,
Gemini free-tier stabilisation (gemini-2.0-flash with retry and quota
handling), and a research-backed rubric expansion that incorporates
findings from Fagan, Basili et al. (PBR), Brykczynski, Machado et al.
(rollback modelling), ITIL 4, Google SRE PRR, AWS ORR, and our internal
work-plan template. All 59 tests pass.

> ※ The "59 tests" count above reflects the state at PR #1 merge time.
> Subsequent PRs (including R-H, R-B, R-C, R-J, R-K, R-L) have brought the total
> to **115**, which is the value used by the verification checklist in
> § 6 below.

### PR summary (bullet version)

- **R1** — Loopback-only URL validation for local sanitizer and local
  sensitivity gate. Refuses DNS-resolved hostnames that could point
  anywhere. Enforced at construction and before every request.
- **R2** — `mask_and_continue` documents now require explicit operator
  confirmation before any external call. Enforced in both the Streamlit
  UI (per-document checkboxes) and the HTTP API (`HTTP 409
  confirmation_required`).
- **R3** — Upstream HTTP errors no longer leak response bodies into
  exceptions visible to the client. Errors are logged (redacted) with a
  request id; the client sees only a generic message.
- **R4** — Response extractors return an empty string on parse failure
  instead of `json.dumps(payload)`, so diagnostic text is never treated
  as sanitized content.
- **Streamlit UI** new as the primary UI; four-step flow (upload →
  preview → confirm → send).
- **PDF extraction** via `pypdf`, with `pdftotext` CLI fallback.
- **Gemini free tier** provider now uses `gemini-2.0-flash` by default,
  retries once on 429/5xx, and converts quota exhaustion into a
  human-readable message instead of retrying.
- **Rubric strengthened** with research-backed checks (reversible vs
  irreversible activities, go/no-go decision points, operational
  handover SLO/RACI/escalation, post-implementation review) and aligned
  with our internal work-plan template (environment distinction,
  risk-level + approval, roles, 3-layer information flow, document
  update list). A well-formed template-compliant change runbook now
  produces zero warnings from the mock review.
- **Bug fixes found during self-review**: AAA false-positive on runbooks
  (gated to design profile), `_has_configuration_information` keyword
  miss for 概要図 / 全体概要 / 体制図.
- **Tests**: 59 passing; 10 new suites/files. <!-- ※ PR #1 merge 時点の数字。現在は R-H/R-B/R-C/R-J/R-K/R-L 追加で 115 件 (§ 6 verification checklist 参照) -->
- **Docs**: `docs/security_boundaries.md` new; `docs/basic_design.md`,
  `docs/handoff.md`, `docs/traceability.md`, `docs/operations_policy.md`,
  `docs/local_ollama_verification.md` rewritten to match the current
  state; `docs/v3_streamlit_verification.md` added for real-data
  verification; `README.md` and `.env.example` updated.

### Suggested commit strategy

Three reasonable options, pick with the user:

1. **Single commit** — simplest, matches the "one feature pass" framing.
2. **Two commits** — `(1) security hardening R1-R4` and `(2) features +
   rubric + docs`. Reviewer can consider security in isolation.
3. **Four logical commits** — `(1) R1-R4 hardening`, `(2) Streamlit UI +
   PDF`, `(3) Gemini free tier stabilisation`, `(4) rubric research +
   template alignment + docs`. Finest granularity.

Option 2 is usually the best trade-off for review.

---

## Detailed change log

This pass addresses four review findings, adds the four features requested
for this round (Streamlit UI, PDF extraction, Gemini free-tier
stabilization, documentation/code consistency), and incorporates research
findings from the document-review literature into the review rubric.

## 1. Security fixes (all applied before any new feature)

### R1 — Loopback-only validation for local endpoints
- New file: `secure_review/network_guard.py`
  - `validate_local_url(url, label=...)` refuses anything that does
    not use `127.0.0.1`, `::1`, or `localhost`. RFC1918 private IPs,
    arbitrary hostnames (even if DNS would resolve them to loopback),
    and non-`http(s)` schemes are all rejected.
- `secure_review/sanitizer.py` — `LocalHttpSanitizationEnhancer`
  validates `LOCAL_SANITIZER_API_URL` at construction **and** before
  every request.
- `secure_review/sensitivity.py` — `LocalHttpSensitivityClassifier`
  does the same for `LOCAL_SENSITIVITY_API_URL`.

### R2 — `mask_and_continue` now requires explicit confirmation
- `secure_review/app.py` now exposes two endpoints:
  - `POST /api/preview` — extract, sanitize, assess. No external call.
  - `POST /api/review` — refuses to proceed (HTTP 409,
    `status: confirmation_required`) when any document's decision is
    `mask_and_continue` unless the body carries
    `confirmMaskAndContinue: true` or
    `documentConfirmations: {"<name>": true}`.
- `MASK_AND_CONTINUE_REQUIRE_CONFIRM` env, default `true`.

### R3 — No exception text reaches the client
- `secure_review/network_guard.post_json_safely` catches HTTP and
  transport errors, logs a redacted detail line, and raises
  `UpstreamHttpError` with a generic message only.
- `secure_review/app.py` top-level `do_POST` catch-all produces a
  generic JSON error with a short request id. Log lines carry the
  request id, the client does not see exception text.

### R4 — Safe fallbacks for unparsable LLM responses
- `_extract_openai_like_text` / `_extract_gemini_text` return `""` on
  failure instead of `json.dumps(payload)`.
- `LocalHttpSanitizationEnhancer.enhance` treats empty/unparseable
  output as "keep regex-only sanitization" and records a finding.
- `LocalHttpSensitivityClassifier.assess` treats unreachable or
  empty gate output as `mask_and_continue` with a clear reason.

## 2. Features

### Gemini free-tier stabilization
- `secure_review/reviewer.py`
  - New provider `GeminiFreeTierProvider` selectable via
    `REVIEW_PROVIDER=gemini-free`. Default model is
    `gemini-2.0-flash`, which actually hits the free tier.
  - `GeminiApiReviewProvider._post_with_retry` retries once on 429/5xx
    transport errors. Quota errors (`RESOURCE_EXHAUSTED`, "rate limit",
    ...) are identified by `_looks_like_quota` and surfaced as a
    human-readable `RuntimeError` without retry.
  - `_first_finish_reason` lets the UI explain empty responses
    ("finish_reason=MAX_TOKENS" etc.) rather than failing silently.

### Streamlit UI (primary)
- New file: `streamlit_app.py`.
- Four-step flow (upload → preview → confirm → send). Send button
  disabled until every `mask_and_continue` document is confirmed.
  Blocked documents cannot be confirmed.
- Per-document cards show the decision badge, sanitizer findings,
  replacements, and sanitized excerpt.
- Sidebar shows current providers and lets the operator override the
  review profile.

### PDF extraction
- `secure_review/extractor.py`
  - `_extract_pdf` uses `pypdf` when present; falls back to
    `pdftotext` on PATH; otherwise records a clear warning and a
    placeholder so the document flow still completes.
  - `MAX_PDF_PAGES` (default 300) bounds extraction.

### Archive bomb guard
- `_open_archive_safely` rejects DOCX/XLSX/PPTX whose total uncompressed
  size exceeds `MAX_UNCOMPRESSED_ARCHIVE_BYTES` (default 200 MiB).

### Documentation / code consistency
- `docs/handoff.md` — rewritten for Streamlit-first operation and the
  post-R1–R4 boundaries.
- `docs/traceability.md` — corrected to mark xlsx / pptx / PDF / OCR
  as implemented, with direct code references.
- `docs/operations_policy.md` — confirmation gate described as
  mandatory in production.
- `docs/security_boundaries.md` — new; formal specification of
  loopback, outbound, and containment boundaries.
- `docs/basic_design.md` — updated so that it no longer claims PDF /
  XLSX / Gemini free tier are "future work" now that they ship. The
  document now reflects the actual architecture.
- `docs/local_ollama_verification.md` — rewritten to match the new
  `scripts/local_ollama_precheck.py` interface.

### Review rubric — research-backed improvements
Incorporates findings from Fagan (1976), Basili et al. (1996, PBR),
Brykczynski (1999, checklist survey), Machado et al. (2008, rollback
modelling in ITIL change management), Google SRE PRR, and AWS ORR:

- `change_runbook` axis `change_risk` now checks for reversible /
  irreversible classification, go/no-go decision points, and
  compensation procedures for irreversible activities.
- `change_runbook` gains a `post_implementation_review` axis: record
  work outcome, confirm SLA impact, capture learnings.
- `operations_runbook` gains an `operational_handover` axis that
  covers SLO / SLA, the link between monitoring and runbooks,
  ownership (RACI-equivalent), escalation path, and hypercare.
- A new `OPTIONAL_CHECKS.wbs_consistency_if_present` is attached to
  both runbook profiles. It verifies WBS integrity **only when WBS is
  present**; it never demands creation of a WBS. This encodes the
  explicit user policy "WBS があれば確認、なければ強要しない".

The `MockReviewProvider` grew matching heuristics so rubric and
observable behaviour move together.

### Review rubric — 作業計画書 template alignment
Reviewed the user's internal work-plan template and aligned the
`change_runbook` rubric to match what the template demands:

- `completeness` axis: added checkpoints for 日時・場所・作業対象 and
  本番／検証環境の区別.
- `change_risk` axis: added checkpoints for リスクレベル + 承認
  プロセスと 予測できない有事への対策方針.
- `operability` axis: added checkpoints for 役割分担（作業者・再鑑者・
  現地統括）と 情報共有の 3 層（エスカレーション／問題発生時展開／
  通常時共有）の区別.
- `post_implementation_review` axis: added checkpoints for 作業後に
  修正が必要となるドキュメントの事前一覧 と 変更履歴管理.

New `MockReviewProvider` heuristics cover these so the mock can flag
templates missing them: `_has_environment_distinction`,
`_has_risk_level_with_approval`, `_has_document_update_list`.

Two integrity bugs found while exercising the template were fixed at
the same time:

- "AAA configuration not explicit" was a Cisco-config rule that was
  firing on runbooks; gated to the `design` profile.
- `_has_configuration_information` missed 概要図 / 全体概要 / 体制図
  so a change runbook saying 「全体概要図」 was flagged as missing
  configuration. Keyword list extended.

A well-formed work plan that matches the template now produces zero
warnings from the mock review, confirming rubric–template alignment.

### Precheck script
- `scripts/local_ollama_precheck.py` now supports `--input-file` for
  a full extract → sanitize → sensitivity pipeline run on a real
  file. The flag was present in the baseline `README.md` and
  `docs/local_ollama_verification.md`; restoring it keeps those docs
  accurate.

## 3. Static UI

The old `static/index.html` + `static/app.js` pre-date the
`/api/preview` endpoint and the confirmation gate. They are replaced
in this bundle with a minimal landing page that points at the
Streamlit app. If you prefer to keep the old static UI as an emergency
fallback, simply do not copy this bundle's `static/index.html` over
your existing file — but note that the old JS will break on any
document that the sensitivity gate marks `mask_and_continue`.

## 4. Tests

All tests live under `tests/`, 59 tests total, all passing.

> ※ 59 = PR #1 merge 時点の数字。R-H で 4 件、R-B/R-C で 6 件、R-J で 3 件、R-K で 14 件、R-L で 25 件追加され、現在は **115 件**。`§ 6 Quick verification checklist` の `expect 115 passing` がカレント値。

Run with:

```
python -m unittest discover tests
```

New or updated suites:

- `tests/test_network_guard.py` — URL validation and safe HTTP client
  (R1/R3).
- `tests/test_sanitizer.py` — IPv6 compressed forms, loopback
  enforcement, LLM-unreachable fail-safe, local masking integration.
- `tests/test_sensitivity.py` — loopback enforcement, fail-safe,
  truncation downgrade.
- `tests/test_reviewer.py` — Gemini retry, quota detection, empty
  response, model selection, OpenAI parser fallback, **rubric
  research-backed additions** (operational handover axis, PIR axis,
  WBS optional check, irreversible-without-rollback heuristic).
- `tests/test_env_loader.py` — unchanged coverage, re-imported so it
  runs as part of the suite.
- `tests/test_app.py` — full HTTP flow including the R2 confirmation
  gate and R3 error containment.

## 5. Map from this bundle to your repository

When unpacking, copy each file back into the matching path in your
working repository. The baseline layout was:

| This bundle | Target repository path |
| --- | --- |
| `secure_review/__init__.py` | `secure_review/__init__.py` |
| `secure_review/app.py` | `secure_review/app.py` |
| `secure_review/env_loader.py` | `secure_review/env_loader.py` (unchanged content; safe to keep yours) |
| `secure_review/extractor.py` | `secure_review/extractor.py` |
| `secure_review/models.py` | `secure_review/models.py` (unchanged content; safe to keep yours) |
| `secure_review/network_guard.py` | `secure_review/network_guard.py` (new) |
| `secure_review/reviewer.py` | `secure_review/reviewer.py` |
| `secure_review/rubric.py` | `secure_review/rubric.py` (unchanged content; safe to keep yours) |
| `secure_review/sanitizer.py` | `secure_review/sanitizer.py` |
| `secure_review/sensitivity.py` | `secure_review/sensitivity.py` |
| `scripts/local_ollama_precheck.py` | `scripts/local_ollama_precheck.py` |
| `static/index.html` | `static/index.html` (only if you want the migration landing) |
| `streamlit_app.py` | repository root |
| `requirements.txt` | repository root |
| `tests/*.py` | `tests/` |
| `docs/handoff.md` | `docs/handoff.md` |
| `docs/traceability.md` | `docs/traceability.md` |
| `docs/operations_policy.md` | `docs/operations_policy.md` |
| `docs/security_boundaries.md` | `docs/security_boundaries.md` (new) |
| `docs/basic_design.md` | `docs/basic_design.md` (overwrite; current version is stale) |
| `docs/local_ollama_verification.md` | `docs/local_ollama_verification.md` (rewritten for new precheck CLI) |
| `docs/v3_streamlit_verification.md` | `docs/v3_streamlit_verification.md` (new) |
| `README.md` | `README.md` (updated: Streamlit-first, current env vars) |
| `.env.example` | `.env.example` (overwrite or merge; contains all current env vars) |
| `CHANGES.md` | `CHANGES.md` (or wherever you keep change notes) |

## 6. Quick verification checklist

After unpacking:

1. `pip install -r requirements.txt`
2. `python -m unittest discover tests` — expect 115 passing.
3. `python scripts/local_ollama_precheck.py` — should pass if your
   local Ollama is running, or clearly refuse a misconfigured non-
   loopback URL without crashing. Add `--input-file <path>` to
   validate a real document end-to-end.
4. `streamlit run streamlit_app.py` — upload a small file, verify
   the preview step runs without an external call, then confirm and
   send.
