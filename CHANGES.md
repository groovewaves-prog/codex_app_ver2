# Changes — April 2026 hardening pass

Baseline commit: `eaf605a`.

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
