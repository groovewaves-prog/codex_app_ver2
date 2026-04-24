# Traceability

Last updated: 2026-04-23 (post R1–R4 hardening pass)

This document traces design goals back to the code that implements them.
It was previously inaccurate about xlsx/pptx/PDF/OCR status; this pass
corrects that.

## 1. File ingestion

| Capability | Status | Code |
| --- | --- | --- |
| Plain text, markdown, logs | Implemented | `extractor.extract_text` default branch |
| Source code (py, ps1, sh, vbs, bas, sql, ...) | Implemented | Same default branch; profile picked by `rubric.classify_documents` |
| JSON / YAML / CSV / XML / HTML | Implemented | `_format_json`, `_format_csv`, `_strip_markup` in `extractor.py` |
| DOCX | Implemented | `extractor._extract_docx` |
| XLSX | Implemented (corrects earlier "not implemented" note) | `extractor._extract_xlsx` with shared-strings + per-sheet scan |
| PPTX | Implemented | `extractor._extract_pptx` with slide + notes + embedded images |
| PDF | Implemented (new in this pass) | `extractor._extract_pdf` via `pypdf`, falling back to `pdftotext` |
| Images (OCR) | Implemented when Tesseract is present | `extractor._run_local_ocr` |
| Archive bomb guard | Implemented | `extractor._open_archive_safely` + `MAX_UNCOMPRESSED_ARCHIVE_BYTES` |
| PDF page cap | Implemented | `MAX_PDF_PAGES` |

## 2. Sanitization

| Capability | Status | Code |
| --- | --- | --- |
| Credential masking (`password`/`token`/`secret`) | Implemented | `SensitiveDataSanitizer._patterns` |
| IPv4 / IPv6 (including compressed forms) | Implemented | Same, plus IPv6 regex covering `::1`, `fe80::1` |
| MAC, email, URL | Implemented | Same |
| Hostname / site / device (label-based) | Implemented | Same |
| Customer / project / ticket / person (label-based) | Implemented | Same |
| Confidentiality markers (社外秘 / confidential / ...) | Implemented | `_confidentiality_patterns` |
| Legal-entity markers (株式会社, Inc., Ltd., ...) | Implemented | `_legal_entity_pattern` |
| Consistent placeholder reuse per value | Implemented | `_placeholder` + `_seen` dict |
| Local LLM sanitizer (optional) | Implemented | `LocalHttpSanitizationEnhancer`, `OllamaSanitizationEnhancer` |
| Unapproved placeholder detection | Implemented | `_UNAPPROVED_PLACEHOLDER_PATTERNS` + surfaced as finding |
| Placeholder normalization (`[SITE_1]` → `[SITE_001]`) | Implemented | `_normalize_local_placeholders` |
| Fail-safe when local LLM unreachable | Implemented | `LocalHttpSanitizationEnhancer.enhance` keeps regex-only text + finding |

## 3. Local sensitivity gate

| Capability | Status | Code |
| --- | --- | --- |
| Heuristic gate (no LLM) | Implemented | `HeuristicSensitivityClassifier` |
| Local LLM gate (Ollama / OpenAI-compatible) | Implemented | `LocalHttpSensitivityClassifier`, `OllamaSensitivityClassifier` |
| Decisions: `safe` / `mask_and_continue` / `block` | Implemented | Both classifiers |
| Truncation downgrade (`safe` → `mask_and_continue` when only head was evaluated) | Implemented | `LocalHttpSensitivityClassifier.assess` |
| Fail-safe when gate unreachable | Implemented | Returns `mask_and_continue` with a reason |

## 4. External boundary

| Capability | Status | Code |
| --- | --- | --- |
| Loopback-only validation (R1) | Implemented | `network_guard.validate_local_url`, called at construction and before each request |
| Safe HTTP client (R3) | Implemented | `network_guard.post_json_safely` |
| Safe parser fallbacks (R4) | Implemented | `_extract_openai_like_text` and `_extract_gemini_text` return `""` on failure |
| `mask_and_continue` confirmation gate (R2) | Implemented | `app._handle_review` returns HTTP 409 without confirm; Streamlit disables Send button without confirm |
| `block` and `high outbound risk` hard refusal | Implemented | `app._enforce_block_gate`, `_enforce_outbound_guard` |
| Request body cap | Implemented | `app.MAX_REQUEST_BYTES` |
| Error containment (no exception text to client) | Implemented | `app.do_POST` catch-all + `request_id` |

## 5. Review providers

| Provider | Status | Code |
| --- | --- | --- |
| Mock | Implemented | `MockReviewProvider` |
| HTTP (OpenAI-compatible) | Implemented | `HttpLlmReviewProvider` |
| Gemini (Gemma-hosted) | Implemented | `GeminiHostedGemmaProvider` |
| Gemini free tier (2.0 flash) | Implemented (new in this pass) | `GeminiFreeTierProvider`, selectable via `REVIEW_PROVIDER=gemini-free` |
| Transient-error retry (429/5xx) | Implemented | `GeminiApiReviewProvider._post_with_retry` |
| Quota detection | Implemented | `_looks_like_quota` |
| Empty-response handling | Implemented | `_first_finish_reason` + clear `RuntimeError` |

## 6. UI

| Capability | Status | Code |
| --- | --- | --- |
| Streamlit UI (primary) | Implemented (new in this pass) | `streamlit_app.py` |
| Preview / confirm / send workflow | Implemented | Same |
| Per-document confirmation checkboxes | Implemented | Same |
| Provider and profile selection | Implemented | Streamlit sidebar |
| Static HTML UI | Replaced with a migration notice pointing at Streamlit (previous `static/index.html` + `static/app.js` are obsolete) | `static/index.html` |

## 7. Documentation

| Document | Status |
| --- | --- |
| `docs/handoff.md` | Rewritten as the canonical handoff artifact for the next chat (GitHub push). Section 0 contains the starter prompt. |
| `docs/traceability.md` | This document |
| `docs/security_boundaries.md` | New in this pass — formal specification of the loopback, outbound, and containment boundaries |
| `docs/operations_policy.md` | Updated: confirmation gate is mandatory in production |
| `docs/basic_design.md` | Updated: PDF/XLSX/Gemini free tier are marked implemented, no longer "future work" |
| `docs/local_ollama_verification.md` | Rewritten to match the new precheck CLI |
| `docs/v3_streamlit_verification.md` | New: step-by-step procedure for verifying the Streamlit UI against real data |
| `README.md` | Rewritten: Streamlit-first, updated env vars table, links to v3 verification |
| `.env.example` | Rewritten: full current env var inventory with comments |

## 8. Review rubric — research-backed improvements

| Capability | Status | Code | Origin |
| --- | --- | --- | --- |
| WBS optional check (verify if present, never demand creation) | Implemented | `rubric.OPTIONAL_CHECKS` attached to `change_runbook` and `operations_runbook` | User policy + Machado 2008 / ITIL 4 practice |
| Reversible vs irreversible activity classification | Implemented (checkpoints + MockReviewProvider heuristic) | `change_runbook.change_risk` axis, `_has_irreversible_operation_signals`, `_has_rollback_signals` | Machado et al. 2008, "Enabling rollback support in IT change management systems" |
| Post-Implementation Review axis | Implemented | `change_runbook.post_implementation_review` | ITIL 4 Change Enablement |
| Operational handover axis (SLO, monitoring→runbook link, RACI, escalation) | Implemented | `operations_runbook.operational_handover` + `_has_operational_handover_signals` | Google SRE PRR + AWS ORR |
| Go/no-go decision point | Implemented as checkpoint | `change_runbook.change_risk` | ITIL 4 Change Enablement |

## 9. Tests

All under `tests/`, 59 tests total:

- `test_network_guard.py` — URL validation + safe HTTP client
- `test_sanitizer.py` — regex coverage + IPv6 + loopback + fail-safe
- `test_sensitivity.py` — heuristic + loopback + truncation + fail-safe
- `test_reviewer.py` — providers + Gemini retry + quota
- `test_env_loader.py` — `.env` parsing
- `test_app.py` — preview/review HTTP flow + R2 + R3
