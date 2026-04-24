# Security boundaries

This document explains the concrete security boundaries enforced by
`secure_review` and the design decisions behind them. It reflects the
implementation after the R1–R4 hardening pass (April 2026).

## 1. Scope

`secure_review` is an internal tool that lets reviewers submit sensitive
artifacts (designs, change runbooks, operations runbooks, scripts) for
AI-assisted review, while keeping the original content from reaching any
external service.

Two boundaries exist:

1. **Loopback boundary.** Anything labeled "local" must reach a loopback
   address only. The application is responsible for refusing to contact
   non-loopback hosts even if an operator misconfigures an environment
   variable.
2. **Outbound boundary.** Only the sanitized text reaches an external LLM
   provider. Original text, replacement maps, and internal identifiers
   never leave the server process.

## 2. Loopback boundary (R1)

### Requirement

The local sanitizer and the local sensitivity gate receive the **original**
(unmasked) text. Therefore their endpoints must not point outside the
machine running `secure_review`.

### Enforcement

`secure_review.network_guard.validate_local_url` accepts only:

- IPv4 loopback literals (`127.0.0.1`, `127.0.0.2`, ...)
- IPv6 loopback literal (`::1`)
- The hostname `localhost` (and its IPv6 aliases)

It rejects:

- Any other hostname — even if DNS would resolve it to `127.0.0.1`, because
  DNS records can change. Operators configure loopback literals directly.
- RFC1918 private ranges (`10/8`, `192.168/16`, `172.16/12`). These are
  private but still off-machine.
- Non-`http(s)` schemes (`file://`, `ftp://`, etc.).

Validation runs twice:

- **At construction**, so `secure_review.sanitizer.choose_local_sanitization_enhancer`
  and `secure_review.sensitivity.choose_sensitivity_classifier` raise
  `LocalUrlError` rather than returning a misconfigured instance.
- **Before every request**, so a long-running process that swaps env vars
  cannot slip past the first check.

## 3. Outbound boundary (R2)

### Requirement

The operator must have explicitly approved each document whose local
sensitivity decision is `mask_and_continue` before the external LLM is
called. The previous version surfaced a warning and proceeded; we now
require a positive confirmation.

### Enforcement

HTTP API:

- `POST /api/preview` runs extract + sanitize + sensitivity gate. It
  **does not** call the external LLM. The response includes each
  document's decision, findings, and sanitized excerpt.
- `POST /api/review` calls the external LLM only if, for every
  document with decision `mask_and_continue`, the request body contains
  either `confirmMaskAndContinue: true` or
  `documentConfirmations: {"<name>": true}`. Otherwise it responds with
  `HTTP 409` and `status: "confirmation_required"`.
- Any document with decision `block` or `outbound_risk = "high"` is
  refused outright (`HTTP 400`).

Streamlit UI:

- Steps are separated. The Send button is disabled until the operator
  has ticked the per-document confirm checkbox for every document whose
  decision is `mask_and_continue`.

The environment variable `MASK_AND_CONTINUE_REQUIRE_CONFIRM` can be set
to `false` in test environments to bypass the gate. It defaults to
`true` and should remain `true` in production.

## 4. Error containment (R3)

Upstream HTTP errors never surface the response body in exceptions that
reach the UI. `secure_review.network_guard.post_json_safely`:

1. Catches HTTP and transport errors.
2. Writes a redacted, truncated detail line to the module logger with
   long lines trimmed so prompt echoes cannot leak through logs either.
3. Raises `UpstreamHttpError` with a generic message ("… returned HTTP
   500. See server logs for details.").

The HTTP handler mirrors this: any unexpected exception is logged with
a short request id, and the client receives a generic JSON error that
includes only the request id and the exception class name (no message,
no traceback).

## 5. Parser fallbacks (R4)

Before this pass, when an LLM response did not match any known shape,
the extractor returned `json.dumps(payload)` as the sanitized text. This
meant upstream diagnostic text or even the echoed prompt could be
treated as "sanitized". Both response extractors used in the pipeline —
`_extract_openai_like_text` (for OpenAI-compatible and Ollama endpoints)
and `_extract_gemini_text` (for the Gemini API) — now return an
**empty string** on failure. Callers treat empty strings as an
explicit failure and fall back to the previously-known-good sanitized
text.

## 6. Additional protections introduced alongside R1–R4

- **Archive bomb guard.** `secure_review.extractor` refuses to expand a
  DOCX / XLSX / PPTX whose total uncompressed size exceeds
  `MAX_UNCOMPRESSED_ARCHIVE_BYTES` (default 200 MiB).
- **PDF page cap.** `MAX_PDF_PAGES` (default 300) bounds how much of a
  single PDF we try to extract.
- **Request body cap.** `MAX_REQUEST_BYTES` (default 64 MiB) bounds a
  single HTTP request; requests larger than this are rejected with
  `HTTP 400` before any buffer allocation.
- **Unapproved placeholder detection.** If the local LLM invents its
  own placeholder style (e.g., `<REDACTED>`, `***`, `[MASKED-FOO]`),
  the sanitizer leaves the content as-is but records a finding so the
  operator can review.
- **Truncation downgrade.** When the local sensitivity gate decides
  `safe` but only saw the head of a long document (above
  `LOCAL_SENSITIVITY_INPUT_CHARS`), the decision is downgraded to
  `mask_and_continue` so a human sees the tail.

## 7. Non-goals and residual risk

- No authentication or authorization is enforced between the browser
  and the HTTP API. Deployments that are not single-user on a trusted
  host must place the app behind an auth proxy.
- No audit log is persisted. Operators who need one should run the
  process under `systemd-journald` or similar and forward stdout.
- The local LLM's own reasoning quality is out of scope. The
  application treats its output as untrusted: every placeholder it
  emits is normalized, unapproved formats are flagged, and a downstream
  regex sanitizer always re-runs.
