# Operations policy

Last updated: 2026-04-24

## 1. Deployment stance

- Run `secure_review` on a single-user machine, or on a shared host
  behind an authentication proxy. The HTTP API and the Streamlit UI do
  not enforce authentication themselves.
- Bind the HTTP server and Streamlit to `127.0.0.1` (the default).
  Exposing either on a non-loopback interface without an auth layer is
  a policy violation.
- Run as a dedicated low-privilege user. Give that user read access
  only to the review input directory.

## 2. Mandatory environment settings

Production deployments **must** have:

- `MASK_AND_CONTINUE_REQUIRE_CONFIRM=true` (default). Setting this to
  `false` disables R2's confirmation gate and is only allowed in
  offline test environments.
- `LOCAL_SANITIZER_API_URL` and `LOCAL_SENSITIVITY_API_URL` pointing
  at `127.0.0.1`, `::1`, or `localhost` when they are set at all. The
  application will refuse to start the request otherwise, but
  operators should still confirm at deploy time.

## 3. Confirmation gate workflow

When the local sensitivity gate returns `mask_and_continue` for a
document, the operator must:

1. Open the sanitized excerpt in the preview step.
2. Verify that no remaining identifier would let an external party
   reconstruct the customer, project, site, or person.
3. Tick the per-document confirmation checkbox (Streamlit) or set
   `documentConfirmations: {"<n>": true}` in the HTTP request.

Only after every `mask_and_continue` document is confirmed will the
external LLM receive any content. Blocked documents cannot be
confirmed — they must be re-sanitized at source.

## 4. Incident response

If the UI shows a document the operator did not expect to be safe:

1. **Do not click Send.** Reset the session from the sidebar.
2. Check `LOCAL_SANITIZER_API_URL` and `LOCAL_SENSITIVITY_API_URL`.
   A non-loopback value will have been rejected at startup; a
   partially-configured local LLM can leave the heuristic gate as
   the only defense.
3. Re-run with `REVIEW_PROVIDER=mock` to confirm the pipeline is
   still reporting the same decisions.

If a `high` outbound risk document reaches the review step anyway, it
is refused by `_enforce_outbound_guard` before the provider is called;
the UI will show the refusal text. No content has been sent.

## 5. Logging

- stdout carries pipeline-level INFO and provider-level INFO.
- Upstream HTTP errors are logged via the module logger
  `secure_review.network` with the response body redacted (long lines
  truncated; no quoted literals over ~240 chars). The URL is stripped
  of query and fragment before logging.
- No request body or document content is logged.

Operators who need an audit trail should capture stdout to a file via
`systemd-journald` or similar and enforce rotation at that layer.

## 6. Provider choice

- `mock`: default. Safe to use for UI verification. No network calls.
- `gemini-free`: Gemini free tier (`gemini-2.0-flash` by default).
  Requires `GEMINI_API_KEY` or `GOOGLE_API_KEY`. Retries once on
  transient errors; raises a clearly-labeled `RuntimeError` on
  quota exhaustion.
- `gemma` / `gemini-gemma`: same API, Gemma-hosted model. Requires
  paid tier access in practice.
- `http`: any OpenAI-compatible endpoint specified by `LLM_API_URL`.

Choose the provider per review session. Switching providers does not
require a restart.

## 7. Upgrade checklist (for subsequent revisions)

When changing this tool:

1. Re-run `python -m unittest discover tests`. All 59 tests must pass.
2. Re-run `python scripts/local_ollama_precheck.py` against the local
   stack you rely on. It will reject non-loopback endpoints and will
   report whether the local sanitizer and gate respond to a synthetic
   request.
3. Review `docs/security_boundaries.md`. If the change touches any of
   its named boundaries (R1–R4, archive bomb guard, PDF cap), update
   that document in the same change.
4. Review `docs/traceability.md` so the code-to-requirement mapping
   stays current.
