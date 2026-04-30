from __future__ import annotations

import json
import logging
import math
import os
import re
from collections import defaultdict
from dataclasses import dataclass

from secure_review.models import SanitizationRecord, SanitizedDocument
from secure_review.network_guard import (
    LocalUrlError,
    UpstreamHttpError,
    post_json_safely,
    validate_local_url,
)


LOGGER = logging.getLogger("secure_review.sanitizer")


@dataclass
class SanitizationResult:
    sanitized_text: str
    records: list[SanitizationRecord]
    findings: list[str]
    estimated_input_tokens: int
    outbound_risk: str


@dataclass
class LocalSanitizationResponse:
    sanitized_text: str
    findings: list[str]
    outbound_risk: str


APPROVED_LOCAL_PLACEHOLDERS = [
    "SECRET",
    "IPV4",
    "IPV6",
    "EMAIL",
    "MAC",
    "HOSTNAME",
    "COMPANY",
    "PROJECT",
    "TICKET",
    "PERSON",
    "URL",
    "SITE",
    "DEVICE",
    "GENERIC_IDENTIFIER",
]


# Internal naming-convention vocabulary for bare hostname detection (R-H / M1).
#
# Used by `_build_internal_hostname_pattern` to match site-internal device
# identifiers like ``tokyo-rtr-01`` that have no ``hostname:`` label and would
# otherwise slip past the labelled regex above.
#
# Design intent: only match when the *middle* segment is a recognised device
# keyword. This keeps false positives low — generic ``foo-bar-01`` strings,
# package versions like ``python-3.11``, dates like ``2026-04-27``, and
# documentation strings like ``gemma-4-31b`` do not match because their middle
# segment is not in this vocabulary.
#
# Operators may extend this list as new device-type abbreviations appear in
# real production data. See `docs/operations_policy.md` § 3.2 for the
# governing policy.
INTERNAL_HOSTNAME_DEVICE_KEYWORDS: tuple[str, ...] = (
    # Network equipment
    "rtr", "fw", "sw", "lb", "nlb", "alb", "gw", "vpn", "ips", "ids", "wlc", "ap",
    # Servers / compute
    "srv", "vm", "host", "node", "app", "web", "api", "bat",
    # Storage / database
    "db", "nas", "san", "bk", "dr",
)


# R-J: detect the canonical placeholder shape ``[CATEGORY_NNN]`` used by this
# sanitizer. Used by `_replace_pattern` to skip re-masking values that have
# already been placeholder-ised by a more specific (earlier) pattern. The
# trailing digit count is open-ended so future hierarchies (e.g. 4-digit
# counters) keep working without changing this regex.
_PLACEHOLDER_REUSE_PATTERN: re.Pattern[str] = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")


def _build_internal_hostname_pattern(keywords: tuple[str, ...]) -> re.Pattern[str]:
    """Compile the bare-hostname regex from a device-keyword vocabulary.

    Matches strings of the form ``[<location-or-env>{sep}]<device-kw>{sep}<digits>``
    where:

    - location-or-env (optional)  : one or more alphanumeric chars starting
      with a letter (e.g. ``tokyo``, ``prd``, ``Tokyo``)
    - device-kw  (mandatory)       : exact match against ``keywords``
    - sep                          : ``-`` / ``_`` / ``.``
    - digits                       : 1-5 decimal digits

    The whole match is case-insensitive. Word boundaries (``\\b``) at both
    ends prevent partial matches inside larger tokens like ``localhost-01``
    or ``combat-01``.
    """
    keyword_alt = "|".join(re.escape(kw) for kw in keywords)
    pattern = (
        r"\b"
        r"(?:[A-Za-z][A-Za-z0-9]*[-_.])?"   # optional location/env segment
        rf"(?:{keyword_alt})"               # device-type keyword (mandatory)
        r"[-_.]"                            # separator
        r"\d{1,5}"                          # numeric suffix (1-5 digits)
        r"\b"
    )
    return re.compile(pattern, re.IGNORECASE)


# Patterns that detect placeholder-like tokens that are NOT in our approved
# list. If the local LLM invents its own masking style (<REDACTED>, ***, etc.)
# we want to flag that rather than silently trust it.
_UNAPPROVED_PLACEHOLDER_PATTERNS = [
    re.compile(r"<[A-Z][A-Z0-9_]{2,}>"),
    re.compile(r"\*{3,}"),
    re.compile(r"\[REDACTED[^\]]*\]", re.IGNORECASE),
    re.compile(r"\[MASKED[^\]]*\]", re.IGNORECASE),
    re.compile(r"\{\{[^}]+\}\}"),
]


LOCAL_SANITIZER_PROMPT = """You are a local data sanitization assistant that runs before any external LLM transfer.
Your only job is to make the text safer for external review while preserving the technical meaning.

Rules:
- Start from the current sanitized text and make the minimum additional changes needed.
- Keep existing placeholders like [SECRET_001] unchanged.
- Preserve the original structure, ordering, indentation, commands, code, and technical meaning.
- Do not summarize, translate, explain, or rewrite generic technical content.
- Replace any remaining customer names, project names, person names, ticket numbers, site names, device names, topology identifiers, credentials, URLs, or other identifying business context with neutral placeholders.
- Use only these placeholder categories:
  [SECRET_001], [IPV4_001], [IPV6_001], [EMAIL_001], [MAC_001], [HOSTNAME_001],
  [COMPANY_001], [PROJECT_001], [TICKET_001], [PERSON_001], [URL_001],
  [SITE_001], [DEVICE_001], [GENERIC_IDENTIFIER_001]
- Reuse the same placeholder consistently when the same sensitive item appears multiple times.
- Do not invent new placeholder formats such as <REDACTED>, *** or {{NAME}}.
- Do not add explanations into the sanitized text.
- Return JSON only.

Return format:
{
  "sanitized_text": "sanitized text",
  "findings": ["finding 1", "finding 2"],
  "risk": "low | medium | high"
}
"""


class SensitiveDataSanitizer:
    """Redacts likely confidential values before any LLM transfer."""

    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)
        self._seen: dict[tuple[str, str], str] = {}
        self._preview_limit = int(os.getenv("SANITIZED_PREVIEW_CHARS", "1200"))
        self._outbound_limit = int(os.getenv("OUTBOUND_TEXT_CHARS", "16000"))
        self._patterns: list[tuple[str, re.Pattern[str]]] = [
            (
                "secret",
                re.compile(
                    r"(?im)\b(password|secret|community|token|apikey|api_key|key)\b\s*[:= ]+\s*([^\s,;]+)"
                ),
            ),
            ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
            # IPv6 coverage: full form, compressed (::1, fe80::1), and mixed.
            (
                "ipv6",
                re.compile(
                    r"(?<![\w:])(?:"
                    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
                    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
                    r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
                    r")(?![\w:])"
                ),
            ),
            ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
            ("mac", re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")),
            (
                "hostname",
                re.compile(
                    r"(?im)\b(hostname|device-name|system-name)\b\s*[:= \t]+\s*([A-Za-z0-9_.-]+)"
                ),
            ),
            # R-H / M1: bare hostnames using internal naming convention
            # (e.g. ``tokyo-rtr-01``). Falls back to the same ``hostname``
            # category so the placeholder ``[HOSTNAME_NNN]`` numbering stays
            # consistent with labelled detections above.
            (
                "hostname",
                _build_internal_hostname_pattern(INTERNAL_HOSTNAME_DEVICE_KEYWORDS),
            ),
            (
                "company",
                re.compile(
                    r"(?im)(?:^|\b)(customer(?:-name)?|client|company(?:-name)?|organization|vendor|"
                    r"顧客名|お客様名|会社名|企業名|ベンダ(?:名)?|委託先)\b\s*[:=: ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            (
                "project",
                re.compile(
                    r"(?im)(?:^|\b)(project(?:-name)?|system(?:-name)?|service(?:-name)?|"
                    r"案件名|プロジェクト名|システム名|サービス名)\b\s*[:=: ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            (
                "ticket",
                re.compile(
                    r"(?im)(?:^|\b)(change-id|change no|ticket|incident|request-id|"
                    r"変更番号|申請番号|案件番号|回線番号|契約番号)\b\s*[:=: ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            (
                "person",
                re.compile(
                    r"(?im)(?:^|\b)(owner|contact|manager|担当者|連絡先|申請者|責任者)\b\s*[:=: ]+\s*([^\r\n,;]{2,80})"
                ),
            ),
            ("url", re.compile(r"\bhttps?://[^\s)]+")),
        ]
        self._confidentiality_patterns: list[re.Pattern[str]] = [
            re.compile(r"(?im)\b(confidential|strictly confidential|internal use only|proprietary)\b"),
            re.compile(r"社外秘|部外秘|機密|極秘|取扱注意|社内限定|関係者限り"),
        ]
        self._legal_entity_pattern = re.compile(
            r"株式会社[^\s、,.;:]{1,40}|[^\s、,.;:]{1,40}(?:株式会社|有限会社)|"
            r"\b[A-Z][A-Za-z0-9&.,' -]{1,40}\s(?:Inc\.?|Corp\.?|LLC|Ltd\.?|Co\.?)\b"
        )

    def sanitize(self, name: str, text: str) -> SanitizedDocument:
        result = self.sanitize_text(text)
        outbound_text = result.sanitized_text[: self._outbound_limit]
        findings = list(result.findings)

        if len(result.sanitized_text) > self._outbound_limit:
            findings.append(
                f"Outbound text was truncated to {self._outbound_limit} characters to stay within a conservative review budget."
            )

        return SanitizedDocument(
            name=name,
            original_excerpt=text[: self._preview_limit],
            sanitized_excerpt=outbound_text[: self._preview_limit],
            outbound_text=outbound_text,
            replacements=result.records[:100],
            findings=findings,
            estimated_input_tokens=self._estimate_tokens(outbound_text),
            outbound_risk=result.outbound_risk,
        )

    def sanitize_text(self, text: str) -> SanitizationResult:
        records: list[SanitizationRecord] = []
        findings: list[str] = []
        sanitized = text
        risk_score = 0

        if self._patterns[0][1].search(text):
            findings.append("Credentials-like values were detected and masked.")
            risk_score = max(risk_score, 1)

        for category, pattern in self._patterns:
            sanitized = self._replace_pattern(sanitized, pattern, category, records)

        confidentiality_hits = sum(1 for pattern in self._confidentiality_patterns if pattern.search(text))
        if confidentiality_hits:
            findings.append(
                "Explicit confidentiality markers were detected locally. External transfer should use only the sanitized text."
            )
            risk_score = max(risk_score, 3)

        if any(record.category in {"company", "project", "ticket", "person"} for record in records):
            findings.append("Customer, project, ticket, or contact identifiers were detected and masked where possible.")
            risk_score = max(risk_score, 2)

        if self._legal_entity_pattern.search(text):
            findings.append("Corporate-name markers were detected. Please confirm that no identifying context remains.")
            risk_score = max(risk_score, 2)

        if len(records) >= 25:
            findings.append(
                "A large number of sensitive values were detected. Consider splitting the review into smaller sanitized batches."
            )
            risk_score = max(risk_score, 2)

        return SanitizationResult(
            sanitized_text=sanitized,
            records=records,
            findings=findings,
            estimated_input_tokens=self._estimate_tokens(sanitized),
            outbound_risk=self._risk_from_score(risk_score),
        )

    def _replace_pattern(
        self,
        text: str,
        pattern: re.Pattern[str],
        category: str,
        records: list[SanitizationRecord],
    ) -> str:
        def replacement(match: re.Match[str]) -> str:
            if match.lastindex and match.lastindex >= 2:
                value = match.group(2)
                # R-J: when the captured value is already a sanitizer placeholder
                # (e.g. ``[EMAIL_001]`` from an earlier pattern), the more specific
                # category that produced it is the correct semantic label. Do not
                # re-mask under this looser label-based pattern. This prevents
                # collisions like ``連絡先: yamada@example.com`` getting masked as
                # ``[PERSON_001]`` after ``email`` already turned the address into
                # ``[EMAIL_001]``.
                if _PLACEHOLDER_REUSE_PATTERN.fullmatch(value.strip()):
                    return match.group(0)
                placeholder = self._placeholder(category, value)
                self._append_record(records, placeholder, value, category)
                return match.group(0).replace(value, placeholder)

            value = match.group(0)
            placeholder = self._placeholder(category, value)
            self._append_record(records, placeholder, value, category)
            return placeholder

        return pattern.sub(replacement, text)

    def _placeholder(self, category: str, value: str) -> str:
        key = (category, value)
        if key not in self._seen:
            self._counters[category] += 1
            self._seen[key] = f"[{category.upper()}_{self._counters[category]:03d}]"
        return self._seen[key]

    @staticmethod
    def _append_record(
        records: list[SanitizationRecord],
        placeholder: str,
        original: str,
        category: str,
    ) -> None:
        if any(record.placeholder == placeholder for record in records):
            return
        records.append(
            SanitizationRecord(
                placeholder=placeholder,
                original=original,
                category=category,
            )
        )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        if not text:
            return 0
        return max(1, math.ceil(len(text) / 4))

    @staticmethod
    def _risk_from_score(score: int) -> str:
        if score >= 3:
            return "high"
        if score >= 2:
            return "medium"
        return "low"


class LocalSanitizationEnhancer:
    name = "none"

    def enhance(
        self,
        name: str,
        original_text: str,
        sanitized_document: SanitizedDocument,
        sanitizer: SensitiveDataSanitizer,
    ) -> SanitizedDocument:
        return sanitized_document


class LocalHttpSanitizationEnhancer(LocalSanitizationEnhancer):
    """Send the already-sanitized text to a local LLM for deeper masking.

    SECURITY NOTE: The original, unmasked text is included in the request body
    (bounded by ``LOCAL_SANITIZER_INPUT_CHARS``). For that reason, the target
    URL MUST point to a loopback address; this is enforced on construction and
    re-checked before every request.
    """

    name = "local-http"

    def __init__(self) -> None:
        raw_url = os.getenv("LOCAL_SANITIZER_API_URL", "").strip()
        self.api_url = validate_local_url(raw_url, label="LOCAL_SANITIZER_API_URL") if raw_url else ""
        self.api_key = os.getenv("LOCAL_SANITIZER_API_KEY", "").strip()
        self.model = os.getenv("LOCAL_SANITIZER_MODEL", "").strip()
        self.max_chars = int(os.getenv("LOCAL_SANITIZER_INPUT_CHARS", "12000"))

    def enhance(
        self,
        name: str,
        original_text: str,
        sanitized_document: SanitizedDocument,
        sanitizer: SensitiveDataSanitizer,
    ) -> SanitizedDocument:
        if not self.api_url or not self.model:
            raise ValueError("LOCAL_SANITIZER_API_URL and LOCAL_SANITIZER_MODEL must be configured.")

        # Re-validate on every call; env may have changed in long-running
        # processes.
        validate_local_url(self.api_url, label="LOCAL_SANITIZER_API_URL")

        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": LOCAL_SANITIZER_PROMPT},
                {
                    "role": "user",
                    "content": _build_local_sanitizer_input(
                        name,
                        original_text[: self.max_chars],
                        sanitized_document,
                    ),
                },
            ],
        }

        try:
            response = post_json_safely(
                self.api_url,
                payload,
                {
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
                },
                context_label="local sanitizer",
            )
        except UpstreamHttpError as exc:
            # Fail safe: if the local LLM is unreachable, keep the regex-only
            # sanitization rather than dropping LLM masking silently.
            document = _copy_document(sanitized_document)
            document.findings.append(
                f"Local LLM sanitizer was unavailable ({exc}); regex-only sanitization was kept."
            )
            document.local_sanitizer_provider = self.name
            return document

        content = _extract_openai_like_text(response)
        if not content.strip():
            document = _copy_document(sanitized_document)
            document.findings.append(
                "Local LLM sanitizer returned an empty response; regex-only sanitization was kept."
            )
            document.local_sanitizer_provider = self.name
            return document

        local_response = _parse_local_sanitization_response(content, sanitized_document.outbound_text)
        return _merge_local_sanitization(
            sanitized_document,
            local_response,
            sanitizer,
            original_text,
            self.name,
        )


class OllamaSanitizationEnhancer(LocalHttpSanitizationEnhancer):
    name = "ollama"

    def __init__(self) -> None:
        # Fill in defaults BEFORE the parent validates, so that a missing env
        # still routes to loopback rather than to empty.
        if not os.getenv("LOCAL_SANITIZER_API_URL", "").strip():
            os.environ["LOCAL_SANITIZER_API_URL"] = "http://127.0.0.1:11434/v1/responses"
        if not os.getenv("LOCAL_SANITIZER_MODEL", "").strip():
            os.environ["LOCAL_SANITIZER_MODEL"] = "gemma3:12b"
        super().__init__()


def choose_local_sanitization_enhancer() -> LocalSanitizationEnhancer:
    mode = os.getenv("LOCAL_SANITIZER_PROVIDER", "none").strip().lower()
    try:
        if mode == "ollama":
            return OllamaSanitizationEnhancer()
        if mode in {"http", "local-http", "openai-compatible"}:
            return LocalHttpSanitizationEnhancer()
    except LocalUrlError as exc:
        LOGGER.error("Local sanitizer URL rejected: %s", exc)
        raise
    return LocalSanitizationEnhancer()


def _build_local_sanitizer_input(
    name: str,
    original_text: str,
    sanitized_document: SanitizedDocument,
) -> str:
    return "\n".join(
        [
            f"document_name: {name}",
            "original_text:",
            original_text,
            "current_sanitized_text:",
            sanitized_document.outbound_text,
            "approved_placeholder_categories:",
            ", ".join(APPROVED_LOCAL_PLACEHOLDERS),
            f"current_outbound_risk: {sanitized_document.outbound_risk}",
            "current_findings:",
            "\n".join(sanitized_document.findings) or "-",
        ]
    )


def _copy_document(document: SanitizedDocument) -> SanitizedDocument:
    """Shallow copy that preserves the fields we mutate when falling back."""
    return SanitizedDocument(
        name=document.name,
        original_excerpt=document.original_excerpt,
        sanitized_excerpt=document.sanitized_excerpt,
        outbound_text=document.outbound_text,
        replacements=list(document.replacements),
        findings=list(document.findings),
        estimated_input_tokens=document.estimated_input_tokens,
        outbound_risk=document.outbound_risk,
        local_sanitizer_provider=document.local_sanitizer_provider,
        local_sensitivity_decision=document.local_sensitivity_decision,
        local_sensitivity_reasons=list(document.local_sensitivity_reasons),
        local_sensitivity_provider=document.local_sensitivity_provider,
    )


def _merge_local_sanitization(
    sanitized_document: SanitizedDocument,
    local_response: LocalSanitizationResponse,
    sanitizer: SensitiveDataSanitizer,
    original_text: str,
    provider_name: str,
) -> SanitizedDocument:
    refined = sanitizer.sanitize_text(local_response.sanitized_text)
    final_text = refined.sanitized_text
    outbound_text = final_text[: sanitizer._outbound_limit]
    findings = _merge_findings(
        sanitized_document.findings,
        local_response.findings,
        refined.findings,
    )

    if outbound_text != sanitized_document.outbound_text:
        findings.append("Local LLM applied additional masking before any external transfer.")
    if len(final_text) > sanitizer._outbound_limit:
        findings.append(
            f"Outbound text was truncated to {sanitizer._outbound_limit} characters to stay within a conservative review budget."
        )

    unapproved = _detect_unapproved_placeholders(outbound_text)
    if unapproved:
        findings.append(
            "Local LLM used non-standard placeholder style(s): "
            + ", ".join(sorted(unapproved)[:5])
            + ". These are kept as-is but should be reviewed."
        )

    merged_records = _merge_records(sanitized_document.replacements, refined.records)
    outbound_risk = _max_risk(
        sanitized_document.outbound_risk,
        local_response.outbound_risk,
        refined.outbound_risk,
    )

    return SanitizedDocument(
        name=sanitized_document.name,
        original_excerpt=original_text[: sanitizer._preview_limit],
        sanitized_excerpt=outbound_text[: sanitizer._preview_limit],
        outbound_text=outbound_text,
        replacements=merged_records[:100],
        findings=findings,
        estimated_input_tokens=sanitizer._estimate_tokens(outbound_text),
        outbound_risk=outbound_risk,
        local_sanitizer_provider=provider_name,
        local_sensitivity_decision=sanitized_document.local_sensitivity_decision,
        local_sensitivity_reasons=list(sanitized_document.local_sensitivity_reasons),
        local_sensitivity_provider=sanitized_document.local_sensitivity_provider,
    )


def _detect_unapproved_placeholders(text: str) -> set[str]:
    hits: set[str] = set()
    for pattern in _UNAPPROVED_PLACEHOLDER_PATTERNS:
        for match in pattern.findall(text):
            hits.add(match if isinstance(match, str) else match[0])
    return hits


def _merge_records(
    base_records: list[SanitizationRecord],
    additional_records: list[SanitizationRecord],
) -> list[SanitizationRecord]:
    merged: list[SanitizationRecord] = []
    seen: set[tuple[str, str, str]] = set()

    for record in [*base_records, *additional_records]:
        key = (record.placeholder, record.original, record.category)
        if key in seen:
            continue
        seen.add(key)
        merged.append(record)

    return merged


def _merge_findings(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for item in group:
            text = str(item).strip()
            if text and text not in merged:
                merged.append(text)
    return merged


def _max_risk(*levels: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    highest = "low"
    for level in levels:
        normalized = _normalize_risk(level)
        if order[normalized] > order[highest]:
            highest = normalized
    return highest


def _normalize_risk(level: str) -> str:
    normalized = str(level or "").strip().lower()
    if normalized in {"low", "medium", "high"}:
        return normalized
    return "medium"


def _normalize_local_placeholders(text: str) -> str:
    for category in APPROVED_LOCAL_PLACEHOLDERS:
        pattern = re.compile(rf"\[{category}_(\d{{1,3}})\]")
        text = pattern.sub(lambda match: f"[{category}_{int(match.group(1)):03d}]", text)
    return text


# Backwards-compat shim: tests patch ``secure_review.sanitizer._post_json``.
# We route through the safe client and convert exceptions to a dict-returning
# failure so that the existing callers don't need to change.
def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    return post_json_safely(url, payload, headers, context_label="local sanitizer")


def _extract_openai_like_text(payload: dict) -> str:
    """Extract text from an OpenAI-style response.

    Previously, this function returned ``json.dumps(payload)`` on parse failure,
    which meant provider diagnostics or prompt echoes could be treated as
    sanitized text. We now return an empty string and let the caller decide how
    to fail safe.
    """
    output = payload.get("output_text")
    if isinstance(output, str) and output.strip():
        return output

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if text:
                chunks.append(text)

    # Some OpenAI-compatible servers (notably Ollama) respond with a Chat
    # Completions shape instead of a Responses shape.
    for choice in payload.get("choices", []):
        message = choice.get("message") or {}
        text = message.get("content")
        if isinstance(text, str) and text:
            chunks.append(text)

    return "\n".join(chunks).strip()


def _parse_local_sanitization_response(
    content: str,
    fallback_text: str,
) -> LocalSanitizationResponse:
    normalized_content = _extract_json_payload(content)
    try:
        payload = json.loads(normalized_content)
    except json.JSONDecodeError:
        return LocalSanitizationResponse(
            sanitized_text=fallback_text,
            findings=["The local sanitizer model did not return valid JSON; regex-only sanitization was kept."],
            outbound_risk="medium",
        )

    sanitized_text = _normalize_local_placeholders(str(payload.get("sanitized_text", fallback_text)))
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = [str(findings)]

    return LocalSanitizationResponse(
        sanitized_text=sanitized_text.strip() or fallback_text,
        findings=[str(item) for item in findings if str(item).strip()],
        outbound_risk=_normalize_risk(str(payload.get("risk", "medium"))),
    )


def _extract_json_payload(content: str) -> str:
    stripped = str(content or "").strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
        return stripped.strip()

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        return stripped[start : end + 1]
    return stripped
