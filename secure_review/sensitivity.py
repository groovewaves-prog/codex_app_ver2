from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from secure_review.models import SanitizedDocument, SensitivityAssessment


LOCAL_SENSITIVITY_PROMPT = """You are a local confidentiality gate before any external LLM transfer.
Your job is not to review quality. Your only job is to decide whether the content is safe to transfer externally.

Decisions:
- safe: external transfer is acceptable
- mask_and_continue: more masking is needed before external transfer
- block: external transfer must not happen

Blocking conditions:
- Explicit labels such as 社外秘, 部外秘, 機密, 極秘, 取扱注意, confidential, strictly confidential
- Customer names, project names, contract numbers, circuit numbers, ticket numbers, direct contact names, or other identifiers that still make the organization or case identifiable
- Detailed topology, site names, device names, operational structure, or context that can reconstruct a specific customer environment
- Any remaining credentials, keys, tokens, or secret material
- Context that strongly reveals a specific customer or case even after masking

mask_and_continue conditions:
- More masking of names, internal nicknames, site names, system names, contact details, or identifiers would make the text safe
- The main technical content is generic, but some business context remains

safe conditions:
- The content is generalized and cannot reasonably identify a customer, project, or person
- Only sanitized design, procedure, or source-code content remains

Return JSON only:
{
  "decision": "safe | mask_and_continue | block",
  "reasons": ["reason 1", "reason 2"],
  "recommended_actions": ["action 1", "action 2"]
}
"""


class SensitivityClassifier:
    name = "base"

    def assess(self, name: str, original_text: str, sanitized_document: SanitizedDocument) -> SensitivityAssessment:
        raise NotImplementedError


class HeuristicSensitivityClassifier(SensitivityClassifier):
    name = "heuristic"

    _explicit_confidentiality = re.compile(
        r"(?im)(社外秘|部外秘|機密|極秘|取扱注意|社内限定|関係者限り|confidential|strictly confidential|internal use only|proprietary)"
    )
    _customer_context = re.compile(
        r"(?im)(顧客名|お客様名|会社名|企業名|案件名|プロジェクト名|システム名|担当者|連絡先|契約番号|回線番号|変更番号|ticket|incident)"
    )
    _topology_context = re.compile(
        r"(?im)(拠点名|データセンタ|dc|network diagram|topology|構成図|接続図|system architecture|site name|rack|core sw|firewall cluster)"
    )

    def assess(self, name: str, original_text: str, sanitized_document: SanitizedDocument) -> SensitivityAssessment:
        reasons: list[str] = []
        actions: list[str] = []
        lowered = original_text.lower()

        if self._explicit_confidentiality.search(original_text):
            reasons.append("Explicit confidentiality markers were found in the local source text.")
            actions.append("Remove or generalize the confidentiality-labelled sections before external transfer.")
            return SensitivityAssessment(
                decision="block",
                reasons=reasons,
                provider=self.name,
                recommended_actions=actions,
            )

        if any(record.category in {"company", "project", "ticket", "person"} for record in sanitized_document.replacements):
            reasons.append("Customer, project, ticket, or contact identifiers were detected locally.")
            actions.append("Confirm that masking removed all remaining context around customer and project identifiers.")

        if self._customer_context.search(original_text):
            reasons.append("Business identifiers or ownership labels were found in the local source text.")
            actions.append("Mask labels and nearby context that could still identify the organization or case.")

        if self._topology_context.search(original_text) and sanitized_document.outbound_risk != "low":
            reasons.append("Topology or environment-specific context appears to remain after sanitization.")
            actions.append("Generalize site names, topology details, and environment-specific wording.")

        if "password" in lowered or "token" in lowered or "secret" in lowered:
            reasons.append("Credential-like wording was found in the local source text.")
            actions.append("Confirm that all credentials and secrets are masked.")

        if sanitized_document.outbound_risk == "high":
            reasons.append("The sanitizer already marked this document as high outbound risk.")
            actions.append("Prepare a more strongly sanitized copy before external transfer.")
            return SensitivityAssessment(
                decision="block",
                reasons=reasons or ["The document is too sensitive for external transfer."],
                provider=self.name,
                recommended_actions=actions,
            )

        if reasons:
            return SensitivityAssessment(
                decision="mask_and_continue",
                reasons=reasons,
                provider=self.name,
                recommended_actions=actions or ["Apply additional masking and review the output locally."],
            )

        return SensitivityAssessment(
            decision="safe",
            reasons=["No strong confidentiality blockers were detected by the local heuristic gate."],
            provider=self.name,
            recommended_actions=["Proceed with the sanitized text only."],
        )


class LocalHttpSensitivityClassifier(SensitivityClassifier):
    name = "local-http"

    def __init__(self) -> None:
        self.api_url = os.getenv("LOCAL_SENSITIVITY_API_URL", "").strip()
        self.api_key = os.getenv("LOCAL_SENSITIVITY_API_KEY", "").strip()
        self.model = os.getenv("LOCAL_SENSITIVITY_MODEL", "").strip()
        self.max_chars = int(os.getenv("LOCAL_SENSITIVITY_INPUT_CHARS", "8000"))

    def assess(self, name: str, original_text: str, sanitized_document: SanitizedDocument) -> SensitivityAssessment:
        if not self.api_url or not self.model:
            raise ValueError("LOCAL_SENSITIVITY_API_URL and LOCAL_SENSITIVITY_MODEL must be configured.")

        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": LOCAL_SENSITIVITY_PROMPT},
                {
                    "role": "user",
                    "content": _build_local_sensitivity_input(
                        name,
                        original_text[: self.max_chars],
                        sanitized_document,
                    ),
                },
            ],
        }
        response = _post_json(
            self.api_url,
            payload,
            {
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
        )
        content = _extract_openai_like_text(response)
        return _parse_sensitivity_assessment(content, self.name)


class OllamaSensitivityClassifier(LocalHttpSensitivityClassifier):
    name = "ollama"

    def __init__(self) -> None:
        super().__init__()
        self.api_url = self.api_url or "http://127.0.0.1:11434/v1/responses"
        self.model = self.model or "gemma4:e4b"


def choose_sensitivity_classifier() -> SensitivityClassifier:
    mode = os.getenv("LOCAL_SENSITIVITY_PROVIDER", "heuristic").strip().lower()
    if mode == "ollama":
        return OllamaSensitivityClassifier()
    if mode in {"http", "local-http", "openai-compatible"}:
        return LocalHttpSensitivityClassifier()
    return HeuristicSensitivityClassifier()


def _build_local_sensitivity_input(
    name: str,
    original_text: str,
    sanitized_document: SanitizedDocument,
) -> str:
    return "\n".join(
        [
            f"document_name: {name}",
            "local_source_excerpt:",
            original_text,
            "sanitized_excerpt:",
            sanitized_document.sanitized_excerpt,
            f"sanitizer_outbound_risk: {sanitized_document.outbound_risk}",
            "sanitizer_findings:",
            "\n".join(sanitized_document.findings) or "-",
        ]
    )


def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON response: {raw[:400]}") from exc


def _extract_openai_like_text(payload: dict) -> str:
    output = payload.get("output_text")
    if isinstance(output, str) and output.strip():
        return output

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip() or json.dumps(payload, ensure_ascii=False)


def _parse_sensitivity_assessment(content: str, provider: str) -> SensitivityAssessment:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return SensitivityAssessment(
            decision="mask_and_continue",
            reasons=["The local sensitivity model did not return valid JSON."],
            provider=provider,
            recommended_actions=["Review the local sensitivity model prompt and output format."],
        )

    decision = str(payload.get("decision", "mask_and_continue")).strip().lower()
    if decision not in {"safe", "mask_and_continue", "block"}:
        decision = "mask_and_continue"

    reasons = payload.get("reasons", [])
    actions = payload.get("recommended_actions", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    if not isinstance(actions, list):
        actions = [str(actions)]

    return SensitivityAssessment(
        decision=decision,
        reasons=[str(item) for item in reasons if str(item).strip()],
        provider=provider,
        recommended_actions=[str(item) for item in actions if str(item).strip()],
    )
