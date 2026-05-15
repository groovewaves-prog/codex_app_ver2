from __future__ import annotations

import json
import logging
import os
import re

from secure_review.models import SanitizedDocument, SensitivityAssessment
from secure_review.network_guard import (
    LocalUrlError,
    UpstreamHttpError,
    post_json_safely,
    validate_local_url,
)


LOGGER = logging.getLogger("secure_review.sensitivity")


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
            reasons.append("ローカル原文中に明示的な機密性マーカー (社外秘・confidential 等) が検出されました。")
            actions.append("外部送信前に、機密性ラベルが付与された箇所を削除または一般化してください。")
            return SensitivityAssessment(
                decision="block",
                reasons=reasons,
                provider=self.name,
                recommended_actions=actions,
            )

        has_identifying_replacements = any(
            record.category in {"company", "project", "ticket", "person"}
            for record in sanitized_document.replacements
        )
        if has_identifying_replacements:
            reasons.append("顧客・案件・チケット・担当者の識別子がローカルで検出されました。")
            actions.append("顧客名・案件名等の識別子周辺の文脈が、マスク処理で完全に除去されているか確認してください。")

        if self._customer_context.search(original_text) and not has_identifying_replacements:
            reasons.append("業務識別子または所有者ラベル (顧客名・案件名・担当者など) がローカル原文中に検出されました。")
            actions.append("組織や案件を特定し得るラベルおよびその周辺文脈をマスク処理してください。")

        if self._topology_context.search(original_text) and sanitized_document.outbound_risk != "low":
            reasons.append("匿名化後もトポロジ・環境固有の文脈が残存している可能性があります。")
            actions.append("拠点名・トポロジ詳細・環境固有の表現を一般化してください。")

        if "password" in lowered or "token" in lowered or "secret" in lowered:
            reasons.append("認証情報を示唆する語 (password, token, secret 等) がローカル原文中に検出されました。")
            actions.append("認証情報や秘密情報がすべてマスクされているか確認してください。")

        if sanitized_document.outbound_risk == "high":
            reasons.append("匿名化処理が、本文書を高い外部送信リスクと判定しています。")
            actions.append("外部送信前に、より厳密に匿名化したコピーを準備してください。")
            return SensitivityAssessment(
                decision="block",
                reasons=reasons or ["本文書は外部送信に適さないと判定されました。"],
                provider=self.name,
                recommended_actions=actions,
            )

        if reasons:
            return SensitivityAssessment(
                decision="mask_and_continue",
                reasons=reasons,
                provider=self.name,
                recommended_actions=actions or ["追加のマスク処理を行い、ローカルで結果を確認してください。"],
            )

        return SensitivityAssessment(
            decision="safe",
            reasons=["ローカル機密度判定で、強い機密性ブロッカーは検出されませんでした。"],
            provider=self.name,
            recommended_actions=["匿名化済みテキストのみで処理を続行してください。"],
        )


class LocalHttpSensitivityClassifier(SensitivityClassifier):
    """Call a local LLM to decide whether external transfer is allowed.

    SECURITY NOTE: The original, unmasked text is included in the request body
    (bounded by ``LOCAL_SENSITIVITY_INPUT_CHARS``). The target URL MUST be
    loopback; this is enforced on construction and re-checked before every
    request.
    """

    name = "local-http"

    def __init__(self) -> None:
        raw_url = os.getenv("LOCAL_SENSITIVITY_API_URL", "").strip()
        self.api_url = validate_local_url(raw_url, label="LOCAL_SENSITIVITY_API_URL") if raw_url else ""
        self.api_key = os.getenv("LOCAL_SENSITIVITY_API_KEY", "").strip()
        self.model = os.getenv("LOCAL_SENSITIVITY_MODEL", "").strip()
        self.max_chars = int(os.getenv("LOCAL_SENSITIVITY_INPUT_CHARS", "8000"))

    def assess(self, name: str, original_text: str, sanitized_document: SanitizedDocument) -> SensitivityAssessment:
        if not self.api_url or not self.model:
            raise ValueError("LOCAL_SENSITIVITY_API_URL and LOCAL_SENSITIVITY_MODEL must be configured.")

        validate_local_url(self.api_url, label="LOCAL_SENSITIVITY_API_URL")

        # If the document is longer than what we send, that is itself a
        # reason to be cautious in the final decision.
        truncated = len(original_text) > self.max_chars

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

        try:
            response = post_json_safely(
                self.api_url,
                payload,
                {
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
                },
                context_label="local sensitivity gate",
            )
        except UpstreamHttpError as exc:
            # Fail safe: if the gate is unreachable, require human review
            # rather than silently letting content through.
            return SensitivityAssessment(
                decision="mask_and_continue",
                reasons=[f"Local sensitivity gate was unavailable ({exc}); human review is required."],
                provider=self.name,
                recommended_actions=[
                    "Restart the local sensitivity service and re-run, or review the sanitized text manually before sending."
                ],
            )

        content = _extract_openai_like_text(response)
        if not content.strip():
            return SensitivityAssessment(
                decision="mask_and_continue",
                reasons=["Local sensitivity gate returned an empty response; human review is required."],
                provider=self.name,
                recommended_actions=["Check the local sensitivity model and re-run."],
            )

        assessment = _parse_sensitivity_assessment(content, self.name)
        if truncated and assessment.decision == "safe":
            # The gate only saw the head of the document; downgrade to
            # mask_and_continue to force human review.
            return SensitivityAssessment(
                decision="mask_and_continue",
                reasons=[
                    *assessment.reasons,
                    (
                        f"The document exceeded the local sensitivity input budget "
                        f"({self.max_chars} chars); only the head was evaluated."
                    ),
                ],
                provider=self.name,
                recommended_actions=[
                    *assessment.recommended_actions,
                    "Split the document into smaller sections before external transfer.",
                ],
            )
        return assessment


class OllamaSensitivityClassifier(LocalHttpSensitivityClassifier):
    name = "ollama"

    def __init__(self) -> None:
        if not os.getenv("LOCAL_SENSITIVITY_API_URL", "").strip():
            os.environ["LOCAL_SENSITIVITY_API_URL"] = "http://127.0.0.1:11434/v1/responses"
        if not os.getenv("LOCAL_SENSITIVITY_MODEL", "").strip():
            os.environ["LOCAL_SENSITIVITY_MODEL"] = "gemma3:12b"
        super().__init__()


def choose_sensitivity_classifier() -> SensitivityClassifier:
    mode = os.getenv("LOCAL_SENSITIVITY_PROVIDER", "heuristic").strip().lower()
    try:
        if mode == "ollama":
            return OllamaSensitivityClassifier()
        if mode in {"http", "local-http", "openai-compatible"}:
            return LocalHttpSensitivityClassifier()
    except LocalUrlError as exc:
        LOGGER.error("Local sensitivity URL rejected: %s", exc)
        raise
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


# Backwards-compat shim for existing tests/callers.
def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    return post_json_safely(url, payload, headers, context_label="local sensitivity gate")


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

    for choice in payload.get("choices", []):
        message = choice.get("message") or {}
        text = message.get("content")
        if isinstance(text, str) and text:
            chunks.append(text)

    # Return empty rather than ``json.dumps(payload)`` so that callers can
    # treat "no output" as a structured failure.
    return "\n".join(chunks).strip()


def _parse_sensitivity_assessment(content: str, provider: str) -> SensitivityAssessment:
    stripped = _extract_json_payload(content)
    try:
        payload = json.loads(stripped)
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
