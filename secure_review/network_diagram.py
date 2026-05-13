from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DiagramOcrSummary:
    external_connections: tuple[str, ...]
    security_zones: tuple[str, ...]
    device_candidates: tuple[str, ...]
    redundancy_terms: tuple[str, ...]
    network_identifiers: tuple[str, ...]
    local_inferences: tuple[str, ...]

    @property
    def has_signal(self) -> bool:
        return any(
            (
                self.external_connections,
                self.security_zones,
                self.device_candidates,
                self.redundancy_terms,
                self.network_identifiers,
                self.local_inferences,
            )
        )


EXTERNAL_KEYWORDS = (
    "internet",
    "インターネット",
    "wan",
    "isp",
    "aws",
    "azure",
    "gcp",
    "direct connect",
    "expressroute",
    "vpn",
    "mpls",
    "閉域",
    "専用線",
)

ZONE_KEYWORDS = (
    "dmz",
    "internal",
    "inside",
    "outside",
    "untrust",
    "trust",
    "mgmt",
    "management",
    "public",
    "private",
    "管理",
    "社内",
    "外部",
    "本番",
    "検証",
)

DEVICE_KEYWORDS = (
    "fortigate",
    "fortinet",
    "firewall",
    "fw",
    "router",
    "rtr",
    "cisco",
    "switch",
    "sw",
    "l2sw",
    "l3sw",
    "core",
    "access",
    "waf",
    "proxy",
    "lb",
    "alb",
    "nlb",
    "server",
    "db",
    "ap",
    "web",
)

REDUNDANCY_KEYWORDS = (
    "ha",
    "冗長",
    "二重化",
    "active/standby",
    "active-standby",
    "active active",
    "active/active",
    "standby",
    "cluster",
    "vrrp",
    "hsrp",
    "glbp",
    "lag",
    "lacp",
    "port-channel",
    "port channel",
    "mlag",
    "stack",
)


def build_diagram_ocr_summary(ocr_text: str) -> DiagramOcrSummary:
    lines = _clean_ocr_lines(ocr_text)
    lowered_lines = [line.lower() for line in lines]

    external = _collect_keyword_lines(lines, lowered_lines, EXTERNAL_KEYWORDS)
    zones = _collect_keyword_lines(lines, lowered_lines, ZONE_KEYWORDS)
    devices = _collect_device_candidates(lines, lowered_lines)
    redundancy = _collect_keyword_lines(lines, lowered_lines, REDUNDANCY_KEYWORDS)
    network_ids = _collect_network_identifiers(lines)
    inferences = _build_local_inferences(
        external,
        zones,
        devices,
        redundancy,
        network_ids,
    )

    return DiagramOcrSummary(
        external_connections=external,
        security_zones=zones,
        device_candidates=devices,
        redundancy_terms=redundancy,
        network_identifiers=network_ids,
        local_inferences=inferences,
    )


def render_diagram_ocr_summary(ocr_text: str) -> str:
    summary = build_diagram_ocr_summary(ocr_text)
    if not summary.has_signal:
        return (
            "## 構成図OCRサマリ（ローカル推定）\n"
            "OCRテキストからネットワーク構成を推定できる強い手掛かりは多くありませんでした。\n"
            "この情報は画像OCRに基づくため、接続線・矢印・配置関係は未確定です。"
        )

    sections = [
        "## 構成図OCRサマリ（ローカル推定）",
        "このサマリはローカルOCRで読めた文字列だけに基づく概要です。",
        "画像そのものは外部LLMへ送信せず、下記テキストもこの後の匿名化処理対象になります。",
        "接続線・矢印・配置関係は確定解析していないため、推定は必ず設計書本文または構成図原本で確認してください。",
        "",
        "### 抽出された主な要素",
    ]

    _append_bullets(sections, "外部接続候補", summary.external_connections)
    _append_bullets(sections, "セグメント/ゾーン候補", summary.security_zones)
    _append_bullets(sections, "機器/役割候補", summary.device_candidates)
    _append_bullets(sections, "冗長化キーワード", summary.redundancy_terms)
    _append_bullets(sections, "ネットワーク識別子", summary.network_identifiers)

    if summary.local_inferences:
        sections.extend(["", "### 文脈からの控えめな推定"])
        for item in summary.local_inferences:
            sections.append(f"- {item}")

    sections.extend(
        [
            "",
            "### 未確定事項",
            "- 実際の接続線、通信方向、経路優先度、HA方式、障害時の切替条件はOCRだけでは確定できません。",
            "- LLMレビューでは、上記を断定ではなく確認観点として扱ってください。",
        ]
    )
    return "\n".join(sections)


def _clean_ocr_lines(ocr_text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in ocr_text.splitlines():
        line = re.sub(r"\s+", " ", raw_line).strip(" \t|")
        if len(line) < 2:
            continue
        if len(line) > 120:
            continue
        # OCR artifacts that are mostly punctuation are not useful for review.
        if not re.search(r"[A-Za-z0-9一-龯ぁ-んァ-ヶ]", line):
            continue
        lines.append(line)
    return list(dict.fromkeys(lines))


def _collect_keyword_lines(
    lines: list[str],
    lowered_lines: list[str],
    keywords: tuple[str, ...],
) -> tuple[str, ...]:
    hits: list[str] = []
    for line, lowered in zip(lines, lowered_lines):
        if any(keyword in lowered for keyword in keywords):
            hits.append(line)
    return _limit_dedupe(hits)


def _collect_device_candidates(
    lines: list[str],
    lowered_lines: list[str],
) -> tuple[str, ...]:
    hits: list[str] = []
    for line, lowered in zip(lines, lowered_lines):
        if any(keyword in lowered for keyword in DEVICE_KEYWORDS):
            hits.append(line)
            continue
        if re.search(r"\b[A-Za-z][A-Za-z0-9_-]{2,}[-_](?:0?1|0?2|a|b)\b", line, re.IGNORECASE):
            hits.append(line)
    return _limit_dedupe(hits, limit=12)


def _collect_network_identifiers(lines: list[str]) -> tuple[str, ...]:
    hits: list[str] = []
    ipv4_cidr = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
    vlan = re.compile(r"\bVLAN\s*\d{1,5}\b", re.IGNORECASE)
    vrf = re.compile(r"\bVRF\s*[:= -]?\s*[A-Za-z0-9_.-]+", re.IGNORECASE)
    for line in lines:
        values = ipv4_cidr.findall(line) + vlan.findall(line) + vrf.findall(line)
        hits.extend(values)
    return _limit_dedupe(hits, limit=12)


def _build_local_inferences(
    external: tuple[str, ...],
    zones: tuple[str, ...],
    devices: tuple[str, ...],
    redundancy: tuple[str, ...],
    network_ids: tuple[str, ...],
) -> tuple[str, ...]:
    lowered_blob = "\n".join(external + zones + devices + redundancy + network_ids).lower()
    inferences: list[str] = []

    if external and any(term in lowered_blob for term in ("fw", "firewall", "fortigate", "waf")):
        inferences.append("外部接続とFirewall/UTM/WAFらしき要素が同時に見えるため、境界防御層がある可能性があります。")
    if any("dmz" in item.lower() for item in zones):
        inferences.append("DMZ表記があるため、外部公開系と内部系を分離している可能性があります。")
    if redundancy or _has_pair_like_devices(devices):
        inferences.append("HA/VRRP/LAG等の表記または01/02/A/Bの機器ペアが見えるため、冗長化構成の可能性があります。")
    if any(term in lowered_blob for term in ("core", "l3sw", "access")):
        inferences.append("Core/Access/L3SW等の表記があるため、階層型ネットワーク構成の可能性があります。")
    if any(term in lowered_blob for term in ("aws", "azure", "gcp", "direct connect", "vpn", "閉域", "専用線")):
        inferences.append("クラウドまたはWAN接続を含む構成の可能性があります。")
    if network_ids:
        inferences.append("IPアドレス、VLAN、VRF等の識別子が見えるため、設計書本文との整合確認に利用できます。")

    return tuple(inferences)


def _has_pair_like_devices(devices: tuple[str, ...]) -> bool:
    prefixes: set[str] = set()
    for device in devices:
        match = re.search(r"(.+?)[-_]?(?:0?1|0?2|a|b)\b", device, re.IGNORECASE)
        if match:
            prefix = re.sub(r"[^A-Za-z0-9一-龯ぁ-んァ-ヶ]+", "", match.group(1)).lower()
            if prefix in prefixes:
                return True
            prefixes.add(prefix)
    return False


def _append_bullets(sections: list[str], label: str, values: tuple[str, ...]) -> None:
    if not values:
        return
    sections.append(f"- {label}: {', '.join(values)}")


def _limit_dedupe(values: list[str], *, limit: int = 8) -> tuple[str, ...]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        key = normalized.lower()
        if not normalized or key in seen:
            continue
        seen.add(key)
        deduped.append(normalized)
        if len(deduped) >= limit:
            break
    return tuple(deduped)
