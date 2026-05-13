from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigFinding:
    severity: str
    title: str
    details: str
    recommendation: str


@dataclass(frozen=True)
class NetworkConfigAnalysis:
    vendor: str
    interface_names: tuple[str, ...]
    routing_signals: tuple[str, ...]
    policy_count: int
    findings: tuple[ConfigFinding, ...]

    @property
    def summary(self) -> str:
        parts = [f"推定ベンダ/構文: {self.vendor}"]
        if self.interface_names:
            shown = ", ".join(self.interface_names[:8])
            suffix = "" if len(self.interface_names) <= 8 else f" ほか{len(self.interface_names) - 8}件"
            parts.append(f"interface: {shown}{suffix}")
        if self.routing_signals:
            parts.append(f"routing: {', '.join(self.routing_signals)}")
        if self.policy_count:
            parts.append(f"firewall policy: {self.policy_count}件")
        if not self.findings:
            parts.append("強い注意候補は検出されませんでした")
        return " / ".join(parts)


def looks_like_network_config(text: str) -> bool:
    lowered = text.lower()
    return _looks_like_cisco_ios(lowered) or _looks_like_fortios(lowered)


def analyze_network_config(text: str) -> NetworkConfigAnalysis:
    lowered = text.lower()
    cisco = _looks_like_cisco_ios(lowered)
    fortios = _looks_like_fortios(lowered)

    if cisco and fortios:
        vendor = "mixed_or_unknown"
    elif fortios:
        vendor = "fortinet_fortios"
    elif cisco:
        vendor = "cisco_ios"
    else:
        vendor = "unknown"

    findings: list[ConfigFinding] = []
    interface_names: list[str] = []
    routing_signals: list[str] = []
    policy_count = 0

    if cisco:
        cisco_result = _analyze_cisco_ios(text)
        findings.extend(cisco_result.findings)
        interface_names.extend(cisco_result.interface_names)
        routing_signals.extend(cisco_result.routing_signals)

    if fortios:
        fortios_result = _analyze_fortios(text)
        findings.extend(fortios_result.findings)
        interface_names.extend(fortios_result.interface_names)
        routing_signals.extend(fortios_result.routing_signals)
        policy_count += fortios_result.policy_count

    return NetworkConfigAnalysis(
        vendor=vendor,
        interface_names=_dedupe(interface_names),
        routing_signals=_dedupe(routing_signals),
        policy_count=policy_count,
        findings=tuple(findings),
    )


def render_network_config_analysis_for_prompt(analysis: NetworkConfigAnalysis) -> list[str]:
    lines = [
        "以下はLLMレビュー前にルールベースで抽出したネットワーク機器Configの概要です。",
        "これは正式なConfig監査ではなく、概要解析と確認観点の抽出です。",
        f"- {analysis.summary}",
    ]
    for finding in analysis.findings[:12]:
        lines.append(
            "- "
            f"severity={finding.severity} / "
            f"title={finding.title} / "
            f"details={finding.details} / "
            f"recommendation={finding.recommendation}"
        )
    if len(analysis.findings) > 12:
        lines.append(f"- ほか {len(analysis.findings) - 12} 件の注意候補があります。")
    return lines


def _looks_like_cisco_ios(lowered: str) -> bool:
    cisco_signals = (
        r"(?m)^interface\s+\S+",
        r"(?m)^line\s+vty\s+\d+",
        r"(?m)^router\s+(ospf|bgp|eigrp|rip)\b",
        r"(?m)^ip\s+access-list\b",
        r"(?m)^access-list\s+\d+\s+",
        r"(?m)^aaa\s+new-model\b",
        r"(?m)^snmp-server\s+community\b",
    )
    return sum(1 for pattern in cisco_signals if re.search(pattern, lowered)) >= 2


def _looks_like_fortios(lowered: str) -> bool:
    fortios_signals = (
        "config system interface",
        "config firewall policy",
        "config firewall address",
        "config router static",
        "config router bgp",
        "config vpn ipsec phase1-interface",
        "set srcintf",
        "set dstintf",
        "set srcaddr",
        "set dstaddr",
    )
    return sum(1 for signal in fortios_signals if signal in lowered) >= 2


def _analyze_cisco_ios(text: str) -> NetworkConfigAnalysis:
    lowered = text.lower()
    findings: list[ConfigFinding] = []
    interface_names = tuple(
        match.group(1).strip()
        for match in re.finditer(r"(?im)^interface\s+(.+?)\s*$", text)
    )
    routing_signals = _extract_cisco_routing_signals(lowered)

    if re.search(r"(?im)^\s*transport\s+input\s+.*\btelnet\b", text) or re.search(
        r"(?im)^\s*transport\s+input\s+all\b", text
    ):
        findings.append(
            ConfigFinding(
                "high",
                "Telnetによる管理アクセスの可能性",
                "line vty 等で Telnet を許可している可能性があります。",
                "SSH のみに限定し、送信元制限とAAA/認証方式を確認してください。",
            )
        )

    if re.search(r"(?im)^enable\s+password\s+", text) and not re.search(
        r"(?im)^enable\s+secret\s+", text
    ):
        findings.append(
            ConfigFinding(
                "high",
                "enable password の利用",
                "enable secret ではなく enable password が使われている可能性があります。",
                "enable secret へ移行し、既存パスワードの再発行を検討してください。",
            )
        )

    if re.search(r"(?im)^snmp-server\s+community\s+", text):
        findings.append(
            ConfigFinding(
                "high",
                "SNMP community string の利用",
                "SNMPv1/v2c相当の community ベース認証が含まれている可能性があります。",
                "SNMPv3、送信元ACL、community値の秘匿化を確認してください。",
            )
        )

    if re.search(r"(?im)^\s*(access-list\s+\d+\s+permit|permit)\s+ip\s+any\s+any\b", text):
        findings.append(
            ConfigFinding(
                "medium",
                "広すぎるACL許可の可能性",
                "permit ip any any に相当する広い許可が含まれている可能性があります。",
                "意図した境界か、適用方向・適用インターフェース・上位/下位ルールを確認してください。",
            )
        )

    if re.search(r"(?im)^ip\s+http\s+server\b", text) and not re.search(
        r"(?im)^no\s+ip\s+http\s+server\b", text
    ):
        findings.append(
            ConfigFinding(
                "medium",
                "HTTP管理機能の有効化",
                "ip http server が有効な可能性があります。",
                "管理HTTPが不要なら無効化し、必要な場合もHTTPS・送信元制限を確認してください。",
            )
        )

    if interface_names:
        blocks = _split_cisco_interface_blocks(text)
        missing_desc = [
            name for name, block in blocks.items()
            if not re.search(r"(?im)^\s*description\s+\S+", block)
            and not name.lower().startswith(("loopback", "null"))
        ]
        if len(missing_desc) >= max(2, len(blocks) // 2):
            findings.append(
                ConfigFinding(
                    "low",
                    "interface description 不足の可能性",
                    "複数の interface に description が見当たりません。",
                    "接続先、用途、回線ID、責任分界点を description に残すことを推奨します。",
                )
            )

    if "aaa new-model" not in lowered:
        findings.append(
            ConfigFinding(
                "medium",
                "AAA設定が明示されていない可能性",
                "aaa new-model が見当たりません。",
                "認証・認可・監査の方式、ローカル認証へのフォールバック条件を確認してください。",
            )
        )

    if "logging host" not in lowered:
        findings.append(
            ConfigFinding(
                "low",
                "外部ログ転送設定が見当たらない可能性",
                "logging host が見当たりません。",
                "Syslog/SIEMへの転送、時刻同期、保存期間を設計書と突き合わせてください。",
            )
        )

    if "ntp server" not in lowered:
        findings.append(
            ConfigFinding(
                "low",
                "NTP設定が見当たらない可能性",
                "ntp server が見当たりません。",
                "ログ証跡の信頼性確保のため、時刻同期先とタイムゾーンを確認してください。",
            )
        )

    return NetworkConfigAnalysis(
        vendor="cisco_ios",
        interface_names=interface_names,
        routing_signals=routing_signals,
        policy_count=0,
        findings=tuple(findings),
    )


def _analyze_fortios(text: str) -> NetworkConfigAnalysis:
    lowered = text.lower()
    findings: list[ConfigFinding] = []
    interface_names = _extract_fortios_interface_names(text)
    routing_signals = _extract_fortios_routing_signals(lowered)
    policy_blocks = _extract_fortios_policy_blocks(text)
    policy_count = len(policy_blocks)

    if re.search(r"(?im)^\s*set\s+allowaccess\s+.*\b(telnet|http)\b", text):
        findings.append(
            ConfigFinding(
                "high",
                "管理アクセスでHTTP/Telnet許可の可能性",
                "interface の allowaccess に http または telnet が含まれている可能性があります。",
                "管理アクセスはHTTPS/SSHに限定し、送信元管理セグメントを制限してください。",
            )
        )

    for block in policy_blocks:
        block_lower = block.lower()
        if (
            "set action accept" in block_lower
            and re.search(r"(?im)^\s*set\s+srcaddr\s+\"?all\"?\s*$", block)
            and re.search(r"(?im)^\s*set\s+dstaddr\s+\"?all\"?\s*$", block)
            and re.search(r"(?im)^\s*set\s+service\s+\"?all\"?\s*$", block)
        ):
            findings.append(
                ConfigFinding(
                    "high",
                    "広すぎるFirewall Policyの可能性",
                    "srcaddr/dstaddr/service が all の accept policy が含まれている可能性があります。",
                    "意図した一時許可か、送信元・宛先・サービスを最小化できるか確認してください。",
                )
            )
            break

    if policy_blocks and "set logtraffic" not in lowered:
        findings.append(
            ConfigFinding(
                "medium",
                "Firewall Policyのログ設定が不明",
                "firewall policy はありますが set logtraffic が見当たりません。",
                "許可/拒否ログの取得方針、ログ量、保管先を設計書と突き合わせてください。",
            )
        )

    if "config system snmp" in lowered or "config system snmp community" in lowered:
        findings.append(
            ConfigFinding(
                "medium",
                "SNMP設定の確認が必要",
                "FortiGateのSNMP設定が含まれている可能性があります。",
                "SNMPv3、manager-hosts、community値の秘匿化、監視元制限を確認してください。",
            )
        )

    if "config system ntp" not in lowered and "set ntpsync" not in lowered:
        findings.append(
            ConfigFinding(
                "low",
                "NTP設定が見当たらない可能性",
                "config system ntp または ntpsync が見当たりません。",
                "ログ・証跡の時刻整合性のため、NTP同期先を確認してください。",
            )
        )

    if "config system ha" not in lowered:
        findings.append(
            ConfigFinding(
                "info",
                "HA構成の記述が見当たらない可能性",
                "config system ha が見当たりません。",
                "単体構成が意図通りか、冗長化要件が別資料にあるか確認してください。",
            )
        )

    return NetworkConfigAnalysis(
        vendor="fortinet_fortios",
        interface_names=interface_names,
        routing_signals=routing_signals,
        policy_count=policy_count,
        findings=tuple(findings),
    )


def _extract_cisco_routing_signals(lowered: str) -> tuple[str, ...]:
    signals: list[str] = []
    if re.search(r"(?m)^ip\s+route\s+", lowered):
        signals.append("static route")
    for protocol in ("ospf", "bgp", "eigrp", "rip"):
        if re.search(rf"(?m)^router\s+{protocol}\b", lowered):
            signals.append(protocol.upper())
    if re.search(r"(?m)^ip\s+prefix-list\s+", lowered):
        signals.append("prefix-list")
    if re.search(r"(?m)^route-map\s+", lowered):
        signals.append("route-map")
    return tuple(signals)


def _extract_fortios_routing_signals(lowered: str) -> tuple[str, ...]:
    signals: list[str] = []
    if "config router static" in lowered:
        signals.append("static route")
    if "config router bgp" in lowered:
        signals.append("BGP")
    if "config router ospf" in lowered:
        signals.append("OSPF")
    if "config router route-map" in lowered:
        signals.append("route-map")
    return tuple(signals)


def _split_cisco_interface_blocks(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?im)^interface\s+(.+?)\s*$", text))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        name = match.group(1).strip()
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks[name] = text[start:end]
    return blocks


def _extract_fortios_policy_blocks(text: str) -> tuple[str, ...]:
    match = re.search(r"(?is)config\s+firewall\s+policy(?P<body>.*?)^\s*end\s*$", text, re.MULTILINE)
    if not match:
        return ()
    body = match.group("body")
    edit_matches = list(re.finditer(r"(?im)^\s*edit\s+\S+.*$", body))
    blocks: list[str] = []
    for index, edit_match in enumerate(edit_matches):
        start = edit_match.start()
        end = edit_matches[index + 1].start() if index + 1 < len(edit_matches) else len(body)
        blocks.append(body[start:end])
    return tuple(blocks)


def _extract_fortios_interface_names(text: str) -> tuple[str, ...]:
    match = re.search(r"(?is)config\s+system\s+interface(?P<body>.*?)^\s*end\s*$", text, re.MULTILINE)
    if not match:
        return ()
    body = match.group("body")
    return tuple(
        edit_match.group(1).strip()
        for edit_match in re.finditer(r"(?im)^\s*edit\s+\"?([^\"\n]+)\"?", body)
    )


def _dedupe(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return tuple(result)
