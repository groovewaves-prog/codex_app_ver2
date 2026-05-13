from __future__ import annotations

import unittest

from secure_review.network_config import analyze_network_config, looks_like_network_config


class NetworkConfigAnalysisTests(unittest.TestCase):
    def test_cisco_ios_attention_candidates(self) -> None:
        text = """
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
!
line vty 0 4
 transport input telnet ssh
!
snmp-server community public RO
ip route 0.0.0.0 0.0.0.0 10.0.0.254
"""
        self.assertTrue(looks_like_network_config(text))
        analysis = analyze_network_config(text)
        self.assertEqual(analysis.vendor, "cisco_ios")
        self.assertIn("GigabitEthernet0/1", analysis.interface_names)
        titles = {finding.title for finding in analysis.findings}
        self.assertIn("Telnetによる管理アクセスの可能性", titles)
        self.assertIn("SNMP community string の利用", titles)
        self.assertIn("static route", analysis.routing_signals)

    def test_fortios_attention_candidates(self) -> None:
        text = """
config system interface
    edit "port1"
        set allowaccess ping http ssh
    next
    edit "port2"
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
config router static
    edit 1
        set dst 0.0.0.0/0
    next
end
"""
        self.assertTrue(looks_like_network_config(text))
        analysis = analyze_network_config(text)
        self.assertEqual(analysis.vendor, "fortinet_fortios")
        self.assertEqual(analysis.policy_count, 1)
        self.assertIn("port1", analysis.interface_names)
        self.assertIn("port2", analysis.interface_names)
        titles = {finding.title for finding in analysis.findings}
        self.assertIn("管理アクセスでHTTP/Telnet許可の可能性", titles)
        self.assertIn("広すぎるFirewall Policyの可能性", titles)


if __name__ == "__main__":
    unittest.main()
