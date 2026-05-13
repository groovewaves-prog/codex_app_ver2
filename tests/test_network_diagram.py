from __future__ import annotations

import unittest

from secure_review.network_diagram import (
    build_diagram_ocr_summary,
    render_diagram_ocr_summary,
)


class NetworkDiagramOcrSummaryTests(unittest.TestCase):
    def test_summarizes_network_diagram_context_without_claiming_certainty(self) -> None:
        ocr_text = """
Internet
FortiGate-01
FortiGate-02
HA Active/Standby
DMZ
CoreSW-01
CoreSW-02
VLAN 100
10.10.1.0/24
AWS Direct Connect
"""
        summary = build_diagram_ocr_summary(ocr_text)
        self.assertIn("Internet", summary.external_connections)
        self.assertIn("DMZ", summary.security_zones)
        self.assertIn("VLAN 100", summary.network_identifiers)
        self.assertTrue(any("冗長化" in item for item in summary.local_inferences))

        rendered = render_diagram_ocr_summary(ocr_text)
        self.assertIn("構成図OCRサマリ", rendered)
        self.assertIn("接続線・矢印・配置関係は確定解析していない", rendered)
        self.assertIn("文脈からの控えめな推定", rendered)


if __name__ == "__main__":
    unittest.main()
