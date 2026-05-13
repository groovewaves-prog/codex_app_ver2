# ネットワーク機器Configレビューの扱い

本ツールでは、Cisco IOS / IOS XE および Fortinet FortiGate / FortiOS の
Configを、技術文書レビューを補助する入力として扱う。

## 位置づけ

- 正式なConfig監査ツールではなく、概要解析と確認観点の抽出を目的とする。
- ルールベースで主要な構文や注意候補を抽出し、その結果をLLMレビューの補助情報として渡す。
- ACL、Firewall Policy、NAT、VRF、route-map、VPNは文脈依存が強いため、原則として断定せず、設計書との突合観点として提示する。

## 初期対応範囲

- Cisco IOS / IOS XE: interface、line vty、AAA、SNMP、ACL、HTTP管理、routing、logging、NTP。
- Fortinet FortiOS: system interface、firewall policy、address/service、VIP/NAT、static route/BGP/OSPF、IPsec VPN、admin/SNMP/log/NTP/HA。

## 出力方針

- 機器種別または構文種別の推定。
- interface、routing、policy、VPN、管理アクセス、ログ/監視の概要。
- Telnet、HTTP管理、SNMP community、広すぎる許可、ログ/NTP不足などの注意候補。
- 設計書・構成図・運用標準と突き合わせるべき確認観点。

## 構成図レビューとの関係

画像としての構成図は、将来的にマルチモーダルLLMで概要解析できる可能性がある。
ただし、実務上はOCRや線・矢印の誤認リスクがあるため、Mermaid、YAML、JSON、draw.ioから抽出した構造データなど、テキスト化された構成情報を優先する。

当面はMermaid等を担当者に強制しない。画像構成図がアップロードされた場合は、ローカルOCRで読めた文字列から「外部接続候補」「セグメント/ゾーン候補」「機器/役割候補」「冗長化キーワード」「ネットワーク識別子」を控えめに整理し、その抽出結果を既存の匿名化処理に通したうえでLLMレビューに利用する。

OCR由来の構成推定は、接続線・矢印・配置関係を確定解析したものではない。レビューでは、ネットワーク階層や冗長化を「可能性」「確認観点」として扱い、設計書本文または構成図原本で確認すべき事項として提示する。
