# Secure Network Review 基本設計書

## 1. 文書情報

- 文書名: Secure Network Review 基本設計書
- 対象システム: ネットワーク設計書 / Config AI レビュー基盤
- 現在フェーズ: 無償 PoC / モック段階
- 更新方針: 設計変更時は本書と `docs/traceability.md` を同時更新する

## 2. 背景

ネットワーク設計書、コンフィグ、運用資料を AI でレビューしたい。
ただし、認証情報、IP アドレス、ホスト名、メールアドレス、コミュニティ文字列などの機密情報をそのまま外部へ送信しないことが前提である。

PoC 段階では費用を発生させたくないため、当面は無償範囲で構築できる構成を採用する。

## 3. システム化方針

### 3.1 基本方針

- UI は Web ベースとする
- AI レビュー対象は匿名化済みデータに限定する
- 原文と匿名化後データを分離して扱う
- LLM 呼び出し部分は抽象化し、将来のモデル差替えを可能にする
- PoC では無償利用を優先し、構造と画面、匿名化フローの成立を確認する

### 3.2 暫定方針

- UI は Streamlit を採用する
- LLM は Gemini free tier を暫定利用する
- Gemini へ送るのは匿名化済みデータのみとする
- Google Cloud の有償サービスや GPU 前提の配備は現段階では行わない
- Gemma 4 自己配備は次段階で対応する

### 3.3 将来方針

- UI は Streamlit のまま継続利用する
- LLM は Gemma 4 自己配備へ移行する
- 重い推論処理は Google Cloud 側で実行する
- ノート PC はブラウザ利用主体とし、ローカルに重い依存は置かない

## 4. 対象範囲

### 4.1 入力対象

- テキストファイル
- ネットワーク機器 Config
- JSON / YAML / CSV
- HTML / XML
- DOCX
- 将来対応: PDF / Excel / 画像付き資料

### 4.2 出力対象

- レビュー要約
- 指摘一覧
- 推奨対応
- 匿名化前後の抜粋プレビュー
- 処理警告

## 5. 全体アーキテクチャ

### 5.1 論理構成

本システムは以下の論理コンポーネントで構成する。

1. UI
2. Backend API
3. Document Parser
4. Sanitizer / Redaction Engine
5. Review Orchestrator
6. LLM Adapter
7. Result Store / Audit Log

### 5.2 暫定配備構成

#### 現在の PoC 構成

- Streamlit UI または軽量 Web UI
- ローカル実行の Backend
- ローカル匿名化
- Gemini free tier への API 呼び出し
- 結果は画面表示のみ

#### 暫定構成の狙い

- 無償で画面と業務フローを確認する
- クレンジング済みデータのみ送信する運用を確立する
- 将来の Gemma 4 移行に備えて provider を抽象化する

#### 目標構成

- Streamlit UI
- Google Cloud 上の Backend API
- Gemma 4 自己配備推論サービス
- Secret Manager による秘密情報管理
- 監査ログ / 結果保存の追加

## 6. 機能設計

### 6.1 ファイル取込

- 複数ファイルのアップロード
- ファイル名と内容の保持
- 未対応形式に対する警告表示

### 6.2 文書抽出

- JSON の整形
- CSV の行列表現化
- HTML / XML のタグ除去
- DOCX の本文抽出
- 将来対応:
  - PDF のテキスト抽出
  - PDF のページ画像化
  - Excel のシート / 表抽出

### 6.3 匿名化

- パスワード
- secret / token / api key
- SNMP community
- IPv4 / IPv6
- email
- MAC address
- hostname 相当

匿名化後はプレースホルダに変換する。

例:

- `[SECRET_001]`
- `[IPV4_001]`
- `[HOSTNAME_001]`

### 6.4 AI レビュー

- 匿名化済みデータからプロンプトを生成する
- レビュー指摘を severity 付きで返す
- 現在は mock provider と HTTP provider を持つ
- 暫定運用では Gemini free tier provider を追加対象とする
- 将来は Gemma 4 provider を追加する

### 6.5 結果表示

- 処理概要
- 指摘一覧
- 匿名化プレビュー
- 警告
- セキュリティメッセージ

## 7. 暫定 LLM 構成

### 7.1 採用理由

- PoC 段階で無償利用を優先するため
- UI とレビュー体験を先に固めるため
- 後から Gemma 4 に差し替えやすい構造を取るため

### 7.2 暫定構成の扱い

- Gemini free tier は PoC 専用とする
- 本番構成とは分離して考える
- 入力は匿名化済みテキストに限定する
- 外部送信する内容は最小化する

### 7.3 将来移行

- `GeminiFreeTierProvider` を `Gemma4Provider` に置換可能な構造とする
- UI と parser と sanitizer はできるだけそのまま再利用する

## 8. PDF / Excel 対応方針

Gemma 4 はマルチモーダルだが、PDF や Excel をそのまま直接理解する前提ではなく、前処理が必要である。
この方針は Gemini 暫定構成でも同じである。

### 8.1 PDF

- 文字主体 PDF:
  - テキスト抽出して投入
- 図表主体 PDF:
  - ページ画像化して投入
- 混在 PDF:
  - テキスト抽出と画像入力を併用

### 8.2 Excel

- シート名の取得
- 表領域の抽出
- セル値の正規化
- Markdown 表または JSON への変換
- 必要に応じて図表を画像化

## 9. 非機能設計

### 9.1 セキュリティ

- 原文をそのまま外部送信しない
- 匿名化後データのみ LLM に送る
- 置換マップは外部送信しない
- PoC では保存を最小化する
- 将来は Secret Manager、IAM、SSO、監査ログを追加する

### 9.2 拡張性

- LLM provider を差替え可能にする
- Parser を形式ごとに追加できる構造とする
- UI と Backend を分離可能とする

### 9.3 運用性

- 警告を UI 表示する
- API 疎通確認スクリプトを持つ
- 将来はジョブ管理と履歴保存を追加する

### 9.4 コスト管理

- PoC は無償利用を前提とする
- GPU 前提構成は採用しない
- 有償サービスへの移行は別途判断とする

## 10. 採用技術

### 10.1 現在

- Python
- `http.server`
- HTML / CSS / JavaScript

### 10.2 PoC 暫定

- Streamlit
- Gemini free tier API
- Python Backend

### 10.3 将来

- Streamlit
- FastAPI もしくは同等の Backend API
- Google Cloud
- Gemma 4 self-hosted inference

## 11. データフロー

1. ユーザーがファイルをアップロードする
2. Backend がファイル内容を受け取る
3. Extractor が形式別にテキスト化する
4. Sanitizer が機密情報を匿名化する
5. Reviewer が匿名化済みテキストでレビューする
6. UI にレビュー結果を表示する

## 12. 今後の開発段階

### 12.1 Phase 1

- 既存 MVP の安定化
- Streamlit UI への移行
- Gemini free tier provider の追加
- README / 設計文書整備

### 12.2 Phase 2

- PDF / Excel 抽出追加
- ベンダー別レビュー観点追加
- 結果保存 / 履歴管理の検討

### 12.3 Phase 3

- Gemma 4 自己配備へ移行
- Google Cloud 配備
- 認証
- 監査ログ
- 保存暗号化
- 権限制御

## 13. 設計とコードの管理方針

- 設計の入口は `docs/basic_design.md`
- コードとの対応は `docs/traceability.md`
- 次チャットへの引き継ぎは `docs/handoff.md`
- 仕様変更時は上記 3 文書を同時更新する
