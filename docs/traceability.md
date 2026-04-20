# 設計とコードの対応表

## 1. 目的

基本設計書の各要素が、どのコードに反映されているかを追跡するための対応表である。

## 2. 対応表

| 設計項目 | 内容 | 主な実装ファイル |
| --- | --- | --- |
| UI | 画面表示、アップロード、結果描画 | `static/index.html`, `static/app.js`, `static/styles.css` |
| Web サーバ | HTTP 受付、API ルーティング、静的ファイル配信 | `server.py`, `secure_review/app.py` |
| 入力モデル | 文書、匿名化結果、レビュー結果のデータ構造 | `secure_review/models.py` |
| 文書抽出 | JSON / CSV / HTML / XML / DOCX の抽出 | `secure_review/extractor.py` |
| 匿名化 | 機密情報の検出とプレースホルダ化 | `secure_review/sanitizer.py` |
| レビュー抽象化 | provider 選択、プロンプト構築、mock / HTTP 呼び出し | `secure_review/reviewer.py` |
| 疎通確認 | OpenAI / Gemma 系 API の smoke test | `scripts/api_smoke_test.py` |
| 品質確認 | sanitizer / reviewer の単体テスト | `tests/test_sanitizer.py`, `tests/test_reviewer.py` |

## 3. 基本設計書との対応

### 3.1 「5. 全体アーキテクチャ」

- Backend API: `secure_review/app.py`
- LLM Adapter: `secure_review/reviewer.py`
- UI: `static/*`

### 3.2 「6.2 文書抽出」

- 実装: `secure_review/extractor.py`
- 現在対応:
  - `.json`
  - `.csv`
  - `.html`
  - `.xml`
  - `.docx`
- 未実装:
  - `.pdf`
  - `.xlsx`

### 3.3 「6.3 匿名化」

- 実装: `secure_review/sanitizer.py`
- 現在の検出対象:
  - password / secret / token / key
  - IPv4 / IPv6
  - email
  - MAC
  - hostname

### 3.4 「6.4 AI レビュー」

- 実装: `secure_review/reviewer.py`
- 現在の provider:
  - `MockReviewProvider`
  - `HttpLlmReviewProvider`
- 次の追加候補:
  - `GeminiFreeTierProvider`
- 将来追加候補:
  - `Gemma4Provider`

### 3.5 「7. 暫定 LLM 構成」

- 現在は文書のみ更新済み
- 実装追加先候補:
  - `secure_review/reviewer.py`
  - `scripts/`
  - 将来の `providers/` 配下

### 3.6 「8. PDF / Excel 対応方針」

- 現在は未実装
- 実装追加先候補:
  - `secure_review/extractor.py`
  - `secure_review/reviewer.py`
  - 将来の `services/` 配下

## 4. 更新ルール

- 実装追加時はこの表に対象ファイルを追記する
- ファイル移動時は本表を更新する
- 設計変更時は `docs/basic_design.md` との整合を取る
