# 引き継ぎ書

## 1. この文書の目的

チャットのコンテキスト上限に近づいた時や、新しいチャットで再開する時に、そのまま作業を引き継ぐための文書である。

## 2. 現在の到達点

- ローカルで動く MVP がある
- ファイル取込、抽出、匿名化、レビュー、UI 表示まで一連の流れがある
- 外部 LLM 呼び出し用の HTTP provider がある
- API 疎通確認用スクリプトがある
- 基本設計書とコード対応表を追加した

## 3. 現在の正式方針

- PoC 段階では無償構成を優先する
- UI は Streamlit を使う前提で進める
- 暫定 LLM は Gemini free tier を想定する
- Gemini へ送るのは匿名化済みデータのみとする
- Gemma 4 自己配備は将来フェーズで移行する
- PDF / Excel は前処理パイプラインで対応する

## 4. 以前の方針との差分

- 以前は Gemma 4 自己配備を直近の前提としていた
- 現在は費用を発生させないため、PoC では Gemini free tier を暫定採用する
- Gemma 4 自己配備は後段へ移した

## 5. 現在のファイル構成の要点

### 5.1 実装

- `server.py`
- `secure_review/app.py`
- `secure_review/models.py`
- `secure_review/extractor.py`
- `secure_review/sanitizer.py`
- `secure_review/reviewer.py`
- `static/index.html`
- `static/app.js`
- `static/styles.css`
- `scripts/api_smoke_test.py`

### 5.2 文書

- `README.md`
- `docs/basic_design.md`
- `docs/traceability.md`
- `docs/handoff.md`

## 6. すぐ再開したい作業候補

優先度順に並べる。

1. Streamlit UI への移行
2. Gemini free tier provider の追加
3. 設定値と API キー管理方法の整理
4. PDF 抽出の追加
5. Excel 抽出の追加
6. 将来の Gemma 4 provider インターフェース準備

## 7. 次チャットで Codex に伝えると良い文

以下をそのまま貼れば再開しやすい。

```text
docs/handoff.md と docs/basic_design.md を読んで現状を把握し、
docs/traceability.md に従ってコードとの対応を確認した上で作業を再開してください。
現在の方針は、PoC では Streamlit UI と Gemini free tier を使う暫定構成です。
Gemma 4 自己配備は将来フェーズへ移しています。
```

## 8. 未解決事項

- Gemini free tier へ接続する provider 実装方法
- API キーの管理方法
- PDF / Excel 抽出ライブラリの選定
- Streamlit UI の画面構成
- Gemma 4 自己配備へ移行するタイミング

## 9. 管理ルール

- 方針が変わったらこの文書を更新する
- 直近タスクは上から順に並べる
- 新しいチャットを始める前に必ず更新する
