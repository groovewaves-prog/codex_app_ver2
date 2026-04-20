# Secure Network Review

ネットワーク設計書や機器 Config を読み込み、機密情報を匿名化した上で AI レビューに渡すアプリケーションです。

## 入口

- 基本設計書: `docs/basic_design.md`
- 設計とコードの対応表: `docs/traceability.md`
- 引き継ぎ書: `docs/handoff.md`

## 現在の実装

- ローカル Web UI の MVP
- ファイル読込
- テキスト抽出
- 機密情報の匿名化
- モックレビュー
- 外部 LLM API 接続用の土台
- API 疎通確認スクリプト

## 起動

```powershell
python server.py
```

ブラウザで `http://127.0.0.1:8000` を開きます。

## API 接続テスト

```powershell
$env:OPENAI_API_KEY="..."
$env:HF_TOKEN="..."
python scripts\api_smoke_test.py --provider both
```

## 今後の主方針

- Gemma 4 は自己配備前提
- UI は Streamlit へ移行予定
- 重い推論処理は Google Cloud 側へ寄せる
- PDF / Excel 対応は前処理パイプラインで実現する
