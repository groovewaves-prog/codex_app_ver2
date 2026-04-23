# Secure Network Review

社内文書や設定情報をローカルで秘匿化してから、外部 LLM でレビューするための PoC です。

## 構成

- ローカル前処理: Ollama `gemma3:12b`
- 外部レビュー: Gemma 4 class model

ローカル側では次を行います。

- 一次マスキング
- `gemma3:12b` による追加クレンジング
- `gemma3:12b` による社外送信可否の確認

外部 LLM には、置換済みテキストだけを送ります。

## セットアップ

```powershell
Copy-Item .env.example .env
```

`.env` を確認し、少なくとも `GEMINI_API_KEY` を設定してください。

ローカル Ollama 側でモデル未取得なら、別セッションで次を実行します。

```powershell
ollama pull gemma3:12b
```

## 起動

```powershell
python server.py
```

起動時にカレントディレクトリの `.env` を自動読込します。ブラウザで `http://127.0.0.1:8000` を開いてください。

## ローカル前処理の確認

組み込みサンプルで確認:

```powershell
python scripts\local_ollama_precheck.py
```

実ファイルで確認:

```powershell
python scripts\local_ollama_precheck.py --input-file C:\path\to\your-document.docx
```

詳しい手順は [local_ollama_verification.md](/c:/Users/S023649/OneDrive%20-%20KDDI株式会社/SecurePC/Documents/codex/docs/local_ollama_verification.md) を参照してください。

## 主な環境変数

- `LOCAL_SANITIZER_PROVIDER=ollama`
- `LOCAL_SANITIZER_API_URL=http://127.0.0.1:11434/v1/responses`
- `LOCAL_SANITIZER_MODEL=gemma3:12b`
- `LOCAL_SENSITIVITY_PROVIDER=ollama`
- `LOCAL_SENSITIVITY_API_URL=http://127.0.0.1:11434/v1/responses`
- `LOCAL_SENSITIVITY_MODEL=gemma3:12b`
- `REVIEW_PROVIDER=gemma4`
- `GEMMA_MODEL=gemma-4-31b-it`
- `GEMINI_API_KEY=...`

## テスト

```powershell
python -m unittest tests.test_env_loader tests.test_sanitizer tests.test_sensitivity tests.test_reviewer
```
