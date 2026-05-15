# Secure Network Review

社内文書や設定情報をローカルで秘匿化してから、外部 LLM でレビューするための PoC です。
2026-04-24 時点で R1–R4 セキュリティ境界対応済み、Streamlit UI が主 UI、PDF 抽出対応済み。

## 1. 構成

- **主 UI**: Streamlit (`streamlit_app.py`)
- **ローカル前処理**: 正規表現 sanitizer + Ollama `gemma3:12b`（任意）
- **社外送信可否判定**: ローカル heuristic または `gemma3:12b` (任意)
- **外部レビュー**: Gemini free tier (`gemini-2.0-flash`) / Gemma 4 クラスモデル

ローカル側で実施:
- 一次マスキング（正規表現）
- Ollama による追加クレンジング（任意）
- Ollama による社外送信可否の判定（任意、未設定時はヒューリスティック）

外部 LLM には**匿名化済みテキストのみ**を送信。`mask_and_continue` 判定時は操作者の
明示的確認なしに送信しません（R2 境界）。

詳細は `docs/security_boundaries.md` を参照。

## 2. セットアップ

```powershell
Copy-Item .env.example .env
```

`.env` を編集して最低限 `GEMINI_API_KEY` を設定してください。主要な環境変数は
`docs/handoff.md` の環境変数表を参照。

依存パッケージをインストール:

```powershell
pip install -r requirements.txt
```

ローカル Ollama を併用する場合（任意）:

```powershell
ollama pull gemma3:12b
```

## 3. 起動

### 3.1 Streamlit UI（推奨）

```powershell
streamlit run streamlit_app.py
```

ブラウザで `http://localhost:8501` が開きます。4 ステップフロー:

1. Upload: 複数ファイルをアップロード
2. Sanitize & preview: ローカルでマスクし判定結果を表示（外部送信なし）
3. Confirm: `mask_and_continue` 判定の文書をチェックで確認
4. Send for review: 外部 LLM に送信して結果を表示

### 3.2 HTTP API（補助的）

```powershell
python server.py
```

`http://127.0.0.1:8000` で `/api/preview` と `/api/review` が利用可能。詳細は
`docs/security_boundaries.md`。

## 4. 事前疎通確認

```powershell
python scripts\local_ollama_precheck.py
```

ループバックアドレス検証 + 合成リクエストで疎通を確認します。

実ファイルで全パイプラインを走らせる:

```powershell
python scripts\local_ollama_precheck.py --input-file C:\path\to\your-document.docx
```

対応形式: `.txt`, `.md`, `.docx`, `.xlsx`, `.pptx`, `.pdf`, `.csv`, `.json`,
`.yaml`/`.yml`, `.xml`, `.html`, スクリプト (`.py`, `.ps1`, `.sh`, `.vbs`, `.sql`等),
画像 (OCR 付き、Tesseract 必須)。

詳細手順は `docs/local_ollama_verification.md`、実データでの検証は
`docs/v3_streamlit_verification.md` を参照。

## 5. 主な環境変数

```
# Provider
REVIEW_PROVIDER=mock|http|gemma|gemini-free
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-2.0-flash           # gemini-free 時の既定

# ローカル sanitizer（任意、ループバック必須）
LOCAL_SANITIZER_PROVIDER=ollama
LOCAL_SANITIZER_API_URL=http://127.0.0.1:11434/v1/responses
LOCAL_SANITIZER_MODEL=gemma3:12b

# ローカル sensitivity gate（任意、ループバック必須）
LOCAL_SENSITIVITY_PROVIDER=ollama
LOCAL_SENSITIVITY_API_URL=http://127.0.0.1:11434/v1/responses
LOCAL_SENSITIVITY_MODEL=gemma3:12b

# 安全
MASK_AND_CONTINUE_REQUIRE_CONFIRM=true  # 本番は必ず true
```

完全な一覧は `.env.example` および `docs/handoff.md` を参照。

## 6. テスト

```powershell
python -m unittest discover tests
```

59 テスト（network_guard / sanitizer / sensitivity / reviewer / env_loader / app）。

## 7. ドキュメント

| 文書 | 役割 |
|---|---|
| `docs/basic_design.md` | 基本設計書 |
| `docs/security_boundaries.md` | R1-R4 セキュリティ境界仕様 |
| `docs/traceability.md` | 設計-コード対応表 |
| `docs/handoff.md` | 引き継ぎ書（現状・残課題） |
| `docs/operations_policy.md` | 運用ポリシー |
| `docs/mock_operation_manual.md` | 上司・評価者向けモック操作マニュアル |
| `docs/local_ollama_verification.md` | ローカル Ollama 検証手順 |
| `docs/v3_streamlit_verification.md` | Streamlit UI 実データ検証手順 |
| `CHANGES.md` | 変更履歴 |
