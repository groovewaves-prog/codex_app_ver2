# Local Ollama Verification

ローカル `Ollama / gemma3:12b` を使って、前処理が正しく動くかを確認するための手順です。

## 1. 前提

- `.env` が配置済みである
- 別セッションで Ollama が起動している
- `gemma3:12b` がローカルに取得済みである

最小確認:

```powershell
ollama list
```

`gemma3:12b` が見えない場合:

```powershell
ollama pull gemma3:12b
```

## 2. サンプルデータで前処理確認

まずは組み込みサンプルで、追加クレンジングと社外送信可否判定が動くかを見ます。

```powershell
python scripts\local_ollama_precheck.py
```

期待すること:

- `Available models:` に `gemma3:12b` が表示される
- `PASS` が出る
- `Sanitized preview` にプレースホルダ化されたテキストが表示される
- `RESULT:` が出る

結果の見方:

- `RESULT: Local pre-check passed.`
  - ローカル前処理としては通過
- `RESULT: Additional review recommended before external transfer.`
  - 外部送信前に秘匿化結果を人手で確認した方がよい
- `RESULT: BLOCKED for external transfer.`
  - 明示的な社外秘や識別可能情報が強く残っている

## 3. 実データで前処理確認

テキスト系や Office 系の実ファイルを 1 つ指定して確認します。

```powershell
python scripts\local_ollama_precheck.py --input-file C:\path\to\your-document.docx
```

PowerPoint や Excel も同様です。

```powershell
python scripts\local_ollama_precheck.py --input-file C:\path\to\change-runbook.xlsx
python scripts\local_ollama_precheck.py --input-file C:\path\to\review-target.pptx
```

確認ポイント:

- `Initial replacement count` より `Enhanced replacement count` が増えることがある
  - ローカル LLM が追加で秘匿化した可能性
- `Outbound risk` が `high` の場合
  - 外部送信前により強い一般化が必要
- `Local sensitivity decision` が `block`
  - 外部レビューへ進めない

## 4. アプリ全体で確認

外部 Gemma 4 側も含めて流れを確認する場合:

```powershell
python server.py
```

ブラウザで `http://127.0.0.1:8000` を開き、実データを投入します。

見るべき点:

- `Sanitized excerpt` に顧客名や拠点名などが残っていないか
- `Local sensitivity decision` が `safe` か `mask_and_continue` か
- `Review processing failed` が出ないか

## 5. 初回確認に向くデータ

最初は次の順で試すのが安全です。

1. ダミー文書
2. 既に匿名化済みの文書
3. 実データの一部抜粋
4. 実データ全体

## 6. 典型的な詰まりどころ

### `Could not connect to local Ollama`

- Ollama が起動していない
- 別環境の `localhost` を見ている
- `.env` の `LOCAL_SANITIZER_API_URL` / `LOCAL_SENSITIVITY_API_URL` が違う

### `Model 'gemma3:12b' was not found`

- モデル未取得
- タグ名が想定と異なる

確認:

```powershell
ollama list
```

### `RESULT: BLOCKED for external transfer.`

- 明示的な社外秘表記
- 顧客識別につながる文脈
- 構成図や拠点情報が残っている

対応:

- 文書を章単位に分割する
- 会社名、拠点名、案件名、担当者名、系統名の文脈をさらに一般化する
