# Local Ollama verification

Last updated: 2026-04-23

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

## 2. エンドポイントの疎通確認

合成リクエストでローカル sanitizer と sensitivity gate の疎通を確認します:

```powershell
python scripts\local_ollama_precheck.py
```

このコマンドは:

1. `LOCAL_SANITIZER_API_URL` と `LOCAL_SENSITIVITY_API_URL` が**ループバックアドレス**
   (`127.0.0.1`, `::1`, `localhost`) を指しているかを検証する
2. 小さな合成文書で POST が通ることを確認する

期待される出力:

- `OK: http://127.0.0.1:11434/...` が sanitizer と sensitivity gate の両方に表示される
- 最終行に `All configured checks passed.` が出る

非ループバック URL が設定されていた場合は `FAIL` で停止します。これは意図した
挙動で、外部ホストに原文が送られることを防ぎます。

## 3. 実ファイルでのパイプライン確認

実ファイルを 1 つ指定して、抽出 → 匿名化 → 社外送信可否判定までを確認します:

```powershell
python scripts\local_ollama_precheck.py --input-file C:\path\to\your-document.docx
```

PowerPoint や Excel、PDF も同様に指定できます:

```powershell
python scripts\local_ollama_precheck.py --input-file C:\path\to\change-runbook.xlsx
python scripts\local_ollama_precheck.py --input-file C:\path\to\review-target.pptx
python scripts\local_ollama_precheck.py --input-file C:\path\to\design.pdf
```

確認ポイント:

- `extracted chars` が 0 でない (抽出が成功している)
- `replacements` が 0 より大きい (匿名化が効いている)
- `outbound risk` が `low` または `medium`
- `gate decision` が `safe` または `mask_and_continue`
- `gate decision` が `block` になる場合は、明示的な社外秘表記や識別可能情報が
  強く残っていると判定されている

結果の見方:

- `RESULT: safe (sanitized text only).`
  - ローカル前処理として通過
- `RESULT: needs explicit confirmation in the UI.`
  - Streamlit UI で各文書のチェックボックスを確認してから送信
- `RESULT: BLOCKED. Do not transfer externally.`
  - 外部レビューへ進めない。より強く匿名化した版を別途作成すること

## 4. 初回確認に向くデータ

最初は次の順で試すのが安全です:

1. ダミー文書
2. 既に匿名化済みの文書
3. 実データの一部抜粋
4. 実データ全体

## 5. Streamlit UI 側での最終確認

precheck が通ったら Streamlit に切り替えます:

```powershell
streamlit run streamlit_app.py
```

ブラウザで表示された URL を開いて、precheck で OK を確認したファイルを投入します。

見るべき点:

- Step 2 の `Sanitized excerpt` に顧客名や拠点名などが残っていないか
- 各文書の判定バッジ (`SAFE` / `NEEDS CONFIRM` / `BLOCKED`)
- `mask_and_continue` 判定のチェックボックスは自分で確認してからオン
- `BLOCKED` が 1 つでもある場合、Send ボタンは無効化される

## 6. 典型的な詰まりどころ

### `endpoint URL host '...' is not a loopback literal`

- ループバック以外の URL が `.env` に書かれている
- 対応: `127.0.0.1`, `::1`, `localhost` に書き換える
- これは R1 の境界が機能している証拠

### `local sanitizer could not be reached`

- Ollama が起動していない
- ポート番号が違う
- 対応: `ollama list` を別シェルで実行して確認

### `Model 'gemma3:12b' was not found`

- モデル未取得
- 対応: `ollama pull gemma3:12b`

### `RESULT: BLOCKED.`

- 明示的な社外秘表記
- 顧客識別につながる文脈
- 構成図や拠点情報が残っている

対応:

- 文書を章単位に分割する
- 会社名、拠点名、案件名、担当者名、系統名の文脈をさらに一般化する
- `.env` に `LOCAL_SANITIZER_PROVIDER=ollama` を設定してローカル LLM による
  追加匿名化を有効化する
