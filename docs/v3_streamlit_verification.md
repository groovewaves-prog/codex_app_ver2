# V3: Streamlit UI end-to-end verification

Last updated: 2026-04-24

本手順書は、Streamlit UI が実データで期待どおり動くかを一巡確認するための
チェックリストです。初回デプロイ後、または env 変更後の検証に使います。

## 0. 事前準備

### 0.1 依存パッケージ

```powershell
cd C:\Users\S023649\OneDrive - KDDI株式会社\SecurePC\Documents\codex
pip install -r requirements.txt
```

期待: `streamlit`, `pypdf` を含むインストール成功。

### 0.2 `.env` の確認

```powershell
Get-Content .env | Select-String -NotMatch "^#"
```

**最低限必要**:

- `GEMINI_API_KEY=...` (外部レビューを実行する場合)
- `REVIEW_PROVIDER=mock` (初回は mock で動かすのが安全)

**ローカル LLM を併用する場合の追加**:

- `LOCAL_SANITIZER_PROVIDER=ollama`
- `LOCAL_SANITIZER_API_URL=http://127.0.0.1:11434/v1/responses`
- `LOCAL_SANITIZER_MODEL=gemma3:12b`
- `LOCAL_SENSITIVITY_PROVIDER=ollama`
- `LOCAL_SENSITIVITY_API_URL=http://127.0.0.1:11434/v1/responses`
- `LOCAL_SENSITIVITY_MODEL=gemma3:12b`

ループバック以外の URL が設定されていると起動時に `LocalUrlError` で拒否されます。

### 0.3 事前疎通確認

```powershell
python scripts\local_ollama_precheck.py
```

期待:
- `local sanitizer` と `local sensitivity gate` の両方に `OK: http://127.0.0.1:...`
- 最終行に `All configured checks passed.`

`local sanitizer` / `local sensitivity` を設定していない場合は `skipped` が出ます。これは想定通り。

## 1. Streamlit 起動

```powershell
streamlit run streamlit_app.py
```

期待:
- コンソールに `You can now view your Streamlit app in your browser.`
- ブラウザが自動的に `http://localhost:8501` を開く

**観察ポイント**:
- サイドバーに `review → mock`、`sanitizer → <設定値>`、`sensitivity → <設定値>` が表示される
- サイドバーの Review profile セレクタが表示される

## 2. ステップ 1（Upload）確認

### 2.1 ダミーファイル（無害な内容）を投入

まずはダミー文書で動作確認。以下の内容でテキストファイル `safe_test.txt` を作成:

```
目的: 定期メンテナンス作業
ネットワーク構成: 別紙
タイムチャート: 別紙
リスクレベル: 低、承認: GL
作業完了後の正常性確認: ping 疎通確認
バックアウト判断基準: エラー継続時は切戻し
変更対象ドキュメント: 運用手順書v1.0
体制: 作業者、再鑑者、エスカレーション先明記
```

UI で:
1. 「Select files」で `safe_test.txt` をアップロード
2. Review profile セレクタで `change_runbook` を選択
3. 「Sanitize & preview」をクリック

期待:
- 「Sanitizing locally...」スピナーが表示された後、Step 2 のプレビューが表示される
- `SAFE` バッジが文書カード右上に表示される
- `Documents: 1`, `Safe: 1`, `Needs confirm: 0`, `Blocked: 0`

### 2.2 機密情報入り文書の投入

`sensitive_test.txt` を作成:

```
作業目的: 本番環境への設定反映
顧客名: 株式会社サンプル
担当者: 山田太郎
password: superSecret!
ip address 10.0.0.1
```

アップロードして preview。期待:
- `NEEDS CONFIRM` バッジ
- Gate reasoning に「Business identifiers or ownership labels were found」相当
- 「Sanitized excerpt」タブで `[COMPANY_001]`, `[PERSON_001]`, `[SECRET_001]`, `[IPV4_001]` などが表示される
- 「Replacements」タブで置換一覧が表形式で見える

### 2.3 社外秘ラベル付き文書

`confidential_test.txt`:

```
社外秘
顧客名: 株式会社重要顧客
案件名: 次期システム移行
```

期待:
- `BLOCKED` バッジ（赤色の doc-card 枠）
- Step 3 で Send ボタンが無効化
- エラーメッセージ: 「Cannot send while documents are blocked.」

## 3. ステップ 3（確認ゲート）確認

### 3.1 mask_and_continue の確認フロー

2.2 の `sensitive_test.txt` のみアップロード状態で:

1. Step 3 のチェックボックス「I have reviewed the sanitized excerpt of **sensitive_test.txt**...」を**チェックせず**、Send ボタンを見る
2. 期待: Send ボタンが**無効化**されている
3. チェックボックスをオン
4. 期待: Send ボタンが**有効化**される

### 3.2 block が混ざる場合

2.2 と 2.3 を同時にアップロード:

1. 期待: `NEEDS CONFIRM` 1 件、`BLOCKED` 1 件
2. sensitive_test.txt のチェックボックスをオンにしても、blocked_test.txt があるため Send は**無効のまま**
3. 期待メッセージ: 「Cannot send while documents are blocked.」

## 4. ステップ 4（レビュー実行）確認

### 4.1 mock provider での実行

`REVIEW_PROVIDER=mock` で 2.1 の `safe_test.txt` を送信:

1. Preview 後、Send をクリック
2. 期待:
   - 「Running review with mock...」スピナー
   - Step 4 に結果表示
   - `provider: mock · rubric: 変更・切替手順書レビュー基準 · profile: change_runbook (forced)`
   - Issues 0 件 または「No major issue found in mock review」(info)

### 4.2 未記入項目があるケース

テンプレートから一部を削った `incomplete_test.txt`:

```
目的: 本番環境への設定反映
全体概要図: 別紙
```

change_runbook として送信。期待 issues:
- `high`: タイムチャートの記載または別紙参照が不足
- `medium`: 作業対象環境の区別が不明確
- `medium`: リスクレベルと承認プロセスの記載が不足
- `low`: 作業後に修正対象となるドキュメントの事前一覧が無い

これで rubric の強化が実動作していることを確認。

### 4.3 Gemini free tier provider での実行

`.env` を一時的に `REVIEW_PROVIDER=gemini-free` に変更して再起動:

```powershell
streamlit run streamlit_app.py
```

2.1 を送信。期待:
- プレビュー → 確認 → Send までは mock と同じ挙動
- 「Running review with gemini-free-tier...」
- 実際の Gemini 応答が表示される
- Summary に「Received review result from Gemini API model gemini-2.0-flash.」

**クォータ枯渇時の挙動確認**（複数回連続送信で発生させる）:
- 期待エラー: 「Gemini free-tier quota appears to be exhausted. Wait a minute and try again, or switch to a paid tier.」
- トレースは出ない（ユーザー向け整形メッセージのみ）

## 5. セッション管理の確認

- 「Reset session」ボタンをサイドバーでクリック
- 期待: アップロード、プレビュー、レビュー結果がクリアされ Step 1 に戻る
- 文書内容はサーバメモリから消える（仕様上）

## 6. 実ファイル形式別の動作確認

各形式 1 ファイルずつアップロードして、preview が成功することを確認:

| 形式 | 期待 |
|---|---|
| `.docx` | 本文抽出される |
| `.xlsx` | シート名+セル値が `# Sheet: xxx` 形式で抽出 |
| `.pptx` | `# Slide N` 形式でスライドテキスト抽出 |
| `.pdf` | `pypdf` でページ単位抽出、スキャン PDF は警告 |
| `.png`/`.jpg` | Tesseract 有り: OCR 結果、無し: プレゼンス通知のみ |
| `.json` / `.csv` / `.yaml` | 整形済み表示 |

**実業務ファイル**での確認:
- 作業計画書テンプレート（pptx）を投入、change_runbook で 0 件 issue になること
- テンプレート未記入項目のある実文書を投入、該当項目の警告が出ること

## 7. 典型的な詰まりどころ

### Streamlit が起動しない

```
ModuleNotFoundError: No module named 'streamlit'
```

→ `pip install -r requirements.txt`

### 起動はするが「A local-only endpoint is misconfigured」

→ `.env` の `LOCAL_SANITIZER_API_URL` / `LOCAL_SENSITIVITY_API_URL` を `127.0.0.1` に修正。

### Preview は動くが Send 後に「review failed」

→ サイドバーの `REVIEW_PROVIDER` を確認。mock 以外なら対応する API キーが `.env` にあるか確認。

### 画像 OCR が効かない

→ Tesseract の有無。Windows なら `tesseract --version` で確認。なければ警告付きプレースホルダで処理は続行。

### PDF が空テキストになる

→ スキャン PDF の可能性。pypdf では本文テキストが取れない。OCR は未対応のため、OCR 済み版に差し替えるか、別手段でテキスト化してから投入。

## 8. 確認完了の合図

以下をすべてクリアしたら V3 完了:

- [ ] ダミーファイルで preview → review まで走る
- [ ] 機密情報入り文書で `NEEDS CONFIRM` が出る
- [ ] 社外秘ラベルで `BLOCKED` が出る
- [ ] 確認ゲートのチェックボックス動作
- [ ] mock provider で issue が出る / 出ない パターン
- [ ] Gemini free tier provider で実 API 応答が出る
- [ ] 作業計画書テンプレートで 0 件 issue
- [ ] 未記入項目のある文書で期待 issue が検出される
- [ ] 主要ファイル形式 (docx/xlsx/pptx/pdf) の抽出

## 9. 発見事項の報告先

V3 で想定外の挙動を見つけた場合:

1. 現象、投入ファイル、期待値、実際値を手短にメモ
2. 次チャットで共有（`docs/handoff.md` の「Known issues discovered during V3」セクションに追記）
3. 重大な不具合（セキュリティ境界の破綻など）は即座に利用停止し、mock provider に切り替えて再検証
