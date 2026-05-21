# Handoff

Last updated: 2026-05-19

この文書は、現在の `codex_app` モックを別の GitHub リポジトリへコピーして作業を継続する人が、
最短で状況を復元できるようにするための引き継ぎ書です。

## 0. 最重要サマリ

- 現在のツール名は **技術文書レビュー支援ツール**。
- サブタイトルは **アップロード文書を匿名化し、業界標準に基づいて構成・品質・リスクをレビューします。**
- 現行リポジトリ: `https://github.com/groovewaves-prog/codex_app`
- Streamlit Cloud URL: `https://codexapp-edwxxq7jek7mrtyr8hwtbp.streamlit.app`
- 現行 main 最新コミット: `1f96172 Polish review summary panels`
- 2026-05-19 時点で、ユーザーがモック実機確認を行い、直近で問題視していたUI/動作不具合は解消済み。
- 現在は **上司・管理者テスト中**。
- 今後の追加作業は、テスト中の現行リポジトリを壊さないよう、**このモックをコピーした新しい GitHub リポジトリ側で継続予定**。
- APIキーやSecretsはこの文書にも、チャットにも貼らない。Streamlit Cloud Secrets または手元 `.env` のみで管理する。

## 1. 現在の到達点

### 1.1 実装済みの主要機能

| 領域 | 現状 |
|---|---|
| UI | Streamlit。日本語UI。ステータスバー、送信前チェック、カード型サマリ、折りたたみ・スクロール表示を実装済み |
| 文書アップロード | PDF / DOCX / XLSX / PPTX / TXT 等を受付。複数PDFは「同一種類の文書を複数ファイルで構成」として一括レビュー |
| 匿名化 | regex + heuristic + NER/R-M補助。外部LLMへ送る前に匿名化済みテキストを確認可能 |
| 送信ゲート | 「LLM送信前の最終承認」チェックが入るまで外部送信不可 |
| 外部レビュー | Gemini API 経由の Gemma 4 31B (`gemma-4-31b-it`) を主想定 |
| レビュー基準 | IPA、AWS Well-Architected、ISO/IEC 25010 をベースに、文書種別別プロファイルを実装 |
| 文書構成チェック | 不足観点、必須要素不足、構成整理の提案をレビュー前提として表示 |
| 文書全体の概要 | LLMまたはローカル補完により、目的・内容要約・全体評価を表示 |
| 章別概要レビュー | 全章を章カードで表示。概要レビューと深堀候補を分離 |
| 章別深堀 | 通常モードは最初の深堀候補章のみ有効。開発者モードでは検証用に全章深堀可。最大2パス |
| 複数ファイル・長文対策 | 合算トークン概算、予定call数、分割推奨表示、Gemini chunking を実装 |
| ネットワークConfig | Cisco IOS / IOS XE、Fortinet FortiOS の概要解析プロファイルを追加 |
| 構成図・画像 | 画像はローカルOCRで読めた文字列から控えめに構成図サマリを作成。画像そのものを外部LLMへ送らない方針 |
| 操作マニュアル | `docs/mock_operation_manual.md` を作成済み。上司・管理者テスト時の説明資料として利用 |

### 1.2 直近の主な改善コミット

```text
1f96172 Polish review summary panels
9025c23 Update mock manual for latest UI labels
2e058f6 Resolve technical follow-up issues
0138154 Add mock operation manual
4894733 Polish Streamlit review UI hierarchy
75dc63d Improve pre-send readiness summary UI
04424e9 Unify workflow task status display
2d8a162 Refine preview ordering and task panel UX
fd14f91 Improve review workflow UX
b90b2ed Fix multi-file anonymization status and token budget summary
caa5826 Add network config and token budget review support
11b4832 Reconcile structure checks with reviews
```

### 1.3 テスト状況

- 2026-05-15 時点で `python -m unittest` は **290 tests OK**。
- テストログには意図的な HTTP 500 / 400 / 409 などの異常系ログが出るが、最終結果が `OK` なら正常。
- 2026-05-19 時点で、ユーザーが Streamlit モックを実機確認し、直近のUI/動作問題が解消されていることを確認済み。

## 2. 現在の運用状態

### 2.1 利用中の想定Secrets

実値は記載しない。Streamlit Cloud Secrets に以下の形で設定する。

```toml
REVIEW_PROVIDER = "gemma"
GEMMA_MODEL = "gemma-4-31b-it"
GEMINI_API_KEY = "***"
GEMINI_MAX_OUTPUT_TOKENS = "16384"
GEMINI_MAX_RETRIES = "3"
GEMINI_CHUNKING_INTERVAL = "6"
LOCAL_SANITIZER_PROVIDER = "none"
LOCAL_SENSITIVITY_PROVIDER = "heuristic"
MASK_AND_CONTINUE_REQUIRE_CONFIRM = "true"
GBIZINFO_API_TOKEN = "***" # R-M / 法人名検索を使う場合のみ
```

### 2.2 重要な運用方針

- Streamlit Cloud は今回のPoCでは信頼境界内として扱う。
- 外部LLMへ送るのは匿名化済みテキストのみ。
- ローカル Ollama / ローカルLLM 構想は凍結中。将来の自己配備フェーズに備え、関連コードは残している。
- 1回のレビューでは、設計書と手順書など異種文書を混在させない。同一種類の文書であれば複数ファイル一括アップロード可。
- 大量PDFや長大な手順書は、Gemma/Gemini側のトークン消費、待ち時間、クォータ制限に影響する。
- スキャンPDFや画像中心資料はOCR精度に依存する。厳密な構成図解析ではなく、概要補助として扱う。

## 3. コピー先 GitHub リポジトリで作業を続ける場合

### 3.1 コピー時に守ること

新しい GitHub リポジトリを作る場合は、次を守る。

- `.git/` はコピーしないか、コピー後に新リポジトリとして初期化する。
- `.env`、`.streamlit/secrets.toml`、ダウンロードした `review_log_*.json`、APIキーを含むファイルは絶対にコミットしない。
- `__pycache__/`、`.pytest_cache/`、仮想環境、ローカル生成物はコピー不要。
- Streamlit Cloud の新アプリを作る場合、Secrets は新アプリ側で手動再設定する。
- GitHub の email privacy 対策として、ローカルGitの email は `groovewaves-prog@users.noreply.github.com` を推奨。

### 3.2 コピー先 GitHub リポジトリで最初に確認すること

```powershell
git status
python -m unittest
streamlit run streamlit_app.py
```

Streamlit Cloud に接続する場合は、以下を確認する。

- main ブランチのデプロイ先が新リポジトリになっているか。
- Secrets が旧アプリから手動で移植されているか。
- Reboot 後にブラウザをハードリフレッシュして最新版を見ているか。

## 4. UI / 操作フローの現状

### 4.1 基本フロー

1. ステップ1: 文書アップロード
2. ステップ2: 匿名化結果プレビュー
3. ステップ3: 確認 & 送信
4. レビュー結果表示

ステータスバーは以下の状態を表示する。

- 新規
- 匿名化済み
- 確認待ち
- 送信準備完了
- レビュー中
- レビュー完了

### 4.2 匿名化結果プレビュー

主な表示は以下。

- 送信前チェック
- 匿名化結果の内訳
- 文書別カード
- 匿名化検知内容
- マスク候補
- 匿名化結果を再生成
- 匿名化後テキスト確認
- 結果ログをダウンロード(JSON)

「匿名化結果を再生成」は、マスク候補など再生成すべき対象がない場合は無効化される。これは正常。

### 4.3 レビュー結果

レビュー結果は以下の順で確認する。

1. Review Result サマリ
2. 文書構成チェック
3. 文書全体の概要
4. 章別概要レビュー
5. 重要指摘表示
6. 必要に応じて章別深堀

`Review Result` と `文書構成チェック` はカード型サマリに変更済み。高重要度・要確認・安全状態が視覚的に分かるようにしている。

## 5. レビュー設計上の重要ポイント

### 5.1 文書構成チェックと概要レビューの整合

- 文書構成チェックは、文書全体として必要な観点があるかを見る。
- 章別概要レビューは、検出された各章本文の概要評価を見る。
- 「はじめに」章だけに関係者・改訂履歴を強制するような誤解を避けるため、現在は文書全体の管理項目として扱う。
- 構成チェックの表示では、意味の薄い「第N章」表記を避け、「不足観点」「必須要素不足」「構成整理の提案」として表示する。

### 5.2 深堀レビューの方針

- 概要レビューで「適切」とした章を無制限に深堀して矛盾を出す運用は避ける。
- 深堀は「深堀候補」と判定された章を対象にする。
- 通常モードでは最初の深堀候補章だけ有効化し、トークン消費を抑える。
- 開発者モードでは検証目的で全章深堀ボタンを有効化できる。
- 2回目以降は「追加確認結果」として扱い、同じサマリを繰り返さない。
- 最大2パスで停止し、それ以上は既存結果の確認を促す。

詳細な考え方は `docs/review_methodology.md` を参照。

### 5.3 ネットワークConfig / 構成図

- Cisco IOS / IOS XE と Fortinet FortiOS は、正式なConfig監査ではなく概要解析として扱う。
- 文書内にConfig抜粋がある場合、本文説明との矛盾や確認観点を出す。
- Config単体の場合、機器役割、管理アクセス、ログ、NTP、SNMP、ACL、VPN、経路などの概要確認に留める。
- 画像構成図は、ローカルOCRで抽出できた文字列だけを匿名化後にLLMへ渡す。
- 接続線、矢印、ネットワーク階層、冗長化方式はOCRだけでは確定しない。レビューでは「確認観点」として扱う。

詳細は `docs/network_config_review_scope.md` を参照。

## 6. 残課題

### 6.1 現在の優先課題

| 優先 | 課題 | 状態 |
|---|---|---|
| 高 | 上司・管理者テストのフィードバック回収 | 実施中 |
| 高 | コピー先リポジトリの作成とSecrets/Streamlit設定 | 次作業候補 |
| 中 | 長文・複数ファイル時の待ち時間、分割call、クォータ挙動の実地確認 | 継続確認 |
| 中 | 実業務文書に近い資料での指摘品質確認 | 継続確認 |
| 中 | Gemini/Gemma free tier のクォータ遭遇時の利用者向け説明確認 | 継続確認 |
| 低 | ガイドライン定義のYAML/JSON外部化 | 将来対応 |
| 低 | ローカルOllama系コードを温存するか削除するか | 判断保留 |
| 低 | スキャンPDF / 画像構成図のOCR精度向上 | 将来対応 |

### 6.2 いま直すべき明確なコードバグ

2026-05-19 時点では、ユーザー確認済みの範囲で、直近の主要UI/動作問題は解消済み。
上司・管理者テストで新たに出たものを次の対応対象とする。

## 7. 既知の制約

- HTTP API 前段に認証はない。通常はStreamlit UIを利用する。
- Streamlit Cloud Secrets はGitHub pushでは同期されない。新アプリ作成時は手動設定が必要。
- APIキーはチャットに貼らない。
- ローカルLLM機能は凍結中。
- 監査ログの本格的な永続化は未実装。必要なら別途設計する。
- スキャンPDFはテキスト抽出できない場合がある。
- 画像OCRはTesseract等のローカルOCR環境に依存する。
- OneDrive配下リポジトリではgitロック警告が出ることがある。実害がない場合は `n` で抜けて状態確認する。
- GitHub push時に private email protection で拒否される場合は、author email を noreply に修正する。

## 8. 主要ファイル

| ファイル | 役割 |
|---|---|
| `streamlit_app.py` | メインUI |
| `streamlit_audit_ui.py` | マスク判断履歴、顧客プロファイル等の補助UI |
| `secure_review/reviewer.py` | Gemini/Gemma呼び出し、プロンプト、JSONパース、深堀 |
| `secure_review/rubric.py` | 文書種別プロファイル、章抽出、レビュー基準 |
| `secure_review/structure_check.py` | 文書構成チェック |
| `secure_review/sanitizer.py` | regexベース匿名化 |
| `secure_review/run_masking_pipeline.py` | NER/R-Mを含むマスク処理パイプライン |
| `secure_review/sensitivity.py` | ローカル機密度判定 |
| `secure_review/token_budget.py` | 送信前トークン概算 |
| `secure_review/network_config.py` | Cisco/Fortinet Config概要解析 |
| `secure_review/network_diagram.py` | OCR文字列からの構成図サマリ |
| `secure_review/extractor.py` | PDF/DOCX/XLSX/PPTX/画像抽出 |
| `docs/mock_operation_manual.md` | 上司・管理者テスト用の操作マニュアル |
| `docs/review_methodology.md` | 深堀レビュー方針 |
| `docs/network_config_review_scope.md` | Config/構成図レビュー方針 |
| `docs/guideline_externalization_policy.md` | レビュー基準外部化方針 |

## 9. 上司・管理者テストで見てほしい点

- 初見で操作の順番が分かるか。
- 匿名化、送信前確認、外部LLM送信の不安が残らないか。
- 文書構成チェックの分類が分かりやすいか。
- 章別概要レビューと深堀候補が矛盾して見えないか。
- 複数PDFを1つのレビュー対象として扱う説明が自然か。
- トークン消費、待ち時間、分割callの説明が十分か。
- Review Result と文書構成チェックのカード表示が判断しやすいか。
- 実業務文書を投入した場合、指摘が厳しすぎないか、浅すぎないか。

## 10. 次のチャット / コピー先作業の開始プロンプト例

```text
前回の続きです。
現行モックは上司・管理者テスト中のため、コピー先 GitHub リポジトリで作業を継続します。

まず docs/handoff.md を読んで、現在の到達点、運用方針、残課題を把握してください。
作業前に、今回の作業対象が「上司テストの指摘対応」「コピー先リポジトリ整備」
「UI改善」「レビュー精度改善」のどれかを1-2行で整理してから進めてください。

APIキーやSecretsはチャットに貼りません。
```

## 11. 作業時の注意

- コード変更後は、最低限 `python -m py_compile streamlit_app.py` と `python -m unittest` を確認する。
- UIだけの変更でも、Streamlit Cloud Reboot 後にブラウザをハードリフレッシュして確認する。
- 既存テスト中の現行モックを壊さないため、今後の大きな変更はコピー先 GitHub リポジトリで行う。
- `.env`、Secrets、レビューJSONログ、業務文書はコミットしない。
- 操作マニュアルに影響するUI変更を行ったら、`docs/mock_operation_manual.md` も更新する。
