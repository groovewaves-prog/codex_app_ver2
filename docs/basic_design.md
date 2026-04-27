# Secure Network Review 基本設計書

Last updated: 2026-04-24 (post R1–R4 hardening + 研究知見反映 + テスト件数反映)

## 1. 文書情報

- 文書名: Secure Network Review 基本設計書
- 対象システム: ネットワーク設計書 / Config / 運用資料 AI レビュー基盤
- 現在フェーズ: PoC (R1–R4 セキュリティ境界対応済み)
- 更新方針: 設計変更時は本書と `docs/traceability.md` を同時更新する

## 2. 背景

ネットワーク設計書、コンフィグ、運用資料を AI でレビューしたい。
ただし、認証情報、IP アドレス、ホスト名、メールアドレス、コミュニティ文字列など、
および顧客名・案件名・拠点名などの識別可能な業務文脈をそのまま外部へ送信しない
ことが前提である。

PoC 段階では費用を発生させたくないため、当面は無償範囲で構築できる構成を採用する。

## 3. システム化方針

### 3.1 基本方針

- UI は Web ベースとする
- AI レビュー対象は匿名化済みデータに限定する
- 原文と匿名化後データを分離して扱う
- LLM 呼び出し部分は抽象化し、将来のモデル差替えを可能にする
- ローカル側とクラウド側のネットワーク境界を明示的に分離し、ローカル限定の
  エンドポイントにはループバックアドレスのみを許可する

### 3.2 暫定方針 (現在適用中)

- UI は Streamlit を採用 (`streamlit_app.py`)
- 外部 LLM には Gemini free tier (`gemini-2.0-flash`) を暫定利用
- 外部 LLM へ送るのは匿名化済みデータのみ
- 匿名化はローカル正規表現 + ローカル LLM (Ollama `gemma3:12b`) の 2 段構え
- 社外送信可否の判定はローカル heuristic または local LLM gate
- `mask_and_continue` 判定時は操作者の明示的確認なしに外部送信しない

### 3.3 将来方針

- UI は Streamlit のまま継続利用する
- LLM は Gemma 4 自己配備へ移行する
- 重い推論処理は Google Cloud 側で実行する

## 4. 対象範囲

### 4.1 入力対象

現在対応している形式:

- テキスト、Markdown、ログ
- ソースコード (Python, PowerShell, Shell, VBA, SQL 等)
- JSON / YAML / CSV / XML / HTML
- DOCX
- XLSX (2026-04 時点で実装済み)
- PPTX (2026-04 時点で実装済み)
- PDF (`pypdf` で本文抽出、`pdftotext` フォールバック、どちらも無ければ警告つきプレースホルダ)
- 画像 (Tesseract がインストールされている場合に OCR)

archive-bomb 防御のため、DOCX/XLSX/PPTX の展開サイズは `MAX_UNCOMPRESSED_ARCHIVE_BYTES`
(既定 200 MiB) を超えると拒否する。PDF は `MAX_PDF_PAGES` (既定 300 ページ) で打ち切る。

### 4.2 出力対象

- レビュー要約
- 指摘一覧（severity と source_document 付き）
- 推奨対応
- 匿名化前後の抜粋プレビュー
- 処理警告

## 5. 全体アーキテクチャ

### 5.1 論理構成

1. UI (Streamlit、補助的に static HTML)
2. Backend API (`secure_review/app.py`: `/api/preview` と `/api/review`)
3. Document Extractor (`secure_review/extractor.py`)
4. Local Sanitizer (`secure_review/sanitizer.py`: regex + optional local LLM)
5. Local Sensitivity Gate (`secure_review/sensitivity.py`: heuristic または local LLM)
6. Network Boundary Guard (`secure_review/network_guard.py`: R1/R3 の実装核)
7. External Review Orchestrator (`secure_review/reviewer.py`)
8. Review Rubric (`secure_review/rubric.py`: 文書プロファイル別の観点定義)

### 5.2 ネットワーク境界

本システムには 2 つの明示的なネットワーク境界がある:

1. **ローカル境界**: ローカル sanitizer / sensitivity gate は原文を受け取るため、
   エンドポイント URL はループバック (`127.0.0.1`, `::1`, `localhost`) のみ許可。
   `network_guard.validate_local_url` が起動時とリクエスト毎に検証する。
2. **外部境界**: 外部 LLM provider には匿名化済みテキストのみ送信。`mask_and_continue`
   判定時は操作者の明示的確認なしに越境しない。`block` 判定や高アウトバウンドリスク
   時は拒否。

詳細は `docs/security_boundaries.md` を参照。

## 6. 機能設計

### 6.1 ファイル取込

- 複数ファイルのアップロード
- ファイル名と内容の保持
- サイズ/件数上限 (`MAX_REQUEST_BYTES`、既定 64 MiB)
- 未対応形式に対する警告表示

### 6.2 文書抽出

- JSON 整形
- CSV の行列表現化
- HTML / XML のタグ除去
- DOCX / XLSX / PPTX の本文抽出 (画像埋め込みは OCR フック付き)
- PDF 本文抽出 (`pypdf` 優先、`pdftotext` CLI フォールバック)
- 画像 OCR (Tesseract 利用可能時)

### 6.3 匿名化 (2 段構え)

段階 1 — regex sanitizer:

- password / secret / community / token / apikey
- IPv4 / IPv6 (圧縮表記を含む)
- email / MAC / hostname
- 顧客名 / 案件名 / 担当者 / チケット番号 / 拠点名 / URL
- 社外秘などの機密ラベル検出（high risk 扱い）
- 法人識別子（株式会社 〜、Inc./Ltd. 等）

段階 2 — local LLM enhancer (optional):

- Ollama `gemma3:12b` など、ループバック限定のエンドポイントでさらに匿名化
- 承認済みプレースホルダ (SECRET/IPV4/IPV6/EMAIL/MAC/HOSTNAME/COMPANY/PROJECT/TICKET/PERSON/URL/SITE/DEVICE/GENERIC_IDENTIFIER) のみ使用
- 未承認プレースホルダ (`<REDACTED>`, `***` 等) を検出した場合は finding として記録
- LLM 不通時は regex-only サニタイズを保持 (fail-safe)

### 6.4 社外送信可否判定 (local sensitivity gate)

3 段階判定:

- `safe`: 外部送信可
- `mask_and_continue`: 操作者の明示的確認が必要 (UI でチェックボックス、API で `confirmMaskAndContinue` または `documentConfirmations`)
- `block`: 外部送信不可

長文で先頭しか評価できなかった場合は `safe` を `mask_and_continue` へ降格。
gate 不通時も同様に `mask_and_continue` にフォールバック。

### 6.5 AI レビュー

- 匿名化済みデータからプロンプトを生成する
- rubric (`rubric.py`) に従って文書プロファイルを判定 (design / change_runbook / operations_runbook / source_code)
- 指摘を severity 付きで返す
- Provider:
  - `MockReviewProvider` (ローカル規則、ネットワーク不要)
  - `HttpLlmReviewProvider` (OpenAI 互換エンドポイント)
  - `GeminiHostedGemmaProvider` (Gemma 4 / Gemini API)
  - `GeminiFreeTierProvider` (`gemini-2.0-flash`、429/5xx リトライ、クォータ検出)

### 6.6 レビュー rubric (文書プロファイル別観点)

各プロファイルに mandatory_checks と evaluation_axes を定義。主な要素:

- **design** (基本設計書、詳細設計書): 完全性 / 整合性 / セキュリティ / 運用保守性 / 試験妥当性
- **change_runbook** (変更・切替・構築手順書): 上記 + **変更影響・切戻し** (可逆/不可逆分類、go/no-go 判定ポイント、補償処置) + **Post-Implementation Review** (作業結果記録、SLA 影響確認、事後レビュー)
- **operations_runbook** (保守・運用・障害対応手順書): 上記 + **作業後運用ハンドオーバー** (SLO/SLA、監視→ランブックのリンク、オーナーシップ/RACI、エスカレーション、ハイパーケア)
- **source_code**: 正確性 / セキュリティ / 保守性 / 運用性 / 試験容易性

**WBS**: `change_runbook` と `operations_runbook` に **optional check** として存在。資料内に WBS があれば本文との整合性を確認、無くても指摘しない (Machado 2008 / ITIL 4 の実務と整合)。

### 6.7 結果表示

- 処理概要
- 指摘一覧 (severity・source・recommendation・詳細)
- 匿名化プレビュー
- 警告
- セキュリティメッセージ (ガード状況、トークン使用量、判定根拠)

## 7. 暫定 LLM 構成

### 7.1 採用理由

- PoC 段階で無償利用を優先するため
- Gemini free tier (`gemini-2.0-flash`) が free tier 枠に実際に適合するため
- UI とレビュー体験を先に固めるため
- 後から Gemma 4 に差し替えやすい構造を取るため

### 7.2 現在の Gemini 利用

- `gemini-2.0-flash` を既定モデルに採用
- 429 / 5xx エラーは 1 回だけリトライ、クォータエラーは即座に人間向けメッセージに変換
- 空応答時は `finish_reason` を表示して原因を開示

### 7.3 将来移行

- `GeminiFreeTierProvider` を `Gemma4Provider` (自己配備) に置換可能な構造
- UI と parser と sanitizer はそのまま再利用

## 8. PDF / Excel 対応方針

両形式とも実装済み。方針は以下の通り。

### 8.1 PDF

- 文字主体 PDF: `pypdf` でページ単位に抽出
- 画像主体 PDF: Tesseract OCR を介してテキスト化 (現時点では PDF 自体の OCR は未、画像抽出のみ)
- 混在 PDF: 両方を併用
- `MAX_PDF_PAGES` による上限
- 暗号化された PDF は警告を残してスキップ

### 8.2 Excel

- シート名の取得
- セル値の共有文字列解決
- 画像埋め込みがあれば OCR フック
- 全体サイズは archive-bomb 防御の対象

## 9. 非機能設計

### 9.1 セキュリティ

- 原文をそのまま外部送信しない
- 匿名化後データのみ LLM に送る
- 置換マップは外部送信しない
- ローカル限定エンドポイントはループバックのみ (R1)
- `mask_and_continue` は明示的確認がなければ外部送信しない (R2)
- 上流エラーの body はクライアントに露出しない (R3)
- LLM 応答のパース失敗時は安全側に倒す (R4、空文字フォールバック)

### 9.2 拡張性

- LLM provider を差替え可能にする
- Parser を形式ごとに追加できる構造
- UI と Backend を分離可能

### 9.3 運用性

- 警告を UI 表示
- `scripts/local_ollama_precheck.py` による事前疎通確認 (URL 検証 + 合成リクエスト + 任意の実ファイルでのパイプライン確認)
- `MAX_REQUEST_BYTES`、`MAX_UNCOMPRESSED_ARCHIVE_BYTES`、`MAX_PDF_PAGES` で入力量を制限

### 9.4 コスト管理

- PoC は無償利用を前提とする
- GPU 前提構成は採用しない
- 有償サービスへの移行は別途判断とする

## 10. 採用技術

### 10.1 現在

- Python 3.10+
- Streamlit (UI)
- pypdf (PDF 抽出)
- Tesseract (画像 OCR、optional)
- Python 標準ライブラリのみ (Backend API、ネットワーク境界)

### 10.2 将来

- FastAPI もしくは同等の Backend API
- Google Cloud
- Gemma 4 self-hosted inference

## 11. データフロー

1. ユーザーがファイルをアップロードする
2. Backend がファイル内容を受け取る
3. Extractor が形式別にテキスト化する (PDF / Excel / PPTX / DOCX / 画像OCR 含む)
4. 正規表現 sanitizer が機密情報を匿名化する
5. (オプション) ローカル LLM sanitizer がさらに匿名化する
6. Local sensitivity gate が safe/mask_and_continue/block を判定する
7. 操作者が preview を確認し、`mask_and_continue` を確認する
8. Reviewer が匿名化済みテキストでレビューする
9. UI にレビュー結果を表示する

## 12. 今後の開発段階

### 12.1 完了 (Phase 1 + R1-R4 hardening)

- MVP 安定化、Streamlit UI、Gemini free tier provider
- PDF 抽出、XLSX/PPTX 抽出、画像 OCR フック
- R1-R4 セキュリティ境界対応、49 → 63 件のテスト整備
- 研究知見 (Fagan inspection / PBR / ITIL / Google SRE PRR / AWS ORR) を rubric に反映

### 12.2 Phase 2

- ベンダー別レビュー観点追加 (Cisco / Juniper 等)
- 結果保存 / 履歴管理
- 監査ログ追加

### 12.3 Phase 3

- Gemma 4 自己配備へ移行
- Google Cloud 配備
- 認証、監査ログ、保存暗号化、権限制御

## 13. 設計とコードの管理方針

- 設計の入口: `docs/basic_design.md` (本書)
- セキュリティ境界仕様: `docs/security_boundaries.md`
- コードとの対応: `docs/traceability.md`
- 次チャットへの引き継ぎ: `docs/handoff.md`
- 運用ポリシー: `docs/operations_policy.md`
- 仕様変更時は関連文書を同時更新する
