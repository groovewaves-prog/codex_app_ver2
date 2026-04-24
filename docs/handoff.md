# Handoff

Last updated: 2026-04-24 (V3 verification materials + GitHub push prep)

## 0. 次のチャットを開く方へ（最重要）

このファイルは、**次のチャット開始時に Claude にこれ 1 本渡せば現状復元できる**
ことを目的に書かれています。まずは次の節（0.1–0.3）を読んでください。

### 0.1 次のチャットで実施する作業

GitHub に push して PR を作成する作業です。具体的には:

1. GitHub MCP コネクタ接続済みの状態で開始（contents write 権限あり）
2. `secure_review_hardening.zip` を展開し、ユーザーのローカル repo と `git diff` で差分確認
3. ブランチ作成（例: `hardening/r1-r4-and-streamlit-and-template-alignment`）
4. コミット（論理単位で分ける / 1 コミットにまとめるかはユーザー確認）
5. push して PR 作成（PR 本文は `CHANGES.md` をベースに）

### 0.2 次のチャットの開始プロンプト（コピペ用）

```
GitHub MCP コネクタが接続済みの新チャットです。
前回の Claude と次の作業を実施しました（詳細は添付の handoff.md と CHANGES.md）:

- secure_review ツールの R1-R4 セキュリティ境界対応
- Streamlit UI 新設
- Gemini free tier 安定化
- PDF 抽出対応
- レビュー rubric の研究知見反映 (Fagan / PBR / ITIL / SRE PRR / AWS ORR)
- 作業計画書テンプレート整合
- テスト 59 件全通過

成果物は `secure_review_hardening.zip` にまとめてあります。
baseline commit は `eaf605a` です。

今回のチャットでは以下を実施します:
1. zip を展開して git diff で baseline との差分を確認
2. ブランチを作成してコミット
3. GitHub に push して PR 作成

まず私のリポジトリ <org>/<repo> にアクセスできるか確認してから、
現在の main ブランチと baseline commit の関係を教えてください。
```

ユーザーは zip の中身と `docs/handoff.md`・`CHANGES.md` を添付して新チャットを
開きます。

### 0.3 合意済みレビュー観点（review-scoping skill）

次チャットでも最初の作業前に 1–2 行で観点合意してから進めてください。
今回は GitHub 操作なので、恐らく:

- **整合性レビュー**: 成果物の内容がユーザーの repo と衝突しないか
- **ユーザー指示反映レビュー**: PR ブランチ命名・コミット粒度など、ユーザーの好みを確認

---

## 1. 現状サマリ

### 1.1 バンドル

- `secure_review_hardening.zip` (88 KB 前後、34 ファイル)
- baseline commit: `eaf605a`
- 配置先（ユーザー環境）: `C:\Users\S023649\OneDrive - KDDI株式会社\SecurePC\Documents\codex\`

### 1.2 テスト

59 件全通過:

```
python -m unittest discover tests
```

### 1.3 主要成果物

- `secure_review/network_guard.py` 新規（R1/R3 の核）
- `secure_review/sanitizer.py`, `sensitivity.py`, `reviewer.py`, `app.py` 更新（R1-R4）
- `secure_review/extractor.py` 更新（PDF + zip bomb 対策）
- `secure_review/rubric.py` 大幅強化（研究知見 + 作業計画書テンプレート反映）
- `streamlit_app.py` 新規
- `docs/security_boundaries.md` 新規
- `docs/basic_design.md`, `handoff.md`, `traceability.md`, `operations_policy.md` 更新
- `docs/v3_streamlit_verification.md` 新規（実データ検証手順）
- `docs/local_ollama_verification.md` 新 precheck CLI に合わせて全面改訂
- `README.md`, `.env.example` 更新
- `tests/test_network_guard.py`, `tests/test_app.py` 新規
- `scripts/local_ollama_precheck.py` リライト（`--input-file` 復元済み）

---

## 2. 実施した作業の経緯（時系列）

1. 同僚からのレビュー依頼書を受けてコードレビューを実施、重大 4 件 (R1-R4) + 中/低 指摘を検出
2. ユーザー判断で「R1-R4 全対応後に機能追加」「UI は Streamlit に移行」「Gemini free tier 安定化」「PDF 抽出」「docs 整合」を優先
3. `network_guard.py` 中心に R1-R4 対応、55 テスト全通過確認
4. 文書レビュー研究の調査を実施（Fagan 1976, Basili PBR 1996, Brykczynski 1999 checklist survey, Machado 2008 rollback, ITIL 4, Google SRE PRR, AWS ORR）
5. ユーザー要望「作業後運用内容、タイムチャート、WBS（強要しない）」を rubric に反映
6. セルフレビューで整合性問題 5 件、ユーザー指示反映問題 3 件を検出、全て修正
7. review-scoping skill を導入し、以降は作業前に観点合意する運用
8. 作業計画書テンプレート (.pptx) を受領、rubric に整合化 + 既存バグ 2 件同時修正
9. V3 実データ検証の手順書作成、README/.env.example 整備

---

## 3. 主要機能の説明

### 3.1 primary UI

Streamlit (`streamlit_app.py`)。4 ステップ強制:

1. Upload: 複数ファイル受付（base64 で送信）
2. Sanitize & preview: ローカル処理のみ、外部呼び出しなし
3. Confirm: `mask_and_continue` 文書をチェックで確認
4. Send for review: 外部 LLM に送信

補助 UI として `server.py` 経由の HTTP API (`/api/preview`, `/api/review`) も維持。

### 3.2 R1: ループバック境界

`secure_review/network_guard.validate_local_url` が:

- 受付: `127.0.0.1`, `::1`, `localhost`（IPv6 アドレス含む）
- 拒否: 他のホスト名（DNS が loopback に向いていても）、RFC1918 私設 IP、非 http(s) スキーム

`LOCAL_SANITIZER_API_URL` と `LOCAL_SENSITIVITY_API_URL` について、起動時とリクエスト毎に検証。

### 3.3 R2: 確認ゲート

`MASK_AND_CONTINUE_REQUIRE_CONFIRM=true`（既定）で:

- HTTP: mask_and_continue 文書があると `/api/review` が HTTP 409 + `status: "confirmation_required"` を返す
- Streamlit: 当該文書のチェックボックスが全てオンになるまで Send ボタン無効

### 3.4 R3: エラー遮断

`network_guard.post_json_safely` が:

- HTTPError の response body をログに redacted で記録（240 文字超の行は切り詰め）
- 呼び出し元には `UpstreamHttpError(f"... returned HTTP {code}. See server logs for details.")` のみ渡す

`app.py` の `do_POST` 全体 try/except で、未知例外は `request_id` 付き汎用メッセージに。

### 3.5 R4: パース安全フォールバック

`_extract_openai_like_text` と `_extract_gemini_text` は失敗時に**空文字を返す**。
呼び出し元は空文字を明示的な失敗と扱い、regex-only sanitize を維持するなどで安全側に。

### 3.6 Gemini free tier

`GeminiFreeTierProvider` (`gemini-2.0-flash` 既定):

- 429 / 5xx は `time.sleep(2.0)` で 1 回リトライ
- `RESOURCE_EXHAUSTED` / "rate limit" 等のキーワードはクォータ判定、リトライせず人間向けメッセージ化
- 空応答時は `finishReason` を表示して原因開示

### 3.7 rubric 強化（研究 + テンプレート反映）

| 軸 / チェック | 根拠 |
|---|---|
| `change_runbook.change_risk` に可逆/不可逆分類、go/no-go 判定、リスクレベル+承認、予測できない有事 | ITIL 4, Machado 2008, 社内テンプレート |
| `change_runbook.post_implementation_review` (新設) | ITIL 4 PIR + 社内テンプレートの変更履歴スライド |
| `change_runbook.operability` に役割分担、3 層情報共有 | 社内テンプレートの体制図スライド |
| `operations_runbook.operational_handover` (新設) | Google SRE PRR, AWS ORR |
| `OPTIONAL_CHECKS.wbs_consistency_if_present` | ユーザー指示「あれば確認、なければ強要しない」 |
| `completeness` に環境区別（本番/検証） | 社内テンプレート |

MockReviewProvider にも対応ヒューリスティック:
`_has_environment_distinction`, `_has_risk_level_with_approval`,
`_has_document_update_list`, `_has_irreversible_operation_signals`,
`_has_rollback_signals`, `_has_operational_handover_signals`.

### 3.8 PDF 抽出

`secure_review/extractor._extract_pdf`:
- `pypdf` 優先（`pip install pypdf` で有効化、requirements.txt に含む）
- 未インストール時は `pdftotext` CLI（Poppler）フォールバック
- どちらも無い場合は警告つきプレースホルダを返してパイプラインを継続
- `MAX_PDF_PAGES` (既定 300) で上限
- 暗号化 PDF は警告つきでスキップ

### 3.9 zip bomb / 上限防御

`_open_archive_safely` で DOCX/XLSX/PPTX の展開前に圧縮率を検証、
`MAX_UNCOMPRESSED_ARCHIVE_BYTES` (既定 200 MiB) 超過時は `ValueError` で拒否。
`MAX_REQUEST_BYTES` (既定 64 MiB) で HTTP request body も制限。

---

## 4. 環境変数一覧

### 4.1 Provider

| 変数 | 既定 | 備考 |
|---|---|---|
| `REVIEW_PROVIDER` | `mock` | `mock` / `http` / `gemma` / `gemini-free` |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | — | Gemini 系 provider 使用時必須 |
| `GEMINI_MODEL` | `gemini-2.0-flash` (gemini-free), `gemma-4-31b-it` (gemma) | |
| `GEMINI_MAX_OUTPUT_TOKENS` | `2048` | |
| `GEMINI_TEMPERATURE` | `0.2` | |
| `LLM_API_URL` / `LLM_API_KEY` / `LLM_MODEL` | — | `REVIEW_PROVIDER=http` 用 |

### 4.2 ローカル sanitizer（ループバック限定）

| 変数 | 既定 |
|---|---|
| `LOCAL_SANITIZER_PROVIDER` | `none` (`none` / `http` / `ollama`) |
| `LOCAL_SANITIZER_API_URL` | — (必須時はループバック必須) |
| `LOCAL_SANITIZER_MODEL` | — |
| `LOCAL_SANITIZER_API_KEY` | — |
| `LOCAL_SANITIZER_INPUT_CHARS` | `12000` |

### 4.3 ローカル sensitivity gate（ループバック限定）

| 変数 | 既定 |
|---|---|
| `LOCAL_SENSITIVITY_PROVIDER` | `heuristic` (`heuristic` / `http` / `ollama`) |
| `LOCAL_SENSITIVITY_API_URL` | — (必須時はループバック必須) |
| `LOCAL_SENSITIVITY_MODEL` | — |
| `LOCAL_SENSITIVITY_API_KEY` | — |
| `LOCAL_SENSITIVITY_INPUT_CHARS` | `8000` |

### 4.4 安全

| 変数 | 既定 | 備考 |
|---|---|---|
| `MASK_AND_CONTINUE_REQUIRE_CONFIRM` | `true` | 本番は true 固定 |
| `MAX_REQUEST_BYTES` | `67108864` (64 MiB) | |
| `MAX_UNCOMPRESSED_ARCHIVE_BYTES` | `209715200` (200 MiB) | |
| `MAX_PDF_PAGES` | `300` | |
| `SANITIZED_PREVIEW_CHARS` | `1200` | UI プレビュー長 |
| `OUTBOUND_TEXT_CHARS` | `12000` | 外部送信本体長 |

---

## 5. ユーザー合意済み方針（忘れない）

1. **WBS は強要しない** — あれば本文との整合を確認、無ければ指摘しない。`rubric.OPTIONAL_CHECKS` に反映済み
2. **PoC は無償構成** — Gemini free tier、Gemma 4 自己配備は将来フェーズ
3. **外部送信は匿名化済みテキストのみ** — R1-R4 境界で強制
4. **ローカル sanitizer / sensitivity は loopback 必須** — 非 loopback は起動時拒否
5. **作業計画書テンプレート** — KDDI 当部門のテンプレ。rubric が整合
6. **review-scoping skill** — 作業前に 1-2 行で観点合意する運用。**2026-04-24 に skill v3 へ更新済み**。主な更新内容:
   - (v2 追加) 整合性レビュー時に単一ファイル完結に陥らず、固有名詞/識別子/テスト件数などをプロジェクト横断で `grep` 確認することが必須化
   - (v3 追加) **目次突合法 (TOC Cross-check Method)** — 既存ドキュメント改訂時は、冒頭から主観的に読み直すのではなく、旧版/新版の目次を機械的に全列挙して突合表で確認する 4 ステップ手順が必須化

   **次チャットで GitHub push する際の必須手順**:
   - `git diff eaf605a -- docs/basic_design.md` などで、改訂した docs 6 本（basic_design.md / handoff.md / traceability.md / operations_policy.md / local_ollama_verification.md / README.md）について、旧版から新版への節の保持状況を目次突合する
   - 特に `docs/basic_design.md` について、本チャットで未検証の項目:
     - 旧 5.2「暫定配備構成」の内容が新版のどこに移動したか
     - 旧 10.2「PoC 暫定」の内容が新版のどこに移動したか
   - 欠落が見つかれば、情報を復元するか「意図的な分割」として改訂ポイントに明記する

---

## 6. 残課題

### 6.1 初回レビューで挙げた未対応（M/L 級）

| # | 内容 | 優先 |
|---|---|---|
| M1 | 裸ホスト名（`tokyo-rtr-01` 等）の検出強化 | 中 |
| L1 | findings / reasons の重複ノイズ整理 | 低 |
| L2 | provider 名の表記ゆれ統一 (`gemma4` / `gemma-4-gemini-api`) | 低 |
| L5 | `env_loader._strip_quotes` のエスケープシーケンス対応 | 低 |
| L6 | `_has_unprotected_command_execution` の `exec(` が SQL `EXEC` に過剰マッチ | 低 |
| L7 | `HeuristicSensitivityClassifier` が sanitizer findings を再評価している冗長性 | 低 |

### 6.2 現場検証（ユーザー環境でしか確認できない）

| # | 内容 | 備考 |
|---|---|---|
| V1 | 実 Ollama 環境での `local_ollama_precheck.py` 実行 | |
| V2 | 実 Gemini free tier でのクォータ遭遇時の挙動確認 | |
| **V3** | **Streamlit UI を実データで一巡** | **手順書は `docs/v3_streamlit_verification.md`。今回これを次に実施** |
| V4 | 作業計画書実データを投入して rubric の指摘精度確認 | mock と本番 LLM の両方 |

### 6.3 機能拡張候補

| # | 内容 |
|---|---|
| E1 | PBR 多視点化（同一文書を複数視点で評価） |
| E2 | 監査ログ永続化 |
| E3 | HTTP API 前段の認証 proxy 例 |
| E4 | レビュー履歴管理 |

### 6.4 将来フェーズ（basic_design.md 記載）

- Gemma 4 自己配備
- Google Cloud 配備
- 暗号化、権限制御

---

## 7. ファイル構成（成果物）

```
secure_review_v2/
├── CHANGES.md
├── README.md
├── .env.example
├── requirements.txt
├── server.py                        # HTTP API 起動スクリプト（未変更、補助的）
├── streamlit_app.py                 # 主 UI
├── docs/
│   ├── basic_design.md              # 基本設計書（更新済み）
│   ├── handoff.md                   # 本ファイル
│   ├── local_ollama_verification.md # ローカル Ollama 検証手順
│   ├── operations_policy.md         # 運用ポリシー
│   ├── security_boundaries.md       # R1-R4 境界仕様（新規）
│   ├── traceability.md              # 設計-コード対応表
│   └── v3_streamlit_verification.md # V3 実データ検証手順（新規）
├── scripts/
│   └── local_ollama_precheck.py     # --input-file 対応
├── secure_review/
│   ├── __init__.py
│   ├── app.py                       # HTTP API ハンドラ
│   ├── env_loader.py
│   ├── extractor.py                 # PDF 含む
│   ├── models.py
│   ├── network_guard.py             # R1/R3 中核（新規）
│   ├── reviewer.py                  # Gemini free tier + mock heuristic
│   ├── rubric.py                    # 研究 + テンプレート反映
│   ├── sanitizer.py
│   └── sensitivity.py
├── static/
│   └── index.html                   # Streamlit 移行案内
└── tests/
    ├── __init__.py
    ├── test_app.py                  # 新規
    ├── test_env_loader.py
    ├── test_network_guard.py        # 新規
    ├── test_reviewer.py             # 研究 + テンプレート反映のテスト含む
    ├── test_sanitizer.py
    └── test_sensitivity.py
```

---

## 8. 既知の制約と注意事項

- HTTP API 前段に認証が無いため、loopback バインド（既定）か auth proxy 背後でのみ運用
- 監査ログ永続化なし、必要なら stdout を systemd-journald 等で保存
- ローカル LLM 出力は untrusted として扱う（regex sanitizer が常に再実行）
- 画像 OCR は Tesseract 必須（無ければ警告つきプレースホルダ）
- PDF OCR は未対応（スキャン PDF は本文抽出されない）
- 現 `docs/basic_design.md` は 2026-04-23 時点版。以降の変更時は同時更新すること

---

## 9. V3 完了後の状態確認

V3 を実施したら、以下のセクションに結果を追記してください:

### 9.1 V3 実施結果

- [ ] 実施日:
- [ ] 実施者:
- [ ] 全確認項目クリア: yes / no
- [ ] 発見された問題:
- [ ] 対応完了: yes / no / 次チャットで対応

### 9.2 V3 で見つかった要改善点

（あれば記載）

---

## 10. 最後に — 次チャットで最初にすること

1. ユーザーから GitHub repo の URL とブランチ命名方針を確認
2. GitHub MCP コネクタでアクセス可能か確認
3. baseline commit `eaf605a` が現在の main から乖離していないか確認
4. 乖離があればマージ戦略を相談
5. ブランチ作成 → 差分適用 → コミット → push → PR 作成
6. PR 本文には `CHANGES.md` の内容を骨子として、日本語サマリを添える
