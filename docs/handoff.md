# Handoff

Last updated: 2026-04-29 (R-H 命名規則 regex / R-B/R-C モデル由来サマリ表示化 / R-J ラベルパターンによるプレースホルダ再マスク防止 すべて main へマージ済み)

## 0. 次のチャットを開く方へ（最重要）

このファイルは、**次のチャット開始時に Claude にこれ 1 本渡せば現状復元できる**
ことを目的に書かれています。まずは次の節（0.1–0.4）を読んでください。

### 0.1 現在の到達点（2026-04-29 現在）

**ツールは Streamlit Community Cloud 上で稼働中です**。

- URL: `https://codexapp-edwxxq7jek7mrtyr8hwtbp.streamlit.app`
- リポジトリ: `https://github.com/groovewaves-prog/codex_app`
- 最新マージコミット: `9b7ee32` (PR #8 = R-B/R-C/R-J マージ済み、PR #7 = R-H もその前にマージ済み)
- UI: 完全日本語化済み（タイトル「セキュアレビュー」、すべての画面要素が日本語）
- 動作確認済み: `test1.txt`（テスト用手順書）で Gemma 4 が 7 件の高品質な日本語指摘を返すことを確認 (2026-04-27)
- **2026-04-29 追加分** (PR #7 / #8 でマージ済み):
  - **R-H** (`sanitizer.py`, PR #7): 社内命名規則 regex `_build_internal_hostname_pattern` を追加。機器種別語彙ベースで裸ホスト名（`tokyo-rtr-01` 等）を検出しつつ過検出を抑制。テスト 4 件追加。
  - **R-B / R-C** (`reviewer.py`, `models.py`, `streamlit_app.py`, PR #8): レビュー結果のサマリをモデルの応答 JSON から取得して UI に表示。空レスポンス時は固定の日本語フォールバック文を表示。`ReviewResult.model` フィールドを追加してモデル識別子（例: `gemma-4-31b-it`）を provider slug と分離して UI に表示。
  - **R-J** (`sanitizer.py`, PR #8): ラベル系パターン（`person` / `company` / `project` / `ticket`）が既存プレースホルダ（`[EMAIL_001]` 等）を再マスクしてしまう問題を修正。`_PLACEHOLDER_REUSE_PATTERN` を導入し `_replace_pattern` で早期 return。
  - テスト件数: 67 → **76 件**（reviewer に R-B/R-C で 6 件、sanitizer に R-J で 3 件追加）。`python -m unittest discover tests` で全件通過確認済み。

**現在の構成**:

| 段階 | 実装 |
|---|---|
| 文書抽出 | `secure_review/extractor.py`（pypdf, docx, xlsx, pptx 対応） |
| 一次マスキング | regex ベース（`SensitiveDataSanitizer`、R-H 命名規則 regex / R-J 再マスク防止 反映済み） |
| ローカル LLM 二次マスキング | **使用しない**（`LOCAL_SANITIZER_PROVIDER=none`） |
| 機密度判定 | regex + heuristic ベース（`HeuristicSensitivityClassifier`、`LOCAL_SENSITIVITY_PROVIDER=heuristic`） |
| 確認ゲート | UI のチェックボックス（`MASK_AND_CONTINUE_REQUIRE_CONFIRM=true`） |
| 外部レビュー LLM | Gemini API 経由の Gemma 4 31B（`gemma-4-31b-it`、JSON モード強制、モデル由来サマリ表示）|

### 0.2 次のチャットで予想される作業

優先度順:

1. **実データでの段階的テスト**: ダミー → 匿名化済み資料 → 実データ抜粋 → 実データ全体
2. **小規模な UI 文言改善**: 残った英語混在箇所（後述）の日本語化
3. **不要な Ollama 系コードの整理（オプション）**: 凍結方針なので、関連コード・テストを残すか削除するか判断
4. **長文・大量ファイルでの動作確認**: トークン上限近辺での挙動

### 0.3 次のチャットの開始プロンプト（コピペ用）

```
前回の続きの新チャットです。secure_review ツールは既に Streamlit Cloud で稼働しており、
今回は運用フェーズの作業を行います。

リポジトリ: https://github.com/groovewaves-prog/codex_app
URL: https://codexapp-edwxxq7jek7mrtyr8hwtbp.streamlit.app

handoff.md を読んで現状を把握してください。
特にセクション 0.1（現在の到達点）と 0.2（次の作業候補）を確認した上で、
本日の作業観点を 1-2 行で合意してから進めてください。

私の作業 PC は KDDI 業務 PC、リポジトリは
C:\Users\S023649\OneDrive - KDDI株式会社\SecurePC\Documents\codex
にあります。OneDrive 配下なので git ロック警告が出ることがありますが、n でスキップで実害ありません。

API キーは Claude には開示しないでください。Streamlit Cloud Secrets と私の手元 .env でのみ管理しています。
```

ユーザーは `docs/handoff.md` を添付して新チャットを開きます。

### 0.4 合意済みレビュー観点（review-scoping skill v3）

作業前に 1-2 行で観点合意してから進めてください。
作業内容によって典型的な観点は異なります:

- **実データテスト** → 「整合性レビュー」「ユーザー指示反映レビュー」
- **コード変更** → 「整合性レビュー」「論理レビュー」
- **docs 改訂** → 「目次突合法」「整合性レビュー」

---

## 1. 現状サマリ

### 1.1 リポジトリ最新状態 (2026-04-29 時点)

```
9b7ee32 Merge pull request #8 from groovewaves-prog/feature/r-b-c-j-summary-and-placeholder-reuse
99de7fb feat(reviewer): surface model summary in UI; fix placeholder re-masking (R-B / R-C / R-J)
31ae41a Merge pull request #7 from groovewaves-prog/feature/r-h-internal-hostname-regex
0bb25ff feat(sanitizer): add internal naming-convention regex for bare hostnames (R-H / M1)
71e8e98 Merge pull request #6 (docs cleanup 2026-04-27)
```

直近のマージコミットを取得するには:

```powershell
git pull origin main
git log --oneline -5
```

### 1.2 テスト

**76 件全通過**(`tests/` 全体を `python -m unittest discover tests` で実行した場合)。

```powershell
python -m unittest discover tests
```

※ `python -m unittest tests.test_reviewer tests.test_sensitivity tests.test_sanitizer` のように 3 ファイル指定で実行した場合は 49 件(うち sanitizer は 16 件で R-H で 4 件 + R-J で 3 件追加済み、reviewer は R-B / R-C で 6 件追加済み)。`discover` 実行では `test_app.py` / `test_env_loader.py` / `test_extractor.py` / `test_network_guard.py` を含めた **76 件** が真値。

### 1.3 デプロイ環境

- **Streamlit Community Cloud**: 自動再デプロイ（main ブランチ更新を検知）
- **手元 PC での動作確認は不要**: Streamlit Cloud で直接ブラシュアップする方針

### 1.4 主要成果物

- `streamlit_app.py` — 主 UI（完全日本語化、`st.secrets` ブリッジ実装、生レスポンス表示エクスパンダ、モデル識別子表示）
- `secure_review/network_guard.py` — R1/R3 の核
- `secure_review/sanitizer.py` — R1-R4 + R-H 命名規則 regex + R-J 再マスク防止
- `secure_review/sensitivity.py` — 日本語化済み
- `secure_review/reviewer.py` — JSON モード対応 + R-B/R-C モデル由来サマリ表示
- `secure_review/models.py` — `ReviewResult.raw_response`, `model` フィールド
- `secure_review/app.py` — R1-R4 + JSON モード対応
- `secure_review/extractor.py` — PDF + zip bomb 対策
- `secure_review/rubric.py` — 研究知見 + 作業計画書テンプレート反映
- `docs/security_boundaries.md` — R1-R4 境界仕様
- `docs/v3_streamlit_verification.md` — 実データ検証手順
- `tests/test_network_guard.py`, `tests/test_app.py`

---

## 2. 実施した作業の経緯（時系列）

### 2.1 旧フェーズ（〜2026-04-24）

1. 同僚からのレビュー依頼書を受けてコードレビューを実施、重大 4 件 (R1-R4) + 中/低 指摘を検出
2. ユーザー判断で「R1-R4 全対応後に機能追加」「UI は Streamlit に移行」「Gemini free tier 安定化」「PDF 抽出」「docs 整合」を優先
3. R1-R4 対応、文書レビュー研究調査（Fagan, PBR, ITIL, SRE PRR, AWS ORR）に基づく rubric 強化
4. 作業計画書テンプレート (.pptx) との整合化
5. PR #1 で R1-R4 + 機能追加をマージ (`502ad81`)

### 2.2 新フェーズ（2026-04-25〜2026-04-27）

6. **Lightning AI Studio 試行と却下**:
   - ローカル Ollama (`gemma3:12b`) を Lightning Studio 上で動かす実験を実施
   - SSH (port 22) は KDDI モバイル網 / 社内 LAN ともにブロックされアクセス不可
   - cloudflared HTTPS トンネルは Zscaler で `Black_Low-Risk_List` 判定、ブロック
   - Lightning Web Preview は CORS エラー / 真っ黒画面で UI アクセス不可
   - CLI 経由でツール本体の動作は確認（regex 匿名化と R4 フェイルセーフが正常動作）
   - 一方、CPU での `gemma3:12b` 推論は 60 秒タイムアウト超で実用不可
   - GPU は Free クレジット不足（課金対象になる）のため使用不可
   - **最終判断**: Lightning Studio を削除（アカウントは残存）、ローカル LLM 構想を凍結

7. **方針転換 → Streamlit Cloud + 外部 Gemma 4 構成に確定**:
   - 「Streamlit Cloud は信頼境界の内側」と扱う方針に変更
   - 原文は Streamlit Cloud 環境内に留め、外部送信は匿名化済みのみ
   - PR #2 で `streamlit_app.py` に `st.secrets` → `os.environ` ブリッジを追加してデプロイ可能に
   - Streamlit Cloud に正常デプロイ完了

8. **UI 完全日本語化** (PR #3):
   - すべての画面要素（A: ラベル/ボタン/見出し、B: severity ラベル、C: プロファイル名、D: 判定ステータス、E: 説明文/エラー文）を日本語化
   - 内部値（`safe`, `design`, `high` 等の文字列）は英語のまま維持し、コア互換性を保持
   - タイトルは「Secure Review」→「セキュアレビュー」

9. **Gemini JSON モード対応** (PR #4):
   - 問題発生: Gemma 4 が SYSTEM_PROMPT のスキーマ例 `ISSUE|severity|title|...` を**プレースホルダではなくリテラルとしてコピーして返す**失敗パターン
   - 表示が `[severity] title 推奨対応: recommendation` のようになり、実用不可
   - 対処: SYSTEM_PROMPT を JSON 形式の Few-shot 例付き日本語プロンプトに刷新
   - Gemini API の `generationConfig.responseMimeType="application/json"` + `responseSchema` で構造化出力を強制
   - 新パーサー `_parse_review_response()` で JSON 優先 + パイプ形式フォールバック、プレースホルダ echo を弾く堅牢化
   - `ReviewResult.raw_response` フィールド追加 → ステップ 4 末尾に「LLM の生レスポンス」エクスパンダ
   - `HeuristicSensitivityClassifier` の英語 reasons/actions を全て日本語化
   - 動作確認: `test1.txt` で 7 件の高品質な日本語指摘（高 4/中 2/低 1）が表示されることを確認

### 2.3 仕上げフェーズ（2026-04-28〜2026-04-29）

10. **R-H 社内命名規則 regex** (PR #7, `31ae41a`):
    - 中優先 M1（裸ホスト名 `tokyo-rtr-01` 等の検出強化）に対応
    - `_build_internal_hostname_pattern` を `sanitizer.py` に追加
    - 機器種別語彙（`rtr` / `sw` / `srv` 等）ベースで構築、地理的トークン（`tokyo` / `osaka` 等）と組み合わせ
    - 一般的な英単語と区別するため過検出を抑制
    - テスト 4 件追加で全件通過

11. **R-B/R-C モデル由来サマリ表示 + R-J プレースホルダ再マスク防止** (PR #8, `9b7ee32`):
    - **R-B/R-C**: レビュー結果のサマリをモデル応答の `summary` フィールドから取得し UI に表示。モデルが summary を返さなかった場合は固定の日本語フォールバック文に。`ReviewResult.model` フィールドを追加してモデル識別子（例: `gemma-4-31b-it`）を provider slug と分離して UI に表示
    - **R-J**: 中優先 L8 に対応。ラベル系パターン（`person` / `company` / `project` / `ticket`）が既存プレースホルダ（`[EMAIL_001]` 等）を再マスクしてしまう問題を `_PLACEHOLDER_REUSE_PATTERN` 導入と `_replace_pattern` の早期 return で修正
    - テスト 9 件追加（reviewer 6 / sanitizer 3）で 67 → 76 件全通過

---

## 3. 主要機能の説明

### 3.1 primary UI

Streamlit (`streamlit_app.py`)。4 ステップ強制:

1. **ステップ 1 — 文書アップロード**: 複数ファイル受付（base64 で送信）
2. **ステップ 2 — 匿名化結果プレビュー**: ローカル処理のみ、外部呼び出しなし
3. **ステップ 3 — 確認 & 送信**: `mask_and_continue` 文書をチェックで確認
4. **ステップ 4 — レビュー結果**: 外部 LLM に送信、結果表示、モデル識別子表示、生レスポンス表示エクスパンダ

補助 UI として `server.py` 経由の HTTP API (`/api/preview`, `/api/review`) も維持。

### 3.2 R1: ループバック境界

`secure_review/network_guard.validate_local_url` が:

- 受付: `127.0.0.1`, `::1`, `localhost`（IPv6 アドレス含む）
- 拒否: 他のホスト名（DNS が loopback に向いていても）、RFC1918 私設 IP、非 http(s) スキーム

`LOCAL_SANITIZER_API_URL` と `LOCAL_SENSITIVITY_API_URL` について、起動時とリクエスト毎に検証。

**※ 現在の構成では LOCAL_SANITIZER_PROVIDER=none / LOCAL_SENSITIVITY_PROVIDER=heuristic のため、R1 検証は実質的に発動しない**

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

### 3.6 Gemini Provider（JSON モード対応版、PR #4 / PR #8 後）

`GeminiApiReviewProvider` (`gemma-4-31b-it` 既定):

- `generationConfig.responseMimeType="application/json"` で JSON 出力強制
- `responseSchema` で structure を server-side 強制（severity は enum 制約）
- 429 / 5xx は `time.sleep(2.0)` で 1 回リトライ
- `RESOURCE_EXHAUSTED` / "rate limit" 等のキーワードはクォータ判定、リトライせず人間向けメッセージ化
- 空応答時は `finishReason` を表示して原因開示
- `_parse_review_payload()` で JSON 優先 + プレースホルダ echo 弾き
- **R-B/R-C 反映済み**: モデル応答の `summary` フィールドを UI のサマリに優先表示。空時は日本語フォールバック文（"レビュー結果を取得しました。" 等）を表示
- **R-B 反映済み**: `ReviewResult.model` でモデル識別子（例: `gemma-4-31b-it`）を provider slug と分離して UI 表示
- `ReviewResult.raw_response` で生レスポンスを UI で確認可能

### 3.7 sanitizer（R-H / R-J 反映済み）

`secure_review/sanitizer.py` `SensitiveDataSanitizer`:

- 各種 regex パターンで一次マスキング（メール、電話、IP、社内ホスト名 等）
- **R-H 反映済み**: `_build_internal_hostname_pattern` で社内命名規則（`tokyo-rtr-01` 等）を語彙ベースで検出。一般英単語との混同を抑制
- **R-J 反映済み**: `_PLACEHOLDER_REUSE_PATTERN = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")` を導入。`_replace_pattern` 内でラベル系パターン（`person` / `company` / `project` / `ticket`）が既存プレースホルダ（`[EMAIL_001]` 等）に当たった場合は再マスクをスキップ
- 結果は `SanitizationRecord` に finding として記録

### 3.8 rubric 強化（研究 + テンプレート反映）

| 軸 / チェック | 根拠 |
|---|---|
| `change_runbook.change_risk` に可逆/不可逆分類、go/no-go 判定、リスクレベル+承認、予測できない有事 | ITIL 4, Machado 2008, 社内テンプレート |
| `change_runbook.post_implementation_review` (新設) | ITIL 4 PIR + 社内テンプレートの変更履歴スライド |
| `change_runbook.operability` に役割分担、3 層情報共有 | 社内テンプレートの体制図スライド |
| `operations_runbook.operational_handover` (新設) | Google SRE PRR, AWS ORR |
| `OPTIONAL_CHECKS.wbs_consistency_if_present` | ユーザー指示「あれば確認、なければ強要しない」 |
| `completeness` に環境区別（本番/検証） | 社内テンプレート |

### 3.9 PDF 抽出

`secure_review/extractor._extract_pdf`:
- `pypdf` 優先（`pip install pypdf` で有効化、requirements.txt に含む）
- 未インストール時は `pdftotext` CLI（Poppler）フォールバック
- どちらも無い場合は警告つきプレースホルダを返してパイプラインを継続
- `MAX_PDF_PAGES` (既定 300) で上限
- 暗号化 PDF は警告つきでスキップ

### 3.10 zip bomb / 上限防御

`_open_archive_safely` で DOCX/XLSX/PPTX の展開前に圧縮率を検証、
`MAX_UNCOMPRESSED_ARCHIVE_BYTES` (既定 200 MiB) 超過時は `ValueError` で拒否。
`MAX_REQUEST_BYTES` (既定 64 MiB) で HTTP request body も制限。

---

## 4. 環境変数一覧（現在の Streamlit Cloud Secrets 設定）

### 4.1 Streamlit Cloud で実際に設定中の値

```toml
REVIEW_PROVIDER = "gemma"
GEMMA_MODEL = "gemma-4-31b-it"
GEMINI_API_KEY = "***"  # ユーザー管理、Claude には非開示
LOCAL_SANITIZER_PROVIDER = "none"
LOCAL_SENSITIVITY_PROVIDER = "heuristic"
MASK_AND_CONTINUE_REQUIRE_CONFIRM = "true"
```

### 4.2 Provider 全リスト

| 変数 | 既定 | 備考 |
|---|---|---|
| `REVIEW_PROVIDER` | `mock` | `mock` / `http` / `gemma` / `gemini-free` |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | — | Gemini 系 provider 使用時必須 |
| `GEMINI_MODEL` | `gemini-2.0-flash` (gemini-free), `gemma-4-31b-it` (gemma) | |
| `GEMINI_MAX_OUTPUT_TOKENS` | `2048` | |
| `GEMINI_TEMPERATURE` | `0.2` | |
| `LLM_API_URL` / `LLM_API_KEY` / `LLM_MODEL` | — | `REVIEW_PROVIDER=http` 用 |

### 4.3 ローカル sanitizer（凍結中だが設定値は維持）

| 変数 | 既定 |
|---|---|
| `LOCAL_SANITIZER_PROVIDER` | `none` (`none` / `http` / `ollama`) |
| `LOCAL_SANITIZER_API_URL` | — (必須時はループバック必須) |
| `LOCAL_SANITIZER_MODEL` | — |
| `LOCAL_SANITIZER_API_KEY` | — |
| `LOCAL_SANITIZER_INPUT_CHARS` | `12000` |

### 4.4 ローカル sensitivity gate（heuristic で稼働中）

| 変数 | 既定 |
|---|---|
| `LOCAL_SENSITIVITY_PROVIDER` | `heuristic` (`heuristic` / `http` / `ollama`) |
| `LOCAL_SENSITIVITY_API_URL` | — (必須時はループバック必須) |
| `LOCAL_SENSITIVITY_MODEL` | — |
| `LOCAL_SENSITIVITY_API_KEY` | — |
| `LOCAL_SENSITIVITY_INPUT_CHARS` | `8000` |

### 4.5 安全

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

### 5.1 不変方針（旧フェーズから継続）

1. **WBS は強要しない** — あれば本文との整合を確認、無ければ指摘しない。`rubric.OPTIONAL_CHECKS` に反映済み
2. **PoC は無償構成** — 課金が発生する選択肢は採用しない（Lightning AI Studio GPU を断念した経緯あり）
3. **外部送信は匿名化済みテキストのみ** — R1-R4 境界で強制
4. **ローカル sanitizer / sensitivity は loopback 必須** — 非 loopback は起動時拒否（実装は維持、機能は凍結）
5. **作業計画書テンプレート** — KDDI 当部門のテンプレ。rubric が整合
6. **review-scoping skill v3** — 作業前に 1-2 行で観点合意する運用。目次突合法を含む

### 5.2 新方針（2026-04-27 確定）

7. **Streamlit Community Cloud は信頼境界の内側として扱う** — 原文を環境内に保持してよい
8. **ローカル LLM (Ollama) 機能は凍結** — Free 環境で実用速度に達しない、課金は方針 (2) に反する
9. **手元 PC での動作確認は不要** — Streamlit Cloud で直接ブラシュアップする
10. **API キーを Claude に開示しない** — Streamlit Cloud Secrets と手元 `.env` のみで管理

### 5.3 補足: review-scoping skill v3 のポイント

- (v2 追加) 整合性レビュー時に単一ファイル完結に陥らず、固有名詞/識別子/テスト件数などをプロジェクト横断で `grep` 確認することが必須化
- (v3 追加) **目次突合法 (TOC Cross-check Method)** — 既存ドキュメント改訂時は、冒頭から主観的に読み直すのではなく、旧版/新版の目次を機械的に全列挙して突合表で確認する 4 ステップ手順が必須化

---

## 6. 残課題

### 6.1 即着手候補（次チャットで実施しやすい）

| # | 内容 | 優先 |
|---|---|---|
| **R-A** | `app.py` の findings 接頭辞 `Local sensitivity gate: safe.` を日本語化（例: `ローカル機密度ゲート: 安全.`） | 低 |
| **R-F** | OneDrive 配下リポジトリの git ロック問題を handoff.md に明記（再発を防ぐ運用 Tips として） | 低 |
| **R-I** | 文書要約 + 「目的」整合性チェック機能。Gemma 4 にレビュー対象文書の内容要約を生成させ UI に表示。さらに文書中に「目的」セクションが存在する場合、LLM 生成要約と「目的」の内容が一致しているか運用者が判断できる形で並列表示。乖離があれば文書品質指摘の候補（『目的と本文の整合性が取れていない』等）として独立フィールド出力 | 中 |

### 6.2 実データテスト（ユーザー環境でしか確認できない）

| # | 内容 | 状態 |
|---|---|---|
| V1 | 実 Ollama 環境での `local_ollama_precheck.py` 実行 | **凍結（ローカル LLM 構想凍結に伴う）** |
| V2 | 実 Gemini free tier でのクォータ遭遇時の挙動確認 | 未実施 |
| **V3** | Streamlit UI を実データで一巡 | 簡易テスト (test1.txt) は成功、本格テストは未実施 |
| **V4** | 作業計画書実データを投入して rubric の指摘精度確認 | 未実施 |
| V5 | 大容量・複数ファイル同時投入の動作確認 | 未実施 |
| V6 | mask_and_continue 判定 → 確認ゲート → 送信の一連フロー実データ確認 | 未実施 |

### 6.3 旧レビューで残った M/L 級

| # | 内容 | 優先 | 状態 |
|---|---|---|---|
| M1 | 裸ホスト名（`tokyo-rtr-01` 等）の検出強化 | 中 | **対応済み**（社内命名規則 regex `_build_internal_hostname_pattern` を `sanitizer.py` に追加。機器種別語彙ベースで過検出を抑制。テスト 4 件追加で全件通過。R-H として PR #7 マージ済み） |
| L1 | findings / reasons の重複ノイズ整理 | 低 | 未対応 |
| L2 | provider 名の表記ゆれ統一 (`gemma4` / `gemma-4-gemini-api`) | 低 | 未対応 |
| L5 | `env_loader._strip_quotes` のエスケープシーケンス対応 | 低 | 未対応 |
| L6 | `_has_unprotected_command_execution` の `exec(` が SQL `EXEC` に過剰マッチ | 低 | 未対応 |
| L7 | `HeuristicSensitivityClassifier` が sanitizer findings を再評価している冗長性 | 低 | 未対応 |
| L8 | ラベル系パターン（`person` / `company` / `project` / `ticket`）が既存プレースホルダ（`[EMAIL_001]` 等）を再マスクしてしまう問題 | 中 | **対応済み**（`_replace_pattern` で値が `_PLACEHOLDER_REUSE_PATTERN` にマッチする場合は再マスクをスキップ。R-J として PR #8 マージ済み、テスト 3 件追加で合計 76 件通過） |

### 6.4 機能拡張候補

| # | 内容 |
|---|---|
| E1 | PBR 多視点化（同一文書を複数視点で評価） |
| E2 | 監査ログ永続化 |
| E3 | HTTP API 前段の認証 proxy 例 |
| E4 | レビュー履歴管理 |
| E5 | GiNZA / SudachiPy による NER 補完層（自然文中の人名・組織名・地名の検出強化）+ 許可リスト機構（過検出制御）。Streamlit Cloud Free tier はメモリ ~1 GiB のため、ja_ginza モデル(~500MB)同梱時の動作実測が必要 |

### 6.5 将来フェーズ（凍結中、basic_design.md 記載）

- Gemma 4 自己配備（PoC では Streamlit Cloud + 外部 Gemma 4 で代替）
- Google Cloud 配備
- 暗号化、権限制御

### 6.6 不要コードの整理（オプション、判断保留）

ローカル LLM 機能の凍結に伴い、以下のコード/ファイルは現在使われていない:

- `secure_review/sanitizer.py` 内の `LocalHttpSanitizationEnhancer` / `OllamaSanitizationEnhancer`
- `secure_review/sensitivity.py` 内の `LocalHttpSensitivityClassifier` / `OllamaSensitivityClassifier`
- `scripts/local_ollama_precheck.py`
- `docs/local_ollama_verification.md`
- `tests/` の Ollama 関連テスト

**判断**: 削除すると将来の自己配備フェーズで再実装が必要。残すなら現状の設定（PROVIDER=none / heuristic）で実害なし。**残す方針が有力**だが、ユーザー判断で削除も可。

---

## 7. ファイル構成

```
codex_app/
├── CHANGES.md
├── README.md
├── .env                            # ユーザー手元のみ（リポジトリにはコミットしない）
├── .env.example
├── requirements.txt
├── server.py                       # HTTP API 起動スクリプト（補助、メインは Streamlit）
├── streamlit_app.py                # 主 UI（完全日本語化、st.secrets ブリッジ実装、R-B モデル識別子表示）
├── docs/
│   ├── basic_design.md             # 基本設計書
│   ├── handoff.md                  # 本ファイル
│   ├── local_ollama_verification.md # 凍結中の機能の手順書
│   ├── operations_policy.md        # 運用ポリシー（日本語化済み、現構成反映済み）
│   ├── security_boundaries.md      # R1-R4 境界仕様
│   ├── streamlit_cloud_deployment.md # Streamlit Cloud デプロイ手順（2026-04-27 新設）
│   ├── traceability.md             # 設計-コード対応表
│   └── v3_streamlit_verification.md # 実データ検証手順
├── scripts/
│   ├── api_smoke_test.py           # 外部 API 疎通確認
│   └── local_ollama_precheck.py    # 凍結中
├── secure_review/
│   ├── __init__.py
│   ├── app.py                      # HTTP API ハンドラ（findings 接頭辞は R-A の対象）
│   ├── env_loader.py
│   ├── extractor.py                # PDF / DOCX / XLSX / PPTX
│   ├── models.py                   # ReviewResult.raw_response, model フィールド追加済み (R-B/R-C)
│   ├── network_guard.py            # R1/R3 中核
│   ├── reviewer.py                 # JSON モード対応済み、R-B/R-C 対応済み (model 由来 summary 優先表示 + フォールバック)
│   ├── rubric.py                   # 研究 + テンプレート反映
│   ├── sanitizer.py                # R-H/R-J 対応済み (内部命名規則 regex / プレースホルダ再マスク防止)
│   └── sensitivity.py              # 日本語化済み
├── static/
│   └── index.html                  # Streamlit 移行案内
├── .devcontainer/                  # 自動追加（Codespaces 用、未使用）
└── tests/
    ├── __init__.py
    ├── test_app.py
    ├── test_env_loader.py
    ├── test_network_guard.py
    ├── test_reviewer.py            # R-B/R-C で 6 件追加（合計 25 件）
    ├── test_sanitizer.py           # R-H で 4 件 + R-J で 3 件追加（合計 16 件）
    └── test_sensitivity.py
```

---

## 8. 既知の制約と注意事項

- HTTP API 前段に認証が無いため、loopback バインド（既定）か auth proxy 背後でのみ運用
- 監査ログ永続化なし、必要なら stdout を systemd-journald 等で保存
- **ローカル LLM 機能は凍結中** — PROVIDER=none/heuristic で動作、関連コードはコードベースに残存
- 画像 OCR は Tesseract 必須（無ければ警告つきプレースホルダ）
- PDF OCR は未対応（スキャン PDF は本文抽出されない）
- **OneDrive 配下リポジトリの git ロック警告** — `git branch -d` 実行時に「Deletion of directory '.git/logs/refs/...' failed. Should I try again? (y/n)」が出ることがある。`n` で抜けて `git branch -a` で削除確認ができれば実害なし
- Streamlit Cloud の Secrets は手動設定（push しても自動で同期されない）
- `.devcontainer/` フォルダはどこかの自動仕組みで追加された可能性あり、現在は使用していない

---

## 9. 現場検証結果

### 9.1 V3 簡易テスト結果（2026-04-27）

- 実施日: 2026-04-27
- 実施者: ユーザー
- 入力: `test1.txt`（テスト用手順書、394 B、機密情報なし）
- 結果: **成功**
  - ステップ 1: アップロード正常
  - ステップ 2: 安全 1 / 要確認 0 / 送信禁止 0、判定理由は日本語表示
  - ステップ 3: 「送信準備完了」表示
  - ステップ 4: Gemma 4 から 7 件の高品質な日本語指摘（高 4 / 中 2 / 低 1）
  - 「LLM の生レスポンス」エクスパンダで JSON 応答を確認、構造化出力が完璧に機能

### 9.2 観察された Gemma 4 の指摘品質

`test1.txt` という極めて簡素な手順書に対して、ITIL change enablement の観点に沿った以下の指摘を生成:

1. [高] 構成情報およびタイムチャートの参照先が不明
2. [高] 具体的な作業手順の欠落
3. [高] 切戻し手順の未記載
4. [高] go/no-go 判定ポイントの未定義
5. [中] 作業対象環境の明記不足
6. [中] 役割分担および連絡体制の未記載
7. [低] 作業後更新ドキュメントの未一覧化

→ **rubric の研究知見が Gemma 4 の指摘に反映されている**ことを確認。プロのレビュアーレベルの指摘品質。

### 9.3 残された V3 観察項目

- [ ] 大容量ファイル（複数 MiB）での挙動
- [ ] 複数文書同時投入時の挙動
- [ ] mask_and_continue 判定発生時の確認ゲート動作
- [ ] block 判定発生時のエラー表示
- [ ] Gemini API のクォータ超過時の挙動
- [ ] R-B/R-C モデル由来サマリ表示の実機確認（ステップ 4 にモデル識別子と要約が表示されること）
- [ ] R-J プレースホルダ再マスク防止の実機確認（メールアドレスを含む文書を投入して二重置換が起きないこと）

---

## 10. 次のチャットで最初にすること

1. **handoff.md セクション 0.1（現在の到達点）と 0.2（次の作業候補）を読む**
2. **本日の作業観点を 1-2 行で合意**（review-scoping skill v3 適用）
3. **どの残課題から着手するか優先順位を確認**
4. **作業中の生成物は手元 PC（OneDrive 配下）でブランチ作成 → push → PR → マージ**
5. **PR マージ後、Streamlit Cloud が自動再デプロイされるのを 5-10 分待つ**

### 10.1 git 作業の標準フロー（業務 PC 用）

```powershell
cd "C:\Users\S023649\OneDrive - KDDI株式会社\SecurePC\Documents\codex"
git status
git checkout main
git pull origin main
git checkout -b feature/<task-name>

# ... 編集 ...

git add <files>
git commit -m "<title>" -m "<body>"
git push -u origin feature/<task-name>

# GitHub で PR 作成 → Merge → Delete branch (https://github.com/groovewaves-prog/codex_app/branches でゴミ箱)

git checkout main
git pull origin main
git branch -d feature/<task-name>  # OneDrive ロックは n で抜ける
git fetch --prune
```

### 10.2 デプロイ確認

```
https://codexapp-edwxxq7jek7mrtyr8hwtbp.streamlit.app
```

ハードリフレッシュ (`Ctrl + Shift + R`) で最新版を確認。

---

## 11. 主要 PR の履歴

| PR | タイトル | マージコミット | 内容 |
|---|---|---|---|
| #1 | hardening/r1-r4-and-features | `502ad81` | R1-R4 セキュリティ境界対応、rubric 強化、PDF 抽出、研究知見反映 |
| #2 | feature/streamlit-cloud-secrets | `e05a7b5` | `st.secrets` → `os.environ` ブリッジ、Streamlit Cloud デプロイ可能化 |
| #3 | feature/japanese-ui | `9f2be91` | UI 完全日本語化（A+B+C+D+E すべて） |
| #4 | feature/json-review-output | (post-#3) | Gemini JSON モード対応、プレースホルダ echo 撃退、生レスポンス表示エクスパンダ追加、HeuristicSensitivityClassifier 日本語化 |
| #6 | feature/docs-cleanup-2026-04-27 | `71e8e98` | docs cleanup（2026-04-27） |
| #7 | feature/r-h-internal-hostname-regex | `31ae41a` | R-H / M1: 社内命名規則 regex `_build_internal_hostname_pattern` を `sanitizer.py` に追加。機器種別語彙ベースで過検出を抑制。テスト 4 件追加。 |
| #8 | feature/r-b-c-j-summary-and-placeholder-reuse | `9b7ee32` | R-B/R-C: モデル由来サマリの UI 表示化と `ReviewResult.model` フィールド追加。R-J: ラベル系パターンが既存プレースホルダを再マスクする問題を修正。テスト 9 件追加で合計 76 件通過。 |

※ PR #5 はインフラ・微修正系で本記録には含めていない。詳細は GitHub Pull requests 一覧を参照のこと。

---

## 12. 連絡事項・注意点

- **API キー (`GEMINI_API_KEY`) は絶対に Claude に開示しない**。Claude 側でも貼り付けを促さないこと
- **Streamlit Cloud Secrets の更新は手動**。コード変更で `st.secrets` の構造を変えた場合、Cloud 側の TOML も手動で同期する必要あり
- **OneDrive 配下リポジトリの git ロック**: 操作中に「y/n?」が出たら `n` で抜ける。`git branch -a` で実態を確認すれば実害は無いことが多い
