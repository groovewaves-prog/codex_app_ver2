# 運用ポリシー

Last updated: 2026-04-27

本文書は `secure_review` ツールの運用ルールを定める。Streamlit Community
Cloud 上での稼働を前提とし、ローカル / 自社環境での運用も補助的に記載する。

## 1. デプロイ環境の選択

### 1.1 Streamlit Community Cloud（現用）

- 主 UI (`streamlit_app.py`) は Streamlit Community Cloud 上で稼働している。
- Streamlit Cloud は **「信頼境界の内側」** として扱う。原文（匿名化前のテキスト）
  を Streamlit Cloud 環境内に保持してよい。外部 LLM への送信は匿名化済み
  テキストのみとする境界は変わらない。
- main ブランチ更新を Streamlit Cloud が検知して自動再デプロイされる。
- Secrets（API キー、`GEMMA_MODEL` 等）は **Streamlit Cloud の管理画面で手動設定**
  する。`st.secrets` の構造をコード変更で変えた場合、Cloud 側の TOML も
  手動で同期する必要がある。
- デプロイ手順の詳細は `docs/streamlit_cloud_deployment.md` を参照。

### 1.2 ローカル / 自社環境（凍結中の選択肢）

ローカル LLM (Ollama) 機能の凍結に伴い、現状の主運用形態ではないが、
将来の自己配備フェーズに向けて以下の規約は維持する。

- HTTP API と Streamlit UI は自前で認証を持たない。シングルユーザマシン、
  または認証プロキシ背後の共有ホストで運用すること。
- HTTP サーバと Streamlit は `127.0.0.1`（既定）にバインドする。認証層なしで
  非ループバックインターフェースに公開するのはポリシー違反。
- 専用の低権限ユーザで実行する。レビュー入力ディレクトリへの read 権限のみを
  そのユーザに付与する。

## 2. 必須環境変数

### 2.1 現構成（2026-04-27 時点）

Streamlit Cloud Secrets で以下が設定されている。

| 変数 | 値 | 役割 |
|---|---|---|
| `REVIEW_PROVIDER` | `gemma` | 外部レビュー LLM として Gemini API 経由の Gemma 4 31B を選択 |
| `GEMMA_MODEL` | `gemma-4-31b-it` | Gemma 4 ファミリーで最大の Dense モデル |
| `GEMINI_API_KEY` | （非開示） | Gemini Developer API キー |
| `LOCAL_SANITIZER_PROVIDER` | `none` | ローカル LLM 二次マスキングは凍結中 |
| `LOCAL_SENSITIVITY_PROVIDER` | `heuristic` | regex + heuristic ベースの機密度判定 |
| `MASK_AND_CONTINUE_REQUIRE_CONFIRM` | `true` | R2 確認ゲートを有効化 |

完全な環境変数一覧は `docs/handoff.md` § 4 を参照。

### 2.2 R2 確認ゲートの運用要件

本番デプロイは以下を **必ず** 満たすこと。

- `MASK_AND_CONTINUE_REQUIRE_CONFIRM=true`（既定）。`false` に設定すると R2 の
  確認ゲートが無効化される。`false` を許容するのはオフラインテスト環境のみ。
- `LOCAL_SANITIZER_API_URL` と `LOCAL_SENSITIVITY_API_URL` を設定する場合（凍結中
  だが設定値は維持）、`127.0.0.1` / `::1` / `localhost` のいずれかを指す URL に
  限定する。アプリケーションは起動時とリクエスト毎に検証し、非ループバック
  値は拒否する。運用者は配備時にも目視確認すること。

## 3. 確認ゲート運用フロー

### 3.1 `mask_and_continue` 判定時の操作手順

ローカル機密度ゲートが文書を `mask_and_continue` と判定した場合、運用者は以下を
実施する。

1. ステップ 2 のプレビューで匿名化済み抜粋を開く。
2. 残存する識別子から、外部の第三者が顧客・案件・拠点・人物を再構築できないか
   確認する。
3. 文書ごとの確認チェックボックスをオンにする（Streamlit UI の場合）、または
   HTTP リクエストで `documentConfirmations: {"<n>": true}` を指定する。

すべての `mask_and_continue` 文書が確認されてから、外部 LLM が初めて内容を
受信する。`block` 判定の文書は確認できない。原本側で再匿名化が必要。

### 3.2 検出に確信が持てない場合の方針

現行構成では機密情報の検出を次の三層で行う:

1. **regex 一次マスキング** (`SensitiveDataSanitizer`)
   検出した識別子を意味的プレースホルダ（`[HOSTNAME_001]`、`[COMPANY_001]`、
   `[PERSON_001]` など）に置換。同じ値は同じプレースホルダに統一される。
2. **heuristic 機密度判定** (`HeuristicSensitivityClassifier`)
   文書全体を `safe` / `mask_and_continue` / `block` に分類。
3. **R2 確認ゲート**
   UI で文書単位の最終確認をユーザに要求。

検出に確信が持てない箇所（裸ホスト名 `tokyo-rtr-01` のような社内命名規則の
識別子、組み合わせから推定可能な固有情報など）については、以下の方針で運用する。

- **疑わしい場合は保守的に `mask_and_continue` に倒す**。heuristic 判定が
  確実に `safe` と言えない要素を含む場合は、確認ゲート側に倒し、運用者の
  目視判断を経由させる。
- **個別箇所単位の確認 UI は持たない**。判定対象の数が増えるとクリック疲れ
  により判断が形骸化するため、確認の粒度は **文書単位** に集約する。
- **無確認のまま外部送信されることはない**。R2 確認ゲートが最終防壁として
  機能する。
- **LLM の文脈推論を併用する**。一次マスキングで検出漏れがあった裸固有名詞も、
  周囲のプレースホルダ（`[HOSTNAME_001]` など）と文脈から、外部 LLM 側で
  「これはホスト名と思われる」と推論できる構造になっている。意味的プレース
  ホルダの語彙を維持することが、この前提の根幹。

将来の検出強化策（別 PR で実装予定）:

- **社内命名規則 regex の追加**（`handoff.md` R-H）— 裸ホスト名・装置名の
  パターン（例: `[a-z]+-[a-z]+-\d{2,3}`）を一次マスキングに組み込む。
  M1 の主犯対応。
- **GiNZA / SudachiPy による NER 補完層**（`handoff.md` E5）— 自然文中の
  人名・組織名・地名検出。Streamlit Cloud のメモリ実測が必要。
- **許可リスト機構** — 上記の過検出（`Cisco`、`AWS` 等の一般技術用語の
  誤マスク）を制御する仕組み。

## 4. インシデント対応

UI が予期せず「安全」と判定した文書を表示した場合:

1. **送信ボタンを押さない**。サイドバーからセッションをリセットする。
2. 設定を確認する:
   - Streamlit Cloud Secrets の `REVIEW_PROVIDER` と `GEMMA_MODEL`。
   - `LOCAL_SANITIZER_API_URL` / `LOCAL_SENSITIVITY_API_URL` を設定している
     場合、ループバック値であること。非ループバック値は起動時に拒否される
     はずだが、部分的に設定された状態では heuristic ゲートのみが防壁となる。
3. `REVIEW_PROVIDER=mock` で再実行し、パイプラインが同じ判定を返すかを確認
   する。

`high` 判定の outbound risk を持つ文書がレビュー段階に到達した場合は、
`_enforce_outbound_guard` が provider 呼び出し前に拒否する。UI は拒否メッセージ
を表示する。**外部 API には何も送信されていない**。

## 5. ロギング

- stdout にパイプラインレベル INFO と provider レベル INFO が出力される。
- upstream HTTP エラーは `secure_review.network` モジュールロガー経由で記録
  される。レスポンスボディは redacted（240 文字超の行は切り詰め、引用文字列
  は ~240 文字以下）。URL は query / fragment を除去してからログ出力する。
- **リクエストボディや文書内容はログに記録しない**。

監査ログが必要な場合は stdout を `systemd-journald` 等でファイルキャプチャし、
そのレイヤでローテーション制御する。

## 6. レビュー Provider の選択

| `REVIEW_PROVIDER` 値 | 説明 |
|---|---|
| `gemma`（現用） | Gemini API 経由の Gemma 4 31B Dense (`gemma-4-31b-it`)、JSON モード強制。Gemma 4 ファミリー最大の Dense モデル。`GEMINI_API_KEY` または `GOOGLE_API_KEY` 必須。429 / 5xx は 1 回リトライ。クォータ枯渇は明確なエラーメッセージで人間向けに通知。 |
| `mock`（既定） | UI 検証用。ネットワーク呼び出しなし。安全に使える。 |
| `gemini-free` | Gemini 2.0 Flash 系列。**注意**: 2.0 Flash は 2026-03-03 に Google により retire 済み。現在この設定で起動するとエラーになる。後方互換のため設定値は残す。 |
| `http` | `LLM_API_URL` で指定する OpenAI 互換エンドポイント。自社配備の LLM 等で使用。 |

Provider はレビューセッションごとに選択する。切替に再起動は不要。

## 7. 改修時のチェックリスト

このツールに変更を加える場合は以下を実施する。

1. **`python -m unittest discover tests` を実行し、76 件全通過を確認する**。
   3 ファイル指定 (`tests.test_reviewer tests.test_sensitivity tests.test_sanitizer`)
   での部分実行は 49 件しか走らないので、`discover` で全件走らせること。
2. `python scripts/local_ollama_precheck.py` は **凍結中**（ローカル LLM 構想
   凍結に伴う）。ローカル LLM 機能を再開する場合のみ実行する。
3. `docs/security_boundaries.md` を確認する。R1-R4 / archive bomb guard /
   PDF cap などの境界仕様に影響する変更があれば、同じ PR で当該文書を更新する。
4. `docs/traceability.md` を確認する。コード-要件マッピングが現状と乖離して
   いないこと。
5. `docs/handoff.md` を確認する。0.1 の到達点、6 章の残課題、§ 11 の PR 履歴を
   現状に合わせて更新する。
