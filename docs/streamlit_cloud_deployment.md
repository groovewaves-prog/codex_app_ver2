# Streamlit Community Cloud デプロイ手順書

Last updated: 2026-04-27

本文書は `secure_review` ツールを Streamlit Community Cloud にデプロイ・運用
するための手順をまとめる。`docs/operations_policy.md`（運用ポリシー全般）と
セットで参照すること。

## 1. 前提

### 1.1 用途と位置づけ

- `secure_review` の **主 UI は Streamlit Community Cloud 上で稼働** している。
- 本文書は初回デプロイ手順、Secrets 設定、再デプロイ動作、トラブルシュートを
  カバーする。
- 設計思想・セキュリティ境界・rubric の根拠は別文書（`docs/basic_design.md`、
  `docs/security_boundaries.md`）を参照。

### 1.2 必要なアカウントと権限

| 項目 | 詳細 |
|---|---|
| GitHub アカウント | リポジトリ `https://github.com/groovewaves-prog/codex_app` の閲覧/Push 権限 |
| Streamlit Community Cloud アカウント | GitHub アカウント連携でサインイン可能 |
| Google AI Studio アカウント | Gemini Developer API キー発行用 |

### 1.3 現在のデプロイ URL

```
https://codexapp-edwxxq7jek7mrtyr8hwtbp.streamlit.app
```

## 2. 初回デプロイ手順

既にデプロイ済みのため再現用の参考。新環境構築時や、別アカウントでの再デプロイ時に
本節を使う。

### 2.1 リポジトリ準備

```powershell
# 業務 PC でリポジトリをクローン
cd "C:\Users\<USER>\Documents"
git clone https://github.com/groovewaves-prog/codex_app.git
cd codex_app

# requirements.txt が含まれていることを確認（含まれていなければ pull）
dir requirements.txt
```

### 2.2 Streamlit Cloud アプリ作成

1. https://share.streamlit.io にアクセスし、GitHub アカウントでサインイン。
2. **「New app」** をクリック。
3. 以下を指定:
   - Repository: `groovewaves-prog/codex_app`
   - Branch: `main`
   - Main file path: `streamlit_app.py`
   - App URL: 既定（自動生成）または任意
4. **「Advanced settings」** → **「Secrets」** で TOML 形式の環境変数を設定
   （次節 § 2.3 を参照）。
5. **「Deploy!」** をクリック。初回は依存解決（pypdf 等）に 2-3 分かかる。

### 2.3 Secrets 設定（TOML 形式）

Streamlit Cloud の管理画面 → アプリ → **Settings** → **Secrets** に以下を貼り付け。

```toml
REVIEW_PROVIDER = "gemma"
GEMMA_MODEL = "gemma-4-31b-it"
GEMINI_API_KEY = "<Google AI Studio で発行した API キー>"
LOCAL_SANITIZER_PROVIDER = "none"
LOCAL_SENSITIVITY_PROVIDER = "heuristic"
MASK_AND_CONTINUE_REQUIRE_CONFIRM = "true"
```

#### Secrets が `os.environ` に橋渡しされる仕組み

`streamlit_app.py` の冒頭に以下のブリッジが実装されている:

```python
if "env_loaded" not in st.session_state:
    load_dotenv()
    try:
        for key, value in st.secrets.items():
            if isinstance(value, str) and key not in os.environ:
                os.environ[key] = value
    except (FileNotFoundError, st.errors.StreamlitSecretNotFoundError):
        # ローカル開発で secrets.toml が無い場合はエラーにしない
        pass
    st.session_state.env_loaded = True
```

これにより、コードベース全体（`os.getenv` で読む側）は Streamlit Cloud と
ローカル `.env` の両環境で同じコードのまま動作する。

### 2.4 デプロイ確認

ブラウザで App URL を開き、以下を確認する。

1. タイトル「セキュアレビュー」が表示される（日本語化されている）。
2. ステップ 1 で `test1.txt`（テスト用手順書、機密情報なし）をアップロード。
3. ステップ 2 で「安全 1 / 要確認 0 / 送信禁止 0」の集計が表示される。
4. ステップ 3 で「送信準備完了」と表示される。
5. ステップ 4 を実行し、Gemma 4 から日本語のレビュー指摘が返る。
6. 「LLM の生レスポンス」エクスパンダで JSON 応答を確認できる。

## 3. 自動再デプロイの動作

### 3.1 トリガー

- `groovewaves-prog/codex_app` の **`main` ブランチへの push** を Streamlit Cloud が
  検知して自動再デプロイされる。
- 再デプロイ完了まで概ね **5-10 分**。デプロイ中もアプリは旧バージョンで稼働
  し続ける（無停止切替）。

### 3.2 標準ワークフロー

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

# GitHub で PR 作成 → Merge → Delete branch
# https://github.com/groovewaves-prog/codex_app/branches でブランチ削除可能

git checkout main
git pull origin main
git branch -d feature/<task-name>  # OneDrive ロック警告は n でスキップ
git fetch --prune
```

PR マージ後、Streamlit Cloud で再デプロイされる。動作確認はブラウザの
ハードリフレッシュ（`Ctrl + Shift + R`）で最新版を表示。

## 4. Secrets 更新時の注意

### 4.1 手動同期が必要

- Streamlit Cloud Secrets は **コードベースには含まれない**。リポジトリへの
  push では同期されず、Cloud 側の管理画面で手動更新する必要がある。
- 例: コード変更で `streamlit_app.py` 側が新しい環境変数 `NEW_VAR` を期待
  するようになった場合、Cloud Secrets にも `NEW_VAR = "..."` を追加する
  必要がある。

### 4.2 Secrets 構造変更時のチェック手順

`streamlit_app.py` または `secure_review/` 配下で `os.getenv("NEW_KEY")` のような
新規環境変数の読み出しを追加した場合:

1. PR の説明文に「**Secrets に `NEW_KEY` 追加が必要**」と明記する。
2. PR マージ前に Cloud 管理画面で Secrets を更新する（後追いだとマージ直後の
   再デプロイで起動失敗する）。
3. デプロイ後、UI で動作確認する。

### 4.3 API キーのローテーション

Gemini API キーをローテーションする場合:

1. Google AI Studio で新しい API キーを発行。
2. Streamlit Cloud Secrets の `GEMINI_API_KEY` を新キーに更新。
3. Streamlit Cloud は Secrets 変更で **自動再起動する**ため、しばらく後に
   ブラウザで動作確認。
4. 旧キーを Google AI Studio で無効化。

## 5. トラブルシュート

### 5.1 デプロイ失敗（依存解決エラー）

症状: 「Deploy」をクリックしてもアプリが起動せず、ログに `ModuleNotFoundError`。

対処:
1. `requirements.txt` が repository root に存在し、必要な依存（`streamlit`、
   `pypdf` など）が記載されているか確認。
2. Streamlit Cloud の管理画面 → **Manage app** → **Logs** でエラー詳細を確認。
3. 必要に応じて requirements.txt を更新して再 push。

### 5.2 アプリ起動時にエラー（環境変数不足）

症状: アプリは表示されるが、ステップ 4 で `ValueError: GEMINI_API_KEY or
GOOGLE_API_KEY must be configured.` 等のエラー。

対処:
1. Streamlit Cloud Secrets で `GEMINI_API_KEY` が設定されているか確認。
2. `REVIEW_PROVIDER` が `gemma` になっているか確認。
3. Secrets 更新後、Cloud 管理画面で **Reboot app** を実行。

### 5.3 Gemini API クォータ超過

症状: ステップ 4 で「Gemini free-tier quota appears to be exhausted」エラー。

対処:
1. 1 分程度待ってから再試行（`gemma-4-31b-it` のレート制限は短時間）。
2. 頻発する場合は、Google AI Studio で当該プロジェクトの quota を確認。
3. 恒常的に必要な場合は `docs/operations_policy.md` § 6 の Provider 選択を
   見直す（ただし方針 (2)「PoC は無償構成」と整合する選択肢に限る）。

### 5.4 Streamlit Cloud がスリープから復帰しない

症状: アプリ URL を開くと「This app has gone to sleep due to inactivity.」
表示。

対処:
- 「Yes, get this app back up!」ボタンを押すと再起動が始まる（30 秒～1 分）。
- 業務時間内に頻繁に使う場合、定期アクセスでスリープを回避する（自動アクセス
  スクリプトの併用は規約上のグレーゾーンなので KDDI 業務 PC では非推奨）。

### 5.5 OneDrive 配下リポジトリの git ロック警告

症状: `git branch -d feature/<task-name>` 実行時に
`Deletion of directory '.git/logs/refs/...' failed. Should I try again? (y/n)`
が出る。

対処:
- `n` でスキップする。`git branch -a` でブランチが実際に削除されていることを
  確認すれば実害はない。OneDrive のファイル同期と git の内部操作が競合する
  ことが原因。
- 頻発する場合は、OneDrive を一時停止してから git 操作する。

## 6. 関連文書

- `docs/operations_policy.md` — 運用ポリシー全般（必須環境変数、確認ゲート、
  インシデント対応）
- `docs/handoff.md` — プロジェクト引き継ぎ文書（現状サマリ、残課題、PR 履歴）
- `docs/security_boundaries.md` — R1-R4 セキュリティ境界仕様
- `docs/basic_design.md` — 基本設計書（信頼境界の前提、フェーズ計画）
