# R-M (Custom Mask Dictionary) Handoff - 2026-05-03

## このドキュメントの目的

本日(2026-05-03)のセッションで、R-M Phase 1+2 の **PR-D 詳細設計**が完全に確定しました。
このドキュメントは、PR-D 実装作業中および完了後の引き継ぎ用です。

前セッション(2026-05-02)の handoff(`handoff_R-M_2026-05-02.md`)も併せて参照してください。

---

## 本日のセッションで完了したこと

| 項目 | 結果 |
|---|---|
| PR-C(HojinLookup)コード作成・コミット・push・マージ | ✅ |
| ローカルブランチクリーンアップ | ✅ |
| PR-D 詳細設計 D1-D8 完全確定 | ✅ |
| PR-D 規模感確認(2 分割で進める方針) | ✅ |

---

## R-M 全体構成と進捗

| PR | 内容 | 状態 |
|---|---|---|
| PR #23 | R-M handoff document | ✅ マージ済み |
| PR #24 (PR-A) | models.py 新規型 + sanitizer.py に register_ner_finding() | ✅ マージ済み |
| PR #25 (PR-B) | NerMasker(spaCy + EntityRuler + シード辞書) | ✅ マージ済み |
| PR #26 (PR-C) | HojinLookup(gBizINFO API クライアント) | ✅ マージ済み(本日) |
| **PR-D1** | パイプライン + シード辞書 | 🔵 実装待ち |
| **PR-D2** | streamlit_app.py 統合 + UI | 🔵 実装待ち |
| **PR-E** | 追加テスト 3-5 件 | 🔵 実装待ち |

---

## PR-D 詳細設計(D1-D8 確定)

### D1: パイプラインモジュールの配置と命名

- **採用**: `secure_review/run_masking_pipeline.py`
- 理由: 責務分離、命名の一貫性、テスタビリティ、将来の拡張性

### D2: パイプラインの API 設計

- **採用**: 2 関数構成、ner_masker / hojin_lookup は None 許容、フォールバックあり

```python
def run_masking_pipeline(
    name: str,
    text: str,
    sanitizer: SensitiveDataSanitizer,
    ner_masker: NerMasker | None,           # None で NER 機能オフ
    hojin_lookup: HojinLookup | None,       # None で gBizINFO 検索オフ
) -> MaskingPipelineState:
    """Phase 1+2 パイプライン: sanitize → NER → gBizINFO 検索。"""

def apply_user_decisions(
    state: MaskingPipelineState,
    user_decisions: dict[str, bool],
    sanitizer: SensitiveDataSanitizer,
) -> SanitizedDocument:
    """ユーザ判断を反映し、最終的な匿名化済みテキストを生成。"""
```

#### 内部処理ステップ(`run_masking_pipeline`)

1. `sanitizer.sanitize(name, text)` → `SanitizedDocument`
2. `ner_masker.extract_candidates(text)` → `list[NerCandidate]`
3. 各 candidate を確定 / 未確定に振り分け:
   - `confirmed=True`(シード辞書ヒット) → 自動マスク対象
   - `confirmed=False`(統計 NER のみ) → ユーザ判断対象
4. 未確定候補について `hojin_lookup.search(name)` → `dict[str, LookupResult]`
5. `MaskingPipelineState` にまとめて返す

#### 内部処理ステップ(`apply_user_decisions`)

1. `state.sanitized` をベースとする
2. `state.confirmed_findings` を `register_ner_finding()` で追加
3. `state.uncertain_candidates` のうち、`user_decisions[c.text] == True` のものを追加
4. 最終的な `SanitizedDocument` を返す

#### フォールバック動作

- NerMasker が None または例外発生 → 既存 sanitize 結果のみ返す、UI に警告
- HojinLookup が None → NER 候補は抽出するが lookups は空
- HojinLookup が部分的に失敗 → エラー候補は `LookupResult.error` に格納、UI 表示

### D3: シード YAML の初期内容

- **採用**: 30 件、メガキャリア + 大手 IT + 銀行 + SIer + 製造業
- ファイル: `data/ner_seeds.yaml`
- スキーマ: `phrases:` と `token_patterns:`(脱出ハッチ)

#### 含める企業カテゴリ(各 5-7 件)

- メガキャリア(KDDI, NTT, NTTドコモ, NTT データ, ソフトバンク, 楽天モバイル)
- 主要 IT(富士通, NEC, 日立製作所, 日立 [canonical: 日立製作所], 東芝)
- 銀行・金融(三菱UFJ銀行, 三井住友銀行, みずほ銀行, りそな銀行)
- SIer・コンサル(野村総合研究所, NRI [canonical], アクセンチュア, TIS, SCSK)
- クラウド(さくらインターネット, GMO, freee)
- 製造業大手(トヨタ自動車, ホンダ, 日産自動車, ソニー, パナソニック, シャープ)

#### 重要: 含めないもの

- AWS, Google, Microsoft 等の海外 IT 大手 → 技術文脈で正当な参照、マスクすると LLM レビュー品質低下
- 顧客固有名・案件名 → リポジトリ公開リスク
- マイナー企業(iret 等)→ HojinLookup で動的検出

### D4: ユーザ確認 UI のレイアウト

- **採用**: カード形式、デフォルトマスク、gBizINFO 表示、確定済みはエクスパンダー

#### UI 構成

```
[⚠️ マスク候補(N 件、ご確認ください)]
  [候補ごとにカード]:
    - 候補テキスト + spaCy ラベル
    - 🏢 gBizINFO 検索結果(件数 + 上位 3-5 件の法人名)
    - ◉ マスクする  ◯ マスクしない(デフォルトはマスクする側)
  [一括: すべてマスクする] [一括: すべてマスクしない]
[エクスパンダー: 自動マスク済み(展開して確認)]
[この内容で確定 → ステップ 3 へ進む]
```

#### 設計詳細

- レイアウト: `st.container()` ベースのカード
- gBizINFO 検索失敗時: 「⚠️ gBizINFO 検索失敗(ネットワークエラー)」と表示、判断委譲
- 確定済み候補(シード辞書ヒット): エクスパンダーで折りたたみ、デフォルトは閉じている

### D5: Streamlit セッション状態管理

- **採用**: NerMasker / HojinLookup は `@st.cache_resource`、sanitizer は毎回新規、user_decisions を session_state

#### キャッシュ戦略

```python
@st.cache_resource
def get_ner_masker():
    try:
        return NerMasker(seed_yaml_path="data/ner_seeds.yaml")
    except Exception as e:
        st.warning(f"NerMasker 初期化失敗: {e}")
        return None

@st.cache_resource
def get_hojin_lookup():
    token = st.secrets.get("GBIZINFO_API_TOKEN", "")
    if not token:
        return None
    return HojinLookup(api_token=token)

def get_sanitizer():
    # キャッシュしない、毎回新規(counter リセット用)
    return SensitiveDataSanitizer()
```

#### セッション状態

- `st.session_state.masking_state: MaskingPipelineState | None`
- `st.session_state.user_decisions: dict[str, bool]`
- `st.session_state.masking_finalized: bool`
- `st.session_state.last_filename: str`(再アップロード検知用)

#### 再アップロード処理

ファイル名変更検知でリセット:
```python
if uploaded_file.name != st.session_state.get("last_filename"):
    st.session_state.masking_state = None
    st.session_state.user_decisions = {}
    st.session_state.masking_finalized = False
    st.session_state.last_filename = uploaded_file.name
```

#### 確定後の再判断

- 確定後は UI を disabled、リセットボタンで再開可能
- (MVP 段階の判断: ラジオ自動再計算は B 案、リセットボタン式は A 案、A を採用)

### D6: 既存 UI への組み込み方

- **採用**: ステップ 2 内に統合、内部で全処理、デフォルト ON

#### チェックボックス UI

```python
rm_enabled_user = st.checkbox(
    "カスタム辞書 + 法人名検索を利用する",
    value=True,  # デフォルト ON
    help="..."
)
```

#### 配置方針

- ステップ 2(匿名化プレビュー)内に R-M 統合
- 既存の R-M Diagnostics エクスパンダーは末尾にそのまま残す(技術検証用)
- 処理中は `st.spinner("R-M 解析中...")` で進捗表示

#### エラー時のフォールバック

- R-M 処理で例外 → エラー表示しつつ、既存 regex 結果のみで処理続行
- 透明性確保(ユーザに状況が分かる)

### D7: テスト方針

- **採用**: 15+ 件、streamlit_app.py の一部もテスト

#### テスト構成

- `test_run_masking_pipeline.py`(新規): 10-12 件、ロジックテスト
- `test_streamlit_app.py`(新規): 3-5 件、Streamlit AppTest 利用

#### `test_run_masking_pipeline.py` の主要ケース

1-8. `run_masking_pipeline()`: 正常系、各種 None / フォールバック、エラー混在
9-12. `apply_user_decisions()`: 全マスク、全除外、混合、対応なしキー無視

#### `test_streamlit_app.py` の主要ケース

1. デフォルト状態(R-M チェックボックス ON)
2. ON 時のフロー(state 生成)
3. OFF 時のフロー(state 生成されず)
4. ユーザ判断の保持
5. 確定ボタン押下

#### モック戦略

- NerMasker / HojinLookup は Fake クラス
- spaCy / urllib は呼ばない
- 実モデル(`ja_core_news_md`)は使わない

### D7-2: テスト分割

- **採用**: PR-D1/D2 で 12 + 3-5 件、PR-E で残り 3-5 件

### D8: デプロイ後の検証とリスク制御

- **採用**: 3 Stage 検証、`R_M_DISABLED` フラグ、即時全展開、Tier 1-3 対処

#### 3 Stage 検証

- Stage 1(デプロイ直後 5 分): デプロイログ確認、R-K/R-L 生存確認、R-M チェックボックスデフォルト ON
- Stage 2(15-30 分): サンプルテキスト「KDDI 様の府中DCから...iret 開発チーム」で動作確認
- Stage 3(必要時): 不具合発生時の Tier 1-3 対処

#### 機能フラグ

```python
def is_rm_enabled() -> bool:
    """R_M_DISABLED が "true" でない限り True."""
    try:
        return st.secrets.get("R_M_DISABLED", "false").lower() != "true"
    except Exception:
        return True
```

#### Tier 別対処

- Tier 1: Streamlit Secrets に `R_M_DISABLED = "true"` 追加(コード変更不要、5 分対処)
- Tier 2: チェックボックスデフォルトを OFF に変更する hotfix PR
- Tier 3: PR-D の revert hotfix(完全に R-M 機能を取り除く)

---

## PR-D1 実装プラン

### 範囲

| ファイル | 状態 | 想定 LOC |
|---|---|---|
| `secure_review/run_masking_pipeline.py` | 新規 | 150-200 |
| `data/ner_seeds.yaml` | 新規 | 80-100 |
| `tests/test_run_masking_pipeline.py` | 新規 | 200-250 |

streamlit_app.py は **触らない**。既存挙動完全維持。

### ブランチ名

`feature/r-m-pipeline-and-seeds`

### 既存テストへの影響

PR-D1 は **追加のみ**(`secure_review/` 配下に新ファイル + tests/ に新ファイル)、既存テスト無影響を期待。

---

## PR-D2 実装プラン(PR-D1 マージ後)

### 範囲

| ファイル | 状態 | 想定 LOC |
|---|---|---|
| `streamlit_app.py` | 更新 | +200-300 |
| `tests/test_streamlit_app.py` | 新規 | 100-150 |
| `CHANGES.md` | 更新 | +20-30 |
| `README.md` | 更新 | +10-20 |

### ブランチ名

`feature/r-m-streamlit-integration`

### マージ後

- Streamlit Cloud で自動デプロイ
- Stage 1 検証(デプロイログ + R-K/R-L 生存確認)
- Stage 2 検証(サンプルテキストで動作確認)

---

## 残課題

| 優先 | 項目 |
|---|---|
| 中 | R-L 効果の実機検証(Gemini API 復旧確認) |
| 中 | R-N: API タイムアウト対策 |
| 低 | Phase E: 詳細設計書 / 手順書ルーブリック深化 |
| 低 | Progress gauge UX 機能 |

---

## 新チャット再開時の参考クエリ

> R-M Phase 1+2 の PR-D1 実装を始めたい(handoff_R-M_2026-05-03.md 参照)

または:

> R-M PR-D2 実装に進みたい(PR-D1 完了後)
