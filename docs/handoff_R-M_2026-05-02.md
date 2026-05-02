# R-M (Custom Mask Dictionary) Handoff - 2026-05-02

## このドキュメントの目的

本日(2026-05-02)のセッションは長丁場で、R-M Phase 1+2 の根本アーキテクチャ確定まで到達しました。
このドキュメントは、新チャットでの作業再開を可能にするための引き継ぎ書です。

---

## R-M とは

### 目的

secure_review における「カスタムマスク辞書」機能の追加。既存の R-H〜R-K 完成後、固有名詞(企業名、組織名)のマスキング能力を強化し、シード辞書 + ユーザ追加 + 外部 DB 検索を統合する。

### 全体 Phase 構成

| Phase | 内容 | 進捗 |
|---|---|---|
| Phase 1 | EntityRuler + シード辞書 + spaCy NER 統合 | 設計確定 |
| Phase 2 | gBizINFO 補助検索 + ユーザ確認 UI | 設計確定、API 検証完了 |
| Phase 3 (将来) | (法人番号 API、改善等) | 未定 |

---

## 確定した設計判断(Step 0)

### 判断 1: SQLite 永続化

- **採用**: 起動毎にシード YAML から再構築、ユーザ追加はセッション限り
- 理由: シンプル、Streamlit Cloud の SQLite 揮発性と整合、ユーザ事情(共有 PC で永続化したくない)とも合致

### 判断 2: シード辞書内容

- **採用**: 公知日本企業名 + 組織サフィックス + 敬称、ラベルは ORG 中心
- 含める: KDDI, NTT, ソフトバンク等の主要日本企業 / 株式会社, 合同会社等のサフィックス / 様, 御中, 殿の敬称
- 除外: AWS, Google 等の IT 大手(技術用語との衝突)、顧客名・案件名(GitHub 公開リスク)

### 判断 3: マスクラベル方針

- **採用**: 既存 `[CATEGORY_NNN]` 形式を継承、PRODUCT はマスクせず通す
- spaCy ラベル → 既存カテゴリのマップ:
  - ORG → COMPANY
  - GPE / FAC → SITE
  - PERSON → PERSON
  - PRODUCT → 素通し(技術用語として LLM レビューに有用)

### 判断 4: sanitizer.py との統合方法

- **採用**: β 案 - 新ファイル `ner_masker.py` を作成、`sanitizer.py` には `register_ner_finding()` メソッドを 1 つ追加するのみ
- 理由: 責務分離、依存関係の明確化、既存コードへの侵襲最小

### 判断 5: テスト方針

- **採用**: hybrid アプローチ
  - 単体ロジック: `spacy.blank('ja')` + モック
  - 実モデル(`ja_core_news_md`)はテストでは使わず、Diagnostics エクスパンダーで実機確認
  - **Memory Zone + doc_cleaner 両方を実装**(spaCy 公式 Memory Management ドキュメントの知見)
- 期待規模: 22-35 件追加(本番環境 115 件 → 137-150 件)

### 判断 6: 未確定候補の処理(本日のセッション末で確定)

- **採用**: gBizINFO 検索 + ユーザ確認 UI、LLM 推論は不使用
- 設計フロー:
  1. シード辞書にあり → 即マスク
  2. gBizINFO で確実にヒット → 自動マスク
  3. gBizINFO でヒットしない / 曖昧 → ユーザに「マスクしますか?」と確認
- 理由: シンプル、自己矛盾を避ける(LLM に未マスク文書を送らずに済む)、現実的な実装規模

---

## 確定アーキテクチャ図

```
[文書テキスト]
    ↓
[既存 regex マスキング (R-H〜R-K, sanitizer.py)]
    ↓
[spaCy NER + EntityRuler + シード辞書 (ner_masker.py)]
    ↓ 確定したものは [COMPANY_NNN] でマスク、未確定は次へ
[各候補について gBizINFO 検索 (hojin_lookup.py 等)]
    ├─ ヒット件数と内容を取得
    └─ ユーザ判断のための情報として保持
    ↓
[ユーザ確認 UI: ステップ 2 のプレビュー画面]
    各候補について:
    - gBizINFO ヒット件数 + 上位法人名表示
    - [マスクする] [しない] ボタン
    ↓
[マスク決定 → ステップ 3 LLM レビュー]
```

---

## 本日の技術検証結果

### NER ライブラリ選定

| ライブラリ | 結果 | 備考 |
|---|---|---|
| GiNZA | ✗ Python 3.14 で動かず | ginza 5.2.0 が spacy 3.7.x 依存、cp314 wheel なし |
| spaCy ja_core_news_md | ✅ 動作 | RAM 462 MB、解析 18 ms、5 エンティティ検出 |
| spaCy ja_core_news_trf | ✗ blis ビルド失敗 | spacy[transformers] → spacy-alignments → blis、cp314 wheel なし |
| ja_core_news_md + disable | ✅ 微小最適化 | RAM 460.5 MB(2 MB 削減のみ、効果は微小) |

### gBizINFO API 検証(本日 PR #22 マージ)

#### API 仕様

- 認証: `X-hojinInfo-api-token` ヘッダー
- エンドポイント v2: `https://api.info.gbiz.go.jp/hojin/v2`
- エンドポイント v1: `https://info.gbiz.go.jp/hojin/v1` (フォールバック)
- 法人名検索: `/hojin?name={name}`
- レスポンス: JSON、部分一致

#### 申請

- 申請ページ: `https://info.gbiz.go.jp/hojin/various_registration/form`
- 発行時間: 数秒(国税庁 法人番号 API は 2 週間〜1.5 ヶ月)
- 商用利用可、出典明記必要(「出典: 経済産業省 gBizINFO」)

#### 実機検証結果

| クエリ | ヒット件数 | レスポンス時間 | 観察 |
|---|---|---|---|
| iret(英字) | 21 件 | 636 ms | 株式会社アイレットが**含まれず**、無関係企業多発 |
| アイレット(カタカナ) | 16 件 | 540 ms | 株式会社アイレット、KDDIアイレット株式会社等を正しく検出 |

#### 重要な発見

- **iret(英字)は精度低**: 部分一致が緩く、誤マッチ大量発生
- **アイレット(カタカナ)は精度高**: 関連法人を正しく抽出
- **「KDDI アイレット株式会社」が実在**: 元の文書(KDDI 様の府中DC...iret 開発チーム)と完全に整合
- **2026-04 に「株式会社アイレット」が「KDDIアイレット株式会社」に社名変更**: gBizINFO はこの新名で登録済み
- **完璧な辞書は存在し得ない**: 法人は常に変化(合併、改名等)、旧社名がドキュメントに残るのは止む無し

---

## 重要な技術的学び

1. **Streamlit Cloud は Python 3.14 デフォルト** - 古いライブラリ(GiNZA / blis 系)が動かない要因
2. **Python バージョン変更にはアプリ削除→再デプロイ必須** - 不可逆操作
3. **EntityRuler の有用性** - 静的辞書 + 統計NER のハイブリッド、ただし「未知語問題」は解決しない
4. **Memory Zone は Web サービスでほぼ必須** - 長期稼働のメモリ膨張を防ぐ(spaCy 3.8+)
5. **doc_cleaner コンポーネント** - tok2vec の中間 tensor をクリーンアップして RAM を抑える
6. **`try/except ImportError` は緊急時の生命線** - 全 hotfix で機能した防御策
7. **記事「Optimize Your spaCy NER Results With This Simple Change」の真の主張** - lg → trf への切り替え推奨。私たちの環境制約で当面採用不可、ただし Python 3.11 環境なら可能性あり
8. **「機密マスキングツール」として完全自動化は不可能** - ユーザの目視確認が最終防衛線
9. **法人番号 API は ID 取得に 2 週間〜1.5 ヶ月** - gBizINFO の方が圧倒的に高速(数秒)
10. **gBizINFO の部分一致検索は緩い** - 短い英字略称(iret, NEC 等)では誤マッチ多発、カタカナや日本企業名なら高精度
11. **完璧を目指さず、合理的な妥協を受け入れる** - 「旧社名残留もやむなし」「ヒットしなければユーザに尋ねる」というシンプル設計が実用的

---

## リポジトリ状態(2026-05-02 時点)

### ブランチ

```
* main (最新: 8704876, PR #22 マージ済み)
  remotes/origin/main
```

ローカル・remote ともにクリーン。古いブランチは整理済み(experiment/r-m-spacy-trf-trial, feature/r-m-spacy-ja-core-news-md, hotfix/r-m-revert-trf-and-apply-disable はすべて削除)。

### 既存テスト

- 80 件(コンテナ環境)/ 115 件(本番リポジトリ)、全通過

### 主要ファイル

| ファイル | 状態 |
|---|---|
| `streamlit_app.py` | 1056 行(本日 PR #22 で gBizINFO Diagnostics エクスパンダー追加) |
| `sanitizer.py` | 727 行(R-K 完成版) |
| `reviewer.py` | (R-K 完成版) |
| `rubric.py` | (R-K 完成版) |
| `models.py` | (R-K 完成版) |

### Streamlit Secrets

- `GEMINI_API_KEY` (R-K 用)
- `GBIZINFO_API_TOKEN` (本日追加、R-M Phase 2 用)

### 本日マージ済み PR

| PR | 内容 |
|---|---|
| #20 | feature/r-m-spacy-ja-core-news-md(spaCy 公式 md 採用)|
| #21 | experiment/r-m-spacy-trf-trial(trf 試行、boot loop)|
| (hotfix) | hotfix/r-m-revert-trf-and-apply-disable(md にロールバック + disable 最適化)|
| #22 | feature/r-m-gbizinfo-diagnostics(gBizINFO Diagnostics 追加、本日)|

---

## 次のステップ(Step 1: 詳細設計)

### 詳細設計で固めるべき項目

| 項目 | 内容 |
|---|---|
| a | モジュール構成と責務(sanitizer.py, ner_masker.py, hojin_lookup.py, streamlit_app.py) |
| b | データフローと関数シグネチャ |
| c | シード YAML スキーマ(match_mode, label, alias 等) |
| d | ユーザ確認 UI の仕様(表示形式、ボタン、状態管理) |
| e | Streamlit セッション状態管理(候補リスト、ユーザ判断履歴) |

### 詳細設計後の Step 2 (実装)

- 想定 PR 数: 3-5
- 想定実装時間: 3-5 セッション
- 新規モジュール 3 個、新規 LOC 〜400-500、新規テスト 40-60 件

---

## 残っている長期課題(R-M 以外)

| 優先 | 項目 |
|---|---|
| 中 | R-L 効果の実機検証(Gemini API 復旧確認) |
| 中 | R-N: API タイムアウト対策 |
| 低 | Phase E: 詳細設計書 / 手順書ルーブリック深化 |
| 低 | Progress gauge UX 機能 |
| 低 | handoff.md ファイル名 mojibake 調査(punted) |

---

## 新チャット再開時の参考クエリ

> R-M Phase 1+2 の Step 1 詳細設計から再開したい(handoff_R-M_2026-05-02.md を参照)

または:

> R-M の実装(Step 2)に進みたい

または:

> 別の課題(R-L 検証 / R-N / Phase E 等)に進みたい

