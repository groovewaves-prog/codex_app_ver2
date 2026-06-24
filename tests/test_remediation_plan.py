from __future__ import annotations

import unittest

from secure_review.models import ReviewIssue, ReviewResult, SanitizedDocument
from secure_review.remediation_plan import (
    RemediationItem,
    _extract_current_state_from_details,
    build_remediation_plan,
    compare_remediation_plan_to_documents,
    remediation_plan_from_dict,
)
from secure_review.structure_check import StructureCheckResult, StructureFinding


class RemediationPlanTests(unittest.TestCase):
    def _sample_item(self, **overrides) -> RemediationItem:
        values = {
            "item_id": "D-001",
            "source_type": "review_issue",
            "severity": "high",
            "title": "DR設計の未定義",
            "target_document": "design.pdf",
            "target_section": "第8章 可用性",
            "problem": "RPO/RTOがない",
            "fix_policy": "RPO/RTOと切替手順を追記する。",
            "template": "RPO RTO 切替手順 バックアップ リージョン",
            "re_review_scope": "design.pdf / 第8章 可用性",
            "re_review_condition": "高重要度指摘が解消したか確認してください。",
            "effort": "大",
        }
        values.update(overrides)
        return RemediationItem(**values)

    def _issue(self, **overrides) -> ReviewIssue:
        values = {
            "severity": "high",
            "title": "DR設計の未定義",
            "details": "RPO/RTOがない",
            "recommendation": "RPO/RTOと切替手順を追記する。",
            "source_document": "design.pdf",
            "issue_id": "D-001",
            "section": "第8章 可用性",
        }
        values.update(overrides)
        return ReviewIssue(**values)

    def _review_with_issues(self, *issues: ReviewIssue) -> ReviewResult:
        return ReviewResult(
            summary="summary",
            issues=list(issues),
            provider="mock",
            prompt_preview="",
        )

    def _source_code_review_with_issues(self, *issues: ReviewIssue) -> ReviewResult:
        return ReviewResult(
            summary="summary",
            issues=list(issues),
            provider="mock",
            prompt_preview="",
            document_profile="source_code",
        )

    def test_remediation_item_origin_defaults_to_initial(self) -> None:
        item = self._sample_item()

        self.assertEqual(item.origin, "initial")

    def test_remediation_item_origin_can_be_set_explicitly(self) -> None:
        item = self._sample_item(origin="document_deep_dive")

        self.assertEqual(item.origin, "document_deep_dive")

    def test_remediation_item_origin_round_trips_through_saved_plan(self) -> None:
        item = self._sample_item(origin="document_deep_dive")
        payload = {
            "headline": "前回の修正計画",
            "summary": "summary",
            "items": [item.to_dict()],
        }

        plan = remediation_plan_from_dict(payload)

        self.assertEqual(plan.items[0].origin, "document_deep_dive")

    def test_saved_plan_without_origin_loads_as_initial(self) -> None:
        payload = {
            "headline": "前回の修正計画",
            "summary": "summary",
            "items": [
                {
                    "item_id": "D-001",
                    "source_type": "review_issue",
                    "severity": "high",
                    "title": "DR設計の未定義",
                    "target_document": "design.pdf",
                    "target_section": "第8章 可用性",
                    "problem": "RPO/RTOがない",
                    "fix_policy": "RPO/RTOと切替手順を追記する。",
                    "template": "RPO RTO 切替手順 バックアップ リージョン",
                    "re_review_scope": "design.pdf / 第8章 可用性",
                    "re_review_condition": "高重要度指摘が解消したか確認してください。",
                    "effort": "大",
                }
            ],
        }

        plan = remediation_plan_from_dict(payload)

        self.assertEqual(plan.items[0].origin, "initial")

    def test_builds_plan_from_high_review_issue(self) -> None:
        review = ReviewResult(
            summary="summary",
            issues=[
                ReviewIssue(
                    severity="high",
                    title="DR設計の未定義",
                    details="RPO/RTOがない",
                    recommendation="RPO/RTOと切替手順を追記する。",
                    source_document="design.pdf",
                    issue_id="D-001",
                    section="第8章 可用性",
                    current_state="バックアップの記載のみ。",
                    issue="復旧目標が未定義。",
                    impact="災害時の判断が遅れる。",
                    re_review_required=True,
                )
            ],
            provider="mock",
            prompt_preview="",
        )

        plan = build_remediation_plan(review)

        self.assertEqual(plan.high_count, 1)
        self.assertEqual(plan.items[0].item_id, "D-001")
        self.assertIn("RPO/RTO", plan.items[0].fix_policy)
        self.assertIn("第8章 可用性", plan.items[0].template)
        self.assertIn("DR設計の未定義", plan.items[0].re_review_condition)
        self.assertIn("第8章 可用性", plan.items[0].re_review_condition)
        self.assertEqual(plan.re_review_steps[0].label, "必須再レビュー")

    def test_template_uses_current_state_when_available(self) -> None:
        review = self._review_with_issues(
            self._issue(
                current_state="バックアップ取得方針のみが記載されています。",
                issue="RPO/RTOが未定義。",
            )
        )

        plan = build_remediation_plan(review)

        self.assertIn(
            "バックアップ取得方針のみが記載されています。",
            plan.items[0].current_state,
        )
        self.assertNotIn("現状の記載を要約してください", plan.items[0].template)
        self.assertIn("#### 追記する本文案", plan.items[0].template)

    def test_template_extracts_current_state_from_details(self) -> None:
        review = self._review_with_issues(
            self._issue(
                current_state="",
                details="【現状】バックアップの取得頻度のみ記載されています。【問題点】復旧目標が未定義です。",
                issue="復旧目標が未定義です。",
            )
        )

        plan = build_remediation_plan(review)

        self.assertIn("バックアップの取得頻度のみ記載されています。", plan.items[0].current_state)
        self.assertNotIn("【問題点】", plan.items[0].current_state)

    def test_template_uses_actionable_fallback_without_legacy_instruction(self) -> None:
        review = self._review_with_issues(
            self._issue(current_state="", details="", issue="復旧目標が未定義です。")
        )

        plan = build_remediation_plan(review)

        self.assertIn("本文から現状の記載を自動抽出できませんでした", plan.items[0].current_state)
        self.assertIn("該当章の元記載を確認", plan.items[0].current_state)
        self.assertNotIn("現状の記載を要約してください", plan.items[0].template)

    def test_template_is_document_draft_not_review_recap(self) -> None:
        review = self._review_with_issues(
            self._issue(
                title="本書の目的および想定読者の記載不足",
                section="該当箇所",
                issue="目的と想定読者が明記されていない。",
                recommendation="本書の目的節を新設し、目的、想定読者、達成すべき成果を具体的に記述する。",
                impact="後続工程で前提や判断基準が揃わない。",
            )
        )

        plan = build_remediation_plan(review)
        template = plan.items[0].template

        self.assertIn("### 文書追記案: 該当箇所", template)
        self.assertIn("#### 追記する本文案", template)
        self.assertIn("本書の目的節を新設", template)
        self.assertIn("【対象・範囲】", template)
        self.assertNotIn("### 該当箇所 追記案", template)
        self.assertNotIn("- 現状:", template)
        self.assertNotIn("- 問題点:", template)
        self.assertNotIn("- 修正方針:", template)

    def test_source_code_plan_uses_code_fix_checklist_not_document_draft(self) -> None:
        review = self._source_code_review_with_issues(
            self._issue(
                title="HTTPリクエストにおけるタイムアウト未設定",
                issue_id="SC-001",
                source_document="get_mails.py",
                section="webapi",
                current_state="urllib.request.urlopen(req) に timeout が指定されていない。",
                issue="ネットワーク停止時に処理がハングする。",
                recommendation="urllib.request.urlopen(req, timeout=CONFIG.API_TIMEOUT) のようにタイムアウトを設定する。",
                impact="メール受信通知が停止する。",
            )
        )

        plan = build_remediation_plan(review)
        item = plan.items[0]

        self.assertIn("コード解析結果", plan.headline)
        self.assertIn("コード修正メモ", item.template)
        self.assertIn("#### 検出根拠", item.template)
        self.assertIn("#### リスク", item.template)
        self.assertIn("#### 推奨確認", item.template)
        self.assertIn("確認観点", item.template)
        self.assertIn("timeout=CONFIG.API_TIMEOUT", item.template)
        self.assertIn("再アップロード", item.re_review_condition)
        self.assertIn("必須再解析", [step.label for step in plan.re_review_steps])
        self.assertNotIn("文書追記案", item.template)
        self.assertNotIn("#### 現状", item.template)
        self.assertNotIn("該当章", item.template)
        self.assertNotIn("構成チェック", " ".join(step.detail for step in plan.re_review_steps))

    def test_source_code_plan_exports_code_analysis_metadata(self) -> None:
        review = self._source_code_review_with_issues(
            self._issue(
                title="対象ルール名のハードコードによる保守性の低下",
                issue_id="SC-001",
                source_document="collect_eb_templates.sh",
                section="コード全体",
                current_state="for r in managed-prod-eb-rule-config managed-prod-eb-rule-guardduty; do",
                issue="対象ルール名が直接記述されています。",
                recommendation="ルール名を外部設定または接頭辞検索に切り出してください。",
                severity="medium",
            ),
            self._issue(
                title="実行アカウントの検証処理の不足",
                issue_id="SC-002",
                source_document="collect_eb_templates.sh",
                section="コード全体",
                current_state="aws sts get-caller-identity を表示しているが期待値検証はない。",
                issue="誤ったAWSアカウントでも処理が続行されます。",
                recommendation="期待アカウントIDと一致しない場合は終了してください。",
                severity="low",
            ),
        )

        payload = build_remediation_plan(review).to_dict()

        self.assertEqual(payload["review_mode"], "code_analysis")
        self.assertIn("中重要度 1 件、低重要度 1 件", payload["summary"])
        self.assertEqual(payload["code_languages"], ["shell"])
        self.assertEqual(payload["total_count"], 2)
        self.assertEqual(payload["medium_count"], 1)
        self.assertEqual(payload["low_count"], 1)
        self.assertEqual(payload["items"][0]["review_mode"], "code_analysis")
        self.assertEqual(payload["items"][0]["code_language"], "shell")
        self.assertEqual(payload["items"][0]["basis"], "llm_with_evidence")
        self.assertEqual(payload["items"][0]["confidence"], "medium")
        self.assertIn("managed-prod-eb-rule-config", payload["items"][0]["evidence_snippet"])

    def test_source_code_plan_metadata_round_trips_from_saved_json(self) -> None:
        payload = {
            "headline": "コード確認メモ",
            "summary": "summary",
            "items": [
                {
                    "item_id": "SC-001",
                    "source_type": "review_issue",
                    "severity": "medium",
                    "title": "対象ルール名のハードコード",
                    "target_document": "collect_eb_templates.sh",
                    "target_section": "コード全体",
                    "problem": "problem",
                    "fix_policy": "fix",
                    "template": "template",
                    "re_review_scope": "collect_eb_templates.sh / コード全体",
                    "re_review_condition": "condition",
                    "effort": "中",
                    "review_mode": "code_analysis",
                    "code_language": "shell",
                    "evidence_snippet": "for r in managed-prod-eb-rule-config",
                    "evidence_line": "15",
                    "basis": "llm_with_evidence",
                    "confidence": "medium",
                }
            ],
        }

        plan = remediation_plan_from_dict(payload)
        item = plan.items[0]

        self.assertEqual(item.review_mode, "code_analysis")
        self.assertEqual(item.code_language, "shell")
        self.assertEqual(item.evidence_line, "15")
        self.assertEqual(item.basis, "llm_with_evidence")
        self.assertEqual(plan.to_dict()["code_languages"], ["shell"])

    def test_source_code_plan_uses_actionable_code_evidence_fallback(self) -> None:
        review = self._source_code_review_with_issues(
            self._issue(
                title="例外処理が広すぎる可能性",
                issue_id="SC-002",
                source_document="lambda_function.py",
                section="lambda_handler 内 / 8行目付近",
                current_state="",
                issue="Exceptionを広く捕捉している。",
                recommendation="捕捉対象と通知条件を具体化する。",
                impact="原因切り分けが遅れる。",
            )
        )

        plan = build_remediation_plan(review)
        item = plan.items[0]

        self.assertEqual(item.current_state, "対象箇所: lambda_handler 内 / 8行目付近")
        self.assertIn("対象箇所: lambda_handler 内 / 8行目付近", item.template)
        self.assertNotIn("本文から現状の記載を自動抽出できませんでした", item.template)

    def test_source_code_plan_uses_code_whole_when_section_is_generic(self) -> None:
        review = self._source_code_review_with_issues(
            self._issue(
                title="入力イベントを丸ごとログ出力している",
                issue_id="SC-003",
                source_document="lambda_function.py",
                section="該当箇所",
                current_state="",
                issue="Lambdaイベント全体をログに出している可能性があります。",
                recommendation="ログ出力を必要なキーに限定してください。",
            )
        )

        plan = build_remediation_plan(review)
        item = plan.items[0]

        self.assertEqual(item.target_section, "コード全体")
        self.assertNotIn("LLM指摘に基づく確認候補", item.target_section)

    def test_source_code_plan_derives_target_section_from_static_evidence(self) -> None:
        review = self._source_code_review_with_issues(
            self._issue(
                title="入力イベントを丸ごとログ出力している",
                issue_id="SC-004",
                source_document="lambda_function.py",
                section="該当箇所",
                current_state="lambda_handler 関数 / 12行目付近: logger.info(event)",
                issue="Lambdaイベント全体をログに出している可能性があります。",
                recommendation="ログ出力を必要なキーに限定してください。",
            )
        )

        plan = build_remediation_plan(review)
        item = plan.items[0]

        self.assertEqual(item.target_section, "lambda_handler 関数 / 12行目付近")

    def test_source_code_plan_ignores_structure_findings_even_if_passed(self) -> None:
        review = self._source_code_review_with_issues(
            self._issue(
                title="広すぎる例外捕捉",
                issue_id="SC-002",
                source_document="script.py",
                section="main",
            )
        )
        structure = StructureCheckResult(
            document_profile="design",
            document_count=1,
            detected_chapter_count=0,
            findings=(
                StructureFinding(
                    kind="required_item_gap",
                    severity="medium",
                    item_name="冒頭の目的記載",
                    message="文書冒頭に目的がありません。",
                    source_document="文書全体",
                ),
            )
        )

        plan = build_remediation_plan(review, structure)

        self.assertEqual(len(plan.items), 1)
        self.assertEqual(plan.items[0].source_type, "review_issue")
        self.assertNotIn("冒頭の目的記載", plan.to_dict()["items"][0]["title"])

    def test_extract_current_state_from_details_supports_multiple_patterns(self) -> None:
        self.assertEqual(
            _extract_current_state_from_details("【現状】状態A\n【問題点】問題B"),
            "状態A",
        )
        self.assertEqual(
            _extract_current_state_from_details("現状: 状態B\n問題点: 問題C"),
            "状態B",
        )
        self.assertEqual(
            _extract_current_state_from_details("現状の記載：状態C\n影響: 影響D"),
            "状態C",
        )
        self.assertIsNone(_extract_current_state_from_details(""))
        self.assertIsNone(_extract_current_state_from_details(None))

    def test_review_issue_origin_propagates_to_remediation_item(self) -> None:
        review = self._review_with_issues(
            self._issue(origin="document_deep_dive")
        )

        plan = build_remediation_plan(review)

        self.assertEqual(plan.items[0].origin, "document_deep_dive")

    def test_initial_review_issues_build_initial_origin_items(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001"),
            self._issue(
                issue_id="D-002",
                severity="medium",
                title="運用体制の未整理",
                section="第10章 運用",
            ),
        )

        plan = build_remediation_plan(review)

        self.assertTrue(plan.items)
        self.assertTrue(all(item.origin == "initial" for item in plan.items))

    def test_document_deep_dive_origin_is_preserved_in_mixed_plan(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", title="初回指摘"),
            self._issue(
                issue_id="DD-001",
                title="文書深堀指摘",
                origin="document_deep_dive",
            ),
        )

        plan = build_remediation_plan(review)

        origins_by_title = {item.title: item.origin for item in plan.items}
        self.assertEqual(origins_by_title["初回指摘"], "initial")
        self.assertEqual(origins_by_title["文書深堀指摘"], "document_deep_dive")

    def test_chapter_deep_dive_origin_is_preserved_in_mixed_plan(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", title="初回指摘"),
            self._issue(
                issue_id="CD-001",
                title="章深堀指摘",
                origin="chapter_deep_dive",
            ),
        )

        plan = build_remediation_plan(review)

        origins_by_title = {item.title: item.origin for item in plan.items}
        self.assertEqual(origins_by_title["初回指摘"], "initial")
        self.assertEqual(origins_by_title["章深堀指摘"], "chapter_deep_dive")

    def test_dedup_does_not_include_origin_in_key(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", origin="initial"),
            self._issue(issue_id="DD-001", origin="document_deep_dive"),
        )

        plan = build_remediation_plan(review)

        self.assertEqual(len(plan.items), 1)
        self.assertEqual(plan.items[0].origin, "initial")

    def test_build_remediation_plan_is_idempotent_for_same_review_result(self) -> None:
        review = self._review_with_issues(
            self._issue(issue_id="D-001", title="初回指摘"),
            self._issue(
                issue_id="CD-001",
                title="章深堀指摘",
                origin="chapter_deep_dive",
            ),
        )

        first = build_remediation_plan(review)
        second = build_remediation_plan(review)

        self.assertEqual(first.to_dict(), second.to_dict())

    def test_structure_findings_become_templates(self) -> None:
        review = ReviewResult(
            summary="summary",
            issues=[],
            provider="mock",
            prompt_preview="",
        )
        structure = StructureCheckResult(
            document_profile="design",
            document_count=1,
            detected_chapter_count=2,
            findings=(
                StructureFinding(
                    kind="missing_chapter",
                    severity="high",
                    message="運用設計が見当たりません。",
                    chapter_id="ch11",
                    chapter_name="運用設計",
                    expected_content="監視・アラート・バックアップ",
                ),
            ),
        )

        plan = build_remediation_plan(review, structure)

        self.assertEqual(plan.high_count, 1)
        self.assertEqual(plan.items[0].source_type, "structure_check")
        self.assertIn("運用設計", plan.items[0].title)
        self.assertIn("### 文書追記案: 運用設計", plan.items[0].template)
        self.assertIn("#### 追加する章・節の本文案", plan.items[0].template)
        self.assertIn("不足観点", plan.items[0].re_review_condition)

    def test_empty_plan_still_has_completion_step(self) -> None:
        review = ReviewResult(summary="ok", issues=[], provider="mock", prompt_preview="")

        plan = build_remediation_plan(review)

        self.assertFalse(plan.items)
        self.assertEqual(plan.headline, "大きな修正アクションはありません")
        self.assertEqual(plan.re_review_steps[0].label, "軽微確認")

    def test_saved_plan_can_be_loaded_and_compared_to_revised_document(self) -> None:
        payload = {
            "headline": "前回の修正計画",
            "summary": "summary",
            "items": [
                {
                    "item_id": "D-001",
                    "source_type": "review_issue",
                    "severity": "high",
                    "title": "DR設計の未定義",
                    "target_document": "design.pdf",
                    "target_section": "第8章 可用性",
                    "problem": "RPO/RTOがない",
                    "fix_policy": "RPO/RTOと切替手順を追記する。",
                    "template": "RPO RTO 切替手順 バックアップ リージョン",
                    "re_review_scope": "design.pdf / 第8章 可用性",
                    "re_review_condition": "高重要度指摘が解消したか確認してください。",
                    "effort": "大",
                }
            ],
        }
        plan = remediation_plan_from_dict(payload)
        revised = SanitizedDocument(
            name="design.pdf",
            original_excerpt="",
            sanitized_excerpt="",
            outbound_text="第8章 可用性\nRPO/RTO、切替手順、バックアップ、リージョン冗長化を追記した。",
        )

        report = compare_remediation_plan_to_documents(plan, [revised])

        self.assertEqual(report.total_count, 1)
        self.assertEqual(report.items[0].status, "improved")
        self.assertIn("RPO", report.items[0].evidence)


if __name__ == "__main__":
    unittest.main()
