from __future__ import annotations

import unittest

from streamlit_audit_ui import (
    HISTORY_DEFAULT_LIMIT,
    _select_history_terms_for_display,
    _sort_history_terms,
    _split_history_terms_by_recommendation,
)


def _entry(total: int, mask_count: int | None = None) -> dict[str, int | float]:
    mask = total if mask_count is None else mask_count
    skip = max(total - mask, 0)
    ratio = (mask / total) if total else 0.0
    return {
        "mask_count": mask,
        "skip_count": skip,
        "total": total,
        "mask_ratio": ratio,
    }


class AuditUiHistoryDisplayTests(unittest.TestCase):
    def test_sort_history_terms_uses_total_descending(self) -> None:
        sorted_terms = _sort_history_terms(
            {
                "term_low": _entry(1),
                "term_high": _entry(9),
                "term_mid": _entry(5),
            }
        )

        self.assertEqual([term for term, _ in sorted_terms], ["term_high", "term_mid", "term_low"])

    def test_under_limit_shows_all_without_more_button_state(self) -> None:
        terms = [(f"term_{idx}", _entry(idx + 1)) for idx in range(HISTORY_DEFAULT_LIMIT)]

        display_terms, remaining, is_limited = _select_history_terms_for_display(
            terms,
            expanded=False,
        )

        self.assertEqual(display_terms, terms)
        self.assertEqual(remaining, 0)
        self.assertFalse(is_limited)

    def test_over_limit_defaults_to_top_ten(self) -> None:
        terms = [(f"term_{idx}", _entry(20 - idx)) for idx in range(HISTORY_DEFAULT_LIMIT + 2)]

        display_terms, remaining, is_limited = _select_history_terms_for_display(
            terms,
            expanded=False,
        )

        self.assertEqual(display_terms, terms[:HISTORY_DEFAULT_LIMIT])
        self.assertEqual(remaining, 2)
        self.assertTrue(is_limited)

    def test_expanded_state_shows_all_terms(self) -> None:
        terms = [(f"term_{idx}", _entry(20 - idx)) for idx in range(HISTORY_DEFAULT_LIMIT + 2)]

        display_terms, remaining, is_limited = _select_history_terms_for_display(
            terms,
            expanded=True,
        )

        self.assertEqual(display_terms, terms)
        self.assertEqual(remaining, 0)
        self.assertFalse(is_limited)

    def test_recommendation_split_preserves_display_subset(self) -> None:
        promote_mask, promote_skip, context_dep, insufficient = _split_history_terms_by_recommendation(
            [
                ("mask", _entry(5, 5)),
                ("skip", _entry(5, 0)),
                ("mixed", _entry(10, 5)),
                ("few", _entry(2, 2)),
            ]
        )

        self.assertEqual([term for term, _ in promote_mask], ["mask"])
        self.assertEqual([term for term, _ in promote_skip], ["skip"])
        self.assertEqual([term for term, _ in context_dep], ["mixed"])
        self.assertEqual([term for term, _ in insufficient], ["few"])


if __name__ == "__main__":
    unittest.main()
