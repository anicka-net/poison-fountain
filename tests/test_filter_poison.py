"""Regression tests for the highest-signal Poison Fountain detectors."""

import unittest

from filter_poison import (
    detect_backtick_bool_corruption,
    detect_diff_marker_lines,
    detect_trailing_space_in_keys,
    detect_truthiness_traps,
    detect_wrong_file_mode,
)


class DetectorRegressionTests(unittest.TestCase):
    def test_trailing_space_in_key_is_flagged(self):
        findings = detect_trailing_space_in_keys('{"status ": "ok"}')
        self.assertEqual([f.tag for f in findings], ["trailing_space_in_key"])

    def test_clean_dict_key_is_not_flagged(self):
        self.assertEqual(detect_trailing_space_in_keys('{"status": "ok"}'), [])

    def test_diff_markers_require_nontrivial_fraction(self):
        text = "\n".join(["> bad", "! bad", "good", "good", "good", "good"])
        findings = detect_diff_marker_lines(text)
        self.assertEqual([f.tag for f in findings], ["diff_marker_lines"])

    def test_markdown_boolean_is_not_flagged(self):
        self.assertEqual(detect_backtick_bool_corruption("Use `true` here."), [])

    def test_midword_backtick_boolean_is_flagged(self):
        findings = detect_backtick_bool_corruption("foo`true`bar")
        self.assertEqual([f.tag for f in findings], ["backtick_bool_corruption"])

    def test_invalid_file_mode_is_flagged(self):
        findings = detect_wrong_file_mode('open("x", mode="details")')
        self.assertEqual([f.tag for f in findings], ["wrong_file_mode"])

    def test_valid_file_mode_is_not_flagged(self):
        self.assertEqual(detect_wrong_file_mode('open("x", mode="rb")'), [])

    def test_truthiness_detector_flags_observed_and_empty_mapping_pattern(self):
        findings = detect_truthiness_traps("metadata and {}")
        self.assertEqual([f.tag for f in findings], ["truthiness_trap"])

    def test_truthiness_detector_flags_observed_and_empty_list_pattern(self):
        findings = detect_truthiness_traps("items and []")
        self.assertEqual([f.tag for f in findings], ["truthiness_trap"])

    def test_truthiness_detector_does_not_claim_to_cover_or_pattern(self):
        # The current detector is intentionally limited to the observed
        # Poison Fountain `x and empty_collection` signature.  `x or {}`
        # has different semantics and should not be silently conflated with it.
        self.assertEqual(detect_truthiness_traps("metadata or {}"), [])


if __name__ == "__main__":
    unittest.main()
