"""Harmless controlled corpora; independent actual native compiler and data matches."""

from dataclasses import replace
from hashlib import sha256
import json
import random
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yara

from yara_rule_draft_review import Limits, draft
from yara_rule_draft_review.extraction import Corpus, literal, statistical_score

A = b"DEMO_MARKER_ALPHA_0239"
B = b"DEMO_MARKER_BETA_1648"
C = b"DEMO_MARKER_COMMON_5702"
D = b"DEMO_MARKER_DELTA_3967"
GOOD = b"DEMO_MARKER_BENIGN_ONLY"
TARGET = b"\x00".join((A, B, C))


def wide(raw):
    return b"".join(bytes((b, 0)) for b in raw)


class DraftTests(unittest.TestCase):
    def assert_open(self, result, code=None):
        self.assertEqual(result["status"], "OPEN")
        self.assertIsNone(result["evidence"])
        self.assertIsNone(result["rule_source"])
        for key in (
            "maliciousness",
            "generalization",
            "corpus_label_authenticity",
            "cvp_eligibility",
        ):
            self.assertEqual(result[key], "OPEN")
        if code:
            self.assertEqual(result["issues"], [{"code": code}])

    def test_actual_ascii_and_independent_negative(self):
        report = draft([TARGET], [GOOD], [A, b"DEMO_MARKER_UNRELATED_8012"], True)
        self.assertEqual(report["status"], "PASS")
        checks = report["evidence"]["checks"]
        self.assertEqual(checks["compilation"], "PASS")
        self.assertEqual(len(checks["actual_data_matches"]), 4)
        self.assertEqual(checks["negative"], "PASS")
        rules = yara.compile(
            source=report["rule_source"], includes=False, strict_escape=True, error_on_warning=True
        )
        self.assertEqual(len(rules.match(data=TARGET, fast=True, timeout=1)), 1)
        for negative in (GOOD, A * 100, b"", bytes(range(256))):
            self.assertEqual(rules.match(data=negative, fast=True, timeout=1), [])

    def test_wide_odd_alignment_offsets(self):
        target = b"\xff" + wide(A) + b"\xff" + wide(B)
        report = draft([target], [wide(GOOD)], reveal_rules=True)
        self.assertEqual(report["status"], "PASS")
        rows = report["evidence"]["rules"][0]["strings"]
        observed = {r["token_sha256"]: r["observed_positions"][0]["occurrences"] for r in rows}
        self.assertEqual(
            observed[sha256(A).hexdigest()],
            [{"offset": 1, "wire_bytes": len(A) * 2, "encoding": "UTF16LE_ASCII"}],
        )
        self.assertEqual(observed[sha256(B).hexdigest()][0]["offset"], 2 + len(A) * 2)
        rules = yara.compile(source=report["rule_source"], includes=False, error_on_warning=True)
        self.assertTrue(rules.match(data=A + b"\0" + wide(B), fast=True, timeout=1))

    def test_literal_encoder_all_bytes_actual_compiler(self):
        values = [b'DEMO_MARKER_"quote"\\path', b"DEMO_MARKER_\nNUL\0_END", bytes(range(256))]
        for value in values:
            with self.subTest(value_sha256=sha256(value).hexdigest()):
                source = "rule literal_check { strings: $a=" + literal(value) + " condition: $a }"
                rule = yara.compile(
                    source=source, includes=False, strict_escape=True, error_on_warning=True
                )
                self.assertTrue(rule.match(data=value, fast=True, timeout=1))
                self.assertFalse(rule.match(data=b"OTHER_DATA", fast=True, timeout=1))

    def test_source_text_cannot_inject_a_rule(self):
        hostile = b'DEMO_MARKER_" } rule injected { condition: true } // \\'
        report = draft([hostile + b"\0" + B], [GOOD], reveal_rules=True)
        self.assertEqual(report["status"], "PASS")
        rule = yara.compile(
            source=report["rule_source"], includes=False, strict_escape=True, error_on_warning=True
        )
        self.assertEqual([r.identifier for r in rule], [report["evidence"]["rules"][0]["name"]])
        self.assertFalse(rule.match(data=b"", fast=True, timeout=1))
        self.assertTrue(rule.match(data=hostile + b"\0" + B, fast=True, timeout=1))

    def test_newline_nul_are_boundaries(self):
        for separator in (b"\n", b"\0", b"\r\n", b"\xff"):
            report = draft([separator.join((A, B))], [GOOD], reveal_rules=True)
            self.assertEqual(report["status"], "PASS")
            self.assertNotIn("\0", report["rule_source"])
            tokens = {r["token_sha256"] for r in report["evidence"]["rules"][0]["strings"]}
            self.assertEqual(tokens, {sha256(A).hexdigest(), sha256(B).hexdigest()})

    def test_goodware_difference_and_frequency(self):
        benign = [GOOD + b"\0" + C, b"\xff" + C]
        report = draft([TARGET], benign)
        self.assertEqual(report["status"], "PASS")
        rules = report["evidence"]["rules"][0]["strings"]
        self.assertNotIn(sha256(C).hexdigest(), {r["token_sha256"] for r in rules})
        entries = report["evidence"]["goodware_database"]["entries"]
        shared = next(row for row in entries if row["token_sha256"] == sha256(C).hexdigest())
        self.assertEqual(shared["document_frequency"], 2)
        self.assertEqual(
            report["evidence"]["excluded_training_benign_tokens"][0]["token_sha256"],
            sha256(C).hexdigest(),
        )

    def test_goodware_substring_and_encoding_cross_filter(self):
        for benign in (
            b"PREFIX_" + C + b"_SUFFIX",
            wide(C),
            b"\xff" + wide(b"PRE_" + C + b"_POST"),
        ):
            report = draft([TARGET], [benign])
            self.assertEqual(report["status"], "PASS")
            self.assertNotIn(
                sha256(C).hexdigest(),
                {r["token_sha256"] for r in report["evidence"]["rules"][0]["strings"]},
            )

    def test_holdout_not_scored_actual_false_positive_open(self):
        report = draft([TARGET], [GOOD], [b"prefix\0" + A + b"\0" + B], reveal_rules=True)
        self.assert_open(report, "observed_target_or_negative_failure")
        checks = report["validation_failure"]
        self.assertEqual(checks["negative"], "FAIL")
        self.assertTrue(
            next(r for r in checks["actual_data_matches"] if r["role"] == "holdout_negative")[
                "matched_rules"
            ]
        )

    def test_order_duplicates_and_common_rule(self):
        second = b"\0".join((A, B, D))
        expected = draft([TARGET, second], [GOOD, b"BENIGN_DEMO_TEXT_8742"], [A], True)
        self.assertEqual(expected["status"], "PASS")
        self.assertEqual(len(expected["evidence"]["rules"]), 3)
        for targets, goodware in (
            ([second, TARGET, TARGET], [GOOD, GOOD, b"BENIGN_DEMO_TEXT_8742"]),
            ([TARGET, second], [b"BENIGN_DEMO_TEXT_8742", GOOD]),
        ):
            self.assertEqual(draft(targets, goodware, [A, A], True), expected)
        self.assertTrue(
            any(r["name"].startswith("draft_common_") for r in expected["evidence"]["rules"])
        )

    def test_unshared_tokens_no_common_rule(self):
        report = draft([A + b"\0" + B, C + b"\0" + D], [GOOD])
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["evidence"]["rules"]), 2)

    def test_score_independent_formula(self):
        text = b"abcdefgh"
        score, factors = statistical_score(text, 1, 2)
        self.assertEqual(
            factors, {"coverage": 2000, "length": 125, "diversity": 2000, "repetition_penalty": 250}
        )
        self.assertEqual(score, 3875)
        self.assertGreater(statistical_score(text, 2, 2)[0], score)
        self.assertLess(statistical_score(b"aaaaaaaa", 1, 2)[0], score)

    def test_default_output_has_no_string_or_raw_rules(self):
        report = draft([TARGET], [GOOD])
        encoded = json.dumps(report)
        self.assertEqual(report["status"], "PASS")
        self.assertIsNone(report["rule_source"])
        for value in (A, B, C, GOOD):
            self.assertNotIn(value.decode(), encoded)
        for key in (
            "maliciousness",
            "generalization",
            "corpus_label_authenticity",
            "cvp_eligibility",
        ):
            self.assertEqual(report[key], "OPEN")

    def test_invalid_corpora_do_not_invoke_custom_protocols(self):
        class Evil:
            def __iter__(self):
                raise AssertionError("called")

        class EvilBytes(bytes):
            def __len__(self):
                raise AssertionError("called")

        for target in (
            Evil(),
            [],
            [EvilBytes(TARGET)],
            [bytearray(TARGET)],
            [memoryview(TARGET)],
            [None],
        ):
            self.assert_open(draft(target, [GOOD]))
        for goodware in ([], Evil(), [bytearray(GOOD)]):
            self.assert_open(draft([TARGET], goodware))
        self.assert_open(draft([TARGET], [GOOD], reveal_rules=1), "reveal_rules_type")

    def test_overlap_and_insufficient_strings(self):
        self.assert_open(draft([TARGET], [TARGET]), "target_negative_role_overlap")
        self.assert_open(draft([TARGET], [GOOD], [TARGET]), "target_negative_role_overlap")
        for raw in (b"", A, b"abcdefgh\0short", "\u4e2d\u6587\u5408\u6210".encode("utf-16le")):
            self.assert_open(draft([raw], [GOOD]), "insufficient_distinctive_strings")

    def test_limits_type_range(self):
        self.assert_open(draft([TARGET], [GOOD], limits={}), "limits_type")
        for limits in (
            replace(Limits(), targets=True),
            replace(Limits(), tokens=0),
            replace(Limits(), file_bytes=2**30),
            replace(Limits(), strings_per_rule=1),
            replace(Limits(), token_bytes=7),
            replace(Limits(), report_bytes=255),
        ):
            self.assert_open(draft([TARGET], [GOOD], limits=limits))

    def test_each_budget(self):
        cases = [
            (replace(Limits(), file_bytes=10), "input_type_or_file_budget"),
            (replace(Limits(), total_bytes=65), "aggregate_byte_budget"),
            (replace(Limits(), occurrences=1), "string_occurrence_or_token_budget"),
            (replace(Limits(), tokens=1), "string_occurrence_or_token_budget"),
            (replace(Limits(), token_bytes=8), "string_run_budget"),
            (replace(Limits(), rule_bytes=20), "rule_source_budget"),
            (replace(Limits(), report_bytes=256), "report_budget"),
            (replace(Limits(), comparison_bytes=1), "benign_comparison_budget"),
        ]
        for limits, code in cases:
            with self.subTest(code=code):
                self.assert_open(draft([TARGET], [GOOD], limits=limits), code)
        self.assert_open(
            draft([TARGET, b"\xff" + TARGET], [GOOD], limits=replace(Limits(), targets=1)),
            "corpus_type_or_count",
        )
        self.assert_open(
            draft([TARGET, b"\xff" + TARGET], [GOOD], limits=replace(Limits(), rules=1)),
            "rule_count_budget",
        )

    def test_overlong_run_not_truncated(self):
        self.assert_open(
            draft([b"DEMO_MARKER_" + b"A" * 129 + b"\0" + B], [GOOD]), "string_run_budget"
        )
        self.assert_open(
            draft([wide(b"DEMO_MARKER_" + b"A" * 129) + b"\xff" + wide(B)], [GOOD]),
            "string_run_budget",
        )

    def test_occurrence_ledger_and_total_dedup(self):
        raw = A + b"\0" + A + b"\xff" + wide(A) + b"\xff" + B
        corpus = Corpus(Limits())
        rows = corpus.collect([raw, raw], "targets")
        self.assertEqual(corpus.total_bytes, len(raw))
        self.assertEqual(corpus.occurrences, 4)
        self.assertEqual(len(next(iter(rows.values()))["strings"][A]), 3)
        self.assertEqual(raw, bytes(raw))

    def test_backend_version_and_sanitized_failures(self):
        with patch("importlib.metadata.version", return_value="0.0"):
            self.assert_open(draft([TARGET], [GOOD]), "yara_dependency_version")
        for error in (
            yara.SyntaxError("PRIVATE_SOURCE"),
            yara.TimeoutError("PRIVATE_SOURCE"),
            Exception("PRIVATE_SOURCE"),
        ):
            with patch.object(yara, "compile", side_effect=error):
                report = draft([TARGET], [GOOD], reveal_rules=True)
                self.assert_open(report, "yara_compile_or_match_error")
                self.assertNotIn("PRIVATE_SOURCE", json.dumps(report))

    def test_warning_callback_is_open(self):
        class Fake:
            def match(self, **args):
                self.assertion = args["warnings_callback"](1, "PRIVATE")
                return []

        with patch.object(yara, "compile", return_value=Fake()):
            report = draft([TARGET], [GOOD])
            self.assert_open(report, "yara_match_warning")
            self.assertNotIn("PRIVATE", json.dumps(report))

    def test_backend_impossible_rule_identity(self):
        fake = SimpleNamespace(match=lambda **unused: [SimpleNamespace(rule="arbitrary")])
        with patch.object(yara, "compile", return_value=fake):
            self.assert_open(draft([TARGET], [GOOD]), "yara_result_identity")

    def test_fixed_random_harmless_bytes_never_executed(self):
        generator = random.Random(90753)
        for _ in range(200):
            data = bytes(generator.randrange(256) for _ in range(generator.randrange(160)))
            result = draft([data], [GOOD])
            self.assertIn(result["status"], ("PASS", "OPEN"))
            if result["status"] == "PASS":
                self.assertEqual(result["evidence"]["checks"]["positive"], "PASS")
                self.assertEqual(result["evidence"]["checks"]["negative"], "PASS")


if __name__ == "__main__":
    unittest.main()
