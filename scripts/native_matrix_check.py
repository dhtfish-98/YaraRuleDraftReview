"""Independent native compilation/data-match assertions on harmless synthetic corpus."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

import yara

from yara_rule_draft_review import draft


def wide(text):
    return b"".join(bytes((value, 0)) for value in text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report")
    args = parser.parse_args()
    cases = []
    data_checks = 0
    for encoding in ("ascii", "wide", "mixed"):
        for count in (1, 2, 4, 8):
            first = b'DEMO_MARKER_SHARED_"QUOTED"_2387'
            second = b"DEMO_MARKER_SHARED_\\PATH_5096"
            shared_good = b"DEMO_MARKER_SHARED_BENIGN_9341"
            targets = []
            for index in range(count):
                tokens = [first, second, shared_good, f"DEMO_MARKER_TARGET_{index}_6815".encode()]
                if encoding == "wide":
                    tokens = [wide(text) for text in tokens]
                elif encoding == "mixed":
                    tokens = [text if i % 2 == 0 else wide(text) for i, text in enumerate(tokens)]
                targets.append(b"\xff".join(tokens))
            benign = [
                shared_good,
                b"BENIGN_DEMO_TEXT_8701",
                b"PREFIX_" + shared_good + b"_SUFFIX",
                wide(shared_good),
            ]
            negatives = [
                b"",
                first,
                second,
                wide(first),
                wide(second),
                b"UNSEEN_BENIGN_DEMO_DATA_7983",
            ]
            report = draft(targets, benign, negatives, reveal_rules=True)
            assert report["status"] == "PASS", report["issues"]
            compiled = yara.compile(
                source=report["rule_source"],
                includes=False,
                error_on_warning=True,
                strict_escape=True,
            )
            actual_names = {rule.identifier for rule in compiled}
            assert actual_names == {rule["name"] for rule in report["evidence"]["rules"]}
            for target in targets:
                matches = compiled.match(data=target, fast=True, timeout=1)
                assert matches
                name = "draft_" + sha256(target).hexdigest()
                assert name in {match.rule for match in matches}
                data_checks += 1
            for raw in benign + negatives:
                assert compiled.match(data=raw, fast=True, timeout=1) == []
                data_checks += 1
            false_positive = first + b"\xff" + second
            assert compiled.match(data=false_positive, fast=True, timeout=1)
            failure = draft(targets, benign, [false_positive], reveal_rules=True)
            assert (
                failure["status"] == "OPEN"
                and failure["evidence"] is None
                and failure["rule_source"] is None
            )
            data_checks += 1
            cases.append(
                {
                    "encoding": encoding,
                    "targets": count,
                    "generated_rules": len(actual_names),
                    "independent_compilation": "PASS",
                    "independent_target_and_negative_matches": "PASS",
                    "false_positive_control": "OPEN_AS_EXPECTED",
                    "rule_source_sha256": report["evidence"]["rule_source_sha256"],
                }
            )
    result = {
        "status": "PASS",
        "synthetic_corpus_cases": len(cases),
        "direct_native_data_checks": data_checks,
        "engine": {"binding": yara.__version__, "libyara": yara.YARA_VERSION},
        "cases": cases,
        "sample_execution": False,
        "generalization": "OPEN",
        "maliciousness": "OPEN",
    }
    if args.report:
        Path(args.report).write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps({key: value for key, value in result.items() if key != "cases"}, sort_keys=True)
    )


if __name__ == "__main__":
    main()
