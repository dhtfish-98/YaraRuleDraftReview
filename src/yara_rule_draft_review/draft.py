"""Independent supplied-goodware difference, deterministic ranking and literal rule draft."""

from hashlib import sha256
import json

from .engine import validate
from .extraction import Corpus, literal, statistical_score
from .model import DEFAULT_LIMITS, Issue, check_limits


def base_report():
    return {
        "schema_version": 1,
        "status": "OPEN",
        "issues": [],
        "evidence": None,
        "rule_source": None,
        "maliciousness": "OPEN",
        "generalization": "OPEN",
        "corpus_label_authenticity": "OPEN",
        "cvp_eligibility": "OPEN",
        "ai_assisted": True,
    }


def fingerprint(digests):
    return sha256("\n".join(sorted(digests)).encode("ascii")).hexdigest()


def create_rules(targets, benign, limits):
    goodware = {}
    support = {}
    for digest, sample in benign.items():
        for text in sample["strings"]:
            goodware.setdefault(text, []).append(digest)
    for digest, sample in targets.items():
        for text in sample["strings"]:
            support.setdefault(text, []).append(digest)
    candidates = []
    excluded = []
    comparison_bytes = 0
    for text, sources in sorted(support.items()):
        wire_wide = b"".join(bytes([byte, 0]) for byte in text)
        lexical = goodware.get(text, [])
        contained = []
        if not lexical:
            for digest, sample in benign.items():
                comparison_bytes += 2 * len(sample["bytes"])
                if comparison_bytes > limits.comparison_bytes:
                    raise Issue("benign_comparison_budget")
                if text in sample["bytes"] or wire_wide in sample["bytes"]:
                    contained.append(digest)
        if lexical or contained:
            excluded.append(
                {
                    "token_sha256": sha256(text).hexdigest(),
                    "training_benign_sha256": sorted(set(lexical + contained)),
                }
            )
            continue
        score, factors = statistical_score(text, len(sources), len(targets))
        candidates.append(
            {"text": text, "target_sha256": sources, "score": score, "factors": factors}
        )
    candidates.sort(key=lambda row: (-row["score"], row["text"]))
    groups = [
        ("draft_" + digest, [digest], [row for row in candidates if digest in row["target_sha256"]])
        for digest in targets
    ]
    common = [row for row in candidates if len(row["target_sha256"]) == len(targets)]
    if len(targets) > 1 and len(common) >= 2:
        groups.append(("draft_common_" + fingerprint(targets), list(targets), common))
    if len(groups) > limits.rules:
        raise Issue("rule_count_budget")
    rules, source = [], []
    goodware_id = fingerprint(benign)
    for name, sources, rows in groups:
        selected = rows[: limits.strings_per_rule]
        if len(selected) < 2:
            raise Issue("insufficient_distinctive_strings")
        lines = [
            f"rule {name} {{",
            "  meta:",
            '    description = "AI assisted detection draft; maliciousness and generalization OPEN"',
            f'    target_corpus_sha256 = "{fingerprint(sources)}"',
            f'    training_benign_corpus_sha256 = "{goodware_id}"',
            "    draft = true",
            "  strings:",
        ]
        selected_rows = []
        for i, row in enumerate(selected):
            text = row["text"]
            lines.append(f"    $s{i + 1} = {literal(text)} ascii wide")
            provenance = [
                {"sha256": digest, "occurrences": targets[digest]["strings"][text]}
                for digest in row["target_sha256"]
            ]
            selected_rows.append(
                {
                    "id": "$s" + str(i + 1),
                    "token_sha256": sha256(text).hexdigest(),
                    "ascii_bytes": len(text),
                    "score": row["score"],
                    "score_factors": row["factors"],
                    "confidence": "UNCALIBRATED_HEURISTIC",
                    "target_sha256": row["target_sha256"],
                    "observed_positions": provenance,
                }
            )
        lines.extend(["  condition:", f"    filesize <= {limits.file_bytes} and 2 of them", "}"])
        source.append("\n".join(lines))
        rules.append(
            {
                "name": name,
                "target_sha256": sources,
                "strings": selected_rows,
                "condition": "bounded_filesize_and_two_distinct_literals",
                "generalization": "OPEN",
            }
        )
    bundle = "\n\n".join(source) + "\n"
    if len(bundle.encode()) > limits.rule_bytes:
        raise Issue("rule_source_budget")
    database = {
        "training_sample_sha256": list(benign),
        "corpus_sha256": goodware_id,
        "entries": [
            {
                "token_sha256": sha256(text).hexdigest(),
                "ascii_bytes": len(text),
                "document_frequency": len(sources),
                "source_sha256": sources,
            }
            for text, sources in sorted(goodware.items())
        ],
        "storage": "READ_ONLY_IN_MEMORY",
        "label_authenticity": "OPEN",
    }
    return bundle, rules, database, excluded


def draft(targets, benign, negatives=(), reveal_rules=False, limits=DEFAULT_LIMITS):
    """Generate and actually validate rules from explicit immutable byte corpora only."""
    report = base_report()
    report_limit = DEFAULT_LIMITS.report_bytes
    try:
        check_limits(limits)
        report_limit = limits.report_bytes
        if type(reveal_rules) is not bool:
            raise Issue("reveal_rules_type")
        corpus = Corpus(limits)
        target = corpus.collect(targets, "targets")
        goodware = corpus.collect(benign, "benign")
        controls = corpus.collect(negatives, "negatives", minimum=False)
        if set(target) & (set(goodware) | set(controls)):
            raise Issue("target_negative_role_overlap")
        source, rules, database, excluded = create_rules(target, goodware, limits)
        checks = validate(source, rules, target, goodware, controls, limits)
        if checks["positive"] != "PASS" or checks["negative"] != "PASS":
            report["validation_failure"] = checks
            raise Issue("observed_target_or_negative_failure")
        report["status"] = "PASS"
        report["evidence"] = {
            "target_sha256": list(target),
            "training_benign_sha256": list(goodware),
            "holdout_negative_sha256": list(controls),
            "goodware_database": database,
            "rules": rules,
            "excluded_training_benign_tokens": excluded,
            "rule_source_sha256": sha256(source.encode()).hexdigest(),
            "rule_source_bytes": len(source.encode()),
            "checks": checks,
            "string_profile": "ASCII printable maximal runs and ASCII code points represented as UTF16LE, minimum8; all other encoding/content semantics OPEN",
        }
        if reveal_rules:
            report["rule_source"] = source
    except Issue as error:
        report["status"] = "OPEN"
        report["issues"] = [{"code": error.code}]
        report["evidence"] = None
        report["rule_source"] = None
    if len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) > report_limit:
        return {
            "schema_version": 1,
            "status": "OPEN",
            "issues": [{"code": "report_budget"}],
            "evidence": None,
            "rule_source": None,
            "maliciousness": "OPEN",
            "generalization": "OPEN",
            "corpus_label_authenticity": "OPEN",
            "cvp_eligibility": "OPEN",
            "ai_assisted": True,
        }
    return report
