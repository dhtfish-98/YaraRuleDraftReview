"""Only compile internally generated literal rules; only match explicitly supplied bytes."""

import importlib.metadata

from .model import Issue


def validate(source, rules, targets, benign, negatives, limits):
    try:
        import yara
    except (ImportError, OSError):
        raise Issue("yara_dependency_unavailable") from None
    try:
        if (
            importlib.metadata.version("yara-python") != "4.5.4"
            or yara.__version__ != "4.5.4"
            or yara.YARA_VERSION != "4.5.4"
        ):
            raise Issue("yara_dependency_version")
        compiled = yara.compile(
            source=source, includes=False, error_on_warning=True, strict_escape=True
        )
        seen_warning = []

        def warning_callback(*unused):
            seen_warning.append(True)
            return yara.CALLBACK_ABORT

        rows = []
        rule_names = {row["name"] for row in rules}
        for role, corpus in (
            ("target", targets),
            ("training_benign", benign),
            ("holdout_negative", negatives),
        ):
            for digest, sample in corpus.items():
                matches = compiled.match(
                    data=sample["bytes"],
                    fast=True,
                    timeout=limits.match_timeout_seconds,
                    warnings_callback=warning_callback,
                )
                if seen_warning:
                    raise Issue("yara_match_warning")
                names = sorted(match.rule for match in matches)
                if not set(names) <= rule_names or len(names) != len(set(names)):
                    raise Issue("yara_result_identity")
                expected = {row["name"] for row in rules if digest in row["target_sha256"]}
                valid = bool(names) and expected <= set(names) if role == "target" else not names
                rows.append(
                    {
                        "role": role,
                        "sha256": digest,
                        "bytes": len(sample["bytes"]),
                        "matched_rules": names,
                        "expected_rules": sorted(expected),
                        "status": "PASS" if valid else "FAIL",
                    }
                )
        return {
            "compilation": "PASS",
            "engine": "yara-python==4.5.4 / libyara4.5.4",
            "actual_data_matches": rows,
            "positive": "PASS"
            if all(row["status"] == "PASS" for row in rows if row["role"] == "target")
            else "FAIL",
            "negative": "PASS"
            if all(row["status"] == "PASS" for row in rows if row["role"] != "target")
            else "FAIL",
            "generalization": "OPEN",
            "maliciousness": "OPEN",
        }
    except importlib.metadata.PackageNotFoundError:
        raise Issue("yara_dependency_unavailable") from None
    except Issue:
        raise
    except Exception:
        raise Issue("yara_compile_or_match_error") from None
