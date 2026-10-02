"""Offline byte-corpus CLI; fixed errors never echo paths or engine diagnostics."""

import argparse
from hashlib import sha256
import json
import sys

from .draft import base_report, draft
from .files import read_local
from .model import DEFAULT_LIMITS, Issue
from .output import write_draft


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Issue("cli_arguments")


def main(argv=None):
    report = base_report()
    try:
        parser = Parser(
            description="Draft literal YARA detection rules from explicit local corpora."
        )
        parser.add_argument("--target", action="append", required=True)
        parser.add_argument("--benign", action="append", required=True)
        parser.add_argument("--negative", action="append", default=[])
        parser.add_argument("--reveal-rules", action="store_true")
        parser.add_argument("--output-dir")
        args = parser.parse_args(argv)
        if not (
            1 <= len(args.target) <= DEFAULT_LIMITS.targets
            and 1 <= len(args.benign) <= DEFAULT_LIMITS.benign
            and len(args.negative) <= DEFAULT_LIMITS.negatives
        ):
            raise Issue("corpus_type_or_count")
        total = 0
        corpora = []
        for paths in (args.target, args.benign, args.negative):
            corpus = []
            seen = set()
            for path in paths:
                raw = read_local(path)
                digest = sha256(raw).hexdigest()
                if digest not in seen:
                    total += len(raw)
                    seen.add(digest)
                if total > DEFAULT_LIMITS.total_bytes:
                    raise Issue("aggregate_byte_budget")
                corpus.append(raw)
            corpora.append(corpus)
        report = draft(*corpora, reveal_rules=args.reveal_rules or args.output_dir is not None)
        if args.output_dir is not None and report["status"] == "PASS":
            output = write_draft(
                report["rule_source"], args.output_dir, args.target + args.benign + args.negative
            )
            report["output"] = output
            if output["status"] != "PASS":
                report["status"] = "OPEN"
                report["issues"] = [{"code": "output_unconfirmed"}]
        if not args.reveal_rules:
            report["rule_source"] = None
    except Issue as error:
        report = base_report()
        report["issues"] = [{"code": error.code}]
    rendered = json.dumps(report, ensure_ascii=True, separators=(",", ":"))
    if len(rendered.encode()) > DEFAULT_LIMITS.report_bytes:
        report = base_report()
        report["issues"] = [{"code": "report_budget"}]
        rendered = json.dumps(report, separators=(",", ":"))
    try:
        sys.stdout.write(rendered + "\n")
    except (OSError, UnicodeError):
        return 2
    return 0 if report["status"] == "PASS" else 2
