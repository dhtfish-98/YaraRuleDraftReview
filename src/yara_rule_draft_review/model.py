"""Finite lower-only budgets; safe fixed-code failures."""

from dataclasses import dataclass, fields


class Issue(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 1024 * 1024
    total_bytes: int = 8 * 1024 * 1024
    targets: int = 16
    benign: int = 16
    negatives: int = 16
    occurrences: int = 8192
    tokens: int = 8192
    token_bytes: int = 128
    strings_per_rule: int = 12
    rules: int = 17
    rule_bytes: int = 256 * 1024
    report_bytes: int = 1024 * 1024
    match_timeout_seconds: int = 1
    comparison_bytes: int = 64 * 1024 * 1024


DEFAULT_LIMITS = Limits()
MIN_TOKEN_BYTES = 8


def check_limits(limits):
    if type(limits) is not Limits:
        raise Issue("limits_type")
    for field in fields(Limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not 0 < value <= getattr(DEFAULT_LIMITS, field.name):
            raise Issue("limits_range")
    if (
        limits.token_bytes < MIN_TOKEN_BYTES
        or limits.strings_per_rule < 2
        or limits.report_bytes < 256
    ):
        raise Issue("limits_minimum")
