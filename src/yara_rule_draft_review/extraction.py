"""Linear fixed ASCII / ASCII code points represented as UTF-16LE string profile."""

from collections import Counter
from hashlib import sha256
import re

from .model import MIN_TOKEN_BYTES, Issue

ASCII = re.compile(rb"[\x20-\x7e]{8,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")


class Corpus:
    def __init__(self, limits):
        self.limits = limits
        self.total_bytes = 0
        self.occurrences = 0
        self.tokens = set()

    def collect(self, supplied, role, minimum=True):
        maximum = getattr(self.limits, role)
        if type(supplied) not in (tuple, list) or not (int(minimum) <= len(supplied) <= maximum):
            raise Issue("corpus_type_or_count")
        unique = {}
        for raw in supplied:
            if type(raw) is not bytes or len(raw) > self.limits.file_bytes:
                raise Issue("input_type_or_file_budget")
            digest = sha256(raw).hexdigest()
            if digest in unique and unique[digest] != raw:
                raise Issue("digest_collision")
            unique[digest] = raw
        self.total_bytes += sum(len(raw) for raw in unique.values())
        if self.total_bytes > self.limits.total_bytes:
            raise Issue("aggregate_byte_budget")
        return {
            digest: {"bytes": raw, "strings": self.extract(raw)}
            for digest, raw in sorted(unique.items())
        }

    def extract(self, raw):
        strings = {}
        for expression, encoding in ((ASCII, "ASCII"), (WIDE, "UTF16LE_ASCII")):
            for match in expression.finditer(raw):
                wire = match.group()
                text = wire if encoding == "ASCII" else wire[::2]
                if len(text) > self.limits.token_bytes:
                    raise Issue("string_run_budget")
                if len(text) < MIN_TOKEN_BYTES:
                    raise Issue("internal_string_profile")
                self.occurrences += 1
                self.tokens.add(text)
                if (
                    self.occurrences > self.limits.occurrences
                    or len(self.tokens) > self.limits.tokens
                ):
                    raise Issue("string_occurrence_or_token_budget")
                strings.setdefault(text, []).append(
                    {"offset": match.start(), "wire_bytes": len(wire), "encoding": encoding}
                )
        return dict(sorted(strings.items()))


def statistical_score(text, support, targets):
    """Transparent integer ranking, not maliciousness or a calibrated probability."""
    counts = Counter(text)
    factors = {
        "coverage": support * 4000 // targets,
        "length": len(text) * 2000 // 128,
        "diversity": len(counts) * 2000 // len(text),
        "repetition_penalty": max(counts.values()) * 2000 // len(text),
    }
    return factors["coverage"] + factors["length"] + factors["diversity"] - factors[
        "repetition_penalty"
    ], factors


def literal(text):
    """Byte-preserving YARA quoted literal, with no interpolation or decoded code."""
    output = []
    for byte in text:
        if byte == 34:
            output.append('\\"')
        elif byte == 92:
            output.append("\\\\")
        elif 32 <= byte <= 126:
            output.append(chr(byte))
        else:
            output.append(f"\\x{byte:02X}")
    return '"' + "".join(output) + '"'
