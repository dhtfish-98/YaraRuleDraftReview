"""Verify complete pinned source-embedded notices, including Bison exception blocks."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import tarfile

SDIST_SHA256 = "4c682170f3d5cb3a73aa1bd0dc9ab1c0957437b937b7a83ff6d7ffd366415b9c"


def notices(archive):
    entries = {}
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            if (
                not member.isfile()
                or not member.name.endswith((".c", ".h", ".l", ".y"))
                or "/tests/" in member.name
            ):
                continue
            raw = source.extractfile(member).read()
            for match in re.finditer(rb"/\*.*?\*/", raw, re.S):
                comment = match.group()
                if any(
                    key in comment
                    for key in (
                        b"Redistribution and use",
                        b"Permission is hereby granted",
                        b"General Public License",
                        b"Licensed under the Apache",
                        b"special exception",
                    )
                ):
                    digest = sha256(comment).hexdigest()
                    row = entries.setdefault(digest, {"bytes": comment, "source": []})
                    row["source"].append(member.name)
    result = []
    for digest, row in sorted(entries.items()):
        prefix = (
            "Original embedded notice SHA256 " + digest + "\n" + "\n".join(row["source"]) + "\n\n"
        ).encode()
        result.append(prefix + row["bytes"] + b"\n\n")
    return b"".join(result), entries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    assert args.archive.stat().st_size == 551142
    assert sha256(args.archive.read_bytes()).hexdigest() == SDIST_SHA256
    raw, entries = notices(args.archive)
    assert raw == (args.root / "licenses/yara-python-embedded-notices.txt").read_bytes()
    assert b"As a special exception" in raw and b"larger work" in raw
    identity = json.loads((args.root / "DEPENDENCY_AUDIT.json").read_text())
    assert len(entries) == identity["license_supplement"]["distinct_original_embedded_comments"]
    uses = sum(len(row["source"]) for row in entries.values())
    assert uses == identity["license_supplement"]["original_uses"]
    for entry in identity["license_files"]:
        data = (args.root / entry["path"]).read_bytes()
        assert len(data) == entry["bytes"] and sha256(data).hexdigest() == entry["sha256"]
    print(
        json.dumps(
            {
                "status": "PASS",
                "distinct_embedded_comments": len(entries),
                "original_uses": uses,
                "full_bison_exception_preserved": True,
                "notice_sha256": sha256(raw).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
