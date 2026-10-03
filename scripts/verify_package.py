"""Check wheel/sdist/consumer bytes, metadata, RECORD and original notices."""

from email import policy
import argparse
import base64
import csv
from email import message_from_bytes
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import tomllib
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--installed", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    config = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = config["version"]
    prefix = f"yara_rule_draft_review-{version}"
    wheel = root / f"dist/{prefix}-py3-none-any.whl"
    sdist = root / f"dist/{prefix}.tar.gz"
    manifest = json.loads((root / "SOURCE_MANIFEST.json").read_text())
    assert manifest["version"] == version
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert all(not name.startswith("/") and ".." not in name.split("/") for name in names)
        metadata_name = f"{prefix}.dist-info/METADATA"
        metadata = message_from_bytes(archive.read(metadata_name), policy=policy.default)
        assert metadata["Name"] == "yara-rule-draft-review" and metadata["Version"] == version
        assert metadata["License-Expression"] == "Apache-2.0"
        assert metadata.get_all("Requires-Dist") == ["yara-python==4.5.4"]
        records = list(csv.reader(io.StringIO(archive.read(f"{prefix}.dist-info/RECORD").decode())))
        assert {row[0] for row in records} == set(names)
        for name, digest, length in records:
            if name.endswith("/RECORD"):
                assert digest == length == ""
                continue
            raw = archive.read(name)
            assert len(raw) == int(length)
            assert digest == "sha256=" + base64.urlsafe_b64encode(
                sha256(raw).digest()
            ).decode().rstrip("=")
        for file in (root / "src/yara_rule_draft_review").iterdir():
            if file.is_file():
                member = "yara_rule_draft_review/" + file.name
                assert archive.read(member) == file.read_bytes()
                if args.installed:
                    assert (args.installed / member).read_bytes() == file.read_bytes()
        license_paths = ["项目文档/LICENSE", "项目文档/NOTICE"] + [
            str(file.relative_to(root)) for file in sorted((root / "licenses").glob("*.txt"))
        ]
        for name in license_paths:
            member = f"{prefix}.dist-info/licenses/" + name
            assert archive.read(member) == (root / name).read_bytes()
            if args.installed:
                assert (args.installed / member).read_bytes() == (root / name).read_bytes()
        forbidden = ("validation-local/", ".venv/", "__pycache__/", ".git/", "tests/", "scripts/")
        assert all(not any(value in name for value in forbidden) for name in names)
    with tarfile.open(sdist, "r:gz") as archive:
        members = {row.name: row for row in archive.getmembers()}
        assert len(members) == len(archive.getmembers())
        for row in manifest["files"]:
            path = root / row["path"]
            raw = path.read_bytes()
            assert len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"]
            if row["path"] == ".gitignore":
                continue
            member = f"{prefix}/" + row["path"]
            assert members[member].isreg() and archive.extractfile(members[member]).read() == raw
        assert all(
            not any(
                value in name for value in ("validation-local/", ".venv/", "__pycache__/", ".git/")
            )
            for name in members
        )
        assert all(row.isfile() or row.isdir() for row in members.values())
    print(
        json.dumps(
            {
                "status": "PASS",
                "record_rows": len(records),
                "license_files": len(license_paths),
                "formal_manifest_files": len(manifest["files"]),
                "installed_bytes_checked": bool(args.installed),
                "wheel_sha256": sha256(wheel.read_bytes()).hexdigest(),
                "sdist_sha256": sha256(sdist.read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
