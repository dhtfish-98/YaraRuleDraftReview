"""Actual installed CLI only, run outside the source tree in a fresh consumer."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def run(arguments):
    completed = subprocess.run(
        [sys.executable, "-I", "-m", "yara_rule_draft_review", *arguments],
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert completed.stderr == b"", completed.stderr
    report = json.loads(completed.stdout)
    assert completed.returncode == (0 if report["status"] == "PASS" else 2)
    assert "PRIVATE_FILENAME" not in completed.stdout.decode()
    return report


def main():
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary).resolve()
        target = folder / "PRIVATE_FILENAME_TARGET"
        goodware = folder / "PRIVATE_FILENAME_BENIGN"
        holdout = folder / "PRIVATE_FILENAME_HOLDOUT"
        out = folder / "drafts"
        out.mkdir()
        raw = b"DEMO_MARKER_ALPHA_0239\0DEMO_MARKER_BETA_1648"
        target.write_bytes(raw)
        goodware.write_bytes(b"DEMO_MARKER_BENIGN_ONLY")
        holdout.write_bytes(b"\xff" + raw)
        arguments = ["--target", str(target), "--benign", str(goodware)]
        normal = run(arguments)
        assert normal["status"] == "PASS" and normal["rule_source"] is None
        assert "DEMO_MARKER" not in json.dumps(normal)
        reveal = run(arguments + ["--reveal-rules"])
        assert reveal["status"] == "PASS" and "DEMO_MARKER_ALPHA" in reveal["rule_source"]
        generated = run(arguments + ["--output-dir", str(out)])
        assert generated["status"] == "PASS" and generated["rule_source"] is None
        artifact = out / generated["output"]["name"]
        assert artifact.read_text() == reveal["rule_source"]
        assert sha256(artifact.read_bytes()).hexdigest() == normal["evidence"]["rule_source_sha256"]
        assert run(arguments + ["--output-dir", str(out)])["status"] == "OPEN"
        assert run(arguments + ["--negative", str(holdout)])["status"] == "OPEN"
        assert (
            run(["--target", "PRIVATE_FILENAME_MISSING", "--benign", str(goodware)])["status"]
            == "OPEN"
        )
        assert run(arguments + ["--PRIVATE_FILENAME_BAD_ARGUMENT"])["status"] == "OPEN"
        symlink = folder / "PRIVATE_FILENAME_SYMLINK"
        symlink.symlink_to(target)
        assert run(["--target", str(symlink), "--benign", str(goodware)])["status"] == "OPEN"
        assert target.read_bytes() == raw
        assert artifact.read_text() == reveal["rule_source"]
    print(
        json.dumps(
            {
                "installed_cli_cases": 8,
                "status": "PASS",
                "sample_execution": False,
                "network": False,
            }
        )
    )


if __name__ == "__main__":
    main()
