> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# YaraRuleDraftReview

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.2**. Upstream authors and reused components retain their original attribution.


Create bounded, offline **detection drafts** from explicit authorized byte corpora.
The independent mechanism extracts strings, builds a read-only in-memory benign
index, removes observed benign strings, ranks the remaining candidates, and
creates individual and common YARA rules with provenance. It then actually
compiles those rules and scans every supplied target, training benign and holdout
negative using **yara-python/libyara 4.5.4**. A failure yields OPEN and suppresses
the draft. Passing these finite observations does not classify a file as malicious
or establish generalization, trustworthy corpus labels, or CVP eligibility.

New implementation author: dhtfish98. This project independently implements the selected pure-string
mechanism of [yarGen at the frozen commit](https://github.com/Neo23x0/yarGen/tree/34c1464eaf46d02e8807d7ef465cd884279def29).
See [ORIGIN](<ORIGIN.md>), [scope](<DEFENSIVE_SCOPE.md>), [validation](<VALIDATION.md>)
and [source and external dependency boundaries](<ORIGIN.md>).

## API

Install with `python -m pip install .`; Python 3.11 or later and the pinned native
`yara-python==4.5.4` dependency are required. This is a mature engine dependency,
not a shell wrapper or replacement for its full implementation.

```python
from yara_rule_draft_review import Limits, draft

report = draft(
    targets=[b"DEMO_MARKER_ALPHA_0239\0DEMO_MARKER_BETA_1648"],
    benign=[b"DEMO_MARKER_BENIGN_ONLY"],
    negatives=[b"DEMO_MARKER_ALPHA_0239"],
    reveal_rules=False,
    limits=Limits(),
)
assert report["status"] == "PASS"
assert report["rule_source"] is None
```

The public API accepts exact lists/tuples of exact immutable bytes. Empty target
or training benign corpora, target/negative role overlap, insufficient distinctive
strings, exceptions, compilation warnings, scan warnings/timeouts, mismatch or
budget exhaustion produce OPEN. Benign/holdout labels are caller declarations.
Holdout negatives do not influence scoring. Any observed holdout match rejects the
whole draft; a diagnostic match ledger remains, with source content suppressed.

Default output contains hashes, lengths, offsets, score components and actual
match identities. It does not echo input filenames or extracted text. Hashes and
positions can still identify a known corpus. `reveal_rules=True` explicitly exposes
the escaped detection literals and associated source; only do this for shareable
inputs. Returning a rule draft is not a malware verdict or independent proof of
human authorship.

## CLI

Only explicit files are read; directories are never scanned. Use an existing
separate output directory if an artifact is wanted:

```text
yara-rule-draft-review --target target-demo.bin --benign benign-demo.bin \
  --negative holdout-demo.bin --output-dir drafts
```

Repeat corpus flags for multiple files. Without `--output-dir`, no artifact is
written. Without `--reveal-rules`, standard output suppresses literals even when
an explicitly requested draft file is created. The only artifact is
`draft-<source_sha256>.yar`, created as a new file with mode 0600, never overwritten.
An output failure retains any partial/replaced artifact, reports `may_exist`, and
returns OPEN. A PASS confirms an observed file identity/size after the write; it
does not promise atomic publication or future path identity. `may_exist=false`
means no file-creation attempt was made; true also covers an already existing name.

Every file/directory component is opened with no-follow descriptors. Empty,
`.`/`..`, repeated or trailing separators, NUL, invalid Unicode and paths over
8192 UTF-8 bytes are rejected. Special files and detected changes/short reads are
OPEN. The current file CLI requires POSIX `O_NOFOLLOW`, `O_DIRECTORY`,
`O_NONBLOCK`, descriptor-relative open/stat and no-follow stat. Unsupported
platforms (including the Windows file CLI) return OPEN; the portable byte API is
separate. Input bytes are not modified. Regular hard links may be read; this does
not prove the input's provenance. Independent output-directory rejection compares
lexical absolute input-parent paths; no-follow and new-file creation provide the
actual write boundary, not a claim about mount aliases.

CLI exit 0 means finite draft/observed-output checks passed, exit 2 means OPEN.
Argument and file/native error diagnostics use fixed codes, without paths or raw
sample/error payloads. Help exits normally.

## Selected string and scoring contract

The complete supported string profile is maximal printable ASCII bytes
`0x20..0x7e` and maximal runs of those same code points encoded as UTF16LE,
minimum 8 and maximum 128 code points. Wide runs can start at odd byte offsets;
ASCII and wide observations of identical text normalize to one candidate. NUL,
newlines and other bytes are boundaries, not decoded/executed content. A run over
the maximum rejects the whole corpus; it is never silently truncated. This is
ASCII represented as UTF16LE, not a general Unicode decoder. Encoding intent,
non-ASCII strings, UTF16BE, Base64/hex semantics and PE opcodes remain outside
this profile and OPEN.

Input order and duplicate content do not alter rules/provenance within the corpus
count budget. Unique samples are sorted by full SHA256. Each benign token records
its unique document frequency and source hashes. Candidates found as complete
benign tokens or as ASCII/wide substrings anywhere in training benign bytes are
excluded. That last test avoids a maximal-run boundary hiding a benign substring.
This index is freshly computed in memory from explicit benign inputs; it has no
external opaque database import, rebuild, update or writeback interface.

For candidate length `L`, unique byte count `U`, most frequent byte count `M`,
target document support `S` among `N` unique targets, the independent integer
ranking is:

```text
coverage           = floor(4000 * S / N)
length             = floor(2000 * L / 128)
diversity          = floor(2000 * U / L)
repetition_penalty = floor(2000 * M / L)
score = coverage + length + diversity - repetition_penalty
```

Ties use lexical byte order. This is an uncalibrated heuristic, never a confidence
probability, and it does not copy yarGen's malicious keyword/decoding scores.
Each unique target gets at most 12 literals; a common rule is also produced when
at least two candidates occur in every target. Every required rule needs two
candidates. Names and metadata use hashes and fixed text; literals use byte-exact
quote/backslash/hex escapes. Conditions are `filesize <= limit and 2 of them`.
Two literal identities may overlap in bytes; independence or generalization is
not established. All generated literals use `ascii wide`. No caller-supplied
YARA source, imports, include, regex, externals, modules, plugins or process scan
interface is accepted.

Default hard ceilings are 1 MiB/file, 8 MiB unique corpus bytes (summed per role),
16 supplied entries/role, 8192 extracted occurrences and distinct tokens across
roles, 128 bytes/token, 12 strings/rule, 17 rules, 256 KiB generated source, 1 MiB
JSON report, 64 MiB conservatively charged benign substring comparison work, and
1 second for each native data scan. Limits can only be lowered (minimum token 8,
strings/rule 2, report 256). The CLI may read at most 48 explicitly named files;
count limits apply before content deduplication. Matching uses `fast=True` so
native output keeps only the first match for each literal, sufficient for this
rule condition. Compiler syntax/escape/warning checks are actual engine calls;
there is no compiler wall-time API or OS memory isolation guarantee. Finite
literal grammar/source budgets bound the input to compilation. General runtime
resource isolation and native-dependency correctness remain OPEN.

Safe file input requires positive integer `O_NOFOLLOW`, `O_DIRECTORY` and `O_NONBLOCK` flags and the directory-relative operations used by this reader. A missing, zero or invalid capability returns `OPEN` with `safe_file_platform_not_supported` before input is opened. The supported and tested file-reader platforms are macOS and Linux; native Windows file reading is not validated by these checks.
