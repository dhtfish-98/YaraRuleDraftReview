# Current release validation — 0.1.3, 2026-10-05

This patch publishes the already public Build/项目文档 layout with a matching package version and CI wheel filename. Native YARA compilation and evidence interpretation are unchanged from public main 4fa6b4e44dc53dbe14f8183ebb5e8f87d38db63b; the package version constant advances. New implementation author and maintainer: dhtfish98. The project Apache-2.0 license and applicable yara-python/libyara notices remain intact.

The current source inventory is SOURCE_MANIFEST.json. Exact local tests, native compiler matrix, installed consumer, package contents, remote CI, tag and release require separate version-bound verification. These engineering checks do not establish CVP eligibility or approval.

## Historical delivery evidence

# Prior licensing validation — 0.1.2

This patch removes only 6 confirmed unused complete reference-license/notice copies. New implementation author remains dhtfish98. Runtime parsing and evidence interpretation are unchanged; runtime changes are package version constants and any existing version display. The new source suite ran **41 unittest methods with nonzero PASS**. Current source identities are in SOURCE_MANIFEST.json, and LICENSE_CLEANUP.json describes the exact licensing boundary. Wheel and sdist reconstruction, fresh isolated consumer tests, CLI contracts, runtime/notice byte identity and package metadata are independently bound to the new assets in the batch release records; source tests alone do not prove those outcomes. New hosted CI and publication remain separate observations.

The actual pinned external yara-python/libyara compiler remains required. Its own original notices are untouched. Complete original-source embedded comment extraction/hash/count and Bison exception checks remain, without shipping duplicate comment/reference text files. The native compiler matrix is retained.

## Historical validation evidence

All following earlier version/count/native observations are historical evidence, not validation of this new patch. Statements below about then-retained reference copies describe the earlier artifacts. Current licensing membership is LICENSE_CLEANUP.json.

# Current validation — 0.1.1

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **41 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.1; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

One functional change in this update rejects missing, non-positive or non-integer safe-file flags before opening input. API/CLI regressions cover missing, None, invalid, zero and boolean flags, plus regular files and symbolic links.

Installed validation used the actual pinned yara-python/libyara 4.5.4 compiler, direct native data matching and the complete existing finite synthetic compiler matrix. No sample was executed.

The current safe-file capability gate also requires set/frozenset directory-relative support declarations containing each actually used operation before opening input. Missing, None, empty, malformed or operation-incomplete collections yield the existing controlled unsupported result. Normal set/frozenset declarations and API/CLI rejection-before-open are regression tested. YARA also requires os.stat in both directory-relative and no-follow-stat support declarations.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

# Validation evidence and limits

The source unittest suite includes 35 methods, with actual native YARA compilation,
ASCII/wide/odd-offset matching, direct hostile literal/quote escaping, independently
computed score factors, benign token and substring subtraction, document
frequency, input order/dedup, individual/common rules, actual holdout false
positives, default privacy, all budget classes and unsupported inputs. Fault
controls cover missing POSIX capabilities, symlink components/leaves, FIFO,
input short reads/dev/ino/size/mtime/ctime/regular-type changes, exclusive output,
private mode, partial write and replacement without deletion. Backend version,
compile/timeout/other exception, unexpected result and warning paths are OPEN
controls; their fault injection is not a native crash or timed-stress proof.
A fixed seed supplies 200 additional harmless byte cases within one method.

`scripts/native_matrix_check.py` independently recompiles generated rule bundles
and asserts actual native matches for twelve harmless corpora: ASCII, wide and
mixed representations with 1/2/4/8 targets. Each case includes benign tokens in
maximal-run substrings/other encodings, ten actual negative data controls, and an
observed two-marker holdout false positive that causes the draft API to return
OPEN. It records exact source hashes and engine identity, without raw strings.
This demonstrates finite selected rule behavior; it is not generalization,
malware/real goodware recognition or whole yarGen differential equivalence.

The installed CLI checker uses eight fresh local subprocess invocations of the
installed product, outside the source tree: redacted report, explicit reveal,
new artifact, existing-name refusal, observed holdout false positive, private
missing path, argument error and symlink refusal. The runtime itself never
launches subprocesses. Inputs remain byte-identical; artifacts are generated only
for fully compiled/validated drafts.

Local validation rebuilds the pinned native dependency from the verified sdist,
then runs source tests/direct native matrix, lint/format, isolated Python wheel
and sdist builds, a new offline wheel consumer, byte-exact dependency notice reproduction, installed tests/direct matrix and
actual CLI, pip check, and wheel RECORD/source/license/metadata/sdist/installed
byte checks. Exact native wheel/module/linked library and project artifact hashes
are recorded in the engineering evidence. This is actual host evidence, separate
from source inspection, future GitHub publication and exact-commit CI.

CI runs the same complete source suite, lint/format, direct native matrix, build,
new independent wheel installation, all installed tests, direct native matrix,
installed CLI and package byte checks on Linux/macOS and Python 3.11/3.14. Its
actions are pinned to verified commits. CI also verifies the fixed PyPI sdist hash
and reproduces all 33 original embedded notices, including the complete Bison
exception. Dependency installation may access the
package index during setup; product runtime has no network path. Other platform
wheels can differ from the locally frozen native build. Remote CI and publication
remain OPEN until parent verifies them for the exact published commit.

Always OPEN: authentic corpus labels, applicant/human contribution, approval of
CVP, effect on model safeguards, malware verdict, wider false-positive/negative
rate, non-ASCII encoding semantics, whole upstream equivalence, native-library
security, hard OS memory/compiler-time isolation, atomic output publication,
future input/output path identity and real deployment or service operation.
