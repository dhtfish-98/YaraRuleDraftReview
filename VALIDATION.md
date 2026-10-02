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
