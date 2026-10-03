# Defensive scope

Only an offline detection-draft workflow from explicit local, authorized corpora
is implemented. Validation fixtures contain harmless DEMO_MARKER content. Samples
are never executed, imported, deserialized, disassembled or uploaded. Runtime code
has no networking, URL access, subprocess, eval/exec, plugins, directory scanning,
monitoring, deletion, sample output, PE/LIEF, opaque external database or database
writeback. The only optional write creates a new detection rule in an explicitly
named existing directory. YARA itself has broader features; the supported public
API never accepts an arbitrary rule, include, module, file/PID scanner or external.

PASS is a finite, scope-qualified result: actual compilation succeeded; every
supplied target matched all rules intended for that target; no supplied training
benign or holdout negative matched any draft rule. A heuristic string rule can
still have false positives/negatives elsewhere. Testing data labels, provenance,
maliciousness, encoding intent, historical events, native code behavior, broader
upstream equivalence, live protection, performance isolation and CVP eligibility
remain OPEN. A target is a caller-defined detection target, not necessarily malware.

The ASCII/UTF16LE-ASCII maximal-run profile and lower-only budgets are complete
for the declared scope. The project does not implement yarGen's whole PE opcode,
imphash/export, XML blacklist, Base64/hex/reversal scores, memory fallbacks,
external downloadable database, common-string clustering beyond all-target shared
literals, directory monitoring/deletion or update branches. Their source was read
to establish the mechanism boundary; those branches are absent from this product.

CLI default output suppresses paths and extracted literals. `--reveal-rules` or
explicit artifact output authorizes material containing escaped literal content.
Hashes, offsets and exact match names still carry correlatable corpus evidence.
Input error or late compilation/negative failure never emits an apparently safe
partial rule source. No claim is made that this project will avoid model
safeguards, satisfy a CVP decision, or prove an applicant's independent authorship.
New implementation author: dhtfish98. Scope and evidence are explicitly disclosed.
