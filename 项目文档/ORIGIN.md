# Origin and attribution

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.3**. Upstream authors and reused components retain their original attribution.


Mechanism baseline: Neo23x0/yarGen at
`34c1464eaf46d02e8807d7ef465cd884279def29`.
The frozen source/CLI closure was read in full: `yarGen.py` (2423 lines),
`tools/byte-mapper.py` (169), README (277), LICENSE (24), requirements (3),
release script (14), `.gitignore` (17), total 2927 physical lines. SOURCE_AUDIT.json
records each original Git blob and SHA256. Upstream has no test file in its frozen
10-blob tree. The PEStudio XML contents and external databases are excluded and
not claimed as reviewed. The original was not executed, installed, updated or
used to fetch its benign databases.

The baseline selects local string extraction, benign document-frequency filtering,
scoring and individual/common rule generation. The new runtime is an independent
Python implementation with explicitly different extraction, integer scoring,
privacy, resources and full finite negative validation. It is not a behavior-
equivalent full rewrite of yarGen or a wrapper around its original CLI/functions.
Both tool lineage and exclusions are visible rather than renaming upstream code.
No yarGen implementation, database or original sample is distributed. Its
separate design-reference license copy is omitted; the fixed source facts remain.

Actual compilation/matching depends on yara-python 4.5.4. The PyPI sdist is frozen
by SHA256 `4c682170f3d5cb3a73aa1bd0dc9ab1c0957437b937b7a83ff6d7ffd366415b9c`.
Its binding C bytes equal upstream git commit
`74920b6da9a70a162b3bdc41b30e4af02e5c7dff`; that tree pins libyara commit
`7ff39042be5c63682a037e13a75221d59393cf8b`. Selected binding initialization,
compile/includes/strict-escape/warnings, memory data scan/timeout/fast and result
callback paths plus the complete package setup script were read. The entire
native compiler, all modules, platform/dependency implementations and every
library test were **not** audited or executed. DEPENDENCY_AUDIT.json separates
that partial source review from actual observed native build/install/matches.
No arbitrary or module-bearing YARA input is accepted by this project's public API.

The native dependency is installed separately and retains its own original
licenses/notices. This product wheel/sdist contains independent Python code,
not native libraries, SDKs, dependency archives or copied C implementations.
Separate optional copies of native license texts and comment-only supplements
are omitted. The source verification script still checks the complete pinned
comment extraction hash/count and Bison exception in the separately obtained
dependency source; it does not relicense or modify that dependency.

Primary API documentation:
[YARA Python API](https://yara.readthedocs.io/en/stable/yarapython.html).
Primary source/license references are the fixed upstream URLs in SOURCE_AUDIT.json
and DEPENDENCY_AUDIT.json. Complete source review means only the enumerated baseline
closure and all new runtime/test/CLI/package/CI source; it is not a whole ecosystem
security audit. New implementation author: dhtfish98; origin review or successful
packaging does not establish CVP qualification or real safeguard impact.
