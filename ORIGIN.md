# Origin and attribution

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
Full original Florian Roth BSD-3-Clause license is preserved unaltered in
licenses/yarGen-BSD-3-Clause.txt and attributed in NOTICE.

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

Complete original yara-python Apache-2.0, libyara BSD-3-Clause COPYING and all
33 distinct embedded C/C-header license comments (129 uses, including Avast MIT
and Bison GPLv3 with its explicit generated-parser exception) are retained.
The GPLv3 reference and actual linked local OpenSSL 3.6.2 license are also supplied.
The parser exception is preserved in the original comments; this does not claim
all libyara is GPL or replace any dependency's license terms. TLSH C files have no
additional embedded notice in this fixed distribution/tree; their licensing is
not independently reconstructed. Optional and platform dependencies retain their
own terms; this wheel contains only the independent Python code and notices,
not native libraries, SDKs or dependency archives.

Primary API documentation:
[YARA Python API](https://yara.readthedocs.io/en/stable/yarapython.html).
Primary source/license references are the fixed upstream URLs in SOURCE_AUDIT.json
and DEPENDENCY_AUDIT.json. Complete source review means only the enumerated baseline
closure and all new runtime/test/CLI/package/CI source; it is not a whole ecosystem
security audit. AI assistance is disclosed, and origin review or successful
packaging does not establish CVP qualification or real safeguard impact.
