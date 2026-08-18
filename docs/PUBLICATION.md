# Publication and research-preview packaging

This document defines a conservative publication boundary for `source-atlas`.
It is an engineering checklist, not a legal conclusion. The project-authored
source code is licensed under the MIT License, but the repository owner must
still review third-party redistribution rights before uploading any input or
derived-data artifact.

## Current release flags

- The project-authored source code is licensed under the MIT License, recorded
  in the root `LICENSE` file and package metadata. This source-code license does
  not grant rights to any third-party input or derived-data artifact.
- The Xbox PDB, game executables, dumped executable, and raw extraction/matching
  inputs are not part of the `source-atlas` tree. Their redistribution status
  has not been established here; do not add them to a public archive without an
  owner review.
- The generated SQLite atlas is a multi-gigabyte artifact containing extensive
  PDB-derived names, source paths, types, SDK observations, and other research
  data. The preview bundle excludes it. Its checksum identifies a separately
  handled local artifact and does not imply permission to distribute that
  artifact.
- The generated build report normally records the builder's absolute output
  path. The preview replaces that field with a fixed, relative external-artifact
  marker and rejects any other machine-local user path.
- The database contains insertion timestamps, so rebuilding from identical
  inputs is not currently expected to produce the same database bytes or
  database SHA-256. Stable logical IDs, manifests, and semantic counts are the
  reproducibility boundary for the database. The preview ZIP itself is
  byte-reproducible when given identical payload metadata.
- The build's `producer_source_id` hashes raw Python bytes, so checkout
  line-ending conversion can change that ID even when Python semantics do not.
  The preview preserves that producer ID and separately records a
  `packaged_source_id` for its LF-normalized source payload.

## Preview contents

The bundler uses a non-recursive allowlist. It includes:

- direct Python package source files under `src/fnv_atlas`;
- direct `test_*.py` unit-test files under `tests`;
- `README.md` and `pyproject.toml`;
- the exact public documentation set: `CONTRIBUTING.md`,
  `CONSUMER_EXPORTS.md`, `DATA_MODEL.md`, `DATA_SOURCES.md`, `MAINTENANCE.md`,
  `PUBLICATION.md`, and `REVIEW_WORKFLOW.md`;
- the repository-local preview and canonical source-package scripts;
- a schema-only SQL snapshot generated from the selected source's current
  `SCHEMA_STATEMENTS` and `SCHEMA_VERSION`;
- a sanitized build report;
- the SHA-256 sidecar for the excluded database;
- a generated publication notice and per-file manifest.

It excludes the SQLite database, PDBs, executables, dumps, raw JSON inputs, raw
SDK source trees, private SDK-derived observations, bulk extracted corpora, compiled Python caches, build
directories, unselected documents, and every other unallowlisted file. Merely
placing a file under `docs`, `tests`, or an SDK directory does not select it. A
payload file larger than 8 MiB or a total payload larger than 64 MiB is
rejected.

The manifest records separate, verifier-enforced `false` flags for inclusion of
the database, executables, PDB, raw inputs, SDK source, and private SDK-derived
observations. Those flags describe
the archive contents; they are not permission to redistribute the separately
held inputs or database.

The static hygiene checks reject user-profile paths, private-key markers, and
several common credential token forms. These checks reduce accidental leakage;
they do not replace manual review.

## Create and verify

From the `source-atlas` directory, after producing and validating the local
database, report, and database checksum:

```powershell
python .\scripts\build_research_preview.py create `
  --repo-root . `
  --output .\dist\fnv-source-atlas-research-preview.zip
```

Creation first verifies that the excluded database bytes match their checksum
and that the report's schema, producer version, producer source ID, and
validation results match the selected checkout. It also opens the database
read-only, verifies the report's exact database SHA-256 and input manifest, and
requires every optional private-SDK table and provenance channel to be empty.
A report from an earlier schema
or source revision is rejected; the schema snapshot is never used to disguise
or migrate a stale report. Creation then verifies the archive before publishing
it locally and writes an archive sidecar named
`fnv-source-atlas-research-preview.zip.sha256`. Existing outputs are not
overwritten unless `--overwrite` is explicit.

The canonical database named by a build report is an immutable release
artifact. Human review commands intentionally mutate a database and refresh its
checksum, so run review workflows on a copy. A reviewed working copy no longer
matches the original build report and is deliberately refused by the preview
packager; accepted-only exports carry their own release/reviewer lineage.

Verify an existing preview independently with:

```powershell
python .\scripts\build_research_preview.py verify `
  .\dist\fnv-source-atlas-research-preview.zip
```

The verifier checks the archive sidecar, strict member/role allowlist, fixed
timestamps and permissions, stored compression policy, canonical manifest,
individual sizes and SHA-256 digests, cross-file version and source identities,
line endings, size limits, sensitive-path patterns, presence of every public
documentation file, and the explicit exclusion of the database, PDB,
executables, raw inputs, SDK source, and private SDK-derived observations.

## Determinism

The preview format uses:

- lexicographically sorted archive members;
- `ZIP_STORED`, avoiding compressor-version output differences;
- a fixed default timestamp of `1980-01-01T00:00:00Z`;
- normalized LF endings for text files;
- canonical, sorted JSON;
- fixed file permissions and no ZIP comments or extra fields;
- SHA-256 for every payload and for the archive itself.

`--source-date-epoch` may set a different explicit timestamp. Two archives made
from identical selected source, sanitized report content, database checksum, and
epoch must be byte-identical.

## Clean-machine checks

The runtime package has no third-party dependencies, but the PEP 517 build
backend requires a sufficiently recent `setuptools`. Before a public tag, test
in a new virtual environment with the oldest supported Python version:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip setuptools
.\.venv\Scripts\python -m pip install --no-deps .
.\.venv\Scripts\python -m unittest discover -s tests -v
```

Also build both wheel and source distribution in an isolated environment and
inspect their file lists. The wheel intentionally contains runtime package code
only. `MANIFEST.in` gives the source distribution a separate, explicit boundary
that includes the public documentation, tests, packaging scripts, and
`.gitattributes`, while excluding generated and proprietary binary artifacts.

The regular setuptools sdist has correct contents but its tar/gzip metadata is
not byte-stable across repeated builds. Build the publication candidate through
the canonical wrapper instead:

```powershell
python .\scripts\build_source_package.py `
  --repo-root . `
  --output-dir .\dist `
  --source-date-epoch 315532800
```

The wrapper runs setuptools in a temporary source copy, validates the resulting
member boundary, then writes members in canonical order with fixed ownership,
permissions, timestamps, and gzip metadata. It also writes a SHA-256 sidecar.
Build twice from the frozen revision with the same epoch and require identical
archive hashes. Installing the canonical archive still exercises the ordinary
PEP 517 backend declared in `pyproject.toml`.

## Owner publication checklist

1. Confirm the root `LICENSE` and package metadata declare the MIT License for
   the project-authored source code.
2. Confirm whether any PDB-derived report fields or database content may be
   redistributed; keep the database separate unless that review is affirmative.
3. Re-run the secret/path scan and manually inspect the manifest file list.
4. Run the full tests and database validator on the final source revision.
5. Create the preview twice in separate output directories and compare SHA-256.
6. Verify the final archive and its sidecar on a clean machine.
7. Publish only after the owner explicitly approves the exact verified bytes.
