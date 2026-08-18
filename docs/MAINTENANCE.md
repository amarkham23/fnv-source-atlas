# Maintenance and release policy

The atlas is maintained as a rebuildable evidence database, not as a hand-edited
binary asset. Stable identities, manifests, producer provenance, validation
results, and review snapshots are the durable release boundary.

The project-authored source code is licensed under the MIT License. That
source-code license is separate from the redistribution status of the Xbox PDB,
generated database, PDB-derived bulk content, executables, dumped executable,
and raw SDK. No clearance has been established for distributing those inputs
or derived data; the owner must make an artifact-specific decision before any
such public release.

## Versioning contracts

Several versions move independently and must be recorded explicitly:

- the Python package/release version in `pyproject.toml`;
- SQLite `SCHEMA_VERSION` and `PRAGMA user_version`;
- producer name, producer version, and producer-source SHA-256;
- content-addressed input manifest;
- JSON artifact format strings such as review queues and consumer export plans;
  and
- review-release identity, source revision, and manifest.

Do not infer one version from another. A package-only fix may leave the schema
unchanged, while a schema change always requires a new database build. Format
consumers must reject an unknown major format suffix rather than guessing.

The project is pre-1.0 and currently has no promised compatibility window.
Nevertheless, maintainers should not silently reuse an artifact format name
for a changed shape, reinterpret an existing stable ID, or remove a documented
field without a versioned replacement and release note.

## Rebuild-only schema policy

The schema initializer validates a current-version database, creates the
current schema only in an empty database, and rejects older nonzero schema
versions because no in-place migration is provided. Therefore:

1. Never run ad hoc `ALTER`, `UPDATE`, or repair SQL on a release database.
2. Preserve the old database and its checksum as a historical local artifact.
3. Check out the intended producer source and gather the exact manifested
   inputs.
4. Build a new database to a separate temporary destination.
5. Validate and compare semantic summaries before replacing any local pointer.
6. Record the new schema, producer source ID, manifest ID, report, and checksum.

If an in-place migration is ever introduced, it needs a separately tested,
transactional, version-to-version contract. Until then, “migration” means a
clean rebuild.

## Reproduction gates

From the source checkout:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests -v

python -m fnv_atlas build `
  --repo C:\path\to\FNV-Mods `
  --xbox-pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --xbox-exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --output .\build\fnv-source-atlas.sqlite `
  --report .\build\fnv-source-atlas.report.json `
  --replace

python -m fnv_atlas validate .\build\fnv-source-atlas.sqlite
python -m fnv_atlas summary .\build\fnv-source-atlas.sqlite --json
```

The final build must pass:

- the complete source test suite;
- strict schema-shape and version validation;
- SQLite integrity and foreign-key checks;
- content-addressed manifest verification;
- all cross-table semantic validation counters at zero;
- input and producer-source rehash immediately before publication; and
- focused read-only queries for representative exact, ambiguous, fold, and
  unresolved records.

Database bytes are not currently reproducible because insertion timestamps are
stored. Compare manifest identity, producer identity, stable IDs, semantic
counts, and validation output; do not require equal database SHA-256 across
independent rebuilds. The preview ZIP has a separate byte-determinism contract
described in [publication](PUBLICATION.md).

## Review and consumer gates

Candidate coverage is not release acceptance. Before publishing reviewed
mapping output:

1. Register an immutable review-release context tied to the exact build.
2. Generate bounded review pages for named reviewers.
3. Preserve reviewer disagreements and decisions at their exact target scope.
4. Freeze a content-addressed review-release snapshot.
5. Evaluate producer counts against that one named reviewer without reporting
   fabricated precision for open targets.
6. Generate consumer actions only from the selected reviewer's current
   `accept` leaf in the exact selected release.
7. Inspect every blocked action and verify the PC executable content hash.

See [review workflow](REVIEW_WORKFLOW.md) and
[consumer exports](CONSUMER_EXPORTS.md). Review snapshots and candidate reports
are not executable rename input.

## Release checklist

### Source freeze

- Freeze the source revision and package version.
- Confirm the worktree contains no accidental generated inputs or unrelated
  changes.
- Review every changed extractor, persistence rule, schema object, validation
  rule, artifact format, and documentation claim.
- Confirm tests use synthetic or otherwise redistributable fixtures.

### Data freeze

- Resolve every required input to an explicit role and SHA-256 identity.
- Confirm optional/experimental inputs are labeled and cannot promote truth.
- Rebuild from scratch; never reuse a database created by older producer code.
- Save the sanitized build report and database checksum separately.
- Compare semantic summaries to the prior release and explain material deltas;
  do not copy provisional counts into documentation.

### Quality gates

- Run focused tests and the full test suite on the frozen revision.
- Run `fnv-atlas validate` and require an affirmative `ok` result.
- Exercise PC, Xbox, class, control-flow, candidate, review-page, snapshot, and
  accepted-only export paths where applicable.
- Reopen the database read-only and repeat validation on the final bytes.
- Build and smoke-test the wheel and the canonical source distribution
  described in [publication](PUBLICATION.md) on the oldest supported Python
  version in a clean environment; build the source archive twice and require
  identical SHA-256 values.

### Security and privacy

- Inspect all archive members, reports, examples, and logs for absolute paths.
- Scan for tokens, private keys, private URLs, email addresses, and usernames.
- Confirm no raw PDB, executable, dump, SDK, generated database, or bulk
  extracted corpus entered source control or the preview.
- Check archive size and allowlist rules and manually inspect the manifest.
- If a secret or proprietary artifact was exposed, stop and remediate before
  creating replacement release bytes.

### Legal and publication gate

- Confirm the root `LICENSE` and package metadata continue to declare the MIT
  License for the project-authored source code.
- Record an artifact-specific decision about PDB/database and SDK-derived
  redistribution. At present, no clearance has been established.
- Create the research preview twice in separate destinations and compare its
  SHA-256 values.
- Verify the chosen preview and sidecar independently.
- Publish only the exact owner-approved bytes. Follow
  [publication](PUBLICATION.md); do not substitute the local database for the
  database-free preview.

## Preview commands

After the database, report, and database checksum exist and match:

```powershell
python .\scripts\build_research_preview.py create `
  --repo-root . `
  --output .\dist\fnv-source-atlas-research-preview.zip

python .\scripts\build_research_preview.py verify `
  .\dist\fnv-source-atlas-research-preview.zip
```

Existing outputs are not overwritten without explicit `--overwrite`. The
verifier checks the archive sidecar, allowlist, canonical manifest, per-file
hashes, cross-file versions, fixed metadata, sensitive strings, and exclusion
of the database and raw inputs.

## Deprecation and compatibility

For a query/API/artifact change:

1. Introduce a new versioned format or explicit replacement.
2. Document the semantic difference and any lost capability.
3. Add tests that old and new identities cannot be confused.
4. Keep old artifacts readable when practical, but never weaken validation to
   guess an unknown shape.
5. Announce removal before deleting the old reader. Because no support window
   is promised yet, the release note must state the actual final supported
   version rather than implying one.

Stable IDs are not deprecated merely because a producer has a better result.
Superseding evidence and human decisions append lineage; they do not rewrite
history. A review release remains immutable once referenced.

## Backups and incident response

Keep the following local artifacts together:

- source revision or source archive;
- build report and validation output;
- input-manifest identity and producer-source identity;
- database checksum and the separately stored database, if legally retained;
- review-release snapshots and their SHA-256 identities; and
- preview ZIP plus sidecar.

Do not put credentials in provenance, review rationales, issue text, or backup
names. Do not expose machine-local absolute paths. If corruption is suspected,
preserve the affected checksum for diagnosis, mark the artifact withdrawn, and
rebuild from known inputs instead of patching it in place.

Until a private security-contact process is published, coordinate sensitive
reports directly with the repository owner through an owner-designated private
channel. Do not disclose secrets, proprietary bytes, or exploitable details in
a public issue.

Source eligibility and redistribution constraints are detailed in
[data sources](DATA_SOURCES.md); contribution rules are in
[CONTRIBUTING.md](CONTRIBUTING.md).
