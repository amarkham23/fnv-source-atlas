# FNV source atlas

`source-atlas` is an evidence-backed map between the Fallout: New Vegas PC
program and the Xbox 360 debug build. It preserves what the Xbox PDB, the PC
executable inventory, RTTI/vtables, control flow, SDK declarations, legacy
matching passes, and human review actually establish without turning an
address-to-name guess into source truth.

The current source targets package version 0.5.0 and SQLite schema 8. A schema-8
database built from the exact local inputs is usable now as a research,
automation, and review substrate. It does **not** recreate Bethesda's source
tree or mean every candidate mapping is correct. Its value is that another
author or agent can ask precise questions, see the ambiguity and provenance,
record review decisions, and export only explicitly accepted exact mappings.

## What authors can use now

| Goal | What the atlas provides |
|---|---|
| Identify a PC function | Canonical PC entry identities, addresses, calls, and unresolved non-entry targets |
| Compare it with Xbox | Lossless physical PDB procedure identities, folded-address groups, aliases, source references, signatures, and candidate PC/Xbox links |
| Recover types and data | Raw Xbox CodeView TPI records, structured tag layouts and members, method overloads, exact type indices, function signatures, and typed global-data symbols |
| Study virtual dispatch | Normalized role-aware PC/Xbox vtables plus raw Xbox `S_PUB32` vftable records, decorated template encodings, same-address aliases, pointer-run observations, slots, and diagnostics |
| Generate more candidates | Conditional control-flow derivations that preserve disjunctions and record their dependency on existing candidate anchors |
| Use SDK research | Source-hashed GAME, GECK, and variant-unspecified prototype, nested call-target, global-data, and boundary observations joined safely to the PC inventory |
| Build a community review set | Deterministic queues, immutable release snapshots, append-only reviewer decisions, and per-producer reviewed/open counts |
| Apply reviewed names | Accepted-only Ghidra and IDA scripts gated by one reviewer, one release manifest, exact endpoint identity, and the PC executable SHA-256 |
| Reproduce the corpus | Content-addressed manifests, source-tree manifests, atomic rebuilds, semantic validation, build reports, database checksums, and deterministic source-only preview packaging |

The atlas is therefore useful before the mapping is complete. For example, a
decompiler author can start with a PC entry, inspect every Xbox alternative and
its type/vtable/control-flow evidence, and use an SDK declaration as a lead
without silently promoting the declaration to a name. When the evidence is
sufficient, a reviewer accepts the exact scalar claim or scalar alternative;
only then can it enter an executable rename plan.

## Non-negotiable invariants

- Function identity is a platform/address-space/stable-record identity. A name
  is an attribute, never a key.
- More than one logical Xbox function or vftable symbol may occupy one address;
  aliases and ICF folds remain intact and unranked.
- A PC subject may have several Xbox alternatives. One fold group is retained
  as one bundle alternative, not expanded into apparently independent claims.
- An address that is not a canonical function entry remains an unresolved
  target or a boundary candidate. Importers never manufacture a function.
- Evidence stays at the scope it can support: hypothesis set, exact
  alternative, or scalar claim. Fan-out never multiplies evidence.
- Control-flow-derived evidence is conditional on candidate anchors and is
  explicitly not independent confirmation.
- GAME, GECK, and variant-unspecified SDK observations remain distinct. GECK
  observations never link to the PC game inventory.
- Producer candidates, human review, and consumer exports are separate layers.
  No importer assigns acceptance, transfers a name, or infers consensus.
- Every build records exact input, SDK source-tree, schema, package-source, and
  behavior identities and rechecks inputs before atomically publishing.

## Build and validate

Python 3.11 or later is required. The atlas has no third-party runtime
dependencies.

From the `source-atlas` directory:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m fnv_atlas build `
  --repo C:\path\to\FNV-Mods `
  --xbox-pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --xbox-exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --replace

python -m fnv_atlas validate .\build\fnv-source-atlas.sqlite
python -m fnv_atlas summary .\build\fnv-source-atlas.sqlite --json
python -m unittest discover -s tests -v
```

The standard repository layout supplies the PC executable/function inventory,
legacy artifacts, vtable/type exports, and Xbox module/source maps. It never
discovers or ingests a colocated SDK directory. A private operator can opt in
deliberately by adding `--sdk-root C:\private-inputs\local-sdk`; public and
community builds should omit that flag. The database, JSON build report, and
database SHA-256 sidecar are written under `build/` by default.

An opt-in build does not copy the raw SDK source into the database, but its
derived declarations, identifiers, relative paths, hashes, and address
observations can still reveal information from private source. Treat an
SDK-derived database and its exports as private until they receive a separate
privacy and redistribution review.

Schema changes are rebuild-only. Do not open an older schema-6/v0.4 database
with the current package and do not repair a release database in place. Rebuild
schema 8 from the manifested inputs instead.

Static counts in documentation become stale as sources and policies improve.
The selected build's `*.report.json` and `fnv-atlas summary --json` output are
the authoritative coverage record.

## Query the research corpus

Query commands are read-only and print compact text by default. Add `--json`
for deterministic machine-readable output. Addresses accept decimal or
`0x`-prefixed hexadecimal notation; plural JSON results include pagination
metadata.

```powershell
$db = ".\build\fnv-source-atlas.sqlite"

# PC identity, names, signature/source, vtable use, hypotheses, evidence,
# alternatives, and current review decisions.
python -m fnv_atlas pc $db 0x00401000 --json

# Xbox physical PDB records, same-address folds, aliases, and PC hypotheses.
python -m fnv_atlas xbox $db 0x82001000 --json
python -m fnv_atlas xbox $db "?Tick@Actor@@UEAAXXZ" --exact --json
python -m fnv_atlas xbox $db "actor" --contains --limit 25 --offset 25

# Same-platform classes, vfptr roles, slots, candidate alignments, and issues.
python -m fnv_atlas class $db "Actor" --exact --slot-limit 64 --json

# Lossless CodeView layouts/members, typed globals, and raw vftable aliases.
python -m fnv_atlas type $db "Actor" --contains --member-limit 64 --json
python -m fnv_atlas data $db 0x82002000 --json
python -m fnv_atlas raw-vftable $db "Actor" --contains --slot-limit 64 --json

# SDK declarations and joins, with variant and observation-kind filters.
python -m fnv_atlas sdk $db "Actor" --contains --variant game `
  --observation-kind prototype --json

# Candidate work queues and persisted Xbox control flow.
python -m fnv_atlas candidates $db --kind ambiguous --limit 100 --json
python -m fnv_atlas candidates $db --kind conflicted --json
python -m fnv_atlas flow $db "?Tick@Actor@@UEAAXXZ" --exact --json
python -m fnv_atlas flow $db --site 0x82001004 --json
```

An Xbox lookup can legitimately return several physical records at one address
or an unresolved address with no PDB procedure. The query layer never chooses
a fold member or promotes an address-derived label.

The summary exposes the schema-8 CodeView type/layout, data-symbol, raw-vftable,
SDK, review, normalized-vtable, control-flow, and mapping families. Researchers
who need bulk access can use SQLite directly; the [data model](docs/DATA_MODEL.md)
defines which tables are identities, observations, candidates, and decisions.

## Review and accepted-only export

The CLI provides the full safe handoff from a candidate corpus to one
reviewer's release-bound output. Keep the canonical built database immutable:
copy it before adding review state, because a reviewed working copy no longer
matches the canonical build report or checksum attestation.

```powershell
# Work on a review copy, not the canonical release database.
Copy-Item $db .\build\fnv-source-atlas.review.sqlite
$db = ".\build\fnv-source-atlas.review.sqlite"

# These commands print the stable IDs needed by later commands.
python -m fnv_atlas reviewer-register $db `
  --identity-kind handle --identity-key alice --display-name "Alice"

python -m fnv_atlas review-release $db `
  --release-key local-v0.5-review-1 `
  --label "Local schema-8 review" --version 0.5.0

$reviewer = "reviewer:sha256:..."
$release = "review-release:sha256:..."

python -m fnv_atlas review-queue $db `
  --reviewer $reviewer --release $release --limit 50 `
  --output .\build\review-page.json

python -m fnv_atlas review-decide $db `
  --reviewer $reviewer --release $release `
  --alternative "match-alternative:sha256:..." --action accept `
  --decided-at "2026-08-17T12:00:00-04:00" `
  --rationale "Verified independently in PC and Xbox disassembly"

python -m fnv_atlas review-snapshot $db `
  --reviewer $reviewer --release $release `
  --output .\build\review-snapshot.json

python -m fnv_atlas review-evaluate $db `
  --reviewer $reviewer --release $release `
  --output .\build\review-evaluation.json

# Candidate reports are non-executable. Plans/scripts contain only mappings
# explicitly accepted by the selected reviewer in the selected release.
python -m fnv_atlas consumer-export $db `
  --reviewer $reviewer --release $release --format candidates `
  --output .\build\candidate-report.json
python -m fnv_atlas consumer-export $db `
  --reviewer $reviewer --release $release --format ghidra `
  --output .\build\apply-atlas-ghidra.py
```

Accepting a hypothesis set does not choose one of its alternatives. Accepting a
fold bundle does not choose one folded function. Unsafe or incomplete accepted
decisions appear in an export plan's `blocked` list rather than being applied.
Generated scripts verify the PC executable hash, require an existing exact
function entry, and never create functions.

## Standalone extraction

The lossless extractors can also be used without building the SQLite atlas:

```powershell
python -m fnv_atlas extract-xbox-procedures `
  --pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --modules C:\path\to\FNV-Mods\symbol-port\modules_360.json `
  --output .\build\xbox-procedures.jsonl

python -m fnv_atlas extract-xbox-data-symbols `
  --pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --modules C:\path\to\FNV-Mods\symbol-port\modules_360.json `
  --output .\build\xbox-data-symbols.jsonl

python -m fnv_atlas extract-xbox-vftables `
  --pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --symbols-output .\build\xbox-vftable-symbols.jsonl `
  --runs-output .\build\xbox-vftable-pointer-runs.jsonl

python -m fnv_atlas extract-sdk-observations `
  --sdk-root C:\private-inputs\local-sdk `
  --output .\build\sdk-observations.json

python -m fnv_atlas extract-xbox-control-flow `
  --pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --modules C:\path\to\FNV-Mods\symbol-port\modules_360.json `
  --output .\build\xbox-control-flow.jsonl
```

Raw vftable pointer runs are observed executable-pointer prefixes, not declared
table extents. SDK JSON contains source-derived observations, not accepted
mappings. Extraction does not grant permission to redistribute the result.

## Package layout

- `pdb_symbols.py`, `tpi_signatures.py`, `tpi_layouts.py`, and
  `pdb_globals.py` preserve physical Xbox procedures, signatures, raw CodeView
  records, class layouts/members/overloads, diagnostics, and typed data symbols.
- `pdb_vftables.py` preserves raw DBI vftable records, decorated template and
  qualifier encodings, unranked same-address aliases, pointer runs, and slots.
- `pc_inventory.py` admits only exported PC entry keys as functions and keeps
  non-entry/external targets unresolved.
- `vtables.py`, `vtable_alignment.py`, and `vtable_hypotheses.py` model
  role-aware tables and candidate-only cross-platform slot alignments.
- `ppc_control_flow.py`, `control_flow_matching.py`, and their adapters preserve
  physical/logical Xbox branches and derive conditional candidates without
  treating their anchors as truth.
- `sdk_prototypes.py` and `sdk_inventory.py` extract source-hashed observations
  and perform variant-safe PC inventory joins.
- `legacy.py` converts the earlier mapping corpus into scoped candidates and
  contextual or contradictory evidence without inheriting confidence tiers.
- `review_queue.py` and `consumer_exports.py` implement deterministic review
  artifacts and the accepted-only, hash-gated Ghidra/IDA boundary.
- `schema.py`, `database.py`, `build.py`, and `validation.py` define the
  rebuild-only schema, transactional persistence, atomic construction, and
  cross-table semantic checks.
- `release.py` and `scripts/build_research_preview.py` create and verify a
  deterministic source-only research preview; the database remains separate.

## Documentation

- [Data model](docs/DATA_MODEL.md): identities, observations, hypotheses,
  evidence, review, and schema-8 corpus tables.
- [Data sources](docs/DATA_SOURCES.md): manifested inputs, provenance, and
  redistribution boundaries, including SDK variant and boundary safety.
- [Review workflow](docs/REVIEW_WORKFLOW.md): deterministic queues, snapshots,
  and evaluation.
- [Consumer exports](docs/CONSUMER_EXPORTS.md): exact acceptance and executable
  identity gates.
- [Contributing](docs/CONTRIBUTING.md): evidence and identity requirements.
- [Maintenance](docs/MAINTENANCE.md): rebuild, validation, and release policy.
- [Publication](docs/PUBLICATION.md): source-preview packaging and legal gates.

The project-authored source code is licensed under the MIT License; see
[`LICENSE`](LICENSE). That license does not grant rights to the Xbox PDB, game
executables, dumped executable, raw SDK, generated database, or bulk derived
records. Redistribution rights for those inputs and derived data remain
unresolved and must be reviewed separately. Keep them private until the owner
makes an explicit decision for each release boundary.
