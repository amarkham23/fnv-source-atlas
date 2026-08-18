# Data sources, provenance, and redistribution boundaries

The atlas is built from local research inputs, but source inclusion is not a
claim of truth and a content hash is not redistribution permission. This
document describes the current engineering boundary; it is not legal advice.

The project-authored source code is licensed under the MIT License. That
source-code license does not grant rights to the Xbox PDB, generated database,
PDB-derived bulk records, game executables, dumped executable, or raw SDK. No
clearance has been established for redistributing those inputs or derived data;
keep them private unless the repository owner records a separate affirmative
decision for the exact artifact.

## Manifested build inputs

`BuildConfig` assigns each input an explicit role. The standard build currently
manifests these source families:

| Source family | Examples of explicit roles | Intended use |
|---|---|---|
| PC executable inventory | `pc_function_export`, `pc_executable` | Canonical PC function-entry boundary, executable ranges, and PC calls |
| Xbox debug artifacts | `xbox_pdb`, `xbox_executable`, `xbox_modules`, `xbox_function_sources` | Physical procedure/data identities, CodeView types, source links, and PowerPC control flow |
| Vtable/type exports | `pc_rtti_vtables`, `xbox_vtables`, `xbox_types` | Platform-specific classes, table roles, slots, and structural candidates |
| Legacy mapping corpus | `legacy_names_tiered`, `legacy_names_final`, `legacy_namemap`, `legacy_strmatch`, `legacy_pgm`, `legacy_matched_ghidra`, `legacy_agent_verdicts`, `legacy_all_seeds`, `legacy_assign`, `legacy_vmatch` | Candidate hypotheses and contextual/contradictory evidence, never inherited certainty |
| Optional SDK tree | `pc_sdk_source_tree` | Portable source-tree hash and observation boundary; declarations are not accepted mappings |

“Manifested” means the exact input identity participated in a build. It does
not mean that every row derived from it is canonical, accepted, independent, or
redistributable. The [data model](DATA_MODEL.md) describes how identities,
claims, observations, and evidence remain separate.

`BuildConfig.from_repo` never discovers an SDK from the repository layout. The
CLI manifests this optional source only when the operator deliberately passes
`--sdk-root`. Public and community builds should omit that flag; a private
local overlay can use a path such as `C:\private-inputs\local-sdk`.

The optional legacy experiment roles—fingerprint, both callee-align passes,
wrappers, both secondary PGM passes, and constant matching—remain explicitly
experimental. They are retained as candidate/context evidence with lineage.
They do not become truth because the builder can parse them.

## Content-addressed provenance

Regular files are hashed as raw bytes with SHA-256. `input_artifacts` records
the digest, byte size, and media type without storing the input bytes. A
canonical, order-independent manifest records role, portable logical name,
content ID, and metadata. Producer provenance then records:

- producer and producer version;
- method and behavior parameters;
- manifest identity;
- schema version and producer-source identity where applicable; and
- notes needed to understand exclusions or lossy source limitations.

The builder hashes first, parses second, and rehashes before publishing. A file
or SDK tree that changes during the build makes the build fail.

For the SDK directory, the manifested artifact is a deterministic source-tree
manifest rather than the raw source. It preserves root-relative POSIX paths,
per-file raw SHA-256 identities, sizes, and a tree identity. It rejects absolute
paths, traversal, case-fold collisions, and unstable path aliases. Individual
observations retain their relative source location and file hash; the absolute
extraction root is not serialized.

Contributors proposing a new source must provide, without uploading restricted
bytes:

- a clear source role and build/variant identity;
- SHA-256 and byte size, or a deterministic directory-manifest identity;
- the producer version and exact extraction command/parameters;
- a description of what the source can and cannot establish;
- a minimal redistributable synthetic fixture for tests; and
- the source's ownership, license, and redistribution status if known.

Unknown legal status must be recorded as unknown, not assumed permissive.

## Canonical versus experimental

The canonical boundary is about repeatable persistence, not epistemic
certainty. A canonical importer may persist candidate hypotheses, unresolved
targets, diagnostics, and contradictions. It must have deterministic identity,
loss-aware parsing, exact provenance, semantic validation, and rebuild support.

An experimental source stays outside that boundary until its lineage and
failure modes are understood. Experimental results:

- remain candidate or context records;
- cannot create functions from non-entry addresses;
- cannot choose one logical member of a fold;
- cannot transfer a wrapper's name to a nested call target;
- cannot combine GAME, GECK, and unspecified SDK variants;
- cannot recursively seed themselves as independent matching truth; and
- cannot assign confidence or acceptance automatically.

Moving a source into the canonical build requires the gates in
[CONTRIBUTING.md](CONTRIBUTING.md), a full rebuild, and maintainer approval.

## What may be stored locally

The local database deliberately preserves facts that lossy JSON maps discarded:
multiple logical records at one address, decorated names, source paths, raw
CodeView type bodies, layouts, signatures, globals, vtables, control-flow
sites, unresolved targets, evidence lineage, and review history. This makes the
database valuable for research and also makes its redistribution status more
sensitive than the source code alone.

The following local operations are supported when the operator lawfully
possesses the inputs:

```powershell
python -m fnv_atlas extract-xbox-procedures `
  --pdb C:\private-inputs\Fallout_Release_MemDebug.pdb `
  --exe C:\private-inputs\Fallout_Release_MemDebug.exe `
  --modules C:\private-inputs\modules_360.json `
  --output .\build\xbox-procedures.jsonl

python -m fnv_atlas extract-sdk-observations `
  --sdk-root C:\private-inputs\local-sdk `
  --output .\build\sdk-observations.json
```

These commands do not grant permission to publish their output. Extracted
names, paths, raw records, declaration text, and sufficiently complete
structured corpora may still carry third-party rights or expose private data.
Excluding raw SDK files from a package does not sanitize a generated database:
derived declarations, identifiers, relative paths, hashes, and address
observations can reveal information from the private source tree.

## Public-artifact boundary

The repository's research-preview packager uses an allowlist and excludes the
database, PDBs, executables, dumps, raw JSON inputs, raw SDK, and build
directories. It includes source, tests, selected documentation, a schema-only
snapshot, a sanitized report, and the checksum of the separately held database.
See [publication](PUBLICATION.md) for the exact checks.

Until an owner review says otherwise:

- do not commit or attach proprietary binaries, PDBs, dumps, or raw SDK files;
- do not publish generated SQLite databases or bulk PDB/SDK-derived exports;
- do not reconstruct restricted inputs from hashes or extracted fragments;
- do not include raw source/declaration bodies merely because they were parsed;
- do not treat a database checksum as permission to obtain or distribute it;
- do not put private input locations into reports, fixtures, logs, or examples;
  and
- do not call restricted inputs or derived data “open source” or “open data”;
  the project's MIT source-code license does not apply to those materials.

Small extracted factual assertions may be technically separable from their
source, but this repository has not made a blanket legal determination about
them. Each proposed public artifact needs its own source, privacy, and
redistribution review.

## Privacy and secret hygiene

PDB source paths, SDK paths, build reports, exception messages, and shell
history can reveal usernames or machine layout. Inputs and comments can also
contain access tokens, private repository URLs, or signing material.

- Store portable logical names and root-relative paths, never absolute roots.
- Use placeholders such as `C:\private-inputs` in documentation.
- Keep credentials out of CLI arguments, JSON details, provenance notes, and
  review rationales.
- Inspect deterministic JSON/JSONL before sharing; deterministic does not mean
  sanitized.
- Run both automated sensitive-path/secret checks and a manual file review.
- If exposure occurs, stop distribution, preserve hashes for incident tracing,
  rotate affected credentials, and replace the public artifact rather than
  editing its manifest in place.

Consumer rename plans have their own accepted-only and executable-hash gates;
they are documented in [consumer exports](CONSUMER_EXPORTS.md). Human review
artifacts and queues are described in [review workflow](REVIEW_WORKFLOW.md).
