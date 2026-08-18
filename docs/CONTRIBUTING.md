# Contributing to the source atlas

This project accepts research as evidence, not as certainty. A contribution may
add a candidate, preserve a contradiction, improve an extractor, or make an
unresolved endpoint easier to investigate without declaring that a PC/Xbox
mapping is correct.

Before contributing, read the [data model](DATA_MODEL.md), the
[review workflow](REVIEW_WORKFLOW.md), and the [data-source policy](DATA_SOURCES.md).
Tool exports have an additional safety boundary documented in
[consumer exports](CONSUMER_EXPORTS.md).

## Legal status comes first

The project-authored source code is licensed under the MIT License; see the
repository's [`LICENSE`](../LICENSE) file. That source-code license does not
grant rights to redistribute the Xbox PDB, game executables, dumped PC
executable, raw SDK tree, generated atlas database, or other PDB-derived bulk
data. Clearance for those inputs and derived data has not been established and
must be considered separately.

Do not submit any of those inputs or artifacts. Contributions to the
project-authored source and documentation are submitted under the same MIT
terms unless the repository owner explicitly agrees otherwise. Do not treat a
pull request, issue, patch, or review comment as an implied grant of rights to
third-party inputs or derived data. Contributors remain responsible for having
the right to share every byte they submit.

## What a useful mapping contribution contains

A mapping proposal should identify all of the following:

- the exact PC subject as an existing `function_id` or `target_id`;
- one hypothesis-set occurrence and its producer identity;
- every still-viable Xbox alternative, without choosing one for convenience;
- whether each alternative is a scalar claim or one complete fold group;
- each evidence row's exact scope: set, alternative, or scalar claim;
- literal effect: `supports`, `contradicts`, or `context`;
- an independence group describing the causal evidence channel;
- content-addressed provenance and enough method detail to reproduce it; and
- explicit diagnostics for exclusions, missing data, and variant uncertainty.

An independence group is not a tool name or a way to increase a score. Evidence
derived from the same structural assumption belongs to the same group even if
two scripts emitted it. For example, a vtable alignment and a reformatted view
of that alignment are not independent confirmations.

Use `context` when an observation is relevant but does not favor or disfavor
the proposition. Use `contradicts` rather than deleting an inconvenient result.
Leave `asserted_strength` empty unless the producer has a documented,
reproducible meaning for it. Never derive confidence or acceptance by counting
rows.

This is a review checklist, not a currently supported import format:

```json
{
  "pc_subject": {"kind": "function", "function_id": "pc:function:..."},
  "occurrence_identity": "producer-specific-stable-key",
  "alternatives": [
    {"kind": "scalar_claim", "claim_id": "claim:sha256:..."},
    {"kind": "fold_bundle", "fold_group_id": "x360-fold:..."}
  ],
  "evidence": [
    {
      "scope": "alternative",
      "alternative_id": "hypothesis-alternative:sha256:...",
      "effect": "supports",
      "evidence_kind": "closed_control_flow_square",
      "independence_group": "control-flow-neighborhood-v1",
      "source_content_id": "sha256:...",
      "details": {"conditional_on": ["hypothesis-set:sha256:..."]}
    }
  ]
}
```

When implementing an importer, use the database APIs rather than direct SQL.
The following shape attaches one genuinely alternative-specific observation to
an already-created candidate in a disposable test database:

```python
from fnv_atlas.database import AtlasDatabase

with AtlasDatabase.open("scratch-atlas.sqlite") as atlas:
    atlas.add_match_hypothesis_alternative_evidence(
        "hypothesis-alternative:sha256:...",
        effect="supports",
        evidence_kind="closed_control_flow_square",
        independence_group="control-flow-neighborhood-v1",
        provenance_id="provenance:sha256:...",
        details={
            "conditional_on": ["hypothesis-set:sha256:..."],
            "selection_policy": "unique-residual-v1",
        },
    )
```

Do not run contribution experiments against the release database. Rebuild a
scratch database or use an in-memory fixture, then add deterministic tests for
replay, conflicts, and input-order changes.

## Identity rules

Names and numeric addresses are lookup attributes, not universal identities.

- Preserve the program and address space with every address.
- Use the stable physical PDB record identity—module index, symbol stream, and
  record offset—for Xbox procedures and data symbols.
- Use only the canonical PC function inventory to identify PC functions.
- Keep a non-entry or uncertain address as an `unresolved_target`; do not create
  a function to make a join succeed.
- Keep every logical function at a folded address. A fold group is one compact
  disjunction, not hundreds of independent claims.
- Keep duplicate names, duplicate type display names, forward declarations,
  variants, and conflicting producer assertions.
- Use exact CodeView type indices within their explicit namespace. Do not join
  types by display name alone.

A patch that collapses any of these distinctions is data loss even if its
output looks simpler.

## Producer facts and human review are separate

Producer code writes candidate facts and evidence. It must not write `accept`
decisions, infer reviewer agreement, or mutate another producer's assertion.
Human review uses durable `reviewer_id` and `review_release_id` values and an
append-only decision chain at exactly one scope: hypothesis set, alternative,
or claim.

Reviewers may `accept`, `reject`, `defer`, `reopen`, or `supersede` with a
non-empty rationale. A later decision names its exact previous decision. One
reviewer's leaf never changes another reviewer's state, and accepting a set does
not accept its children. Follow the practical procedure in the
[review workflow](REVIEW_WORKFLOW.md).

The write-side API makes reviewer, release, and target scope explicit. This
example assumes the manifest, provenance, and alternative already exist in a
scratch database:

```python
from datetime import datetime, timezone

from fnv_atlas.database import AtlasDatabase

with AtlasDatabase.open("scratch-atlas.sqlite") as atlas:
    reviewer_id = atlas.upsert_reviewer(
        identity_kind="project-handle",
        identity_key="example-reviewer",
        display_name="Example reviewer",
    )
    release_id = atlas.upsert_review_release(
        release_key="local-review-r1",
        label="Local review build 1",
        source_revision="source-revision-id",
        manifest_id="sha256:...",
        provenance_id="provenance:sha256:...",
    )
    decision_id = atlas.add_review_decision(
        reviewer_id=reviewer_id,
        review_release_id=release_id,
        alternative_id="hypothesis-alternative:sha256:...",
        action="defer",
        decided_at=datetime.now(timezone.utc),
        rationale="Needs an independent call-site or type check.",
        provenance_id="provenance:sha256:...",
    )
```

Use the returned `decision_id` as `previous_decision_id` when appending a
successor. Do not rewrite or delete the earlier row.

## Experimental and canonical boundaries

Adding a file to an extractor test does not make it a canonical build input.
Canonical inclusion requires all of these:

1. an explicit input role and content identity;
2. a deterministic, loss-aware parser;
3. a documented persistence policy and provenance record;
4. synthetic tests for ambiguity, malformed input, and replay;
5. semantic validation rules that catch cross-table corruption;
6. a clean rebuild from the complete manifest; and
7. owner review of distribution and privacy consequences.

Experimental artifacts remain candidate/context observations with explicit
lineage. They may not seed recursive matching as though they were accepted
truth. SDK declarations remain observations even when the SDK source tree is
manifested, and GAME/GECK/unspecified variants remain distinct.

## Development workflow

Python 3.11 or later is required. From the repository root:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests -v
```

Build only when you possess the required local inputs and keep the output under
the ignored `build` directory:

```powershell
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

The build hashes inputs before parsing, rechecks them before publication, and
atomically replaces the destination only after integrity, foreign-key, schema,
manifest, and semantic validation pass. Never bypass those gates by checking in
a manually edited database.

For each code change:

1. Add a minimal synthetic fixture that contains no proprietary bytes.
2. Test both the normal path and the lossy/ambiguous/malformed edge case.
3. Test deterministic output under input reordering when order is not semantic.
4. Test idempotent replay and immutable-identity conflicts.
5. Run the focused tests, then the full suite.
6. If persistence changed, rebuild from scratch and run validation.
7. Update documentation without copying machine-local paths or private inputs.

## Pull-request checklist

- The patch contains no PDB, executable, dump, raw SDK file, generated database,
  extracted bulk corpus, credentials, or machine-local path.
- New facts have stable identities, content hashes, explicit provenance, and an
  exact candidate/evidence scope.
- Folds, unresolved endpoints, variants, and contradictory evidence remain
  explicit.
- No candidate is promoted by score, name similarity, majority vote, or source
  list order.
- Tests use synthetic or contributor-owned redistributable fixtures.
- Full tests pass, and schema/persistence changes have a fresh validation run.
- Public artifact changes follow the [publication policy](PUBLICATION.md).
- The legal-status section above is still accurate, or an owner-approved legal
  change accompanies the patch.

Security-sensitive findings and accidental proprietary-data exposure should be
reported privately to the repository owner through a channel the owner has
designated. Do not paste secrets, private paths, proprietary bytes, or exploit
details into a public issue while no disclosure process is published.
