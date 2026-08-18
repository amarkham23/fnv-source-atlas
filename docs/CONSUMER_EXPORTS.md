# Accepted-only consumer exports

`fnv_atlas.consumer_exports` is a read-only bridge from the atlas review model
to Ghidra and IDA. It is intentionally not a matching engine. It does not score
evidence, infer agreement between reviewers, change atlas rows, or turn a
candidate into an accepted mapping.

The layer produces two distinct JSON document types:

- `fnv-source-atlas-consumer-export-plan/v1` contains executable actions plus
  every accepted decision that was blocked by the safety policy.
- `fnv-source-atlas-candidate-report/v1` inventories producer candidates and
  one reviewer's current leaf state. It is explicitly non-executable, and the
  script renderers reject its Python artifact type.

## What qualifies for an executable action

The caller must select one stable `reviewer_id` and one stable
`review_release_id`. An action is emitted only when all of the following are
true:

1. The decision is that reviewer's current leaf for its exact target.
2. The leaf decision itself belongs to the selected review release.
3. Its action is explicitly `accept`.
4. It accepts a scalar claim directly, or accepts an alternative that contains
   one scalar claim.
5. The claim names an exact PC function and an exact Xbox 360 function.
6. The PC endpoint belongs to a PC program and uses a runtime address space
   (`ram` or `va`); the Xbox endpoint belongs to an Xbox 360 program.
7. The Xbox function has exactly one distinct explicit primary name.
8. The accepted claim (and, for an alternative, its parent hypothesis set),
   both endpoint functions, and the selected primary Xbox name all have
   producer/assertion provenance tied to the selected release's exact input
   manifest. An alternative inherits lineage from its parent set and selected
   claim because alternatives do not carry an independent provenance column.
9. All accepted mappings at the same physical PC entry agree on both the exact
   Xbox function identity and the raw Xbox name.

An acceptance by another reviewer has no effect. Multiple reviewers are never
counted as a vote, and no consensus field is calculated. If the selected
reviewer's older acceptance has a later `reject`, `defer`, `reopen`, or
`supersede` successor, the older row is history rather than a current export
authorization.

Repeated accepted lineages for the same exact mapping are consolidated into one
tool action without losing their decision, claim, alternative, hypothesis-set,
reviewer, or release records.

## Blocked accepted decisions

Unsafe accepted decisions remain in the export plan's `blocked` array. They are
never silently discarded. Stable reason codes include:

- `hypothesis_set_only_acceptance`: accepting a set preserves its ambiguity; it
  does not select an alternative.
- `xbox_fold_bundle`: a fold bundle is not one exact logical destination.
- `pc_unresolved_endpoint` or `xbox_unresolved_endpoint`.
- `missing_pc_function` or `missing_xbox_function`.
- `pc_endpoint_wrong_platform` or `xbox_endpoint_wrong_platform`.
- `pc_address_space_not_runtime`.
- `alternative_pc_subject_mismatch`.
- `provenance_manifest_mismatch`: at least one accepted target, endpoint
  function assertion, or selected primary-name assertion is absent from or tied
  to a different input manifest than the selected review release.
- `missing_xbox_name` or `ambiguous_xbox_names`.
- `conflicting_accepted_destination` or `conflicting_accepted_name` at one
  physical PC entry.

This makes a human review mistake or an incomplete mapping visible without
allowing it to mutate a reverse-engineering project.

## Executable identity gate

The selected review release must reference a valid content-addressed input
manifest with exactly one `pc_executable` entry. Plan construction verifies the
manifest digest, its normalized entries, and the executable artifact identity.
It also verifies the complete mapping lineage against that same manifest;
placing a human decision in a release is not by itself permission to export
claims or symbols imported from another release.
Both generated scripts hash the reverse-engineering tool's input executable and
abort before applying any action if it differs from that manifest SHA-256.

Each script then performs an exact-entry check:

- Ghidra uses `getFunctionAt(address)` and verifies the returned entry point.
- IDA uses `ida_funcs.get_func(address)` and verifies `start_ea` equals the
  accepted PC entry.

The scripts never call a function-creation API. A missing function, rejected
label, tool exception, or comment failure is logged and skipped. Labels are
portable ASCII identifiers derived from the raw Xbox name and carry a stable
hash suffix. The complete review lineage remains in the JSON plan; the
unmodified Xbox name and stable lineage IDs are also placed in the generated
function comment.

## Python API

The APIs accept either a filesystem path or an existing `sqlite3.Connection`.
Paths are opened with SQLite `mode=ro`; all database statements in this module
are `SELECT` statements.

```python
from pathlib import Path

from fnv_atlas.consumer_exports import (
    build_candidate_report,
    build_export_plan,
    candidate_report_json,
    export_plan_json,
    render_ghidra_script,
    render_idapython_script,
)

database = Path("build/fnv-source-atlas.sqlite")
reviewer_id = "reviewer:sha256:..."
review_release_id = "review-release:sha256:..."

plan = build_export_plan(
    database,
    reviewer_id=reviewer_id,
    review_release_id=review_release_id,
)
Path("accepted-plan.json").write_text(
    export_plan_json(plan) + "\n", encoding="utf-8", newline="\n"
)
Path("apply-atlas-ghidra.py").write_text(
    render_ghidra_script(plan), encoding="utf-8", newline="\n"
)
Path("apply-atlas-ida.py").write_text(
    render_idapython_script(plan), encoding="utf-8", newline="\n"
)

report = build_candidate_report(
    database,
    reviewer_id=reviewer_id,
    review_release_id=review_release_id,
)
Path("candidate-review.json").write_text(
    candidate_report_json(report) + "\n", encoding="utf-8", newline="\n"
)
```

Writing these output files is the caller's choice; plan/report construction
does not write to the atlas database. Keep the accepted plan beside its exact
database release and inspect `blocked` before running either script.

## Scope

This first consumer layer transfers reviewed names and an audit comment only.
It does not transfer prototypes, types, layouts, globals, source files, or
candidate confidence. Those require their own reviewed contracts and tool-side
validation rather than being smuggled through a name export.
