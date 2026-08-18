# Human review queues and release snapshots

`fnv_atlas.review_queue` turns the atlas candidate graph into deterministic,
read-only review artifacts. It does not add or update decisions. It also does
not score evidence, choose an alternative, infer confidence, or combine several
reviewers into a consensus.

## The three artifacts

`build_review_queue_page(...)` returns one bounded, standalone
`ReviewQueuePage` for an explicitly selected reviewer and review release. Each
item is one hypothesis set. The item keeps:

- the PC subject, including unresolved subjects;
- every scalar or fold-bundle alternative;
- set-, alternative-, and claim-scoped evidence with its literal effect,
  independence group, strength, details, and provenance;
- every reviewer's current leaf decision at each exact target scope; and
- a separate selected-reviewer state for the exact selected release.

`build_review_release_snapshot(...)` freezes every claim, hypothesis set, and
alternative in the loaded database together with one named reviewer's
release-bound state. Its canonical JSON and SHA-256 identity make it suitable
as a reproducible gold-label snapshot. Its shared provenance, endpoint, and
fold-bundle catalogs prevent the archival artifact from repeating large records
for every target. Claims, sets, and alternatives remain different evaluation
units: accepting a set is not copied to its alternatives, and accepting an
alternative is not copied to its scalar claim.

`evaluate_producers(snapshot)` compares producer target inventories with that
one snapshot. It reports only `accepted`, `rejected`, `deferred`, and `open`
counts, both overall and by exact target kind. It intentionally calculates no
precision, accuracy, confidence, or reviewer consensus. When nothing has been
reviewed, every unit is `open`; there is no fabricated zero-percent result.

Example:

```python
from fnv_atlas.review_queue import (
    build_review_queue_page,
    build_review_release_snapshot,
    evaluate_producers,
)

page = build_review_queue_page(
    "build/fnv-source-atlas.sqlite",
    reviewer_id="reviewer:alice",
    review_release_id="review-release:v0.5-review-1",
    limit=50,
    fold_sample_limit=8,
)

while page.to_dict()["next_cursor"] is not None:
    page = build_review_queue_page(
        "build/fnv-source-atlas.sqlite",
        reviewer_id="reviewer:alice",
        review_release_id="review-release:v0.5-review-1",
        limit=50,
        after=page.to_dict()["next_cursor"],
        fold_sample_limit=8,
    )

snapshot = build_review_release_snapshot(
    "build/fnv-source-atlas.sqlite",
    reviewer_id="reviewer:alice",
    review_release_id="review-release:v0.5-review-1",
)
evaluation = evaluate_producers(snapshot)

page_json = page.to_json()
snapshot_json = snapshot.to_json()
evaluation_json = evaluation.to_json()
```

These calls use only `SELECT` statements. A filesystem database is opened with
SQLite `mode=ro`. Passing an existing `sqlite3.Connection` is supported for
tests and embedded consumers, but the module still executes no mutation or
temporary-schema statements.

## Release-bound state

The queue shows all reviewers' literal current leaves so disagreement is not
hidden. The selected reviewer's state for the selected release follows these
rules:

| Current leaf | State in selected release |
|---|---|
| `accept` in this release | `accepted` |
| `reject` in this release | `rejected` |
| `defer` in this release | `deferred` |
| `reopen` or `supersede` in this release | `open` |
| no current leaf | `open` |
| current leaf belongs to another release | `open` |

An older- or newer-release leaf is retained in the artifact with the basis
`current_leaf_from_another_release`; it is never silently discarded or treated
as a decision on the selected release. Distinct literal leaf actions are marked
as an action disagreement, but no majority or winning action is computed.

## Descriptive triage

Queue order uses six visible buckets, not a hidden score. The first applicable
rule wins:

1. `contradicted`: at least one set-, alternative-, or claim-scoped evidence
   row literally has effect `contradicts`.
2. `incomplete`: the set has no alternatives, has no directional (`supports`
   or `contradicts`) evidence, or contains an empty fold bundle.
3. `ambiguous`: more than one alternative remains in the set.
4. `fold`: the single alternative is one complete fold bundle.
5. `unresolved`: the single scalar alternative contains an unresolved PC or
   Xbox endpoint.
6. `exact`: the single alternative is a resolved function-to-function scalar
   topology.

`exact` describes shape only. It does not mean accepted, correct, high
confidence, or safe to export. Every item also carries all triage flags and raw
counts, so characteristics hidden by precedence remain visible—for example, an
ambiguous set can also report that one alternative is a fold bundle.

Within one bucket, items sort by stable hypothesis-set ID. The page builder
streams the complete ordered key index to obtain bucket counts and a
`queue_order_sha256`, but materializes details only for the requested page. A
cursor is tied to that ordering identity and the exact reviewer, release,
triage, and fold-sample context. A cursor from another queue is rejected. If an
evidence change moves an item between buckets, an older cursor is rejected and
review should restart at the first page.

## Fold safety

A fold group remains exactly one alternative. The artifact contains its total
member count and a deterministic function-ID-ordered sample bounded by
`fold_sample_limit` (default 8, maximum 100). It never turns members of a large
fold into independent candidate mappings. A zero sample limit is valid when a
consumer wants counts with no member details.

## Suggested community workflow

1. Register a durable reviewer identity and immutable review-release context
   through the database's append-only review APIs.
2. Generate bounded pages and save their common `queue_order_sha256` alongside
   review notes.
3. Inspect the set proposition and then the exact alternative or claim being
   decided. Record the decision at that same scope; do not accept a parent as a
   shortcut for accepting its children.
4. Regenerate the queue. The current leaf changes only for that reviewer and
   exact target; other reviewers and the producer candidate remain untouched.
5. At a release checkpoint, save `ReviewReleaseSnapshot.to_json()` and its
   `snapshot_sha256` as the reproducible review artifact.
6. Use the count-only producer evaluation to measure reviewed coverage and
   decision distribution. Do not describe those counts as precision until an
   independently designed benchmark defines truth and sampling policy.

The accepted-only Ghidra/IDA consumer export is a later, separate boundary.
Neither a queue nor a snapshot is executable rename input.
