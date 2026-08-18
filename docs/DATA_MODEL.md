# Data model

Schema 8 represents PC/Xbox source recovery as an evidence graph. It is not a
flat address-to-name map and it does not claim to be recovered source code.
Stable program records, physical debug records, observations, mapping
hypotheses, evidence, human decisions, and executable consumer actions are
different layers.

The central promotion boundary is deliberate:

```text
input fact or observation -> candidate hypothesis -> human review -> consumer export
```

No count, score, matching producer, SDK declaration, or address equality moves
a row across that boundary automatically.

## Programs, addresses, functions, and unresolved targets

`programs` identifies the PC game and Xbox 360 debug build.
`address_groups` identifies a numeric address inside one explicit program and
address space. The numeric address is not itself a function identity.

For Xbox procedures, the stable physical identity comes from the PDB module
index, symbol stream, and record offset, for example:

```text
x360-proc:m0045:s0055:o000001A4
```

Its resolved VA is a separate attribute. Several rows in `functions` may
therefore share one address group after identical-code folding without losing
their distinct names, types, source references, or physical records.
`fold_groups` and `fold_group_members` preserve that complete set and never rank
one member as the real function.

For PC, only keys in the canonical Ghidra inventory become `functions`. A call
target absent from that key set becomes an `unresolved_target`; an SDK address
inside executable code but absent from the inventory can become a boundary
candidate. Neither case manufactures a PC function.

`call_edges` records PC caller-to-callee relationships while keeping canonical
callee functions separate from unresolved targets. `modules` and
`source_files` retain portable compilation/source identity for the records that
refer to them; machine-local input roots are not semantic keys.

## Names, source references, and assertions

`function_names` and `class_names` permit multiple names and name kinds for one
logical identity. Primary status is an import projection, not a claim that an
Xbox alias is the correct PC name. Address-derived vtable labels and source
author declarations cannot silently replace canonical names.

Canonical function metadata, names, source ranges, class names, and vtable
slots have append-only producer assertion tables. Re-importing the same
projection from another producer cannot erase the earlier provenance or
details. Consumers can use the canonical row for convenience and the assertion
rows to audit its lineage.

## Function signatures and the complete CodeView type corpus

`function_signatures` is keyed by stable logical function ID, not by name or
address. It stores the exact CodeView type index and structured
`LF_PROCEDURE`/`LF_MFUNCTION` fields. Ordered parameters live in
`function_signature_arguments`; terminal `T_NOTYPE` vararg markers are
preserved. If a type belongs to an unavailable local or type-server namespace,
the signature remains present with an explicit resolution error.

Schema 8 also preserves the Xbox global TPI stream without reducing it to
rendered strings:

- `codeview_type_extractions` records extraction totals and provenance.
- `codeview_type_records` stores every physical record's type index, leaf kind,
  exact raw body, length, and raw-body SHA-256.
- `codeview_type_record_assertions` records the extraction-specific leaf name
  and rendered form.
- `codeview_tag_layouts` represents class, structure, union, and enum tag
  records, including definitions, forward references, size, field-list links,
  derivation/vtable-shape links, display names, and unique names.
- `codeview_field_members` identifies each physical field-list member by its
  source type index and record offset. `codeview_tag_member_uses` records every
  ordered use of that physical member by a tag, so continuation lists and
  repeated uses do not duplicate or lose identity.
- `codeview_method_overloads` preserves every physical `LF_METHODLIST`
  occurrence and its exact method type index, attributes, access, method kind,
  options, and optional vtable offset.
- `codeview_layout_diagnostics` retains parse limitations with source type and
  record offsets instead of dropping the containing layout.

Raw records remain the lossless fallback if a structured decoder is expanded
later. Rendered types are a view of those records, not a replacement for them.

## Typed Xbox data symbols

`data_symbol_extractions`, `data_symbol_records`, and
`data_symbol_record_assertions` preserve physical `S_LDATA32` and `S_GDATA32`
records from the module streams. Module/stream/offset identity remains distinct
from the optional resolved address. Each assertion retains section, offset,
exact type index, raw name, and resolution state.

Several data records may resolve to the same address; the schema does not
collapse aliases into one global. A data symbol is never admitted as a
function, and its type index can be joined to the CodeView corpus without
claiming that a rendered declaration is complete.

## Match claims, disjunctions, and scoped evidence

`match_claims` represents exactly one PC endpoint paired with exactly one Xbox
endpoint. Either endpoint may be a canonical function or an unresolved target.

`match_hypothesis_sets` represents one producer occurrence whose PC subject is
known but whose Xbox identity may remain ambiguous. Its unordered
`match_hypothesis_alternatives` may reference scalar `match_claims` or one Xbox
`fold_group` bundle. A fold bundle is one compact disjunction over the existing
physical members; it is never expanded into hundreds of apparently independent
claims. Legacy name ambiguity and control-flow residual ambiguity are likewise
retained as alternatives in one set rather than resolved by list order.

Evidence is attached at the narrowest scope the source supports:

- `match_hypothesis_evidence` applies to the entire disjunction once.
- `match_hypothesis_alternative_evidence` supports, contradicts, or
  contextualizes one exact alternative.
- `claim_evidence` is reserved for evidence that genuinely distinguishes one
  scalar endpoint pair outside a set occurrence.

Each evidence row records a literal `effect`, an `evidence_kind`, an
`independence_group`, provenance, optional asserted strength, and structured
details. Alternative fan-out cannot multiply set evidence. Producers that
depend on the same class/slot alignment or candidate mapping lineage share an
independence group and cannot be counted as independent confirmations merely
because they emitted several rows.

Confidence is optional metadata. The schema contains no trigger or helper that
promotes a claim by counting support, subtracting contradictions, or averaging
producer scores.

`observations` holds standalone contextual facts that do not assert a
directional PC/Xbox endpoint pair. Keeping those rows outside the claim tables
prevents a useful research note from being mistaken for mapping support.

## Xbox control flow and conditional derivation

`control_flow_sites` represents physical PowerPC branch instructions by Xbox
VA. `control_flow_uses` separately records every logical PDB procedure whose
declared extent contains a site, preserving folds, overlaps, and shared
physical instructions. Site and use assertions retain the exact extraction,
decoded instruction, syntactic role, target classification, and provenance.

A direct target is classified as one unique procedure, one complete fold group,
or an address-only non-entry/out-of-image endpoint. Indirect calls remain
explicitly indirect. No control-flow import can create a function, choose a
fold member, transfer a name, or change a mapping status. Procedure scan state
and coverage remain in `control_flow_scans` and `control_flow_extractions`.

The default `call_relevant_v1` persistence policy selects a physical site when
any logical use is a call or tail transfer, then retains every use of that
selected site. `all_branches_v1` is the opt-in full-CFG policy. Extraction and
persistence share the selection predicate.

The schema-8 control-flow matcher uses existing PC/Xbox mapping alternatives as
**conditional anchors**. It can record closed-square relations and
unique-residual proposal sets, but every output remains `candidate` with null
confidence. Evidence that distinguishes a residual alternative is stored in
`match_hypothesis_alternative_evidence`, and its details explicitly mark
`conditional_evidence = true`, `independent_confirmation = false`, and no
acceptance effect. The matcher preserves unresolved and fold endpoints, never
compares names, and never expands a fold bundle. Its own derived output is not
fed back as a fresh independent seed.

## Normalized vtables and alignment hypotheses

The normalized cross-platform vtable model uses `classes`, `vtables`, and
`vtable_slots`. A table identity includes platform class, vfptr role, address
space, and address. Primary, explicit secondary-subobject, and unresolved roles
remain distinct; a class is not reduced to its first or largest table. Slot
targets point to an address group or unresolved target.

`vtable_alignment.py` compares exact class-name overlaps and pairs only unique
compatible roles. It does not use list order, largest-table heuristics, or an
address-derived slot label to select a table. Candidate pairs and explicit
non-alignment reasons are stored in `vtable_alignment_candidates` and
`vtable_alignment_issues`.

Each equal-index slot occurrence becomes a candidate-only
`vtable_slot_alignment` linked to an occurrence-specific hypothesis set.
`vtable_hypotheses.py` resolves its PC subject to a canonical function or
address-specific unresolved target. The Xbox alternative is one exact
procedure, one intact fold bundle, or an address-specific unresolved target.
This normalized layer proposes structure; it does not accept a match, assign
confidence, or transfer an Xbox name to PC.

## Raw Xbox vftable symbols and pointer observations

The raw schema-8 vftable corpus complements rather than replaces the normalized
table model. Xbox MSVC vftable names are physical `S_PUB32` records in the PDB
DBI symbol-record stream, not typed per-module data records:

- `xbox_vftable_extractions` identifies the DBI and symbol streams, scan policy,
  totals, diagnostics, and provenance.
- `xbox_vftable_symbol_records` stores each exact physical record, including
  its raw bytes and SHA-256. `xbox_vftable_symbol_assertions` stores the
  section/offset/VA, public flags, exact decorated-name identity, conservative
  owner/qualifier/role encodings, parse status, and template flags.
- `xbox_vftable_name_identities` keys exact decorated-name bytes by content
  hash. Template owners and template qualifiers survive without guessing a
  demangled display identity.
- `xbox_vftable_address_observations` and
  `xbox_vftable_address_members` retain every physical same-address symbol as
  an unranked alias set. `is_ranked` is fixed false.
- `xbox_vftable_pointer_runs` stores executable-pointer prefixes and their
  termination/boundary observations. `extent_semantics` is fixed to
  `observed_pointer_prefix_not_declared_extent`: adjacent vftables may form one
  uninterrupted run, so a run is never treated as a declared table extent.
- `xbox_vftable_pointer_run_symbols` keeps all table/next-boundary symbol
  aliases associated with a run, while `xbox_vftable_pointer_slots` stores each
  physical slot address, raw word, and target address group.
- `xbox_vftable_diagnostics` preserves symbol, run, and scan limitations.

These rows are observations only. They do not create `vtables`, choose a
primary alias, manufacture functions at pointer targets, create mapping claims,
or apply names.

## SDK source manifests, observations, and PC inventory joins

The optional SDK import is disabled unless the operator explicitly supplies
`--sdk-root`; community builds omit it. It begins with a portable content identity.
`sdk_source_trees` stores the canonical tree SHA-256, file count, and total byte
count. `sdk_source_tree_files` stores root-relative POSIX paths, case-folded
collision keys, raw-file hashes, and byte lengths. Absolute extraction roots
are not persisted. The builder manifests the same canonical source-tree bytes
as the `pc_sdk_source_tree` input and fails if the tree changes before
publication. These hashes and the derived declaration/path rows can reveal
private source even though raw files are not copied, so SDK-enriched databases
remain private until separately reviewed.

`sdk_extractions` ties one observation run to that tree, the PC inventory,
policy counts, and provenance. The observation families are deliberately
separate:

- `sdk_prototype_observations` retains address annotations, declared names,
  signatures, declaration/source text, variant, lines, source file, and stable
  source ordinal.
- `sdk_call_target_observations` retains nested helper or typed-function-pointer
  calls. Parameter types and argument expressions remain ordered in
  `sdk_call_parameter_types` and `sdk_call_argument_expressions`; enclosing
  wrapper identity is context, not a target name.
- `sdk_data_observations` retains global-data declarations such as
  `AddressPtr` and `NIRTTI_ADDRESS` without treating them as functions.
- Per-family extraction assertions preserve source membership and order;
  `sdk_diagnostics` retains variant disagreements and parse limitations.

`sdk_code_inventory_joins` and `sdk_data_inventory_joins` classify observations
against the exact PC executable inventory and PE sections. Variant policy is
structural:

- A concrete GAME prototype at an exact canonical function entry may receive
  an `sdk_game_exact_entry_links` row. This is a definitive *inventory join*,
  not an accepted name or PC/Xbox mapping.
- An `unspecified_pc` observation at an exact entry is kept separately in
  `sdk_unspecified_exact_entry_candidates`; it does not inherit GAME status.
- GECK observations are classified as `non_game_variant` and never receive a PC
  game link.
- Data observations receive section classifications only; they do not create
  PC global identities.
- Executable non-entry `CREATE_OBJECT` observations may become
  `sdk_boundary_candidates`. `sdk_boundary_candidate_containers` records every
  known PC function extent containing the address without choosing one or
  adding a function.

SDK rows do not create function names, match claims, confidence, or review
decisions. Publication of source text or bulk derived records is a separate
rights decision; see [data sources](DATA_SOURCES.md).

## Human review

`reviewers` gives each contributor a durable identity.
`review_releases` records the exact manifested atlas release inspected.
`review_decisions` is append-only history targeting exactly one hypothesis set,
alternative, or scalar claim. A reviewer may accept, reject, defer, reopen, or
supersede an earlier decision with an explicit timestamp and rationale.

`current_review_decisions` exposes the leaf of each reviewer's history without
mutating the producer candidate or manufacturing consensus. A decision by one
reviewer does not authorize another reviewer, an older-release decision does
not carry into a newer release, accepting a set does not accept its
alternatives, and accepting a fold bundle does not select a member.

Deterministic queue pages preserve all evidence scopes and literal reviewer
leaves. Immutable snapshots bind one reviewer to one release and can be used to
count accepted, rejected, deferred, and open producer targets. Those counts are
review coverage, not accuracy or confidence. See the
[review workflow](REVIEW_WORKFLOW.md).

## Accepted-only consumer boundary

Consumer plans and Ghidra/IDA scripts are derived artifacts, not database
tables. An executable action requires the selected reviewer's current
release-bound `accept` decision on one exact scalar PC-function/Xbox-function
mapping, a single explicit primary Xbox name, complete lineage to the selected
input manifest, and no conflicting accepted destination/name at the PC entry.

The selected manifest must contain exactly one PC executable. Generated scripts
hash the reverse-engineering tool's input, abort on a mismatch, require an
existing exact function entry, and never call a function-creation API. Unsafe
acceptances remain visible in the plan's `blocked` array. Types, layouts,
globals, SDK declarations, candidates, and confidence are not smuggled through
the first name-export contract. See [consumer exports](CONSUMER_EXPORTS.md).

## Provenance, manifests, and release identity

Every extraction or import has a `provenance` row referring to a
content-addressed `input_manifest`. `input_artifacts` records SHA-256 and byte
size without storing ordinary input bytes; `manifest_entries` records stable
roles and portable logical names. Producer provenance also records method,
behavior parameters, schema version, package version, and producer-source
identity where applicable.

The builder hashes inputs before parsing and rechecks regular files, the SDK
tree manifest, and producer source before atomically replacing its destination.
The JSON build report records semantic coverage and validation results; a
sidecar hashes the resulting database. Database byte identity is not promised
across rebuild timestamps, so stable IDs, exact manifests, semantic summaries,
review snapshots, and the source-only preview manifest are the reproducibility
boundary.

Schema evolution is rebuild-only. A database is never upgraded or repaired in
place to make a newer package accept stale semantics. Release and publication
rules are documented in [maintenance](MAINTENANCE.md) and
[publication](PUBLICATION.md).
