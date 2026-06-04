# Crosswalk Governance

This document specifies how OpenWright's compliance crosswalks are authored, versioned, cited, and trusted. It describes only what is implemented in OpenWright v0.1.

> **This is not legal advice.** OpenWright produces *evidence* that specific controls were exercised at runtime. It does **not** assert legal compliance, certification, conformity assessment, or an audit opinion. Determinations of compliance are reserved for qualified auditors, notified bodies, and counsel. The crosswalks shipped in this repository are maintainer-authored, rigorously cited, and **pending** qualified legal/standards-body review. They carry **no normative authority** (C-03).

---

## 1. What a crosswalk is

A crosswalk maps OpenWright canonical events (`ComplianceEvent`) to a set of regulatory or framework controls, and defines — for each control — a testable predicate over those events.

Two design rules are foundational:

- **Crosswalks are data, not code (FR-MAP-01).** There is no per-article or per-criterion logic hard-coded in Python. Each crosswalk is a declarative YAML document. The engine in `src/openwright/crosswalk.py` is a generic interpreter; it has no knowledge of any specific article or criterion.
- **Crosswalks are declarative, versioned YAML (NFR-MNT-01).** Built-in crosswalks live in `src/openwright/crosswalks/`. The directory currently contains:
  - `eu_ai_act.yaml` — EU AI Act crosswalk `v1.0.0` (Articles 12, 13, 14, 26, 27, 73).
  - `soc2.yaml` — SOC 2 Trust Services Criteria crosswalk `v1.0.0` (CC7.2).
  - `CHANGELOG.md` — the shared, per-crosswalk changelog.

Built-ins are loaded by logical name via `crosswalk_loader.load_builtin("eu-ai-act" | "soc2")`. Custom files are loaded with `crosswalk_loader.load_crosswalk_file(path)`. Both paths funnel through `load_crosswalk_text()`, which requires a top-level `crosswalk:` key and validates the document against the `Crosswalk` pydantic model.

---

## 2. Versioning, citation, and provenance

### 2.1 Independent versioning (FR-MAP-05)

Each crosswalk carries its own `version` field and is versioned **independently** of the OpenWright package. Built-in crosswalks share a single `CHANGELOG.md` in `src/openwright/crosswalks/`, with a section per crosswalk `id` recording each version, its release date, and what changed.

### 2.2 Every report records the crosswalk version that produced it

`report.build_report()` embeds the exact crosswalk identity into the signed report under a `crosswalk` block:

```json
"crosswalk": {
  "id": "...",
  "title": "...",
  "version": "...",
  "source": "...",
  "reviewed_as_of": "...",
  "disclaimer": "..."
}
```

These values are copied from the `CrosswalkResult` returned by `evaluate()` (`crosswalk_id`, `crosswalk_title`, `crosswalk_version`, `source`, `reviewed_as_of`, `disclaimer`). Because the entire report is Ed25519-signed, the crosswalk version that produced a given set of control results is itself tamper-evident: a result can always be traced back to the precise crosswalk revision that generated it.

### 2.3 Primary-source citation and review date (NFR-MNT-02)

Every control cites its primary source and the date the source text was reviewed:

- At the **crosswalk** level: `source` (the governing instrument) and `reviewed_as_of` (the date the instrument text was last reviewed).
- At the **control** level: a `citation` object naming the instrument and the specific provision (`article` or `clause`, plus `paragraphs`), a `url`, a verbatim `quote` of the cited text, an `effective_date`, and optional `notes`.

This is enforced structurally: `Crosswalk` requires `source` and `reviewed_as_of`, and `Control` requires a `citation` whose `instrument` is mandatory.

---

## 3. Crosswalk file format

A crosswalk is a YAML document with a single top-level `crosswalk:` mapping. The model is defined in `src/openwright/crosswalk.py`.

### 3.1 Crosswalk-level fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable logical identifier (e.g. `eu-ai-act`). |
| `title` | yes | Human-readable title. |
| `version` | yes | Independent semantic version of this crosswalk. |
| `source` | yes | The governing instrument (e.g. `Regulation (EU) 2024/1689`). |
| `reviewed_as_of` | yes | Date the source text was reviewed (ISO date string). |
| `description` | no | Free-text scope summary. |
| `disclaimer` | no | The non-compliance/non-opinion statement carried into reports. |
| `controls` | yes | List of `Control` objects. |

The model uses `extra="forbid"` at the crosswalk level: unknown top-level keys are rejected at load time.

### 3.2 Control fields

Each entry in `controls` is a `Control` (`extra="forbid"`):

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Control identifier, unique within the crosswalk. |
| `title` | yes | Human-readable control title. |
| `requirement` | yes | Plain-language statement of what must hold. |
| `citation` | yes | Primary-source citation (see below). |
| `scope` | no | An `EventFilter` selecting the events this control applies to. Defaults to an empty filter (all events). |
| `condition` | yes | A `Condition` predicate evaluated against each in-scope event. |
| `empty_scope` | no | Policy when no events fall in scope. Defaults to `insufficient_evidence`. |
| `rationale` | no | Free-text explanation of why the predicate is the right test. |

`citation` is a `Citation` object (`extra="allow"`):

| Field | Required | Meaning |
|---|---|---|
| `instrument` | yes | The governing document. |
| `article` / `clause` | no | The cited provision (use `article` for regulations, `clause` for framework criteria). |
| `paragraphs` | no | List of paragraph identifiers. |
| `url` | no | Link to the primary source. |
| `quote` | no | Verbatim excerpt of the cited text. |
| `effective_date` | no | When the cited obligation takes effect. |
| `notes` | no | Caveats (e.g. pending amendments). |

### 3.3 `EventFilter` (scope and link targets)

An `EventFilter` (`extra="forbid"`) selects events. All present sub-filters are ANDed:

| Field | Matches on |
|---|---|
| `kind` | `event.kind` is in the listed values. |
| `risk_classification` | `event.risk.classification` is in the listed values. |
| `oversight_status` | `event.oversight.status` is in the listed values. |
| `source_format` | `event.source.format` is in the listed values. |
| `attribute_equals` | Each dotted path equals the given value (exact match). |
| `has` | Each listed dotted path resolves to a non-null value. |

An empty `EventFilter` (`{}`) matches every event.

### 3.4 `Condition` predicate DSL (FR-MAP-06)

A `Condition` (`extra="forbid"`) is evaluated per in-scope event. The `type` field selects the predicate:

| `type` | Fields used | Holds when |
|---|---|---|
| `committed` | — | The event is present in the evaluated ledger snapshot (its `ledger.leaf_hash` is set). Presence in the append-only Merkle ledger is itself the evidence. |
| `field` | `path`, `op`, `value` | A field comparison on the event. |
| `linked` | `link`, `target` | The event is linked to another in-scope event matching the `target` `EventFilter` (see link kinds). |
| `any_of` | `conditions` | At least one sub-condition holds. |
| `all_of` | `conditions` | All sub-conditions hold. |
| `not` | `conditions` | Not all sub-conditions hold (negation of the `all_of` of its children). |

**`field` operators** (`op`): `exists` (default), `eq`, `ne`, `in`, `gte`, `lte`. `path` is a dotted path into the JSON-serialized event (e.g. `io.output_ref`, `risk.rationale_ref`, `attributes.finish_reasons`).

**`linked` link kinds** (`link`):

| `link` | Resolution |
|---|---|
| `approval_ref` | Follows `oversight.approval_ref` to the referenced event by `event_id`, then matches it against `target`. |
| `same_task` | Matches any other event sharing the same `provenance.task_id`. |
| `same_context` | Matches any other event sharing the same `provenance.context_id`. |
| `references_root` | Matches any other event sharing the same `provenance.root_task_id`. |

For the `same_*` / `references_root` kinds, the linking key must be present on the subject event, and at least one *other* event must share that key and match `target`.

---

## 4. The strict three-state result rule (FR-MAP-07)

`evaluate(crosswalk, events)` returns a `CrosswalkResult` containing one `ControlResult` per control. Every control resolves to exactly one of:

- `satisfied`
- `not_satisfied`
- `insufficient_evidence`

The evaluation procedure for each control is:

1. **Scope.** Select in-scope events via the control's `scope` filter.
2. **Empty scope.** If no events are in scope, report the control's `empty_scope` policy. The default — and the policy used by every shipped control — is `insufficient_evidence`. **An empty scope is never collapsed into `not_satisfied`** (FR-MAP-07): absence of in-scope evidence is reported honestly as "nothing to evaluate," not as a failure.
3. **Predicate.** Otherwise, evaluate `condition` against each in-scope event. If every in-scope event satisfies the predicate, the control is `satisfied`. If any in-scope event fails it, the control is `not_satisfied`, and the failing events are recorded in `gap_event_ids`.

`empty_scope` may also be set to `satisfied` (vacuously true — use sparingly and document why in `rationale`) or `not_satisfied`. The default is the honest one.

Each `ControlResult` also reports `evaluated_count`, `satisfied_count`, a human-readable `reason`, and bounded lists of `evidence_event_ids` and `gap_event_ids` (capped at 50 each to keep reports bounded).

---

## 5. Trust escalation path (NFR-MNT-03) and authority (C-03)

The crosswalks in this repository at v0.1 are **maintainer-authored and rigorously cited**, but they have **no normative authority** (C-03) and are **pending qualified legal/standards-body review** (NFR-MNT-03).

The intended escalation path is:

1. **v0.1 (current):** maintainer-authored, every control tied to a primary-source citation with a `quote`, `url`, and a `reviewed_as_of` date.
2. **Qualified review (planned milestone):** review by qualified legal counsel and/or the relevant standards body. Only after such review will a "reviewed-by" attestation be added to a crosswalk's metadata. As recorded in `CHANGELOG.md`, this is a planned funded milestone and no such attestation exists yet.

This boundary is carried into every artifact OpenWright produces. The report `BOUNDARY_STATEMENT` (in `report.py`) and each crosswalk's `disclaimer` field both state plainly that the output is evidence, not a compliance determination, and that crosswalks are maintainer-authored and pending review. The OSCAL and SARIF exporters carry the same boundary statement.

---

## 6. EU AI Act timeline caveat

The `eu-ai-act` crosswalk cites obligations from **Regulation (EU) 2024/1689** ("EU AI Act"). The relevant timeline as reviewed on 2026-05-28:

- High-risk obligations in Chapter III (including Articles 12, 13, 14, 26, 27) apply from **2 August 2026** under the Regulation **as enacted**. Each affected control records `effective_date: "2026-08-02"`.
- A **"Digital Omnibus" provisional political agreement** (reached 6–7 May 2026) would defer Annex III standalone high-risk obligations to **2 December 2027** — but that amendment is **not yet adopted or published** in the Official Journal. Therefore **2 August 2026 legally stands**.

This caveat is recorded both in the header of `eu_ai_act.yaml` and in `CHANGELOG.md`, and is referenced in control `notes` (e.g. `art-12-record-keeping`). **Re-verify this date before relying on it.** None of the above is legal advice.

---

## 7. Worked example: adding a new control

Suppose you want to add a control to the EU AI Act crosswalk asserting that **every serious-incident event records a `severity` attribute**. You would add the following entry to the `controls:` list in `src/openwright/crosswalks/eu_ai_act.yaml`:

```yaml
    - id: art-73-incident-severity
      title: "Article 73 — Serious-incident severity recorded"
      requirement: >
        Every recorded serious incident records a severity classification.
      citation:
        instrument: "Regulation (EU) 2024/1689"
        article: "73"
        paragraphs: ["1"]
        url: "https://artificialintelligenceact.eu/article/73/"
        quote: >
          Providers of high-risk AI systems placed on the Union market shall
          report any serious incident to the market surveillance authorities ...
        effective_date: "2026-08-02"
      scope:
        kind: ["incident"]
      condition:
        type: field
        path: "attributes.severity"
        op: exists
      empty_scope: insufficient_evidence
```

Then update the crosswalk version and `CHANGELOG.md`:

1. Bump `version:` in the crosswalk header (e.g. `1.0.0` → `1.1.0`), since the control surface changed.
2. If you re-reviewed the source text, update `reviewed_as_of:`.
3. Add a changelog entry under the `## eu-ai-act` section in `src/openwright/crosswalks/CHANGELOG.md` describing the added control and the date.

Because reports embed the crosswalk `version`, any report produced after this change is attributable to the new revision.

---

## 8. Authoring and validating a custom crosswalk file

A custom crosswalk is an ordinary YAML file loaded with `load_crosswalk_file(path)`; it does not need to live in the package directory. Minimal example:

```yaml
crosswalk:
  id: internal-policy
  title: "Internal agent-oversight policy"
  version: "0.1.0"
  source: "ACME internal policy POL-AI-001"
  reviewed_as_of: "2026-05-28"
  disclaimer: >
    Evidence that internal controls were exercised. Not a compliance
    determination.
  controls:
    - id: pol-001-approval
      title: "High-risk decisions require human approval"
      requirement: >
        Every high-risk agent decision links to an approved human-approval event.
      citation:
        instrument: "ACME internal policy POL-AI-001"
        clause: "3.2"
      scope:
        kind: ["agent_decision"]
        risk_classification: ["high"]
      condition:
        type: linked
        link: approval_ref
        target:
          kind: ["human_approval"]
          oversight_status: ["approved"]
      empty_scope: insufficient_evidence
```

**Validation.** Loading is validation: `load_crosswalk_file()` parses the YAML and runs it through `Crosswalk.model_validate()`. Because the `Crosswalk`, `Control`, `EventFilter`, and `Condition` models use `extra="forbid"`, any unknown or misnamed key, missing required field (`id`, `title`, `version`, `source`, `reviewed_as_of`; per control `id`, `title`, `requirement`, `citation`, `condition`), or malformed structure is rejected at load time with a pydantic validation error. You can validate a file by loading it:

```python
from openwright.crosswalk_loader import load_crosswalk_file
cw = load_crosswalk_file("path/to/your_crosswalk.yaml")  # raises on any error
```

The CLI also surfaces built-ins via `openwright crosswalks`, and a custom crosswalk can be supplied wherever a crosswalk is consumed (e.g. report generation), at which point the same load-time validation applies.

---

## 9. Summary of the hard boundary

OpenWright's crosswalks turn agent runtime behavior into cited, three-state control results over a signed, tamper-evident log. They are declarative, independently versioned, primary-source-cited data — not legal interpretations. A `satisfied` result means **evidence exists that a control was exercised**, mapped to a maintainer-authored, citation-backed predicate. It does **not** mean the system is legally compliant, certified, or has passed an audit. Those determinations remain with qualified auditors, notified bodies, and counsel. **This document is not legal advice.**