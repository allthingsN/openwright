# The Compliance Boundary

This is the most important page in the project. Read it before you rely on any
OpenWright output.

## What OpenWright does

OpenWright produces **evidence that specific controls were exercised** at an
agent's runtime, and attests that evidence so it is tamper-evident and
independently verifiable. Concretely, a OpenWright report lets a third party
confirm, without trusting you:

- that a specific set of events was committed to an append-only log;
- that no committed event was later altered, reordered, inserted, or deleted;
- which regulatory controls those events were evaluated against, **with a
  primary-source citation for each control**; and
- the result of that evaluation: **satisfied / not-satisfied /
  insufficient-evidence**.

## What OpenWright does NOT do

OpenWright **does not, and must not be read to, assert or imply**:

- legal compliance with the EU AI Act, GDPR, SOC 2, or any other regime;
- a certification, conformity assessment, or "seal of approval";
- an audit opinion or assurance engagement conclusion;
- that a control was *adequately* exercised, only that evidence of its exercise
  exists and is integrity-protected;
- the *truthfulness* of the party that recorded the evidence (see
  [SECURITY.md](SECURITY.md)).

Those determinations are reserved for **qualified auditors, notified bodies, and
counsel**. A "satisfied" result means *the recorded evidence meets the testable
predicate the crosswalk states for that control* — it is an input to a
professional's judgment, not a substitute for it.

## Why the distinction is enforced, not just stated

Overclaiming compliance is the single largest legal and credibility risk for a
tool in this space (spec risk R-02). So the boundary is enforced in code:

- `report.BOUNDARY_STATEMENT` is embedded in **every** signed JSON report;
- it is rendered in a highlighted box in the **PDF**;
- it appears in the OSCAL output's `metadata.remarks`;
- each crosswalk carries its own `disclaimer` field, surfaced in the report;
- the CLI help and package docstring repeat it;
- a test (`test_boundary_statement_in_all_artifacts`) fails the build if the
  boundary is ever dropped from an artifact.

This satisfies FR-RPT-07, NFR-COMP-01, and NFR-COMP-02.

## Crosswalk authority

The shipped crosswalks are **maintainer-authored**, rigorously cited, and dated,
but they are **pending** qualified legal/standards-body review (spec risk R-01,
assumption A-05). They carry **no normative authority of their own** (constraint
C-03); regulatory text is the source of truth. The path to third-party review and
a "reviewed-by" attestation is described in
[CROSSWALK_GOVERNANCE.md](CROSSWALK_GOVERNANCE.md).

## The verbatim statement

> This report constitutes EVIDENCE that the listed controls were exercised at
> runtime, attested with a tamper-evident Merkle log and an Ed25519 signature.
> It DOES NOT constitute legal compliance, certification, conformity assessment,
> or an audit opinion. Determinations of compliance are reserved for qualified
> auditors, notified bodies, and counsel. Crosswalks are maintainer-authored,
> rigorously cited, and pending qualified legal/standards review.
