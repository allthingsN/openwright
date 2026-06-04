"""Schema round-trip (V13): every emitted ComplianceEvent, crosswalk, and report
validates against the published JSON Schemas (FR-NRM-02)."""

from __future__ import annotations

import jsonschema
import pytest

from openwright.crosswalk import evaluate
from openwright.crosswalk_loader import available_builtins, load_builtin
from openwright.report import build_report
from openwright.spec import compliance_event_schema, crosswalk_schema, report_schema


def test_published_schemas_are_themselves_valid():
    # Each published schema must be a valid Draft 2020-12 schema.
    for schema in (compliance_event_schema(), crosswalk_schema(), report_schema()):
        jsonschema.Draft202012Validator.check_schema(schema)


def test_every_emitted_event_validates(populated_ledger):
    validator = jsonschema.Draft202012Validator(compliance_event_schema())
    events = list(populated_ledger.events())
    assert events
    for ev in events:
        validator.validate(ev.model_dump(mode="json", exclude_none=True))


def test_every_builtin_crosswalk_validates():
    validator = jsonschema.Draft202012Validator(crosswalk_schema())
    for name in available_builtins():
        cw = load_builtin(name)
        validator.validate(cw.model_dump(mode="json", exclude_none=True))


def test_built_report_validates_against_report_schema(populated_ledger, key):
    report_validator = jsonschema.Draft202012Validator(report_schema())
    event_validator = jsonschema.Draft202012Validator(compliance_event_schema())
    result = evaluate(load_builtin("eu-ai-act"), list(populated_ledger.events()))
    report = build_report(populated_ledger, result, key, scope_description="schema round-trip")

    # The whole report envelope validates against the published report schema...
    report_validator.validate(report)
    # ...and every embedded event still validates against the event schema.
    for item in report["events"]:
        event_validator.validate(item["event"])


@pytest.mark.parametrize("profile", [None, ["on_the_loop"], ["on_the_loop", "fria_applicable"]])
def test_profiled_reports_validate(populated_ledger, key, profile):
    """Profile variants (B14) still emit schema-valid reports + pinned hashes."""
    cw = load_builtin("eu-ai-act", profile=profile)
    result = evaluate(cw, list(populated_ledger.events()))
    report = build_report(populated_ledger, result, key, scope_description="profiled")
    jsonschema.Draft202012Validator(report_schema()).validate(report)
    assert report["crosswalk"]["content_hash"].startswith("sha256:")
