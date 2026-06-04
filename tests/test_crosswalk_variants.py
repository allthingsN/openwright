"""EU AI Act crosswalk variants + deployer profiles + narrowed v1 (B13, B14, U12)."""

from __future__ import annotations

from openwright.crosswalk import ControlStatus, evaluate
from openwright.crosswalk_loader import available_builtins, load_builtin


def _ids(cw):
    return {c.id for c in cw.controls}


# -- backward compatibility: unprofiled default is the historical set ----------


def test_default_profile_is_backward_compatible(populated_ledger):
    cw = load_builtin("eu-ai-act")  # no profile -> default_profiles
    ids = _ids(cw)
    assert "art-14-human-oversight" in ids  # in-the-loop variant present by default
    assert "art-14-human-oversight-on-the-loop" not in ids  # on-the-loop excluded
    assert "art-27-fria" in ids  # FRIA included by default (historical)
    res = evaluate(cw, list(populated_ledger.events()))
    s = {c.control_id: c.status for c in res.controls}
    assert s["art-14-human-oversight"] == ControlStatus.NOT_SATISFIED
    assert s["art-12-record-keeping"] == ControlStatus.SATISFIED
    assert s["art-73-serious-incident"] == ControlStatus.INSUFFICIENT_EVIDENCE


# -- B14: variants selectable by deployer profile ------------------------------


def test_on_the_loop_profile_swaps_art14_variant():
    cw = load_builtin("eu-ai-act", profile=["on_the_loop"])
    ids = _ids(cw)
    assert "art-14-human-oversight-on-the-loop" in ids
    assert "art-14-human-oversight" not in ids  # in-the-loop excluded
    assert "art-27-fria" not in ids  # not FRIA-applicable -> Art-27 omitted, not a gap


def test_fria_applicable_profile_includes_art27():
    cw = load_builtin("eu-ai-act", profile=["on_the_loop", "fria_applicable"])
    ids = _ids(cw)
    assert "art-14-human-oversight-on-the-loop" in ids
    assert "art-27-fria" in ids


def test_on_the_loop_predicate_evaluates(populated_ledger):
    # t1 decision shares context with a human_approval (oversight touchpoint) -> ok;
    # t2 decision has no oversight touchpoint -> violator -> control not_satisfied.
    cw = load_builtin("eu-ai-act", profile=["on_the_loop"])
    res = evaluate(cw, list(populated_ledger.events()))
    onloop = next(c for c in res.controls if c.control_id == "art-14-human-oversight-on-the-loop")
    assert onloop.status == ControlStatus.NOT_SATISFIED
    assert onloop.evaluated_count == 2 and onloop.satisfied_count == 1


def test_profile_changes_content_hash():
    """The pinned crosswalk hash (B9) reflects the profile actually evaluated."""
    a = evaluate(load_builtin("eu-ai-act", profile=["in_the_loop", "fria_applicable"]), [])
    b = evaluate(load_builtin("eu-ai-act", profile=["on_the_loop"]), [])
    assert a.crosswalk_content_hash and b.crosswalk_content_hash
    assert a.crosswalk_content_hash != b.crosswalk_content_hash


# -- B13: narrowed, review-survivable v1 --------------------------------------


def test_narrowed_v1_is_the_review_subset(populated_ledger):
    assert "eu-ai-act-v1" in available_builtins()
    cw = load_builtin("eu-ai-act-v1")
    assert _ids(cw) == {"art-14-human-oversight", "art-26-retention"}
    res = evaluate(cw, list(populated_ledger.events()))
    s = {c.control_id: c.status for c in res.controls}
    # in-the-loop oversight: one unapproved high-risk decision -> not_satisfied
    assert s["art-14-human-oversight"] == ControlStatus.NOT_SATISFIED
    # retention commitment present on the high-risk decisions -> satisfied
    assert s["art-26-retention"] == ControlStatus.SATISFIED
    # every control cites a primary source
    for c in cw.controls:
        assert c.citation.instrument and c.citation.url
