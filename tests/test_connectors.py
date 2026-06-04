"""The connector contract: protocols, discovery/registry, URI resolution, CLI,
and contract versioning (CORE-1..4) — plus the modularity guarantee that adding
a connector needs zero core change."""

from __future__ import annotations

import contextlib

import pytest

from openwright import connectors as C
from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import Ledger


def _ev():
    return ComplianceEvent(
        timestamp="2026-05-28T00:00:00.000000000Z", kind=EventKind.GENERIC,
        actor={"agent_id": "a"}, source={"format": "sdk"},
    )


# -- CORE-1: contract surface -------------------------------------------------


def test_contract_surface_present():
    assert C.CONTRACT_VERSION
    # storage/signing ABCs re-exported from one place
    assert C.LedgerBackend and C.CheckpointStore and C.KeySource
    # new protocols + result type
    assert C.SourceConnector and C.ReportExporter and C.Forwarder and C.ExportResult
    assert set(C.GROUPS) >= {
        "openwright.source_connectors", "openwright.forwarders",
        "openwright.report_exporters", "openwright.ledger_backends",
        "openwright.checkpoint_stores",
    }


def test_protocols_are_structural():
    class MyExporter:
        name = "x"
        def export(self, report, *, config):  # noqa: D401
            return C.ExportResult(True, "ok")

    class MySource:
        name = "s"
        def instrument(self, client, **opts):
            return contextlib.nullcontext()

    assert isinstance(MyExporter(), C.ReportExporter)
    assert isinstance(MySource(), C.SourceConnector)


# -- CORE-2: discovery + registry ---------------------------------------------


def test_register_and_discover_roundtrip():
    class Dummy:
        name = "dummy"
        def instrument(self, client, **opts):
            return contextlib.nullcontext()

    C.register("openwright.source_connectors", "dummy", Dummy)
    try:
        found = C.discover("openwright.source_connectors")
        assert found.get("dummy") is Dummy
        assert C.load("openwright.source_connectors", "dummy") is Dummy
    finally:
        C._REGISTRY["openwright.source_connectors"].pop("dummy", None)


def test_load_missing_raises():
    with pytest.raises(KeyError):
        C.load("openwright.report_exporters", "does-not-exist")


def test_core_builtin_backends_are_discoverable():
    ledgers = C.discover("openwright.ledger_backends")
    stores = C.discover("openwright.checkpoint_stores")
    assert {"sqlite", "postgres", "file"} <= set(ledgers)
    assert {"local", "s3", "file"} <= set(stores)


def test_adding_a_connector_needs_zero_core_change():
    """The modularity test: a brand-new connector (as a _template-derived package
    would) is discovered purely by registering — core is untouched."""
    class BrandNew:
        name = "brand-new"
        CONTRACT_VERSION = C.CONTRACT_VERSION
        def export(self, report, *, config):
            return C.ExportResult(True, "exported")

    C.register("openwright.report_exporters", "brand-new", BrandNew())
    try:
        assert "brand-new" in C.available()["openwright.report_exporters"]
    finally:
        C._REGISTRY["openwright.report_exporters"].pop("brand-new", None)


# -- CORE-3: URI resolution ---------------------------------------------------


def test_resolve_sqlite_ledger_backend_commits():
    backend = C.resolve_backend("openwright.ledger_backends", "sqlite://:memory:")
    led = Ledger(backend)
    led.commit(_ev())
    assert led.size() == 1


def test_resolve_file_ledger_and_local_checkpoint(tmp_path):
    led = Ledger(C.resolve_backend("openwright.ledger_backends", f"file://{tmp_path}/led"))
    led.commit(_ev())
    assert led.size() == 1

    store = C.resolve_backend("openwright.checkpoint_stores", f"file://{tmp_path}/cps")
    from openwright.checkpoint_store import LocalCheckpointStore

    assert isinstance(store, LocalCheckpointStore)


def test_resolve_unknown_scheme_raises():
    with pytest.raises(KeyError):
        C.resolve_backend("openwright.ledger_backends", "weirdscheme://x")


# -- CORE-4: contract versioning ----------------------------------------------


def test_discover_warns_on_major_contract_mismatch():
    class FromFuture:
        name = "future"
        CONTRACT_VERSION = "2.0"
        def export(self, report, *, config):
            return C.ExportResult(True)

    C.register("openwright.report_exporters", "future", FromFuture())
    try:
        with pytest.warns(UserWarning, match="major mismatch"):
            C.discover("openwright.report_exporters")
        assert not C.contract_compatible(FromFuture())
    finally:
        C._REGISTRY["openwright.report_exporters"].pop("future", None)


# -- CLI ----------------------------------------------------------------------


def test_cli_connectors_list_runs():
    from typer.testing import CliRunner

    from openwright.cli import app

    res = CliRunner().invoke(app, ["connectors", "list"])
    assert res.exit_code == 0
    assert "connector contract" in res.stdout
    assert "ledger_backends" in res.stdout and "sqlite" in res.stdout


def test_cli_export_via_registered_exporter(tmp_path):
    import json

    from typer.testing import CliRunner

    from openwright.cli import app

    captured = {}

    class CaptureExporter:
        name = "capture"
        def export(self, report, *, config):
            captured["report_id"] = report.get("report_id")
            captured["config"] = config
            return C.ExportResult(True, "captured", url="https://example/x")

    C.register("openwright.report_exporters", "capture", CaptureExporter())
    try:
        rp = tmp_path / "r.json"
        rp.write_text(json.dumps({"report_id": "rpt_1"}))
        res = CliRunner().invoke(app, ["export", str(rp), "--to", "capture", "-c", "k=v"])
        assert res.exit_code == 0, res.stdout
        assert "OK" in res.stdout and "captured" in res.stdout
        assert captured == {"report_id": "rpt_1", "config": {"k": "v"}}
    finally:
        C._REGISTRY["openwright.report_exporters"].pop("capture", None)
