"""openwright.instrument() + the process Runtime (the 1-line integration plumbing)."""

from __future__ import annotations

import subprocess
import sys

import pytest

import openwright
from openwright.checkpoint_store import LocalCheckpointStore
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.runtime import Runtime
from openwright.signing import InMemoryKeySource
from openwright.verify import verify_report


def _rt(tmp_path, store=None):
    return Runtime(agent_id="a", ledger=Ledger(InMemoryLedgerBackend(), origin="t"),
                   store=store, key=InMemoryKeySource())


def test_lazy_top_level_exports():
    assert callable(openwright.instrument)
    assert callable(openwright.configure)
    assert callable(openwright.get_runtime)


def test_runtime_records_checkpoints_reports_and_verifies(tmp_path):
    rt = _rt(tmp_path, store=LocalCheckpointStore(str(tmp_path / "cp")))
    with rt.client.task("t1"):
        rt.client.record_decision(output="APPROVED", risk_classification="high",
                                  rationale="ok", control="art-14-human-oversight")
    cp = rt.checkpoint()
    assert cp.tree_size >= 1
    assert rt.store.latest() is not None  # persisted to the store
    rep = rt.report(out_dir=str(tmp_path / "out"))
    vr = verify_report(rep, trusted_public_key_raw=rt.key.public_key_raw(), deep=True)
    assert vr.valid, vr.summary()


def test_instrument_unknown_framework_is_a_clear_error(tmp_path):
    with pytest.raises(ValueError) as e:
        openwright.instrument("nope-not-real", runtime=_rt(tmp_path))
    assert "instrumentor" in str(e.value)


def test_instrument_dispatches_to_entry_point(tmp_path, monkeypatch):
    """instrument() loads the named instrumentor and calls it with (runtime, **opts)."""
    called = {}

    def fake_auto_instrument(runtime, **opts):
        called["runtime"] = runtime
        called["opts"] = opts
        return "handle"

    monkeypatch.setattr("openwright._instrument._load_instrumentor", lambda name: fake_auto_instrument)
    rt = _rt(tmp_path)
    out = openwright.instrument("openai-agents", runtime=rt, decision_tools=["update_seat"])
    assert out == "handle"
    assert called["runtime"] is rt
    assert called["opts"] == {"decision_tools": ["update_seat"]}


def test_report_persists_to_local_and_s3(tmp_path):
    rt = _rt(tmp_path)
    with rt.client.task("t1"):
        rt.client.record_decision(output="OK", risk_classification="low", rationale="x",
                                  control="art-12-record-keeping")
    # local
    rt.report(out_dir=str(tmp_path / "out"))
    assert (tmp_path / "out" / "report.json").exists()
    assert (tmp_path / "out" / "public_key.pem").exists()
    # file:// scheme
    rt.report(out_dir=f"file://{tmp_path}/out2", name="report.json")
    assert (tmp_path / "out2" / "report.json").exists()
    # s3:// via moto
    moto = pytest.importorskip("moto")
    import boto3
    with moto.mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="ow-reports")
        rt.report(out_dir="s3://ow-reports/reports", name="report.json")
        s3 = boto3.client("s3", region_name="us-east-1")
        keys = {o["Key"] for o in s3.list_objects_v2(Bucket="ow-reports").get("Contents", [])}
        assert "reports/report.json" in keys and "reports/public_key.pem" in keys


def test_persist_report_names_by_size_and_scheduler_starts(tmp_path):
    rt = _rt(tmp_path)
    with rt.client.task("t1"):
        rt.client.record_decision(output="OK", risk_classification="low", rationale="x",
                                  control="art-12-record-keeping")
    ref = rt.persist_report(str(tmp_path / "o"))
    size = rt.ledger.backend.size()
    assert (tmp_path / "o" / f"report-{size:012d}.json").exists()
    assert ref.endswith(f"report-{size:012d}.json")
    stop = rt.start_report_scheduler(str(tmp_path / "sched"), interval=0.05)
    import time
    time.sleep(0.2)
    stop.set()
    assert any((tmp_path / "sched").glob("report-*.json"))


def test_importing_verifier_stays_dependency_light():
    # INV-2: importing the verifier (even though the package now has instrument/runtime)
    # must not pull pydantic/yaml/reportlab/typer or networking libs.
    code = (
        "import openwright.verify, sys; "
        "banned={'requests','grpc','urllib3','httpx','aiohttp','pydantic','yaml','reportlab','typer'}; "
        "leaked=banned & set(sys.modules); "
        "sys.exit('LEAKED:%s' % leaked if leaked else 0)"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
