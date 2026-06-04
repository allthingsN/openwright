"""OpenWright command-line interface."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import typer

from . import __version__

app = typer.Typer(
    add_completion=False,
    help="OpenWright — the Agent Evidence Layer. Produces EVIDENCE of controls "
    "exercised; NOT legal compliance or certification.",
    no_args_is_help=True,
)


def _echo(msg: str, err: bool = False) -> None:
    typer.echo(msg, err=err)


@app.callback(invoke_without_command=True)
def _root(
    version: bool = typer.Option(False, "--version", help="Print the OpenWright version and exit."),
) -> None:
    if version:
        _echo(f"openwright {__version__}")
        raise typer.Exit()


@app.command()
def version() -> None:
    """Print the OpenWright version."""
    _echo(f"openwright {__version__}")


@app.command()
def demo(
    workdir: Optional[Path] = typer.Option(None, help="Where to write the ledger + artifacts (default: a temp dir)."),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Don't open the interactive demo page in a browser (for CI/headless)."
    ),
) -> None:
    """Run the full end-to-end demo (the one-command quickstart).

    Opens an interactive page in your browser where you can verify the real signed
    report offline (in-browser WASM) and watch tampering fail. Use --no-browser to
    skip opening it (the page is still written to the artifacts dir).
    """
    from .demo import run_demo

    target = workdir or Path(tempfile.mkdtemp(prefix="openwright-demo-"))
    _echo("=" * 72)
    _echo("OpenWright demo — high-risk loan-decisioning agent")
    _echo("=" * 72)
    out = run_demo(target, log=_echo)
    _echo("-" * 72)
    vr = out["verification"]
    _echo(vr.summary())
    _echo("-" * 72)
    _echo("The value story:")
    _echo(f"  Sits on a receipt    : verified upstream receipt → {out['receipt_format']} tool_call")
    _echo(f"  Catches the gap      : Art. 14 human-oversight = {out['art14_before']} (before)")
    _echo(f"  Proves remediation   : Art. 14 human-oversight = {out['art14_after']} (after) — red→green")
    _echo("-" * 72)
    _echo("Acceptance criteria exercised:")
    _echo(f"  AC-01 fan-out preserved : downstream got {out['downstream_spans']} spans unchanged")
    _echo(f"  AC-02 signed report     : {out['summary']}")
    _echo(f"  AC-03 offline verify    : VALID={vr.valid} (hash-only, no network)")
    _echo(f"  AC-04 tamper-evident    : tamper detected={out['tamper_detected']}, restore valid={out['restore_valid']}")
    _echo("  AC-05 self-hosted       : no hosted dependency; key on disk, not embedded")
    _echo("  AC-06 boundary stated   : present in JSON/PDF/OSCAL/SARIF")
    _echo("-" * 72)
    _echo("Artifacts:")
    for k in ("demo_html", "report_json", "report_pdf", "oscal", "sarif", "public_key"):
        _echo(f"  {k:12s} {out[k]}")
    _echo("")
    _echo("Verify it yourself, offline:")
    _echo(f"  openwright verify {out['report_json']} --pubkey {out['public_key']} --deep")
    _echo("-" * 72)

    # Open the interactive page: it explains the run AND lets you verify the real
    # report in your browser (WASM) and watch tampering fail.
    import os
    import webbrowser

    page = out["demo_html"]
    page_uri = Path(page).resolve().as_uri()
    _echo("Interactive demo (story + verify-it-yourself in your browser):")
    _echo(f"  {page_uri}")
    import os

    if no_browser or os.environ.get("OPENWRIGHT_NO_BROWSER"):
        _echo("  (auto-open disabled — open the link above to explore and verify)")
    else:
        try:
            opened = webbrowser.open(page_uri)
            _echo(
                "  Opened in your default browser — click “Verify this report” to check it yourself."
                if opened
                else "  (no browser available — open the link above manually)"
            )
        except Exception:  # noqa: BLE001 - never fail the demo on a headless box
            _echo("  (could not open a browser automatically — open the link above manually)")

    if not (vr.valid and out["tamper_detected"]):
        raise typer.Exit(code=1)


@app.command()
def verify(
    report: Path = typer.Argument(..., help="Path to a signed report.json."),
    pubkey: Optional[Path] = typer.Option(None, help="Trusted signer public key (PEM). Strongly recommended."),
    deep: bool = typer.Option(
        False, "--deep", help="Also re-evaluate the crosswalk over the included events (verifies verdicts, not just integrity)."
    ),
) -> None:
    """Independently verify a signed report against its checkpoint (offline)."""
    from .verify import verify_report_file

    result = verify_report_file(str(report), public_key_pem_path=str(pubkey) if pubkey else None, deep=deep)
    _echo(result.summary())
    raise typer.Exit(code=0 if result.valid else 1)


@app.command()
def gate(
    report: Path = typer.Argument(..., help="Path to a signed report.json."),
    require: List[str] = typer.Option([], "--require", "-r", help="Control id(s) that MUST be satisfied."),
    pubkey: Optional[Path] = typer.Option(None, help="Trusted signer public key (PEM)."),
    sarif_out: Optional[Path] = typer.Option(None, help="Write SARIF gap findings here."),
    deep: bool = typer.Option(
        False, "--deep", help="Re-evaluate the crosswalk over the included events before gating (verifies verdicts)."
    ),
) -> None:
    """CI/CD gate: exit non-zero if verification fails or a required control is unsatisfied (UC-4)."""
    from .report import to_sarif
    from .verify import verify_report_file

    data = json.loads(Path(report).read_text())
    result = verify_report_file(str(report), public_key_pem_path=str(pubkey) if pubkey else None, deep=deep)
    if not result.valid:
        _echo("GATE FAIL: report did not verify.", err=True)
        _echo(result.summary(), err=True)
        raise typer.Exit(code=2)

    statuses = {c["control_id"]: c["status"] for c in data["controls"]}
    required = require or [cid for cid in statuses]  # default: all controls
    failures = [cid for cid in required if statuses.get(cid) != "satisfied"]

    if sarif_out:
        Path(sarif_out).write_text(json.dumps(to_sarif(data), indent=2))
        _echo(f"Wrote SARIF gap findings to {sarif_out}")

    for cid in required:
        _echo(f"  [{'OK' if statuses.get(cid)=='satisfied' else 'GAP'}] {cid}: {statuses.get(cid, 'absent')}")
    if failures:
        _echo(f"GATE FAIL: {len(failures)} required control(s) unsatisfied: {failures}", err=True)
        raise typer.Exit(code=1)
    _echo("GATE PASS: all required controls satisfied.")


@app.command()
def report(
    ledger_dir: Path = typer.Argument(..., help="Path to a file ledger directory."),
    key: Path = typer.Option(..., help="Ed25519 signing key (PEM)."),
    crosswalk: str = typer.Option("eu-ai-act", help="Built-in crosswalk id or path to a YAML file."),
    out: Path = typer.Option(Path("./openwright-out"), help="Output directory."),
    scope: str = typer.Option("Agent evidence", help="Scope description for the report."),
    pdf: bool = typer.Option(True, help="Also render a PDF."),
) -> None:
    """Generate a signed report from an existing ledger."""
    from .crosswalk import evaluate
    from .crosswalk_loader import available_builtins, load_builtin, load_crosswalk_file
    from .ledger import FileLedgerBackend, Ledger
    from .report import build_report, render_pdf, to_oscal, to_sarif
    from .signing import FileKeySource

    cw = load_builtin(crosswalk) if crosswalk in available_builtins() else load_crosswalk_file(crosswalk)
    led = Ledger(FileLedgerBackend(str(ledger_dir)))
    keysrc = FileKeySource(str(key))
    result = evaluate(cw, list(led.events()))
    rep = build_report(led, result, keysrc, scope_description=scope)

    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(rep, indent=2))
    (out / "report.oscal.json").write_text(json.dumps(to_oscal(rep), indent=2))
    (out / "report.sarif.json").write_text(json.dumps(to_sarif(rep), indent=2))
    if pdf:
        render_pdf(rep, str(out / "report.pdf"))
    s = rep["summary"]
    _echo(f"Report written to {out} — {s['satisfied']}/{s['total']} satisfied, "
          f"{s['not_satisfied']} not, {s['insufficient_evidence']} insufficient.")


@app.command()
def schema(
    kind: str = typer.Option("event", help="'event', 'crosswalk', or 'report'."),
    out: Optional[Path] = typer.Option(None, help="Write the schema here instead of stdout."),
) -> None:
    """Print/export a published, versioned JSON Schema (FR-NRM-02)."""
    from .spec import compliance_event_schema, crosswalk_schema, report_schema

    doc = {"event": compliance_event_schema, "crosswalk": crosswalk_schema, "report": report_schema}.get(
        kind, compliance_event_schema
    )()
    text = json.dumps(doc, indent=2)
    if out:
        Path(out).write_text(text)
        _echo(f"Wrote {kind} schema to {out}")
    else:
        _echo(text)


@app.command()
def crosswalks() -> None:
    """List built-in crosswalks with their versions and sources."""
    from .crosswalk_loader import available_builtins, load_builtin

    for name in available_builtins():
        cw = load_builtin(name)
        _echo(f"{name}: {cw.title}")
        _echo(f"    version={cw.version}  reviewed_as_of={cw.reviewed_as_of}  controls={len(cw.controls)}")
        _echo(f"    source={cw.source}")


@app.command()
def sbom(out: Optional[Path] = typer.Option(None, help="Write the CycloneDX SBOM here instead of stdout.")) -> None:
    """Generate a CycloneDX SBOM of the installed environment (NFR-SEC-03)."""
    from .sbom import generate_cyclonedx

    text = json.dumps(generate_cyclonedx(), indent=2)
    if out:
        Path(out).write_text(text)
        _echo(f"Wrote SBOM to {out}")
    else:
        _echo(text)


@app.command()
def dashboard(
    reports: List[Path] = typer.Argument(..., help="One or more report.json files (time-ordered)."),
    out: Path = typer.Option(Path("./openwright-dashboard.html"), help="Output HTML file."),
) -> None:
    """Render a static coverage dashboard across reports (FR-RPT-06)."""
    from .dashboard import write_dashboard

    write_dashboard([str(p) for p in reports], str(out))
    _echo(f"Wrote coverage dashboard to {out} ({len(reports)} report(s)).")


@app.command()
def keygen(out: Path = typer.Option(Path("./signing_key.pem"), help="Where to write the private key (PEM).")) -> None:
    """Generate an Ed25519 signing key (operator-controlled; never embedded)."""
    from .signing import FileKeySource, generate_private_key_pem, public_key_pem

    Path(out).write_bytes(generate_private_key_pem())
    key = FileKeySource(str(out))
    pub = Path(str(out) + ".pub")
    pub.write_bytes(public_key_pem(key.public_key_raw()))
    _echo(f"Wrote private key to {out} (keep it secret) and public key to {pub}")
    _echo(f"Key id: {key.key_id()}")


@app.command()
def collector(
    ledger_dir: Path = typer.Option(Path("./openwright-ledger"), help="File ledger directory."),
    downstream: Optional[str] = typer.Option(None, help="Downstream OTLP/HTTP endpoint to fan out to."),
    host: str = typer.Option("127.0.0.1"),
    http_port: int = typer.Option(4318, help="OTLP/HTTP port."),
    grpc_port: Optional[int] = typer.Option(None, help="Also serve OTLP/gRPC on this port."),
    agent_id: Optional[str] = typer.Option(None, help="Default agent id for events lacking one."),
    auth_token: Optional[str] = typer.Option(None, help="Require this bearer token to write evidence (NFR-SEC-04)."),
    key: Optional[Path] = typer.Option(None, help="Ed25519 signing key (PEM) for scheduled checkpoints (B6)."),
    checkpoint_interval: float = typer.Option(0.0, help="Seconds between signed checkpoints (0 disables; B6)."),
    checkpoints: Path = typer.Option(Path("./openwright-checkpoints"), help="Where scheduled checkpoints are stored."),
    ledger_backend: Optional[str] = typer.Option(
        None, help="Ledger backend URI (e.g. postgres://…, sqlite:///path); resolved via an installed connector, overrides --ledger-dir."
    ),
    checkpoint_store: Optional[str] = typer.Option(
        None, help="Checkpoint store URI (e.g. s3://bucket/prefix); resolved via an installed connector."
    ),
) -> None:
    """Run the OTLP collector: fan out telemetry unchanged, fork into the ledger.

    Durability (B1/B2) auto-enables on the file ledger. With --key and a positive
    --checkpoint-interval it also emits signed tree heads on a schedule (B6).
    --ledger-backend / --checkpoint-store resolve a storage connector by URI.
    """
    import time as _time

    from .ingest.http_server import EvidenceCollector
    from .ingest.pipeline import EvidencePipeline
    from .ledger import FileLedgerBackend, Ledger

    authority = None
    if auth_token:
        from .authz import Capability, Principal, TokenAuthority

        authority = TokenAuthority({auth_token: Principal("collector-writer", frozenset({Capability.WRITE_EVIDENCE}))})

    if ledger_backend:
        from .connectors import resolve_backend

        try:
            backend = resolve_backend("openwright.ledger_backends", ledger_backend)
        except (KeyError, Exception) as exc:  # noqa: BLE001
            _echo(f"could not resolve ledger backend {ledger_backend!r}: {exc}", err=True)
            raise typer.Exit(code=2)
        led = Ledger(backend)
        _echo(f"Using ledger backend connector: {ledger_backend}")
    else:
        led = Ledger(FileLedgerBackend(str(ledger_dir)))
    pipe = EvidencePipeline(led, agent_id=agent_id)
    coll = EvidenceCollector(pipe, host=host, port=http_port, downstream_url=downstream, token_authority=authority).start()
    _echo(f"OTLP/HTTP collector on {coll.traces_url}  ledger={ledger_dir}  downstream={downstream or 'none'}")
    grpc_server = None
    if grpc_port:
        from .ingest.grpc_server import serve_grpc

        grpc_server = serve_grpc(pipe, host=host, port=grpc_port)
        _echo(f"OTLP/gRPC collector on {host}:{grpc_port}")

    scheduler = None
    if key and checkpoint_interval > 0:
        from .scheduler import CheckpointScheduler
        from .signing import FileKeySource

        if checkpoint_store:
            from .connectors import resolve_backend

            store = resolve_backend("openwright.checkpoint_stores", checkpoint_store)
            store_desc = checkpoint_store
        else:
            from .checkpoint_store import LocalCheckpointStore

            store = LocalCheckpointStore(str(checkpoints))
            store_desc = str(checkpoints)
        scheduler = CheckpointScheduler(
            led, FileKeySource(str(key)), store, interval=checkpoint_interval
        ).start()
        _echo(f"Scheduled checkpoints every {checkpoint_interval}s -> {store_desc}")

    _echo("Press Ctrl-C to stop.")
    try:
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        _echo(f"\nStopping. Evidence stats: {pipe.stats()}, ledger size={led.size()}")
    finally:
        if scheduler:
            scheduler.stop()
        coll.stop()
        pipe.stop()
        if grpc_server:
            grpc_server.stop(0)


@app.command()
def witness(
    key: Path = typer.Option(..., help="Witness Ed25519 signing key (PEM) — its OWN independent key (B8)."),
    host: str = typer.Option("0.0.0.0"),
    port: int = typer.Option(4319, help="HTTP port for POST /cosign and GET /pubkey."),
) -> None:
    """Run the standalone witness service: co-signs producer checkpoints after
    verifying a consistency proof, on separate infra with an independent key (B8)."""
    import time as _time

    from .signing import FileKeySource
    from .witness_service import WitnessService

    svc = WitnessService(FileKeySource(str(key)), host=host, port=port).start()
    _echo(f"Witness service on {svc.url}  key_id={svc.key_id}")
    _echo("Press Ctrl-C to stop.")
    try:
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        _echo("\nStopping witness service.")
    finally:
        svc.stop()


@app.command()
def export(
    report: Path = typer.Argument(..., help="Path to a signed report.json."),
    to: str = typer.Option(..., "--to", help="Exporter connector name (see `openwright connectors list`)."),
    config: List[str] = typer.Option([], "--config", "-c", help="Exporter config as key=value (repeatable)."),
) -> None:
    """Export a signed report to a sink (GRC, CI, …) via an installed exporter connector."""
    from .connectors import load

    cfg = {}
    for kv in config:
        k, _, v = kv.partition("=")
        cfg[k.strip()] = v
    data = json.loads(Path(report).read_text())
    try:
        exporter = load("openwright.report_exporters", to)
    except KeyError as exc:
        _echo(str(exc), err=True)
        raise typer.Exit(code=2)
    impl = exporter() if isinstance(exporter, type) else exporter
    result = impl.export(data, config=cfg)
    suffix = f" {result.url}" if getattr(result, "url", None) else ""
    _echo(f"export via {to}: {'OK' if result.ok else 'FAILED'} — {result.detail}{suffix}")
    raise typer.Exit(code=0 if result.ok else 1)


connectors_app = typer.Typer(add_completion=False, help="Inspect installed OpenWright connectors.")
app.add_typer(connectors_app, name="connectors")


@connectors_app.command("list")
def connectors_list() -> None:
    """List installed connectors by group and the contract version each targets."""
    from .connectors import CONTRACT_VERSION, GROUPS, contract_compatible, discover

    _echo(f"OpenWright connector contract: v{CONTRACT_VERSION}")
    found = False
    for group in GROUPS:
        impls = discover(group)
        if not impls:
            continue
        found = True
        _echo(f"\n{group.split('.')[-1]}:")
        for name, impl in sorted(impls.items()):
            tv = getattr(impl, "CONTRACT_VERSION", None) or "—"
            flag = "ok" if contract_compatible(impl) else "INCOMPATIBLE"
            _echo(f"  {name:18s} contract={str(tv):5s} [{flag}]")
    if not found:
        _echo("\n(no connectors discovered)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
