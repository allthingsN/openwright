"""Process-wide OpenWright runtime — the zero-config plumbing behind ``instrument()``.

Builds the ledger + checkpoint store + signing key once, from explicit args or env,
so an agent never has to wire them by hand:

    OPENWRIGHT_LEDGER            ledger backend URI (default: file → ./openwright-ledger)
    OPENWRIGHT_CHECKPOINT_STORE  checkpoint store URI, e.g. s3://bucket/checkpoints?lock=COMPLIANCE&days=180
    OPENWRIGHT_SIGNING_KEY       Ed25519 private key PEM (inline); else
    OPENWRIGHT_SIGNING_KEY_FILE  path to the key PEM (default ./openwright-signing_key.pem, generated if absent)
    OPENWRIGHT_AGENT_ID          agent id stamped on events (default "agent")
    OPENWRIGHT_ORIGIN            ledger origin (default "openwright/agent")

Use :func:`configure` before first use to set these in code, or just rely on env.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

from .ledger import FileLedgerBackend, Ledger
from .sdk import EvidenceClient
from .signing import EnvKeySource, FileKeySource, KeySource, generate_private_key_pem, public_key_pem

log = logging.getLogger("openwright")


def _resolve_ledger_backend(uri: Optional[str]):
    if not uri or uri.startswith("file://") or uri.startswith("file:"):
        path = uri.split("file://", 1)[-1] if uri and "file://" in uri else (uri[5:] if uri and uri.startswith("file:") else None)
        path = path or os.environ.get("OPENWRIGHT_LEDGER_DIR") or "./openwright-ledger"
        return FileLedgerBackend(path)
    from .connectors import resolve_backend  # e.g. postgres://… via openwright-postgres
    return resolve_backend("openwright.ledger_backends", uri)


def _resolve_store(uri: Optional[str]):
    if not uri:
        return None
    if uri.startswith("file://") or uri.startswith("file:"):
        from .checkpoint_store import LocalCheckpointStore
        path = uri.split("file://", 1)[-1] if "file://" in uri else uri[5:]
        return LocalCheckpointStore(path or "./openwright-checkpoints")
    from .connectors import resolve_backend  # s3://… via openwright-s3
    return resolve_backend("openwright.checkpoint_stores", uri)


def _resolve_key() -> KeySource:
    if os.environ.get("OPENWRIGHT_SIGNING_KEY"):
        return EnvKeySource("OPENWRIGHT_SIGNING_KEY")
    keyfile = Path(os.environ.get("OPENWRIGHT_SIGNING_KEY_FILE", "./openwright-signing_key.pem"))
    if not keyfile.exists():
        keyfile.parent.mkdir(parents=True, exist_ok=True)
        keyfile.write_bytes(generate_private_key_pem())
        log.warning("OpenWright: generated a new signing key at %s (set OPENWRIGHT_SIGNING_KEY_FILE "
                    "or OPENWRIGHT_SIGNING_KEY to use a managed key)", keyfile)
    return FileKeySource(str(keyfile))


class Runtime:
    """Holds the ledger, checkpoint store, signing key, and a shared EvidenceClient."""

    def __init__(self, *, agent_id: Optional[str] = None, origin: Optional[str] = None,
                 ledger: Optional[Ledger] = None, store: Any = None, key: Optional[KeySource] = None,
                 retention_days: int = 365) -> None:
        agent_id = agent_id or os.environ.get("OPENWRIGHT_AGENT_ID", "agent")
        origin = origin or os.environ.get("OPENWRIGHT_ORIGIN", "openwright/agent")
        self.ledger = ledger or Ledger(_resolve_ledger_backend(os.environ.get("OPENWRIGHT_LEDGER")),
                                       origin=origin, retention=timedelta(days=retention_days))
        self.store = store if store is not None else _resolve_store(os.environ.get("OPENWRIGHT_CHECKPOINT_STORE"))
        self.key = key or _resolve_key()
        self.client = EvidenceClient(self.ledger, agent_id=agent_id)
        # Optional: auto-persist reports on a cadence to OPENWRIGHT_REPORT_DIR (s3://… or a path).
        report_dir = os.environ.get("OPENWRIGHT_REPORT_DIR")
        if report_dir:
            self.start_report_scheduler(
                report_dir, interval=float(os.environ.get("OPENWRIGHT_REPORT_INTERVAL", "300")))

    def checkpoint(self):
        """Sign a checkpoint over the current ledger and persist it to the store (if any)."""
        cp = self.ledger.checkpoint(self.key)
        if self.store is not None:
            self.store.put(cp)
        return cp

    def report(self, *, crosswalk: str = "eu-ai-act", scope_description: str = "agent",
               out_dir: Optional[str] = None, name: str = "report.json") -> dict:
        """Build a signed, control-mapped evidence pack over everything recorded so far.

        ``out_dir`` may be a local path, ``file://…``, or ``s3://bucket/prefix`` — in the
        S3 case the report + public key are written to the bucket (durable, auditor-fetchable)
        via boto3. ``name`` is the report object's filename (the public key is always
        ``public_key.pem`` alongside it).
        """
        from .crosswalk import evaluate
        from .crosswalk_loader import load_builtin
        from .report import build_report

        result = evaluate(load_builtin(crosswalk), list(self.ledger.events()))
        rep = build_report(self.ledger, result, self.key, scope_description=scope_description)
        if out_dir:
            self._write_report_pair(out_dir, name,
                                    json.dumps(rep, indent=2).encode("utf-8"),
                                    public_key_pem(self.key.public_key_raw()))
        return rep

    @staticmethod
    def _write_report_pair(out_dir: str, name: str, report_bytes: bytes, pubkey_pem: bytes) -> str:
        """Write report + public key to a local dir, ``file://``, or ``s3://bucket/prefix``."""
        if out_dir.startswith("s3://"):
            import boto3
            bucket, _, prefix = out_dir[len("s3://"):].partition("/")
            prefix = prefix.rstrip("/")
            key = lambda f: f"{prefix}/{f}" if prefix else f
            s3 = boto3.client("s3")
            s3.put_object(Bucket=bucket, Key=key(name), Body=report_bytes,
                          ContentType="application/json")
            s3.put_object(Bucket=bucket, Key=key("public_key.pem"), Body=pubkey_pem,
                          ContentType="application/x-pem-file")
            return f"s3://{bucket}/{key(name)}"
        d = Path(out_dir[len("file://"):] if out_dir.startswith("file://") else out_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(report_bytes)
        (d / "public_key.pem").write_bytes(pubkey_pem)
        return str(d / name)

    def persist_report(self, out_dir: str, *, crosswalk: str = "eu-ai-act",
                       scope_description: str = "agent") -> str:
        """Emit one report named by ledger size (``report-<size>.json``) and persist it —
        a stable, ordered, retained artifact (vs. ``report()`` which writes ``report.json``)."""
        size = self.ledger.backend.size()
        self.report(crosswalk=crosswalk, scope_description=scope_description,
                    out_dir=out_dir, name=f"report-{size:012d}.json")
        return f"{out_dir.rstrip('/')}/report-{size:012d}.json"

    def start_report_scheduler(self, out_dir: str, *, interval: float = 300.0,
                               crosswalk: str = "eu-ai-act", scope_description: str = "agent"):
        """Persist a report to ``out_dir`` every ``interval`` seconds on a daemon thread, so
        auditors always have durable, retained packs. Returns a ``threading.Event``; ``.set()``
        it to stop. Failures are logged and never crash the loop."""
        stop = threading.Event()

        def _loop():
            while not stop.wait(interval):
                if self.ledger.backend.size() == 0:
                    continue
                try:
                    self.persist_report(out_dir, crosswalk=crosswalk, scope_description=scope_description)
                except Exception:  # noqa: BLE001 - never crash the scheduler
                    log.exception("scheduled report persist failed")

        threading.Thread(target=_loop, name="openwright-report-scheduler", daemon=True).start()
        self._report_stop = stop
        return stop


_lock = threading.Lock()
_runtime: Optional[Runtime] = None
_config: dict = {}


def configure(**opts) -> None:
    """Set the options used to build the process runtime (call before first use)."""
    global _config
    _config = opts


def get_runtime() -> Runtime:
    """Return the process-wide :class:`Runtime`, building it once from config/env."""
    global _runtime
    with _lock:
        if _runtime is None:
            _runtime = Runtime(**_config)
        return _runtime


def reset_runtime() -> None:
    """Drop the singleton (tests)."""
    global _runtime
    _runtime = None
