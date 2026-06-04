"""The OpenWright connector contract — stable, versioned, public (CORE-1..4).

This is the *only* surface a connector depends on. **Core never imports a
connector**; connectors depend on this module and register via entry points, so
adding or removing a connector requires **zero changes to core** (the modularity
test). Core ships a few reference backends registered in-process (see
``builtin``); third-party connectors are discovered via ``importlib.metadata``
entry points in the groups listed in :data:`GROUPS`.

Connector kinds:

* **Storage / signing** — implement the core ABCs :class:`LedgerBackend`,
  :class:`CheckpointStore`, :class:`KeySource` (re-exported here so connectors
  import them from one stable place).
* :class:`SourceConnector` — framework *capture*: map a framework's runtime
  events to SDK calls (``record_decision`` / ``record_human_approval`` / …).
* :class:`Forwarder` — downstream observability (the Langfuse pattern):
  co-ingest, back-link verdicts, and pull external data as events.
* :class:`ReportExporter` — sinks (GRC, CI) that consume a signed report.

Invariants every connector preserves (enforced by the conformance harness +
review): **hashes-only** (never put raw prompts/PII in a ``ComplianceEvent``),
**no crypto re-implementation** (call core for canonical/Merkle/signing),
**append-only**, **boundary statement** in any emitted artifact, and an
**additive evidence path** (never drop/alter the host app's primary telemetry).
"""

from __future__ import annotations

import importlib
import logging
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Protocol, runtime_checkable

# Re-export the existing storage/signing contracts from one stable location.
from ..checkpoint_store import CheckpointStore
from ..ledger import LedgerBackend
from ..signing import KeySource

if TYPE_CHECKING:  # avoid importing the SDK/events at module load (keeps this light)
    from ..events import ComplianceEvent
    from ..sdk import EvidenceClient

log = logging.getLogger("openwright.connectors")

#: Semver-stable connector contract version (CORE-4). A connector declares the
#: version it targets (a ``CONTRACT_VERSION`` attribute on the loaded object or
#: its module); core warns on a **major** mismatch.
CONTRACT_VERSION = "1.0"

#: Entry-point groups core scans for connectors (CORE-2).
GROUPS = (
    "openwright.source_connectors",
    "openwright.forwarders",
    "openwright.report_exporters",
    "openwright.ledger_backends",
    "openwright.checkpoint_stores",
)

__all__ = [
    "CONTRACT_VERSION", "GROUPS",
    "LedgerBackend", "CheckpointStore", "KeySource",
    "SourceConnector", "Forwarder", "ReportExporter", "ExportResult", "BackendFactory",
    "discover", "discover_all", "load", "register", "available", "contract_compatible",
    "resolve_backend",
]


@dataclass
class ExportResult:
    """The outcome of a :class:`ReportExporter` / :class:`Forwarder` action."""

    ok: bool
    detail: str = ""
    url: Optional[str] = None


@runtime_checkable
class SourceConnector(Protocol):
    """Framework capture: map a framework's runtime events to SDK calls."""

    name: str

    def instrument(self, client: "EvidenceClient", **opts: Any) -> Any:
        """Return a context manager that, while active, hooks the framework and
        maps its runtime events to ``client.record_*`` calls with correct
        task/context linkage. Payloads are hashed, never stored raw."""


@runtime_checkable
class ReportExporter(Protocol):
    """Sink for a signed report (GRC platform, CI, ticketing, …)."""

    name: str

    def export(self, report: dict, *, config: dict) -> ExportResult:
        """Push a signed report (and/or its verdicts) to an external system."""


@runtime_checkable
class Forwarder(Protocol):
    """Downstream observability (the Langfuse pattern): co-ingest + back-link + pull."""

    name: str

    def forward(self, payload: Any, *, config: dict) -> ExportResult:
        """Co-ingest a telemetry payload to the downstream system, unchanged."""

    def backlink(self, report: dict, *, config: dict) -> ExportResult:
        """Push ``openwright:<control>`` verdicts back onto the downstream traces."""

    def pull(self, *, config: dict) -> Iterable["ComplianceEvent"]:
        """Read external data (e.g. evals) and yield it as ComplianceEvents."""


@runtime_checkable
class BackendFactory(Protocol):
    """Builds a storage backend from a URI (e.g. ``postgres://…``, ``s3://bucket/prefix``)."""

    name: str

    def from_uri(self, uri: str) -> Any:
        """Return a configured ``LedgerBackend`` / ``CheckpointStore``."""


# -- registry: entry-point discovery + in-process registration ----------------

_REGISTRY: Dict[str, Dict[str, Any]] = {g: {} for g in GROUPS}


def register(group: str, name: str, impl: Any) -> None:
    """Register a connector in-process (used by core's built-ins, tests, and
    embedding). External connectors normally register via entry points instead."""
    if group not in _REGISTRY:
        raise ValueError(f"unknown connector group {group!r}; one of {GROUPS}")
    _REGISTRY[group][name] = impl


def _entry_points(group: str):
    import importlib.metadata as md

    eps = md.entry_points()
    try:
        return list(eps.select(group=group))  # py3.10+
    except AttributeError:  # pragma: no cover - legacy mapping API
        return list(eps.get(group, []))


def _targeted_version(impl: Any) -> Optional[str]:
    v = getattr(impl, "CONTRACT_VERSION", None)
    if v is not None:
        return str(v)
    mod_name = getattr(impl, "__module__", None)
    if mod_name:
        try:
            return str(getattr(importlib.import_module(mod_name), "CONTRACT_VERSION", None) or "") or None
        except Exception:  # noqa: BLE001
            return None
    return None


def contract_compatible(impl: Any) -> bool:
    """True if ``impl`` targets a contract major-compatible with core's."""
    target = _targeted_version(impl)
    if not target:
        return True  # undeclared = assume compatible (warned at discovery)
    return target.split(".")[0] == CONTRACT_VERSION.split(".")[0]


def _warn_if_incompatible(group: str, name: str, impl: Any) -> None:
    target = _targeted_version(impl)
    if target and not contract_compatible(impl):
        warnings.warn(
            f"connector {name!r} ({group}) targets contract v{target} but core provides "
            f"v{CONTRACT_VERSION}; major mismatch — behavior is not guaranteed",
            stacklevel=2,
        )


def discover(group: str) -> Dict[str, Any]:
    """Return ``{name: impl}`` for connectors in ``group`` — installed entry
    points merged with in-process registrations. Entry points that fail to load
    are skipped and logged (a broken connector never breaks core)."""
    if group not in _REGISTRY:
        raise ValueError(f"unknown connector group {group!r}; one of {GROUPS}")
    out: Dict[str, Any] = {}
    for ep in _entry_points(group):
        try:
            impl = ep.load()
        except Exception:  # noqa: BLE001
            log.exception("failed to load connector %r in %s", ep.name, group)
            continue
        _warn_if_incompatible(group, ep.name, impl)
        out[ep.name] = impl
    # In-process registrations fill in (don't override an installed package).
    for name, impl in _REGISTRY[group].items():
        out.setdefault(name, impl)
        _warn_if_incompatible(group, name, impl)
    return out


def discover_all() -> Dict[str, Dict[str, Any]]:
    return {g: discover(g) for g in GROUPS}


def available() -> Dict[str, List[str]]:
    """``{group: [names]}`` — for ``openwright connectors list``."""
    return {g: sorted(discover(g)) for g in GROUPS}


def load(group: str, name: str) -> Any:
    """Load one connector by group + name. Raises ``KeyError`` if absent."""
    impl = discover(group).get(name)
    if impl is None:
        raise KeyError(
            f"no connector {name!r} in group {group!r}; available: {sorted(discover(group))}"
        )
    return impl


def resolve_backend(group: str, uri: str) -> Any:
    """Resolve a storage URI (``scheme://…``) to a backend via the scheme's
    registered factory, e.g. ``resolve_backend('openwright.ledger_backends',
    'postgres://…')`` -> a ``LedgerBackend``."""
    scheme = uri.split("://", 1)[0] if "://" in uri else uri
    factory = load(group, scheme)
    if not hasattr(factory, "from_uri"):
        raise TypeError(f"connector {scheme!r} in {group} has no from_uri(uri)")
    return factory.from_uri(uri)


# Register core's reference backends in-process so URI resolution works out of
# the box (importing this triggers builtin registration). Kept at the bottom to
# avoid a circular import during module initialization.
from . import builtin as _builtin  # noqa: E402,F401
