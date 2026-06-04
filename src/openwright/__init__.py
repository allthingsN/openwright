"""OpenWright — the Agent Evidence Layer.

OpenWright turns the runtime behavior of AI agents into signed, tamper-evident,
control-mapped audit evidence: telemetry/SDK signals → a canonical
``ComplianceEvent`` → declarative regulatory crosswalks → an append-only Merkle
log → signed reports → independent verification.

Boundary (non-negotiable, see FR-RPT-07 / NFR-COMP-01): OpenWright produces
*evidence that controls were exercised*. It does NOT assert or imply legal
compliance, certification, or fitness. Those are judgments reserved for
qualified auditors and counsel.
"""

__version__ = "0.7.1"

# Schema version for the canonical event model. Bumped independently of the
# package version; readers MUST tolerate unknown future fields (DR-04).
COMPLIANCE_EVENT_SCHEMA_VERSION = "1.0.0"

__all__ = ["__version__", "COMPLIANCE_EVENT_SCHEMA_VERSION", "instrument", "configure", "get_runtime"]


def __getattr__(name):
    # Lazy so that `import openwright.verify` stays dependency-light (INV-2 / the
    # no-network verifier test): the instrument/runtime path pulls pydantic etc.,
    # so it is imported only when actually accessed. The impl module is named
    # ``_instrument`` so the ``instrument`` *function* isn't shadowed by a submodule.
    if name == "instrument":
        from ._instrument import instrument
        return instrument
    if name == "configure":
        from .runtime import configure
        return configure
    if name == "get_runtime":
        from .runtime import get_runtime
        return get_runtime
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
