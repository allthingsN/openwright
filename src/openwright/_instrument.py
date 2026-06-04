"""One-call agent instrumentation: ``openwright.instrument("openai-agents")``.

Resolves a framework instrumentor (shipped by the matching connector and advertised
under the ``openwright.instrumentors`` entry-point group) and attaches it to the
process runtime, so capturing an agent's evidence is a single line:

    import openwright
    openwright.instrument("openai-agents", decision_tools=["update_seat"])

The connector's ``auto_instrument(runtime, **opts)`` does the framework-specific
wiring (e.g. registering a global tracing processor). ``opts`` are passed through.
"""

from __future__ import annotations

import importlib.metadata as _im
from typing import Any, Optional

from .runtime import Runtime, get_runtime


def _load_instrumentor(name: str):
    try:
        eps = _im.entry_points(group="openwright.instrumentors")
    except TypeError:  # Python < 3.10 API shape
        eps = _im.entry_points().get("openwright.instrumentors", [])  # type: ignore[attr-defined]
    for ep in eps:
        if ep.name == name:
            return ep.load()
    available = sorted(ep.name for ep in eps)
    raise ValueError(
        f"No OpenWright instrumentor for {name!r}. Install the connector that provides it "
        f"(e.g. `pip install openwright-openai-agents`). Available: {available or 'none'}"
    )


def instrument(framework: str, *, runtime: Optional[Runtime] = None, **opts: Any):
    """Attach OpenWright evidence capture to ``framework`` in one call.

    Args:
        framework: instrumentor name, e.g. ``"openai-agents"`` or ``"langgraph"``.
        runtime: an explicit :class:`~openwright.runtime.Runtime`; defaults to the
            process runtime built from config/env.
        **opts: passed to the connector's ``auto_instrument`` (e.g. ``decision_tools``,
            ``approval_tools``, ``control``).

    Returns whatever the instrumentor returns (typically a handle/processor).
    """
    rt = runtime or get_runtime()
    return _load_instrumentor(framework)(rt, **opts)
