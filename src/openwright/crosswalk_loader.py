"""Loading declarative crosswalks from YAML (FR-MAP-01/05, NFR-MNT-01).

Built-in crosswalks live in the separately versioned ``openwright.crosswalks``
package directory, each with its own ``version`` and a shared ``CHANGELOG.md``.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .crosswalk import Crosswalk, select_profile

_BUILTINS = {
    "eu-ai-act": "eu_ai_act.yaml",
    "eu-ai-act-v1": "eu_ai_act_v1.yaml",
    "soc2": "soc2.yaml",
    "nist-ai-rmf": "nist_ai_rmf.yaml",
    "iso-42001": "iso_42001.yaml",
    "gdpr": "gdpr.yaml",
}


def load_crosswalk_text(text: str, *, profile: Optional[List[str]] = None) -> Crosswalk:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "crosswalk" not in data:
        raise ValueError("crosswalk YAML must have a top-level 'crosswalk:' key")
    cw = Crosswalk.model_validate(data["crosswalk"])
    return select_profile(cw, profile)


def load_crosswalk_file(path: str | Path, *, profile: Optional[List[str]] = None) -> Crosswalk:
    return load_crosswalk_text(Path(path).read_text(encoding="utf-8"), profile=profile)


def load_builtin(name: str, *, profile: Optional[List[str]] = None) -> Crosswalk:
    """Load a built-in crosswalk, optionally selecting a deployer profile (B14).

    ``profile`` chooses among variant controls (e.g. ``["in_the_loop"]`` vs
    ``["on_the_loop"]`` for EU AI Act Art. 14, and ``"fria_applicable"`` to include
    Art. 27). ``None`` uses the crosswalk's declared defaults.
    """
    if name not in _BUILTINS:
        raise KeyError(f"unknown built-in crosswalk {name!r}; available: {sorted(_BUILTINS)}")
    text = resources.files("openwright.crosswalks").joinpath(_BUILTINS[name]).read_text(encoding="utf-8")
    return load_crosswalk_text(text, profile=profile)


def available_builtins() -> Dict[str, str]:
    return dict(_BUILTINS)
