"""A2A task-provenance reconstruction (FR-ING-05).

Verified against the A2A spec (v0.3.0): a ``Task`` has ``id`` and ``contextId``
but NO parent-task field; cross-task lineage is expressed softly via
``Message.referenceTaskIds`` and grouping via ``contextId``. OpenWright therefore
*reconstructs* a parent/root chain from those signals — the ``parent_task_id``
and ``root_task_id`` on a :class:`Provenance` are OpenWright-derived, not native
A2A fields. Absent A2A, provenance degrades to single-event records (A-02).

All A2A-origin data is treated as untrusted input (FR-ING-10): IDs are used only
as opaque correlation keys, never interpreted or executed.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..events import Provenance


def reconstruct_provenance(
    task_id: Optional[str],
    context_id: Optional[str] = None,
    reference_task_ids: Optional[List[str]] = None,
    known: Optional[Dict[str, Provenance]] = None,
) -> Provenance:
    """Reconstruct parent/root for ``task_id`` from A2A signals.

    ``known`` maps already-seen task IDs to their reconstructed provenance, used
    to walk the root chain. ``reference_task_ids`` (from the triggering Message)
    yields the parent; the root is the parent's root, or this task if it has none.
    """
    known = known or {}
    parent_task_id = reference_task_ids[0] if reference_task_ids else None

    if parent_task_id and parent_task_id in known and known[parent_task_id].root_task_id:
        root_task_id = known[parent_task_id].root_task_id
    elif parent_task_id:
        root_task_id = parent_task_id  # parent unseen; best-effort root = parent
    else:
        root_task_id = task_id  # no parent → this task is its own root

    return Provenance(
        task_id=task_id,
        context_id=context_id,
        parent_task_id=parent_task_id,
        root_task_id=root_task_id,
    )


# Attribute keys some instrumentations use to carry A2A identifiers on spans.
A2A_TASK_ID = "a2a.task.id"
A2A_CONTEXT_ID = "a2a.context.id"
A2A_REFERENCE_TASK_IDS = "a2a.reference_task_ids"


def provenance_from_attributes(
    attrs: Dict[str, object], known: Optional[Dict[str, Provenance]] = None
) -> Optional[Provenance]:
    """Reconstruct provenance from A2A identifiers carried as span attributes."""
    task_id = attrs.get(A2A_TASK_ID)
    if not task_id:
        return None
    refs = attrs.get(A2A_REFERENCE_TASK_IDS)
    ref_list = list(refs) if isinstance(refs, (list, tuple)) else ([refs] if refs else None)
    return reconstruct_provenance(
        str(task_id),
        context_id=str(attrs[A2A_CONTEXT_ID]) if attrs.get(A2A_CONTEXT_ID) else None,
        reference_task_ids=[str(r) for r in ref_list] if ref_list else None,
        known=known,
    )
