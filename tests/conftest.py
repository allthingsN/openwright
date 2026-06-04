"""Shared fixtures and the RFC 6962 golden test vectors."""

from __future__ import annotations

from datetime import timedelta

import pytest

from openwright.events import ComplianceEvent, EventKind
from openwright.ledger import InMemoryLedgerBackend, Ledger
from openwright.sdk import EvidenceClient
from openwright.signing import InMemoryKeySource

FIXED_TS = "2026-05-28T12:00:00.000000000Z"

# Google Certificate Transparency reference vectors (merkle_tree_test.cc).
CT_LEAVES_HEX = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                 "606162636465666768696a6b6c6d6e6f"]
CT_ROOTS = {
    0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}
# (leaf_index_0based, tree_size, expected_path_hex)
CT_INCLUSION = [
    (0, 1, []),
    (0, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]),
    (5, 8, ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]),
    (2, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]),
    (1, 5, ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]),
]
# (first_size, second_size, expected_proof_hex)
CT_CONSISTENCY = [
    (1, 1, []),
    (1, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]),
    (6, 8, ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]),
    (2, 5, ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]),
]


@pytest.fixture
def key():
    return InMemoryKeySource()


@pytest.fixture
def populated_ledger():
    """A ledger with one approved high-risk decision and one un-approved one,
    plus FRIA references — produces all three control states."""
    led = Ledger(InMemoryLedgerBackend(), origin="openwright/test",
                 retention=timedelta(days=200), clock=lambda: FIXED_TS)
    client = EvidenceClient(led, agent_id="loan-agent", clock=lambda: FIXED_TS)
    with client.task("t1", context_id="c1", root_task_id="t1"):
        appr = client.record_human_approval(reviewer="alice", rationale="reviewed")
        client.record_risk_classification("high", rationale="credit", fria="FRIA-1")
        client.record_decision(output="APPROVED", risk_classification="high",
                               rationale="score ok", approval_ref=appr.event_id,
                               control="art-14-human-oversight")
    with client.task("t2", context_id="c2", root_task_id="t2"):
        client.record_risk_classification("high", rationale="credit", fria="FRIA-1")
        client.record_decision(output="DENIED", risk_classification="high",
                               rationale="auto-denied", control="art-14-human-oversight")
    return led
