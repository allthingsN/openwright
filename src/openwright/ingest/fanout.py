"""Fan-out forwarding to a downstream OTLP/HTTP backend, bytes unchanged.

Per FR-ING-04 / IR-07, telemetry forwarded to existing backends (Langfuse,
Phoenix, Datadog) must not be altered. We forward the exact original request
body with its original content type. Uses only the standard library.
"""

from __future__ import annotations

import logging
import urllib.request
from typing import Optional, Tuple

log = logging.getLogger("openwright.ingest.fanout")


class Forwarder:
    def __init__(self, downstream_url: str, *, timeout: float = 5.0) -> None:
        self.downstream_url = downstream_url
        self.timeout = timeout

    def forward(self, body: bytes, content_type: str = "application/x-protobuf") -> Tuple[int, bytes]:
        req = urllib.request.Request(
            self.downstream_url, data=body, method="POST",
            headers={"Content-Type": content_type},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.status, resp.read()


def maybe_forward(forwarder: Optional[Forwarder], body: bytes, content_type: str) -> Tuple[int, bytes]:
    if forwarder is None:
        return 200, b""
    try:
        return forwarder.forward(body, content_type)
    except Exception as exc:  # noqa: BLE001 - surface as a telemetry-path error
        log.warning("downstream forward failed: %s", exc)
        return 502, b""
