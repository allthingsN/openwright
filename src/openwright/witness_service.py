"""Standalone witness service (B8, FR-ATT-08).

The in-process :class:`~openwright.witness.Witness` packaged as separately-hosted
infrastructure with its **own independent key**, co-signing a producer's signed
tree heads over HTTP after verifying (a) the producer's signature and (b) a
consistency proof from the last head it endorsed. Run it on a different host from
the producer; then forging an *endorsed, rewritten* history requires compromising
the producer **and** the witness — which is the whole point of FR-ATT-08.

The transport is stdlib ``http.server`` only (no new dependency). The service
never sees raw payloads — it co-signs public tree heads (INV-3).
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .signing import Checkpoint, KeySource, public_key_pem, public_key_raw_from_pem
from .witness import Witness, WitnessCosignature, WitnessError


class WitnessService:
    """Hosts a :class:`Witness` (its own key) behind ``POST /cosign`` + ``GET /pubkey``."""

    def __init__(self, key: KeySource, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self.witness = Witness(key)
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def key_id(self) -> str:
        return self.witness.key_id

    @property
    def public_key_pem(self) -> str:
        return public_key_pem(self.witness.key.public_key_raw()).decode("ascii")

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "WitnessService":
        witness = self.witness

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence access logging
                pass

            def _send(self, code: int, body: bytes) -> None:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path != "/pubkey":
                    self._send(404, b'{"error":"not found"}')
                    return
                self._send(
                    200,
                    json.dumps(
                        {
                            "public_key_pem": public_key_pem(witness.key.public_key_raw()).decode("ascii"),
                            "key_id": witness.key_id,
                        }
                    ).encode("utf-8"),
                )

            def do_POST(self):
                if self.path != "/cosign":
                    self._send(404, b'{"error":"not found"}')
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    req = json.loads(self.rfile.read(length) or b"{}")
                    cp = Checkpoint.model_validate(req["checkpoint"])
                    producer_raw = public_key_raw_from_pem(req["producer_public_key_pem"].encode("utf-8"))
                    cosig = witness.cosign(
                        cp, producer_raw, consistency_proof_hex=req.get("consistency_proof_hex")
                    )
                    self._send(200, cosig.model_dump_json().encode("utf-8"))
                except (WitnessError, KeyError, ValueError, TypeError) as exc:
                    # 409: the witness refuses to endorse (bad sig / non-extension / equivocation).
                    self._send(409, json.dumps({"error": str(exc)}).encode("utf-8"))

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name="openwright-witness", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


class WitnessClient:
    """Talks to a (separately-hosted) :class:`WitnessService`."""

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def public_key_pem(self) -> str:
        with urllib.request.urlopen(self.url + "/pubkey", timeout=5) as resp:
            return json.loads(resp.read())["public_key_pem"]

    def cosign(
        self,
        checkpoint: Checkpoint,
        producer_public_key_pem: str,
        consistency_proof_hex=None,
    ) -> WitnessCosignature:
        payload = json.dumps(
            {
                "checkpoint": checkpoint.model_dump(),
                "producer_public_key_pem": producer_public_key_pem,
                "consistency_proof_hex": consistency_proof_hex,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            self.url + "/cosign", data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return WitnessCosignature.model_validate_json(resp.read())
        except urllib.error.HTTPError as exc:
            raise WitnessError(json.loads(exc.read()).get("error", "witness refused to co-sign"))
