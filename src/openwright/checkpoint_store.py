"""Persistent checkpoint (signed tree head) stores (FR-LED-03).

Checkpoints are small and append-only by nature (one per tree size/epoch). A
local filesystem store ships for the demo path; an S3-compatible object store
(boto3, imported lazily) is the production path — both behind one interface.

The S3 store enforces WORM retention **in code** (B4): when configured with an
object-lock mode + retention, every ``put`` stamps the object with
``ObjectLockMode`` + ``ObjectLockRetainUntilDate`` so the bucket's Object Lock
makes the checkpoint immutable and undeletable until the retention window
expires — there is no code path that overwrites or deletes a checkpoint.
"""

from __future__ import annotations

import abc
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from .signing import Checkpoint


class CheckpointStore(abc.ABC):
    @abc.abstractmethod
    def put(self, checkpoint: Checkpoint) -> str:
        """Persist a checkpoint; return its storage key."""

    @abc.abstractmethod
    def get(self, tree_size: int) -> Optional[Checkpoint]: ...

    @abc.abstractmethod
    def tree_sizes(self) -> List[int]: ...

    def latest(self) -> Optional[Checkpoint]:
        sizes = self.tree_sizes()
        return self.get(max(sizes)) if sizes else None


class LocalCheckpointStore(CheckpointStore):
    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, tree_size: int) -> Path:
        return self.dir / f"checkpoint-{tree_size:012d}.json"

    def put(self, checkpoint: Checkpoint) -> str:
        path = self._path(checkpoint.tree_size)
        path.write_text(json.dumps(checkpoint.model_dump(), indent=2))
        return str(path)

    def get(self, tree_size: int) -> Optional[Checkpoint]:
        path = self._path(tree_size)
        if not path.exists():
            return None
        return Checkpoint.model_validate(json.loads(path.read_text()))

    def tree_sizes(self) -> List[int]:
        return sorted(int(p.stem.split("-")[1]) for p in self.dir.glob("checkpoint-*.json"))


class S3CheckpointStore(CheckpointStore):
    """S3-compatible object store (boto3, lazy import) with enforced WORM (B4).

    Pass ``object_lock_mode`` (``"COMPLIANCE"`` or ``"GOVERNANCE"``) + ``retention``
    and every checkpoint is written with S3 Object Lock metadata, so the object
    cannot be overwritten or deleted until the retention window elapses — the
    retention is enforced by the object store from the metadata this code sets,
    not by a comment. The bucket must have Object Lock enabled at creation
    (versioning is implied); :meth:`create_locked_bucket` does that.

    ``COMPLIANCE`` mode is the strong setting: not even the root account can
    shorten retention or delete early. Use ``GOVERNANCE`` when privileged
    override is acceptable.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "openwright/checkpoints",
        *,
        client=None,
        object_lock_mode: Optional[str] = None,
        retention: Optional[timedelta] = None,
    ) -> None:
        if client is None:
            import boto3  # lazy: optional dependency

            client = boto3.client("s3")
        if object_lock_mode is not None:
            if object_lock_mode not in ("COMPLIANCE", "GOVERNANCE"):
                raise ValueError("object_lock_mode must be 'COMPLIANCE' or 'GOVERNANCE'")
            if retention is None:
                raise ValueError("object_lock_mode requires a retention window")
        self._s3 = client
        self.bucket = bucket
        self.prefix = prefix.rstrip("/")
        self.object_lock_mode = object_lock_mode
        self.retention = retention

    @staticmethod
    def create_locked_bucket(client, bucket: str) -> None:
        """Create ``bucket`` with Object Lock enabled (required before WORM puts)."""
        client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)

    def _key(self, tree_size: int) -> str:
        return f"{self.prefix}/checkpoint-{tree_size:012d}.json"

    def put(self, checkpoint: Checkpoint) -> str:
        key = self._key(checkpoint.tree_size)
        extra: dict = {}
        if self.object_lock_mode is not None:
            retain_until = datetime.now(timezone.utc) + self.retention  # type: ignore[operator]
            extra["ObjectLockMode"] = self.object_lock_mode
            extra["ObjectLockRetainUntilDate"] = retain_until
        self._s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(checkpoint.model_dump()).encode("utf-8"),
            ContentType="application/json",
            **extra,
        )
        return f"s3://{self.bucket}/{key}"

    def get(self, tree_size: int) -> Optional[Checkpoint]:
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=self._key(tree_size))
        except Exception:  # noqa: BLE001 - missing key
            return None
        return Checkpoint.model_validate(json.loads(obj["Body"].read()))

    def tree_sizes(self) -> List[int]:
        resp = self._s3.list_objects_v2(Bucket=self.bucket, Prefix=f"{self.prefix}/checkpoint-")
        sizes = []
        for item in resp.get("Contents", []):
            stem = item["Key"].rsplit("/", 1)[-1].replace(".json", "")
            sizes.append(int(stem.split("-")[1]))
        return sorted(sizes)
