"""Cadeia de custódia: registro imutável de ações sobre evidências."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class CustodyEntry:
    timestamp: str
    actor: str
    action: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "detail": self.detail,
        }


@dataclass
class CustodyLog:
    entries: list[CustodyEntry] = field(default_factory=list)

    def record(self, actor: str, action: str, detail: str = "") -> CustodyEntry:
        entry = CustodyEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            detail=detail,
        )
        self.entries.append(entry)
        return entry

    def to_dict(self) -> list[dict]:
        return [e.to_dict() for e in self.entries]

    @classmethod
    def from_dict(cls, data: list[dict]) -> "CustodyLog":
        log = cls()
        for item in data:
            log.entries.append(CustodyEntry(**item))
        return log
