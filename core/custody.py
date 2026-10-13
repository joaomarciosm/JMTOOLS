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


def sha256_path(path: Path) -> str:
    """Hash de um item de evidência: arquivo único (SHA-256 direto) ou pasta
    (SHA-256 da concatenação ordenada de "caminho relativo + hash de cada
    arquivo" — fingerprint determinístico de todo o conteúdo da pasta, usado
    quando a evidência é uma extração lógica como um backup iOS ou dump de
    DVR em vários arquivos)."""
    if path.is_file():
        return sha256_file(path)

    digest = hashlib.sha256()
    for file_path in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = file_path.relative_to(path).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(sha256_file(file_path).encode("ascii"))
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
