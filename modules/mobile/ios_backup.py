"""Análise de backup iOS (iTunes/Finder), formato documentado pelo projeto
libimobiledevice e usado por toda a comunidade forense.

Estrutura de uma pasta de backup iOS:
    <backup_dir>/
        Manifest.plist      — metadados gerais, inclui flag IsEncrypted
        Manifest.db         — SQLite: tabela Files(fileID, domain, relativePath, flags, file)
        Info.plist
        <2 primeiros chars do fileID>/<fileID>   — conteúdo real de cada arquivo

fileID = SHA1("domain-relativePath") em versões antigas; em versões novas é um
GUID. Este módulo lê o Manifest.db (SQLite, não depende do algoritmo de hash)
para resolver path lógico -> arquivo físico.

Backups **criptografados** (IsEncrypted=True no Manifest.plist) não são
decodificados aqui — a derivação de chave a partir do keybag exige validação
cuidadosa antes de uso em laudo real (ver docs/roadmap.md).
"""
from __future__ import annotations

import plistlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.plugin import AnalysisModule
from core.timeline import Event


class IOSBackupModule(AnalysisModule):
    name = "mobile.ios_backup"

    def supports(self, evidence_path: Path) -> bool:
        return evidence_path.is_dir() and (evidence_path / "Manifest.db").exists()

    def analyze(self, evidence_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []

        manifest_plist_path = evidence_path / "Manifest.plist"
        if manifest_plist_path.exists():
            with open(manifest_plist_path, "rb") as f:
                manifest = plistlib.load(f)
            if manifest.get("IsEncrypted"):
                events.append(
                    self._event(
                        evidence_item_id,
                        "backup_encrypted",
                        "Backup iOS criptografado (senha definida no iTunes/Finder); "
                        "decodificação do keybag não implementada neste módulo.",
                    )
                )
                return events

        conn = sqlite3.connect(f"file:{evidence_path / 'Manifest.db'}?mode=ro", uri=True)
        try:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT fileID, domain, relativePath, flags FROM Files")
            for file_id, domain, relative_path, flags in rows:
                if not relative_path:
                    continue
                is_dir = flags == 2
                physical_path = evidence_path / file_id[0:2] / file_id
                size = physical_path.stat().st_size if physical_path.exists() and not is_dir else None

                events.append(
                    self._event(
                        evidence_item_id,
                        "backup_file",
                        f"[{domain}] {relative_path}",
                        metadata={
                            "domain": domain,
                            "relative_path": relative_path,
                            "file_id": file_id,
                            "size": size,
                            "is_dir": is_dir,
                        },
                    )
                )

                lower_path = relative_path.lower()
                if "sms.db" in lower_path and physical_path.exists():
                    events.extend(self._scan_sms_db(physical_path, evidence_item_id))
                elif "call_history" in lower_path or "callhistory" in lower_path:
                    if physical_path.exists():
                        events.extend(self._scan_call_history(physical_path, evidence_item_id))
        finally:
            conn.close()

        return events

    def _scan_sms_db(self, db_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error:
            return events
        try:
            cursor = conn.cursor()
            tables = {r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "message" not in tables:
                return events
            for row in cursor.execute(
                "SELECT date, text, is_from_me, service FROM message WHERE text IS NOT NULL"
            ):
                date_val, text, is_from_me, service = row
                ts = self._apple_epoch_to_iso(date_val)
                direction = "enviada" if is_from_me else "recebida"
                events.append(
                    self._event(
                        evidence_item_id,
                        "sms",
                        f"Mensagem ({direction}, {service}): {(text or '')[:120]}",
                        metadata={"is_from_me": bool(is_from_me), "service": service},
                        timestamp=ts,
                    )
                )
        except sqlite3.Error:
            pass
        finally:
            conn.close()
        return events

    def _scan_call_history(self, db_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error:
            return events
        try:
            cursor = conn.cursor()
            tables = {r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "call" not in tables:
                return events
            for row in cursor.execute("SELECT address, date, duration, answered FROM call"):
                address, date_val, duration, answered = row
                ts = self._apple_epoch_to_iso(date_val)
                events.append(
                    self._event(
                        evidence_item_id,
                        "call",
                        f"Chamada com {address} (duração {duration}s, "
                        f"{'atendida' if answered else 'não atendida'})",
                        timestamp=ts,
                    )
                )
        except sqlite3.Error:
            pass
        finally:
            conn.close()
        return events

    @staticmethod
    def _apple_epoch_to_iso(value) -> str:
        # Epoch Apple (Core Data / Mac absolute time) = 2001-01-01T00:00:00Z.
        # iOS >= 11 armazena em nanossegundos; versões antigas em segundos.
        try:
            value = float(value)
            if value > 1e12:
                value /= 1_000_000_000
            apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc).timestamp()
            return datetime.fromtimestamp(apple_epoch + value, tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            return datetime.now(timezone.utc).isoformat()

    def _event(self, evidence_item_id, event_type, description, metadata=None, timestamp=None) -> Event:
        return Event(
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
