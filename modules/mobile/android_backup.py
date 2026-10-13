"""Análise de backups Android ADB (.ab).

Formato .ab (documentado publicamente pelo AOSP / projetos como
android-backup-extractor):

    linha 1: "ANDROID BACKUP"
    linha 2: versão (1-5)
    linha 3: flag de compressão (0/1)
    linha 4: algoritmo de criptografia ("none" ou "AES-256")
    [resto]: payload (tar, opcionalmente zlib-compressed, opcionalmente
              criptografado com a senha que o dono do backup definiu)

Backups criptografados (linha 4 = "AES-256") são decodificados quando o
examinador fornece a senha (já conhecida legalmente — ver
modules/mobile/android_crypto.py para o algoritmo e seu escopo/limites).
Sem senha, o módulo apenas reporta que o backup está criptografado.
"""
from __future__ import annotations

import io
import sqlite3
import tarfile
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from core.extraction import save_extracted_file
from core.plugin import AnalysisContext, AnalysisModule
from core.timeline import Event
from modules.mobile.android_crypto import AndroidBackupDecryptError, decrypt_backup

MAGIC = b"ANDROID BACKUP"


class AndroidBackupModule(AnalysisModule):
    name = "mobile.android_backup"

    def supports(self, evidence_path: Path) -> bool:
        if evidence_path.suffix.lower() != ".ab":
            return False
        try:
            with open(evidence_path, "rb") as f:
                return f.read(len(MAGIC)) == MAGIC
        except OSError:
            return False

    def analyze(self, evidence_path: Path, evidence_item_id: str, context: AnalysisContext) -> list[Event]:
        events: list[Event] = []
        with open(evidence_path, "rb") as f:
            raw = f.read()

        header_lines, payload_offset = self._split_header(raw)
        version, compressed, encryption = header_lines[1], header_lines[2], header_lines[3]

        if encryption.lower() != "none":
            if not context.credential:
                events.append(
                    self._event(
                        evidence_item_id,
                        "backup_encrypted",
                        f"Backup Android criptografado ({encryption}); forneça a senha conhecida "
                        "pelo examinador para decodificar.",
                    )
                )
                return events

            crypto_lines, payload_offset = self._split_header(raw, start_offset=payload_offset, count=5)
            try:
                user_salt = bytes.fromhex(crypto_lines[0])
                rounds = int(crypto_lines[2])
                user_iv = bytes.fromhex(crypto_lines[3])
                master_key_blob = bytes.fromhex(crypto_lines[4])
                payload = decrypt_backup(
                    context.credential, user_salt, rounds, user_iv, master_key_blob, raw[payload_offset:]
                )
            except (AndroidBackupDecryptError, ValueError) as exc:
                events.append(
                    self._event(
                        evidence_item_id,
                        "backup_decrypt_failed",
                        f"Falha ao decodificar backup com a senha fornecida: {exc}",
                    )
                )
                return events
        else:
            payload = raw[payload_offset:]

        if compressed == "1":
            try:
                payload = zlib.decompress(payload)
            except zlib.error as exc:
                events.append(
                    self._event(
                        evidence_item_id,
                        "backup_decrypt_failed",
                        f"Payload decriptado não é um stream zlib válido (senha incorreta?): {exc}",
                    )
                )
                return events

        try:
            with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
                events.extend(self._scan_tar(tar, evidence_item_id, context.extracted_dir, context.max_extract_size))
        except tarfile.TarError as exc:
            events.append(
                self._event(
                    evidence_item_id,
                    "backup_decrypt_failed",
                    f"Payload não é um tar válido (senha incorreta?): {exc}",
                )
            )

        return events

    def _split_header(self, raw: bytes, start_offset: int = 0, count: int = 4) -> tuple[list[str], int]:
        lines = []
        offset = start_offset
        for _ in range(count):
            nl = raw.index(b"\n", offset)
            lines.append(raw[offset:nl].decode("utf-8", errors="replace"))
            offset = nl + 1
        return lines, offset

    def _scan_tar(
        self, tar: tarfile.TarFile, evidence_item_id: str, extracted_dir: Path | None, max_extract_size: int,
    ) -> list[Event]:
        events: list[Event] = []
        db_members = []

        for member in tar.getmembers():
            if not member.isfile():
                continue
            events.append(
                self._event(
                    evidence_item_id,
                    "backup_file",
                    f"Arquivo no backup: {member.name}",
                    metadata={"path": member.name, "size": member.size},
                    timestamp=self._member_timestamp(member),
                )
            )
            if member.name.lower().endswith(".db"):
                db_members.append(member)

            if extracted_dir is not None and 0 < member.size <= max_extract_size:
                extracted = tar.extractfile(member)
                if extracted is not None:
                    save_extracted_file(extracted_dir, evidence_item_id, member.name, extracted.read())

        with tempfile.TemporaryDirectory() as tmp:
            for member in db_members:
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                db_path = Path(tmp) / Path(member.name).name
                db_path.write_bytes(extracted.read())
                events.extend(self._scan_sqlite(db_path, member.name, evidence_item_id))

        return events

    def _scan_sqlite(self, db_path: Path, origin_name: str, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error:
            return events

        try:
            cursor = conn.cursor()
            tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")]

            for table in tables:
                lower = table.lower()
                if "sms" in lower or "mms" in lower:
                    events.extend(self._scan_messages_table(cursor, table, origin_name, evidence_item_id))
                elif "call" in lower:
                    events.extend(self._scan_calls_table(cursor, table, origin_name, evidence_item_id))
        except sqlite3.Error:
            pass
        finally:
            conn.close()

        return events

    def _scan_messages_table(self, cursor, table: str, origin_name: str, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            columns = {row[1].lower() for row in cursor.execute(f"PRAGMA table_info({table})")}
        except sqlite3.Error:
            return events
        if not {"date", "address"}.issubset(columns):
            return events

        body_col = "body" if "body" in columns else None
        type_col = "type" if "type" in columns else None
        select_cols = ["date", "address"] + ([body_col] if body_col else []) + ([type_col] if type_col else [])

        try:
            for row in cursor.execute(f"SELECT {', '.join(select_cols)} FROM {table}"):
                row_dict = dict(zip(select_cols, row))
                ts = self._epoch_ms_to_iso(row_dict.get("date"))
                direction = self._sms_direction(row_dict.get(type_col)) if type_col else "desconhecida"
                events.append(
                    self._event(
                        evidence_item_id,
                        "sms",
                        f"SMS ({direction}) com {row_dict.get('address')}: "
                        f"{(row_dict.get(body_col) or '')[:120]}",
                        metadata={"table": table, "source_file": origin_name, **row_dict},
                        timestamp=ts,
                    )
                )
        except sqlite3.Error:
            pass
        return events

    def _scan_calls_table(self, cursor, table: str, origin_name: str, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            columns = {row[1].lower() for row in cursor.execute(f"PRAGMA table_info({table})")}
        except sqlite3.Error:
            return events
        if not {"date", "number"}.issubset(columns):
            return events

        extra_cols = [c for c in ("duration", "type") if c in columns]
        select_cols = ["date", "number"] + extra_cols

        try:
            for row in cursor.execute(f"SELECT {', '.join(select_cols)} FROM {table}"):
                row_dict = dict(zip(select_cols, row))
                ts = self._epoch_ms_to_iso(row_dict.get("date"))
                events.append(
                    self._event(
                        evidence_item_id,
                        "call",
                        f"Chamada com {row_dict.get('number')} "
                        f"(duração {row_dict.get('duration', '?')}s)",
                        metadata={"table": table, "source_file": origin_name, **row_dict},
                        timestamp=ts,
                    )
                )
        except sqlite3.Error:
            pass
        return events

    @staticmethod
    def _sms_direction(type_value) -> str:
        # Convenção do provider Android: 1=recebida, 2=enviada
        return {1: "recebida", 2: "enviada"}.get(type_value, "desconhecida")

    @staticmethod
    def _epoch_ms_to_iso(value) -> str:
        try:
            return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _member_timestamp(member: tarfile.TarInfo) -> str:
        try:
            return datetime.fromtimestamp(member.mtime, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
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
