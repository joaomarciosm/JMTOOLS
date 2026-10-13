"""Decodificação de mídia do WhatsApp já extraída (pasta com um banco de
mensagens — `message_media`/`media` — e os arquivos de mídia referenciados
por ele, como um sandbox de app inteiro extraído via `adb backup`/App
Data). Usa modules/mobile/whatsapp_media_crypto.py (algoritmo público,
documentado por diversas reimplementações independentes).

Como o schema do WhatsApp varia entre versões (coluna de chave pode se
chamar `media_key` ou `key`; de caminho, `file_path` ou `path`), a
detecção de tabela/coluna é genérica (mesma estratégia usada em
mobile/android_backup.py para SMS). E como nem sempre dá para confiar no
mimetype salvo no banco, este módulo tenta decodificar com os 4 tipos de
mídia conhecidos e aceita o resultado cujo MAC validar — a verificação
criptográfica já diz qual é o tipo certo, sem precisar adivinhar.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.extraction import save_extracted_file
from core.plugin import AnalysisContext, AnalysisModule
from core.timeline import Event
from modules.mobile.whatsapp_media_crypto import (
    HKDF_INFO_BY_MEDIA_TYPE,
    WhatsAppMediaDecryptError,
    decrypt_media,
)

KEY_COLUMN_CANDIDATES = ("media_key", "key")
PATH_COLUMN_CANDIDATES = ("file_path", "path")


class WhatsAppMediaModule(AnalysisModule):
    name = "mobile.whatsapp_media"

    def supports(self, evidence_path: Path) -> bool:
        if not evidence_path.is_dir():
            return False
        return any(self._find_media_db(evidence_path))

    def _find_media_db(self, folder: Path):
        for db_path in folder.rglob("*.db"):
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            except sqlite3.Error:
                continue
            try:
                tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                for table in tables:
                    if "media" not in table.lower():
                        continue
                    columns = {r[1].lower() for r in conn.execute(f"PRAGMA table_info({table})")}
                    key_col = next((c for c in KEY_COLUMN_CANDIDATES if c in columns), None)
                    path_col = next((c for c in PATH_COLUMN_CANDIDATES if c in columns), None)
                    if key_col and path_col:
                        yield db_path, table, key_col, path_col
            finally:
                conn.close()

    def analyze(self, evidence_path: Path, evidence_item_id: str, context: AnalysisContext) -> list[Event]:
        events: list[Event] = []
        for db_path, table, key_col, path_col in self._find_media_db(evidence_path):
            events.extend(self._decrypt_from_table(evidence_path, db_path, table, key_col, path_col,
                                                     evidence_item_id, context))
        return events

    def _decrypt_from_table(
        self, root: Path, db_path: Path, table: str, key_col: str, path_col: str,
        evidence_item_id: str, context: AnalysisContext,
    ) -> list[Event]:
        events: list[Event] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error:
            return events

        try:
            rows = conn.execute(f"SELECT {key_col}, {path_col} FROM {table}").fetchall()
        except sqlite3.Error:
            return events
        finally:
            conn.close()

        for media_key_raw, rel_path in rows:
            if not media_key_raw or not rel_path:
                continue
            media_key = self._coerce_key_bytes(media_key_raw)
            if media_key is None or len(media_key) != 32:
                continue

            media_path = (root / str(rel_path).lstrip("/\\")).resolve()
            if not media_path.exists() or not media_path.is_file():
                continue

            encrypted = media_path.read_bytes()
            plaintext, media_type = self._try_all_media_types(media_key, encrypted)

            if plaintext is None:
                events.append(
                    self._event(
                        evidence_item_id,
                        "whatsapp_media_decrypt_failed",
                        f"Falha ao decodificar mídia (MAC não validou em nenhum tipo conhecido): {rel_path}",
                    )
                )
                continue

            events.append(
                self._event(
                    evidence_item_id,
                    "whatsapp_media_decrypted",
                    f"Mídia do WhatsApp decodificada ({media_type}): {rel_path}",
                    metadata={"path": str(rel_path), "media_type": media_type, "size": len(plaintext)},
                )
            )
            if context.extracted_dir is not None and len(plaintext) <= context.max_extract_size:
                save_extracted_file(context.extracted_dir, evidence_item_id, f"decrypted_media/{rel_path}", plaintext)

        return events

    @staticmethod
    def _coerce_key_bytes(value) -> bytes | None:
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return bytes.fromhex(value)
            except ValueError:
                return None
        return None

    @staticmethod
    def _try_all_media_types(media_key: bytes, encrypted: bytes) -> tuple[bytes | None, str | None]:
        for media_type in HKDF_INFO_BY_MEDIA_TYPE:
            try:
                return decrypt_media(media_key, encrypted, media_type), media_type
            except WhatsAppMediaDecryptError:
                continue
        return None, None

    def _event(self, evidence_item_id, event_type, description, metadata=None) -> Event:
        return Event(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
