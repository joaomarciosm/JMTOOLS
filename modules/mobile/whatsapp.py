"""Análise de backups do WhatsApp (.crypt12/.crypt14/.crypt15) já extraídos
de um backup Android/iOS ou copiados diretamente do armazenamento do app.

Requer a credencial: o caminho do arquivo de chave (`key` para crypt12/14,
`encrypted_backup.key` para crypt15) ou, só para crypt15, a chave em
hexadecimal de 64 dígitos que o próprio WhatsApp exibe na tela de backup
— exatamente como o examinador já a teria extraído/anotado legalmente.

O parsing de mensagens após a decodificação é propositalmente genérico
(procura qualquer tabela com colunas de timestamp + texto), porque o
esquema do `msgstore.db` muda bastante entre versões do WhatsApp — ver
docs/roadmap.md para o plano de suportar o esquema atual completo
(tabelas chat/jid/message relacionadas).
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.extraction import save_extracted_file
from core.plugin import AnalysisModule
from core.timeline import Event
from modules.mobile.whatsapp_crypto import (
    SQLITE_MAGIC,
    WhatsAppDecryptError,
    decrypt_crypt12,
    decrypt_crypt14_or_15,
    derive_aes_key,
    key_payload_from_hex,
    load_key_payload_from_file,
)

EXTENSIONS = {".crypt12", ".crypt14", ".crypt15"}


class WhatsAppModule(AnalysisModule):
    name = "mobile.whatsapp"

    def supports(self, evidence_path: Path) -> bool:
        return evidence_path.is_file() and evidence_path.suffix.lower() in EXTENSIONS

    def analyze(
        self, evidence_path: Path, evidence_item_id: str,
        credential: str | None = None, extracted_dir: Path | None = None,
    ) -> list[Event]:
        if not credential:
            return [
                self._event(
                    evidence_item_id,
                    "whatsapp_db_encrypted",
                    "Backup do WhatsApp criptografado; forneça o caminho do arquivo de chave "
                    "(ou, para crypt15, a chave hex de 64 dígitos) para decodificar.",
                )
            ]

        try:
            key_payload = self._resolve_key_payload(credential)
            aes_key = derive_aes_key(key_payload)
            raw = evidence_path.read_bytes()
            suffix = evidence_path.suffix.lower()
            if suffix == ".crypt12":
                plaintext = decrypt_crypt12(raw, aes_key)
            else:
                plaintext = decrypt_crypt14_or_15(raw, aes_key)
        except WhatsAppDecryptError as exc:
            return [
                self._event(
                    evidence_item_id,
                    "whatsapp_decrypt_failed",
                    f"Falha ao decodificar backup do WhatsApp: {exc}",
                )
            ]

        if plaintext[: len(SQLITE_MAGIC)] != SQLITE_MAGIC:
            return [
                self._event(
                    evidence_item_id,
                    "whatsapp_decrypt_failed",
                    "Decodificação não produziu um banco SQLite válido — chave incorreta ou formato inesperado.",
                )
            ]

        events = [
            self._event(
                evidence_item_id,
                "whatsapp_db_decrypted",
                f"Banco de mensagens do WhatsApp decodificado com sucesso ({len(plaintext)} bytes).",
                metadata={"size": len(plaintext)},
            )
        ]

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "msgstore.db"
            db_path.write_bytes(plaintext)
            events.extend(self._scan_messages(db_path, evidence_item_id))

        if extracted_dir is not None:
            save_extracted_file(extracted_dir, evidence_item_id, f"{evidence_path.name}.decrypted.db", plaintext)

        return events

    def _resolve_key_payload(self, credential: str) -> bytes:
        if len(credential.strip()) == 64 and all(c in "0123456789abcdefABCDEF" for c in credential.strip()):
            return key_payload_from_hex(credential)
        if not os.path.isfile(credential):
            raise WhatsAppDecryptError(f"Arquivo de chave não encontrado: {credential}")
        return load_key_payload_from_file(credential)

    def _scan_messages(self, db_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error:
            return events

        try:
            cursor = conn.cursor()
            tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                try:
                    columns = {row[1].lower() for row in cursor.execute(f"PRAGMA table_info({table})")}
                except sqlite3.Error:
                    continue
                if "timestamp" not in columns:
                    continue
                text_col = next((c for c in ("data", "text_data", "text", "body") if c in columns), None)
                if text_col is None:
                    continue
                jid_col = next((c for c in ("key_remote_jid", "remote_jid", "jid_row_id") if c in columns), None)
                select_cols = ["timestamp", text_col] + ([jid_col] if jid_col else [])
                try:
                    for row in cursor.execute(f"SELECT {', '.join(select_cols)} FROM {table} LIMIT 5000"):
                        row_dict = dict(zip(select_cols, row))
                        if not row_dict.get(text_col):
                            continue
                        ts = self._epoch_ms_to_iso(row_dict.get("timestamp"))
                        contact = row_dict.get(jid_col, "desconhecido") if jid_col else "desconhecido"
                        events.append(
                            self._event(
                                evidence_item_id,
                                "whatsapp_message",
                                f"Mensagem WhatsApp ({contact}): {str(row_dict[text_col])[:120]}",
                                metadata={"table": table, **row_dict},
                                timestamp=ts,
                            )
                        )
                except sqlite3.Error:
                    continue
        finally:
            conn.close()

        return events

    @staticmethod
    def _epoch_ms_to_iso(value) -> str:
        try:
            value = int(value)
            seconds = value / 1000 if value > 10_000_000_000 else value
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError, OverflowError):
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
