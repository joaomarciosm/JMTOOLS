"""Histórico de navegação — Chrome/Edge/Brave (`History`, SQLite) e
Firefox (`places.sqlite`), formatos públicos e documentados pelos próprios
projetos abertos (Chromium, Firefox). O examinador adiciona o arquivo
`History`/`places.sqlite` já extraído (de um backup Android/iOS, de uma
imagem de disco, ou copiado diretamente) como um item de evidência.

Época dos timestamps:
    Chrome/Edge/Brave: microssegundos desde 1601-01-01 (igual ao FILETIME
    do Windows, mas em microssegundos em vez de intervalos de 100ns).
    Firefox: microssegundos desde 1970-01-01 (época Unix).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.plugin import AnalysisContext, AnalysisModule
from core.timeline import Event

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class BrowserHistoryModule(AnalysisModule):
    name = "web.browser_history"

    def supports(self, evidence_path: Path) -> bool:
        if not evidence_path.is_file():
            return False
        name = evidence_path.name.lower()
        if name not in ("history", "places.sqlite"):
            return False
        try:
            with open(evidence_path, "rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except OSError:
            return False

    def analyze(self, evidence_path: Path, evidence_item_id: str, context: AnalysisContext) -> list[Event]:
        is_firefox = evidence_path.name.lower() == "places.sqlite"
        try:
            conn = sqlite3.connect(f"file:{evidence_path}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            return [self._event(evidence_item_id, "browser_history_parse_error", f"Falha ao abrir banco: {exc}")]

        events: list[Event] = []
        try:
            cursor = conn.cursor()
            if is_firefox:
                events.extend(self._scan_firefox(cursor, evidence_item_id))
            else:
                events.extend(self._scan_chrome(cursor, evidence_item_id))
        except sqlite3.Error as exc:
            events.append(self._event(evidence_item_id, "browser_history_parse_error", f"Falha ao ler tabelas: {exc}"))
        finally:
            conn.close()

        return events

    def _scan_chrome(self, cursor, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        for url, title, visit_count, last_visit_time in cursor.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time"
        ):
            ts = self._chrome_time_to_iso(last_visit_time)
            events.append(
                self._event(
                    evidence_item_id,
                    "browser_history",
                    f"[Chrome/Edge] {title or url}",
                    metadata={"url": url, "title": title, "visit_count": visit_count, "browser": "chrome"},
                    timestamp=ts,
                )
            )
        return events

    def _scan_firefox(self, cursor, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        for url, title, visit_count, last_visit_date in cursor.execute(
            "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL "
            "ORDER BY last_visit_date"
        ):
            ts = self._firefox_time_to_iso(last_visit_date)
            events.append(
                self._event(
                    evidence_item_id,
                    "browser_history",
                    f"[Firefox] {title or url}",
                    metadata={"url": url, "title": title, "visit_count": visit_count, "browser": "firefox"},
                    timestamp=ts,
                )
            )
        return events

    @staticmethod
    def _chrome_time_to_iso(value) -> str:
        try:
            return (CHROME_EPOCH + timedelta(microseconds=int(value))).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _firefox_time_to_iso(value) -> str:
        try:
            return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc).isoformat()
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
