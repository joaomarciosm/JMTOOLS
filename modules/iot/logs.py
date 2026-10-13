"""Análise de logs de dispositivos IoT (Linux embarcado) já extraídos —
por exemplo de um dump de flash (eMMC/SPI) montado, ou pasta copiada via
SSH/console serial com acesso já concedido pelo proprietário/perícia.

Reconhece dois formatos de timestamp comuns em syslog:
    - RFC3164 clássico, sem ano: "Oct 12 22:33:10 hostname proc[pid]: msg"
    - ISO-8601: "2026-10-12T22:33:10 ..." ou "2026-10-12 22:33:10 ..."

Não interpreta nenhum formato binário proprietário (ex: journald binário) —
isso fica como item de roadmap; aqui o foco é texto plano, que é o formato
mais comum em firmware embarcado simples (BusyBox syslogd, etc.).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from core.plugin import AnalysisModule
from core.timeline import Event

LOG_FILENAME_HINTS = {"syslog", "messages", "kern.log", "daemon.log", "auth.log", "dmesg"}

RFC3164_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\S*\s+(?P<msg>.*)$"
)
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


class IoTLogModule(AnalysisModule):
    name = "iot.logs"

    def supports(self, evidence_path: Path) -> bool:
        if not evidence_path.is_dir():
            return False
        return any(self._is_log_file(p) for p in evidence_path.rglob("*") if p.is_file())

    def analyze(self, evidence_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        for path in evidence_path.rglob("*"):
            if not path.is_file() or not self._is_log_file(path):
                continue
            file_year = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).year
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for line in lines:
                event = self._parse_line(line, file_year, path, evidence_path, evidence_item_id)
                if event:
                    events.append(event)

        return events

    @staticmethod
    def _is_log_file(path: Path) -> bool:
        name = path.name.lower()
        return name in LOG_FILENAME_HINTS or name.endswith(".log")

    def _parse_line(self, line: str, file_year: int, path: Path, root: Path, evidence_item_id: str) -> Event | None:
        line = line.strip()
        if not line:
            return None

        iso_match = ISO_RE.match(line)
        if iso_match:
            ts = iso_match.group("ts").replace(" ", "T")
            timestamp = f"{ts}+00:00" if "+" not in ts and "Z" not in ts else ts
            return self._event(evidence_item_id, "iot_log_line", iso_match.group("msg"),
                                metadata={"file": str(path.relative_to(root))}, timestamp=timestamp)

        rfc_match = RFC3164_RE.match(line)
        if rfc_match:
            month = MONTHS.get(rfc_match.group("mon"), 1)
            try:
                dt = datetime(file_year, month, int(rfc_match.group("day")),
                               *map(int, rfc_match.group("time").split(":")), tzinfo=timezone.utc)
            except ValueError:
                return None
            desc = f"[{rfc_match.group('proc').strip()}] {rfc_match.group('msg')}"
            return self._event(
                evidence_item_id, "iot_log_line", desc,
                metadata={
                    "file": str(path.relative_to(root)),
                    "host": rfc_match.group("host"),
                    "year_assumed": True,
                },
                timestamp=dt.isoformat(),
            )

        return None

    def _event(self, evidence_item_id, event_type, description, metadata=None, timestamp=None) -> Event:
        return Event(
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
