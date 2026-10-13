"""Análise de logs de barramento CAN já capturados (formato `candump -L` do
SocketCAN, padrão amplamente usado por ferramentas Linux de diagnóstico).

Este módulo NÃO se conecta a nenhum veículo nem envia quadros — ele lê um
arquivo de log que o examinador já capturou via porta OBD-II (interface de
diagnóstico padrão do veículo, conexão cooperativa) usando uma ferramenta
como `candump` ou um adaptador ELM327/SocketCAN.

Formato de linha:
    (1700000000.123456) can0 7E8#4105B2

Quando a resposta corresponde ao Serviço 01 (Show Current Data) da norma
SAE J1979/ISO 15031-5 — pública —, decodifica os PIDs padrão mais comuns
(RPM do motor, velocidade, temperatura do motor, nível de combustível).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from core.plugin import AnalysisModule
from core.timeline import Event

LINE_RE = re.compile(r"^\((?P<ts>\d+\.\d+)\)\s+(?P<iface>\S+)\s+(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)$")

# SAE J1979 — decodificadores de PID padrão (Serviço 01, resposta 0x41)
def _pid_rpm(data: bytes) -> tuple[str, float]:
    return "Engine RPM", ((data[0] * 256) + data[1]) / 4


def _pid_speed(data: bytes) -> tuple[str, float]:
    return "Vehicle speed (km/h)", float(data[0])


def _pid_coolant_temp(data: bytes) -> tuple[str, float]:
    return "Engine coolant temp (C)", float(data[0] - 40)


def _pid_fuel_level(data: bytes) -> tuple[str, float]:
    return "Fuel level (%)", data[0] * 100 / 255


STANDARD_PIDS = {
    0x05: (_pid_coolant_temp, 1),
    0x0C: (_pid_rpm, 2),
    0x0D: (_pid_speed, 1),
    0x2F: (_pid_fuel_level, 1),
}


class CANLogModule(AnalysisModule):
    name = "vehicle.can_log"

    def supports(self, evidence_path: Path) -> bool:
        if not evidence_path.is_file():
            return False
        try:
            with open(evidence_path, "r", encoding="ascii", errors="ignore") as f:
                first_line = f.readline().strip()
        except OSError:
            return False
        return bool(LINE_RE.match(first_line))

    def analyze(self, evidence_path: Path, evidence_item_id: str, credential: str | None = None) -> list[Event]:
        events: list[Event] = []
        with open(evidence_path, "r", encoding="ascii", errors="ignore") as f:
            for line in f:
                match = LINE_RE.match(line.strip())
                if not match:
                    continue

                timestamp = datetime.fromtimestamp(float(match.group("ts")), tz=timezone.utc).isoformat()
                can_id = int(match.group("id"), 16)
                data = bytes.fromhex(match.group("data")) if match.group("data") else b""

                events.append(
                    self._event(
                        evidence_item_id,
                        "can_frame",
                        f"Quadro CAN id=0x{can_id:X} dados={data.hex().upper()}",
                        metadata={"can_id": can_id, "interface": match.group("iface"), "data_hex": data.hex()},
                        timestamp=timestamp,
                    )
                )

                obd_event = self._decode_obd_response(data, evidence_item_id, timestamp, can_id)
                if obd_event:
                    events.append(obd_event)

        return events

    def _decode_obd_response(self, data: bytes, evidence_item_id: str, timestamp: str, can_id: int) -> Event | None:
        # Resposta ECU ao Serviço 01: byte0=tamanho ISO-TP, byte1=0x41, byte2=PID, resto=valor
        if len(data) < 3 or data[1] != 0x41:
            return None
        pid = data[2]
        decoder_entry = STANDARD_PIDS.get(pid)
        if not decoder_entry:
            return None
        decoder, nbytes = decoder_entry
        value_bytes = data[3:3 + nbytes]
        if len(value_bytes) < nbytes:
            return None
        label, value = decoder(value_bytes)
        return self._event(
            evidence_item_id,
            "obd_pid",
            f"{label} = {value}",
            metadata={"pid": hex(pid), "value": value, "can_id": can_id},
            timestamp=timestamp,
        )

    def _event(self, evidence_item_id, event_type, description, metadata=None, timestamp=None) -> Event:
        return Event(
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
