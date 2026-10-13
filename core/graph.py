"""Grafo de comunicação — quem falou com quem, a partir dos eventos já
extraídos (SMS, chamadas, mensagens de WhatsApp). Inspirado na análise de
grafo de comunicações do IPED, numa versão bem mais simples: contagem de
frequência por contato + layout circular para desenho em Canvas (GUI).
"""
from __future__ import annotations

import math

from core.timeline import Timeline

COMMUNICATION_EVENT_TYPES = {"sms", "call", "whatsapp_message", "browser_history"}

CONTACT_METADATA_KEYS = ("address", "number", "key_remote_jid", "remote_jid")


def _contact_of(metadata: dict) -> str | None:
    for key in CONTACT_METADATA_KEYS:
        value = metadata.get(key)
        if value:
            return str(value)
    return None


def build_contact_counts(timeline: Timeline) -> dict[str, int]:
    """Retorna {contato: numero_de_interacoes}, ordenado por frequência
    (maior primeiro) ao converter para lista."""
    counts: dict[str, int] = {}
    for event in timeline.sorted_events():
        if event.event_type not in COMMUNICATION_EVENT_TYPES:
            continue
        contact = _contact_of(event.metadata)
        if not contact:
            continue
        counts[contact] = counts.get(contact, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def circular_layout(contacts: list[str], center=(0, 0), radius: float = 200) -> dict[str, tuple[float, float]]:
    """Posições (x, y) para desenhar os nós em círculo ao redor do centro
    (que representa o dono do dispositivo/caso)."""
    positions = {"__center__": center}
    n = max(len(contacts), 1)
    for i, contact in enumerate(contacts):
        angle = 2 * math.pi * i / n
        x = center[0] + radius * math.cos(angle)
        y = center[1] + radius * math.sin(angle)
        positions[contact] = (x, y)
    return positions
