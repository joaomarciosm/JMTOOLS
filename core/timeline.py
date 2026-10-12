"""Modelo de evento unificado para a timeline forense."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    timestamp: str  # ISO-8601 UTC
    source_module: str  # ex: "mobile.android_backup"
    event_type: str  # ex: "sms_received", "file_created", "trip_start"
    description: str
    evidence_item_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_module": self.source_module,
            "event_type": self.event_type,
            "description": self.description,
            "evidence_item_id": self.evidence_item_id,
            "metadata": self.metadata,
        }


class Timeline:
    def __init__(self) -> None:
        self._events: list[Event] = []

    def add(self, event: Event) -> None:
        self._events.append(event)

    def extend(self, events: list[Event]) -> None:
        self._events.extend(events)

    def sorted_events(self) -> list[Event]:
        return sorted(self._events, key=lambda e: e.timestamp)

    def filter(self, event_type: str | None = None, source_module: str | None = None) -> list[Event]:
        result = self._events
        if event_type:
            result = [e for e in result if e.event_type == event_type]
        if source_module:
            result = [e for e in result if e.source_module == source_module]
        return sorted(result, key=lambda e: e.timestamp)

    def to_dict(self) -> list[dict]:
        return [e.to_dict() for e in self.sorted_events()]

    def __len__(self) -> int:
        return len(self._events)
