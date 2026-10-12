"""Interface base de módulos (plugins) de análise forense.

Cada domínio (disk, mobile, dvr, iot, vehicle) implementa um ou mais
AnalysisModule. O core nunca assume nada sobre como um módulo lê a
evidência — ele só orquestra: detecta compatibilidade, chama analyze(),
agrega os eventos resultantes na timeline do caso.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from core.timeline import Event


class AnalysisModule(ABC):
    """Módulo de análise: lê uma evidência já adquirida e produz eventos."""

    #: identificador curto, ex: "mobile.android_backup"
    name: str = "base"

    @abstractmethod
    def supports(self, evidence_path: Path) -> bool:
        """Retorna True se este módulo sabe processar o item de evidência."""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, evidence_path: Path, evidence_item_id: str) -> list[Event]:
        """Processa a evidência e retorna uma lista de eventos de timeline."""
        raise NotImplementedError


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: list[AnalysisModule] = []

    def register(self, module: AnalysisModule) -> None:
        self._modules.append(module)

    def find_supporting(self, evidence_path: Path) -> list[AnalysisModule]:
        return [m for m in self._modules if m.supports(evidence_path)]

    def all(self) -> list[AnalysisModule]:
        return list(self._modules)


def build_default_registry() -> ModuleRegistry:
    """Carrega todos os módulos built-in disponíveis."""
    registry = ModuleRegistry()

    from modules.mobile.android_backup import AndroidBackupModule
    from modules.disk.filesystem import DiskImageModule

    registry.register(AndroidBackupModule())
    registry.register(DiskImageModule())

    return registry
