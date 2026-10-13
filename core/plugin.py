"""Interface base de módulos (plugins) de análise forense.

Cada domínio (disk, mobile, dvr, iot, vehicle, web) implementa um ou mais
AnalysisModule. O core nunca assume nada sobre como um módulo lê a
evidência — ele só orquestra: detecta compatibilidade, chama analyze(),
agrega os eventos resultantes na timeline do caso.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from core.timeline import Event


@dataclass
class AnalysisContext:
    """Parâmetros de uma rodada de análise — agrupados num objeto só para
    não precisar mexer na assinatura de analyze() a cada funcionalidade
    nova (já aconteceu demais vezes antes deste refactor)."""

    #: senha/chave que o examinador já conhece legalmente (ex: senha de
    #: backup definida pelo dono do aparelho) — usada só para decodificar
    #: dados já adquiridos, nunca para descobrir/quebrar uma credencial
    #: desconhecida. Nunca é persistida no caso nem no laudo.
    credential: str | None = None

    #: pasta onde o módulo pode salvar (via core.extraction.save_extracted_file)
    #: os arquivos que já extraiu, para indexação posterior por
    #: Case.run_processing(). Opcional — um módulo sem bytes de arquivo
    #: prontos (ex: só metadados de partição) ignora o campo.
    extracted_dir: Path | None = None

    #: tamanho máximo (bytes) de um arquivo individual que um módulo deve
    #: copiar para extracted_dir — configurável pelo operador (core/config.py)
    #: para não estourar disco/tempo em evidências muito grandes.
    max_extract_size: int = 50 * 1024 * 1024

    #: termos de destaque definidos pelo operador (core/config.py) — módulos
    #: podem usar para marcar eventos como "relevante" na própria análise,
    #: embora o destaque principal aconteça no processamento (core/indexer.py).
    keywords: list[str] = field(default_factory=list)


class AnalysisModule(ABC):
    """Módulo de análise: lê uma evidência já adquirida e produz eventos."""

    #: identificador curto, ex: "mobile.android_backup"
    name: str = "base"

    @abstractmethod
    def supports(self, evidence_path: Path) -> bool:
        """Retorna True se este módulo sabe processar o item de evidência."""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, evidence_path: Path, evidence_item_id: str, context: AnalysisContext) -> list[Event]:
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


def build_default_registry(disabled_modules: set[str] | None = None) -> ModuleRegistry:
    """Carrega todos os módulos built-in disponíveis, exceto os listados em
    `disabled_modules` (configurável pelo operador — ver core/config.py)."""
    disabled_modules = disabled_modules or set()
    registry = ModuleRegistry()

    from modules.disk.carving import CarvingModule
    from modules.disk.filesystem import DiskImageModule
    from modules.dvr.recordings import DVRRecordingsModule
    from modules.iot.logs import IoTLogModule
    from modules.mobile.android_backup import AndroidBackupModule
    from modules.mobile.ios_backup import IOSBackupModule
    from modules.mobile.whatsapp import WhatsAppModule
    from modules.vehicle.can_log import CANLogModule
    from modules.web.browser_history import BrowserHistoryModule

    all_modules = [
        AndroidBackupModule(),
        IOSBackupModule(),
        WhatsAppModule(),
        DiskImageModule(),
        DVRRecordingsModule(),
        IoTLogModule(),
        CANLogModule(),
        BrowserHistoryModule(),
        CarvingModule(),
    ]
    for module in all_modules:
        if module.name not in disabled_modules:
            registry.register(module)

    return registry
