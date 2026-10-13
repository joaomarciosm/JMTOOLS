"""Configuração do caso, ajustável pelo operador (perito/examinador).

Cada caso tem seu próprio `config.json` (criado com valores padrão ao
criar o caso). O operador pode editar esse arquivo diretamente ou pela
GUI antes de rodar a análise/processamento.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_PII_PATTERNS = ["credit_card", "cpf", "cnpj", "email", "url", "btc_address", "eth_address", "phone_br"]


@dataclass
class Config:
    #: módulos de análise desabilitados por nome (ex: "disk.carving", que é
    #: lento e ruidoso o suficiente para ficar desligado por padrão).
    disabled_modules: list[str] = field(default_factory=lambda: ["disk.carving"])

    #: tamanho máximo (MB) de um arquivo individual extraído para indexação.
    max_extract_size_mb: int = 50

    #: termos de destaque — ficam marcados como relevantes no processamento.
    keywords: list[str] = field(default_factory=list)

    #: busca por padrões sensíveis (cartão de crédito, CPF/CNPJ, e-mail,
    #: URL, carteiras de criptomoeda, telefone) durante o processamento.
    pii_scan_enabled: bool = True
    pii_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_PII_PATTERNS))

    #: caminho para um arquivo texto com um hash SHA-256 por linha
    #: (minúsculo) de arquivos conhecidos/irrelevantes (estilo NSRL) —
    #: arquivos cujo hash bater ficam marcados, não removidos.
    known_hash_ignore_file: str | None = None

    #: agrupamento de imagens semelhantes por hash perceptual durante o
    #: processamento (ver core/image_hash.py).
    image_clustering_enabled: bool = True
    image_clustering_hamming_threshold: int = 8

    #: OCR em imagens via Tesseract, se o binário estiver instalado no
    #: PATH do sistema — ver core/ocr.py. Desligado por padrão porque
    #: exige uma instalação externa que pode não existir na máquina.
    ocr_enabled: bool = False

    @classmethod
    def load(cls, path: Path) -> "Config":
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls()
        defaults = asdict(cls())
        defaults.update({k: v for k, v in data.items() if k in defaults})
        return cls(**defaults)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")

    @property
    def max_extract_size_bytes(self) -> int:
        return self.max_extract_size_mb * 1024 * 1024
