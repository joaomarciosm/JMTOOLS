"""Armazenamento local de arquivos já extraídos durante a análise, para
indexação posterior (core/indexer.py) — inspirado no estágio de
"processamento" de ferramentas como o IPED, onde cada módulo de análise
despeja os arquivos que já tem em mãos para serem indexados depois, sem
precisar saber nada sobre indexação."""
from __future__ import annotations

import re
from pathlib import Path

_UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def safe_relative_path(evidence_item_id: str, relative_path: str) -> Path:
    """Sanitiza um caminho relativo vindo de dentro de um container (tar,
    backup etc.) para evitar path traversal e caracteres inválidos no
    sistema de arquivos local."""
    parts = [p for p in relative_path.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    safe_parts = [_UNSAFE_CHARS.sub("_", p) for p in parts] or ["_"]
    return Path(evidence_item_id, *safe_parts)


def save_extracted_file(extracted_dir: Path, evidence_item_id: str, relative_path: str, data: bytes) -> Path:
    dest = extracted_dir / safe_relative_path(evidence_item_id, relative_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest
