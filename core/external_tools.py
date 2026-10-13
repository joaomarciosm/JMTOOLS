"""Integração com ferramentas externas já instaladas pelo examinador —
hoje só o IPED de verdade (github.com/sepinf-inc/IPED). JM Tools tem seu
próprio processamento/indexação inspirado no IPED (core/indexer.py), mas
se o examinador já tem o IPED instalado e quer rodar a indexação completa
dele (OCR avançado, carving de 40+ formatos, etc.) sobre o que foi
extraído, este módulo só chama o `iped.exe` dele — nenhuma lógica do IPED
é reimplementada ou copiada aqui.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class ExternalToolError(Exception):
    pass


def run_iped(iped_exe_path: Path, source_dir: Path, output_dir: Path, timeout: int = 7200) -> str:
    if not iped_exe_path.exists():
        raise ExternalToolError(f"iped.exe não encontrado em: {iped_exe_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [str(iped_exe_path), "-d", str(source_dir), "-o", str(output_dir)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolError(f"IPED expirou (timeout={timeout}s).") from exc
    if result.returncode != 0:
        raise ExternalToolError(f"IPED retornou erro: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout
