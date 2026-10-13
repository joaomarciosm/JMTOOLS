"""Gancho opcional de OCR via Tesseract — inspirado no OCR do IPED, mas
sem empacotar o motor: chama o binário `tesseract` do sistema diretamente
(sem depender do pacote pytesseract, que é só um wrapper fino em cima do
mesmo binário). Se o Tesseract não estiver instalado, is_available()
retorna False e o chamador deve reportar isso claramente — nunca falha
silenciosamente nem tenta baixar/instalar nada sozinho.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def is_available() -> bool:
    return shutil.which("tesseract") is not None


def extract_text(image_path: Path, lang: str = "por+eng", timeout: int = 60) -> str | None:
    if not is_available():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        out_base = Path(tmp) / "out"
        try:
            subprocess.run(
                ["tesseract", str(image_path), str(out_base), "-l", lang],
                capture_output=True, timeout=timeout, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return None
        out_file = out_base.with_suffix(".txt")
        if not out_file.exists():
            return None
        return out_file.read_text(encoding="utf-8", errors="replace")
