"""Aquisição iOS via libimobiledevice (ferramentas open source — mesmo
protocolo que o iTunes/Finder usa para parear e sincronizar). Pressupõe um
iPhone/iPad já pareado ("Confiar neste computador?" já aceito no aparelho)
— não contorna Face ID/Touch ID/senha nem explora vulnerabilidade.

Sobre criptografar o backup com uma senha escolhida pelo examinador: isso
não é um bypass da senha do aparelho — é só escolher, dentre as opções
normais de backup que a Apple oferece, a criptografada, porque só backups
criptografados incluem o chaveiro (Wi-Fi salvas, tokens de apps etc.). A
senha do backup é independente da senha/Face ID do aparelho.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REQUIRED_TOOLS = ["idevice_id", "ideviceinfo", "idevicebackup2", "idevicescreenshot"]


class LibimobiledeviceError(Exception):
    pass


def is_available() -> bool:
    return all(shutil.which(tool) is not None for tool in REQUIRED_TOOLS)


def missing_tools() -> list[str]:
    return [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]


def _run(tool: str, args: list[str], timeout: int = 120) -> str:
    if shutil.which(tool) is None:
        raise LibimobiledeviceError(f"'{tool}' não encontrado no PATH — instale libimobiledevice.")
    try:
        result = subprocess.run([tool, *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LibimobiledeviceError(f"Comando '{tool}' expirou (timeout={timeout}s).") from exc
    if result.returncode != 0:
        raise LibimobiledeviceError(f"{tool} {' '.join(args)} falhou: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def list_devices() -> list[str]:
    output = _run("idevice_id", ["-l"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def device_info(udid: str | None = None) -> dict:
    args = (["-u", udid] if udid else [])
    output = _run("ideviceinfo", args)
    info = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def take_screenshot(output_path: Path, udid: str | None = None) -> Path:
    args = (["-u", udid] if udid else []) + [str(output_path)]
    _run("idevicescreenshot", args)
    return output_path


def set_backup_password(password: str, udid: str | None = None) -> None:
    """Liga a criptografia do backup com uma senha que o EXAMINADOR
    escolhe agora (não é a senha do aparelho) — necessário para que o
    próximo backup inclua o chaveiro (Wi-Fi, tokens etc.)."""
    args = (["-u", udid] if udid else []) + ["encryption", "on", password]
    _run("idevicebackup2", args, timeout=60)


def full_backup(output_dir: Path, udid: str | None = None, timeout: int = 3600) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    args = (["-u", udid] if udid else []) + ["backup", str(output_dir)]
    _run("idevicebackup2", args, timeout=timeout)
    return output_dir
