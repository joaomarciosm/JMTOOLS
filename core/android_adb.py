"""Aquisição Android via ADB (Android Debug Bridge, ferramenta oficial do
Android SDK) — tudo aqui pressupõe um aparelho **já conectado e com a
depuração USB já autorizada pelo proprietário/examinador** (a mesma tela
"Permitir depuração USB?" que qualquer um vê ao plugar o cabo). Nada aqui
contorna bloqueio de tela nem explora vulnerabilidade — é automação do
mesmo `adb` que qualquer desenvolvedor Android usa.

Inclui a técnica de "downgrade de APK": reinstalar uma versão mais antiga
e legitimamente assinada do mesmo app (fornecida pelo examinador, nunca
baixada por este módulo) para reativar a flag `android:allowBackup` que
versões mais novas de certos apps desligaram — prática documentada na
comunidade de perícia móvel, usando só a API padrão do Android
(`pm install -r -d`), sem explorar nada.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class AdbError(Exception):
    pass


def is_available() -> bool:
    return shutil.which("adb") is not None


def _run(args: list[str], timeout: int = 120) -> str:
    if not is_available():
        raise AdbError("adb não encontrado no PATH — instale o Android SDK Platform Tools.")
    try:
        result = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise AdbError(f"Comando adb expirou (timeout={timeout}s): {' '.join(args)}") from exc
    if result.returncode != 0:
        raise AdbError(f"adb {' '.join(args)} falhou: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def list_devices() -> list[dict]:
    """Retorna [{"serial": ..., "state": ...}, ...] dos aparelhos conectados."""
    output = _run(["devices", "-l"])
    devices = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1]})
    return devices


def device_info(serial: str | None = None) -> dict:
    props_to_read = {
        "model": "ro.product.model",
        "manufacturer": "ro.product.manufacturer",
        "android_version": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "serial_no": "ro.serialno",
        "build_fingerprint": "ro.build.fingerprint",
    }
    info = {}
    for key, prop in props_to_read.items():
        args = (["-s", serial] if serial else []) + ["shell", "getprop", prop]
        try:
            info[key] = _run(args).strip()
        except AdbError:
            info[key] = None
    return info


def full_backup(output_path: Path, serial: str | None = None, timeout: int = 1800) -> Path:
    """`adb backup` completo (apk + obb + dados compartilhados + todos os
    apps que permitirem). Gera um .ab — use modules/mobile/android_backup.py
    para analisar o resultado depois. Pode levar bastante tempo; o próprio
    aparelho pede confirmação na tela (e opcionalmente uma senha de
    backup) antes de começar — nada roda sem essa confirmação do dono."""
    args = (["-s", serial] if serial else []) + [
        "backup", "-apk", "-shared", "-all", "-f", str(output_path),
    ]
    _run(args, timeout=timeout)
    return output_path


def pull_path(device_path: str, local_dest: Path, serial: str | None = None, timeout: int = 1800) -> None:
    args = (["-s", serial] if serial else []) + ["pull", "-a", device_path, str(local_dest)]
    _run(args, timeout=timeout)


def find_paths_by_extension(extension: str, serial: str | None = None, base: str = "/sdcard/") -> list[str]:
    ext = extension.lstrip(".")
    args = (["-s", serial] if serial else []) + ["shell", "find", base, "-iname", f"*.{ext}"]
    output = _run(args, timeout=300)
    return [line.strip() for line in output.splitlines() if line.strip()]


def find_trash_paths(serial: str | None = None, base: str = "/sdcard/") -> list[str]:
    """Pastas de "lixeira" de apps (ex: WhatsApp/.Trash) — não indexadas
    pelo explorador de arquivos normal, mas não é recuperação de deletados
    de baixo nível: são pastas que o próprio app mantém."""
    args = (["-s", serial] if serial else []) + ["shell", "find", base, "-iname", "*.trash*"]
    output = _run(args, timeout=300)
    return [line.strip() for line in output.splitlines() if line.strip()]


def dumpsys_services(serial: str | None = None) -> list[str]:
    args = (["-s", serial] if serial else []) + ["shell", "dumpsys", "-l"]
    output = _run(args)
    return [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("Currently")]


def dumpsys(service: str, extra_args: str = "", serial: str | None = None) -> str:
    args = (["-s", serial] if serial else []) + ["shell", "dumpsys", service] + (extra_args.split() if extra_args else [])
    return _run(args)


def downgrade_and_backup(
    package: str,
    older_apk_path: Path,
    output_backup_path: Path,
    serial: str | None = None,
) -> Path:
    """Reinstala uma versão mais antiga (fornecida pelo examinador) do
    app por cima da atual mantendo os dados, depois tira um `adb backup`
    só daquele app. Requer que `older_apk_path` seja uma build legítima
    e mais antiga do mesmo app (assinada pela mesma chave do
    desenvolvedor) — este módulo não baixa nem distribui APKs."""
    if not older_apk_path.exists():
        raise AdbError(f"APK não encontrado: {older_apk_path}")

    base_args = ["-s", serial] if serial else []
    _run(base_args + ["shell", "cmd", "package", "uninstall", "-k", package])
    _run(base_args + ["install", "-r", "-d", str(older_apk_path)], timeout=300)
    _run(base_args + ["backup", "-f", str(output_backup_path), package], timeout=1800)
    return output_backup_path
