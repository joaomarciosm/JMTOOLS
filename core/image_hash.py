"""Hash perceptual simples (average hash) para agrupar imagens semelhantes
— inspirado no agrupamento por similaridade do IPED, mas bem mais modesto
(um "average hash" de 64 bits, não um fuzzy hash de arquivo genérico tipo
ssdeep). Serve para achar fotos quase idênticas (recompressão, recorte
leve, marca d'água) — não para arquivos binários em geral.
"""
from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def average_hash(path: Path, hash_size: int = 8) -> int | None:
    if not PIL_AVAILABLE:
        return None
    try:
        with Image.open(path) as img:
            img = img.convert("L").resize((hash_size, hash_size), Image.LANCZOS)
            pixels = list(img.getdata())
    except Exception:  # noqa: BLE001 — qualquer imagem corrompida/formato não suportado só fica sem hash
        return None

    avg = sum(pixels) / len(pixels)
    bits = 0
    for pixel in pixels:
        bits = (bits << 1) | (1 if pixel >= avg else 0)
    return bits


def hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def cluster_images(hashes: dict[str, int], threshold: int) -> dict[str, int]:
    """Agrupamento guloso: retorna {path: cluster_id} — imagens cujo hash
    perceptual difira em até `threshold` bits do representante do cluster
    entram no mesmo grupo. Simples e O(n²), adequado para o volume de
    imagens de um caso de perícia de dispositivo (não de um datacenter)."""
    cluster_of: dict[str, int] = {}
    representatives: list[tuple[str, int]] = []  # (path, hash) do 1º item de cada cluster

    for path, h in hashes.items():
        matched_cluster = None
        for rep_path, rep_hash in representatives:
            if hamming_distance(h, rep_hash) <= threshold:
                matched_cluster = cluster_of[rep_path]
                break
        if matched_cluster is None:
            matched_cluster = len(representatives)
            representatives.append((path, h))
        cluster_of[path] = matched_cluster

    return cluster_of
