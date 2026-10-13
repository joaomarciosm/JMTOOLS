"""Indexação de texto completo sobre os arquivos extraídos de um caso —
inspirado no estágio de indexação/processamento de ferramentas como o IPED
(github.com/sepinf-inc/IPED): depois que os módulos de análise extraem
arquivos para `case.extracted_dir`, esta etapa constrói um índice de busca
(SQLite + FTS5, já embutido no Python — sem dependência nova), categoriza
por tipo, deduplica por hash SHA-256, marca arquivos de uma lista de hash
conhecido (estilo NSRL), busca padrões sensíveis (PII) no texto indexado,
agrupa imagens semelhantes por hash perceptual e, se configurado e o
Tesseract estiver instalado, roda OCR em imagens.

Escopo (bem mais modesto que o IPED, que tem motor de carving avançado,
reconhecimento facial etc.): indexa nome/caminho de todo arquivo extraído;
indexa também o conteúdo textual de arquivos de texto puro (txt, json,
xml, csv, html, log) e de bancos SQLite (despeja as linhas das tabelas
como texto pesquisável) — e, com OCR ligado, de imagens.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from core import ocr
from core.image_hash import PIL_AVAILABLE, average_hash, cluster_images
from core.pii_scan import scan_text as scan_pii

TEXT_EXTENSIONS = {".txt", ".json", ".xml", ".csv", ".html", ".htm", ".log", ".md", ".plist"}
DB_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}

MAX_TEXT_CHARS = 2_000_000  # evita indexar um banco gigante inteiro como um blob só

CATEGORY_BY_EXTENSION = {
    ".jpg": "imagem", ".jpeg": "imagem", ".png": "imagem", ".gif": "imagem",
    ".bmp": "imagem", ".webp": "imagem", ".heic": "imagem",
    ".mp4": "video", ".avi": "video", ".mov": "video", ".mkv": "video",
    ".264": "video", ".h264": "video", ".265": "video", ".dav": "video",
    ".mp3": "audio", ".wav": "audio", ".m4a": "audio", ".ogg": "audio", ".opus": "audio",
    ".db": "banco_de_dados", ".sqlite": "banco_de_dados", ".sqlite3": "banco_de_dados",
    ".txt": "texto", ".log": "texto", ".md": "texto",
    ".json": "dados_estruturados", ".xml": "dados_estruturados", ".plist": "dados_estruturados",
    ".csv": "dados_estruturados", ".html": "dados_estruturados", ".htm": "dados_estruturados",
    ".pdf": "documento", ".doc": "documento", ".docx": "documento", ".xls": "documento", ".xlsx": "documento",
    ".apk": "aplicativo", ".exe": "executavel", ".dll": "executavel",
}


def _category(path: Path) -> str:
    return CATEGORY_BY_EXTENSION.get(path.suffix.lower(), "outro")


def _extract_text(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT_CHARS]
        except OSError:
            return None
    if suffix in DB_EXTENSIONS:
        return _extract_sqlite_text(path)
    return None


def _extract_sqlite_text(path: Path) -> str | None:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None

    chunks: list[str] = []
    total_len = 0
    try:
        cursor = conn.cursor()
        tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            try:
                for row in cursor.execute(f"SELECT * FROM {table} LIMIT 10000"):
                    line = " ".join(str(v) for v in row if v is not None)
                    chunks.append(line)
                    total_len += len(line)
                    if total_len > MAX_TEXT_CHARS:
                        return "\n".join(chunks)[:MAX_TEXT_CHARS]
            except sqlite3.Error:
                continue
    finally:
        conn.close()
    return "\n".join(chunks) if chunks else None


def load_known_hashes(path: str | Path | None) -> set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        return set()
    return {line.strip().lower() for line in p.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_index(
    extracted_dir: Path,
    index_path: Path,
    *,
    known_hashes: set[str] | None = None,
    pii_enabled: bool = True,
    pii_patterns: list[str] | None = None,
    image_clustering_enabled: bool = True,
    image_clustering_threshold: int = 8,
    ocr_enabled: bool = False,
) -> dict:
    """Indexa tudo em `extracted_dir` em um banco SQLite+FTS5 em `index_path`.
    Retorna estatísticas: {files, indexed_text, duplicates, known_ignored,
    pii_hits, image_clusters, ocr_processed, categories: {...}}."""
    known_hashes = known_hashes or set()
    pii_patterns = pii_patterns or []

    if index_path.exists():
        index_path.unlink()

    conn = sqlite3.connect(index_path)
    conn.execute(
        "CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT, evidence_item_id TEXT, "
        "category TEXT, sha256 TEXT, size INTEGER, is_duplicate INTEGER, is_known_ignore INTEGER, "
        "img_cluster INTEGER)"
    )
    conn.execute("CREATE VIRTUAL TABLE files_fts USING fts5(path, content)")
    conn.execute("CREATE TABLE pii_hits (file_id INTEGER, type TEXT, value TEXT)")
    conn.execute("CREATE INDEX idx_files_sha256 ON files(sha256)")
    conn.execute("CREATE INDEX idx_files_category ON files(category)")

    seen_hashes: set[str] = set()
    stats = {
        "files": 0, "indexed_text": 0, "duplicates": 0, "known_ignored": 0,
        "pii_hits": 0, "image_clusters": 0, "ocr_processed": 0, "categories": {},
    }

    image_hashes: dict[str, int] = {}
    image_file_ids: dict[str, int] = {}

    if extracted_dir.exists():
        for path in sorted(extracted_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(extracted_dir)
            evidence_item_id = rel.parts[0] if rel.parts else ""
            digest = sha256_of(path)
            is_duplicate = digest in seen_hashes
            seen_hashes.add(digest)
            is_known_ignore = digest in known_hashes
            category = _category(path)
            size = path.stat().st_size

            stats["files"] += 1
            stats["categories"][category] = stats["categories"].get(category, 0) + 1
            if is_duplicate:
                stats["duplicates"] += 1
            if is_known_ignore:
                stats["known_ignored"] += 1

            cursor = conn.execute(
                "INSERT INTO files (path, evidence_item_id, category, sha256, size, is_duplicate, "
                "is_known_ignore, img_cluster) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                (str(rel), evidence_item_id, category, digest, size, int(is_duplicate), int(is_known_ignore)),
            )
            row_id = cursor.lastrowid

            text = None
            if not is_duplicate and not is_known_ignore:
                text = _extract_text(path)
                if text is None and category == "imagem" and ocr_enabled:
                    text = ocr.extract_text(path)
                    if text:
                        stats["ocr_processed"] += 1

            if text:
                stats["indexed_text"] += 1
                if pii_enabled:
                    hits = scan_pii(text, pii_patterns)
                    for hit in hits:
                        conn.execute(
                            "INSERT INTO pii_hits (file_id, type, value) VALUES (?, ?, ?)",
                            (row_id, hit["type"], hit["value"]),
                        )
                    stats["pii_hits"] += len(hits)

            conn.execute(
                "INSERT INTO files_fts (rowid, path, content) VALUES (?, ?, ?)",
                (row_id, str(rel), text or ""),
            )

            if category == "imagem" and image_clustering_enabled and PIL_AVAILABLE and not is_duplicate:
                h = average_hash(path)
                if h is not None:
                    image_hashes[str(rel)] = h
                    image_file_ids[str(rel)] = row_id

    if image_hashes:
        clusters = cluster_images(image_hashes, image_clustering_threshold)
        for rel_str, cluster_id in clusters.items():
            conn.execute("UPDATE files SET img_cluster = ? WHERE id = ?", (cluster_id, image_file_ids[rel_str]))
        stats["image_clusters"] = len(set(clusters.values()))

    conn.commit()
    conn.close()
    return stats


def search(index_path: Path, query: str, limit: int = 100) -> list[dict]:
    if not index_path.exists() or not query.strip():
        return []
    conn = sqlite3.connect(index_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT f.path, f.evidence_item_id, f.category, f.sha256, f.size, f.is_duplicate, "
            "f.is_known_ignore, f.img_cluster, "
            "snippet(files_fts, 1, '[', ']', '...', 10) AS snippet "
            "FROM files_fts JOIN files f ON f.id = files_fts.rowid "
            "WHERE files_fts MATCH ? ORDER BY rank LIMIT ?",
            (query, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def pii_report(index_path: Path) -> list[dict]:
    if not index_path.exists():
        return []
    conn = sqlite3.connect(index_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT p.type, p.value, f.path, f.evidence_item_id "
            "FROM pii_hits p JOIN files f ON f.id = p.file_id ORDER BY p.type"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def image_clusters_report(index_path: Path) -> dict[int, list[dict]]:
    if not index_path.exists():
        return {}
    conn = sqlite3.connect(index_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT path, evidence_item_id, img_cluster FROM files "
            "WHERE img_cluster IS NOT NULL ORDER BY img_cluster"
        ).fetchall()
    finally:
        conn.close()

    clusters: dict[int, list[dict]] = {}
    for r in rows:
        clusters.setdefault(r["img_cluster"], []).append(dict(r))
    return {cid: items for cid, items in clusters.items() if len(items) > 1}
