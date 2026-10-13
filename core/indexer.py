"""Indexação de texto completo sobre os arquivos extraídos de um caso —
inspirado no estágio de indexação/processamento de ferramentas como o IPED
(github.com/sepinf-inc/IPED): depois que os módulos de análise extraem
arquivos para `case.extracted_dir`, esta etapa constrói um índice de busca
(SQLite + FTS5, já embutido no Python — sem dependência nova), categoriza
por tipo e deduplica por hash SHA-256.

Escopo desta versão (bem mais modesto que o IPED, que tem motor de carving,
OCR, reconhecimento facial etc.): indexa nome/caminho de todo arquivo
extraído; indexa também o conteúdo textual de arquivos de texto puro (txt,
json, xml, csv, html, log) e de bancos SQLite (despeja as linhas das
tabelas como texto pesquisável). Arquivos binários sem extrator de texto
conhecido (imagens, vídeos, PDFs) ficam pesquisáveis só pelo nome — ver
docs/roadmap.md para OCR/extração de PDF/mídia.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

TEXT_EXTENSIONS = {".txt", ".json", ".xml", ".csv", ".html", ".htm", ".log", ".md", ".plist"}
DB_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}

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


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_index(extracted_dir: Path, index_path: Path) -> dict:
    """Indexa tudo em `extracted_dir` em um banco SQLite+FTS5 em `index_path`.
    Retorna estatísticas: {files, indexed_text, duplicates, categories: {...}}."""
    if index_path.exists():
        index_path.unlink()

    conn = sqlite3.connect(index_path)
    conn.execute(
        "CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT, evidence_item_id TEXT, "
        "category TEXT, sha256 TEXT, size INTEGER, is_duplicate INTEGER)"
    )
    conn.execute("CREATE VIRTUAL TABLE files_fts USING fts5(path, content)")
    conn.execute("CREATE INDEX idx_files_sha256 ON files(sha256)")
    conn.execute("CREATE INDEX idx_files_category ON files(category)")

    seen_hashes: set[str] = set()
    stats = {"files": 0, "indexed_text": 0, "duplicates": 0, "categories": {}}

    if extracted_dir.exists():
        for path in sorted(extracted_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(extracted_dir)
            evidence_item_id = rel.parts[0] if rel.parts else ""
            digest = sha256_of(path)
            is_duplicate = digest in seen_hashes
            seen_hashes.add(digest)
            category = _category(path)
            size = path.stat().st_size

            stats["files"] += 1
            stats["categories"][category] = stats["categories"].get(category, 0) + 1
            if is_duplicate:
                stats["duplicates"] += 1

            cursor = conn.execute(
                "INSERT INTO files (path, evidence_item_id, category, sha256, size, is_duplicate) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(rel), evidence_item_id, category, digest, size, int(is_duplicate)),
            )
            row_id = cursor.lastrowid

            text = None if is_duplicate else _extract_text(path)
            if text:
                stats["indexed_text"] += 1
            conn.execute(
                "INSERT INTO files_fts (rowid, path, content) VALUES (?, ?, ?)",
                (row_id, str(rel), text or ""),
            )

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
