"""Varre uma pasta de armazenamento de DVR/NVR já extraída (cartão SD, HD
retirado do aparelho e montado, ou pasta copiada via rede) procurando
arquivos de vídeo e metadados.

A maioria dos DVRs domésticos grava em contêineres proprietários (H.264 raw,
.dav da Dahua, .264 da Hikvision, etc.) cujo layout não é público e varia por
fabricante/firmware — para esses, este módulo registra o arquivo (nome,
tamanho, timestamps do sistema de arquivos) sem decodificar o conteúdo.

Para contêineres **padrão** (MP4/MOV, formato ISO/IEC 14496-12, público),
lê a caixa `mvhd` para extrair duração e horário de criação embutido.
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.plugin import AnalysisModule
from core.timeline import Event

KNOWN_VIDEO_EXTENSIONS = {
    ".mp4", ".mov", ".avi", ".ts", ".264", ".h264", ".265", ".h265",
    ".dav", ".asf", ".mkv",
}

MP4_LIKE_EXTENSIONS = {".mp4", ".mov"}

MP4_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)


class DVRRecordingsModule(AnalysisModule):
    name = "dvr.recordings"

    def supports(self, evidence_path: Path) -> bool:
        if not evidence_path.is_dir():
            return False
        return any(
            p.suffix.lower() in KNOWN_VIDEO_EXTENSIONS
            for p in evidence_path.rglob("*")
            if p.is_file()
        )

    def analyze(self, evidence_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        for path in evidence_path.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in KNOWN_VIDEO_EXTENSIONS:
                continue

            stat = path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
            metadata = {
                "path": str(path.relative_to(evidence_path)),
                "size": stat.st_size,
                "extension": path.suffix.lower(),
            }

            if path.suffix.lower() in MP4_LIKE_EXTENSIONS:
                mp4_meta = self._read_mp4_mvhd(path)
                if mp4_meta:
                    metadata.update(mp4_meta)

            events.append(
                self._event(
                    evidence_item_id,
                    "dvr_recording_found",
                    f"Gravação encontrada: {metadata['path']} ({stat.st_size} bytes)",
                    metadata=metadata,
                    timestamp=metadata.get("creation_time", mtime),
                )
            )

        return events

    def _read_mp4_mvhd(self, path: Path) -> dict | None:
        try:
            with open(path, "rb") as f:
                file_size = path.stat().st_size
                moov_range = self._find_child_box(f, 0, file_size, b"moov")
                if moov_range is None:
                    return None
                moov_start, moov_end = moov_range
                mvhd_range = self._find_child_box(f, moov_start, moov_end, b"mvhd")
                if mvhd_range is None:
                    return None
                f.seek(mvhd_range[0])
                mvhd = f.read(mvhd_range[1] - mvhd_range[0])

                version = mvhd[0]
                if version == 1:
                    creation_time, _, timescale, duration = struct.unpack_from(">QQII", mvhd, 4)
                else:
                    creation_time, _, timescale, duration = struct.unpack_from(">IIII", mvhd, 4)
                creation_dt = MP4_EPOCH + timedelta(seconds=creation_time)
                duration_s = duration / timescale if timescale else None
                return {
                    "creation_time": creation_dt.isoformat(),
                    "duration_seconds": duration_s,
                }
        except (OSError, struct.error, IndexError):
            return None

    def _find_child_box(self, f, start: int, end: int, target_type: bytes) -> tuple[int, int] | None:
        """Procura uma caixa ISO-BMFF (`target_type`) diretamente dentro do
        intervalo [start, end) e retorna (início do conteúdo, fim da caixa)."""
        pos = start
        while pos < end:
            f.seek(pos)
            header = f.read(8)
            if len(header) < 8:
                break
            size, box_type = struct.unpack(">I4s", header)
            if size < 8:
                break
            content_start = pos + 8
            box_end = pos + size
            if box_type == target_type:
                return content_start, box_end
            pos = box_end
        return None

    def _event(self, evidence_item_id, event_type, description, metadata=None, timestamp=None) -> Event:
        return Event(
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
