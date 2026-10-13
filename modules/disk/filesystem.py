"""Análise de imagens de disco raw (dd/img): tabela de partições (MBR/GPT)
e detecção de assinatura de sistema de arquivos.

Escopo desta versão (MVP): leitura de metadados de partição e assinatura de
FS. Listagem de arquivos e recuperação de deletados dependem de um parser
completo de sistema de arquivos (NTFS/ext4/FAT) — ver docs/roadmap.md para
o plano de integração com bibliotecas como `dissect` ou `pytsk3`.

Formatos de imagem forense comprimidos/proprietários (E01/EWF, AFF) não são
suportados aqui; apenas imagens raw (dd/img/bin), que é o formato produzido
por `dd`, `dc3dd` e a maioria dos write-blockers.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from core.plugin import AnalysisModule
from core.timeline import Event
from modules.disk.fat32 import FAT32Volume
from modules.disk.ntfs import NTFSVolume

SECTOR_SIZE = 512
RAW_EXTENSIONS = {".img", ".dd", ".raw", ".bin"}

MBR_PARTITION_TYPES = {
    0x00: "vazia",
    0x07: "NTFS/exFAT",
    0x0B: "FAT32",
    0x0C: "FAT32 (LBA)",
    0x82: "Linux swap",
    0x83: "Linux",
    0xEE: "GPT protetora",
}


@dataclass
class PartitionInfo:
    index: int
    start_lba: int
    sector_count: int
    type_label: str

    @property
    def start_offset(self) -> int:
        return self.start_lba * SECTOR_SIZE

    @property
    def size_bytes(self) -> int:
        return self.sector_count * SECTOR_SIZE


class DiskImageModule(AnalysisModule):
    name = "disk.image"

    def supports(self, evidence_path: Path) -> bool:
        if evidence_path.suffix.lower() in RAW_EXTENSIONS:
            return True
        try:
            with open(evidence_path, "rb") as f:
                boot_sector = f.read(SECTOR_SIZE)
        except OSError:
            return False
        return len(boot_sector) == SECTOR_SIZE and boot_sector[510:512] == b"\x55\xaa"

    def analyze(self, evidence_path: Path, evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        with open(evidence_path, "rb") as f:
            boot_sector = f.read(SECTOR_SIZE)
            if len(boot_sector) < SECTOR_SIZE or boot_sector[510:512] != b"\x55\xaa":
                events.append(self._event(evidence_item_id, "image_unrecognized",
                                           "Assinatura MBR (0x55AA) não encontrada no setor de boot."))
                return events

            partitions = self._parse_mbr(boot_sector)

            is_gpt_protective = len(partitions) == 1 and partitions[0].type_label == "GPT protetora"
            if is_gpt_protective:
                f.seek(1 * SECTOR_SIZE)
                gpt_header = f.read(SECTOR_SIZE)
                partitions = self._parse_gpt(f, gpt_header)

            for p in partitions:
                events.append(
                    self._event(
                        evidence_item_id,
                        "partition_found",
                        f"Partição {p.index}: tipo={p.type_label} offset={p.start_offset} "
                        f"tamanho={p.size_bytes} bytes",
                        metadata={
                            "index": p.index,
                            "start_offset": p.start_offset,
                            "size_bytes": p.size_bytes,
                            "type_label": p.type_label,
                        },
                    )
                )
                fs_guess = self._detect_filesystem(f, p.start_offset)
                if fs_guess:
                    events.append(
                        self._event(
                            evidence_item_id,
                            "filesystem_detected",
                            f"Partição {p.index}: sistema de arquivos detectado = {fs_guess}",
                            metadata={"index": p.index, "filesystem": fs_guess},
                        )
                    )
                if fs_guess == "FAT32":
                    events.extend(self._list_fat32(f, p, evidence_item_id))
                elif fs_guess == "NTFS":
                    events.extend(self._list_ntfs(f, p, evidence_item_id))

        return events

    def _list_ntfs(self, f, partition: "PartitionInfo", evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            volume = NTFSVolume(f, partition.start_offset)
            for entry in volume.list_files():
                event_type = "deleted_file_found" if entry["is_deleted"] else "file_found"
                marker = "[DELETADO] " if entry["is_deleted"] else ""
                events.append(
                    self._event(
                        evidence_item_id,
                        event_type,
                        f"{marker}Partição {partition.index}: {entry['path']} ({entry['size']} bytes)",
                        metadata={
                            "index": partition.index,
                            "path": entry["path"],
                            "size": entry["size"],
                            "mft_record": entry["mft_record"],
                            "mtime": entry["mtime"],
                            "ctime": entry["ctime"],
                        },
                        timestamp=entry["mtime"],
                    )
                )
        except (struct.error, ValueError, OSError):
            events.append(
                self._event(
                    evidence_item_id,
                    "ntfs_parse_error",
                    f"Partição {partition.index}: falha ao percorrer a $MFT.",
                )
            )
        return events

    def _list_fat32(self, f, partition: "PartitionInfo", evidence_item_id: str) -> list[Event]:
        events: list[Event] = []
        try:
            volume = FAT32Volume(f, partition.start_offset)
            for path, fat_entry in volume.walk():
                if fat_entry.is_dir:
                    continue
                event_type = "deleted_file_found" if fat_entry.is_deleted else "file_found"
                marker = "[DELETADO] " if fat_entry.is_deleted else ""
                events.append(
                    self._event(
                        evidence_item_id,
                        event_type,
                        f"{marker}Partição {partition.index}: {path} ({fat_entry.size} bytes)",
                        metadata={
                            "index": partition.index,
                            "path": path,
                            "size": fat_entry.size,
                            "first_cluster": fat_entry.first_cluster,
                            "mtime": fat_entry.mtime,
                            "ctime": fat_entry.ctime,
                        },
                    )
                )
        except (struct.error, OSError, ValueError):
            events.append(
                self._event(
                    evidence_item_id,
                    "fat32_parse_error",
                    f"Partição {partition.index}: falha ao percorrer diretórios FAT32.",
                )
            )
        return events

    def _parse_mbr(self, boot_sector: bytes) -> list[PartitionInfo]:
        partitions = []
        for i in range(4):
            entry = boot_sector[446 + i * 16: 446 + (i + 1) * 16]
            part_type = entry[4]
            start_lba, sector_count = struct.unpack_from("<II", entry, 8)
            if part_type == 0x00 or sector_count == 0:
                continue
            partitions.append(
                PartitionInfo(
                    index=i,
                    start_lba=start_lba,
                    sector_count=sector_count,
                    type_label=MBR_PARTITION_TYPES.get(part_type, f"desconhecido (0x{part_type:02x})"),
                )
            )
        return partitions

    def _parse_gpt(self, f, gpt_header: bytes) -> list[PartitionInfo]:
        if gpt_header[0:8] != b"EFI PART":
            return []
        entry_lba, num_entries, entry_size = struct.unpack_from("<QII", gpt_header, 72)

        f.seek(entry_lba * SECTOR_SIZE)
        table = f.read(num_entries * entry_size)

        partitions = []
        for i in range(num_entries):
            raw = table[i * entry_size: (i + 1) * entry_size]
            if len(raw) < 128 or raw[0:16] == b"\x00" * 16:
                continue
            first_lba, last_lba = struct.unpack_from("<QQ", raw, 32)
            name = raw[56:128].decode("utf-16-le", errors="ignore").rstrip("\x00")
            partitions.append(
                PartitionInfo(
                    index=i,
                    start_lba=first_lba,
                    sector_count=last_lba - first_lba + 1,
                    type_label=f"GPT: {name or 'sem nome'}",
                )
            )
        return partitions

    def _detect_filesystem(self, f, partition_offset: int) -> str | None:
        f.seek(partition_offset)
        sector = f.read(SECTOR_SIZE)
        if len(sector) < SECTOR_SIZE:
            return None

        if sector[3:11] == b"NTFS    ":
            return "NTFS"
        if sector[3:11] == b"EXFAT   ":
            return "exFAT"
        if sector[0x52:0x5A] == b"FAT32   ":
            return "FAT32"
        if sector[0x36:0x3E] == b"FAT16   ":
            return "FAT16"
        if sector[0x36:0x3E] == b"FAT12   ":
            return "FAT12"

        f.seek(partition_offset + 1024)
        superblock = f.read(128)
        if len(superblock) >= 58 and superblock[56:58] == b"\x53\xef":
            return "ext2/3/4"

        return None

    def _event(self, evidence_item_id, event_type, description, metadata=None, timestamp=None) -> Event:
        from datetime import datetime, timezone

        return Event(
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
