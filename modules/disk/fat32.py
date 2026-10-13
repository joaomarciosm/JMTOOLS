"""Leitor de volume FAT32 (especificação pública Microsoft FAT32).

Implementa o suficiente para perícia: BIOS Parameter Block, cadeia de
clusters via FAT, entradas de diretório (8.3 + Long File Name) e detecção
de entradas marcadas como deletadas (primeiro byte 0xE5).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

FAT32_EOC_MIN = 0x0FFFFFF8
FAT32_BAD_CLUSTER = 0x0FFFFFF7


@dataclass
class FatEntry:
    name: str
    is_dir: bool
    is_deleted: bool
    size: int
    first_cluster: int
    mtime: str | None
    ctime: str | None


class FAT32Volume:
    def __init__(self, f, partition_offset: int):
        self.f = f
        self.partition_offset = partition_offset

        f.seek(partition_offset)
        bpb = f.read(512)

        self.bytes_per_sector = struct.unpack_from("<H", bpb, 0x0B)[0]
        self.sectors_per_cluster = bpb[0x0D]
        self.reserved_sectors = struct.unpack_from("<H", bpb, 0x0E)[0]
        self.num_fats = bpb[0x10]
        self.fat_size_sectors = struct.unpack_from("<I", bpb, 0x24)[0]
        self.root_cluster = struct.unpack_from("<I", bpb, 0x2C)[0]

        self.fat_start_sector = self.reserved_sectors
        self.data_start_sector = self.reserved_sectors + self.num_fats * self.fat_size_sectors
        self.cluster_size = self.sectors_per_cluster * self.bytes_per_sector

    def _cluster_offset(self, cluster: int) -> int:
        sector = self.data_start_sector + (cluster - 2) * self.sectors_per_cluster
        return self.partition_offset + sector * self.bytes_per_sector

    def _read_fat_entry(self, cluster: int) -> int:
        fat_offset = self.partition_offset + self.fat_start_sector * self.bytes_per_sector + cluster * 4
        self.f.seek(fat_offset)
        raw = self.f.read(4)
        return struct.unpack("<I", raw)[0] & 0x0FFFFFFF

    def read_cluster_chain(self, start_cluster: int, max_clusters: int = 100_000) -> bytes:
        data = bytearray()
        cluster = start_cluster
        seen = set()
        for _ in range(max_clusters):
            if cluster in seen or cluster < 2 or cluster >= FAT32_BAD_CLUSTER:
                break
            seen.add(cluster)
            self.f.seek(self._cluster_offset(cluster))
            data += self.f.read(self.cluster_size)
            next_cluster = self._read_fat_entry(cluster)
            if next_cluster >= FAT32_EOC_MIN or next_cluster == FAT32_BAD_CLUSTER:
                break
            cluster = next_cluster
        return bytes(data)

    def list_directory(self, cluster: int) -> list[FatEntry]:
        raw = self.read_cluster_chain(cluster)
        entries: list[FatEntry] = []
        lfn_parts: dict[int, str] = {}

        for offset in range(0, len(raw) - 31, 32):
            entry = raw[offset: offset + 32]
            first_byte = entry[0]
            if first_byte == 0x00:
                break

            attr = entry[11]
            is_deleted = first_byte == 0xE5

            if attr == 0x0F and not is_deleted:
                seq = entry[0] & 0x1F
                chars = entry[1:11] + entry[14:26] + entry[28:32]
                try:
                    part = chars.decode("utf-16-le").split("\x00")[0]
                except UnicodeDecodeError:
                    continue
                lfn_parts[seq] = part
                continue

            if attr & 0x08:  # volume label
                continue

            short_name = self._decode_short_name(entry, deleted=is_deleted)
            long_name = "".join(lfn_parts[k] for k in sorted(lfn_parts)) if lfn_parts else None
            lfn_parts = {}

            first_cluster = (
                struct.unpack_from("<H", entry, 20)[0] << 16 | struct.unpack_from("<H", entry, 26)[0]
            )
            size = struct.unpack_from("<I", entry, 28)[0]
            is_dir = bool(attr & 0x10)

            entries.append(
                FatEntry(
                    name=long_name or short_name,
                    is_dir=is_dir,
                    is_deleted=is_deleted,
                    size=size,
                    first_cluster=first_cluster,
                    mtime=self._decode_datetime(entry, 24, 22),
                    ctime=self._decode_datetime(entry, 17, 15, has_tenths=True, tenths_offset=13),
                )
            )

        return entries

    def walk(self, cluster: int | None = None, prefix: str = "", max_depth: int = 40) -> list[tuple[str, FatEntry]]:
        if cluster is None:
            cluster = self.root_cluster
        results: list[tuple[str, FatEntry]] = []
        if max_depth <= 0:
            return results

        for entry in self.list_directory(cluster):
            if entry.name in (".", ".."):
                continue
            path = f"{prefix}/{entry.name}" if prefix else entry.name
            results.append((path, entry))
            if entry.is_dir and not entry.is_deleted and entry.first_cluster >= 2:
                results.extend(self.walk(entry.first_cluster, path, max_depth - 1))

        return results

    @staticmethod
    def _decode_short_name(entry: bytes, deleted: bool) -> str:
        raw_name = entry[0:8]
        raw_ext = entry[8:11]
        if deleted:
            raw_name = b"?" + raw_name[1:]
        name = raw_name.decode("ascii", errors="replace").rstrip(" ")
        ext = raw_ext.decode("ascii", errors="replace").rstrip(" ")
        return f"{name}.{ext}" if ext else name

    @staticmethod
    def _decode_datetime(entry: bytes, date_off: int, time_off: int, has_tenths=False, tenths_offset=None) -> str | None:
        try:
            date_val = struct.unpack_from("<H", entry, date_off)[0]
            time_val = struct.unpack_from("<H", entry, time_off)[0]
            if date_val == 0:
                return None
            year = 1980 + (date_val >> 9)
            month = (date_val >> 5) & 0x0F
            day = date_val & 0x1F
            hour = time_val >> 11
            minute = (time_val >> 5) & 0x3F
            second = (time_val & 0x1F) * 2
            dt = datetime(year, month or 1, day or 1, hour, minute, second, tzinfo=timezone.utc)
            return dt.isoformat()
        except (ValueError, struct.error):
            return None
