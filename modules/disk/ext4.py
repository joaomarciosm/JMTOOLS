"""Leitor de volume ext2/3/4 (especificação pública, documentada em
https://www.kernel.org/doc/html/latest/filesystems/ext4/).

Escopo: superbloco, tabela de descritores de grupo, inodes e diretórios
(ext4_dir_entry_2) via árvore de extents (só profundidade 0 — suficiente
para arquivos que cabem nos 4 extents diretos do inode; árvores mais
profundas, usadas por arquivos grandes/fragmentados, não são resolvidas
nesta versão — ver docs/roadmap.md).

Importante sobre arquivos deletados em ext4: ao contrário de FAT32/NTFS, o
kernel Linux tipicamente zera os ponteiros de bloco/extent do inode no
unlink. Por isso, aqui reportamos inodes deletados (dtime != 0, links_count
== 0) com os metadados que ainda restarem (tamanho, timestamps, modo) — mas
**não** com um caminho recuperável, porque a entrada de diretório que
apontava para eles normalmente também já foi removida.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

EXT4_MAGIC = 0xEF53
EXTENT_MAGIC = 0xF30A

S_IFDIR = 0x4000
S_IFREG = 0x8000

FEATURE_INCOMPAT_FILETYPE = 0x0002
FEATURE_INCOMPAT_EXTENTS = 0x0040

ROOT_INODE = 2


def _epoch_to_iso(value: int) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class Inode:
    inode_num: int
    mode: int
    size: int
    atime: str | None
    ctime: str | None
    mtime: str | None
    dtime: int
    links_count: int
    uses_extents: bool
    raw_iblock: bytes

    @property
    def is_dir(self) -> bool:
        return (self.mode & 0xF000) == S_IFDIR

    @property
    def is_regular(self) -> bool:
        return (self.mode & 0xF000) == S_IFREG

    @property
    def is_deleted(self) -> bool:
        return self.dtime != 0 and self.links_count == 0


class Ext4Volume:
    def __init__(self, f, partition_offset: int):
        self.f = f
        self.partition_offset = partition_offset

        f.seek(partition_offset + 1024)
        sb = f.read(1024)
        magic = struct.unpack_from("<H", sb, 56)[0]
        if magic != EXT4_MAGIC:
            raise ValueError("Assinatura ext2/3/4 (0xEF53) não encontrada no superbloco.")

        log_block_size = struct.unpack_from("<I", sb, 24)[0]
        self.block_size = 1024 << log_block_size
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]
        self.inodes_count = struct.unpack_from("<I", sb, 0)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0] or 128
        self.feature_incompat = struct.unpack_from("<I", sb, 96)[0]

        num_groups = (self.inodes_count + self.inodes_per_group - 1) // self.inodes_per_group
        sb_block = 1 if self.block_size == 1024 else 0
        gd_start_block = sb_block + 1

        self.group_inode_table: dict[int, int] = {}
        f.seek(self._block_offset(gd_start_block))
        gd_table = f.read(num_groups * 32)
        for g in range(num_groups):
            desc = gd_table[g * 32:(g + 1) * 32]
            if len(desc) < 32:
                break
            inode_table_block = struct.unpack_from("<I", desc, 8)[0]
            self.group_inode_table[g] = inode_table_block

    def _block_offset(self, block_num: int) -> int:
        return self.partition_offset + block_num * self.block_size

    def read_inode(self, inode_num: int) -> Inode | None:
        group = (inode_num - 1) // self.inodes_per_group
        index = (inode_num - 1) % self.inodes_per_group
        inode_table_block = self.group_inode_table.get(group)
        if inode_table_block is None:
            return None

        offset = self._block_offset(inode_table_block) + index * self.inode_size
        self.f.seek(offset)
        raw = self.f.read(min(self.inode_size, 160))
        if len(raw) < 128:
            return None

        mode = struct.unpack_from("<H", raw, 0)[0]
        size_lo = struct.unpack_from("<I", raw, 4)[0]
        atime, ctime, mtime, dtime = struct.unpack_from("<IIII", raw, 8)
        links_count = struct.unpack_from("<H", raw, 26)[0]
        flags = struct.unpack_from("<I", raw, 32)[0]
        iblock = raw[40:100]

        return Inode(
            inode_num=inode_num,
            mode=mode,
            size=size_lo,
            atime=_epoch_to_iso(atime),
            ctime=_epoch_to_iso(ctime),
            mtime=_epoch_to_iso(mtime),
            dtime=dtime,
            links_count=links_count,
            uses_extents=bool(flags & 0x80000),
            raw_iblock=iblock,
        )

    def _resolve_extents_depth0(self, iblock: bytes) -> list[tuple[int, int]] | None:
        """Retorna [(bloco_fisico_inicial, num_blocos), ...] ou None se a
        árvore tiver profundidade > 0 (não suportado nesta versão)."""
        magic, entries, _max_entries, depth, _gen = struct.unpack_from("<HHHHI", iblock, 0)
        if magic != EXTENT_MAGIC or depth != 0:
            return None

        runs = []
        for i in range(entries):
            entry_off = 12 + i * 12
            ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from("<IHHI", iblock, entry_off)
            length = ee_len if ee_len <= 32768 else ee_len - 32768
            start = (ee_start_hi << 32) | ee_start_lo
            runs.append((start, length))
        return runs

    def _read_raw_blocks(self, inode: Inode) -> bytes | None:
        if not inode.uses_extents:
            return None
        runs = self._resolve_extents_depth0(inode.raw_iblock)
        if runs is None:
            return None
        data = bytearray()
        for start_block, length in runs:
            self.f.seek(self._block_offset(start_block))
            data += self.f.read(length * self.block_size)
        return bytes(data)

    def read_file_data(self, inode: Inode) -> bytes | None:
        raw = self._read_raw_blocks(inode)
        return raw if raw is None else raw[: inode.size]

    def list_directory(self, inode: Inode) -> list[tuple[int, str, int]]:
        """Retorna [(inode_num, nome, file_type), ...] a partir dos blocos
        de dados do diretório."""
        data = self._read_raw_blocks(inode)
        if data is None:
            return []

        entries = []
        pos = 0
        while pos < len(data) - 8:
            inode_num, rec_len, name_len, file_type = struct.unpack_from("<IHBB", data, pos)
            if rec_len == 0:
                break
            if inode_num != 0:
                name = data[pos + 8: pos + 8 + name_len].decode("utf-8", errors="replace")
                entries.append((inode_num, name, file_type))
            pos += rec_len
        return entries

    def walk(self, inode_num: int = ROOT_INODE, prefix: str = "", max_depth: int = 40) -> list[dict]:
        results: list[dict] = []
        if max_depth <= 0:
            return results

        inode = self.read_inode(inode_num)
        if inode is None or not inode.is_dir:
            return results

        for child_num, name, _file_type in self.list_directory(inode):
            if name in (".", ".."):
                continue
            child = self.read_inode(child_num)
            if child is None:
                continue
            path = f"{prefix}/{name}" if prefix else name
            if child.is_dir:
                results.extend(self.walk(child_num, path, max_depth - 1))
            else:
                results.append(
                    {
                        "path": path,
                        "is_deleted": False,
                        "size": child.size,
                        "mtime": child.mtime,
                        "ctime": child.ctime,
                        "inode": child_num,
                    }
                )
        return results

    def find_deleted_inodes(self) -> list[dict]:
        """Varre toda a tabela de inodes em busca de registros com dtime != 0
        e links_count == 0 — metadados sobrevivem, caminho geralmente não."""
        results = []
        for inode_num in range(ROOT_INODE + 1, self.inodes_count + 1):
            inode = self.read_inode(inode_num)
            if inode is None:
                continue
            if inode.is_deleted and inode.mode != 0:
                results.append(
                    {
                        "path": f"(inode #{inode_num}, caminho não recuperável)",
                        "is_deleted": True,
                        "size": inode.size,
                        "mtime": inode.mtime,
                        "ctime": inode.ctime,
                        "inode": inode_num,
                    }
                )
        return results
