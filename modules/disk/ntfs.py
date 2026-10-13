"""Leitor de volume NTFS (especificação pública, documentada por exemplo em
https://flatcap.org/linux-ntfs/ntfs/ e pelo próprio comportamento observável
do driver da Microsoft).

Estratégia: em vez de implementar o parser de árvore B+ dos atributos
$INDEX_ROOT/$INDEX_ALLOCATION (bem mais complexo), percorremos a $MFT inteira
registro a registro, extraímos o atributo $FILE_NAME de cada um (que contém
a referência ao diretório pai) e reconstruímos o caminho completo subindo a
cadeia de pais. Isso é uma técnica padrão de ferramentas de parsing de MFT e
tem a vantagem de também encontrar registros marcados como deletados (flag
"em uso" = 0), já que eles continuam fisicamente na tabela até serem
reaproveitados.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF

FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002

ROOT_RECORD_NUMBER = 5

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(value: int) -> str | None:
    if value == 0:
        return None
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class FileNameAttr:
    parent_record: int
    name: str
    namespace: int
    is_dir_hint: bool
    creation_time: str | None
    modification_time: str | None
    access_time: str | None
    real_size: int


@dataclass
class MftRecord:
    record_number: int
    in_use: bool
    is_dir: bool
    file_names: list[FileNameAttr] = field(default_factory=list)
    data_size: int | None = None


def parse_data_runs(buf: bytes) -> list[tuple[int, int | None]]:
    """Decodifica a lista de data runs de um atributo não-residente.
    Retorna [(tamanho_em_clusters, delta_lcn_ou_None_se_esparso), ...]."""
    runs: list[tuple[int, int | None]] = []
    pos = 0
    while pos < len(buf):
        header = buf[pos]
        if header == 0x00:
            break
        length_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F
        pos += 1

        length_bytes = buf[pos: pos + length_size]
        pos += length_size
        length = int.from_bytes(length_bytes, "little", signed=False)

        if offset_size == 0:
            runs.append((length, None))  # run esparso
            continue

        offset_bytes = buf[pos: pos + offset_size]
        pos += offset_size
        delta = int.from_bytes(offset_bytes, "little", signed=True)
        runs.append((length, delta))

    return runs


class NTFSVolume:
    def __init__(self, f, partition_offset: int):
        self.f = f
        self.partition_offset = partition_offset

        f.seek(partition_offset)
        boot = f.read(512)
        if boot[3:7] != b"NTFS" and boot[3:11] != b"NTFS    ":
            raise ValueError("Assinatura NTFS não encontrada no setor de boot.")

        self.bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
        self.sectors_per_cluster = boot[0x0D]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]

        self.mft_record_size = self._decode_record_size(boot[0x40], self.cluster_size)

        # Registro 0 da $MFT está sempre fisicamente no LCN indicado pelo boot sector.
        f.seek(partition_offset + mft_lcn * self.cluster_size)
        record0_raw = bytearray(f.read(self.mft_record_size))
        record0 = self._apply_fixup(record0_raw)

        kind, payload = self._find_unnamed_data(record0)
        if kind is None:
            raise ValueError("Não foi possível localizar o atributo $DATA de $MFT (registro 0).")
        self.mft_data = payload if kind == "resident" else self._resolve_data_runs(payload)
        self.total_records = len(self.mft_data) // self.mft_record_size

    @staticmethod
    def _decode_record_size(raw_byte: int, cluster_size: int) -> int:
        signed = raw_byte - 256 if raw_byte > 127 else raw_byte
        if signed < 0:
            return 1 << (-signed)
        return signed * cluster_size

    def _apply_fixup(self, raw: bytearray) -> bytes:
        if bytes(raw[0:4]) != b"FILE":
            return bytes(raw)
        usa_offset, usa_count = struct.unpack_from("<HH", raw, 4)
        if usa_count == 0:
            return bytes(raw)
        usn = raw[usa_offset: usa_offset + 2]
        for i in range(usa_count - 1):
            sector_end = (i + 1) * self.bytes_per_sector - 2
            if sector_end + 2 > len(raw):
                break
            replacement = raw[usa_offset + 2 + i * 2: usa_offset + 4 + i * 2]
            if bytes(raw[sector_end: sector_end + 2]) != bytes(usn):
                continue  # setor sem assinatura esperada — ignora fixup desse setor
            raw[sector_end: sector_end + 2] = replacement
        return bytes(raw)

    def _iter_attributes(self, record: bytes):
        if record[0:4] != b"FILE":
            return
        first_attr_offset = struct.unpack_from("<H", record, 20)[0]
        pos = first_attr_offset
        while pos + 8 <= len(record):
            attr_type = struct.unpack_from("<I", record, pos)[0]
            if attr_type == ATTR_END:
                break
            attr_len = struct.unpack_from("<I", record, pos + 4)[0]
            if attr_len == 0:
                break
            yield attr_type, record[pos: pos + attr_len]
            pos += attr_len

    def _find_unnamed_data(self, record: bytes):
        """Retorna ('resident', bytes) ou ('non_resident', data_runs) para o
        atributo $DATA sem nome, ou (None, None) se não encontrado."""
        for attr_type, attr in self._iter_attributes(record):
            if attr_type != ATTR_DATA:
                continue
            name_length = attr[9]
            if name_length != 0:
                continue  # stream nomeada (ex: ADS) — ignora, queremos o $DATA padrão
            non_resident = attr[8]
            if non_resident == 0:
                content_len, content_off = struct.unpack_from("<IH", attr, 16)
                return "resident", attr[content_off: content_off + content_len]
            run_offset = struct.unpack_from("<H", attr, 32)[0]
            return "non_resident", parse_data_runs(attr[run_offset:])
        return None, None

    def _resolve_data_runs(self, runs: list[tuple[int, int | None]]) -> bytes:
        data = bytearray()
        current_lcn = 0
        for length_clusters, delta in runs:
            if delta is None:
                data += b"\x00" * (length_clusters * self.cluster_size)
                continue
            current_lcn += delta
            self.f.seek(self.partition_offset + current_lcn * self.cluster_size)
            data += self.f.read(length_clusters * self.cluster_size)
        return bytes(data)

    def _parse_record(self, record_number: int) -> MftRecord | None:
        start = record_number * self.mft_record_size
        raw = self.mft_data[start: start + self.mft_record_size]
        if len(raw) < self.mft_record_size or raw[0:4] != b"FILE":
            return None
        fixed = self._apply_fixup(bytearray(raw))

        flags = struct.unpack_from("<H", fixed, 22)[0]
        in_use = bool(flags & FLAG_IN_USE)
        is_dir = bool(flags & FLAG_DIRECTORY)

        mft_record = MftRecord(record_number=record_number, in_use=in_use, is_dir=is_dir)

        for attr_type, attr in self._iter_attributes(fixed):
            if attr_type == ATTR_FILE_NAME:
                fn = self._parse_file_name(attr)
                if fn:
                    mft_record.file_names.append(fn)
            elif attr_type == ATTR_DATA:
                name_length = attr[9]
                if name_length != 0:
                    continue
                non_resident = attr[8]
                if non_resident == 0:
                    mft_record.data_size = struct.unpack_from("<I", attr, 16)[0]
                else:
                    mft_record.data_size = struct.unpack_from("<Q", attr, 52)[0]  # real_size

        return mft_record

    def _parse_file_name(self, attr: bytes) -> FileNameAttr | None:
        non_resident = attr[8]
        if non_resident != 0:
            return None  # $FILE_NAME é sempre residente por especificação; defensivo
        content_len, content_off = struct.unpack_from("<IH", attr, 16)
        content = attr[content_off: content_off + content_len]
        if len(content) < 66:
            return None

        parent_ref = struct.unpack_from("<Q", content, 0)[0]
        parent_record = parent_ref & 0x0000FFFFFFFFFFFF
        creation_time, mod_time, _mft_mod_time, access_time = struct.unpack_from("<QQQQ", content, 8)
        real_size = struct.unpack_from("<Q", content, 48)[0]
        fn_flags = struct.unpack_from("<I", content, 56)[0]
        name_len_chars = content[64]
        namespace = content[65]
        name_bytes = content[66: 66 + name_len_chars * 2]
        try:
            name = name_bytes.decode("utf-16-le")
        except UnicodeDecodeError:
            return None

        return FileNameAttr(
            parent_record=parent_record,
            name=name,
            namespace=namespace,
            is_dir_hint=bool(fn_flags & 0x10000000),
            creation_time=filetime_to_iso(creation_time),
            modification_time=filetime_to_iso(mod_time),
            access_time=filetime_to_iso(access_time),
            real_size=real_size,
        )

    def list_files(self, max_records: int | None = None) -> list[dict]:
        """Varre todos os registros da $MFT e reconstrói caminhos completos.
        Retorna uma lista de dicts com path, is_dir, is_deleted, size, mtime."""
        limit = min(self.total_records, max_records) if max_records else self.total_records

        records: dict[int, MftRecord] = {}
        for n in range(limit):
            rec = self._parse_record(n)
            if rec is not None:
                records[n] = rec

        def best_name(rec: MftRecord) -> FileNameAttr | None:
            if not rec.file_names:
                return None
            win32 = [fn for fn in rec.file_names if fn.namespace in (1, 3)]
            return (win32 or rec.file_names)[0]

        def resolve_path(record_number: int, depth: int = 0) -> str | None:
            if record_number == ROOT_RECORD_NUMBER:
                return ""
            if depth > 64 or record_number not in records:
                return None
            rec = records[record_number]
            fn = best_name(rec)
            if fn is None:
                return None
            parent_path = resolve_path(fn.parent_record, depth + 1)
            if parent_path is None:
                return None
            return f"{parent_path}/{fn.name}" if parent_path else fn.name

        results = []
        for n, rec in records.items():
            if n == ROOT_RECORD_NUMBER or rec.is_dir:
                continue
            fn = best_name(rec)
            if fn is None:
                continue
            path = resolve_path(n)
            if path is None:
                continue
            results.append(
                {
                    "path": path,
                    "is_dir": rec.is_dir,
                    "is_deleted": not rec.in_use,
                    "size": rec.data_size if rec.data_size is not None else fn.real_size,
                    "mtime": fn.modification_time,
                    "ctime": fn.creation_time,
                    "atime": fn.access_time,
                    "mft_record": n,
                }
            )
        return results
