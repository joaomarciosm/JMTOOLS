"""Gera arquivos de evidência sintéticos para testar os módulos localmente."""
from __future__ import annotations

import hashlib
import io
import plistlib
import shutil
import sqlite3
import struct
import tarfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_android_backup() -> Path:
    FIXTURES_DIR.mkdir(exist_ok=True)
    db_path = FIXTURES_DIR / "_mmssms.db"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, body TEXT, type INTEGER)")
    conn.execute("INSERT INTO sms (address, date, body, type) VALUES ('+5511999999999', 1700000000000, 'Oi, tudo bem?', 1)")
    conn.execute("INSERT INTO sms (address, date, body, type) VALUES ('+5511999999999', 1700000100000, 'Tudo sim, e você?', 2)")
    conn.execute("CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER)")
    conn.execute("INSERT INTO calls (number, date, duration, type) VALUES ('+5511888888888', 1700000500000, 120, 1)")
    conn.commit()
    conn.close()

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        tar.add(db_path, arcname="apps/com.android.providers.telephony/db/mmssms.db")
        info = tarfile.TarInfo(name="apps/com.whatsapp/f/dummy.txt")
        data = b"arquivo de exemplo"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    payload = zlib.compress(tar_buffer.getvalue())
    header = b"ANDROID BACKUP\n5\n1\nnone\n"

    out_path = FIXTURES_DIR / "sample_backup.ab"
    out_path.write_bytes(header + payload)
    db_path.unlink()
    return out_path


def _fat_dir_entry(name: str, ext: str, attr: int, first_cluster: int, size: int, deleted: bool = False) -> bytes:
    entry = bytearray(32)
    entry[0:8] = name.ljust(8)[:8].encode("ascii")
    entry[8:11] = ext.ljust(3)[:3].encode("ascii")
    if deleted:
        entry[0] = 0xE5
    entry[11] = attr
    entry[20:22] = struct.pack("<H", (first_cluster >> 16) & 0xFFFF)
    entry[26:28] = struct.pack("<H", first_cluster & 0xFFFF)
    entry[28:32] = struct.pack("<I", size)
    return bytes(entry)


def make_disk_image() -> Path:
    """Imagem raw com MBR + 1 partição FAT32 funcional (BPB, FAT, diretórios)."""
    FIXTURES_DIR.mkdir(exist_ok=True)
    out_path = FIXTURES_DIR / "sample_disk.img"

    PART_START_LBA = 2048
    PART_OFFSET = PART_START_LBA * 512
    BYTES_PER_SECTOR = 512
    SECTORS_PER_CLUSTER = 1
    RESERVED_SECTORS = 32
    NUM_FATS = 1
    FAT_SIZE_SECTORS = 16
    ROOT_CLUSTER = 2
    CLUSTER_SIZE = SECTORS_PER_CLUSTER * BYTES_PER_SECTOR

    data_start_sector = RESERVED_SECTORS + NUM_FATS * FAT_SIZE_SECTORS

    def cluster_offset(cluster: int) -> int:
        sector = data_start_sector + (cluster - 2) * SECTORS_PER_CLUSTER
        return PART_OFFSET + sector * BYTES_PER_SECTOR

    total_size = PART_OFFSET + (data_start_sector + 10) * BYTES_PER_SECTOR
    image = bytearray(total_size)

    # MBR: partição 0 tipo FAT32 (0x0C), start_lba, sector_count
    entry = struct.pack("<BBBBBBBBII", 0x00, 0, 0, 0, 0x0C, 0, 0, 0, PART_START_LBA, 20480)
    image[446:446 + len(entry)] = entry
    image[510:512] = b"\x55\xaa"

    # BPB da partição FAT32
    bpb_off = PART_OFFSET
    struct.pack_into("<H", image, bpb_off + 0x0B, BYTES_PER_SECTOR)
    image[bpb_off + 0x0D] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", image, bpb_off + 0x0E, RESERVED_SECTORS)
    image[bpb_off + 0x10] = NUM_FATS
    struct.pack_into("<I", image, bpb_off + 0x24, FAT_SIZE_SECTORS)
    struct.pack_into("<I", image, bpb_off + 0x2C, ROOT_CLUSTER)
    image[bpb_off + 0x52: bpb_off + 0x5A] = b"FAT32   "

    # Tabela FAT: marca clusters 2 (root), 3 (HELLO.TXT), 4 (SECRET.TXT, deletado),
    # 5 (SUBDIR), 6 (NESTED.TXT) todos como fim-de-cadeia (arquivos de 1 cluster)
    fat_off = PART_OFFSET + RESERVED_SECTORS * BYTES_PER_SECTOR
    for cluster in (2, 3, 4, 5, 6):
        struct.pack_into("<I", image, fat_off + cluster * 4, 0x0FFFFFFF)

    hello_content = b"Hello world, este arquivo e normal.\n"
    secret_content = b"Conteudo que foi deletado mas o cluster ainda esta intacto.\n"
    nested_content = b"Arquivo dentro de subdiretorio.\n"

    root_dir = (
        _fat_dir_entry("HELLO", "TXT", 0x20, 3, len(hello_content))
        + _fat_dir_entry("SECRET", "TXT", 0x20, 4, len(secret_content), deleted=True)
        + _fat_dir_entry("SUBDIR", "", 0x10, 5, 0)
    )
    subdir = (
        _fat_dir_entry(".", "", 0x10, 5, 0)
        + _fat_dir_entry("..", "", 0x10, 0, 0)
        + _fat_dir_entry("NESTED", "TXT", 0x20, 6, len(nested_content))
    )

    image[cluster_offset(2): cluster_offset(2) + len(root_dir)] = root_dir
    image[cluster_offset(3): cluster_offset(3) + len(hello_content)] = hello_content
    image[cluster_offset(4): cluster_offset(4) + len(secret_content)] = secret_content
    image[cluster_offset(5): cluster_offset(5) + len(subdir)] = subdir
    image[cluster_offset(6): cluster_offset(6) + len(nested_content)] = nested_content

    out_path.write_bytes(bytes(image))
    return out_path


def make_ios_backup() -> Path:
    out_dir = FIXTURES_DIR / "ios_backup"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    (out_dir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))

    sms_db_path = FIXTURES_DIR / "_sms.db"
    if sms_db_path.exists():
        sms_db_path.unlink()
    conn = sqlite3.connect(sms_db_path)
    conn.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, date INTEGER, text TEXT, is_from_me INTEGER, service TEXT)")
    apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc).timestamp()
    sample_ts = int((datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc).timestamp() - apple_epoch) * 1_000_000_000)
    conn.execute("INSERT INTO message (date, text, is_from_me, service) VALUES (?, ?, 0, 'iMessage')", (sample_ts, "Chegou?"))
    conn.execute("INSERT INTO message (date, text, is_from_me, service) VALUES (?, ?, 1, 'iMessage')", (sample_ts + 60_000_000_000, "Cheguei sim"))
    conn.commit()
    conn.close()

    file_id = hashlib.sha1(b"HomeDomain-Library/SMS/sms.db").hexdigest()
    sub_dir = out_dir / file_id[0:2]
    sub_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(sms_db_path, sub_dir / file_id)
    sms_db_path.unlink()

    manifest_db_path = out_dir / "Manifest.db"
    conn = sqlite3.connect(manifest_db_path)
    conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    conn.execute(
        "INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?, ?, ?, 1, NULL)",
        (file_id, "HomeDomain", "Library/SMS/sms.db"),
    )
    conn.commit()
    conn.close()

    return out_dir


def _mp4_box(box_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + box_type + payload


def make_dvr_folder() -> Path:
    out_dir = FIXTURES_DIR / "dvr_storage"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    mp4_epoch = datetime(1904, 1, 1, tzinfo=timezone.utc)
    creation_dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    creation_time = int((creation_dt - mp4_epoch).total_seconds())

    ftyp = _mp4_box(b"ftyp", b"isom" + b"\x00\x00\x02\x00" + b"isom")
    mvhd_payload = struct.pack(">IIII", creation_time, creation_time, 1000, 5000)
    mvhd_payload = b"\x00\x00\x00\x00" + mvhd_payload  # version(1) + flags(3)
    moov = _mp4_box(b"moov", _mp4_box(b"mvhd", mvhd_payload))

    (out_dir / "CH01_20260115120000.mp4").write_bytes(ftyp + moov)
    (out_dir / "CH02_raw.264").write_bytes(b"\x00\x00\x00\x01" + b"\x65" * 200)  # stream H.264 cru, sem container
    return out_dir


def make_can_log() -> Path:
    FIXTURES_DIR.mkdir(exist_ok=True)
    out_path = FIXTURES_DIR / "sample_can.log"
    base_ts = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc).timestamp()

    lines = [
        f"({base_ts:.6f}) can0 7E8#0361000000000000",
        f"({base_ts + 0.1:.6f}) can0 7E8#04410C1A2E000000",  # resposta PID 0x0C (RPM): (0x1A*256+0x2E)/4 = 1675.5
        f"({base_ts + 0.2:.6f}) can0 7E8#03410D3C000000",    # resposta PID 0x0D (velocidade): 0x3C = 60 km/h
    ]
    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return out_path


if __name__ == "__main__":
    ab = make_android_backup()
    img = make_disk_image()
    ios_dir = make_ios_backup()
    dvr_dir = make_dvr_folder()
    can_log = make_can_log()
    print(f"Backup Android: {ab}")
    print(f"Imagem de disco: {img}")
    print(f"Backup iOS: {ios_dir}")
    print(f"Pasta DVR: {dvr_dir}")
    print(f"Log CAN: {can_log}")
