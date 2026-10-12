"""Gera arquivos de evidência sintéticos para testar os módulos localmente."""
from __future__ import annotations

import io
import sqlite3
import struct
import tarfile
import zlib
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


def make_disk_image() -> Path:
    FIXTURES_DIR.mkdir(exist_ok=True)
    out_path = FIXTURES_DIR / "sample_disk.img"

    boot_sector = bytearray(512)
    # Partição 0: tipo FAT32 (0x0C), start_lba=2048, sector_count=20480
    entry = struct.pack("<BBBBBBBBII", 0x00, 0, 0, 0, 0x0C, 0, 0, 0, 2048, 20480)
    boot_sector[446:446 + len(entry)] = entry
    boot_sector[510:512] = b"\x55\xaa"

    image = bytearray(b"\x00" * (2048 * 512 + 512))
    image[0:512] = boot_sector

    fat32_sector_offset = 2048 * 512
    image[fat32_sector_offset + 0x52: fat32_sector_offset + 0x5A] = b"FAT32   "

    out_path.write_bytes(bytes(image))
    return out_path


if __name__ == "__main__":
    ab = make_android_backup()
    img = make_disk_image()
    print(f"Backup Android: {ab}")
    print(f"Imagem de disco: {img}")
