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


def make_encrypted_android_backup(password: str = "senha-conhecida-123") -> Path:
    """Backup .ab criptografado de verdade (AES-256), para validar
    modules/mobile/android_crypto.py ponta a ponta."""
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    FIXTURES_DIR.mkdir(exist_ok=True)

    def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len]) * pad_len

    def pbkdf2(password_bytes: bytes, salt: bytes, rounds: int, length: int) -> bytes:
        return PBKDF2HMAC(algorithm=hashes.SHA1(), length=length, salt=salt, iterations=rounds).derive(password_bytes)

    def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        info = tarfile.TarInfo(name="apps/com.example/f/segredo.txt")
        data = b"conteudo sigiloso dentro do backup criptografado"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    compressed_tar = zlib.compress(tar_buffer.getvalue())

    rounds = 10000
    user_salt = os.urandom(64)
    checksum_salt = os.urandom(64)
    user_iv = os.urandom(16)
    master_key = os.urandom(32)
    master_iv = os.urandom(16)

    checksum = pbkdf2(master_key, checksum_salt, rounds, 32)
    master_key_blob_plain = bytes([len(master_iv)]) + master_iv + bytes([len(master_key)]) + master_key + bytes([len(checksum)]) + checksum

    user_key = pbkdf2(password.encode("utf-8"), user_salt, rounds, 32)
    master_key_blob_encrypted = aes_cbc_encrypt(user_key, user_iv, pkcs7_pad(master_key_blob_plain))

    encrypted_payload = aes_cbc_encrypt(master_key, master_iv, pkcs7_pad(compressed_tar))

    header = (
        "ANDROID BACKUP\n5\n1\nAES-256\n"
        f"{user_salt.hex()}\n{checksum_salt.hex()}\n{rounds}\n{user_iv.hex()}\n{master_key_blob_encrypted.hex()}\n"
    ).encode("utf-8")

    out_path = FIXTURES_DIR / "sample_backup_encrypted.ab"
    out_path.write_bytes(header + encrypted_payload)
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


def _ntfs_filetime(dt: datetime) -> int:
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int(delta.total_seconds() * 10_000_000)


def _ntfs_resident_attr(attr_type: int, content: bytes, attr_id: int) -> bytes:
    content_offset = 24
    unpadded = content_offset + len(content)
    padded = unpadded + ((-unpadded) % 8)
    buf = bytearray(padded)
    struct.pack_into("<I", buf, 0, attr_type)
    struct.pack_into("<I", buf, 4, padded)
    buf[8] = 0
    buf[9] = 0
    struct.pack_into("<H", buf, 14, attr_id)
    struct.pack_into("<I", buf, 16, len(content))
    struct.pack_into("<H", buf, 20, content_offset)
    buf[content_offset: content_offset + len(content)] = content
    return bytes(buf)


def _ntfs_non_resident_attr(attr_type: int, data_runs: bytes, attr_id: int, size: int, start_vcn: int, end_vcn: int) -> bytes:
    run_offset = 68
    unpadded = run_offset + len(data_runs)
    padded = unpadded + ((-unpadded) % 8)
    buf = bytearray(padded)
    struct.pack_into("<I", buf, 0, attr_type)
    struct.pack_into("<I", buf, 4, padded)
    buf[8] = 1
    buf[9] = 0
    struct.pack_into("<H", buf, 14, attr_id)
    struct.pack_into("<Q", buf, 16, start_vcn)
    struct.pack_into("<Q", buf, 24, end_vcn)
    struct.pack_into("<H", buf, 32, run_offset)
    struct.pack_into("<Q", buf, 44, size)
    struct.pack_into("<Q", buf, 52, size)
    struct.pack_into("<Q", buf, 60, size)
    buf[run_offset: run_offset + len(data_runs)] = data_runs
    return bytes(buf)


def _ntfs_file_name_attr(parent_record: int, name: str, is_dir: bool, size: int, dt: datetime, attr_id: int) -> bytes:
    ft = _ntfs_filetime(dt)
    parent_ref = parent_record | (1 << 48)
    name_bytes = name.encode("utf-16-le")
    content = bytearray(66 + len(name_bytes))
    struct.pack_into("<Q", content, 0, parent_ref)
    struct.pack_into("<QQQQ", content, 8, ft, ft, ft, ft)
    struct.pack_into("<Q", content, 40, size)
    struct.pack_into("<Q", content, 48, size)
    struct.pack_into("<I", content, 56, 0x10000000 if is_dir else 0x20)
    content[64] = len(name)
    content[65] = 1
    content[66:66 + len(name_bytes)] = name_bytes
    return _ntfs_resident_attr(ATTR_FILE_NAME, bytes(content), attr_id)


ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80


def _ntfs_build_record(record_size: int, sector_size: int, in_use: bool, is_dir: bool, attrs: list[bytes]) -> bytes:
    usa_offset = 0x30
    sectors = record_size // sector_size
    usa_count = 1 + sectors
    first_attr_offset = usa_offset + usa_count * 2
    first_attr_offset += (-first_attr_offset) % 8

    buf = bytearray(record_size)
    buf[0:4] = b"FILE"
    struct.pack_into("<H", buf, 4, usa_offset)
    struct.pack_into("<H", buf, 6, usa_count)
    struct.pack_into("<H", buf, 16, 1)
    struct.pack_into("<H", buf, 18, 1)
    struct.pack_into("<H", buf, 20, first_attr_offset)
    flags = (0x0001 if in_use else 0) | (0x0002 if is_dir else 0)
    struct.pack_into("<H", buf, 22, flags)

    pos = first_attr_offset
    for attr_bytes in attrs:
        buf[pos: pos + len(attr_bytes)] = attr_bytes
        pos += len(attr_bytes)
    struct.pack_into("<I", buf, pos, 0xFFFFFFFF)
    pos += 4
    struct.pack_into("<I", buf, 24, pos)
    struct.pack_into("<I", buf, 28, record_size)
    struct.pack_into("<H", buf, 40, len(attrs))

    usn = 1
    struct.pack_into("<H", buf, usa_offset, usn)
    for i in range(sectors):
        sector_end = (i + 1) * sector_size - 2
        replacement = int.from_bytes(bytes(buf[sector_end:sector_end + 2]), "little")
        struct.pack_into("<H", buf, usa_offset + 2 + i * 2, replacement)
        struct.pack_into("<H", buf, sector_end, usn)

    return bytes(buf)


def make_ntfs_image() -> Path:
    """Imagem raw com MBR + 1 partição NTFS funcional ($MFT com registros reais)."""
    FIXTURES_DIR.mkdir(exist_ok=True)
    out_path = FIXTURES_DIR / "sample_disk_ntfs.img"

    PART_START_LBA = 2048
    PART_OFFSET = PART_START_LBA * 512
    SECTOR_SIZE = 512
    CLUSTER_SIZE = 512
    RECORD_SIZE = 1024
    MFT_LCN = 4
    MFT_CLUSTERS = 32  # 32*512 = 16384 bytes = 16 registros de 1024 bytes
    NUM_RECORDS = MFT_CLUSTERS * CLUSTER_SIZE // RECORD_SIZE

    total_size = PART_OFFSET + (MFT_LCN + MFT_CLUSTERS + 10) * CLUSTER_SIZE
    image = bytearray(total_size)

    entry = struct.pack("<BBBBBBBBII", 0x00, 0, 0, 0, 0x07, 0, 0, 0, PART_START_LBA, 20480)
    image[446:446 + len(entry)] = entry
    image[510:512] = b"\x55\xaa"

    boot_off = PART_OFFSET
    image[boot_off + 3: boot_off + 11] = b"NTFS    "
    struct.pack_into("<H", image, boot_off + 0x0B, SECTOR_SIZE)
    image[boot_off + 0x0D] = CLUSTER_SIZE // SECTOR_SIZE
    struct.pack_into("<Q", image, boot_off + 0x30, MFT_LCN)
    image[boot_off + 0x40] = (256 - 10) if RECORD_SIZE == 1024 else 2  # -10 => 2^10 = 1024

    now = datetime(2026, 4, 1, 15, 30, 0, tzinfo=timezone.utc)

    # Registro 0: $MFT — DATA não residente descrevendo seu próprio extent físico
    mft_size = MFT_CLUSTERS * CLUSTER_SIZE
    data_runs = bytes([0x11, MFT_CLUSTERS, MFT_LCN, 0x00])  # 1 byte tamanho, 1 byte delta LCN
    record0_attrs = [_ntfs_non_resident_attr(ATTR_DATA, data_runs, 0, mft_size, 0, MFT_CLUSTERS - 1)]
    record0 = _ntfs_build_record(RECORD_SIZE, SECTOR_SIZE, in_use=True, is_dir=False, attrs=record0_attrs)

    # Registro 5: diretório raiz
    root_fn = _ntfs_file_name_attr(5, ".", True, 0, now, 0)
    record5 = _ntfs_build_record(RECORD_SIZE, SECTOR_SIZE, in_use=True, is_dir=True, attrs=[root_fn])

    # Registro 6: HELLO.TXT (arquivo normal, DATA residente)
    hello_content = b"Conteudo do arquivo NTFS de teste.\n"
    hello_fn = _ntfs_file_name_attr(5, "HELLO.TXT", False, len(hello_content), now, 0)
    hello_data = _ntfs_resident_attr(ATTR_DATA, hello_content, 1)
    record6 = _ntfs_build_record(RECORD_SIZE, SECTOR_SIZE, in_use=True, is_dir=False, attrs=[hello_fn, hello_data])

    # Registro 7: SECRET.TXT (deletado — in_use=False, mas ainda presente na $MFT)
    secret_content = b"Conteudo NTFS deletado mas ainda na MFT.\n"
    secret_fn = _ntfs_file_name_attr(5, "SECRET.TXT", False, len(secret_content), now, 0)
    secret_data = _ntfs_resident_attr(ATTR_DATA, secret_content, 1)
    record7 = _ntfs_build_record(RECORD_SIZE, SECTOR_SIZE, in_use=False, is_dir=False, attrs=[secret_fn, secret_data])

    mft_table = bytearray(NUM_RECORDS * RECORD_SIZE)
    mft_table[0 * RECORD_SIZE: 1 * RECORD_SIZE] = record0
    mft_table[5 * RECORD_SIZE: 6 * RECORD_SIZE] = record5
    mft_table[6 * RECORD_SIZE: 7 * RECORD_SIZE] = record6
    mft_table[7 * RECORD_SIZE: 8 * RECORD_SIZE] = record7

    mft_offset = PART_OFFSET + MFT_LCN * CLUSTER_SIZE
    image[mft_offset: mft_offset + len(mft_table)] = mft_table

    out_path.write_bytes(bytes(image))
    return out_path


def _ext4_dirent(inode: int, name: str, file_type: int, rec_len: int) -> bytes:
    name_bytes = name.encode("utf-8")
    buf = bytearray(8 + len(name_bytes))
    struct.pack_into("<IHBB", buf, 0, inode, rec_len, len(name_bytes), file_type)
    buf[8: 8 + len(name_bytes)] = name_bytes
    return bytes(buf)


def _ext4_inode(mode: int, size: int, ts: int, dtime: int, links_count: int,
                 extent_block: int | None, extent_len: int, inode_size: int = 256) -> bytes:
    buf = bytearray(inode_size)
    struct.pack_into("<H", buf, 0, mode)
    struct.pack_into("<I", buf, 4, size)
    struct.pack_into("<IIII", buf, 8, ts, ts, ts, dtime)  # atime, ctime, mtime, dtime
    struct.pack_into("<H", buf, 26, links_count)
    flags = 0x80000 if extent_block is not None else 0
    struct.pack_into("<I", buf, 32, flags)
    if extent_block is not None:
        struct.pack_into("<HHHHI", buf, 40, 0xF30A, 1, 4, 0, 0)
        struct.pack_into("<IHHI", buf, 52, 0, extent_len, 0, extent_block)
    return bytes(buf)


def make_ext4_image() -> Path:
    """Imagem raw com MBR + 1 partição ext2/3/4 funcional (superbloco, tabela
    de grupo, tabela de inodes, diretório raiz com extents, 1 inode deletado)."""
    FIXTURES_DIR.mkdir(exist_ok=True)
    out_path = FIXTURES_DIR / "sample_disk_ext4.img"

    PART_START_LBA = 2048
    PART_OFFSET = PART_START_LBA * 512
    BLOCK_SIZE = 1024
    INODES_PER_GROUP = 32
    INODE_SIZE = 256
    INODES_COUNT = INODES_PER_GROUP

    SB_BLOCK = 1
    GD_BLOCK = 2
    INODE_TABLE_BLOCK = 3  # ocupa blocos 3..10 (32*256=8192 bytes = 8 blocos de 1024)
    ROOT_DIR_BLOCK = 11
    HELLO_DATA_BLOCK = 12

    total_blocks = 20
    image = bytearray(PART_OFFSET + total_blocks * BLOCK_SIZE)

    entry = struct.pack("<BBBBBBBBII", 0x00, 0, 0, 0, 0x83, 0, 0, 0, PART_START_LBA, 20480)
    image[446:446 + len(entry)] = entry
    image[510:512] = b"\x55\xaa"

    def block_off(n: int) -> int:
        return PART_OFFSET + n * BLOCK_SIZE

    sb_off = PART_OFFSET + 1024
    struct.pack_into("<I", image, sb_off + 0, INODES_COUNT)
    struct.pack_into("<I", image, sb_off + 4, total_blocks)
    struct.pack_into("<I", image, sb_off + 20, 1)  # first_data_block
    struct.pack_into("<I", image, sb_off + 24, 0)  # log_block_size => 1024 << 0
    struct.pack_into("<I", image, sb_off + 32, 8192)  # blocks_per_group
    struct.pack_into("<I", image, sb_off + 40, INODES_PER_GROUP)
    struct.pack_into("<H", image, sb_off + 56, 0xEF53)  # magic
    struct.pack_into("<H", image, sb_off + 88, INODE_SIZE)
    struct.pack_into("<I", image, sb_off + 96, 0x0002 | 0x0040)  # FILETYPE | EXTENTS

    gd_off = block_off(GD_BLOCK)
    struct.pack_into("<I", image, gd_off + 8, INODE_TABLE_BLOCK)  # bg_inode_table_lo

    now_epoch = int(datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc).timestamp())

    hello_content = b"Conteudo ext4 de teste.\n"
    secret_content_size = 999  # simula tamanho que ainda constava no inode antes do unlink

    root_inode = _ext4_inode(0x4000 | 0o755, BLOCK_SIZE, now_epoch, 0, 2, ROOT_DIR_BLOCK, 1)
    hello_inode = _ext4_inode(0x8000 | 0o644, len(hello_content), now_epoch, 0, 1, HELLO_DATA_BLOCK, 1)
    deleted_inode = _ext4_inode(0x8000 | 0o644, secret_content_size, now_epoch, now_epoch + 60, 0, None, 0)

    def write_inode(inode_num: int, data: bytes) -> None:
        index = inode_num - 1
        off = block_off(INODE_TABLE_BLOCK) + index * INODE_SIZE
        image[off: off + len(data)] = data

    write_inode(2, root_inode)   # raiz
    write_inode(11, hello_inode)
    write_inode(12, deleted_inode)

    root_block = bytearray(BLOCK_SIZE)
    dirent_offset = 0
    for inode_num, name, ftype, rec_len in (
        (2, ".", 2, 12),
        (2, "..", 2, 12),
        (11, "hello.txt", 1, BLOCK_SIZE - 24),
    ):
        entry_bytes = _ext4_dirent(inode_num, name, ftype, rec_len)
        root_block[dirent_offset: dirent_offset + len(entry_bytes)] = entry_bytes
        dirent_offset += rec_len  # próxima entrada começa no rec_len da anterior (alinhamento ext4)
    root_block_off = block_off(ROOT_DIR_BLOCK)
    image[root_block_off: root_block_off + len(root_block)] = root_block

    hello_block_off = block_off(HELLO_DATA_BLOCK)
    image[hello_block_off: hello_block_off + len(hello_content)] = hello_content

    out_path.write_bytes(bytes(image))
    return out_path


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
    ab_encrypted = make_encrypted_android_backup()
    img = make_disk_image()
    ntfs_img = make_ntfs_image()
    ext4_img = make_ext4_image()
    ios_dir = make_ios_backup()
    dvr_dir = make_dvr_folder()
    can_log = make_can_log()
    print(f"Backup Android: {ab}")
    print(f"Backup Android criptografado (senha: senha-conhecida-123): {ab_encrypted}")
    print(f"Imagem de disco (FAT32): {img}")
    print(f"Imagem de disco (NTFS): {ntfs_img}")
    print(f"Imagem de disco (ext4): {ext4_img}")
    print(f"Backup iOS: {ios_dir}")
    print(f"Pasta DVR: {dvr_dir}")
    print(f"Log CAN: {can_log}")
