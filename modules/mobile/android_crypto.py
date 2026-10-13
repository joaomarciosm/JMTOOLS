"""Decodificação de backup Android ADB criptografado — algoritmo documentado
publicamente pelo próprio AOSP (frameworks/base, BackupManagerService) e
replicado por ferramentas open source como `android-backup-extractor`.

Pressupõe que o examinador já conhece a senha (ela foi definida pelo dono do
aparelho e é fornecida legalmente) — isto decodifica dados já adquiridos,
não "quebra" nem força senha nenhuma.

Escopo: valida o resultado via padding PKCS7 e abertura do tar resultante.
NÃO reimplementa a verificação do checksum MAC do cabeçalho (linha 6 do
header), que historicamente teve duas variantes incompatíveis entre versões
do Android por um bug de conversão de charset — ver docs/roadmap.md. Se a
senha estiver errada, o padding PKCS7 ou a abertura do tar vão falhar com um
erro claro, então a ausência da checagem de checksum não arrisca aceitar
silenciosamente um resultado corrompido.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AndroidBackupDecryptError(Exception):
    pass


def _pbkdf2_sha1(password: bytes, salt: bytes, rounds: int, key_len: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=key_len, salt=salt, iterations=rounds)
    return kdf.derive(password)


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise AndroidBackupDecryptError("Dados vazios após decriptação — senha provavelmente incorreta.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise AndroidBackupDecryptError("Padding PKCS7 inválido — senha provavelmente incorreta.")
    return data[:-pad_len]


def decrypt_backup(
    password: str,
    user_salt: bytes,
    rounds: int,
    user_iv: bytes,
    master_key_blob: bytes,
    encrypted_payload: bytes,
) -> bytes:
    """Retorna o payload decriptado (tar, ou tar+zlib se compressed=1 no
    cabeçalho — a descompressão é responsabilidade do chamador)."""
    user_key = _pbkdf2_sha1(password.encode("utf-8"), user_salt, rounds, 32)

    try:
        decrypted_blob = _pkcs7_unpad(_aes_cbc_decrypt(user_key, user_iv, master_key_blob))
    except ValueError as exc:  # tamanho de bloco inválido etc.
        raise AndroidBackupDecryptError(f"Falha ao decriptar blob da chave mestra: {exc}") from exc

    pos = 0
    iv_len = decrypted_blob[pos]
    pos += 1
    master_iv = decrypted_blob[pos: pos + iv_len]
    pos += iv_len
    mk_len = decrypted_blob[pos]
    pos += 1
    master_key = decrypted_blob[pos: pos + mk_len]

    try:
        return _pkcs7_unpad(_aes_cbc_decrypt(master_key, master_iv, encrypted_payload))
    except ValueError as exc:
        raise AndroidBackupDecryptError(f"Falha ao decriptar payload principal: {exc}") from exc
