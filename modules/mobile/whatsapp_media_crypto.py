"""Decodificação de mídia do WhatsApp (fotos, vídeos, áudios, documentos
enviados/recebidos) — formato publicamente documentado (usado por diversas
ferramentas open source independentes, ex: "WhatsApp-Media-Decrypt" e
variantes em várias linguagens, todas convergindo no mesmo esquema):

    chave_derivada = HKDF-SHA256(media_key, salt=b"\\x00"*32, info=<string
                      específica do tipo de mídia>, length=112)
    iv          = chave_derivada[0:16]
    cipher_key  = chave_derivada[16:48]
    mac_key     = chave_derivada[48:80]
    # chave_derivada[80:112] = "ref key", não usada para decodificar

    mac_recebido = arquivo[-10:]
    ciphertext   = arquivo[:-10]
    mac_esperado = HMAC-SHA256(mac_key, iv + ciphertext)[:10]  # deve bater
    plaintext    = AES-256-CBC-decrypt(cipher_key, iv, ciphertext)  # com padding PKCS7

A `media_key` vem do próprio banco de mensagens já decodificado
(`message_media.key`/`media_key`, 32 bytes) — não é uma senha a descobrir.
"""
from __future__ import annotations

import hmac
from hashlib import sha256

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO_BY_MEDIA_TYPE = {
    "image": b"WhatsApp Image Keys",
    "video": b"WhatsApp Video Keys",
    "audio": b"WhatsApp Audio Keys",
    "document": b"WhatsApp Document Keys",
    "sticker": b"WhatsApp Image Keys",  # stickers usam o mesmo esquema de imagem
}


class WhatsAppMediaDecryptError(Exception):
    pass


def decrypt_media(media_key: bytes, encrypted: bytes, media_type: str) -> bytes:
    info = HKDF_INFO_BY_MEDIA_TYPE.get(media_type.lower())
    if info is None:
        raise WhatsAppMediaDecryptError(f"Tipo de mídia desconhecido: {media_type!r}")
    if len(media_key) != 32:
        raise WhatsAppMediaDecryptError(f"media_key deve ter 32 bytes, tem {len(media_key)}")
    if len(encrypted) < 10:
        raise WhatsAppMediaDecryptError("Arquivo pequeno demais para conter MAC.")

    derived = HKDF(algorithm=hashes.SHA256(), length=112, salt=b"\x00" * 32, info=info).derive(media_key)
    iv, cipher_key, mac_key = derived[0:16], derived[16:48], derived[48:80]

    ciphertext, received_mac = encrypted[:-10], encrypted[-10:]
    expected_mac = hmac.new(mac_key, iv + ciphertext, sha256).digest()[:10]
    if not hmac.compare_digest(expected_mac, received_mac):
        raise WhatsAppMediaDecryptError("MAC inválido — media_key incorreta ou arquivo corrompido.")

    decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise WhatsAppMediaDecryptError(f"Padding inválido ao remover PKCS7: {exc}") from exc
