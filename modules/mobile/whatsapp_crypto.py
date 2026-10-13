"""Decodificação de backups do WhatsApp (.crypt12/.crypt14/.crypt15).

Formato publicamente documentado e replicado por diversas ferramentas open
source (ex: projeto `wa-crypt-tools`, GPL-3.0 — consultado apenas para
confirmar o formato; nada do código deles foi copiado, esta é uma
implementação própria usando `cryptography` e `javaobj-py3`).

Pressupõe que o examinador já tem o arquivo de chave extraído do aparelho
(`/data/data/com.whatsapp/files/key` para crypt12/14, ou
`encrypted_backup.key`/a chave de 64 dígitos hex exibida pelo próprio
WhatsApp para crypt15) — decodifica dados já adquiridos, não quebra senha
nenhuma.

Resumo do formato:
- Arquivo de chave: um `byte[]` serializado em Java. Depois de
  desserializado: 131 bytes (crypt12/14, AES key = últimos 32 bytes) ou
  32 bytes (crypt15, "chave raiz" que precisa passar por HKDF-SHA256 com
  salt zerado e info=b"backup encryption" para virar a chave AES real).
- crypt12: header fixo de 67 bytes (cipher_version[2] + key_version[1] +
  server_salt[32] + google_id[16] + IV[16]); rodapé
  [tag(16)][checksum_md5(16)][jid(4)].
- crypt14/crypt15: header = varint (tamanho) + mensagem protobuf
  `BackupPrefix`, que carrega o IV dentro de um campo aninhado
  (`wa_provided_key_data.encryption_iv` para crypt14,
  `e2ee_key_data.encryption_iv` para crypt15); rodapé [tag(16)][checksum(16)].
- Cifra: AES-256-GCM em todos os três formatos.
"""
from __future__ import annotations

import io

import javaobj
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SQLITE_MAGIC = b"SQLite format 3\x00"


class WhatsAppDecryptError(Exception):
    pass


def load_key_payload_from_file(path) -> bytes:
    """Desserializa um `byte[]` do Java (formato do arquivo de chave do
    WhatsApp) e devolve os bytes sem sinal (0-255) corretos."""
    with open(path, "rb") as f:
        try:
            java_array = javaobj.load(f)
        except Exception as exc:  # noqa: BLE001 — qualquer erro de parsing vira um erro claro nosso
            raise WhatsAppDecryptError(f"Arquivo de chave não é um objeto Java serializado válido: {exc}") from exc
    return bytes(v & 0xFF for v in java_array)


def key_payload_from_hex(hex_string: str) -> bytes:
    hex_string = hex_string.strip()
    if len(hex_string) != 64:
        raise WhatsAppDecryptError("Chave em hexadecimal deve ter 64 dígitos (32 bytes) — só válida para crypt15.")
    try:
        return bytes.fromhex(hex_string)
    except ValueError as exc:
        raise WhatsAppDecryptError(f"Chave em hexadecimal inválida: {exc}") from exc


def derive_aes_key(key_payload: bytes) -> bytes:
    if len(key_payload) == 131:
        return key_payload[99:131]  # crypt12/14: a chave já é o trecho final do arquivo de chave
    if len(key_payload) == 32:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=b"backup encryption").derive(
            key_payload
        )
    raise WhatsAppDecryptError(
        f"Tamanho de chave não reconhecido: {len(key_payload)} bytes (esperado 131 para crypt12/14 ou 32 para crypt15)."
    )


def _parse_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise WhatsAppDecryptError("Varint do cabeçalho protobuf truncado.")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _parse_protobuf_fields(data: bytes) -> dict[int, bytes]:
    """Parser mínimo: só extrai campos wire-type 2 (length-delimited —
    bytes/string/submensagem), que é tudo que o BackupPrefix usa para os
    campos que nos interessam. Suficiente para este formato específico,
    não é um parser protobuf genérico."""
    fields: dict[int, bytes] = {}
    pos = 0
    while pos < len(data):
        tag, pos = _parse_varint(data, pos)
        field_num, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:
            _, pos = _parse_varint(data, pos)
        elif wire_type == 2:
            length, pos = _parse_varint(data, pos)
            fields[field_num] = data[pos: pos + length]
            pos += length
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            raise WhatsAppDecryptError(f"Wire type protobuf não suportado: {wire_type}")
    return fields


def decrypt_crypt14_or_15(raw: bytes, aes_key: bytes) -> bytes:
    header_len, pos = _parse_varint(raw, 0)
    header = raw[pos: pos + header_len]
    body = raw[pos + header_len:]
    if len(header) != header_len:
        raise WhatsAppDecryptError("Cabeçalho protobuf truncado — arquivo corrompido ou formato inesperado.")

    outer = _parse_protobuf_fields(header)
    iv = None
    if 2 in outer:  # wa_provided_key_data -> crypt14
        iv = _parse_protobuf_fields(outer[2]).get(5)
    if iv is None and 3 in outer:  # e2ee_key_data -> crypt15
        iv = _parse_protobuf_fields(outer[3]).get(1)
    if iv is None or len(iv) != 16:
        raise WhatsAppDecryptError("Não foi possível extrair o IV do cabeçalho do backup.")

    if len(body) < 32:
        raise WhatsAppDecryptError("Arquivo pequeno demais para conter dados cifrados + tag + checksum.")
    encrypted_data = body[:-32]
    auth_tag = body[-32:-16]
    # body[-16:] é o checksum MD5 do arquivo — não validamos aqui; a tag GCM já garante
    # integridade, e uma chave/IV errados vão falhar no decrypt() abaixo de forma clara.

    try:
        return AESGCM(aes_key).decrypt(iv, encrypted_data + auth_tag, None)
    except InvalidTag as exc:
        raise WhatsAppDecryptError("Falha na verificação da tag GCM — chave incorreta ou arquivo corrompido.") from exc


def decrypt_crypt12(raw: bytes, aes_key: bytes) -> bytes:
    if len(raw) < 67 + 36:
        raise WhatsAppDecryptError("Arquivo pequeno demais para um crypt12 válido.")
    iv = raw[51:67]
    body = raw[67:]
    encrypted_data = body[:-36]
    auth_tag = body[-36:-20]
    # body[-20:-4] = checksum MD5, body[-4:] = sufixo do JID — não usados na decodificação.

    try:
        return AESGCM(aes_key).decrypt(iv, encrypted_data + auth_tag, None)
    except InvalidTag as exc:
        raise WhatsAppDecryptError("Falha na verificação da tag GCM — chave incorreta ou arquivo corrompido.") from exc
