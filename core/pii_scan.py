"""Busca por padrões de dados sensíveis em texto já extraído/indexado —
inspirado na busca por cartão de crédito/e-mail/URL/carteiras de
criptomoeda do IPED. Só expressões regulares sobre texto que o próprio
caso já indexou; não varre a internet nem tenta identificar pessoas.

Valores de cartão de crédito e CPF/CNPJ são mascarados ao serem
armazenados/exibidos — e-mail, URL, telefone e endereços de carteira
cripto costumam ser o próprio artefato de interesse da perícia, então
ficam completos.
"""
from __future__ import annotations

import re

PATTERNS: dict[str, re.Pattern] = {
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "cpf": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    "cnpj": re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "btc_address": re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth_address": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "phone_br": re.compile(r"\b(?:\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b"),
}

MASKED_TYPES = {"credit_card", "cpf", "cnpj"}


def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _mask(pattern_type: str, value: str) -> str:
    digits = "".join(c for c in value if c.isdigit())
    if pattern_type == "credit_card":
        return f"**** **** **** {digits[-4:]}" if len(digits) >= 4 else "****"
    if pattern_type in ("cpf", "cnpj"):
        return f"{value[:3]}.***.***-{value[-2:]}" if len(value) >= 5 else "***"
    return value


def scan_text(text: str, enabled_patterns: list[str]) -> list[dict]:
    """Retorna [{"type": ..., "value": ... (mascarado se sensível)}, ...],
    sem duplicar o mesmo (tipo, valor_bruto) mais de uma vez por texto."""
    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for name in enabled_patterns:
        pattern = PATTERNS.get(name)
        if not pattern:
            continue
        for m in pattern.finditer(text):
            raw_value = m.group(0)
            if name == "url":
                raw_value = raw_value.rstrip(",.;:)]}>'\"")
            if name == "credit_card" and not luhn_valid(raw_value):
                continue
            key = (name, raw_value)
            if key in seen:
                continue
            seen.add(key)
            display_value = _mask(name, raw_value) if name in MASKED_TYPES else raw_value
            hits.append({"type": name, "value": display_value})

    return hits
