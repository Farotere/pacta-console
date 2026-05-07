from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Severity = Literal["high", "medium", "low"]

DataType = Literal[
    "email",
    "phone_fr",
    "iban",
    "social_security",
    "credit_card",
    "ip_internal",
    "ip_external",
    "password_inline",
    "api_key",
    "jwt_token",
    "crypto_wallet",
    "passport",
    "address_fr",
    "siret",
    "bank_bic",
]


@dataclass
class Match:
    type: DataType
    severity: Severity
    masked: str    # valeur masquée, jamais la vraie
    start: int
    end: int


def _mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


_PATTERNS: list[tuple[DataType, Severity, re.Pattern]] = [
    # Emails
    (
        "email", "medium",
        re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    ),
    # Téléphones français (mobile + fixe)
    (
        "phone_fr", "medium",
        re.compile(r"\b(?:(?:\+33|0033|0)[1-9](?:[\s.\-]?\d{2}){4})\b"),
    ),
    # IBAN (international, commence par 2 lettres + chiffres)
    (
        "iban", "high",
        re.compile(r"\b[A-Z]{2}\d{2}[\s]?(?:[A-Z0-9]{4}[\s]?){4,7}\b"),
    ),
    # Numéro de sécurité sociale français (15 chiffres, commence par 1 ou 2)
    (
        "social_security", "high",
        re.compile(r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b"),
    ),
    # Cartes bancaires (Visa, Mastercard, Amex)
    (
        "credit_card", "high",
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?:[\s\-]?\d{3})?\b"),
    ),
    # IP internes (RFC 1918)
    (
        "ip_internal", "low",
        re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
    ),
    # IP publiques
    (
        "ip_external", "low",
        re.compile(r"\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)(?:[1-9]\d{0,2}\.){3}[1-9]\d{0,2}\b"),
    ),
    # Mots de passe en clair — séparateur obligatoire pour éviter les noms de champs JSON
    (
        "password_inline", "high",
        re.compile(r"(?i)(?:password|passwd|pwd|mdp|secret|mot[\s_\-]?de[\s_\-]?passe)\s*(?:[=:\-]|(?:est|is|c'?est|vaut)\s)\s*\S{3,}"),
    ),
    # Clés API génériques (sk-, pk-, Bearer, api_key=)
    (
        "api_key", "high",
        re.compile(r"(?i)(?:api[_\-]?key|access[_\-]?token|secret[_\-]?key)\s*[=:]\s*[A-Za-z0-9\-_\.]{16,}"),
    ),
    # JWT tokens
    (
        "jwt_token", "high",
        re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
    ),
    # Adresses de wallets crypto — keyword requis pour Bitcoin (trop de faux positifs sinon)
    (
        "crypto_wallet", "medium",
        re.compile(
            r"(?i)(?:wallet|bitcoin|btc|ethereum|eth|crypto|address|addr)\s*[=:\s]\s*"
            r"(?:(?:1|3)[A-HJ-NP-Za-km-z1-9]{25,34}|0x[a-fA-F0-9]{40})"
            r"|0x[a-fA-F0-9]{40}\b"  # Ethereum seul reste détectable sans keyword
        ),
    ),
    # Numéros de passeport français (2 lettres + 7 chiffres)
    (
        "passport", "high",
        re.compile(r"\b[A-Z]{2}\d{7}\b"),
    ),
    # SIRET (14 chiffres précédés du mot-clé pour éviter les faux positifs)
    (
        "siret", "low",
        re.compile(r"(?i)(?:siret|siren)\s*[:\-n°]*\s*\d{3}[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{5}\b"),
    ),
    # BIC/SWIFT — keyword requis (sinon trop de faux positifs sur IDs et tokens)
    (
        "bank_bic", "medium",
        re.compile(r"(?i)(?:bic|swift|code\s+(?:bic|swift))\s*[=:\s]\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?"),
    ),
]


def scan(text: str) -> list[Match]:
    """Analyse un texte et retourne la liste des données sensibles détectées."""
    results: list[Match] = []
    seen: set[tuple[int, int]] = set()

    for data_type, severity, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            if span in seen:
                continue
            seen.add(span)
            results.append(Match(
                type=data_type,
                severity=severity,
                masked=_mask(m.group()),
                start=m.start(),
                end=m.end(),
            ))

    results.sort(key=lambda x: x.start)
    return results


def has_sensitive_data(text: str) -> bool:
    return len(scan(text)) > 0


def highest_severity(matches: list[Match]) -> Severity | None:
    if not matches:
        return None
    order = {"high": 0, "medium": 1, "low": 2}
    return min(matches, key=lambda m: order[m.severity]).severity
