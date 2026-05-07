from __future__ import annotations

import hashlib
import platform
import uuid
from pathlib import Path

_CACHE_FILE = Path.home() / ".pacta" / "fingerprint"


def _generate() -> str:
    """Génère un fingerprint stable basé sur le machine-id ou les infos système."""
    machine_id_paths = [
        Path("/etc/machine-id"),
        Path("/var/lib/dbus/machine-id"),
    ]
    for path in machine_id_paths:
        if path.exists():
            raw = path.read_text().strip()
            return hashlib.sha256(raw.encode()).hexdigest()[:64]

    # Fallback : hash des infos système
    raw = f"{platform.node()}-{platform.machine()}-{uuid.getnode()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def get_fingerprint() -> str:
    """Retourne le fingerprint stable de la machine, en le mettant en cache."""
    _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _CACHE_FILE.exists():
        return _CACHE_FILE.read_text().strip()
    fp = _generate()
    _CACHE_FILE.write_text(fp)
    return fp
