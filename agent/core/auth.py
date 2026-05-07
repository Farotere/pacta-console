"""Authentification de l'agent — flux d'enrôlement par token.

Flux au premier démarrage :
  1. Aucune credentials dans ~/.pacta/agent.json
  2. Lecture du enrollment_token depuis config.yml
  3. POST /agents/enroll → reçoit agent_id + agent_secret (une seule fois)
  4. Sauvegarde dans ~/.pacta/agent.json
  5. POST /agents/auth → reçoit un JWT court (15 min), mis en cache

Flux nominal :
  1. Lecture agent_id + agent_secret depuis ~/.pacta/agent.json
  2. Si le JWT est en cache et valide → retourne directement
  3. Sinon POST /agents/auth → nouveau JWT
"""

from __future__ import annotations

import json
import platform
import socket
import time
import uuid
from pathlib import Path

import httpx

from agent.core.config import get_config
from agent.core.logging import get_logger

_AGENT_FILE = Path.home() / ".pacta" / "agent.json"
_TOKEN_FILE = Path.home() / ".pacta" / "token.json"
_DEVICE_FILE = Path.home() / ".pacta" / "device.json"
_log = get_logger("auth")

AGENT_VERSION = "0.2.0"


# ---------------------------------------------------------------------------
# Device fingerprint (stable par machine)
# ---------------------------------------------------------------------------

def _get_device_fingerprint() -> str:
    """Retourne un UUID stable pour ce poste, généré une seule fois."""
    _DEVICE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _DEVICE_FILE.exists():
        try:
            return json.loads(_DEVICE_FILE.read_text())["fingerprint"]
        except Exception:
            pass
    fingerprint = str(uuid.uuid4())
    _DEVICE_FILE.write_text(json.dumps({"fingerprint": fingerprint}))
    return fingerprint


def _get_platform() -> str:
    sys = platform.system().lower()
    if sys == "windows":
        return "windows"
    if sys == "darwin":
        return "macos"
    return "linux"


# ---------------------------------------------------------------------------
# JWT cache
# ---------------------------------------------------------------------------

def _load_token() -> str | None:
    if not _TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(_TOKEN_FILE.read_text())
        token = data.get("access_token")
        saved_at = data.get("saved_at", 0)
        if not token or (time.time() - saved_at) > 840:  # 14 min (JWT dure 15 min)
            _TOKEN_FILE.unlink()
            return None
        return token
    except Exception:
        return None


def _save_token(token: str) -> None:
    _TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    _TOKEN_FILE.write_text(json.dumps({"access_token": token, "saved_at": time.time()}))


def clear_token() -> None:
    if _TOKEN_FILE.exists():
        _TOKEN_FILE.unlink()


# ---------------------------------------------------------------------------
# Agent credentials (agent_id + agent_secret)
# ---------------------------------------------------------------------------

def _load_agent_credentials() -> tuple[str, str] | None:
    """Retourne (agent_id, agent_secret) ou None si non enrôlé."""
    if not _AGENT_FILE.exists():
        return None
    try:
        data = json.loads(_AGENT_FILE.read_text())
        agent_id = data.get("agent_id")
        agent_secret = data.get("agent_secret")
        if agent_id and agent_secret:
            return agent_id, agent_secret
    except Exception:
        pass
    return None


def _save_agent_credentials(agent_id: str, agent_secret: str) -> None:
    _AGENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _AGENT_FILE.write_text(json.dumps({
        "agent_id": agent_id,
        "agent_secret": agent_secret,
        "enrolled_at": time.time(),
    }))


# ---------------------------------------------------------------------------
# Enrôlement (première fois uniquement)
# ---------------------------------------------------------------------------

def _enroll() -> tuple[str, str]:
    """Consomme le token d'enrôlement → retourne (agent_id, agent_secret)."""
    import os
    cfg = get_config()
    enrollment_token = cfg.api.enrollment_token or os.environ.get("PACTA_ENROLLMENT_TOKEN", "")
    if not enrollment_token:
        raise RuntimeError(
            "Aucun token d'enrôlement configuré.\n"
            "Générez-en un depuis la console Pacta (Agents → Enrôler un agent)\n"
            "puis ajoutez-le dans config.yml :\n"
            "  api:\n"
            "    enrollment_token: pact_enroll_xxxxx"
        )

    _log.info("auth.enrolling", hostname=socket.gethostname())
    try:
        resp = httpx.post(
            f"{cfg.api.url}/agents/enroll",
            json={
                "token": enrollment_token,
                "hostname": socket.gethostname(),
                "device_fingerprint": _get_device_fingerprint(),
                "platform": _get_platform(),
                "agent_version": AGENT_VERSION,
            },
            timeout=15,
        )
    except httpx.ConnectError as e:
        raise RuntimeError(f"Impossible de joindre le backend Pacta ({cfg.api.url})") from e

    if resp.status_code == 401:
        detail = resp.json().get("detail", "")
        raise RuntimeError(f"Token d'enrôlement invalide ou expiré : {detail}")
    resp.raise_for_status()

    data = resp.json()
    agent_id = data["agent_id"]
    agent_secret = data["agent_secret"]
    _save_agent_credentials(agent_id, agent_secret)
    _log.info("auth.enrolled", agent_id=agent_id)
    return agent_id, agent_secret


# ---------------------------------------------------------------------------
# Auth M2M (échange credentials → JWT court)
# ---------------------------------------------------------------------------

def _agent_login(agent_id: str, agent_secret: str) -> str:
    """Échange agent_id + agent_secret contre un JWT de 15 minutes."""
    cfg = get_config()
    try:
        resp = httpx.post(
            f"{cfg.api.url}/agents/auth",
            json={"agent_id": agent_id, "agent_secret": agent_secret},
            timeout=10,
        )
    except httpx.ConnectError as e:
        raise RuntimeError(f"Impossible de joindre le backend Pacta ({cfg.api.url})") from e

    if resp.status_code == 401:
        # Secret invalide (re-enrôlement nécessaire)
        _AGENT_FILE.unlink(missing_ok=True)
        clear_token()
        raise RuntimeError(
            "Identifiants agent invalides — re-enrôlement nécessaire.\n"
            "Supprimez ~/.pacta/agent.json et relancez l'agent."
        )
    resp.raise_for_status()

    token = resp.json()["access_token"]
    _save_token(token)
    _log.info("auth.login_success", agent_id=agent_id)
    return token


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def get_token() -> str:
    """Retourne un JWT valide.

    Enrôle automatiquement si c'est le premier démarrage.
    """
    # 1. JWT encore valide en cache → retour immédiat
    cached = _load_token()
    if cached:
        return cached

    # 2. Credentials agent présentes → login M2M
    creds = _load_agent_credentials()
    if creds is None:
        # 3. Premier démarrage → enrôlement
        creds = _enroll()

    agent_id, agent_secret = creds
    return _agent_login(agent_id, agent_secret)
