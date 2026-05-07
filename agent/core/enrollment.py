from __future__ import annotations

import json
import platform
import socket
from pathlib import Path

import httpx

from agent import __version__
from agent.core.auth import get_token
from agent.core.config import get_config
from agent.core.fingerprint import get_fingerprint
from agent.core.logging import get_logger

_STATE_FILE = Path.home() / ".pacta" / "agent.json"
_log = get_logger("enrollment")


def _load_state() -> dict | None:
    if _STATE_FILE.exists():
        return json.loads(_STATE_FILE.read_text())
    return None


def _save_state(agent_id: str, organization_id: str) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps({
        "agent_id": agent_id,
        "organization_id": organization_id,
    }))


def enroll() -> dict:
    """Enrôle l'agent au premier démarrage, sinon retourne l'état local."""
    state = _load_state()
    if state:
        _log.info("enrollment.already_enrolled", agent_id=state["agent_id"])
        return state

    cfg = get_config()
    token = get_token()

    payload = {
        "hostname": socket.gethostname(),
        "device_fingerprint": get_fingerprint(),
        "platform": platform.system().lower(),
        "agent_version": __version__,
    }

    _log.info("enrollment.enrolling", hostname=payload["hostname"], fingerprint=payload["device_fingerprint"][:12] + "...")

    resp = httpx.post(
        f"{cfg.api.url}/agents/enroll",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    resp.raise_for_status()

    data = resp.json()
    _save_state(data["agent_id"], data["organization_id"])
    _log.info("enrollment.success", agent_id=data["agent_id"])
    return data
