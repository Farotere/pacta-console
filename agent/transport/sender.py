from __future__ import annotations

import queue
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from agent.core.auth import get_token
from agent.core.config import load_config
from agent.core.logging import get_logger
from agent.notifications.toast import notify

_log = get_logger("sender")
_q: queue.Queue[dict] = queue.Queue()
_started = False
_lock = threading.Lock()


def _load_agent_id() -> str | None:
    state_file = Path.home() / ".pacta" / "agent.json"
    if not state_file.exists():
        return None
    import json
    try:
        return json.loads(state_file.read_text()).get("agent_id")
    except Exception:
        return None


def _send_loop() -> None:
    cfg = load_config()
    backoff = 5

    while True:
        event = _q.get()
        agent_id = _load_agent_id()
        if not agent_id:
            _log.warning("sender.no_agent_id_skip")
            continue

        payload = {
            "agent_id": agent_id,
            "detected_at": datetime.now(tz=UTC).isoformat(),
            "provider": event.get("provider"),
            "severity": event.get("severity"),
            "detected_types": event.get("detected_types", []),
            "match_count": event.get("match_count", 0),
            "prompt_hash": event.get("prompt_hash", ""),
            "prompt_length": event.get("prompt_length", 0),
        }

        for attempt in range(4):
            try:
                token = get_token()
                r = httpx.post(
                    f"{cfg.api.url}/events/ingest",
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                if r.status_code == 401:
                    # Token expiré — on vide le cache et on réessaie
                    from agent.core.auth import clear_token
                    clear_token()
                    continue
                r.raise_for_status()
                _log.info("sender.sent", provider=payload["provider"], event_id=r.json().get("id"))
                backoff = 5
                break
            except Exception as e:
                wait = backoff * (2 ** attempt)
                _log.warning("sender.retry", attempt=attempt + 1, wait=wait, error=str(e))
                time.sleep(wait)
        else:
            _log.error("sender.dropped", provider=payload["provider"])


def _heartbeat_loop() -> None:
    """Ping le backend toutes les 2 minutes pour signaler que l'agent est actif."""
    cfg = load_config()
    while True:
        time.sleep(120)
        try:
            token = get_token()
            httpx.post(
                f"{cfg.api.url}/agents/ping",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            _log.debug("heartbeat.ok")
        except Exception as e:
            _log.debug("heartbeat.failed", error=str(e))


def _ensure_started() -> None:
    global _started
    with _lock:
        if not _started:
            threading.Thread(target=_send_loop, daemon=True).start()
            threading.Thread(target=_heartbeat_loop, daemon=True).start()
            _started = True


def queue_event(event: dict) -> None:
    _ensure_started()
    _q.put(event)
    _log.info(
        "sender.queued",
        provider=event.get("provider"),
        severity=event.get("severity"),
        types=event.get("detected_types"),
    )
    threading.Thread(target=notify, args=(event,), daemon=True).start()
