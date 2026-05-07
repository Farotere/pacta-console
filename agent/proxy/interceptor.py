from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from pathlib import Path

from mitmproxy import http
from mitmproxy.tools import dump

from agent.core.logging import get_logger
from agent.detectors.sensitive import highest_severity, scan

_log = get_logger("proxy")

# Préfixes de chemins à ignorer (télémétrie, analytics, pings)
_SKIP_PATH_PREFIXES: tuple[str, ...] = (
    "/ces/v1/",           # ChatGPT telemetry
    "/ces/statsc/",       # ChatGPT stats client
    "/backend-anon/sentinel/",
    "/backend-api/sentinel/",
    "/backend-anon/f/conversation/prepare",
    "/api/oauth/",
    "/api/event/",
    "/api/event_logging/",
    "/v1/b",              # Claude.ai telemetry/batching
    "/api/organizations/",  # Claude.ai org management (notifications, channels…)
)

# Providers IA surveillés
_AI_PROVIDERS: dict[str, str] = {
    "api.openai.com": "chatgpt",
    "chatgpt.com": "chatgpt",
    "chat.openai.com": "chatgpt",
    "api.anthropic.com": "claude",
    "claude.ai": "claude",
    "copilot.microsoft.com": "copilot",
    "generativelanguage.googleapis.com": "gemini",
    "gemini.google.com": "gemini",
    "api.mistral.ai": "mistral",
    "api.cohere.com": "cohere",
    "api.perplexity.ai": "perplexity",
}

# Callback appelé quand un event est détecté (branché depuis cli.py)
_event_callback = None


def set_event_callback(fn) -> None:
    global _event_callback
    _event_callback = fn


def _extract_strings(obj, depth: int = 0) -> list[str]:
    """Parcourt récursivement un objet JSON et extrait toutes les chaînes."""
    if depth > 10:
        return []
    if isinstance(obj, str):
        return [obj] if len(obj) > 3 else []
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_extract_strings(item, depth + 1))
        return out
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_extract_strings(v, depth + 1))
        return out
    return []


def _extract_prompt(content_type: str, body: bytes) -> str | None:
    """Extrait le texte du prompt depuis le body de la requête."""
    # Format JSON standard (OpenAI, Anthropic API, Claude web, ChatGPT web)
    try:
        if "application/json" in content_type:
            data = json.loads(body)
            if "messages" in data:
                parts = []
                for m in data["messages"]:
                    content = m.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        # Anthropic : [{"type": "text", "text": "..."}]
                        for block in content:
                            if isinstance(block, dict):
                                parts.append(block.get("text", ""))
                    elif isinstance(content, dict):
                        # ChatGPT web : {"content_type": "text", "parts": ["..."]}
                        for part in content.get("parts", []):
                            if isinstance(part, str):
                                parts.append(part)
                extracted = " ".join(p for p in parts if p)
                return extracted if extracted.strip() else None
            if "prompt" in data:
                return str(data["prompt"])
            # Pas de prompt détectable → on ne scanne pas ce payload
            return None
    except Exception:
        pass

    # Format Google RPC — Gemini web app (f.req=[[...]] URL-encodé)
    try:
        if "x-www-form-urlencoded" in content_type or b"f.req=" in body:
            decoded = urllib.parse.unquote_plus(body.decode("utf-8", errors="ignore"))
            # Extraire la valeur de f.req
            match = re.search(r"f\.req=(.+?)(?:&|$)", decoded)
            raw = match.group(1) if match else decoded
            # Parser le JSON imbriqué (peut être doublement encodé)
            try:
                outer = json.loads(raw)
                strings = _extract_strings(outer)
                # Essayer de re-parser les chaînes qui ressemblent à du JSON
                all_strings = []
                for s in strings:
                    if s.startswith("[") or s.startswith("{"):
                        try:
                            all_strings.extend(_extract_strings(json.loads(s)))
                        except Exception:
                            all_strings.append(s)
                    else:
                        all_strings.append(s)
                return " ".join(all_strings)
            except Exception:
                return decoded
    except Exception:
        pass

    # Contenu binaire (images, multipart…) — on ne scanne pas
    return None


class PactaInterceptor:
    """Addon mitmproxy — analyse les requêtes sortantes vers les providers IA."""

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        # Log toutes les requêtes pour diagnostic
        _log.debug("proxy.request", method=flow.request.method, host=host)

        provider = next((v for k, v in _AI_PROVIDERS.items() if host.endswith(k)), None)
        if not provider:
            return
        path = flow.request.path
        if any(path.startswith(p) for p in _SKIP_PATH_PREFIXES):
            return
        _log.info("proxy.ai_request", provider=provider, method=flow.request.method, path=path)
        if flow.request.method != "POST":
            return

        content_type = flow.request.headers.get("content-type", "")
        prompt = _extract_prompt(content_type, flow.request.content)
        if not prompt:
            return
        # _log.debug("proxy.prompt_extracted", provider=provider, length=len(prompt), preview=prompt[:120])

        matches = scan(prompt)
        if not matches:
            _log.debug("proxy.clean", provider=provider, host=host)
            return

        severity = highest_severity(matches)
        detected_types = list({m.type for m in matches})

        _log.warning(
            "proxy.sensitive_data_detected",
            provider=provider,
            severity=severity,
            types=detected_types,
            count=len(matches),
        )

        if _event_callback:
            _event_callback({
                "provider": provider,
                "severity": severity,
                "detected_types": detected_types,
                "match_count": len(matches),
                "masked_values": [m.masked for m in matches],
                "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
                "prompt_length": len(prompt),
            })


def _dbus_env() -> dict:
    """Retourne l'env D-Bus de session pour l'utilisateur courant (uid réel)."""
    import os
    import pwd
    uid = os.getuid()
    # Sous un service system lancé avec User=xxx, getuid() retourne l'uid de cet user
    env = os.environ.copy()
    bus_path = f"/run/user/{uid}/bus"
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"
    # gsettings a aussi besoin de HOME pour trouver le keyfile backend
    try:
        env.setdefault("HOME", pwd.getpwuid(uid).pw_dir)
    except Exception:
        pass
    return env


def _set_system_proxy(host: str, port: int) -> None:
    """Configure le proxy GNOME/système pour intercepter le trafic HTTP/HTTPS."""
    import subprocess
    env = _dbus_env()
    cmds = [
        ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
        ["gsettings", "set", "org.gnome.system.proxy.http", "host", host],
        ["gsettings", "set", "org.gnome.system.proxy.http", "port", str(port)],
        ["gsettings", "set", "org.gnome.system.proxy.https", "host", host],
        ["gsettings", "set", "org.gnome.system.proxy.https", "port", str(port)],
        ["gsettings", "set", "org.gnome.system.proxy", "ignore-hosts",
         "['localhost', '127.0.0.0/8', '::1', '*.local']"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, capture_output=True, env=env)
        except Exception:
            pass
    _log.info("proxy.system_proxy_set", host=host, port=port)


def _clear_system_proxy() -> None:
    """Remet le proxy système en mode automatique (aucun proxy)."""
    import subprocess
    try:
        subprocess.run(
            ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"],
            check=True, capture_output=True, env=_dbus_env(),
        )
    except Exception:
        pass
    _log.info("proxy.system_proxy_cleared")


def start_proxy(port: int = 8080) -> None:
    """Lance le proxy mitmproxy sur le port donné et configure le proxy système."""
    import asyncio
    import logging
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    for noisy in ("hpack", "mitmproxy", "asyncio", "h2", "hyperframe", "wsproto"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    _set_system_proxy("127.0.0.1", port)

    async def _run() -> None:
        import os
        confdir = os.environ.get("MITMPROXY_HOME", str(Path.home() / ".mitmproxy"))
        options = Options(listen_host="127.0.0.1", listen_port=port, confdir=confdir)
        master = DumpMaster(options, with_termlog=False, with_dumper=False)
        master.addons.add(PactaInterceptor())
        _log.info("proxy.start", port=port)
        try:
            await master.run()
        except KeyboardInterrupt:
            master.shutdown()
            _log.info("proxy.stop")

    try:
        asyncio.run(_run())
    finally:
        _clear_system_proxy()
