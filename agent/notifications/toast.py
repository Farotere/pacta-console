from __future__ import annotations

from agent.core.logging import get_logger

_log = get_logger("notifications")

_SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}

_TYPE_LABELS: dict[str, str] = {
    "email": "Adresse email",
    "phone_fr": "Numéro de téléphone",
    "iban": "IBAN",
    "social_security": "Numéro de sécurité sociale",
    "credit_card": "Carte bancaire",
    "ip_internal": "IP interne",
    "ip_external": "IP externe",
    "password_inline": "Mot de passe",
    "api_key": "Clé API",
    "jwt_token": "Token JWT",
    "crypto_wallet": "Wallet crypto",
    "passport": "Numéro de passeport",
    "siret": "SIRET",
    "bank_bic": "BIC bancaire",
}

_PROVIDER_LABELS: dict[str, str] = {
    "chatgpt": "ChatGPT",
    "claude": "Claude",
    "gemini": "Gemini",
    "copilot": "Copilot",
    "mistral": "Mistral",
    "cohere": "Cohere",
    "perplexity": "Perplexity",
}


def notify(event: dict) -> None:
    severity = event.get("severity", "low")
    provider = event.get("provider", "IA")
    detected_types = event.get("detected_types", [])

    emoji = _SEVERITY_EMOJI.get(severity, "⚠️")
    provider_label = _PROVIDER_LABELS.get(provider, provider.capitalize())
    types_label = ", ".join(_TYPE_LABELS.get(t, t) for t in detected_types)

    title = f"{emoji} Pacta — Donnée sensible détectée"
    message = f"{provider_label} · {types_label}\nVérifiez ce que vous envoyez."

    import platform
    import subprocess

    system = platform.system()

    if system == "Linux":
        try:
            import os
            import pwd
            uid = os.getuid()
            env = os.environ.copy()
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
            env.setdefault("DISPLAY", ":0")
            env.setdefault("HOME", pwd.getpwuid(uid).pw_dir)
            urgency = "critical" if severity == "high" else "normal"
            subprocess.Popen(
                ["notify-send", "--urgency", urgency, "--expire-time", "6000", title, message],
                env=env,
            )
            return
        except Exception as e:
            _log.debug("notifications.notify_send_failed", error=str(e))
    else:
        # macOS / Windows via plyer
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from plyer import notification
                notification.notify(
                    title=title,
                    message=message,
                    app_name="Pacta Agent",
                    timeout=6,
                )
            return
        except Exception as e:
            _log.debug("notifications.plyer_failed", error=str(e))

    _log.debug("notifications.no_backend")
