from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import click

from agent.core.auth import get_token
from agent.core.config import load_config
from agent.core.logging import configure_logging, get_logger


@click.group()
def cli() -> None:
    """Pacta Agent — surveillance des usages IA."""


@cli.command()
@click.option("--config", default="config.yml", help="Chemin vers config.yml")
def start(config: str) -> None:
    """Démarrer l'agent (proxy + enrôlement)."""
    cfg = load_config()
    configure_logging(cfg.log.level)
    log = get_logger("agent")
    log.info("agent.start", version="0.1.0", proxy_port=cfg.proxy.port, api=cfg.api.url)

    try:
        get_token()
        log.info("agent.ready")
    except Exception as e:
        log.warning("agent.enrollment_failed", error=str(e))

    from agent.proxy.interceptor import set_event_callback, start_proxy
    from agent.transport.sender import queue_event

    set_event_callback(queue_event)

    # Proxy dans un thread séparé pour ne pas bloquer
    proxy_thread = threading.Thread(
        target=start_proxy,
        kwargs={"port": cfg.proxy.port},
        daemon=True,
    )
    proxy_thread.start()

    click.echo(f"Agent Pacta démarré.")
    click.echo("Ctrl+C pour arrêter.")

    try:
        proxy_thread.join()
    except KeyboardInterrupt:
        log.info("agent.stop")


@cli.command()
def status() -> None:
    """Afficher l'état de l'agent."""
    state_file = Path.home() / ".pacta" / "agent.json"
    if state_file.exists():
        state = json.loads(state_file.read_text())
        click.echo(f"Enrôlé — agent_id : {state['agent_id']}")
    else:
        click.echo("Non enrôlé — lancez 'pacta-agent start' avec email/password configurés.")


@cli.command("install-service")
@click.option("--config", default=str(Path.cwd() / "config.yml"), help="Chemin absolu vers config.yml")
def install_service(config: str) -> None:
    """Installer l'agent comme service systemd (démarrage automatique au boot)."""
    python = sys.executable
    run_py = Path(__file__).parent.parent / "run.py"

    unit = f"""[Unit]
Description=Pacta Agent — surveillance des usages IA
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {run_py} start --config {config}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""

    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    unit_path = systemd_dir / "pacta-agent.service"
    unit_path.write_text(unit)

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "--now", "pacta-agent"], check=True)
        click.echo(f"Service installé et démarré : {unit_path}")
        click.echo("Commandes utiles :")
        click.echo("  systemctl --user status pacta-agent")
        click.echo("  systemctl --user stop pacta-agent")
        click.echo("  journalctl --user -u pacta-agent -f")
    except subprocess.CalledProcessError as e:
        click.echo(f"Service créé dans {unit_path} mais activation échouée : {e}")
        click.echo("Lancez manuellement : systemctl --user enable --now pacta-agent")


@cli.command("uninstall-service")
def uninstall_service() -> None:
    """Désinstaller le service systemd."""
    try:
        subprocess.run(["systemctl", "--user", "disable", "--now", "pacta-agent"], check=True)
        unit_path = Path.home() / ".config" / "systemd" / "user" / "pacta-agent.service"
        unit_path.unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        click.echo("Service désinstallé.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Erreur : {e}")
