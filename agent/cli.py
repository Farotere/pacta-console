from __future__ import annotations

import click

from agent.core.config import load_config
from agent.core.logging import configure_logging, get_logger


@click.group()
def cli() -> None:
    """Pacta Agent — surveillance des usages IA."""


@cli.command()
@click.option("--config", default="config.yml", help="Chemin vers config.yml")
def start(config: str) -> None:
    """Démarrer l'agent."""
    cfg = load_config()
    configure_logging(cfg.log.level)
    log = get_logger("agent")
    log.info("agent.start", version="0.1.0", proxy_port=cfg.proxy.port, api=cfg.api.url)
    click.echo("Agent Pacta démarré. Proxy sur le port " + str(cfg.proxy.port))


@cli.command()
def status() -> None:
    """Afficher l'état de l'agent."""
    click.echo("Agent Pacta — statut : en cours de développement")
