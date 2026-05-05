from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


class ApiConfig(BaseModel):
    url: str = "http://localhost:8000"
    key: str = ""


class ProxyConfig(BaseModel):
    port: int = 8080


class DetectorsConfig(BaseModel):
    email: bool = True
    phone: bool = True
    iban: bool = True
    social_security: bool = True
    internal_ip: bool = True


class LogConfig(BaseModel):
    level: str = "INFO"


class Config(BaseModel):
    api: ApiConfig = ApiConfig()
    proxy: ProxyConfig = ProxyConfig()
    detectors: DetectorsConfig = DetectorsConfig()
    log: LogConfig = LogConfig()


_config: Config | None = None

DEFAULT_PATH = Path(__file__).parent.parent.parent / "config.yml"


def load_config(path: Path = DEFAULT_PATH) -> Config:
    global _config
    if path.exists():
        raw = yaml.safe_load(path.read_text())
        _config = Config.model_validate(raw or {})
    else:
        _config = Config()
    return _config


def get_config() -> Config:
    if _config is None:
        return load_config()
    return _config
