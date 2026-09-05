import json
import os
from typing import Any

from zeebountee.models import ScopeConfig


class ConfigManager:
    def __init__(self, config_path: str = "zeebountee.json") -> None:
        self.config_path = config_path
        self.data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        else:
            self.data = {}

    @property
    def timeout(self) -> float:
        return float(self.data.get("timeout", 5.0))

    @property
    def default_output(self) -> str | None:
        output = self.data.get("output")
        return str(output) if output is not None else None

    @property
    def scope_config(self) -> ScopeConfig:
        scope_data = self.data.get("scope", {})
        return ScopeConfig(
            allowed_domains=list(scope_data.get("allowed_domains", [])),
            blocked_domains=list(scope_data.get("blocked_domains", [])),
            allowed_ips=list(scope_data.get("allowed_ips", []))
        )
