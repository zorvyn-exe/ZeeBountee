
from zeebountee.models import ScopeConfig, Target


class ScopeValidator:
    def __init__(self, config: ScopeConfig) -> None:
        self.config = config

    def _matches_domain(self, host: str, domain_list: list[str]) -> bool:
        for domain in domain_list:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def is_in_scope(self, target: str | Target) -> bool:
        host = target.host if isinstance(target, Target) else target

        # Clean up URL to extract host
        host = host.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Remove port if specified
        host = host.split(":")[0]

        # Explicitly blocked?
        if self._matches_domain(host, self.config.blocked_domains):
            return False

        if self.config.allowed_domains:
            return self._matches_domain(host, self.config.allowed_domains)
        return True
