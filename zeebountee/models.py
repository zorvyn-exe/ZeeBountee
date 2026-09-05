from dataclasses import dataclass, field


@dataclass
class Target:
    host: str
    ip: str | None = None
    is_in_scope: bool = True

@dataclass
class ReconResult:
    target: str

@dataclass
class LivenessResult(ReconResult):
    status_code: int
    server: str

@dataclass
class PortResult(ReconResult):
    port: int
    service: str
    state: str = "OPEN"

@dataclass
class EndpointResult(ReconResult):
    endpoint: str
    status_code: int

@dataclass
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
