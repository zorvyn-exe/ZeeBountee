from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    target: str
    evidence: str


@dataclass
class ScanReport:
    target: "Target"
    timestamp: str
    liveness: "LivenessResult | None" = None
    ports: list["PortResult"] = field(default_factory=list)
    subdomains: list["EndpointResult"] = field(default_factory=list)
    web_discovery: list["WebDiscoveryResult"] = field(default_factory=list)
    vulnerabilities: list[Finding] = field(default_factory=list)

    def calculate_risk_score(self) -> int:
        if not self.vulnerabilities:
            return 0
        severity_scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0
        }
        return max((severity_scores.get(f.severity, 0) for f in self.vulnerabilities), default=0)

    def severity_distribution(self) -> dict[str, int]:
        dist = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for v in self.vulnerabilities:
            dist[v.severity.value] += 1
        return dist


@dataclass
class Target:
    host: str
    ip: str | None = None
    is_in_scope: bool = True

    def __post_init__(self) -> None:
        cleaned = self.host.strip()
        if cleaned.startswith("http://"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("https://"):
            cleaned = cleaned[8:]
        cleaned = cleaned.split("/")[0]
        
        if not cleaned:
            raise ValueError(f"Invalid target host provided: {self.host}")
            
        self.host = cleaned


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
class WebDiscoveryResult(ReconResult):
    url: str
    status_code: int | None
    found: bool
    description: str

@dataclass
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
