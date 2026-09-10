import json
import pathlib
from datetime import datetime, timezone

from zeebountee.models import (
    Finding,
    LivenessResult,
    PortResult,
    ScanReport,
    Severity,
    Target,
    WebDiscoveryResult,
)
from zeebountee.reporting import ReportGenerator


def test_generate_json(tmp_path: pathlib.Path) -> None:
    target = Target(host="example.com")
    report = ScanReport(
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        liveness=LivenessResult(target="example.com", status_code=200, server="Nginx"),
        ports=[PortResult(target="example.com", port=80, service="HTTP", state="OPEN")],
        subdomains=[],
        web_discovery=[
            WebDiscoveryResult(target="example.com", url="https://example.com/robots.txt", status_code=200, found=True, description="FOUND")
        ],
        vulnerabilities=[
            Finding(title="Test", description="Desc", severity=Severity.HIGH, target="example.com", evidence="None")
        ]
    )
    
    gen = ReportGenerator()
    json_path = tmp_path / "report.json"
    gen.generate_json(report, str(json_path))
    
    assert json_path.exists()
    
    with open(json_path) as f:
        data = json.load(f)
        
    assert data["target"]["host"] == "example.com"
    assert data["liveness"]["status_code"] == 200
    assert len(data["ports"]) == 1
    assert data["vulnerabilities"][0]["severity"] == "HIGH"


def test_generate_html(tmp_path: pathlib.Path) -> None:
    target = Target(host="example.com")
    report = ScanReport(
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        liveness=LivenessResult(target="example.com", status_code=200, server="Nginx"),
        ports=[PortResult(target="example.com", port=80, service="HTTP", state="OPEN")],
        subdomains=[],
        web_discovery=[
            WebDiscoveryResult(target="example.com", url="https://example.com/robots.txt", status_code=200, found=True, description="FOUND")
        ],
        vulnerabilities=[
            Finding(title="Test", description="Desc", severity=Severity.HIGH, target="example.com", evidence="None")
        ]
    )
    
    gen = ReportGenerator()
    html_path = tmp_path / "report.html"
    gen.generate_html(report, str(html_path))
    
    assert html_path.exists()
    
    with open(html_path) as f:
        content = f.read()
        
    assert "example.com" in content
    assert "ZeeBountee Scan Report" in content
    assert "HIGH" in content
    assert "80" in content
