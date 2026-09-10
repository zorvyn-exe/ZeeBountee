import json
import os
from dataclasses import asdict

from jinja2 import Environment, FileSystemLoader

from zeebountee.models import ScanReport


class ReportGenerator:
    def __init__(self) -> None:
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_json(self, report: ScanReport, filepath: str) -> None:
        """Serialize the ScanReport to a JSON file."""
        data = asdict(report)
        # Convert enums to strings in vulnerabilities
        for vuln in data.get("vulnerabilities", []):
            if "severity" in vuln and hasattr(vuln["severity"], "value"):
                vuln["severity"] = vuln["severity"].value
                
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)

    def generate_html(self, report: ScanReport, filepath: str) -> None:
        """Render the ScanReport to an HTML file using Jinja2."""
        template = self.env.get_template("report.html")
        
        # We need to explicitly order findings by severity
        severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        sorted_vulns = sorted(report.vulnerabilities, key=lambda x: severity_order.get(x.severity.value, 99))
        report.vulnerabilities = sorted_vulns

        html_content = template.render(
            report=report,
            risk_score=report.calculate_risk_score(),
            severity_dist=report.severity_distribution()
        )
        
        with open(filepath, "w") as f:
            f.write(html_content)
