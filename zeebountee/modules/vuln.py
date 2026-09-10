import asyncio
import json
from typing import Protocol

import click
import httpx
from rich.console import Console
from rich.table import Table

from zeebountee.config import ConfigManager
from zeebountee.models import Finding, Severity, Target
from zeebountee.scope import ScopeValidator

console = Console()


class SecurityCheck(Protocol):
    async def run(self, target: Target, client: httpx.AsyncClient) -> list[Finding]:
        """Run the security check and return a list of findings."""
        ...


class SecurityHeadersCheck:
    async def run(self, target: Target, client: httpx.AsyncClient) -> list[Finding]:
        findings = []
        try:
            url = f"https://{target.host}"
            response = await client.get(url, follow_redirects=True)
            
            headers_to_check = {
                "Strict-Transport-Security": (Severity.MEDIUM, "Missing HSTS Header"),
                "X-Frame-Options": (Severity.LOW, "Missing X-Frame-Options Header"),
                "X-Content-Type-Options": (Severity.LOW, "Missing X-Content-Type-Options Header"),
            }
            
            for header, (severity, title) in headers_to_check.items():
                if header.lower() not in (k.lower() for k in response.headers):
                    findings.append(Finding(
                        title=title,
                        description=f"The {header} header is missing from the response.",
                        severity=severity,
                        target=url,
                        evidence=f"Headers: {dict(response.headers)}"
                    ))
                    
        except httpx.RequestError:
            pass
            
        return findings


class CookieSecurityCheck:
    async def run(self, target: Target, client: httpx.AsyncClient) -> list[Finding]:
        from http.cookies import SimpleCookie
        
        findings = []
        try:
            url = f"https://{target.host}"
            response = await client.get(url, follow_redirects=True)
            
            if "set-cookie" in (k.lower() for k in response.headers):
                for cookie_str in response.headers.get_list("set-cookie"):
                    cookie_parser = SimpleCookie()
                    cookie_parser.load(cookie_str)
                    
                    for name, morsel in cookie_parser.items():
                        if not morsel.get('secure'):
                            findings.append(Finding(
                                title="Insecure Cookie (Missing Secure Flag)",
                                description="A cookie was set without the Secure flag.",
                                severity=Severity.LOW,
                                target=url,
                                evidence=cookie_str
                            ))
                        if not morsel.get('httponly'):
                            findings.append(Finding(
                                title="Insecure Cookie (Missing HttpOnly Flag)",
                                description="A cookie was set without the HttpOnly flag.",
                                severity=Severity.LOW,
                                target=url,
                                evidence=cookie_str
                            ))
        except httpx.RequestError:
            pass
            
        return findings


class InformationDisclosureCheck:
    async def run(self, target: Target, client: httpx.AsyncClient) -> list[Finding]:
        findings = []
        try:
            url = f"https://{target.host}"
            response = await client.get(url, follow_redirects=True)
            
            for header in ["Server", "X-Powered-By"]:
                val = response.headers.get(header)
                if val:
                    findings.append(Finding(
                        title=f"Information Disclosure ({header} Header)",
                        description=f"The server is exposing its software version via the {header} header.",
                        severity=Severity.INFO,
                        target=url,
                        evidence=f"{header}: {val}"
                    ))
        except httpx.RequestError:
            pass
            
        return findings


class TLSCheck:
    async def run(self, target: Target, client: httpx.AsyncClient) -> list[Finding]:
        findings = []
        http_url = f"http://{target.host}"
        https_url = f"https://{target.host}"
        
        try:
            # Check if HTTP redirects to HTTPS
            response = await client.get(http_url, follow_redirects=False)
            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get("location", "").strip()
                is_insecure = False
                
                if not location:
                    is_insecure = True
                elif location.startswith("http://"):
                    is_insecure = True
                elif "://" in location and not location.startswith("https://"):
                    is_insecure = True
                
                if is_insecure:
                    findings.append(Finding(
                        title="Insecure HTTP Redirection",
                        description="HTTP traffic is redirected, but not to an HTTPS URL.",
                        severity=Severity.LOW,
                        target=http_url,
                        evidence=f"Location: {location}" if location else "Location header missing"
                    ))
            else:
                findings.append(Finding(
                    title="Cleartext HTTP Supported",
                    description="The server supports cleartext HTTP without redirecting to HTTPS.",
                    severity=Severity.MEDIUM,
                    target=http_url,
                    evidence=f"Status: {response.status_code} on HTTP port 80"
                ))
        except httpx.RequestError:
            pass
            
        try:
            # Verify HTTPS handshake succeeds
            await client.get(https_url)
        except httpx.TimeoutException:
            # Network timeout is not a TLS vulnerability
            pass
        except httpx.RequestError as e:
            error_str = str(e).lower()
            if "ssl" in error_str or "tls" in error_str or "certificate" in error_str or "handshake" in error_str:
                findings.append(Finding(
                    title="TLS Configuration Error",
                    description="Failed to establish a secure connection via HTTPS.",
                    severity=Severity.MEDIUM,
                    target=https_url,
                    evidence=str(e)
                ))
            
        return findings


CHECKS: list[type[SecurityCheck]] = [
    SecurityHeadersCheck,
    CookieSecurityCheck,
    InformationDisclosureCheck,
    TLSCheck,
]


async def run_vuln_scan(target: Target, timeout: float = 10.0) -> list[Finding]:
    """Run all vulnerability checks concurrently against a target."""
    findings = []
    
    absolute_timeout = timeout * 3
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        tasks = []
        for check_class in CHECKS:
            check_instance = check_class()
            tasks.append(asyncio.wait_for(check_instance.run(target, client), timeout=absolute_timeout))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
    return findings


@click.command(name="vuln")
@click.argument("target_str", required=True, metavar="TARGET")
@click.option("--timeout", type=float, help="Timeout in seconds.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
def vuln_command(target_str: str, timeout: float | None, output: str | None) -> None:
    """
    Perform a lightweight vulnerability assessment on a target.
    """
    config_mgr = ConfigManager()
    validator = ScopeValidator(config_mgr.scope_config)
    
    target = Target(host=target_str)
    
    if not validator.is_in_scope(target):
        console.print(f"[bold red]❌ Target {target.host} is OUT OF SCOPE.[/bold red]")
        return
        
    actual_timeout = timeout if timeout is not None else config_mgr.timeout
    actual_output = output if output is not None else config_mgr.default_output

    console.print(f"[bold cyan]🔍 Running Vulnerability Assessment:[/bold cyan] {target.host}")

    try:
        findings = asyncio.run(run_vuln_scan(target, actual_timeout))
        
        if not findings:
            console.print("[bold green]✔ No vulnerabilities found.[/bold green]")
        else:
            # Sort findings by severity (naive sort works if we give them order, but let's just group or use list)
            severity_order = {Severity.CRITICAL: 1, Severity.HIGH: 2, Severity.MEDIUM: 3, Severity.LOW: 4, Severity.INFO: 5}
            findings.sort(key=lambda f: severity_order.get(f.severity, 99))
            
            table = Table(title=f"Vulnerability Scan Results for {target.host}")
            table.add_column("Severity", justify="center", style="bold")
            table.add_column("Title")
            table.add_column("Description")
            
            for finding in findings:
                sev_color = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                    Severity.INFO: "green"
                }.get(finding.severity, "white")
                
                table.add_row(
                    f"[{sev_color}]{finding.severity.value}[/{sev_color}]",
                    finding.title,
                    finding.description
                )
            
            console.print(table)
            
        if actual_output and findings:
            if actual_output.endswith(".json"):
                with open(actual_output, "w") as f:
                    json_data = [
                        {
                            "title": f.title,
                            "description": f.description,
                            "severity": f.severity.value,
                            "target": f.target,
                            "evidence": f.evidence
                        }
                        for f in findings
                    ]
                    json.dump(json_data, f, indent=4)
                console.print(f"[bold blue]📁 Vuln report saved to {actual_output}[/bold blue]")
            elif actual_output.endswith(".txt"):
                with open(actual_output, "w") as f:
                    f.write(f"Vulnerability Report: {target.host}\n")
                    for finding in findings:
                        f.write(f"[{finding.severity.value}] {finding.title}\n")
                        f.write(f"Description: {finding.description}\n")
                        f.write(f"Evidence: {finding.evidence}\n\n")
                console.print(f"[bold blue]📁 Vuln report saved to {actual_output}[/bold blue]")
    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Scan aborted by user.[/bold red]")

