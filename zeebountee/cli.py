import asyncio
from datetime import datetime, timezone

import click
from rich.console import Console

from zeebountee.config import ConfigManager
from zeebountee.models import ScanReport, Target
from zeebountee.modules.ports import ports_command, run_port_scan
from zeebountee.modules.recon import check_liveness, recon_command
from zeebountee.modules.subdomains import discover_command, run_discovery
from zeebountee.modules.vuln import run_vuln_scan, vuln_command
from zeebountee.modules.web_discovery import discover_web_command, run_web_discovery
from zeebountee.reporting import ReportGenerator
from zeebountee.scope import ScopeValidator

console = Console()

@click.group()
@click.version_option(version="1.0.0", prog_name="ZeeBountee")
def main() -> None:
    """
    ZeeBountee - Professional Python CLI Reconnaissance & Asset Discovery Tool.
    """


@click.command(name="scan")
@click.argument("target_str", required=True, metavar="TARGET")
@click.option("--timeout", type=float, help="Timeout in seconds for operations.")
@click.option("--format", "output_format", type=click.Choice(["json", "html"]), default="html", help="Report output format (json or html).")
@click.option("--output", type=str, help="Output file path (default is reports/<target>_report.<format>).")
def scan_command(target_str: str, timeout: float | None, output_format: str, output: str | None) -> None:
    """
    Run a full automated scan (Recon, Ports, Subdomains, Vulns) and generate a report.
    """
    config_mgr = ConfigManager()
    validator = ScopeValidator(config_mgr.scope_config)
    
    target = Target(host=target_str)
    
    if not validator.is_in_scope(target):
        console.print(f"[bold red]❌ Target {target.host} is OUT OF SCOPE.[/bold red]")
        return
        
    actual_timeout = timeout if timeout is not None else config_mgr.timeout
    
    console.print(f"[bold cyan]🚀 Starting full scan on[/bold cyan] {target.host}...")
    
    async def run_full_scan() -> ScanReport | None:
        console.print("[bold yellow]1/5 Probing liveness...[/bold yellow]")
        liveness = await check_liveness(target, actual_timeout)
        if not liveness:
            console.print("[bold red]❌ Target is offline. Aborting scan.[/bold red]")
            return None
            
        console.print("[bold yellow]2/5 Scanning ports...[/bold yellow]")
        ports = await run_port_scan(target, actual_timeout)
        
        console.print("[bold yellow]3/5 Discovering subdomains...[/bold yellow]")
        subdomains = await run_discovery(target, actual_timeout)
        
        console.print("[bold yellow]4/5 Discovering web endpoints...[/bold yellow]")
        web_discovery = await run_web_discovery(target, actual_timeout)
        
        console.print("[bold yellow]5/5 Assessing vulnerabilities...[/bold yellow]")
        
        vuln_targets = [target]
        seen_hosts = {target.host.lower()}
        
        for ep in subdomains:
            ep_host = ep.endpoint.lower()
            if ep_host not in seen_hosts:
                ep_target = Target(host=ep.endpoint)
                if validator.is_in_scope(ep_target):
                    vuln_targets.append(ep_target)
                    seen_hosts.add(ep_host)
                    
        vuln_tasks = [run_vuln_scan(t, actual_timeout) for t in vuln_targets]
        vulns_results = await asyncio.gather(*vuln_tasks)
        
        vulns = []
        for result in vulns_results:
            vulns.extend(result)
        
        return ScanReport(
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            liveness=liveness,
            ports=ports,
            subdomains=subdomains,
            web_discovery=web_discovery,
            vulnerabilities=vulns
        )

    try:
        report = asyncio.run(run_full_scan())
        if not report:
            return
            
        import re
        safe_target = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.host)
        
        generator = ReportGenerator()
        
        if output:
            out_file = output
        else:
            import os
            base_name = f"reports/{safe_target}"
            ext = f"_report.{output_format}"
            out_file = f"{base_name}{ext}"
            counter = 1
            while os.path.exists(out_file):
                out_file = f"{base_name}_{counter}{ext}"
                counter += 1
        
        if output_format == "json":
            generator.generate_json(report, out_file)
        else:
            generator.generate_html(report, out_file)
            
        console.print(f"\n[bold green]✅ Full scan complete![/bold green] Report saved to [bold white]{out_file}[/bold white]")
        
    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Scan aborted by user.[/bold red]")



# Register modules
main.add_command(recon_command)
main.add_command(ports_command)
main.add_command(discover_command)
main.add_command(vuln_command)
main.add_command(discover_web_command)
main.add_command(scan_command)


if __name__ == "__main__":
    main()
