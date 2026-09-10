import asyncio
import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from zeebountee.config import ConfigManager
from zeebountee.models import PortResult, Target
from zeebountee.scope import ScopeValidator

console = Console()

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

async def scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult | None:
    service = COMMON_PORTS.get(port, "Unknown")
    async with sem:
        try:
            coro = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(coro, timeout=timeout)
            
            # Allow a brief moment to detect transparent proxies that drop connection immediately
            # after establishing the handshake. A legitimate service typically waits for data
            # or sends a banner, keeping the connection open.
            try:
                await asyncio.sleep(0.1)
                if reader.at_eof():
                    writer.close()
                    return None
            except OSError:
                writer.close()
                return None
                
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (asyncio.TimeoutError, OSError):
                pass
                
            return PortResult(target=host, port=port, service=service, state="OPEN")
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

async def run_port_scan(target: Target, timeout: float, max_concurrency: int = 50) -> list[PortResult]:
    host = target.host.replace("http://", "").replace("https://", "").split("/")[0]
    sem = asyncio.Semaphore(max_concurrency)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task(f"Scanning {len(COMMON_PORTS)} ports concurrently...", total=None)
        tasks = [scan_port(host, port, timeout, sem) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks)
        
    return [res for res in results if res is not None]

@click.command(name="ports")
@click.argument("target_str", required=True, metavar="TARGET")
@click.option("--timeout", type=float, help="Timeout in seconds for port connection.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
@click.option("--concurrency", default=50, type=int, help="Max concurrent connections.")
def ports_command(target_str: str, timeout: float | None, output: str | None, concurrency: int) -> None:
    """
    Perform an asynchronous port scan for common security ports.
    """
    config_mgr = ConfigManager()
    validator = ScopeValidator(config_mgr.scope_config)
    
    target = Target(host=target_str)
    
    if not validator.is_in_scope(target):
        console.print(f"[bold red]❌ Target {target.host} is OUT OF SCOPE.[/bold red]")
        return
        
    actual_timeout = timeout if timeout is not None else config_mgr.timeout
    actual_output = output if output is not None else config_mgr.default_output

    console.print(f"[bold cyan]⚡ Scanning common ports for target:[/bold cyan] {target.host}")

    try:
        results = asyncio.run(run_port_scan(target, actual_timeout, concurrency))
        
        table = Table(title=f"Port Scan Results: {target.host}")
        table.add_column("Port", style="cyan", justify="center")
        table.add_column("Service", style="magenta")
        table.add_column("State", style="green", justify="center")
        
        if not results:
            console.print(f"[bold yellow]⚠️ No open ports found for {target.host}.[/bold yellow]")
            return
            
        for res in results:
            table.add_row(str(res.port), res.service, res.state)
            
        console.print(table)
        console.print(f"\n[bold green]✅ Port scan complete. Found {len(results)} open ports.[/bold green]")

        if actual_output:
            data = [{"port": r.port, "service": r.service, "state": r.state} for r in results]
            if actual_output.endswith(".json"):
                with open(actual_output, "w") as f:
                    json.dump({"target": target.host, "open_ports": data}, f, indent=4)
                console.print(f"[bold blue]📁 Port report saved to {actual_output}[/bold blue]")
            elif actual_output.endswith(".txt"):
                with open(actual_output, "w") as f:
                    f.write(f"Port Scan Results: {target.host}\n")
                    f.writelines(f"Port {r.port} ({r.service}) -> {r.state}\n" for r in results)
                console.print(f"[bold blue]📁 Port report saved to {actual_output}[/bold blue]")

    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Port scan aborted by user.[/bold red]")
