import asyncio
import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

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

async def scan_port(host: str, port: int, timeout: float) -> tuple[int, str, bool]:
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        coro = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(coro, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, service, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, service, False

async def run_port_scan(target: str, timeout: float, output: str | None = None) -> None:
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    console.print(f"[bold cyan]⚡ Scanning common ports for target:[/bold cyan] {host}")
    
    open_ports = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task(f"Scanning {len(COMMON_PORTS)} ports concurrently...", total=None)
        tasks = [scan_port(host, port, timeout) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks)
        open_ports = [res for res in results if res[2]]

    table = Table(title=f"Port Scan Results: {host}")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Service", style="magenta")
    table.add_column("State", style="green", justify="center")
    
    if not open_ports:
        console.print(f"[bold yellow]⚠️ No open ports found for {host}.[/bold yellow]")
        return
        
    for port, service, _ in open_ports:
        table.add_row(str(port), service, "OPEN")
        
    console.print(table)
    console.print(f"\n[bold green]✅ Port scan complete. Found {len(open_ports)} open ports.[/bold green]")

    if output:
        data = [{"port": p, "service": s, "state": "OPEN"} for p, s, _ in open_ports]
        if output.endswith(".json"):
            with open(output, "w") as f:
                json.dump({"target": host, "open_ports": data}, f, indent=4)
            console.print(f"[bold blue]📁 Port report saved to {output}[/bold blue]")
        elif output.endswith(".txt"):
            with open(output, "w") as f:
                f.write(f"Port Scan Results: {host}\n")
                for p, s, _ in open_ports:
                    f.write(f"Port {p} ({s}) -> OPEN\n")
            console.print(f"[bold blue]📁 Port report saved to {output}[/bold blue]")

@click.command(name="ports")
@click.argument("target", required=True)
@click.option("--timeout", default=1.0, type=float, help="Timeout in seconds for port connection.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
def ports_command(target: str, timeout: float, output: str | None) -> None:
    """
    Perform an asynchronous port scan for common security ports.
    """
    try:
        asyncio.run(run_port_scan(target, timeout, output))
    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Port scan aborted by user.[/bold red]")
