import asyncio
import json

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

COMMON_ENDPOINTS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "test", "dev", "staging", "api", "admin", "dashboard", "portal", "shop"
]

async def check_endpoint(client: httpx.AsyncClient, domain: str, word: str, timeout: float) -> tuple[str, int, bool]:
    url = f"http://{word}.{domain}"
    try:
        response = await client.get(url, timeout=timeout, follow_redirects=False)
        return f"{word}.{domain}", response.status_code, True
    except (httpx.TimeoutException, httpx.RequestError):
        return f"{word}.{domain}", 0, False
    except Exception:
        return f"{word}.{domain}", 0, False

async def run_discovery(target: str, timeout: float, output: str | None = None) -> None:
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    console.print(f"[bold cyan]🔍 Discovering endpoints for target:[/bold cyan] {domain}")
    
    active_results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task(f"Scanning {len(COMMON_ENDPOINTS)} common asset names...", total=None)
        
        async with httpx.AsyncClient(verify=False) as client:
            tasks = [check_endpoint(client, domain, word, timeout) for word in COMMON_ENDPOINTS]
            results = await asyncio.gather(*tasks)
            active_results = [res for res in results if res[2]]

    table = Table(title=f"Endpoint Discovery Results: {domain}")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Status Code", style="green", justify="center")
    
    if not active_results:
        console.print(f"[bold yellow]⚠️ No active endpoints found for {domain}.[/bold yellow]")
        return
        
    for endpoint, status, _ in active_results:
        table.add_row(endpoint, str(status))
        
    console.print(table)
    console.print(f"\n[bold green]✅ Discovery complete. Found {len(active_results)} active endpoints.[/bold green]")

    if output:
        data = [{"endpoint": ep, "status_code": st} for ep, st, _ in active_results]
        if output.endswith(".json"):
            with open(output, "w") as f:
                json.dump({"target": domain, "endpoints": data}, f, indent=4)
            console.print(f"[bold blue]📁 Report saved to {output}[/bold blue]")
        elif output.endswith(".txt"):
            with open(output, "w") as f:
                f.write(f"Endpoint Discovery Results: {domain}\n")
                for ep, st, _ in active_results:
                    f.write(f"{ep} -> {st}\n")
            console.print(f"[bold blue]📁 Report saved to {output}[/bold blue]")

@click.command(name="discover")
@click.argument("target", required=True)
@click.option("--timeout", default=3.0, type=float, help="Timeout in seconds for requests.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
def discover_command(target: str, timeout: float, output: str | None) -> None:
    """
    Perform an asynchronous asset and endpoint discovery check.
    """
    try:
        asyncio.run(run_discovery(target, timeout, output))
    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Discovery aborted by user.[/bold red]")
