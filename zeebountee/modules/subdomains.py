import asyncio
import json

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from zeebountee.config import ConfigManager
from zeebountee.models import EndpointResult, Target
from zeebountee.scope import ScopeValidator

console = Console()

COMMON_ENDPOINTS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "test", "dev", "staging", "api", "admin", "dashboard", "portal", "shop"
]

async def check_endpoint(client: httpx.AsyncClient, domain: str, word: str, timeout: float, sem: asyncio.Semaphore) -> EndpointResult | None:
    url = f"http://{word}.{domain}"
    absolute_timeout = timeout * 3
    async with sem:
        try:
            response = await asyncio.wait_for(client.get(url, follow_redirects=False), timeout=absolute_timeout)
            return EndpointResult(target=domain, endpoint=f"{word}.{domain}", status_code=response.status_code)
        except (httpx.TimeoutException, httpx.RequestError, asyncio.TimeoutError):
            return None
        except Exception:  # noqa: BLE001
            return None

async def run_discovery(target: Target, timeout: float, max_concurrency: int = 50) -> list[EndpointResult]:
    domain = target.host.replace("http://", "").replace("https://", "").split("/")[0]
    sem = asyncio.Semaphore(max_concurrency)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task(f"Scanning {len(COMMON_ENDPOINTS)} common asset names...", total=None)
        
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            tasks = [check_endpoint(client, domain, word, timeout, sem) for word in COMMON_ENDPOINTS]
            results = await asyncio.gather(*tasks)
            
    return [res for res in results if res is not None]

@click.command(name="discover")
@click.argument("target_str", required=True, metavar="TARGET")
@click.option("--timeout", type=float, help="Timeout in seconds for requests.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
@click.option("--concurrency", default=50, type=int, help="Max concurrent connections.")
def discover_command(target_str: str, timeout: float | None, output: str | None, concurrency: int) -> None:
    """
    Perform an asynchronous asset and endpoint discovery check.
    """
    config_mgr = ConfigManager()
    validator = ScopeValidator(config_mgr.scope_config)
    
    target = Target(host=target_str)
    
    if not validator.is_in_scope(target):
        console.print(f"[bold red]❌ Target {target.host} is OUT OF SCOPE.[/bold red]")
        return
        
    actual_timeout = timeout if timeout is not None else config_mgr.timeout
    actual_output = output if output is not None else config_mgr.default_output

    console.print(f"[bold cyan]🔍 Discovering endpoints for target:[/bold cyan] {target.host}")

    try:
        results = asyncio.run(run_discovery(target, actual_timeout, concurrency))
        
        table = Table(title=f"Endpoint Discovery Results: {target.host}")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Status Code", style="green", justify="center")
        
        if not results:
            console.print(f"[bold yellow]⚠️ No active endpoints found for {target.host}.[/bold yellow]")
            return
            
        for res in results:
            table.add_row(res.endpoint, str(res.status_code))
            
        console.print(table)
        console.print(f"\n[bold green]✅ Discovery complete. Found {len(results)} active endpoints.[/bold green]")

        if actual_output:
            data = [{"endpoint": r.endpoint, "status_code": r.status_code} for r in results]
            if actual_output.endswith(".json"):
                with open(actual_output, "w") as f:
                    json.dump({"target": target.host, "endpoints": data}, f, indent=4)
                console.print(f"[bold blue]📁 Report saved to {actual_output}[/bold blue]")
            elif actual_output.endswith(".txt"):
                with open(actual_output, "w") as f:
                    f.write(f"Endpoint Discovery Results: {target.host}\n")
                    f.writelines(f"{r.endpoint} -> {r.status_code}\n" for r in results)
                console.print(f"[bold blue]📁 Report saved to {actual_output}[/bold blue]")

    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Discovery aborted by user.[/bold red]")
