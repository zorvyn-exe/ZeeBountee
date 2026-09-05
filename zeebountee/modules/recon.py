import asyncio
import json

import click
import httpx
from rich.console import Console

console = Console()

async def check_liveness(target: str, timeout: float = 5.0, output: str | None = None) -> None:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    console.print(f"[bold cyan]🔍 Probing target liveness:[/bold cyan] {url}")
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            response = await client.get(url, follow_redirects=True)
            console.print(f"[bold green]✔ Target is LIVE![/bold green] Status: {response.status_code} | Server: {response.headers.get('Server', 'Unknown')}")
            
            if output:
                data = {"target": url, "status_code": response.status_code, "server": response.headers.get('Server', 'Unknown')}
                if output.endswith(".json"):
                    with open(output, "w") as f:
                        json.dump(data, f, indent=4)
                    console.print(f"[bold blue]📁 Recon report saved to {output}[/bold blue]")
                elif output.endswith(".txt"):
                    with open(output, "w") as f:
                        f.write(f"Recon Report: {url}\nStatus: {response.status_code}\nServer: {response.headers.get('Server', 'Unknown')}\n")
                    console.print(f"[bold blue]📁 Recon report saved to {output}[/bold blue]")
    except httpx.TimeoutException:
        console.print(f"[bold red]❌ Request timed out for {url}[/bold red]")
    except httpx.RequestError as e:
        console.print(f"[bold red]❌ Network error: {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]❌ Unexpected error: {e}[/bold red]")

@click.command(name="recon")
@click.argument("target", required=True)
@click.option("--timeout", default=5.0, type=float, help="Timeout in seconds.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
def recon_command(target: str, timeout: float, output: str | None) -> None:
    """
    Perform a basic liveness check on a target (e.g., example.com).
    """
    try:
        asyncio.run(check_liveness(target, timeout, output))
    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Recon aborted by user.[/bold red]")
