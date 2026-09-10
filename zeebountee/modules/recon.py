import asyncio
import json

import click
import httpx
from rich.console import Console

from zeebountee.config import ConfigManager
from zeebountee.models import LivenessResult, Target
from zeebountee.scope import ScopeValidator

console = Console()

async def check_liveness(target: Target, timeout: float = 5.0) -> LivenessResult | None:
    url = target.host if target.host.startswith(("http://", "https://")) else f"https://{target.host}"
    
    absolute_timeout = timeout * 3
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            response = await asyncio.wait_for(client.get(url, follow_redirects=True), timeout=absolute_timeout)
            return LivenessResult(
                target=url, 
                status_code=response.status_code, 
                server=response.headers.get('Server', 'Unknown')
            )
    except httpx.ConnectTimeout:
        console.print(f"[bold red]❌ Connection timed out (Host unreachable or port filtered) for {url}[/bold red]")
    except httpx.ReadTimeout:
        console.print(f"[bold red]❌ Read timed out (Tarpit or slow server) for {url}[/bold red]")
    except httpx.TimeoutException:
        console.print(f"[bold red]❌ Request timed out for {url}[/bold red]")
    except asyncio.TimeoutError:
        console.print(f"[bold red]❌ Absolute timeout exceeded (Request chain took too long) for {url}[/bold red]")
    except httpx.RequestError as e:
        console.print(f"[bold red]❌ Network error: {e}[/bold red]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[bold red]❌ Unexpected error: {e}[/bold red]")
    
    return None

@click.command(name="recon")
@click.argument("target_str", required=True, metavar="TARGET")
@click.option("--timeout", type=float, help="Timeout in seconds.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
def recon_command(target_str: str, timeout: float | None, output: str | None) -> None:
    """
    Perform a basic liveness check on a target (e.g., example.com).
    """
    config_mgr = ConfigManager()
    validator = ScopeValidator(config_mgr.scope_config)
    
    target = Target(host=target_str)
    
    if not validator.is_in_scope(target):
        console.print(f"[bold red]❌ Target {target.host} is OUT OF SCOPE.[/bold red]")
        return
        
    actual_timeout = timeout if timeout is not None else config_mgr.timeout
    actual_output = output if output is not None else config_mgr.default_output

    console.print(f"[bold cyan]🔍 Probing target liveness:[/bold cyan] {target.host}")

    try:
        result = asyncio.run(check_liveness(target, actual_timeout))
        
        if result:
            console.print(f"[bold green]✔ Target is LIVE![/bold green] Status: {result.status_code} | Server: {result.server}")
            
            if actual_output:
                if actual_output.endswith(".json"):
                    with open(actual_output, "w") as f:
                        json.dump({"target": result.target, "status_code": result.status_code, "server": result.server}, f, indent=4)
                    console.print(f"[bold blue]📁 Recon report saved to {actual_output}[/bold blue]")
                elif actual_output.endswith(".txt"):
                    with open(actual_output, "w") as f:
                        f.write(f"Recon Report: {result.target}\nStatus: {result.status_code}\nServer: {result.server}\n")
                    console.print(f"[bold blue]📁 Recon report saved to {actual_output}[/bold blue]")
    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Recon aborted by user.[/bold red]")
