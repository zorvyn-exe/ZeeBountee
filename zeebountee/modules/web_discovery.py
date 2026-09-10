import asyncio
import io
import json
import xml.etree.ElementTree as ET

import click
import httpx
from rich.console import Console
from rich.table import Table

from zeebountee.config import ConfigManager
from zeebountee.models import Target, WebDiscoveryResult
from zeebountee.scope import ScopeValidator

console = Console()

ENDPOINTS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt"
]

async def check_endpoint(client: httpx.AsyncClient, target: Target, path: str, timeout: float) -> WebDiscoveryResult:
    # Use https if no scheme provided, or http if target starts with it
    scheme = "http" if target.host.startswith("http://") else "https"
    domain = target.host.replace("http://", "").replace("https://", "")
    url = f"{scheme}://{domain}{path}"
    
    absolute_timeout = timeout * 3
    try:
        # Use a stream to only fetch headers and avoid downloading full large responses
        async with client.stream("GET", url, follow_redirects=False, timeout=absolute_timeout) as response:
            status_code = response.status_code
            
            if status_code == 200:
                content_type = response.headers.get("Content-Type", "")
                if path in ["/robots.txt", "/.well-known/security.txt"] and "text/html" in content_type:
                    return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=False, description=f"probable Soft 404 / False Positive (Content-Type: {content_type})")
                if path == "/robots.txt":
                    body_bytes = b""
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        body_bytes += chunk
                        if len(body_bytes) >= 16384:
                            body_bytes = body_bytes[:16384]
                            break
                    
                    content = body_bytes.decode("utf-8", errors="ignore")
                    disallow_count = 0
                    allow_count = 0
                    sitemaps = 0
                    
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        lower_line = line.lower()
                        if lower_line.startswith("disallow:"):
                            disallow_count += 1
                        elif lower_line.startswith("allow:"):
                            allow_count += 1
                        elif lower_line.startswith("sitemap:"):
                            sitemaps += 1
                            
                    desc_parts = []
                    if disallow_count > 0:
                        desc_parts.append(f"{disallow_count} Disallow")
                    if allow_count > 0:
                        desc_parts.append(f"{allow_count} Allow")
                    if sitemaps > 0:
                        desc_parts.append(f"{sitemaps} Sitemap")
                        
                    description = f"FOUND/AVAILABLE ({', '.join(desc_parts)})" if desc_parts else "FOUND/AVAILABLE"
                    return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=True, description=description)

                if path == "/sitemap.xml":
                    body_bytes = b""
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        body_bytes += chunk
                        if len(body_bytes) >= 32768:
                            body_bytes = body_bytes[:32768]
                            break

                    loc_count = 0
                    tag = None
                    parse_failed = False
                    try:
                        for event, elem in ET.iterparse(io.BytesIO(body_bytes), events=("start",)):
                            elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                            if tag is None:
                                tag = elem_tag
                            if elem_tag == "loc":
                                loc_count += 1
                    except ET.ParseError:
                        parse_failed = True

                    if tag in ["urlset", "sitemapindex"]:
                        description = f"FOUND/AVAILABLE ({tag}, {loc_count} URLs)"
                    elif parse_failed:
                        description = "FOUND/AVAILABLE (XML Parse Failed)"
                    else:
                        description = "FOUND/AVAILABLE"
                        
                    return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=True, description=description)

                elif path == "/.well-known/security.txt":
                    body_bytes = b""
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        body_bytes += chunk
                        if len(body_bytes) >= 16384:
                            body_bytes = body_bytes[:16384]
                            break
                    
                    content = body_bytes.decode("utf-8", errors="ignore")
                    contact_count = 0
                    has_policy = False
                    has_expires = False
                    
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        lower_line = line.lower()
                        if lower_line.startswith("contact:"):
                            contact_count += 1
                        elif lower_line.startswith("policy:"):
                            has_policy = True
                        elif lower_line.startswith("expires:"):
                            has_expires = True
                            
                    desc_parts = []
                    if contact_count > 0:
                        desc_parts.append(f"{contact_count} Contact")
                    if has_policy:
                        desc_parts.append("Policy")
                    if has_expires:
                        desc_parts.append("Expires")
                        
                    description = f"FOUND/AVAILABLE ({', '.join(desc_parts)})" if desc_parts else "FOUND/AVAILABLE"
                    return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=True, description=description)

                return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=True, description="FOUND/AVAILABLE")
            elif 300 <= status_code < 400:
                location = response.headers.get("Location", "Unknown")
                return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=True, description=f"REDIRECT -> {location}")
            elif status_code == 404:
                return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=False, description="NOT FOUND")
            else:
                return WebDiscoveryResult(target=target.host, url=url, status_code=status_code, found=False, description=f"HTTP {status_code}")
                
    except httpx.ConnectTimeout:
        return WebDiscoveryResult(target=target.host, url=url, status_code=None, found=False, description="Connection Timeout")
    except httpx.ReadTimeout:
        return WebDiscoveryResult(target=target.host, url=url, status_code=None, found=False, description="Read Timeout")
    except httpx.TimeoutException:
        return WebDiscoveryResult(target=target.host, url=url, status_code=None, found=False, description="Request Timeout")
    except httpx.RequestError as e:
        return WebDiscoveryResult(target=target.host, url=url, status_code=None, found=False, description=f"Network Error: {type(e).__name__}")
    except Exception as e:  # noqa: BLE001
        return WebDiscoveryResult(target=target.host, url=url, status_code=None, found=False, description=f"Unexpected Error: {type(e).__name__}")

async def run_web_discovery(target: Target, timeout: float) -> list[WebDiscoveryResult]:
    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        tasks = [check_endpoint(client, target, path, timeout) for path in ENDPOINTS]
        results = await asyncio.gather(*tasks)
    return list(results)

@click.command(name="discover-web")
@click.argument("target_str", required=True, metavar="TARGET")
@click.option("--timeout", type=float, help="Timeout in seconds for requests.")
@click.option("--output", type=str, help="Save report to file (.json or .txt).")
def discover_web_command(target_str: str, timeout: float | None, output: str | None) -> None:
    """
    Perform a safe web discovery check for standard endpoints (robots.txt, etc.).
    """
    config_mgr = ConfigManager()
    validator = ScopeValidator(config_mgr.scope_config)
    
    target = Target(host=target_str)
    
    if not validator.is_in_scope(target):
        console.print(f"[bold red]❌ Target {target.host} is OUT OF SCOPE.[/bold red]")
        return
        
    actual_timeout = timeout if timeout is not None else config_mgr.timeout
    actual_output = output if output is not None else config_mgr.default_output

    console.print(f"[bold cyan]🔍 Discovering web endpoints for target:[/bold cyan] {target.host}")

    try:
        results = asyncio.run(run_web_discovery(target, actual_timeout))
        
        table = Table(title=f"Web Discovery Results: {target.host}")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Status Code", style="green", justify="center")
        table.add_column("Description")
        
        for res in results:
            status_display = str(res.status_code) if res.status_code is not None else "ERR"
            table.add_row(res.url, status_display, res.description)
            
        console.print(table)
        console.print(f"\n[bold green]✅ Web Discovery complete.[/bold green]")

        if actual_output:
            data = [
                {
                    "url": r.url, 
                    "status_code": r.status_code, 
                    "found": r.found, 
                    "description": r.description
                } for r in results
            ]
            if actual_output.endswith(".json"):
                with open(actual_output, "w") as f:
                    json.dump({"target": target.host, "web_discovery": data}, f, indent=4)
                console.print(f"[bold blue]📁 Report saved to {actual_output}[/bold blue]")
            elif actual_output.endswith(".txt"):
                with open(actual_output, "w") as f:
                    f.write(f"Web Discovery Results: {target.host}\n")
                    for r in results:
                        f.write(f"{r.url} -> {r.status_code} ({r.description})\n")
                console.print(f"[bold blue]📁 Report saved to {actual_output}[/bold blue]")

    except KeyboardInterrupt:
        console.print("\n[bold red]❌ Web Discovery aborted by user.[/bold red]")
