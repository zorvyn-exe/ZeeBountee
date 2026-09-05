import click
from rich.console import Console

from zeebountee.modules.ports import ports_command
from zeebountee.modules.recon import recon_command
from zeebountee.modules.subdomains import discover_command

console = Console()

@click.group()
@click.version_option(version="0.1.0", prog_name="ZeeBountee")
def main() -> None:
    """
    ZeeBountee - Professional Python CLI Reconnaissance & Asset Discovery Tool.
    """

# Register modules
main.add_command(recon_command)
main.add_command(ports_command)
main.add_command(discover_command)

if __name__ == "__main__":
    main()
