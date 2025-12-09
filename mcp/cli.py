"""
CLI entry point for the security scanner.
"""

import asyncio

import click
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Security Scanner - AI-driven vulnerability assessment."""
    pass


@main.command()
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(["active", "passive", "full"]),
    default="active",
    help="Scan mode: active (nmap/nikto), passive (shodan/dns), or full",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def scan(target: str, mode: str, verbose: bool):
    """
    Run a security scan against TARGET.

    TARGET should be an IP address or hostname in scope.

    Examples:

        scanner scan 192.168.56.101

        scanner scan 192.168.56.101 --mode active -v
    """
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n[bold]Mode:[/bold] {mode}",
        title="Security Scan",
        border_style="blue"
    ))

    if mode == "passive":
        console.print("[yellow]Passive scanning not yet implemented.[/yellow]")
        console.print("Use --mode active for nmap/nikto scanning.")
        return

    if mode == "full":
        console.print("[yellow]Full scan mode not yet implemented.[/yellow]")
        console.print("Use --mode active for nmap/nikto scanning.")
        return

    # Run active scan
    asyncio.run(_run_active_scan(target, verbose))


async def _run_active_scan(target: str, verbose: bool):
    """Run the scanner agent against a target."""
    from agents.scanner_agent import ScannerAgent

    agent = ScannerAgent()

    task = f"""Perform a comprehensive security scan of {target}.

1. Start with a quick port scan to identify open services
2. For any open ports, get detailed version information
3. Run vulnerability scripts on interesting services
4. For any web services (HTTP/HTTPS), run nikto and feroxbuster
5. Provide a structured report of all findings
"""

    console.print("\n[bold blue]Starting scan...[/bold blue]\n")

    try:
        result = await agent.run(task, verbose=verbose)
        console.print("\n")
        console.print(Panel(
            Markdown(result),
            title="Scan Results",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        raise


@main.command()
def interactive():
    """Start an interactive scanning session."""
    console.print(Panel(
        "Interactive mode - chat with the scanner agent.\n"
        "Type 'exit' or 'quit' to end the session.",
        title="Interactive Mode",
        border_style="blue"
    ))

    asyncio.run(_interactive_session())


async def _interactive_session():
    """Run an interactive session with the scanner agent."""
    from agents.scanner_agent import ScannerAgent

    agent = ScannerAgent()

    while True:
        try:
            user_input = console.input("\n[bold green]You>[/bold green] ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye![/dim]")
            break

        if user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Goodbye![/dim]")
            break

        if not user_input.strip():
            continue

        try:
            result = await agent.run(user_input, verbose=True)
            console.print("\n[bold blue]Agent>[/bold blue]")
            console.print(Markdown(result))
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


@main.command()
def check_tools():
    """Check if required scanning tools are installed."""
    import shutil

    tools = {
        "nmap": "Port scanning",
        "feroxbuster": "Directory brute-forcing",
        "nikto": "Web vulnerability scanning",
    }

    console.print("\n[bold]Checking installed tools...[/bold]\n")

    all_found = True
    for tool, description in tools.items():
        path = shutil.which(tool)
        if path:
            console.print(f"[green]✓[/green] {tool}: {path}")
        else:
            console.print(f"[red]✗[/red] {tool}: NOT FOUND ({description})")
            all_found = False

    if not all_found:
        console.print("\n[yellow]Some tools are missing. Install them to use all features.[/yellow]")
    else:
        console.print("\n[green]All tools installed![/green]")


@main.command()
@click.argument("target")
def check_scope(target: str):
    """Check if a TARGET is in scope for scanning."""
    from mcp_servers.scanner.scope import is_target_allowed

    if is_target_allowed(target):
        console.print(f"[green]✓[/green] {target} is [bold]in scope[/bold]")
    else:
        console.print(f"[red]✗[/red] {target} is [bold]NOT in scope[/bold]")
        console.print("[dim]Add it to config/targets.yaml to allow scanning.[/dim]")


if __name__ == "__main__":
    main()
