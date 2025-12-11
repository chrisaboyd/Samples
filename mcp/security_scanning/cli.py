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
@click.option(
    "--provider",
    "-p",
    type=str,
    default="poolside",
    help="LLM provider to use (anthropic, openai, ollama, etc.)",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Model to use (provider-specific). Defaults to provider's default.",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def scan(target: str, mode: str, provider: str, model: str | None, verbose: bool):
    """
    Run a security scan against TARGET.

    TARGET should be an IP address or hostname in scope.

    Examples:

        scanner scan 192.168.56.101

        scanner scan 192.168.56.101 --mode active -v

        scanner scan 192.168.56.101 -p poolside -m malibu_agent_1201_2k

        scanner scan 192.168.56.101 -p openai -m gpt-4o
    """
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {mode}\n"
        f"[bold]Provider:[/bold] {provider}" + (f" ({model})" if model else ""),
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
    asyncio.run(_run_active_scan(target, provider, model, verbose))


async def _run_active_scan(target: str, provider_name: str, model: str | None, verbose: bool):
    """Run the scanner agent against a target."""
    from agents import ScannerAgent, get_provider

    try:
        llm_provider = get_provider(provider_name, model)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    agent = ScannerAgent(provider=llm_provider)

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
@click.option(
    "--provider",
    "-p",
    type=str,
    default="poolside",
    help="LLM provider to use (anthropic, openai, ollama, etc.)",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Model to use (provider-specific).",
)
def interactive(provider: str, model: str | None):
    """Start an interactive scanning session."""
    console.print(Panel(
        f"Interactive mode - chat with the scanner agent.\n"
        f"Provider: {provider}" + (f" ({model})" if model else "") + "\n"
        "Type 'exit' or 'quit' to end the session.",
        title="Interactive Mode",
        border_style="blue"
    ))

    asyncio.run(_interactive_session(provider, model))


async def _interactive_session(provider_name: str, model: str | None):
    """Run an interactive session with the scanner agent."""
    from agents import ScannerAgent, get_provider

    try:
        llm_provider = get_provider(provider_name, model)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    agent = ScannerAgent(provider=llm_provider)

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
        "p0f": "Passive OS fingerprinting",
        "rustscan": "Port scanning",
        "smbmap": "SMB share mapping",
        "onesixtyone": "SNMP enumeration",
        "enum4linux-ng": "Enumerate information from Windows and Samba systems",
        "dnsrecon": "DNS reconnaissance",
        "sslscan": "SSL/TLS server testing",
        "sublist3r": "Subdomain enumeration",
        "whatweb": "Web server fingerprinting",
        "wpscan": "WordPress security scanner"
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


@main.command()
def list_providers():
    """List available LLM providers."""
    console.print("\n[bold]Available LLM Providers:[/bold]\n")

    providers = [
        ("anthropic", "Anthropic models (claude-sonnet-4-20250514, claude-opus-4-20250514)", "ANTHROPIC_API_KEY"),
        ("poolside", "Poolside models (malibu_agent_1201_2k)", "POOLSIDE_API_KEY + POOLSIDE_BASE_URL"),
    ]

    for name, models, env_var in providers:
        console.print(f"[bold]{name}[/bold]")
        console.print(f"  Models: {models}")
        console.print(f"  Env var: {env_var}")
        console.print()


# --- New Orchestrated Assessment Commands ---

@main.command()
@click.argument("target")
@click.option(
    "--scan-id",
    type=str,
    default=None,
    help="Custom scan ID (auto-generated if not provided)",
)
@click.option(
    "--phases",
    type=str,
    default="recon,scan,analysis,report",
    help="Comma-separated phases to run (recon,scan,analysis,report)",
)
@click.option(
    "--provider",
    "-p",
    type=str,
    default="poolside",
    help="LLM provider to use",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Model to use (provider-specific)",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def assess(
    target: str,
    scan_id: str | None,
    phases: str,
    provider: str,
    model: str | None,
    verbose: bool,
):
    """
    Run a full security assessment against TARGET.

    This orchestrates the complete workflow:
    1. Passive reconnaissance
    2. Active scanning
    3. Vulnerability analysis
    4. Report generation

    Examples:

        scanner assess 192.168.56.101

        scanner assess 192.168.56.101 --phases recon,scan -v

        scanner assess 192.168.56.101 --scan-id my-scan-001
    """
    phase_list = [p.strip() for p in phases.split(",")]

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Phases:[/bold] {', '.join(phase_list)}\n"
        f"[bold]Provider:[/bold] {provider}" + (f" ({model})" if model else ""),
        title="Security Assessment",
        border_style="blue"
    ))

    # TODO: Implement when orchestrator is ready
    # asyncio.run(_run_assessment(target, scan_id, phase_list, provider, model, verbose))
    console.print("[yellow]Orchestrated assessment not yet implemented.[/yellow]")
    console.print("Use 'scanner scan' for active scanning only.")


@main.command()
@click.argument("target")
@click.option(
    "--provider",
    "-p",
    type=str,
    default="poolside",
    help="LLM provider to use",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Model to use (provider-specific)",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def recon(target: str, provider: str, model: str | None, verbose: bool):
    """
    Run passive reconnaissance against TARGET.

    Gathers information using DNS, WHOIS, Shodan, and certificate
    transparency without directly interacting with the target.

    Examples:

        scanner recon example.com

        scanner recon 192.168.56.101 -v
    """
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] Passive Reconnaissance\n"
        f"[bold]Provider:[/bold] {provider}" + (f" ({model})" if model else ""),
        title="Passive Recon",
        border_style="cyan"
    ))

    # TODO: Implement when recon agent is ready
    # asyncio.run(_run_recon(target, provider, model, verbose))
    console.print("[yellow]Passive recon not yet implemented.[/yellow]")


@main.command()
@click.argument("scan_id")
@click.option(
    "--provider",
    "-p",
    type=str,
    default="poolside",
    help="LLM provider to use",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Model to use (provider-specific)",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def analyze(scan_id: str, provider: str, model: str | None, verbose: bool):
    """
    Run vulnerability analysis on findings from SCAN_ID.

    Researches CVEs, exploits, and remediation for discovered services.

    Examples:

        scanner analyze scan-20240115-001

        scanner analyze scan-20240115-001 -v
    """
    console.print(Panel(
        f"[bold]Scan ID:[/bold] {scan_id}\n"
        f"[bold]Mode:[/bold] Vulnerability Analysis\n"
        f"[bold]Provider:[/bold] {provider}" + (f" ({model})" if model else ""),
        title="Analysis",
        border_style="yellow"
    ))

    # TODO: Implement when analysis agent is ready
    # asyncio.run(_run_analysis(scan_id, provider, model, verbose))
    console.print("[yellow]Analysis not yet implemented.[/yellow]")


@main.command()
@click.argument("scan_id")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["markdown", "json", "both"]),
    default="both",
    help="Report format",
)
@click.option(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Output directory (defaults to scans/<scan_id>/report/)",
)
def report(scan_id: str, format: str, output: str | None):
    """
    Generate a report for SCAN_ID.

    Creates Markdown and/or JSON reports from stored findings.

    Examples:

        scanner report scan-20240115-001

        scanner report scan-20240115-001 -f markdown -o ./reports/
    """
    console.print(Panel(
        f"[bold]Scan ID:[/bold] {scan_id}\n"
        f"[bold]Format:[/bold] {format}\n"
        f"[bold]Output:[/bold] {output or 'default'}",
        title="Report Generation",
        border_style="green"
    ))

    # TODO: Implement when report generator is ready
    # _generate_report(scan_id, format, output)
    console.print("[yellow]Report generation not yet implemented.[/yellow]")


@main.command()
def list_scans():
    """List all stored scans."""
    # TODO: Implement when storage is ready
    # from storage import ScanStorage
    # storage = ScanStorage()
    # scans = storage.list_scans()
    # for scan in scans:
    #     console.print(f"{scan.scan_id} - {scan.target} ({scan.status})")
    console.print("[yellow]Scan listing not yet implemented.[/yellow]")


if __name__ == "__main__":
    main()
