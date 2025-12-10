"""
CLI entry point for your application.

This provides the command-line interface that users interact with.
Customize the commands below for your use case.
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
    """Your Application - Brief description of what it does."""
    pass


@main.command()
@click.argument("task")
@click.option(
    "--provider",
    "-p",
    type=str,
    default="poolside",
    help="LLM provider to use (poolside, etc.)",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Model to use (provider-specific). Defaults to provider's default.",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def run(task: str, provider: str, model: str | None, verbose: bool):
    """
    Run a task using the agent.

    TASK is a description of what you want to accomplish.

    Examples:

        your-cli run "Process the data"

        your-cli run "Analyze the results" -v

        your-cli run "Generate report" -p poolside -m malibu_agent_1201_2k
    """
    console.print(Panel(
        f"[bold]Task:[/bold] {task}\n"
        f"[bold]Provider:[/bold] {provider}" + (f" ({model})" if model else ""),
        title="Running Task",
        border_style="blue"
    ))

    asyncio.run(_run_task(task, provider, model, verbose))


async def _run_task(task: str, provider_name: str, model: str | None, verbose: bool):
    """Execute a task using the agent."""
    # TODO: Import your agent
    # from agents import YourAgent, get_provider

    # try:
    #     llm_provider = get_provider(provider_name, model)
    # except ValueError as e:
    #     console.print(f"[red]Error: {e}[/red]")
    #     return

    # agent = YourAgent(provider=llm_provider)

    console.print("\n[bold blue]Starting...[/bold blue]\n")

    try:
        # TODO: Run your agent
        # result = await agent.run(task, verbose=verbose)

        # Placeholder response
        result = f"Task received: {task}\n\nTODO: Implement your agent and uncomment the code in cli.py"

        console.print("\n")
        console.print(Panel(
            Markdown(result),
            title="Results",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise


@main.command()
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
    help="Model to use (provider-specific).",
)
def interactive(provider: str, model: str | None):
    """Start an interactive session with the agent."""
    console.print(Panel(
        f"Interactive mode - chat with the agent.\n"
        f"Provider: {provider}" + (f" ({model})" if model else "") + "\n"
        "Type 'exit' or 'quit' to end the session.",
        title="Interactive Mode",
        border_style="blue"
    ))

    asyncio.run(_interactive_session(provider, model))


async def _interactive_session(provider_name: str, model: str | None):
    """Run an interactive session with the agent."""
    # TODO: Import and initialize your agent
    # from agents import YourAgent, get_provider
    # llm_provider = get_provider(provider_name, model)
    # agent = YourAgent(provider=llm_provider)

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
            # TODO: Run your agent
            # result = await agent.run(user_input, verbose=True)
            result = f"You said: {user_input}\n\nTODO: Implement your agent"

            console.print("\n[bold blue]Agent>[/bold blue]")
            console.print(Markdown(result))
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


@main.command()
def check():
    """Check if the environment is configured correctly."""
    import os
    import shutil

    console.print("\n[bold]Checking environment...[/bold]\n")

    # Check Python version
    import sys
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        console.print(f"[green]✓[/green] Python version: {py_version}")
    else:
        console.print(f"[red]✗[/red] Python version: {py_version} (requires >= 3.10)")

    # Check API keys
    api_keys = {
        "POOLSIDE_API_KEY": "Poolside API",
        # Add other API keys your app needs:
        # "OPENAI_API_KEY": "OpenAI API",
    }

    console.print("\n[bold]API Keys:[/bold]")
    for key, name in api_keys.items():
        if os.environ.get(key):
            console.print(f"[green]✓[/green] {name}: Set")
        else:
            console.print(f"[yellow]![/yellow] {name}: Not set ({key})")

    # Check for required tools (customize for your app)
    # tools = {
    #     "tool_name": "Description",
    # }
    #
    # console.print("\n[bold]Required Tools:[/bold]")
    # for tool, description in tools.items():
    #     path = shutil.which(tool)
    #     if path:
    #         console.print(f"[green]✓[/green] {tool}: {path}")
    #     else:
    #         console.print(f"[red]✗[/red] {tool}: NOT FOUND ({description})")

    console.print()


@main.command()
def list_providers():
    """List available LLM providers."""
    console.print("\n[bold]Available LLM Providers:[/bold]\n")

    # TODO: Update this list as you add providers
    providers = [
        ("poolside", "Poolside models (agent_malibu_1201_2k)", "POOLSIDE_API_KEY"),
        # ("openai", "GPT models (gpt-4, gpt-4-turbo)", "OPENAI_API_KEY"),
    ]

    for name, models, env_var in providers:
        console.print(f"[bold]{name}[/bold]")
        console.print(f"  Models: {models}")
        console.print(f"  Env var: {env_var}")
        console.print()


if __name__ == "__main__":
    main()
