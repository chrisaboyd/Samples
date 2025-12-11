"""
Base agent infrastructure shared by all agents.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel

from .providers import LLMProvider, AnthropicProvider, PoolsideProvider

console = Console()


class BaseAgent(ABC):
    """Base class for all security scanning agents."""

    def __init__(
        self,
        provider: LLMProvider | None = None,
        max_tokens: int = 3276,
    ):
        """
        Initialize the agent.

        Args:
            provider: LLM provider to use. Defaults to PoolsideProvider.
            max_tokens: Maximum tokens for LLM responses.
        """
        self.provider = provider or PoolsideProvider()
        self.max_tokens = max_tokens
        self.system_prompt = self._load_system_prompt()

    @property
    @abstractmethod
    def name(self) -> str:
        """Agent name for display."""
        pass

    @property
    @abstractmethod
    def mcp_server_module(self) -> str:
        """Python module path for the MCP server (e.g., 'mcp_servers.scanner.server')."""
        pass

    @property
    @abstractmethod
    def prompt_file(self) -> str:
        """Filename of the system prompt in prompts/ directory."""
        pass

    def _load_system_prompt(self) -> str:
        """Load system prompt from file."""
        prompt_path = Path(__file__).parent.parent / "prompts" / self.prompt_file
        if prompt_path.exists():
            return prompt_path.read_text()
        return self._default_prompt()

    @abstractmethod
    def _default_prompt(self) -> str:
        """Default system prompt if file doesn't exist."""
        pass

    async def run(self, task: str, verbose: bool = False) -> str:
        """
        Run the agent with a given task.

        Args:
            task: The task description for the agent
            verbose: If True, print intermediate steps

        Returns:
            Final response from the agent
        """
        server_params = StdioServerParameters(
            command="python",
            args=["-m", self.mcp_server_module]
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Get available tools from MCP server
                tools_result = await session.list_tools()
                tools = self.provider.convert_mcp_tools(tools_result.tools)

                if verbose:
                    console.print(f"[dim]Provider: {self.provider.name} ({self.provider.model})[/dim]")
                    # Handle both Anthropic format (name at top level) and OpenAI format (name in function)
                    tool_names = [
                        t.get('name') or t.get('function', {}).get('name', 'unknown')
                        for t in tools
                    ]
                    console.print(f"[dim]Available tools: {tool_names}[/dim]")

                # Start conversation
                messages = [{"role": "user", "content": task}]

                # Agentic loop
                while True:
                    response = self.provider.complete(
                        messages=messages,
                        tools=tools,
                        system=self.system_prompt,
                        max_tokens=self.max_tokens,
                    )

                    if verbose:
                        console.print(f"[dim]Stop reason: {response.stop_reason}[/dim]")

                    # Check if we're done
                    if response.stop_reason == "end_turn":
                        return response.content or ""

                    # Handle tool use
                    if response.stop_reason == "tool_use":
                        tool_results = []

                        for tool_call in response.tool_calls:
                            if verbose:
                                console.print(Panel(
                                    f"[bold]{tool_call.name}[/bold]\n{json.dumps(tool_call.arguments, indent=2)}",
                                    title="Tool Call",
                                    border_style="blue"
                                ))

                            # Call the MCP tool
                            try:
                                result = await session.call_tool(tool_call.name, tool_call.arguments)
                                result_text = result.content[0].text if result.content else "No output"

                                if verbose:
                                    # Truncate long outputs
                                    display_text = result_text[:500] + "..." if len(result_text) > 500 else result_text
                                    console.print(Panel(
                                        display_text,
                                        title="Tool Result",
                                        border_style="green"
                                    ))

                                tool_results.append(
                                    self.provider.format_tool_result(tool_call.id, result_text)
                                )
                            except Exception as e:
                                error_msg = f"Error calling tool: {e}"
                                if verbose:
                                    console.print(f"[red]{error_msg}[/red]")
                                tool_results.append(
                                    self.provider.format_tool_result(
                                        tool_call.id,
                                        json.dumps({"error": str(e)}),
                                        is_error=True
                                    )
                                )

                        # Add assistant response and tool results to messages
                        messages.append(self.provider.format_assistant_message(response))

                        # Handle both list (OpenAI/Poolside) and dict (Anthropic) returns
                        tool_results_msg = self.provider.format_tool_results_message(tool_results)
                        if isinstance(tool_results_msg, list):
                            messages.extend(tool_results_msg)
                        else:
                            messages.append(tool_results_msg)

                    else:
                        # Unexpected stop reason
                        return response.content or ""
