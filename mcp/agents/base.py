"""
Base agent infrastructure shared by all agents.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel

console = Console()


class BaseAgent(ABC):
    """Base class for all security scanning agents."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
    ):
        self.anthropic = Anthropic()
        self.model = model
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

    def _convert_mcp_tools_to_anthropic(self, mcp_tools: list) -> list[dict]:
        """Convert MCP tool definitions to Anthropic tool format."""
        anthropic_tools = []
        for tool in mcp_tools:
            anthropic_tools.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            })
        return anthropic_tools

    def _extract_text_response(self, response) -> str:
        """Extract text content from Claude response."""
        text_parts = []
        for block in response.content:
            if hasattr(block, 'text'):
                text_parts.append(block.text)
        return "\n".join(text_parts)

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
                tools = self._convert_mcp_tools_to_anthropic(tools_result.tools)

                if verbose:
                    console.print(f"[dim]Available tools: {[t['name'] for t in tools]}[/dim]")

                # Start conversation
                messages = [{"role": "user", "content": task}]

                # Agentic loop
                while True:
                    response = self.anthropic.messages.create(
                        model=self.model,
                        max_tokens=self.max_tokens,
                        system=self.system_prompt,
                        tools=tools,
                        messages=messages,
                    )

                    if verbose:
                        console.print(f"[dim]Stop reason: {response.stop_reason}[/dim]")

                    # Check if we're done
                    if response.stop_reason == "end_turn":
                        return self._extract_text_response(response)

                    # Handle tool use
                    if response.stop_reason == "tool_use":
                        tool_results = []

                        for block in response.content:
                            if block.type == "tool_use":
                                tool_name = block.name
                                tool_input = block.input

                                if verbose:
                                    console.print(Panel(
                                        f"[bold]{tool_name}[/bold]\n{json.dumps(tool_input, indent=2)}",
                                        title="Tool Call",
                                        border_style="blue"
                                    ))

                                # Call the MCP tool
                                try:
                                    result = await session.call_tool(tool_name, tool_input)
                                    result_text = result.content[0].text if result.content else "No output"

                                    if verbose:
                                        # Truncate long outputs
                                        display_text = result_text[:500] + "..." if len(result_text) > 500 else result_text
                                        console.print(Panel(
                                            display_text,
                                            title="Tool Result",
                                            border_style="green"
                                        ))

                                    tool_results.append({
                                        "type": "tool_result",
                                        "tool_use_id": block.id,
                                        "content": result_text,
                                    })
                                except Exception as e:
                                    error_msg = f"Error calling tool: {e}"
                                    if verbose:
                                        console.print(f"[red]{error_msg}[/red]")
                                    tool_results.append({
                                        "type": "tool_result",
                                        "tool_use_id": block.id,
                                        "content": json.dumps({"error": str(e)}),
                                        "is_error": True,
                                    })

                        # Add assistant response and tool results to messages
                        messages.append({"role": "assistant", "content": response.content})
                        messages.append({"role": "user", "content": tool_results})

                    else:
                        # Unexpected stop reason
                        return self._extract_text_response(response)
