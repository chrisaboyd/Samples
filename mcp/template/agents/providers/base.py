"""
Base LLM Provider abstraction.

This module defines the interface that all LLM providers must implement.
The abstraction allows swapping between different LLM backends (Poolside, Ollama, etc. ) 
while keeping the MCP tool integration unchanged.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """Represents a tool call requested by the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """
    Normalized response from any LLM provider.

    This provides a consistent interface regardless of whether
    LLM provider you are using.
    """
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"  # "end_turn" | "tool_use"
    raw_response: Any = None  # Original provider response for debugging

    @property
    def has_tool_calls(self) -> bool:
        """Check if response contains tool calls."""
        return len(self.tool_calls) > 0


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    Implement this interface to add support for a new LLM backend.
    See agents/providers/_template/ for a starting point.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for display/logging."""
        pass

    @property
    @abstractmethod
    def model(self) -> str:
        """Current model being used."""
        pass

    @abstractmethod
    def complete(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Send a completion request to the LLM.

        Args:
            messages: Conversation history in provider-neutral format
            tools: List of tool definitions (MCP format)
            system: System prompt
            max_tokens: Maximum tokens in response

        Returns:
            Normalized LLMResponse
        """
        pass

    @abstractmethod
    def format_tool_result(self, tool_call_id: str, result: str, is_error: bool = False) -> dict:
        """
        Format a tool result for inclusion in the next message.

        Different providers have different formats for tool results.
        This method normalizes that.

        Args:
            tool_call_id: ID of the tool call this is responding to
            result: The tool's output
            is_error: Whether the tool execution failed

        Returns:
            Dict formatted for this provider's message format
        """
        pass

    @abstractmethod
    def format_assistant_message(self, response: LLMResponse) -> dict:
        """
        Format the assistant's response for conversation history.

        Args:
            response: The LLMResponse to format

        Returns:
            Dict formatted for this provider's message format
        """
        pass

    @abstractmethod
    def format_tool_results_message(self, tool_results: list[dict]) -> dict | list[dict]:
        """
        Format tool results into a message for the conversation.

        Some providers (Poolside) nest tool results in a user message.
        Others (OpenAI) use separate tool messages.

        Args:
            tool_results: List of formatted tool results

        Returns:
            Message dict(s) to append to conversation
        """
        pass

    def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
        """
        Convert MCP tool definitions to this provider's format.

        Default implementation returns MCP format directly.
        Override if your provider needs different tool schemas.

        Args:
            mcp_tools: Tools from MCP server's list_tools()

        Returns:
            Tools formatted for this provider's API
        """
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            for tool in mcp_tools
        ]
