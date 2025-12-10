"""
Poolside LLM Provider.

Uses Poolside's OpenAI-compatible API at /openai/v1/chat/completions.
"""

import json
import os
import uuid
from typing import Any

import httpx

from ..base import LLMProvider, LLMResponse, ToolCall


class PoolsideProvider(LLMProvider):
    """
    LLM Provider for Poolside models.

    Uses the OpenAI-compatible chat completions API.

    Requires:
        - POOLSIDE_API_KEY environment variable (Bearer token)
        - POOLSIDE_BASE_URL environment variable (optional, defaults to https://poolside.poolside.local)
    """

    def __init__(
        self,
        model: str = "malibu",
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 120.0,
    ):
        """
        Initialize the Poolside provider.

        Args:
            model: Model to use (default: "malibu")
            base_url: API base URL (default: from POOLSIDE_BASE_URL env or https://poolside.poolside.local)
            api_key: API key (default: from POOLSIDE_API_KEY env)
            timeout: Request timeout in seconds
        """
        self._model = model
        self._base_url = (
            base_url
            or os.environ.get("POOLSIDE_BASE_URL")
            or "https://poolside.poolside.local"
        ).rstrip("/")
        self._api_key = api_key or os.environ.get("POOLSIDE_API_KEY")
        self._timeout = timeout

        if not self._api_key:
            raise ValueError(
                "Poolside API key required. Set POOLSIDE_API_KEY environment variable "
                "or pass api_key parameter."
            )

    @property
    def name(self) -> str:
        return "Poolside"

    @property
    def model(self) -> str:
        return self._model

    def complete(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send completion request to Poolside's OpenAI-compatible API."""
        # Build messages list with system prompt first
        api_messages = []

        # Add system message if provided
        if system:
            api_messages.append({"role": "system", "content": system})

        # Add conversation messages
        api_messages.extend(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_completion_tokens": max_tokens,
        }

        # Add tools if provided
        if tools:
            payload["tools"] = tools

        # Make API request
        url = f"{self._base_url}/openai/v1/chat/completions"
        headers = {
            "Authorization": f"bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json, application/problem+json",
        }

        with httpx.Client(timeout=self._timeout) as client:
            response = client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        # Parse response
        choice = data["choices"][0] if data.get("choices") else {}
        message = choice.get("message", {})

        # Extract content
        content = message.get("content")

        # Extract tool calls
        tool_calls = []
        for tc in message.get("tool_calls", []):
            # Generate an ID if not provided
            tc_id = tc.get("id") or f"call_{uuid.uuid4().hex[:8]}"
            func = tc.get("function", {})

            # Arguments come as JSON string
            arguments = func.get("arguments", "{}")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}

            tool_calls.append(ToolCall(
                id=tc_id,
                name=func.get("name", ""),
                arguments=arguments,
            ))

        # Determine stop reason
        finish_reason = choice.get("finish_reason", "stop")
        stop_reason = "tool_use" if tool_calls else "end_turn"

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw_response=data,
        )

    def format_tool_result(self, tool_call_id: str, result: str, is_error: bool = False) -> dict:
        """Format tool result for Poolside (OpenAI format)."""
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        }

    def format_assistant_message(self, response: LLMResponse) -> dict:
        """Format assistant response for conversation history."""
        message: dict[str, Any] = {
            "role": "assistant",
            "content": response.content or "",
        }

        # Include tool_calls if present
        if response.tool_calls:
            message["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in response.tool_calls
            ]

        return message

    def format_tool_results_message(self, tool_results: list[dict]) -> list[dict]:
        """
        Format tool results for Poolside (OpenAI format).

        OpenAI/Poolside expects separate messages for each tool result.
        """
        return tool_results

    def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
        """
        Convert MCP tools to OpenAI/Poolside format.

        MCP format:
            {"name": "...", "description": "...", "inputSchema": {...}}

        Poolside format (OpenAI-compatible):
            {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema,
                },
            }
            for tool in mcp_tools
        ]
