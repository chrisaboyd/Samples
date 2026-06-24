"""
providers.py — Model-agnostic LLM provider abstraction.

Supports Anthropic (via SDK) and Poolside (via OpenAI-compatible HTTP API).
Each provider implements a single `chat()` method that takes messages and returns text.
"""

from dataclasses import dataclass
from typing import Protocol

import anthropic
import httpx


class LLMProvider(Protocol):
    """Interface for LLM providers."""

    def chat(self, messages: list[dict], system: str = "") -> str:
        """Send messages and return the assistant's text response."""
        ...


@dataclass
class AnthropicProvider:
    """Anthropic provider using the official SDK."""

    api_key: str
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 8192

    def chat(self, messages: list[dict], system: str = "") -> str:
        client = anthropic.Anthropic(api_key=self.api_key)
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        response = client.messages.create(**kwargs)
        return response.content[0].text


@dataclass
class PoolsideProvider:
    """Poolside provider using their OpenAI-compatible chat completions API."""

    api_key: str
    base_url: str = "https://api.poolsi.de"
    model: str = "laguna-m.1"
    max_tokens: int = 8192

    def chat(self, messages: list[dict], system: str = "") -> str:
        if system:
            messages = [{"role": "system", "content": system}] + messages

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        resp = httpx.post(
            f"{self.base_url}/openai/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=180,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


# Registry of provider constructors
PROVIDERS = {
    "anthropic": AnthropicProvider,
    "poolside": PoolsideProvider,
}


def make_provider(provider_name: str, **kwargs) -> LLMProvider:
    """Create a provider instance by name. Raises KeyError for unknown providers."""
    cls = PROVIDERS[provider_name]
    return cls(**kwargs)
