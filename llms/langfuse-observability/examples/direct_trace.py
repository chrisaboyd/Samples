"""Trace a direct call to an OpenAI-compatible endpoint (no LiteLLM in the path).

Required environment variables:
  POOLSIDE_STANDALONE_BASE_URL   OpenAI-style base, e.g. https://host/v1
  POOLSIDE_STANDALONE_MODEL      model id served by the endpoint
  POOLSIDE_API_KEY               bearer token for the endpoint
  LANGFUSE_PUBLIC_KEY            pk-lf-... (Langfuse project key)
  LANGFUSE_SECRET_KEY            sk-lf-...
  LANGFUSE_HOST                  e.g. https://langfuse.poolsi.de

  pip install "langfuse>=3" requests
"""
import os
import requests
from langfuse import observe, get_client

langfuse = get_client()

MODEL = os.environ["POOLSIDE_STANDALONE_MODEL"]
BASE_URL = os.environ["POOLSIDE_STANDALONE_BASE_URL"].rstrip("/")
API_KEY = os.environ["POOLSIDE_API_KEY"]
CHAT_URL = f"{BASE_URL}/chat/completions"


@observe(as_type="generation", name="direct-openai-compatible-call")
def call_model(messages):
    langfuse.update_current_generation(
        model=MODEL,
        input=messages,
        metadata={"endpoint": "poolside-standalone", "url": CHAT_URL},
    )

    r = requests.post(
        CHAT_URL,
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={"model": MODEL, "messages": messages},
        timeout=120,
    )
    r.raise_for_status()
    data = r.json()

    usage = data.get("usage") or {}
    usage_details = {
        k: v
        for k, v in {
            "input": usage.get("prompt_tokens"),
            "output": usage.get("completion_tokens"),
            "total": usage.get("total_tokens"),
        }.items()
        if v is not None
    }

    langfuse.update_current_generation(
        output=data["choices"][0]["message"]["content"],
        usage_details=usage_details or None,
    )
    return data


if __name__ == "__main__":
    data = call_model([{"role": "user", "content": "Reply with exactly: poolside standalone trace ok"}])
    print("MODEL_REPLY:", data["choices"][0]["message"]["content"].strip())
    print("USAGE:", data.get("usage"))
    langfuse.flush()  # short-lived script: flush before exit
