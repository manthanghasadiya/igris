"""
AI Provider Configurations
=========================

Supported LLM providers for result classification.
"""

import os
import json
from pathlib import Path
from typing import Optional

from openai import OpenAI

PROVIDERS = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "env_key": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "env_key": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "env_key": "OPENROUTER_API_KEY",
        "default_model": "meta-llama/llama-3.3-70b-instruct",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "env_key": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
    },
    # Note: Anthropic is NOT OpenAI-compatible. Use OpenRouter for Claude models:
    #   igris scan --ai --provider openrouter  (with OPENROUTER_API_KEY set)
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "env_key": None,  # No key needed
        "default_model": "llama3.2",
    },
    "grok": {
        "base_url": "https://api.x.ai/v1",
        "env_key": "XAI_API_KEY",
        "default_model": "grok-2-latest",
    },
    "huggingface": {
        "base_url": "https://api-inference.huggingface.co/v1",
        "env_key": "HF_API_KEY",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct",
    },
}

CONFIG_DIR = Path.home() / ".igris"
CONFIG_FILE = CONFIG_DIR / "config.json"


def get_config() -> dict:
    """Load configuration from ~/.igris/config.json"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


class AIClient:
    """Unified client for multiple LLM providers using OpenAI-compatible APIs."""

    def __init__(self, provider: str = "auto"):
        self.config = get_config()
        
        if provider == "auto":
            # Try configured providers first
            provider = self._auto_detect()

        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}")

        config = PROVIDERS[provider]
        env_key = config.get("env_key")
        
        # Priority: Env Var > Config File > Default ("ollama" for Ollama)
        api_key = os.environ.get(env_key or "") or self.config.get("api_keys", {}).get(provider)
        
        if not api_key and env_key is not None:
             # If no key found for a provider that requires it, fall back to auto
             # unless the user explicitly requested this provider
             if provider != "ollama":
                 auto_provider = self._auto_detect()
                 if auto_provider != provider:
                     config = PROVIDERS[auto_provider]
                     env_key = config.get("env_key")
                     api_key = os.environ.get(env_key or "") or self.config.get("api_keys", {}).get(auto_provider)
                     provider = auto_provider

        # Final check for keys
        if not api_key and provider != "ollama":
            raise RuntimeError(
                f"No API key found for {provider}. Set {config['env_key']} "
                f"or run 'igris setup' to configure."
            )

        self.client = OpenAI(
            base_url=config["base_url"],
            api_key=api_key or "ollama",
        )
        self.model = config["default_model"]
        self.provider = provider

    def _auto_detect(self) -> str:
        """Find the first provider with an available API key."""
        for name, config in PROVIDERS.items():
            env_key = config.get("env_key")
            if env_key and os.environ.get(env_key):
                return name
            if self.config.get("api_keys", {}).get(name):
                return name
        return "ollama"

    def classify(self, prompt: str) -> str:
        """Send a prompt for classification."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=500,
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"AI classification failed with {self.provider}: {e}")
