"""Token counting and response truncation for MCP tool responses."""
import os
from typing import Optional


def count_tokens(text: str, model: str = "gpt-4") -> int:
    """Count tokens in text using tiktoken. Falls back to word-count estimate."""
    try:
        import tiktoken
        enc = tiktoken.encoding_for_model(model)
        return len(enc.encode(text))
    except Exception:
        return len(text.split())


def truncate_to_token_limit(text: str, max_tokens: int, model: str = "gpt-4") -> str:
    """Truncate text to fit within max_tokens. Appends a notice when truncated."""
    try:
        import tiktoken
        enc = tiktoken.encoding_for_model(model)
        tokens = enc.encode(text)
        if len(tokens) <= max_tokens:
            return text
        truncated = enc.decode(tokens[:max_tokens])
        return truncated + f"\n\n[TRUNCATED: output exceeded {max_tokens} tokens]"
    except Exception:
        # Fallback: rough character-based truncation (avg ~4 chars/token)
        char_limit = max_tokens * 4
        if len(text) <= char_limit:
            return text
        return text[:char_limit] + f"\n\n[TRUNCATED: output exceeded {max_tokens} tokens]"


def get_max_response_tokens() -> int:
    """Return the configured max response tokens from environment."""
    return int(os.environ.get("CTFTOOLKIT_MAX_RESPONSE_TOKENS", "4000"))
