"""LLM abstraction with token accounting.

GLASSBOX runs end-to-end with **no LLM at all** (the ``heuristic`` backend):
planning, correlation, verification, and the self-correction decision are all
deterministic code. That is the point — the safety-critical logic is not
prompt-dependent. The LLM, when enabled, only adds natural-language *reasoning
narration* ("which tool I chose, why, what I expected") for the analyst-training
transparency goal, and never gains authority over evidence, verdicts, or the loop.

Backends:
  * ``HeuristicLLM``  — offline, 0 tokens, templated narration. Default.
  * ``AnthropicLLM``  — real reasoning + true token usage, with prompt caching.
"""

from __future__ import annotations

import os
from typing import Optional

from glassbox.models import TokenUsage


class BaseLLM:
    name = "base"

    def narrate(self, system: str, user: str) -> tuple[str, TokenUsage]:
        raise NotImplementedError


class HeuristicLLM(BaseLLM):
    """No network, no tokens. Returns a compact deterministic rationale so the
    transparent-reasoning ('analyst training loop') feature works offline."""

    name = "heuristic"

    def narrate(self, system: str, user: str) -> tuple[str, TokenUsage]:
        # The caller passes a pre-built rationale as `user`; we echo it. This keeps
        # reasoning fully reproducible and free.
        return user.strip(), TokenUsage(input_tokens=0, output_tokens=0)


class AnthropicLLM(BaseLLM):  # pragma: no cover - requires network + key
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-4-8"):
        from anthropic import Anthropic  # lazy import

        if not os.getenv("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        self.client = Anthropic()
        self.model = model

    def narrate(self, system: str, user: str) -> tuple[str, TokenUsage]:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=512,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(getattr(b, "text", "") for b in resp.content)
        usage = TokenUsage(
            input_tokens=getattr(resp.usage, "input_tokens", 0),
            output_tokens=getattr(resp.usage, "output_tokens", 0),
        )
        return text, usage


def get_llm(backend: str = "heuristic", model: str = "claude-opus-4-8") -> BaseLLM:
    if backend == "anthropic":
        try:
            return AnthropicLLM(model=model)
        except Exception:
            # graceful degradation: fall back to offline narration
            return HeuristicLLM()
    return HeuristicLLM()
