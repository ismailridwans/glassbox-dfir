"""HMAC-signed finding approval gate (Valhuntir-grade human-in-the-loop).

Inspired by Valhuntir's architecture which enforces that AI findings require
human approval before actioning (via HMAC-signed approval tokens and a
password-gated CLI command). GLASSBOX implements a deterministic approval
gate that:

1. For CRITICAL findings with ANUMANA (inferred) epistemic type:
   generates an HMAC-signed approval token that an operator must verify.
2. For all other confirmed findings: AUTO_APPROVED with full audit trail.
3. The gate is ARCHITECTURAL — not a prompt. The MCP server exposes a
   `generate_approval_token` tool; the `approve_finding` tool consumes it.
   The model cannot self-approve its own findings.
"""

from glassbox.approve.gate import ApprovalGate, ApprovalToken

__all__ = ["ApprovalGate", "ApprovalToken"]
