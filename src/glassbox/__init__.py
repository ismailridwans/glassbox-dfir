"""GLASSBOX — read-only, self-correcting, autonomous DFIR triage for the SANS SIFT Workstation.

Design thesis (one sentence): *the LLM proposes; the deterministic graph and the
hallucination verifier dispose.* The model never has the authority to (a) touch
evidence, (b) mark a finding CONFIRMED, or (c) loop forever — those are enforced
in code, not in a prompt.

Primary architectural pattern: **Custom read-only MCP Server** (typed tool
functions, no shell/write primitives), orchestrated by a **LangGraph** state
machine. See docs/ARCHITECTURE.md.
"""

from glassbox.version import __version__

__all__ = ["__version__"]
