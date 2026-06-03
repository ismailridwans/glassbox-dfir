"""The read-only Custom MCP Server (GLASSBOX's primary architectural pattern).

The agent is handed *typed read functions only* — there is no ``execute_shell``,
``write_file``, or ``delete`` tool anywhere in this package. That absence is the
guardrail: spoliation is impossible because the capability does not exist in the
tool surface, not because a prompt asked the model to behave.

``ReadOnlyToolKit`` is the single source of truth for tool behavior; both the
stdio MCP server (``server.py``, launched by Claude Code / Claude Desktop) and
the in-process LangGraph orchestrator call the very same code.
"""

from glassbox.mcp_server.runner import ToolPaths, ToolRunner
from glassbox.mcp_server.toolkit import ReadOnlyToolKit, ToolResult

__all__ = ["ReadOnlyToolKit", "ToolResult", "ToolRunner", "ToolPaths"]
