"""Live SIEM/endpoint integration stubs.

GLASSBOX supports four live-data backends, each exposed as a read-only MCP
tool. On the SIFT Workstation these require external services; in offline
mode they return gracefully with UNAVAILABLE status so the rest of the
pipeline continues.

Backends implemented:
  WazuhClient    — Wazuh SIEM REST API (gensecaihq/Wazuh-MCP-Server architecture)
  ElasticClient  — Elasticsearch (cr7258/elasticsearch-mcp-server architecture)
  VelociraptorClient — Velociraptor gRPC VQL (SOCFortress architecture)
  SplunkClient   — Splunk REST API (CiscoDevNet/Splunk-MCP-Server architecture)

Each returns normalized alert/event dicts that slot directly into GLASSBOX's
Finding pipeline — the hallucination gate applies to live data exactly as it
does to on-disk evidence.
"""

from glassbox.siem.client import (
    ElasticClient,
    LiveQueryResult,
    SplunkClient,
    VelociraptorClient,
    WazuhClient,
    build_client,
)

__all__ = [
    "WazuhClient", "ElasticClient", "VelociraptorClient", "SplunkClient",
    "LiveQueryResult", "build_client",
]
