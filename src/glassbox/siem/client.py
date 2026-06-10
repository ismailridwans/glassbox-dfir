"""SIEM client stubs — real network calls with graceful offline degradation.

Each client follows the same pattern:
  * Constructor reads credentials from environment variables (never hardcoded).
  * `query()` performs a read-only API call and returns a `LiveQueryResult`.
  * If the service is unreachable or credentials are missing, returns a
    `LiveQueryResult` with `status="UNAVAILABLE"` and empty data — never crashes.
  * No write operations are implemented — these are read-only tools by design.

This architecture follows the hackathon's Custom MCP Server pattern: the agent
physically cannot exfiltrate data or trigger responses because no such tool
exists in the surface.

Usage in GLASSBOX CLI:
    GLASSBOX_WAZUH_URL=https://wazuh.internal:55000 \
    GLASSBOX_WAZUH_TOKEN=eyJ... \
    glassbox triage /cases/live-001
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from typing import Any, Optional


def _ssl_context() -> "ssl.SSLContext":
    """TLS context for SIEM calls — **verifying by default**.

    A forensic agent that talks to a SIEM over an unverified TLS channel can be
    MITM'd: an attacker on-path could feed it forged alerts or capture the case
    context it sends. So GLASSBOX verifies the server certificate by default.

    Some IR labs run SIEMs with self-signed certs. For those, verification can be
    disabled — but only by an explicit, opt-in environment variable, so the
    insecure mode is a documented operator decision, never a silent default:

        GLASSBOX_SIEM_INSECURE_TLS=1   # accept self-signed / unverified certs
    """
    ctx = ssl.create_default_context()
    if os.getenv("GLASSBOX_SIEM_INSECURE_TLS", "").lower() in ("1", "true", "yes"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass
class LiveQueryResult:
    backend: str
    status: str      # OK | UNAVAILABLE | ERROR | AUTH_ERROR
    query: str
    count: int = 0
    data: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def to_tool_result_summary(self) -> dict:
        return {
            "backend": self.backend,
            "status": self.status,
            "query": self.query,
            "count": self.count,
            "data": self.data[:50],  # cap context window impact
            "note": self.note,
        }


class WazuhClient:
    """Read-only Wazuh SIEM client.

    Env vars: GLASSBOX_WAZUH_URL, GLASSBOX_WAZUH_TOKEN
    Architecture: gensecaihq/Wazuh-MCP-Server (48 tools, RBAC token scoped).
    """

    def __init__(self):
        self.url   = os.getenv("GLASSBOX_WAZUH_URL", "").rstrip("/")
        self.token = os.getenv("GLASSBOX_WAZUH_TOKEN", "")
        self.available = bool(self.url and self.token)

    def get_alerts(self, *, severity: str = "high", limit: int = 50,
                   time_range: str = "1h") -> LiveQueryResult:
        """Pull recent high-severity alerts (read-only)."""
        if not self.available:
            return LiveQueryResult("wazuh", "UNAVAILABLE",
                                   "get_alerts", note="Set GLASSBOX_WAZUH_URL and GLASSBOX_WAZUH_TOKEN")
        try:
            import urllib.request, json, ssl
            url = (f"{self.url}/alerts?"
                   f"limit={limit}&level=high&search=&timeframe={time_range}")
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            })
            ctx = _ssl_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = json.loads(resp.read())
            items = body.get("data", {}).get("affected_items", [])
            return LiveQueryResult("wazuh", "OK", "get_alerts", count=len(items), data=items)
        except Exception as exc:
            return LiveQueryResult("wazuh", "ERROR", "get_alerts",
                                   note=f"{type(exc).__name__}: {exc}")

    def search_events(self, query: str, limit: int = 50) -> LiveQueryResult:
        """Full-text event search (read-only)."""
        if not self.available:
            return LiveQueryResult("wazuh", "UNAVAILABLE", query)
        try:
            import urllib.request, json, ssl, urllib.parse
            q = urllib.parse.quote(query)
            url = f"{self.url}/events?q={q}&limit={limit}"
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {self.token}",
            })
            ctx = _ssl_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = json.loads(resp.read())
            items = body.get("data", {}).get("affected_items", [])
            return LiveQueryResult("wazuh", "OK", query, count=len(items), data=items)
        except Exception as exc:
            return LiveQueryResult("wazuh", "ERROR", query, note=f"{type(exc).__name__}: {exc}")


class ElasticClient:
    """Read-only Elasticsearch client.

    Env vars: GLASSBOX_ELASTIC_URL, GLASSBOX_ELASTIC_API_KEY
    Architecture: cr7258/elasticsearch-mcp-server / elastic/mcp-server-elasticsearch.
    """

    def __init__(self):
        self.url     = os.getenv("GLASSBOX_ELASTIC_URL", "").rstrip("/")
        self.api_key = os.getenv("GLASSBOX_ELASTIC_API_KEY", "")
        self.available = bool(self.url)

    def search(self, index: str, query: dict, *, size: int = 50) -> LiveQueryResult:
        """Read-only Elasticsearch search (DSL query)."""
        if not self.available:
            return LiveQueryResult("elasticsearch", "UNAVAILABLE", index,
                                   note="Set GLASSBOX_ELASTIC_URL")
        try:
            import urllib.request, json, ssl
            body = json.dumps({"query": query, "size": size}).encode()
            url = f"{self.url}/{index}/_search"
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            ctx = _ssl_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                result = json.loads(resp.read())
            hits = [h["_source"] for h in result.get("hits", {}).get("hits", [])]
            return LiveQueryResult("elasticsearch", "OK", index, count=len(hits), data=hits)
        except Exception as exc:
            return LiveQueryResult("elasticsearch", "ERROR", index,
                                   note=f"{type(exc).__name__}: {exc}")

    def winlogbeat_security_events(self, *, event_codes: list[int],
                                   hours: int = 1, size: int = 50) -> LiveQueryResult:
        """Fetch specific Windows Security event codes from Winlogbeat index (read-only)."""
        query = {
            "bool": {
                "must": [
                    {"terms": {"event.code": [str(c) for c in event_codes]}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        }
        return self.search("winlogbeat-*", query, size=size)


class VelociraptorClient:
    """Read-only Velociraptor client via VQL.

    Env vars: GLASSBOX_VELOCIRAPTOR_API_CONFIG (path to api_client.yaml)
    Architecture: socfortress/velociraptor-mcp-server (gRPC, 11 tools).
    """

    def __init__(self):
        self.api_config = os.getenv("GLASSBOX_VELOCIRAPTOR_API_CONFIG", "")
        self.available = bool(self.api_config and os.path.exists(self.api_config))

    def run_vql(self, vql: str, max_rows: int = 100) -> LiveQueryResult:
        """Execute a VQL query and return results (read-only by convention)."""
        if not self.available:
            return LiveQueryResult("velociraptor", "UNAVAILABLE", vql,
                                   note="Set GLASSBOX_VELOCIRAPTOR_API_CONFIG to api_client.yaml path")
        try:
            # Use pyvelociraptor if available
            import pyvelociraptor
            import pyvelociraptor.api_pb2 as api_pb2
            import pyvelociraptor.api_pb2_grpc as api_pb2_grpc
            import grpc, yaml

            config = yaml.safe_load(open(self.api_config))
            creds = grpc.ssl_channel_credentials(
                root_certificates=config["ca_certificate"].encode(),
                private_key=config["client_private_key"].encode(),
                certificate_chain=config["client_cert"].encode(),
            )
            channel = grpc.secure_channel(config["api_connection_string"], creds)
            stub = api_pb2_grpc.APIStub(channel)
            request = api_pb2.VQLCollectorArgs(
                max_row=max_rows,
                Query=[api_pb2.VQLRequest(VQL=vql)],
            )
            rows = []
            for resp in stub.Query(request):
                for row in resp.Response:
                    import json as _json
                    rows.append(_json.loads(row))
            return LiveQueryResult("velociraptor", "OK", vql, count=len(rows), data=rows)
        except ImportError:
            return LiveQueryResult("velociraptor", "UNAVAILABLE", vql,
                                   note="Install pyvelociraptor: pip install pyvelociraptor")
        except Exception as exc:
            return LiveQueryResult("velociraptor", "ERROR", vql,
                                   note=f"{type(exc).__name__}: {exc}")

    def get_running_processes(self, client_id: str) -> LiveQueryResult:
        """Get process list from a live Velociraptor client (read-only)."""
        vql = f"SELECT * FROM pslist() WHERE ClientId = '{client_id}'"
        return self.run_vql(vql)

    def get_network_connections(self, client_id: str) -> LiveQueryResult:
        """Get network connections from a live client (read-only)."""
        vql = f"SELECT * FROM netstat() WHERE ClientId = '{client_id}'"
        return self.run_vql(vql)


class SplunkClient:
    """Read-only Splunk REST client.

    Env vars: GLASSBOX_SPLUNK_URL, GLASSBOX_SPLUNK_TOKEN
    Architecture: CiscoDevNet/Splunk-MCP-Server-official (Bearer token, RBAC).
    """

    def __init__(self):
        self.url   = os.getenv("GLASSBOX_SPLUNK_URL", "").rstrip("/")
        self.token = os.getenv("GLASSBOX_SPLUNK_TOKEN", "")
        self.available = bool(self.url and self.token)

    def search(self, spl: str, earliest: str = "-1h", latest: str = "now",
               count: int = 50) -> LiveQueryResult:
        """Execute a Splunk SPL search job (read-only)."""
        if not self.available:
            return LiveQueryResult("splunk", "UNAVAILABLE", spl,
                                   note="Set GLASSBOX_SPLUNK_URL and GLASSBOX_SPLUNK_TOKEN")
        try:
            import urllib.request, urllib.parse, json, ssl, time
            # Step 1: create search job
            data = urllib.parse.urlencode({
                "search": f"search {spl}",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            }).encode()
            req = urllib.request.Request(
                f"{self.url}/services/search/jobs",
                data=data,
                headers={"Authorization": f"Bearer {self.token}",
                         "Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            ctx = _ssl_context()
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                sid = json.loads(resp.read()).get("sid", "")
            if not sid:
                return LiveQueryResult("splunk", "ERROR", spl, note="No SID returned")
            # Step 2: poll for results (up to 30s)
            for _ in range(6):
                time.sleep(5)
                res_url = f"{self.url}/services/search/jobs/{sid}/results?output_mode=json&count={count}"
                req2 = urllib.request.Request(res_url, headers={
                    "Authorization": f"Bearer {self.token}"})
                with urllib.request.urlopen(req2, timeout=10, context=ctx) as resp2:
                    body = json.loads(resp2.read())
                if "results" in body:
                    rows = body["results"]
                    return LiveQueryResult("splunk", "OK", spl, count=len(rows), data=rows)
            return LiveQueryResult("splunk", "ERROR", spl, note="Search timed out")
        except Exception as exc:
            return LiveQueryResult("splunk", "ERROR", spl, note=f"{type(exc).__name__}: {exc}")


_BACKEND_MAP = {
    "wazuh": WazuhClient,
    "elastic": ElasticClient,
    "velociraptor": VelociraptorClient,
    "splunk": SplunkClient,
}


def build_client(backend: str):
    """Factory: build a SIEM client by name. Returns None for unknown backends."""
    cls = _BACKEND_MAP.get(backend.lower())
    return cls() if cls else None
