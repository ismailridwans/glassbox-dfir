"""GLASSBOX web dashboard — zero-dependency stdlib backend + static SPA.

Deliberately built on Python's standard library (``http.server`` + Server-Sent
Events) so it runs on the SANS SIFT Workstation with **no pip install** beyond
GLASSBOX itself. Launch with ``glassbox serve``.
"""

from glassbox.web.server import serve

__all__ = ["serve"]
