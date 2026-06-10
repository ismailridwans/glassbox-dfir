"""Adversarial Verification Panel — GLASSBOX's flagship differentiator.

The mechanical hallucination gate (``glassbox.verify``) answers *"is this claim
grounded in tool output?"*. The adversarial panel answers a harder question:
*"a grounded claim can still be a false positive — does it survive a red-team?"*

Every finding is challenged by a panel of skeptic perspectives, each encoding
real DFIR false-positive knowledge (SSDT-UNKNOWN is often EDR, malfind RWX in a
.NET process is often JIT, process enumeration alone is baseline activity, …).
A finding's severity/confidence is then UPHELD, DEMOTED, or REFUTED by majority
vote — turning a noisy grounded-finding set into a high-precision, red-team-
verified one.

This directly targets the hackathon's #1 (Autonomous Execution Quality — the
tiebreaker: "recognize when something doesn't add up, and self-correct") and #2
(IR Accuracy — fewer false positives) criteria, and the GTG-1002 failure mode
where an agent "overstated findings." The skeptics are deterministic code
offline (reproducible) and LLM-powered when enabled.
"""

from glassbox.adversarial.panel import AdversarialPanel, PanelResult
from glassbox.adversarial.skeptic import SkepticVote, Vote

__all__ = ["AdversarialPanel", "PanelResult", "SkepticVote", "Vote"]
