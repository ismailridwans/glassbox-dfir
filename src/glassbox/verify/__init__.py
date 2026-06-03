"""Mechanical hallucination detection — the anti-fabrication gate."""

from glassbox.verify.hallucination import (
    VerificationOutcome,
    VerificationResult,
    verify_discrepancies,
    verify_findings,
)

__all__ = [
    "VerificationOutcome",
    "VerificationResult",
    "verify_findings",
    "verify_discrepancies",
]
