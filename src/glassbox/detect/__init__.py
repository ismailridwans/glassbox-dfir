"""Deterministic detection logic: LOLBAS, credential access, lateral movement."""

from glassbox.detect.lolbas import detect_lolbas_abuse
from glassbox.detect.credential import detect_credential_access
from glassbox.detect.lateral import detect_lateral_movement

__all__ = ["detect_lolbas_abuse", "detect_credential_access", "detect_lateral_movement"]
