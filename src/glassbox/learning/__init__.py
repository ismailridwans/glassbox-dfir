"""Persistent learning loop (Starter Idea #7).

Cross-run failure memory that accumulates lessons from quarantined findings
across GLASSBOX runs. On each run the agent:
  1. Reads the lessons file for previously-seen false patterns
  2. Uses those lessons to suppress or downgrade matching claims
  3. After verification, appends new lessons from freshly-quarantined findings

This makes GLASSBOX measurably improve in accuracy between the first and
final iteration on the same data — the core requirement of starter idea #7.
All lessons are stored as a YAML/JSON file under the case directory.
"""

from glassbox.learning.lessons import LessonsLog

__all__ = ["LessonsLog"]
