"""ATT&CK mapping: verified technique IDs, tactic rollups, sigma tags."""

import pytest

from glassbox.attack import for_artifact, for_event_id, from_sigma_tags, coverage_by_tactic
from glassbox.attack.mapping import technique


def test_service_install_maps_to_T1543_003():
    mappings = for_artifact("service_install")
    ids = [m.technique_id for m in mappings]
    assert "T1543.003" in ids


def test_powershell_encoded_maps_three_techniques():
    mappings = for_artifact("powershell_encoded")
    ids = [m.technique_id for m in mappings]
    assert "T1059.001" in ids
    assert "T1027.010" in ids


def test_event_7045_maps_service():
    mappings = for_event_id(7045)
    ids = [m.technique_id for m in mappings]
    assert "T1543.003" in ids


def test_event_1102_maps_clear_logs():
    mappings = for_event_id(1102)
    ids = [m.technique_id for m in mappings]
    assert "T1070.001" in ids


def test_sigma_tags_parse_attack_prefix():
    tags = ["attack.t1059.001", "attack.credential_access", "attack.t1003.001"]
    mappings = from_sigma_tags(tags)
    ids = [m.technique_id for m in mappings]
    assert "T1059.001" in ids
    assert "T1003.001" in ids


def test_coverage_by_tactic_ordered():
    from glassbox.attack.attack_data import TACTIC_ORDER
    mappings = for_artifact("service_install") + for_artifact("lsass_dump")
    coverage = coverage_by_tactic(mappings)
    order_vals = [TACTIC_ORDER.get(r["tactic_id"], 999) for r in coverage]
    assert order_vals == sorted(order_vals)


def test_technique_enriches_tactic_names():
    m = technique("T1543.003")
    assert m is not None
    assert "Persistence" in m.tactic_names
    assert "TA0003" in m.tactic_ids


def test_unknown_technique_returns_none():
    assert technique("T9999.999") is None
