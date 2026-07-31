from __future__ import annotations

from app.mapping.framework_mapper import loaded_framework_keys, map_indicators


def test_loads_all_four_frameworks():
    assert set(loaded_framework_keys()) == {"mitre_attack", "nist_csf", "iso_27001", "soc2"}


def test_maps_known_indicator_to_controls_in_every_framework():
    mappings = map_indicators(["LOOKALIKE_DOMAIN"])
    for framework_key in loaded_framework_keys():
        assert len(mappings[framework_key]) > 0
        for ref in mappings[framework_key]:
            assert ref.indicator_id == "LOOKALIKE_DOMAIN"
            assert ref.control_id
            assert ref.control_name


def test_unknown_indicator_yields_no_controls():
    mappings = map_indicators(["NOT_A_REAL_INDICATOR"])
    for framework_key in loaded_framework_keys():
        assert mappings[framework_key] == []


def test_empty_indicator_list_yields_empty_mappings_per_framework():
    mappings = map_indicators([])
    for framework_key in loaded_framework_keys():
        assert mappings[framework_key] == []
